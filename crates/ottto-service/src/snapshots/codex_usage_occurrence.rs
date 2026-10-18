//! Codex usage counting V2: one billed request is counted once at its native
//! usage. Local only; Legacy sessions never construct this state.
//!
//! Native `token_usage_record`s are the authority for their turn. Coverage on
//! the native thread counter (`[before, after)`, six dimensions) decides what
//! a native adds; a response id is a conflict detector only. UI `token_count`
//! events add money only in a bound turn that has no native, published when
//! the turn closes, or in an unbound span with today's rule. Published money
//! is a monotone function of the record prefix: nothing is ever subtracted.
use super::codex_counting_version::{self, AckEvidence, CountingVersion};
use super::*;
use crate::owned_heap::OwnedMap;

/// Counting-contract row cap for one open turn's staged UI money. Changing it
/// is a new counting version. Overflow publishes the staged rows and marks the
/// turn `ui_published`; it never depends on memory pressure.
pub(super) const MAX_PENDING_ROWS: usize = 64;
/// Counting-contract content cap for one staged row: the byte length of every
/// string it holds (bucket, row identity, selector context/sources, activity
/// times). A larger row takes the same deterministic overflow path, so the
/// staged state has a schema bound without a resource-dependent decision.
pub(super) const MAX_PENDING_ROW_CONTENT_BYTES: usize = 4096;
const MAX_TURN_ID_BYTES: usize = 128;
const MAX_RESPONSE_ID_BYTES: usize = 256;

/// `input, cached_input, cache_write_input, output, reasoning_output, total`.
pub(super) type T6 = [u64; 6];

#[derive(Clone)]
pub(super) struct CodexCounting {
    evidence: AckEvidence,
    cutover_unix_ms: Option<i64>,
    version: Option<CountingVersion>,
    reducer: Option<OccurrenceReducer>,
}

impl CodexCounting {
    pub(super) fn new(evidence: AckEvidence, cutover_unix_ms: Option<i64>) -> Self {
        Self {
            evidence,
            cutover_unix_ms,
            version: None,
            reducer: None,
        }
    }

    #[cfg(test)]
    pub(super) fn counters(&self) -> Option<&OccurrenceCounters> {
        self.reducer.as_ref().map(|reducer| &reducer.counters)
    }

    /// UI money staged in a still-open UI-only turn: visible local debt,
    /// never published on a timer.
    #[cfg(test)]
    pub(super) fn open_turn_ui_pending(&self) -> Option<(u64, UsageTotals)> {
        let turn = self.reducer.as_ref()?.turn.as_ref()?;
        let mut usage = UsageTotals::default();
        for row in turn.pending.values() {
            if !usage.add(&row.usage) {
                return None;
            }
        }
        Some((turn.staged_events, usage))
    }

    /// A retained reduction may continue under fresh evidence only when that
    /// evidence would have selected the same rule (B handoff H4).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn reusable_under(&self, fresh: &CodexCounting) -> bool {
        self.cutover_unix_ms == fresh.cutover_unix_ms
            && match self.version {
                None => self.evidence == fresh.evidence,
                Some(CountingVersion::Legacy) => {
                    // Legacy chosen from the header itself stays Legacy under
                    // any evidence; Legacy chosen only from ACK evidence must
                    // not be resumed once that evidence is gone.
                    self.evidence == fresh.evidence || fresh.evidence == AckEvidence::LegacyAcked
                }
                Some(CountingVersion::V2) => fresh.evidence != AckEvidence::LegacyAcked,
            }
    }
}

#[derive(Clone, Default)]
struct OccurrenceReducer {
    epoch: Option<Epoch>,
    last_native: Option<LastNative>,
    prev_ui: Option<UiTuple>,
    native_since_prev_ui: bool,
    /// Raw six-field `last`/`total` of the current line, read before the
    /// shared UI path runs for it.
    line_ui: Option<(T6, T6)>,
    /// `None` is an unbound span.
    turn: Option<BoundTurn>,
    last_closed_turn: Option<String>,
    counters: OccurrenceCounters,
}

#[derive(Clone)]
struct Epoch {
    base: T6,
    hwm: T6,
    first_id: String,
    contiguous: bool,
}

#[derive(Clone)]
struct LastNative {
    id: String,
    usage: T6,
    after: T6,
}

#[derive(Clone, PartialEq, Eq)]
struct UiTuple {
    last: UsageTotals,
    total: UsageTotals,
    last_t6: T6,
    total_t6: T6,
}

#[derive(Clone)]
struct BoundTurn {
    id: String,
    native: bool,
    ui_published: bool,
    staged_events: u64,
    pending: OwnedMap<(String, RowKey), PendingRow>,
}

#[derive(Clone)]
struct PendingRow {
    selector_context: BTreeMap<String, String>,
    selector_sources: BTreeMap<String, String>,
    usage: UsageTotals,
    events: u64,
    first_activity_at: String,
    last_activity_at: String,
}

/// Local receipts. Usage sums are six-dimension vectors; UI sums use
/// `input + output` as their total.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct OccurrenceCounters {
    pub(super) native_counted: u64,
    pub(super) native_not_authority: u64,
    pub(super) native_restated: u64,
    pub(super) native_inside_holed_coverage: u64,
    pub(super) native_inside_holed_coverage_usage: T6,
    pub(super) native_chain_gap: u64,
    pub(super) native_chain_overlap: u64,
    pub(super) native_chain_overlap_covered: T6,
    pub(super) native_epoch_reset: u64,
    pub(super) native_conflict: u64,
    pub(super) native_outside_open_turn: u64,
    pub(super) native_outside_open_turn_usage: T6,
    pub(super) native_after_turn_closed: u64,
    pub(super) native_after_turn_closed_usage: T6,
    pub(super) native_after_ui_flush: u64,
    pub(super) native_after_ui_flush_usage: T6,
    pub(super) ui_equal_total_repeat: u64,
    pub(super) ui_equal_total_repeat_usage: T6,
    pub(super) ui_in_native_turn_not_counted: u64,
    pub(super) ui_in_native_turn_not_counted_usage: T6,
    pub(super) ui_in_unbound_span: u64,
    pub(super) v2_cumulative_base_uncounted: u64,
    pub(super) v2_cumulative_base_uncounted_usage: T6,
    pub(super) turn_closure_mismatch: u64,
    pub(super) pending_overflow_flushes: u64,
}

struct NativeRecord {
    id: String,
    turn_id: Option<String>,
    usage: T6,
    before: T6,
    after: T6,
}

enum Staging {
    Staged,
    Dropped,
    Overflow,
}

fn strict_t6(value: &Value) -> Option<T6> {
    Some([
        value.get("input_tokens")?.as_u64()?,
        value.get("cached_input_tokens")?.as_u64()?,
        value
            .get("cache_write_input_tokens")
            .map_or(Some(0), Value::as_u64)?,
        value.get("output_tokens")?.as_u64()?,
        value.get("reasoning_output_tokens")?.as_u64()?,
        value.get("total_tokens")?.as_u64()?,
    ])
}

fn lenient_t6(value: &Value) -> T6 {
    let field = |name: &str| value.get(name).and_then(Value::as_u64).unwrap_or(0);
    [
        field("input_tokens"),
        field("cached_input_tokens"),
        field("cache_write_input_tokens"),
        field("output_tokens"),
        field("reasoning_output_tokens"),
        field("total_tokens"),
    ]
}

fn ui_t6_pair(value: &Value) -> Option<(T6, T6)> {
    let last = value
        .pointer("/token_count/info/last_token_usage")
        .or_else(|| value.pointer("/payload/info/last_token_usage"))
        .or_else(|| value.pointer("/payload/last_token_usage"))
        .or_else(|| value.pointer("/last_token_usage"))?;
    let total = value
        .pointer("/token_count/info/total_token_usage")
        .or_else(|| value.pointer("/payload/info/total_token_usage"))
        .or_else(|| value.pointer("/payload/total_token_usage"))
        .or_else(|| value.pointer("/total_token_usage"))?;
    Some((lenient_t6(last), lenient_t6(total)))
}

fn all_le(left: &T6, right: &T6) -> bool {
    left.iter().zip(right).all(|(l, r)| l <= r)
}

fn add_t6(sum: &mut T6, value: &T6) {
    for (slot, value) in sum.iter_mut().zip(value) {
        *slot = slot.saturating_add(*value);
    }
}

fn totals_t6(usage: &UsageTotals) -> T6 {
    [
        usage.input_tokens,
        usage.cache_read_tokens,
        usage.cache_creation_5m_tokens,
        usage.output_tokens,
        usage.reasoning_output_tokens,
        usage.input_tokens.saturating_add(usage.output_tokens),
    ]
}

fn native_money(money: &T6) -> UsageTotals {
    UsageTotals {
        input_tokens: money[0],
        cache_read_tokens: money[1],
        cache_creation_5m_tokens: money[2],
        output_tokens: money[3],
        reasoning_output_tokens: money[4],
        request_count: 1,
        ..UsageTotals::default()
    }
}

/// An owned native whose counter interval is self-consistent and whose
/// thread is this session. Anything else adds nothing, as today.
fn native_record(value: &Value, session: Option<&str>) -> Option<NativeRecord> {
    let payload = value.get("payload")?;
    let thread = resolve_codex_identity(payload.get("thread_id")?.as_str()?);
    if session.map(resolve_codex_identity).as_deref() != Some(thread.as_str()) {
        return None;
    }
    let id = payload.get("response_id")?.as_str()?;
    if id.is_empty() || id.len() > MAX_RESPONSE_ID_BYTES {
        return None;
    }
    let usage = strict_t6(payload.get("usage")?)?;
    let after = strict_t6(payload.get("thread_token_usage")?)?;
    let mut before = [0; 6];
    for (slot, (after, usage)) in before.iter_mut().zip(after.iter().zip(&usage)) {
        *slot = after.checked_sub(*usage)?;
    }
    Some(NativeRecord {
        id: id.to_owned(),
        turn_id: payload
            .get("turn_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        usage,
        before,
        after,
    })
}

impl OccurrenceReducer {
    /// Coverage disposition (first match wins); returns the money it adds.
    fn cover(&mut self, native: &NativeRecord) -> T6 {
        let NativeRecord {
            id,
            usage,
            before,
            after,
            ..
        } = native;
        if self
            .last_native
            .as_ref()
            .is_some_and(|last| last.id == *id && (last.usage != *usage || last.after != *after))
        {
            self.counters.native_conflict += 1;
        }
        self.last_native = Some(LastNative {
            id: id.clone(),
            usage: *usage,
            after: *after,
        });
        self.native_since_prev_ui = true;
        let open = || Epoch {
            base: *before,
            hwm: *after,
            first_id: id.clone(),
            contiguous: true,
        };
        let Some(epoch) = self.epoch.as_mut() else {
            self.epoch = Some(open());
            return *usage;
        };
        if *before == epoch.hwm {
            epoch.hwm = *after;
            return *usage;
        }
        let new_first_response = before.iter().all(|value| *value == 0) && *id != epoch.first_id;
        if all_le(&epoch.base, before) && all_le(after, &epoch.hwm) && !new_first_response {
            if epoch.contiguous {
                self.counters.native_restated += 1;
            } else {
                self.counters.native_inside_holed_coverage += 1;
                add_t6(&mut self.counters.native_inside_holed_coverage_usage, usage);
            }
            return [0; 6];
        }
        if all_le(&epoch.hwm, before) {
            self.counters.native_chain_gap += 1;
            epoch.hwm = *after;
            epoch.contiguous = false;
            return *usage;
        }
        if all_le(&epoch.hwm, after) && all_le(&epoch.base, before) {
            // Count only the uncovered part of each dimension.
            let mut money = [0; 6];
            for (dimension, slot) in money.iter_mut().enumerate() {
                *slot =
                    after[dimension].saturating_sub(before[dimension].max(epoch.hwm[dimension]));
            }
            let mut covered = *usage;
            for (slot, counted) in covered.iter_mut().zip(&money) {
                *slot = slot.saturating_sub(*counted);
            }
            self.counters.native_chain_overlap += 1;
            add_t6(&mut self.counters.native_chain_overlap_covered, &covered);
            epoch.hwm = *after;
            epoch.contiguous = false;
            return money;
        }
        self.counters.native_epoch_reset += 1;
        self.epoch = Some(open());
        *usage
    }

    fn note_ui(&mut self, tuple: Option<UiTuple>) {
        self.prev_ui = tuple;
        self.native_since_prev_ui = false;
    }
}

impl SnapshotAccumulator {
    pub(super) fn codex_counting_v2(&self) -> bool {
        self.codex_counting
            .as_ref()
            .is_some_and(|counting| counting.version == Some(CountingVersion::V2))
    }

    fn codex_occurrence(&mut self) -> Option<&mut OccurrenceReducer> {
        self.codex_counting.as_mut()?.reducer.as_mut()
    }

    /// Runs for every owned Codex line before the shared UI usage path. The
    /// first owned record fixes the session's counting version.
    pub(super) fn observe_codex_counting_line(
        &mut self,
        value: &Value,
        timestamp: Option<&str>,
        selector: &SelectorCapture,
    ) {
        let Some(counting) = self.codex_counting.as_mut() else {
            return;
        };
        if counting.version.is_none() {
            let version =
                codex_counting_version::decide(value, counting.evidence, counting.cutover_unix_ms);
            counting.version = Some(version);
            if version == CountingVersion::V2 {
                counting.reducer = Some(OccurrenceReducer::default());
            }
        }
        let Some(reducer) = counting.reducer.as_mut() else {
            return;
        };
        reducer.line_ui = ui_t6_pair(value);
        let event = string_at(value, &["payload", "type"]);
        match event.as_deref() {
            Some("task_started") => {
                self.close_codex_turn(None);
                let turn_id = string_at(value, &["payload", "turn_id"])
                    .filter(|id| !id.is_empty() && id.len() <= MAX_TURN_ID_BYTES);
                if let Some(reducer) = self.codex_occurrence() {
                    reducer.turn = turn_id.map(|id| BoundTurn {
                        id,
                        native: false,
                        ui_published: false,
                        staged_events: 0,
                        pending: OwnedMap::new(),
                    });
                }
            }
            Some("task_complete" | "turn_aborted") => {
                let closing = string_at(value, &["payload", "turn_id"]);
                self.close_codex_turn(closing.as_deref());
            }
            _ => {}
        }
        if string_eq_at(value, &["type"], "token_usage_record") {
            self.admit_codex_native(value, timestamp, selector);
        }
    }

    /// Closure publishes a UI-only turn's staged rows. A later native for the
    /// closed turn adds nothing, which is exactly the Legacy outcome.
    fn close_codex_turn(&mut self, closing_turn_id: Option<&str>) {
        let Some(reducer) = self.codex_occurrence() else {
            return;
        };
        let Some(turn) = reducer.turn.take() else {
            return;
        };
        if closing_turn_id.is_some_and(|closing| closing != turn.id) {
            reducer.counters.turn_closure_mismatch += 1;
        }
        let BoundTurn {
            id,
            native,
            ui_published,
            pending,
            ..
        } = turn;
        reducer.last_closed_turn = Some(id);
        if !native && !ui_published {
            self.publish_codex_pending(&pending);
        }
    }

    fn admit_codex_native(
        &mut self,
        value: &Value,
        timestamp: Option<&str>,
        selector: &SelectorCapture,
    ) {
        let native = native_record(value, self.source_session_id.as_deref());
        let Some(reducer) = self.codex_occurrence() else {
            return;
        };
        let Some(native) = native else {
            reducer.counters.native_not_authority += 1;
            return;
        };
        let mut money = reducer.cover(&native);
        let bound = reducer
            .turn
            .as_mut()
            .filter(|turn| native.turn_id.as_deref() == Some(turn.id.as_str()));
        match bound {
            Some(turn) if turn.ui_published => {
                reducer.counters.native_after_ui_flush += 1;
                add_t6(
                    &mut reducer.counters.native_after_ui_flush_usage,
                    &native.usage,
                );
                money = [0; 6];
            }
            Some(turn) => {
                if !turn.native {
                    turn.native = true;
                    let staged = std::mem::take(&mut turn.staged_events);
                    let pending = std::mem::replace(&mut turn.pending, OwnedMap::new());
                    reducer.counters.ui_in_native_turn_not_counted += staged;
                    for row in pending.values() {
                        add_t6(
                            &mut reducer.counters.ui_in_native_turn_not_counted_usage,
                            &totals_t6(&row.usage),
                        );
                    }
                }
            }
            None => {
                if native.turn_id.is_some() && native.turn_id == reducer.last_closed_turn {
                    reducer.counters.native_after_turn_closed += 1;
                    add_t6(
                        &mut reducer.counters.native_after_turn_closed_usage,
                        &native.usage,
                    );
                } else {
                    reducer.counters.native_outside_open_turn += 1;
                    add_t6(
                        &mut reducer.counters.native_outside_open_turn_usage,
                        &native.usage,
                    );
                }
                money = [0; 6];
            }
        }
        if money[..5].iter().all(|value| *value == 0) {
            return;
        }
        reducer.counters.native_counted += 1;
        let mut usage_selector = selector.clone();
        if self.current_turn_is_priority() {
            usage_selector.insert(
                "service_tier",
                "priority".to_string(),
                "derived_from_logs_2",
            );
        }
        let model = string_at(value, &["payload", "model"]);
        let applied_tier = self.codex_tier_replay.as_mut().and_then(|replay| {
            replay.selector(
                value,
                &mut usage_selector,
                &self.current_selector,
                model.as_deref().or(self.latest_model.as_deref()),
                self.latest_reasoning_effort.as_deref(),
                self.latest_turn_id.as_deref(),
            )
        });
        let effort = self.latest_reasoning_effort.clone();
        self.add_usage_with_selector(
            model,
            native_money(&money),
            usage_selector,
            timestamp,
            effort,
        );
        if let Some(replay) = self.codex_tier_replay.as_mut() {
            replay.admitted(applied_tier);
        }
    }

    /// V2 counterpart of the shared UI path. Returns the occurrence-admitted
    /// `last` (published, staged or native-turn) so the existing tier/curve
    /// consumers keep their meaning; repeats and exact duplicates are `None`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn set_codex_v2_cumulative_usage(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        last_usage: Option<UsageTotals>,
        usage_event_identity: Option<String>,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        implicit_request_count: Option<u64>,
        effort: Option<String>,
    ) -> Option<UsageTotals> {
        let resolved_model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.latest_model = Some(resolved_model.clone());
        if usage_event_identity.is_some()
            && usage_event_identity == self.codex_last_usage_event_identity
        {
            self.codex_duplicate_usage_records_skipped =
                self.codex_duplicate_usage_records_skipped.saturating_add(1);
            return None;
        }
        if usage_event_identity.is_some() {
            self.codex_last_usage_event_identity = usage_event_identity;
        }
        let previous = self.session_cumulative_usage.clone();
        let reset = previous
            .as_ref()
            .is_some_and(|previous| !usage.is_monotonic_after(previous));
        if reset {
            self.codex_cumulative_reset_count = self.codex_cumulative_reset_count.saturating_add(1);
        }
        // Today's delta: `last`, else the cumulative delta, else the whole
        // total on a first event or reset. A bound turn never counts that
        // inherited/reset base.
        let (legacy_delta, bound_delta) = match (&last_usage, &previous) {
            (Some(last), _) => (last.clone(), Some(last.clone())),
            (None, Some(previous)) if !reset => {
                let delta = usage.delta_from(previous);
                (delta.clone(), Some(delta))
            }
            (None, _) => (usage.clone(), None),
        };
        self.session_cumulative_usage = Some(usage.clone());
        let with_count = |mut delta: UsageTotals| {
            if !delta.is_zero() {
                if let Some(count) = implicit_request_count {
                    delta.request_count = count;
                }
            }
            delta
        };
        let legacy_delta = with_count(legacy_delta);
        if legacy_delta.is_zero() {
            return None;
        }
        let reducer = self.codex_occurrence()?;
        let tuple = reducer
            .line_ui
            .take()
            .zip(last_usage)
            .map(|((last_t6, total_t6), last)| UiTuple {
                last,
                total: usage,
                last_t6,
                total_t6,
            });
        if reducer.turn.is_none() {
            reducer.counters.ui_in_unbound_span += 1;
            reducer.note_ui(tuple);
            self.add_usage_with_selector(
                Some(resolved_model),
                legacy_delta.clone(),
                selector,
                timestamp,
                effort,
            );
            return Some(legacy_delta);
        }
        // Rule 2: same `last` and same total as the previous UI candidate with
        // no native between is a re-emission. A decreased total never matches.
        if !reducer.native_since_prev_ui && tuple.is_some() && tuple == reducer.prev_ui {
            reducer.counters.ui_equal_total_repeat += 1;
            add_t6(
                &mut reducer.counters.ui_equal_total_repeat_usage,
                &totals_t6(&legacy_delta),
            );
            return None;
        }
        reducer.note_ui(tuple);
        let Some(delta) = bound_delta.map(with_count).filter(|delta| !delta.is_zero()) else {
            reducer.counters.v2_cumulative_base_uncounted += 1;
            add_t6(
                &mut reducer.counters.v2_cumulative_base_uncounted_usage,
                &totals_t6(&legacy_delta),
            );
            return None;
        };
        let turn = reducer.turn.as_mut()?;
        if turn.native {
            reducer.counters.ui_in_native_turn_not_counted += 1;
            add_t6(
                &mut reducer.counters.ui_in_native_turn_not_counted_usage,
                &totals_t6(&delta),
            );
            return Some(delta);
        }
        if !turn.ui_published {
            match self.stage_codex_ui(
                &resolved_model,
                &delta,
                selector.clone(),
                timestamp,
                effort.as_deref(),
            ) {
                Staging::Staged | Staging::Dropped => return Some(delta),
                Staging::Overflow => {
                    let reducer = self.codex_occurrence()?;
                    reducer.counters.pending_overflow_flushes += 1;
                    let turn = reducer.turn.as_mut()?;
                    turn.ui_published = true;
                    let pending = std::mem::replace(&mut turn.pending, OwnedMap::new());
                    self.publish_codex_pending(&pending);
                }
            }
        }
        self.add_usage_with_selector(
            Some(resolved_model),
            delta.clone(),
            selector,
            timestamp,
            effort,
        );
        Some(delta)
    }

    /// Resolves the row exactly as publication would at this record, without
    /// publishing it. Row identity uses the current selector, not closure's.
    fn stage_codex_ui(
        &mut self,
        model: &str,
        usage: &UsageTotals,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        effort: Option<&str>,
    ) -> Staging {
        let bucket_input = timestamp
            .map(str::to_string)
            .or_else(|| self.fallback_bucket_timestamp(None));
        let Some((bucket_start, activity_at)) = bucket_input
            .as_deref()
            .and_then(activity_bucket_from_timestamp)
        else {
            self.note_dropped_usage();
            return Staging::Dropped;
        };
        let mut merged = self.current_selector.clone();
        merged.merge(selector);
        let (row_key, context, sources) = build_row_identity(model, &merged, effort);
        // Exact-capacity copies, so the content cap is also their heap bound.
        let bucket_start = bucket_start.as_str().to_owned();
        let activity_at = activity_at.as_str().to_owned();
        let content = pending_row_content_bytes(&bucket_start, &row_key, &context, &sources)
            .saturating_add(activity_at.len().saturating_mul(2));
        let Some(reducer) = self.codex_occurrence() else {
            return Staging::Overflow;
        };
        let Some(turn) = reducer.turn.as_mut() else {
            return Staging::Overflow;
        };
        let key = (bucket_start, row_key);
        let existing = turn.pending.contains_key(&key);
        if content > MAX_PENDING_ROW_CONTENT_BYTES
            || (!existing && turn.pending.len() >= MAX_PENDING_ROWS)
        {
            return Staging::Overflow;
        }
        if existing {
            let Some(mut row) = turn.pending.get_mut(&key) else {
                return Staging::Overflow;
            };
            // The row keeps the union of its sources: re-check the cap on it.
            let mut merged_sources = row.selector_sources.clone();
            merged_sources.extend(sources);
            let (bucket_start, row_key) = &key;
            let merged_content = pending_row_content_bytes(
                bucket_start,
                row_key,
                &row.selector_context,
                &merged_sources,
            )
            .saturating_add(activity_at.len().saturating_mul(2));
            if merged_content > MAX_PENDING_ROW_CONTENT_BYTES {
                return Staging::Overflow;
            }
            if !row.usage.add(usage) {
                return Staging::Overflow;
            }
            row.selector_sources = merged_sources;
            row.events = row.events.saturating_add(1);
            if timestamp_is_before(&activity_at, &row.first_activity_at) {
                row.first_activity_at = activity_at.clone();
            }
            if timestamp_is_after(&activity_at, &row.last_activity_at) {
                row.last_activity_at = activity_at;
            }
        } else {
            turn.pending.insert(
                key,
                PendingRow {
                    selector_context: context,
                    selector_sources: sources,
                    usage: usage.clone(),
                    events: 1,
                    first_activity_at: activity_at.clone(),
                    last_activity_at: activity_at,
                },
            );
        }
        turn.staged_events = turn.staged_events.saturating_add(1);
        Staging::Staged
    }

    /// Deferred publication of staged rows, row by row, with the same
    /// overflow refusal and bucket merge as immediate publication.
    fn publish_codex_pending(&mut self, pending: &OwnedMap<(String, RowKey), PendingRow>) {
        for ((bucket_start, row_key), row) in pending.iter() {
            if !self.accepted_usage_totals.add(&row.usage) {
                self.dropped_usage_record_count =
                    self.dropped_usage_record_count.saturating_add(row.events);
                continue;
            }
            let bucket = self.usage_buckets.entry(bucket_start.clone()).or_default();
            bucket.note_activity_at(&row.first_activity_at);
            bucket.note_activity_at(&row.last_activity_at);
            match bucket.rows.get_mut(row_key) {
                Some(existing) => {
                    for (field, source) in &row.selector_sources {
                        existing
                            .selector_sources
                            .insert(field.clone(), source.clone());
                    }
                    let row_added = existing.usage.add(&row.usage);
                    debug_assert!(row_added);
                }
                None => {
                    bucket.rows.insert(
                        row_key.clone(),
                        BucketRowAccumulator {
                            selector_context: row.selector_context.clone(),
                            selector_sources: row.selector_sources.clone(),
                            usage: row.usage.clone(),
                            reasoning_effort: row_key.reasoning_effort.clone(),
                        },
                    );
                }
            }
        }
    }
}

/// Byte length of every string a staged row and its key hold, excluding the
/// two activity times (charged by the caller).
fn pending_row_content_bytes(
    bucket_start: &str,
    key: &RowKey,
    context: &BTreeMap<String, String>,
    sources: &BTreeMap<String, String>,
) -> usize {
    let optional = |value: &Option<String>| value.as_ref().map_or(0, String::len);
    let map = |values: &BTreeMap<String, String>| {
        values.iter().fold(0usize, |sum, (key, value)| {
            sum.saturating_add(key.len()).saturating_add(value.len())
        })
    };
    [
        bucket_start.len(),
        key.model.len(),
        key.selector_hash.len(),
        optional(&key.reasoning_effort),
        optional(&key.auth_mode),
        optional(&key.billing_channel),
        optional(&key.billing_provider),
        optional(&key.gateway_provider),
        optional(&key.model_provider),
        optional(&key.subscription_product),
        map(context),
        map(sources),
    ]
    .into_iter()
    .fold(0usize, usize::saturating_add)
}

/// Requested-layout charge of a maximal staged turn: 64 rows at the content
/// cap, each with full selector maps, plus the outer row map's nodes.
#[cfg(test)]
pub(super) const fn max_pending_heap_bytes() -> usize {
    const fn nodes(entries: usize, key: usize, value: usize) -> usize {
        (entries + 1) * (256 + 12 * std::mem::size_of::<usize>() + 11 * (key + value))
    }
    let string = std::mem::size_of::<String>();
    let selector_map = nodes(SELECTOR_CONTEXT_ALLOWED.len(), string, string);
    nodes(
        MAX_PENDING_ROWS,
        std::mem::size_of::<(String, RowKey)>(),
        std::mem::size_of::<PendingRow>(),
    ) + MAX_PENDING_ROWS * (MAX_PENDING_ROW_CONTENT_BYTES + 2 * selector_map)
}

crate::heap_layout_bound::fields!(CodexCounting; evidence, cutover_unix_ms, version, reducer);
crate::heap_layout_bound::fields!(OccurrenceReducer; epoch, last_native, prev_ui, native_since_prev_ui, line_ui, turn, last_closed_turn, counters);
crate::heap_layout_bound::fields!(Epoch; base, hwm, first_id, contiguous);
crate::heap_layout_bound::fields!(LastNative; id, usage, after);
crate::heap_layout_bound::fields!(UiTuple; last, total, last_t6, total_t6);
crate::heap_layout_bound::fields!(BoundTurn; id, native, ui_published, staged_events, pending);
crate::heap_layout_bound::fields!(PendingRow; selector_context, selector_sources, usage, events, first_activity_at, last_activity_at);
crate::heap_layout_bound::fields!(OccurrenceCounters; native_counted, native_not_authority, native_restated, native_inside_holed_coverage, native_inside_holed_coverage_usage, native_chain_gap, native_chain_overlap, native_chain_overlap_covered, native_epoch_reset, native_conflict, native_outside_open_turn, native_outside_open_turn_usage, native_after_turn_closed, native_after_turn_closed_usage, native_after_ui_flush, native_after_ui_flush_usage, ui_equal_total_repeat, ui_equal_total_repeat_usage, ui_in_native_turn_not_counted, ui_in_native_turn_not_counted_usage, ui_in_unbound_span, v2_cumulative_base_uncounted, v2_cumulative_base_uncounted_usage, turn_closure_mismatch, pending_overflow_flushes);
