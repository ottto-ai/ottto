//! Codex usage counting V2: one billed request is counted once at its native
//! usage. Local only: never uploaded except where the upload contract
//! already carries it; persisted only in the local durable-tail store (raw
//! response and turn ids are class `L`). Legacy sessions never construct this
//! state.
//!
//! Native `token_usage_record`s are the authority for their turn. Coverage on
//! the native thread counter (`[before, after)`, six dimensions) decides what
//! a native adds; a response id is a conflict detector only. UI `token_count`
//! events add money only in a bound turn that has no native, published when
//! the turn closes, or in an unbound span with today's rule. Published money
//! is a monotone function of the record prefix: nothing is ever subtracted.
#[cfg(test)]
mod rss_test_support;

use super::codex_counting_version::{self, AckEvidence, CountingVersion};
use super::*;
use crate::codex_scan_diagnostics::CountingV2Receipts;
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
/// Recently closed turn ids kept for closure finality. A native or a
/// `task_started` for one of them can never reopen native authority.
pub(super) const MAX_CLOSED_TURN_IDS: usize = 64;
/// Counting-contract size of the per-session filter of EVERY closed turn id
/// (COST round 2): 8 KiB, four bit positions per id from SHA-256 (no process
/// seed), so membership is a pure function of the record prefix. It has no
/// false negatives; a hit outside the exact ring is unconfirmed (a reopen
/// beyond 64 closures, or a false positive) and only zeroes natives.
pub(super) const CLOSED_TURN_FILTER_BYTES: usize = 8 * 1024;
const CLOSED_TURN_FILTER_HASHES: usize = 4;
const CLOSED_TURN_FILTER_WORDS: usize = CLOSED_TURN_FILTER_BYTES / 8;
const MAX_RESPONSE_ID_BYTES: usize = 256;

/// `input, cached_input, cache_write_input, output, reasoning_output, total`.
pub(super) type T6 = [u64; 6];

#[derive(Clone)]
pub(super) struct CodexCounting {
    evidence: AckEvidence,
    cutover_unix_ms: Option<i64>,
    version: Option<CountingVersion>,
    /// Boxed: a Legacy decision keeps only the pointer slot.
    reducer: Option<Box<OccurrenceReducer>>,
}

impl CodexCounting {
    pub(super) fn durable_cutover(&self) -> Option<i64> {
        self.cutover_unix_ms
    }

    pub(super) fn durable_contract(&self) -> (Option<i64>, u8, u8) {
        (
            self.cutover_unix_ms,
            match self.version {
                None => 0,
                Some(CountingVersion::Legacy) => 1,
                Some(CountingVersion::V2) => 2,
            },
            match self.evidence {
                AckEvidence::None => 0,
                AckEvidence::V2Marked => 1,
                AckEvidence::LegacyAcked => 2,
            },
        )
    }

    pub(super) fn new(evidence: AckEvidence, cutover_unix_ms: Option<i64>) -> Self {
        Self {
            evidence,
            cutover_unix_ms,
            version: None,
            reducer: None,
        }
    }

    pub(super) fn content_scratch(&self) -> Self {
        Self {
            evidence: self.evidence,
            cutover_unix_ms: self.cutover_unix_ms,
            version: self.version,
            reducer: (self.version == Some(CountingVersion::V2)).then(Box::default),
        }
    }

    /// Local, content-free receipts for the diagnostics owner to fold in
    /// before the accumulator is consumed (no consumer yet: activation gate).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn counters(&self) -> Option<&OccurrenceCounters> {
        self.reducer.as_ref().map(|reducer| &reducer.counters)
    }

    /// UI money staged in a still-open UI-only turn: visible local debt,
    /// never published on a timer.
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

    /// Adds this parse's receipts and open-turn debt to the scan's local
    /// diagnostics. A Legacy decision adds nothing.
    pub(super) fn fold_receipts(&self, into: &mut CountingV2Receipts) {
        let Some(reducer) = self.reducer.as_deref() else {
            return;
        };
        let count = |slot: &mut u64, value: u64| *slot = slot.saturating_add(value);
        let usage = |slot: &mut T6, value: &T6| {
            for (slot, value) in slot.iter_mut().zip(value) {
                *slot = slot.saturating_add(*value);
            }
        };
        let c = &reducer.counters;
        count(&mut into.v2_sessions, 1);
        count(&mut into.native_counted, c.native_counted);
        count(&mut into.native_not_authority, c.native_not_authority);
        count(&mut into.native_restated, c.native_restated);
        count(
            &mut into.native_inside_holed_coverage,
            c.native_inside_holed_coverage,
        );
        usage(
            &mut into.native_inside_holed_coverage_usage,
            &c.native_inside_holed_coverage_usage,
        );
        count(&mut into.native_chain_gap, c.native_chain_gap);
        count(&mut into.native_chain_overlap, c.native_chain_overlap);
        usage(
            &mut into.native_chain_overlap_covered,
            &c.native_chain_overlap_covered,
        );
        count(&mut into.native_epoch_reset, c.native_epoch_reset);
        count(&mut into.native_conflict, c.native_conflict);
        count(
            &mut into.native_outside_open_turn,
            c.native_outside_open_turn,
        );
        usage(
            &mut into.native_outside_open_turn_usage,
            &c.native_outside_open_turn_usage,
        );
        count(
            &mut into.native_after_turn_closed,
            c.native_after_turn_closed,
        );
        usage(
            &mut into.native_after_turn_closed_usage,
            &c.native_after_turn_closed_usage,
        );
        count(&mut into.native_after_ui_flush, c.native_after_ui_flush);
        usage(
            &mut into.native_after_ui_flush_usage,
            &c.native_after_ui_flush_usage,
        );
        count(&mut into.ui_equal_total_repeat, c.ui_equal_total_repeat);
        usage(
            &mut into.ui_equal_total_repeat_usage,
            &c.ui_equal_total_repeat_usage,
        );
        count(
            &mut into.ui_in_native_turn_not_counted,
            c.ui_in_native_turn_not_counted,
        );
        usage(
            &mut into.ui_in_native_turn_not_counted_usage,
            &c.ui_in_native_turn_not_counted_usage,
        );
        count(&mut into.ui_in_unbound_span, c.ui_in_unbound_span);
        count(
            &mut into.v2_cumulative_base_uncounted,
            c.v2_cumulative_base_uncounted,
        );
        usage(
            &mut into.v2_cumulative_base_uncounted_usage,
            &c.v2_cumulative_base_uncounted_usage,
        );
        count(&mut into.turn_closure_mismatch, c.turn_closure_mismatch);
        count(&mut into.turn_reopened, c.turn_reopened);
        count(
            &mut into.closed_filter_hit_unconfirmed,
            c.closed_filter_hit_unconfirmed,
        );
        usage(
            &mut into.closed_filter_hit_unconfirmed_native_usage,
            &c.closed_filter_hit_unconfirmed_native_usage,
        );
        count(
            &mut into.pending_overflow_flushes,
            c.pending_overflow_flushes,
        );
        let Some(turn) = reducer.turn.as_ref().filter(|turn| turn.staged_events > 0) else {
            return;
        };
        count(&mut into.open_turn_ui_pending_sessions_this_scan, 1);
        count(
            &mut into.open_turn_ui_pending_events_this_scan,
            turn.staged_events,
        );
        match self.open_turn_ui_pending() {
            Some((_, staged)) => usage(
                &mut into.open_turn_ui_pending_usage_this_scan,
                &totals_t6(&staged),
            ),
            None => count(&mut into.open_turn_ui_pending_unsummable_this_scan, 1),
        }
    }

    /// A retained reduction may continue under fresh evidence only when that
    /// evidence would have selected the same rule (B handoff H4).
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
    /// Oldest first, at most `MAX_CLOSED_TURN_IDS`.
    closed_turns: VecDeque<String>,
    /// Every closed turn id; allocated at the first closure, never cleared.
    closed_filter: Option<ClosedTurnFilter>,
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
    pub(super) turn_reopened: u64,
    pub(super) closed_filter_hit_unconfirmed: u64,
    pub(super) closed_filter_hit_unconfirmed_native_usage: T6,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Closed {
    No,
    /// In the exact ring of recent closures.
    Recent,
    /// Filter hit only: an older closure or a false positive.
    Unconfirmed,
}

#[derive(Clone)]
struct ClosedTurnFilter(Box<[u64; CLOSED_TURN_FILTER_WORDS]>);
crate::durable_tail_codec::durable_struct!(ClosedTurnFilter(L x0: Box<[u64; CLOSED_TURN_FILTER_WORDS]>));

impl ClosedTurnFilter {
    fn new() -> Self {
        Self(Box::new([0; CLOSED_TURN_FILTER_WORDS]))
    }

    fn positions(turn_id: &str) -> [usize; CLOSED_TURN_FILTER_HASHES] {
        let mut hasher = Sha256::new();
        hasher.update(b"codex_closed_turn:v1\0");
        hasher.update(turn_id.as_bytes());
        let digest = hasher.finalize();
        let mut positions = [0; CLOSED_TURN_FILTER_HASHES];
        for (index, position) in positions.iter_mut().enumerate() {
            // 16 bits address exactly the filter's 8 KiB * 8 bits.
            *position = usize::from(u16::from_be_bytes([
                digest[2 * index],
                digest[2 * index + 1],
            ]));
        }
        positions
    }

    fn insert(&mut self, turn_id: &str) {
        for position in Self::positions(turn_id) {
            self.0[position / 64] |= 1 << (position % 64);
        }
    }

    fn contains(&self, turn_id: &str) -> bool {
        Self::positions(turn_id)
            .into_iter()
            .all(|position| self.0[position / 64] & (1 << (position % 64)) != 0)
    }
}

/// One fixed allocation, charged in one visit (not one per word).
impl crate::heap_layout_bound::HeapLayoutBound for ClosedTurnFilter {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(
            std::mem::size_of::<[u64; CLOSED_TURN_FILTER_WORDS]>()
                + std::mem::align_of::<[u64; CLOSED_TURN_FILTER_WORDS]>(),
        )
    }
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

    /// Enters a closed id into the filter and, once, into the exact ring.
    fn remember_closed(&mut self, id: String) {
        self.closed_filter
            .get_or_insert_with(ClosedTurnFilter::new)
            .insert(&id);
        if self.closed_turns.contains(&id) {
            return;
        }
        if self.closed_turns.len() >= MAX_CLOSED_TURN_IDS {
            self.closed_turns.pop_front();
        }
        self.closed_turns.push_back(id);
    }

    fn closed(&self, turn_id: &str) -> Closed {
        if self.closed_turns.iter().any(|closed| closed == turn_id) {
            Closed::Recent
        } else if self
            .closed_filter
            .as_ref()
            .is_some_and(|filter| filter.contains(turn_id))
        {
            Closed::Unconfirmed
        } else {
            Closed::No
        }
    }
}

impl SnapshotAccumulator {
    pub(super) fn codex_counting_v2(&self) -> bool {
        self.codex_counting
            .as_ref()
            .is_some_and(|counting| counting.version == Some(CountingVersion::V2))
    }

    fn codex_occurrence(&mut self) -> Option<&mut OccurrenceReducer> {
        self.codex_counting.as_mut()?.reducer.as_deref_mut()
    }

    /// Runs for every owned Codex line before the shared UI usage path. The
    /// first owned record fixes the session's counting version.
    pub(super) fn observe_codex_counting_line(
        &mut self,
        value: &Value,
        timestamp: Option<&str>,
        selector: &SelectorCapture,
    ) {
        self.observe_codex_turn_lifecycle(value, true);
        if string_eq_at(value, &["type"], "token_usage_record") {
            self.admit_codex_native(value, timestamp, selector);
        }
    }

    fn observe_codex_turn_lifecycle(&mut self, value: &Value, publish: bool) {
        let Some(counting) = self.codex_counting.as_mut() else {
            return;
        };
        if counting.version.is_none() {
            let version =
                codex_counting_version::decide(value, counting.evidence, counting.cutover_unix_ms);
            counting.version = Some(version);
            if version == CountingVersion::V2 {
                counting.reducer = Some(Box::default());
            }
        }
        let Some(reducer) = counting.reducer.as_mut() else {
            return;
        };
        reducer.line_ui = ui_t6_pair(value);
        let event = string_at(value, &["payload", "type"]);
        match event.as_deref() {
            Some("task_started") => {
                if let Some(pending) = self.close_codex_turn_content(None) {
                    if publish {
                        self.publish_codex_pending(&pending);
                    }
                }
                let turn_id = string_at(value, &["payload", "turn_id"])
                    .filter(|id| !id.is_empty() && id.len() <= MAX_TURN_ID_BYTES);
                if let Some(reducer) = self.codex_occurrence() {
                    // Closure is final: a closed id reopens only as an unbound
                    // span (Legacy UI, natives 0), never as a new turn.
                    let closed = turn_id
                        .as_deref()
                        .map_or(Closed::No, |id| reducer.closed(id));
                    match closed {
                        Closed::Recent => reducer.counters.turn_reopened += 1,
                        Closed::Unconfirmed => reducer.counters.closed_filter_hit_unconfirmed += 1,
                        Closed::No => {}
                    }
                    reducer.turn = turn_id
                        .filter(|_| closed == Closed::No)
                        .map(|id| BoundTurn {
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
                if let Some(pending) = self.close_codex_turn_content(closing.as_deref()) {
                    if publish {
                        self.publish_codex_pending(&pending);
                    }
                }
            }
            _ => {}
        }
    }

    pub(super) fn observe_codex_content_counting(&mut self, value: &Value) {
        self.observe_codex_turn_lifecycle(value, false);
        if string_eq_at(value, &["type"], "token_usage_record") {
            let _ = self.note_codex_native_authority(value);
        }
    }

    /// Closure publishes a UI-only turn's staged rows. A later native for the
    /// closed turn adds nothing, which is exactly the Legacy outcome. Every
    /// explicit closure is final, including one whose start was never bound.
    fn close_codex_turn_content(
        &mut self,
        closing_turn_id: Option<&str>,
    ) -> Option<OwnedMap<(String, RowKey), PendingRow>> {
        let reducer = self.codex_occurrence()?;
        let closing = closing_turn_id.filter(|id| !id.is_empty() && id.len() <= MAX_TURN_ID_BYTES);
        let Some(turn) = reducer.turn.take() else {
            if let Some(closing) = closing {
                reducer.remember_closed(closing.to_owned());
            }
            return None;
        };
        if closing_turn_id.is_some_and(|closing| closing != turn.id) {
            reducer.counters.turn_closure_mismatch += 1;
            if let Some(closing) = closing {
                reducer.remember_closed(closing.to_owned());
            }
        }
        let BoundTurn {
            id,
            native,
            ui_published,
            pending,
            ..
        } = turn;
        reducer.remember_closed(id);
        (!native && !ui_published).then_some(pending)
    }

    fn admit_codex_native(
        &mut self,
        value: &Value,
        timestamp: Option<&str>,
        selector: &SelectorCapture,
    ) {
        let Some((native, money)) = self.note_codex_native_authority(value) else {
            return;
        };
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
        // Match the UI price stamp after tier replay, on this row only. Codex
        // input already includes cached input; price the original request's
        // prompt, even when coverage admits only part of its usage.
        if !usage_selector.context.contains_key("context_bucket") {
            if let Some(bucket) = model
                .as_deref()
                .or(self.latest_model.as_deref())
                .and_then(|model| provider_context_bucket(model, native.usage[0], timestamp))
            {
                usage_selector.insert(
                    "context_bucket",
                    bucket.to_string(),
                    "derived_from_native_usage",
                );
            }
        }
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

    fn note_codex_native_authority(&mut self, value: &Value) -> Option<(NativeRecord, T6)> {
        let native = native_record(value, self.source_session_id.as_deref());
        let reducer = self.codex_occurrence()?;
        let Some(native) = native else {
            reducer.counters.native_not_authority += 1;
            return None;
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
                let closed = native
                    .turn_id
                    .as_deref()
                    .map_or(Closed::No, |turn| reducer.closed(turn));
                let (count, usage) = match closed {
                    Closed::Recent => (
                        &mut reducer.counters.native_after_turn_closed,
                        &mut reducer.counters.native_after_turn_closed_usage,
                    ),
                    Closed::Unconfirmed => (
                        &mut reducer.counters.closed_filter_hit_unconfirmed,
                        &mut reducer.counters.closed_filter_hit_unconfirmed_native_usage,
                    ),
                    Closed::No => (
                        &mut reducer.counters.native_outside_open_turn,
                        &mut reducer.counters.native_outside_open_turn_usage,
                    ),
                };
                *count += 1;
                add_t6(usage, &native.usage);
                money = [0; 6];
            }
        }
        if money[..5].iter().all(|value| *value == 0) {
            return None;
        }
        reducer.counters.native_counted += 1;
        Some((native, money))
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
        let (resolved_model, delta, bound) = self.decide_codex_usage(
            model,
            usage,
            last_usage,
            usage_event_identity,
            implicit_request_count,
        )?;
        if !bound {
            self.add_usage_with_selector(
                Some(resolved_model),
                delta.clone(),
                selector,
                timestamp,
                effort,
            );
            return Some(delta);
        }
        let reducer = self.codex_occurrence()?;
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
                    turn.staged_events = 0;
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

    /// Shared admission decision, with no publication/staging. `false` is
    /// the unbound span admitted before the bound equal-total repeat filter.
    pub(super) fn decide_codex_usage(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        last_usage: Option<UsageTotals>,
        usage_event_identity: Option<String>,
        implicit_request_count: Option<u64>,
    ) -> Option<(String, UsageTotals, bool)> {
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
            return Some((resolved_model, legacy_delta, false));
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
        Some((resolved_model, delta, true))
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

/// Heap charge of the fixed reducer state at its id caps: the boxed reducer,
/// two response ids, the open turn id, the closed-turn ring and the filter.
pub(super) const fn max_fixed_heap_bytes() -> usize {
    std::mem::size_of::<OccurrenceReducer>()
        + std::mem::align_of::<OccurrenceReducer>()
        + 2 * MAX_RESPONSE_ID_BYTES
        + MAX_TURN_ID_BYTES
        + MAX_CLOSED_TURN_IDS * (std::mem::size_of::<String>() + MAX_TURN_ID_BYTES)
        + CLOSED_TURN_FILTER_BYTES
        + std::mem::align_of::<u64>()
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
crate::durable_tail_codec::durable_struct!(CodexCounting {
    N evidence: AckEvidence,
    N cutover_unix_ms: Option<i64>,
    N version: Option<CountingVersion>,
    D reducer: Option<Box<OccurrenceReducer>>,
});
crate::heap_layout_bound::fields!(OccurrenceReducer; epoch, last_native, prev_ui, native_since_prev_ui, line_ui, turn, closed_turns, closed_filter, counters);
crate::durable_tail_codec::durable_struct!(OccurrenceReducer {
    D epoch: Option<Epoch>,
    D last_native: Option<LastNative>,
    N prev_ui: Option<UiTuple>,
    N native_since_prev_ui: bool,
    N line_ui: Option<(T6, T6)>,
    D turn: Option<BoundTurn>,
    L closed_turns: VecDeque<String>,
    // A membership filter over closed turn ids: a nested type whose one
    // field is L (provider ids; it carries strictly less than the ids, so
    // it is L, not H (F1)).
    D closed_filter: Option<ClosedTurnFilter>,
    N counters: OccurrenceCounters,
});
crate::heap_layout_bound::fields!(Epoch; base, hwm, first_id, contiguous);
crate::durable_tail_codec::durable_struct!(Epoch {
    N base: T6,
    N hwm: T6,
    L first_id: String,
    N contiguous: bool,
});
crate::heap_layout_bound::fields!(LastNative; id, usage, after);
crate::durable_tail_codec::durable_struct!(LastNative {
    L id: String,
    N usage: T6,
    N after: T6,
});
crate::heap_layout_bound::fields!(UiTuple; last, total, last_t6, total_t6);
crate::durable_tail_codec::durable_struct!(UiTuple {
    N last: UsageTotals,
    N total: UsageTotals,
    N last_t6: T6,
    N total_t6: T6,
});
crate::heap_layout_bound::fields!(BoundTurn; id, native, ui_published, staged_events, pending);
crate::durable_tail_codec::durable_struct!(BoundTurn {
    L id: String,
    N native: bool,
    N ui_published: bool,
    N staged_events: u64,
    D pending: OwnedMap<(String, RowKey), PendingRow>,
});
crate::heap_layout_bound::fields!(PendingRow; selector_context, selector_sources, usage, events, first_activity_at, last_activity_at);
crate::durable_tail_codec::durable_struct!(PendingRow {
    U selector_context: BTreeMap<String, String>,
    U selector_sources: BTreeMap<String, String>,
    N usage: UsageTotals,
    N events: u64,
    N first_activity_at: String,
    N last_activity_at: String,
});
crate::heap_layout_bound::fields!(OccurrenceCounters; native_counted, native_not_authority, native_restated, native_inside_holed_coverage, native_inside_holed_coverage_usage, native_chain_gap, native_chain_overlap, native_chain_overlap_covered, native_epoch_reset, native_conflict, native_outside_open_turn, native_outside_open_turn_usage, native_after_turn_closed, native_after_turn_closed_usage, native_after_ui_flush, native_after_ui_flush_usage, ui_equal_total_repeat, ui_equal_total_repeat_usage, ui_in_native_turn_not_counted, ui_in_native_turn_not_counted_usage, ui_in_unbound_span, v2_cumulative_base_uncounted, v2_cumulative_base_uncounted_usage, turn_closure_mismatch, turn_reopened, closed_filter_hit_unconfirmed, closed_filter_hit_unconfirmed_native_usage, pending_overflow_flushes);
crate::durable_tail_codec::durable_struct!(OccurrenceCounters {
    N native_counted: u64,
    N native_not_authority: u64,
    N native_restated: u64,
    N native_inside_holed_coverage: u64,
    N native_inside_holed_coverage_usage: T6,
    N native_chain_gap: u64,
    N native_chain_overlap: u64,
    N native_chain_overlap_covered: T6,
    N native_epoch_reset: u64,
    N native_conflict: u64,
    N native_outside_open_turn: u64,
    N native_outside_open_turn_usage: T6,
    N native_after_turn_closed: u64,
    N native_after_turn_closed_usage: T6,
    N native_after_ui_flush: u64,
    N native_after_ui_flush_usage: T6,
    N ui_equal_total_repeat: u64,
    N ui_equal_total_repeat_usage: T6,
    N ui_in_native_turn_not_counted: u64,
    N ui_in_native_turn_not_counted_usage: T6,
    N ui_in_unbound_span: u64,
    N v2_cumulative_base_uncounted: u64,
    N v2_cumulative_base_uncounted_usage: T6,
    N turn_closure_mismatch: u64,
    N turn_reopened: u64,
    N closed_filter_hit_unconfirmed: u64,
    N closed_filter_hit_unconfirmed_native_usage: T6,
    N pending_overflow_flushes: u64,
});

#[cfg(test)]
mod content_decision_tests {
    use super::*;
    #[test]
    fn unbound_equal_totals_precede_bound_repeat_filter_and_physical_duplicates() {
        for bound in [false, true] {
            let mut acc = SnapshotAccumulator::new(SnapshotSource::Codex);
            let mut counting = CodexCounting::new(AckEvidence::None, None);
            counting.version = Some(CountingVersion::V2);
            counting.reducer = Some(Box::default());
            acc.codex_counting = Some(Box::new(counting));
            if bound {
                acc.observe_codex_content_counting(
                    &serde_json::json!({"payload":{"type":"task_started","turn_id":"t"}}),
                );
            }
            let usage = UsageTotals {
                input_tokens: 10,
                output_tokens: 2,
                request_count: 1,
                ..Default::default()
            };
            for (identity, admitted) in [("a", true), ("b", !bound), ("b", false)] {
                acc.codex_occurrence().unwrap().line_ui =
                    Some(([10, 0, 0, 2, 0, 12], [10, 0, 0, 2, 0, 12]));
                assert_eq!(
                    acc.decide_codex_usage(
                        None,
                        usage.clone(),
                        Some(usage.clone()),
                        Some(identity.into()),
                        Some(1)
                    )
                    .is_some(),
                    admitted
                );
            }
            assert!(
                acc.usage_buckets.is_empty(),
                "scratch decisions cannot publish or stage money"
            );
            assert!(acc
                .codex_occurrence()
                .unwrap()
                .turn
                .as_ref()
                .is_none_or(|turn| turn.pending.is_empty()));
        }
    }
}
