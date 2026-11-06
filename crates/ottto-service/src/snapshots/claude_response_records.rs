//! Retained form of Claude response records. A long session keeps every
//! usage-bearing content-block record until finish, so this form stores only
//! what decoding cannot rebuild exactly:
//! - the request slot's strings repeat the record's own request id,
//!   timestamp, model and effort (`claude_cache_request_slot`);
//! - text equal to the response's first record is a back-reference;
//! - selectors are interned once per file;
//! - tool uses keep their `BTreeMap` order as a sorted list.
//!
//! Every encoding is total: a value without a cheaper exact form is stored as
//! is. Resolution decodes each record back to `ClaudeResponseRecord` before
//! the unchanged response merge, so finalized output is identical by
//! construction.
//!
//! The decoded records, the per-response observation that retains them, and
//! the resolution that merges them live here too.
//!
//! Raw request, message and tool-use ids here (class `L`) are never uploaded
//! except where the upload contract already carries them; persisted only in
//! the local durable-tail store.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::owned_heap::{OwnedMap, OwnedVec, ValueGuard};
use std::collections::BTreeMap;

/// Distinct selectors interned per file. Sessions normally carry a handful;
/// past the cap a record keeps its own selector, so interning never refuses.
const MAX_INTERNED_SELECTORS: usize = 64;

/// Per-file Claude responses retained until finish: an index from the
/// response key to its slot, the responses in first-seen order, and the
/// file's interned selectors.
#[derive(Debug, Clone, Default)]
pub(super) struct ClaudeResponseBook {
    index: OwnedMap<String, u32>,
    responses: OwnedVec<ClaudeResponseObservation>,
    pub(super) selectors: ClaudeSelectorTable,
}

impl ClaudeResponseBook {
    /// Responses in first-seen order.
    pub(super) fn values(&self) -> std::slice::Iter<'_, ClaudeResponseObservation> {
        self.responses.iter()
    }

    /// Each slot's response key: the index inverted. Tail pages store a key
    /// beside its response, so the index re-derives from the pages.
    pub(super) fn slot_keys(&self) -> Vec<&str> {
        let mut keys = vec![""; self.responses.len()];
        for (key, slot) in self.index.iter() {
            if let Some(at) = keys.get_mut(*slot as usize) {
                *at = key.as_str();
            }
        }
        keys
    }

    pub(super) fn get_mut(
        &mut self,
        key: &str,
    ) -> Option<ValueGuard<'_, ClaudeResponseObservation>> {
        let slot = *self.index.get(key)?;
        self.responses.get_mut(slot as usize)
    }

    /// Adds a response under a key that is not yet present. Returns false,
    /// retaining nothing, if its slot cannot be indexed.
    pub(super) fn insert(&mut self, key: String, response: ClaudeResponseObservation) -> bool {
        let Ok(slot) = u32::try_from(self.responses.len()) else {
            return false;
        };
        self.index.insert(key, slot);
        self.responses.push(response);
        true
    }

    pub(super) fn into_parts(self) -> (Vec<ClaudeResponseObservation>, ClaudeSelectorTable) {
        (self.responses.into_vec(), self.selectors)
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ClaudeSelectorTable {
    selectors: OwnedVec<SelectorCapture>,
}

impl ClaudeSelectorTable {
    /// Equal selectors (context and sources) share one entry. Equality is by
    /// value, never "same as the previous record", so record order and the
    /// last-writer `sources` merge are untouched.
    pub(super) fn intern(&mut self, selector: SelectorCapture) -> CompactClaudeSelector {
        if let Some(index) = self.selectors.iter().rposition(|known| *known == selector) {
            return CompactClaudeSelector::Interned(index as u32);
        }
        if self.selectors.len() >= MAX_INTERNED_SELECTORS {
            return CompactClaudeSelector::Inline(Box::new(selector));
        }
        self.selectors.push(selector);
        CompactClaudeSelector::Interned((self.selectors.len() - 1) as u32)
    }

    fn decode(&self, selector: CompactClaudeSelector) -> Option<SelectorCapture> {
        match selector {
            CompactClaudeSelector::Interned(index) => self.selectors.get(index as usize).cloned(),
            CompactClaudeSelector::Inline(selector) => Some(*selector),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum CompactClaudeSelector {
    Interned(u32),
    Inline(Box<SelectorCapture>),
}
crate::durable_tail_codec::durable_enum!(CompactClaudeSelector {
    0 => Interned(N x0: u32),
    1 => Inline(D x0: Box<SelectorCapture>),
});

impl From<SelectorCapture> for CompactClaudeSelector {
    fn from(selector: SelectorCapture) -> Self {
        Self::Inline(Box::new(selector))
    }
}

/// Text stored as a back-reference when it equals the response's first record.
#[derive(Debug, Clone)]
enum ClaudeRecordText {
    SameAsFirstRecord,
    Own(Option<String>),
}
crate::durable_tail_codec::durable_enum!(ClaudeRecordText {
    0 => SameAsFirstRecord,
    1 => Own(P x0: Option<String>),
});

impl ClaudeRecordText {
    fn encode(value: Option<String>, first: Option<&Self>) -> Self {
        match first {
            Some(Self::Own(first)) if *first == value => Self::SameAsFirstRecord,
            _ => Self::Own(value),
        }
    }

    fn get<'a>(&'a self, first: Option<&'a Self>) -> Option<&'a Option<String>> {
        match self {
            Self::Own(value) => Some(value),
            Self::SameAsFirstRecord => match first? {
                Self::Own(value) => Some(value),
                Self::SameAsFirstRecord => None,
            },
        }
    }

    /// A back-reference without a first record cannot be decoded and fails
    /// the response closed.
    fn decode(self, first: Option<&Option<String>>) -> Option<Option<String>> {
        match self {
            Self::SameAsFirstRecord => first.cloned(),
            Self::Own(value) => Some(value),
        }
    }
}

/// `UsageTotals` with the cost block boxed: Claude transcript rows normally
/// carry no costs, and the default block decodes back to the default value.
#[derive(Debug, Clone)]
struct CompactClaudeUsage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_5m_tokens: u64,
    cache_creation_1h_tokens: u64,
    reasoning_output_tokens: u64,
    unattributed_total_tokens: u64,
    request_count: u64,
    costs: Option<Box<UsageCosts>>,
}

impl CompactClaudeUsage {
    fn encode(usage: UsageTotals) -> Self {
        let UsageTotals {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_creation_5m_tokens,
            cache_creation_1h_tokens,
            reasoning_output_tokens,
            unattributed_total_tokens,
            request_count,
            costs,
        } = usage;
        Self {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_creation_5m_tokens,
            cache_creation_1h_tokens,
            reasoning_output_tokens,
            unattributed_total_tokens,
            request_count,
            costs: (costs != UsageCosts::default()).then(|| Box::new(costs)),
        }
    }

    fn decode(self) -> UsageTotals {
        let Self {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_creation_5m_tokens,
            cache_creation_1h_tokens,
            reasoning_output_tokens,
            unattributed_total_tokens,
            request_count,
            costs,
        } = self;
        UsageTotals {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_creation_5m_tokens,
            cache_creation_1h_tokens,
            reasoning_output_tokens,
            unattributed_total_tokens,
            request_count,
            costs: costs.map_or_else(UsageCosts::default, |costs| *costs),
        }
    }
}

#[derive(Debug, Clone)]
struct ClaudeSlotTokens {
    prompt_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_creation_tokens: Option<u64>,
    uncached_tokens: Option<u64>,
    output_tokens: Option<u64>,
}

/// The record's request slot. `Derived` keeps only the token counts; its
/// strings are rebuilt from the record's decoded fields. Any other slot is
/// kept whole.
#[derive(Debug, Clone)]
enum ClaudeSlot {
    Derived(ClaudeSlotTokens),
    Explicit(Box<RequestSlot>),
}
crate::durable_tail_codec::durable_enum!(ClaudeSlot {
    0 => Derived(N x0: ClaudeSlotTokens),
    1 => Explicit(D x0: Box<RequestSlot>),
});

impl ClaudeSlot {
    fn encode(
        slot: RequestSlot,
        request_id: &Option<String>,
        timestamp: &Option<String>,
        model: &Option<String>,
        effort: &Option<String>,
    ) -> Self {
        let derived = slot.request_ref == request_id.as_deref().unwrap_or_default()
            && slot.occurred_at == timestamp.as_deref().unwrap_or_default()
            && slot.model == *model
            && slot.effort == *effort;
        if !derived {
            return Self::Explicit(Box::new(slot));
        }
        let RequestSlot {
            request_ref: _,
            occurred_at: _,
            model: _,
            effort: _,
            prompt_tokens,
            cache_read_tokens,
            cache_creation_tokens,
            uncached_tokens,
            output_tokens,
        } = slot;
        Self::Derived(ClaudeSlotTokens {
            prompt_tokens,
            cache_read_tokens,
            cache_creation_tokens,
            uncached_tokens,
            output_tokens,
        })
    }

    fn decode(
        self,
        request_id: &Option<String>,
        timestamp: &Option<String>,
        model: &Option<String>,
        effort: &Option<String>,
    ) -> RequestSlot {
        let tokens = match self {
            Self::Explicit(slot) => return *slot,
            Self::Derived(tokens) => tokens,
        };
        let ClaudeSlotTokens {
            prompt_tokens,
            cache_read_tokens,
            cache_creation_tokens,
            uncached_tokens,
            output_tokens,
        } = tokens;
        RequestSlot {
            request_ref: request_id.clone().unwrap_or_default(),
            occurred_at: timestamp.clone().unwrap_or_default(),
            model: model.clone(),
            effort: effort.clone(),
            prompt_tokens,
            cache_read_tokens,
            cache_creation_tokens,
            uncached_tokens,
            output_tokens,
        }
    }
}

/// Retained form of one `ClaudeResponseRecord`.
#[derive(Debug, Clone)]
pub(super) struct CompactClaudeResponseRecord {
    usage: CompactClaudeUsage,
    slot: ClaudeSlot,
    physical_sequence: u16,
    model: ClaudeRecordText,
    reasoning_effort: ClaudeRecordText,
    request_id: ClaudeRecordText,
    timestamp: Option<String>,
    computed_effective_input_context: Option<u64>,
    selector: CompactClaudeSelector,
    tool_uses: Vec<ClaudeToolUse>,
}

/// One retained tool use: the provider tool-use id apart from the tool
/// name, so a durable record's `L` span is the id alone.
#[derive(Debug, Clone)]
struct ClaudeToolUse {
    id: String,
    name: String,
}

impl CompactClaudeResponseRecord {
    /// `first` is the response's first retained record, absent for that
    /// record itself. `position` is its index in the response. Decoding reads
    /// that index from the vector; the saved field keeps its old width, so past
    /// `u16::MAX` it saturates.
    #[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
    pub(super) fn encode(
        first: Option<&Self>,
        position: usize,
        usage: UsageTotals,
        model: Option<String>,
        selector: CompactClaudeSelector,
        reasoning_effort: Option<String>,
        request_id: Option<String>,
        timestamp: Option<String>,
        computed_effective_input_context: Option<u64>,
        tool_uses: BTreeMap<String, String>,
        cache_slot: RequestSlot,
    ) -> Self {
        let slot = ClaudeSlot::encode(
            cache_slot,
            &request_id,
            &timestamp,
            &model,
            &reasoning_effort,
        );
        Self {
            usage: CompactClaudeUsage::encode(usage),
            slot,
            physical_sequence: u16::try_from(position).unwrap_or(u16::MAX),
            model: ClaudeRecordText::encode(model, first.map(|first| &first.model)),
            reasoning_effort: ClaudeRecordText::encode(
                reasoning_effort,
                first.map(|first| &first.reasoning_effort),
            ),
            request_id: ClaudeRecordText::encode(request_id, first.map(|first| &first.request_id)),
            timestamp,
            computed_effective_input_context,
            selector,
            tool_uses: tool_uses
                .into_iter()
                .map(|(id, name)| ClaudeToolUse { id, name })
                .collect(),
        }
    }

    /// The provider request id `decode` would yield, borrowed without
    /// decoding. `first` is the response's first retained record. A
    /// back-reference without one cannot occur (the first record is always
    /// encoded with its own text) and reads as no id.
    pub(super) fn request_id<'a>(&'a self, first: Option<&'a Self>) -> Option<&'a str> {
        self.request_id
            .get(first.map(|first| &first.request_id))?
            .as_deref()
    }

    fn decode(
        self,
        position: usize,
        first: Option<&ClaudeResponseRecord>,
        selectors: &ClaudeSelectorTable,
    ) -> Option<ClaudeResponseRecord> {
        let Self {
            usage,
            slot,
            physical_sequence: _,
            model,
            reasoning_effort,
            request_id,
            timestamp,
            computed_effective_input_context,
            selector,
            tool_uses,
        } = self;
        let model = model.decode(first.map(|first| &first.model))?;
        let reasoning_effort =
            reasoning_effort.decode(first.map(|first| &first.reasoning_effort))?;
        let request_id = request_id.decode(first.map(|first| &first.request_id))?;
        let cache_slot = slot.decode(&request_id, &timestamp, &model, &reasoning_effort);
        Some(ClaudeResponseRecord {
            cache_slot,
            physical_sequence: position as u64,
            usage: usage.decode(),
            model,
            selector: selectors.decode(selector)?,
            reasoning_effort,
            request_id,
            timestamp,
            computed_effective_input_context,
            tool_uses: tool_uses
                .into_iter()
                .map(|ClaudeToolUse { id, name }| (id, name))
                .collect(),
        })
    }
}

/// Decode one response's records in physical order. Any record that cannot
/// be decoded exactly fails the whole response closed.
pub(super) fn decode_records(
    records: Vec<CompactClaudeResponseRecord>,
    selectors: &ClaudeSelectorTable,
) -> Option<Vec<ClaudeResponseRecord>> {
    let mut decoded: Vec<ClaudeResponseRecord> = Vec::with_capacity(records.len());
    for (position, record) in records.into_iter().enumerate() {
        let record = record.decode(position, decoded.first(), selectors)?;
        decoded.push(record);
    }
    Some(decoded)
}

impl HeapLayoutBound for ClaudeRecordText {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::SameAsFirstRecord => c.add(0),
            Self::Own(value) => value.heap_bound(c),
        }
    }
}
impl HeapLayoutBound for CompactClaudeSelector {
    fn stable_heap(&self) -> bool {
        match self {
            Self::Interned(_) => true,
            Self::Inline(selector) => selector.stable_heap(),
        }
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::Interned(_) => c.add(0),
            Self::Inline(selector) => selector.heap_bound(c),
        }
    }
}
impl HeapLayoutBound for ClaudeSlot {
    fn stable_heap(&self) -> bool {
        match self {
            Self::Derived(tokens) => tokens.stable_heap(),
            Self::Explicit(slot) => slot.stable_heap(),
        }
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::Derived(tokens) => tokens.heap_bound(c),
            Self::Explicit(slot) => slot.heap_bound(c),
        }
    }
}
crate::heap_layout_bound::fields!(ClaudeResponseBook; index, responses, selectors);
crate::durable_tail_codec::durable_struct!(ClaudeResponseBook {
    L index: OwnedMap<String, u32>,
    D responses: OwnedVec<ClaudeResponseObservation>,
    D selectors: ClaudeSelectorTable,
});
crate::heap_layout_bound::fields!(ClaudeSelectorTable; selectors);
crate::durable_tail_codec::durable_struct!(ClaudeSelectorTable {
    D selectors: OwnedVec<SelectorCapture>,
});
crate::heap_layout_bound::fields!(CompactClaudeUsage; input_tokens, output_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, reasoning_output_tokens, unattributed_total_tokens, request_count, costs);
crate::durable_tail_codec::durable_struct!(CompactClaudeUsage {
    N input_tokens: u64,
    N output_tokens: u64,
    N cache_read_tokens: u64,
    N cache_creation_5m_tokens: u64,
    N cache_creation_1h_tokens: u64,
    N reasoning_output_tokens: u64,
    N unattributed_total_tokens: u64,
    N request_count: u64,
    N costs: Option<Box<UsageCosts>>,
});
crate::heap_layout_bound::fields!(ClaudeSlotTokens; prompt_tokens, cache_read_tokens, cache_creation_tokens, uncached_tokens, output_tokens);
crate::durable_tail_codec::durable_struct!(ClaudeSlotTokens {
    N prompt_tokens: Option<u64>,
    N cache_read_tokens: Option<u64>,
    N cache_creation_tokens: Option<u64>,
    N uncached_tokens: Option<u64>,
    N output_tokens: Option<u64>,
});
crate::heap_layout_bound::fields!(ClaudeToolUse; id, name);
crate::durable_tail_codec::durable_struct!(ClaudeToolUse {
    L id: String,
    U name: String,
});
crate::heap_layout_bound::fields!(CompactClaudeResponseRecord; usage, slot, physical_sequence, model, reasoning_effort, request_id, timestamp, computed_effective_input_context, selector, tool_uses);
crate::durable_tail_codec::durable_struct!(CompactClaudeResponseRecord {
    N usage: CompactClaudeUsage,
    D slot: ClaudeSlot,
    N physical_sequence: u16,
    U model: ClaudeRecordText,
    U reasoning_effort: ClaudeRecordText,
    L request_id: ClaudeRecordText,
    N timestamp: Option<String>,
    N computed_effective_input_context: Option<u64>,
    D selector: CompactClaudeSelector,
    D tool_uses: Vec<ClaudeToolUse>,
});

/// One physical Claude transcript observation for a provider response. Claude
/// can append an earlier progressive content-block observation after a later
/// one, so response-local observations are retained until the file is complete
/// and then ordered by their provider timestamps. They are retained in the
/// compact form of `claude_response_records` and decoded back to this form
/// before resolution.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ClaudeResponseRecord {
    pub(super) cache_slot: RequestSlot,
    pub(super) physical_sequence: u64,
    pub(super) usage: UsageTotals,
    pub(super) model: Option<String>,
    pub(super) selector: SelectorCapture,
    pub(super) reasoning_effort: Option<String>,
    pub(super) request_id: Option<String>,
    pub(super) timestamp: Option<String>,
    pub(super) computed_effective_input_context: Option<u64>,
    pub(super) tool_uses: BTreeMap<String, String>,
}

// Response-local buffering repairs provider-time ordering, so it grows with the
// file's usage-bearing lines and never refuses one. Above this size the
// finalizer only counts a hit: it gates nothing.
pub(super) const CLAUDE_RECORDS_PER_FILE_ALARM: usize = 65_536;

/// One Claude provider response assembled from its content-block transcript
/// records. Usage is withheld from the session projection until this response
/// is complete, canonically ordered, and internally consistent.
#[derive(Debug, Clone)]
pub(super) struct ClaudeResponseObservation {
    pub(super) sequence: u64,
    preceding_user_timestamp: Option<String>,
    pub(super) records: crate::owned_heap::OwnedVec<CompactClaudeResponseRecord>,
    /// Never set any more. A book saved while the record caps existed may
    /// carry it: that book lost records, so it stays retryable until a cold
    /// read, which now keeps them all.
    record_limit_exceeded: bool,
    pub(super) desktop_request: bool,
    /// `e2::RULE_EPOCH` at the request's first admission; a later record of
    /// the same request keeps it.
    pub(super) rule_epoch: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct ResolvedClaudeResponse {
    pub(super) cache_slot: RequestSlot,
    pub(super) sequence: u64,
    pub(super) usage: UsageTotals,
    pub(super) model: Option<String>,
    pub(super) selector: SelectorCapture,
    pub(super) reasoning_effort: Option<String>,
    pub(super) request_id: Option<String>,
    pub(super) first_timestamp: Option<String>,
    pub(super) terminal_timestamp: Option<String>,
    pub(super) event_clock_complete: bool,
    pub(super) desktop_request: bool,
    pub(super) preceding_user_timestamp: Option<String>,
    pub(super) computed_effective_input_context: Option<u64>,
    pub(super) tool_uses: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaudeTranscriptUsageOccurrence {
    pub(super) sequence: u64,
    pub(super) usage: UsageTotals,
    pub(super) model: Option<String>,
    // Shared: a page retains every occurrence until upload, and nearly all of a
    // session's requests carry an identical selector.
    pub(super) selector: Arc<SelectorCapture>,
    pub(super) reasoning_effort: Option<String>,
    pub(super) timestamp: Option<String>,
    // Evaluated before response folding can retain a stamped partial. Local only.
    pub(super) event_clock_complete: bool,
    pub(super) desktop_request: bool,
    pub(super) effective_input_context: u64,
    /// Page-local `e2` outcome; neither persisted nor sent.
    pub(super) telemetry_attached: bool,
}

/// Why a retained Claude response has no resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaudeResolveFailure {
    /// A compact record no longer decodes against the file's selector table,
    /// or a restored book already lost records.
    Decode,
    /// Incompatible observations: the native resolver's conflict.
    Conflict,
}

impl ClaudeResponseObservation {
    #[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
    pub(super) fn new(
        sequence: u64,
        usage: UsageTotals,
        model: Option<String>,
        selector: impl Into<CompactClaudeSelector>,
        reasoning_effort: Option<String>,
        request_id: Option<String>,
        timestamp: Option<String>,
        preceding_user_timestamp: Option<String>,
        computed_effective_input_context: Option<u64>,
        tool_uses: BTreeMap<String, String>,
        cache_slot: RequestSlot,
    ) -> Self {
        Self {
            sequence,
            preceding_user_timestamp,
            records: vec![CompactClaudeResponseRecord::encode(
                None,
                0,
                usage,
                model,
                selector.into(),
                reasoning_effort,
                request_id,
                timestamp,
                computed_effective_input_context,
                tool_uses,
                cache_slot,
            )]
            .into(),
            record_limit_exceeded: false,
            desktop_request: false,
            rule_epoch: claude_request_money::e2::RULE_EPOCH,
        }
    }

    #[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
    pub(super) fn push(
        &mut self,
        usage: UsageTotals,
        model: Option<String>,
        selector: impl Into<CompactClaudeSelector>,
        reasoning_effort: Option<String>,
        request_id: Option<String>,
        timestamp: Option<String>,
        computed_effective_input_context: Option<u64>,
        tool_uses: BTreeMap<String, String>,
        cache_slot: RequestSlot,
    ) {
        let record = CompactClaudeResponseRecord::encode(
            self.records.first(),
            self.records.len(),
            usage,
            model,
            selector.into(),
            reasoning_effort,
            request_id,
            timestamp,
            computed_effective_input_context,
            tool_uses,
            cache_slot,
        );
        self.records.push(record);
    }

    #[cfg(test)]
    pub(super) fn resolve_with(
        self,
        selectors: &ClaudeSelectorTable,
    ) -> Option<ResolvedClaudeResponse> {
        self.resolve_classified(selectors).ok()
    }

    /// Resolve against the file's selector table, telling why a response
    /// has no resolution.
    pub(super) fn resolve_classified(
        self,
        selectors: &ClaudeSelectorTable,
    ) -> Result<ResolvedClaudeResponse, ClaudeResolveFailure> {
        if self.record_limit_exceeded {
            return Err(ClaudeResolveFailure::Decode);
        }
        let mut records =
            claude_response_records::decode_records(self.records.into_vec(), selectors)
                .ok_or(ClaudeResolveFailure::Decode)?;
        // Provider time is authoritative only when it proves a complete order
        // for this response. Mixed valid/missing timestamps retain physical
        // append order, preserving the conservative legacy behavior instead
        // of moving a stamped terminal record ahead of an unstamped partial.
        let event_clock_complete = records
            .iter()
            .all(|record| claude_response_provider_time(record).is_some());
        if event_clock_complete {
            records.sort_by(claude_response_record_order);
        } else {
            records.sort_by_key(|record| record.physical_sequence);
        }
        let mut canonical_records: Vec<ClaudeResponseRecord> = Vec::new();
        for record in records {
            if canonical_records.last().is_some_and(|previous| {
                claude_response_records_share_provider_time(previous, &record)
            }) {
                // Same-instant observations are ordered by their cumulative
                // usage tuple, then collapsed to that instant's terminal state.
                // Incomparable tuples still fail the progressive merge below.
                if !merge_claude_response_record(
                    canonical_records.last_mut().expect("record exists"),
                    record,
                ) {
                    return Err(ClaudeResolveFailure::Conflict);
                }
            } else {
                canonical_records.push(record);
            }
        }

        let mut records = canonical_records.into_iter();
        let mut aggregate = records.next().ok_or(ClaudeResolveFailure::Conflict)?;
        let first_timestamp = aggregate.timestamp.clone();
        for record in records {
            if !merge_claude_response_record(&mut aggregate, record) {
                return Err(ClaudeResolveFailure::Conflict);
            }
        }
        Ok(ResolvedClaudeResponse {
            cache_slot: aggregate.cache_slot,
            sequence: self.sequence,
            usage: aggregate.usage,
            model: aggregate.model,
            selector: aggregate.selector,
            reasoning_effort: aggregate.reasoning_effort,
            request_id: aggregate.request_id,
            first_timestamp,
            terminal_timestamp: aggregate.timestamp,
            event_clock_complete,
            desktop_request: self.desktop_request,
            preceding_user_timestamp: self.preceding_user_timestamp,
            computed_effective_input_context: aggregate.computed_effective_input_context,
            tool_uses: aggregate.tool_uses,
        })
    }
}

fn merge_claude_response_record(
    current: &mut ClaudeResponseRecord,
    next: ClaudeResponseRecord,
) -> bool {
    if !claude_usage_is_progressive_after(&next.usage, &current.usage)
        || !merge_optional_claude_field(&mut current.model, next.model)
        || !merge_optional_claude_field(&mut current.reasoning_effort, next.reasoning_effort)
        || !merge_optional_claude_field(&mut current.request_id, next.request_id)
        || !merge_claude_response_selector(&mut current.selector, next.selector)
        || !merge_claude_response_tool_uses(&mut current.tool_uses, next.tool_uses)
    {
        return false;
    }
    current.cache_slot = next.cache_slot;
    current.usage = next.usage;
    if let Some(next_context) = next.computed_effective_input_context {
        current.computed_effective_input_context = Some(
            current
                .computed_effective_input_context
                .map_or(next_context, |value| value.max(next_context)),
        );
    }
    if next.timestamp.is_some() {
        current.timestamp = next.timestamp;
    }
    true
}

fn claude_response_record_order(
    left: &ClaudeResponseRecord,
    right: &ClaudeResponseRecord,
) -> Ordering {
    match (
        claude_response_provider_time(left),
        claude_response_provider_time(right),
    ) {
        (Some(left_time), Some(right_time)) => left_time
            .cmp(&right_time)
            .then_with(|| claude_usage_deterministic_order(&left.usage, &right.usage))
            .then_with(|| left.physical_sequence.cmp(&right.physical_sequence)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        // Preserve append order for missing or malformed timestamps. There is
        // no provider chronology to justify reordering these observations.
        (None, None) => left.physical_sequence.cmp(&right.physical_sequence),
    }
}

fn claude_response_provider_time(record: &ClaudeResponseRecord) -> Option<OffsetDateTime> {
    record
        .timestamp
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
}

fn claude_usage_deterministic_order(left: &UsageTotals, right: &UsageTotals) -> Ordering {
    left.input_tokens
        .cmp(&right.input_tokens)
        .then_with(|| left.output_tokens.cmp(&right.output_tokens))
        .then_with(|| left.cache_read_tokens.cmp(&right.cache_read_tokens))
        .then_with(|| {
            left.cache_creation_5m_tokens
                .cmp(&right.cache_creation_5m_tokens)
        })
        .then_with(|| {
            left.cache_creation_1h_tokens
                .cmp(&right.cache_creation_1h_tokens)
        })
        .then_with(|| {
            left.reasoning_output_tokens
                .cmp(&right.reasoning_output_tokens)
        })
        .then_with(|| {
            left.unattributed_total_tokens
                .cmp(&right.unattributed_total_tokens)
        })
        .then_with(|| left.request_count.cmp(&right.request_count))
        .then_with(|| left.costs.observed.cmp(&right.costs.observed))
        .then_with(|| left.costs.reported.cmp(&right.costs.reported))
        .then_with(|| left.costs.total.cmp(&right.costs.total))
        .then_with(|| left.costs.input.cmp(&right.costs.input))
        .then_with(|| left.costs.output.cmp(&right.costs.output))
        .then_with(|| left.costs.cache_read.cmp(&right.costs.cache_read))
        .then_with(|| left.costs.cache_creation.cmp(&right.costs.cache_creation))
}

fn claude_response_records_share_provider_time(
    left: &ClaudeResponseRecord,
    right: &ClaudeResponseRecord,
) -> bool {
    match (
        claude_response_provider_time(left),
        claude_response_provider_time(right),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn merge_claude_response_tool_uses(
    current: &mut BTreeMap<String, String>,
    next: BTreeMap<String, String>,
) -> bool {
    for (tool_use_id, name) in next {
        if current
            .get(&tool_use_id)
            .is_some_and(|existing| existing != &name)
        {
            return false;
        }
        current.insert(tool_use_id, name);
    }
    true
}

fn merge_optional_claude_field(current: &mut Option<String>, next: Option<String>) -> bool {
    match (current.as_ref(), next) {
        (Some(current), Some(next)) if current != &next => false,
        (None, Some(next)) => {
            *current = Some(next);
            true
        }
        _ => true,
    }
}

fn merge_claude_response_selector(current: &mut SelectorCapture, next: SelectorCapture) -> bool {
    for (field, value) in &next.context {
        if current
            .context
            .get(field)
            .is_some_and(|existing| existing != value)
        {
            return false;
        }
    }
    current.merge(next);
    true
}

/// Claude content-block records progressively fill cumulative response usage.
/// Recent Fable writers can begin with zero input/cache counters and populate
/// them on a later provider timestamp, so every counter must be monotonic; a
/// chronological regression remains unsafe and fails the whole response.
fn claude_usage_is_progressive_after(current: &UsageTotals, previous: &UsageTotals) -> bool {
    current.input_tokens >= previous.input_tokens
        && current.output_tokens >= previous.output_tokens
        && current.cache_read_tokens >= previous.cache_read_tokens
        && current.cache_creation_5m_tokens >= previous.cache_creation_5m_tokens
        && current.cache_creation_1h_tokens >= previous.cache_creation_1h_tokens
        && current.reasoning_output_tokens >= previous.reasoning_output_tokens
        && current.unattributed_total_tokens >= previous.unattributed_total_tokens
        && current.request_count >= previous.request_count
        && current.costs.is_monotonic_after(&previous.costs)
}

crate::heap_layout_bound::fields!(ClaudeResponseRecord; cache_slot, physical_sequence, usage, model, selector, reasoning_effort, request_id, timestamp, computed_effective_input_context, tool_uses);
crate::heap_layout_bound::fields!(ClaudeResponseObservation; sequence, preceding_user_timestamp, records, record_limit_exceeded, desktop_request, rule_epoch);
crate::durable_tail_codec::durable_struct!(ClaudeResponseObservation {
    N sequence: u64,
    N preceding_user_timestamp: Option<String>,
    D records: crate::owned_heap::OwnedVec<CompactClaudeResponseRecord>,
    N record_limit_exceeded: bool,
    N desktop_request: bool,
    N rule_epoch: u8,
});
crate::heap_layout_bound::fields!(ClaudeTranscriptUsageOccurrence; sequence, usage, model, selector, reasoning_effort, timestamp, event_clock_complete, desktop_request, effective_input_context, telemetry_attached);

#[cfg(test)]
mod output_tests {
    use super::*;

    /// A retained tool use is `{L id, U name}`. Its only `L`
    /// span is the id, so an id copied into the name half would sit outside
    /// every `L` span and fail the privacy canary.
    #[test]
    fn tool_use_l_span_is_the_id_alone() {
        use crate::durable_tail_codec::{take_l_spans, Durable, Enc};
        let id = "toolu_CANARYSPLITdt";
        let name = "toolu_NAMEHALFdt";
        let tool_uses = vec![ClaudeToolUse {
            id: id.into(),
            name: name.into(),
        }];
        take_l_spans();
        let body = Enc::count_write(1 << 10, |e| tool_uses.put(e)).unwrap();
        let spans = take_l_spans();
        assert_eq!(spans.len(), 1, "{spans:?}");
        let (start, end, path) = spans[0];
        assert_eq!(path, "ClaudeToolUse.id");
        let at = |needle: &str| {
            body.windows(needle.len())
                .position(|window| window == needle.as_bytes())
                .unwrap()
        };
        assert!(start <= at(id) && at(id) + id.len() <= end);
        assert!(at(name) >= end || at(name) + name.len() <= start);
    }
}
