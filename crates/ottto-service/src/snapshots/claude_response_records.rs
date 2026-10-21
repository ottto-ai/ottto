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
use super::{
    ClaudeResponseObservation, ClaudeResponseRecord, RequestSlot, SelectorCapture, UsageCosts,
    UsageTotals,
};
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
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }

    pub(super) fn contains_key(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// Responses in first-seen order.
    #[cfg(test)]
    pub(super) fn values(&self) -> std::slice::Iter<'_, ClaudeResponseObservation> {
        self.responses.iter()
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

impl ClaudeRecordText {
    fn encode(value: Option<String>, first: Option<&Self>) -> Self {
        match first {
            Some(Self::Own(first)) if *first == value => Self::SameAsFirstRecord,
            _ => Self::Own(value),
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
    tool_uses: Vec<(String, String)>,
}

impl CompactClaudeResponseRecord {
    /// `first` is the response's first retained record, absent for that
    /// record itself.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn encode(
        first: Option<&Self>,
        physical_sequence: u16,
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
            physical_sequence,
            model: ClaudeRecordText::encode(model, first.map(|first| &first.model)),
            reasoning_effort: ClaudeRecordText::encode(
                reasoning_effort,
                first.map(|first| &first.reasoning_effort),
            ),
            request_id: ClaudeRecordText::encode(request_id, first.map(|first| &first.request_id)),
            timestamp,
            computed_effective_input_context,
            selector,
            tool_uses: tool_uses.into_iter().collect(),
        }
    }

    fn decode(
        self,
        first: Option<&ClaudeResponseRecord>,
        selectors: &ClaudeSelectorTable,
    ) -> Option<ClaudeResponseRecord> {
        let Self {
            usage,
            slot,
            physical_sequence,
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
            physical_sequence: u64::from(physical_sequence),
            usage: usage.decode(),
            model,
            selector: selectors.decode(selector)?,
            reasoning_effort,
            request_id,
            timestamp,
            computed_effective_input_context,
            tool_uses: tool_uses.into_iter().collect(),
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
    for record in records {
        let record = record.decode(decoded.first(), selectors)?;
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
crate::heap_layout_bound::fields!(ClaudeSelectorTable; selectors);
crate::heap_layout_bound::fields!(CompactClaudeUsage; input_tokens, output_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, reasoning_output_tokens, unattributed_total_tokens, request_count, costs);
crate::heap_layout_bound::fields!(ClaudeSlotTokens; prompt_tokens, cache_read_tokens, cache_creation_tokens, uncached_tokens, output_tokens);
crate::heap_layout_bound::fields!(CompactClaudeResponseRecord; usage, slot, physical_sequence, model, reasoning_effort, request_id, timestamp, computed_effective_input_context, selector, tool_uses);
