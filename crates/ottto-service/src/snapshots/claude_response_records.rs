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
//! Raw request, message and tool-use ids here (class `L`) are never uploaded
//! except where the upload contract already carries them; persisted only in
//! the local durable-tail store.
use super::cache_observations::OwnedRequest;
use super::{
    BucketRowAccumulator, ClaudeResponseObservation, ClaudeResponseRecord,
    ClaudeTranscriptUsageOccurrence, RequestSlot, RowKey, SelectorCapture, SnapshotModelUsage,
    SnapshotToolUsage, SnapshotUsageBucket, UsageBucketState, UsageCosts, UsageTotals,
    ROW_BILLING_FIELDS, SELECTOR_CONTEXT_ALLOWED,
};
use crate::heap_layout_bound::{tree_node_bytes, Counter, HeapLayoutBound};
use crate::owned_heap::{OwnedMap, OwnedVec, ValueGuard};
use std::collections::BTreeMap;
use std::mem::{align_of, size_of};
use std::sync::Arc;

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

    /// Completion-only preflight, before cloning or decoding. The existing
    /// budget has already charged the entire active compact book, selectors,
    /// other accumulator fields, residents and reader. Its two equal shares
    /// fund a retained copy and finish/output. Deducting the extra peak from
    /// BOTH shares conservatively leaves that peak funded alongside both.
    /// None declines only optional retention; native output remains unchanged.
    pub(super) fn finish_copy_budget(&self, budget: usize) -> Option<usize> {
        budget.checked_sub(self.decode_peak_bound(budget)?)
    }

    /// Responses are resolved serially, so reserve the largest response, not
    /// every decoded record in the file. The compact input backing storage and
    /// unprocessed responses remain covered by the active charge throughout.
    pub(super) fn decode_peak_bound(&self, limit: usize) -> Option<usize> {
        self.completion_bounds(limit).map(|bounds| bounds.peak)
    }

    /// `decode_peak_bound`'s peak, and from the same pass what finalizing the
    /// responses adds to the finished file (X_out family R, #665). Only the
    /// peak decides `None`, exactly where it did before the output term
    /// existed; an output that cannot be bounded within `limit` is
    /// `output: None` and never changes the peak.
    pub(super) fn completion_bounds(&self, limit: usize) -> Option<CompletionBounds> {
        if self.responses.is_empty() {
            return Some(CompletionBounds {
                peak: 0,
                output: Some(0),
                fold: Some(FoldKeys::default()),
            });
        }
        if !crate::heap_layout_bound::layout_supported() {
            return None;
        }
        let mut peak = 0;
        let mut output = Some(BookOutput::default());
        for response in self.responses.iter() {
            // A response over the record limit resolves to nothing (only a
            // dropped-usage count), so it adds no output either.
            if !response.record_limit_exceeded {
                let response = decoded_response_bounds(&response.records, &self.selectors, limit)?;
                peak = peak.max(response.peak);
                output = output
                    .zip(response.output)
                    .and_then(|(book, response)| book.add(response, limit));
            }
        }
        // finalize_claude_responses sorts the response vector before decoding;
        // this scratch never overlaps the per-response decode/sort scratch.
        let response_sort = self
            .responses
            .len()
            .checked_mul(std::mem::size_of::<ClaudeResponseObservation>())?;
        let peak = peak.max(response_sort);
        (peak <= limit).then(|| {
            let bytes = output.and_then(|book| book.bytes(limit));
            CompletionBounds {
                peak,
                output: bytes,
                fold: output.filter(|_| bytes.is_some()).map(|book| book.fold),
            }
        })
    }

    pub(super) fn into_parts(self) -> (Vec<ClaudeResponseObservation>, ClaudeSelectorTable) {
        (self.responses.into_vec(), self.selectors)
    }
}

/// `ClaudeResponseBook::completion_bounds`: #667's decode peak, and the
/// finish-output term of the book's responses (X_out family R, #665).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CompletionBounds {
    /// `decode_peak_bound`'s value.
    pub(super) peak: usize,
    /// What `finalize_claude_responses_e2` and `into_items` build from
    /// these responses, with their finalize scratch; `None` when it cannot
    /// be bounded.
    pub(super) output: Option<usize>,
    /// What a gate-on E2 fold's grain keys copy from the same responses;
    /// present exactly when `output` is.
    pub(super) fold: Option<FoldKeys>,
}

/// The responses' share of a gate-on E2 fold's grain keys (`live_key`),
/// for X_out's E term: every response its own key, worst case.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct FoldKeys {
    pub(super) responses: usize,
    /// Responses naming no model: each a `model_fallbacks` entry.
    pub(super) modelless: usize,
    /// The largest model a response names.
    pub(super) max_model: usize,
    /// Context text a key can copy from its response: the selector's
    /// context, a `context_bucket`, the effort and its `reasoning_effort`
    /// key. The file's base selector is the caller's.
    pub(super) context_strings: usize,
    /// Context entries from the response, each key capped at
    /// `KEY_CONTEXT_FIELDS`.
    pub(super) context_entries: usize,
}

/// A key's context keeps allow-listed selector keys and the hoisted billing
/// fields (`build_row_identity`, `live_key`); `reasoning_effort` is the
/// caller's one more.
pub(super) const KEY_CONTEXT_FIELDS: usize =
    SELECTOR_CONTEXT_ALLOWED.len() + ROW_BILLING_FIELDS.len();

/// Live copies of one usage row's strings and maps (X_out family R): the
/// accumulator's row and the bucket and session `SnapshotModelUsage` clones
/// `into_items` emits. The other two are the retired Claude attribution
/// rebalancer's clone and fallback row, still charged until the X_out owner
/// re-proves the bound without them.
pub(super) const ROW_COPIES: usize = 5;
/// A `time` RFC 3339 text: at most 35 bytes (four-digit year, nine fraction
/// digits, a `+hh:mm` offset) in a buffer grown to at most twice that.
pub(super) const RFC3339_TEXT_BYTES: usize = 128;
/// `build_row_identity`'s `selector_hash`: 16 hex digits, or "base".
const ROW_SELECTOR_HASH_BYTES: usize = 16;
/// The `context_bucket` selector `finalize_claude_responses_e2` may
/// insert: its key in both maps, "long" or "short", and its source text.
const CONTEXT_BUCKET_BYTES: usize =
    2 * "context_bucket".len() + "short".len() + "derived_from_effective_input_volume".len();
/// `sha256_hex`'s `format!` text (64 hex digits, buffer at most twice that).
pub(super) const SHA256_HEX_TEXT_BYTES: usize = 128;
/// `serde_json::to_string`'s initial buffer.
const JSON_TEXT_MIN_BYTES: usize = 128;

/// One record's decoded bound (#667, unchanged) and its output term.
struct RecordBounds {
    decoded: usize,
    output: Option<ResponseOutput>,
}

/// One response's decode peak (#667, unchanged) and merged output term.
struct ResponseBounds {
    peak: usize,
    output: Option<ResponseOutput>,
}

/// A response's strings in the merge's real direction (`resolve_with`,
/// `merge_claude_response_record`; R1a R3): the response keeps one record's
/// first-non-None text (model, effort, request id) and one record's
/// last-writer slot and timestamp, so those are the largest over its
/// records; the selector and tool uses are unions, so those are sums.
#[derive(Debug, Default, Clone, Copy)]
struct ResponseOutput {
    records: usize,
    model: usize,
    effort: usize,
    request_id: usize,
    timestamp: usize,
    slot: usize,
    selector_bytes: usize,
    /// Context plus sources entries.
    selector_entries: usize,
    /// The context map's share of `selector_bytes` and `selector_entries`.
    context_bytes: usize,
    context_entries: usize,
    tool_bytes: usize,
    tool_entries: usize,
}

impl ResponseOutput {
    fn merge(self, record: Self) -> Option<Self> {
        let Self {
            records,
            model,
            effort,
            request_id,
            timestamp,
            slot,
            selector_bytes,
            selector_entries,
            context_bytes,
            context_entries,
            tool_bytes,
            tool_entries,
        } = record;
        Some(Self {
            records: self.records.checked_add(records)?,
            model: self.model.max(model),
            effort: self.effort.max(effort),
            request_id: self.request_id.max(request_id),
            timestamp: self.timestamp.max(timestamp),
            slot: self.slot.max(slot),
            selector_bytes: self.selector_bytes.checked_add(selector_bytes)?,
            selector_entries: self.selector_entries.checked_add(selector_entries)?,
            context_bytes: self.context_bytes.checked_add(context_bytes)?,
            context_entries: self.context_entries.checked_add(context_entries)?,
            tool_bytes: self.tool_bytes.checked_add(tool_bytes)?,
            tool_entries: self.tool_entries.checked_add(tool_entries)?,
        })
    }
}

/// The book's output term, summed over its responses (X_out family R). Tree
/// nodes are counted as entries (roots included) and charged once, at the
/// summed count, in `bytes` (R1a R4).
#[derive(Debug, Default, Clone, Copy)]
struct BookOutput {
    responses: usize,
    max_model: usize,
    strings: usize,
    /// The largest single response's finalize scratch: responses resolve
    /// one at a time.
    scratch: usize,
    /// `(String, String)` entries and roots of every selector map built.
    selector_nodes: usize,
    tool_entries: usize,
    fold: FoldKeys,
}

impl BookOutput {
    /// Adds one resolved response: what `finalize_claude_responses_e2`
    /// builds from it (cache request, request-id set entry, occurrence with
    /// its selector `Arc`, the `shared_selectors` entry, a usage row and
    /// bucket, tool names) and what `into_items` clones from that row. A
    /// response that resolves to nothing adds nothing.
    fn add(self, response: ResponseOutput, limit: usize) -> Option<Self> {
        let ResponseOutput {
            records,
            model,
            effort,
            request_id,
            timestamp,
            slot,
            selector_bytes,
            selector_entries,
            context_bytes,
            context_entries,
            tool_bytes,
            tool_entries,
        } = response;
        if records == 0 {
            return Some(self);
        }
        // `finalize_claude_responses_e2` may insert `context_bucket`.
        let selector = selector_bytes.checked_add(CONTEXT_BUCKET_BYTES)?;
        let entries = selector_entries.checked_add(2)?;
        let row_copy = effort
            .checked_mul(2)?
            .checked_add(ROW_SELECTOR_HASH_BYTES)?
            .checked_add(selector.checked_mul(2)?)?;
        let strings = request_id
            .checked_mul(2)? // the request-id set and the occurrence key
            .checked_add(model)? // the occurrence (rows take `max_model`)
            .checked_add(effort)?
            .checked_add(timestamp.checked_mul(2)?)? // occurrence; bucket input
            .checked_add(selector)? // the occurrence's selector
            .checked_add(slot)? // the cache request's slot clone
            .checked_add("sequential".len())?
            .checked_add(row_copy.checked_mul(ROW_COPIES)?)?
            .checked_add(RFC3339_TEXT_BYTES.checked_mul(4)?)? // bucket key, first, last, normalized
            .checked_add(tool_bytes.checked_mul(2)?)?; // names counted, then cloned
                                                       // The row identity's JSON text (every byte escaped at most 6 times)
                                                       // and its digest, dropped before the next response.
        let json = selector
            .checked_add(entries)?
            .checked_mul(6)?
            .checked_add(2)?
            .checked_mul(2)?
            .max(JSON_TEXT_MIN_BYTES);
        let scratch = json.checked_add(SHA256_HEX_TEXT_BYTES)?;
        // Selector map roots: the occurrence's two, two per row copy; a row
        // keeps only allow-listed keys.
        let row_entries = entries.min(2 * SELECTOR_CONTEXT_ALLOWED.len());
        let selector_nodes = entries
            .checked_add(2)?
            .checked_add(row_entries.checked_add(2)?.checked_mul(ROW_COPIES)?)?;
        // E2's key: the context (and a `context_bucket`), then the effort.
        let key_strings = context_bytes
            .checked_add("context_bucket".len() + "short".len())?
            .checked_add(effort)?
            .checked_add("reasoning_effort".len())?;
        let key_entries = context_entries.checked_add(1)?.min(KEY_CONTEXT_FIELDS);
        let fold = FoldKeys {
            responses: self.fold.responses.checked_add(1)?,
            modelless: self.fold.modelless.checked_add(usize::from(model == 0))?,
            max_model: self.fold.max_model.max(model),
            context_strings: self.fold.context_strings.checked_add(key_strings)?,
            context_entries: self.fold.context_entries.checked_add(key_entries)?,
        };
        let next = Self {
            responses: self.responses.checked_add(1)?,
            max_model: self.max_model.max(model),
            strings: self.strings.checked_add(strings)?,
            scratch: self.scratch.max(scratch),
            selector_nodes: self.selector_nodes.checked_add(selector_nodes)?,
            tool_entries: self.tool_entries.checked_add(tool_entries)?,
            fold,
        };
        (next.strings <= limit && next.fold.context_strings <= limit).then_some(next)
    }

    /// The summed term, on its own counter. Per response: one node each in
    /// the request-id set, the occurrence map, `shared_selectors` (R1a R6)
    /// and the bucket map; a row-map root and `ROW_COPIES` row nodes; the
    /// occurrence's and `shared_selectors`' `Arc` headers; `SnapshotModelUsage`
    /// slots for two clones in vectors grown from four, two bucket slots, and
    /// two `cache_requests` slots (the file's own share is
    /// `finish_output_bound`'s).
    /// Rows without a model take an earlier response's (`latest_model`), so
    /// each row copy is charged the largest model, plus the live
    /// `latest_model`.
    fn bytes(self, limit: usize) -> Option<usize> {
        let Self {
            responses,
            max_model,
            strings,
            scratch,
            selector_nodes,
            tool_entries,
            fold: _,
        } = self;
        let arc = size_of::<SelectorCapture>()
            .checked_add(align_of::<SelectorCapture>())?
            .checked_add(2 * size_of::<usize>())?;
        let per_response = tree_node_bytes::<String, ()>()?
            .checked_add(tree_node_bytes::<String, ClaudeTranscriptUsageOccurrence>()?)?
            .checked_add(tree_node_bytes::<Arc<SelectorCapture>, ()>()?)?
            .checked_add(tree_node_bytes::<String, UsageBucketState>()?)?
            .checked_add(
                tree_node_bytes::<RowKey, BucketRowAccumulator>()?
                    .checked_mul(ROW_COPIES.checked_add(1)?)?,
            )?
            .checked_add(arc.checked_mul(2)?)?
            .checked_add(size_of::<SnapshotModelUsage>().checked_mul(7)?)?
            .checked_add(size_of::<SnapshotUsageBucket>().checked_mul(2)?)?
            .checked_add(size_of::<OwnedRequest>().checked_mul(2)?)?
            .checked_add(max_model.checked_mul(ROW_COPIES)?)?;
        let tool = tree_node_bytes::<String, u64>()?.checked_add(size_of::<SnapshotToolUsage>())?;
        let mut out = Counter::new(limit);
        out.add(strings)?;
        out.add(scratch)?;
        out.add(selector_nodes.checked_mul(tree_node_bytes::<String, String>()?)?)?;
        out.add(responses.checked_mul(per_response)?)?;
        out.add(tool_entries.checked_mul(tool)?)?;
        // `shared_selectors`' root and the live `latest_model`.
        out.add(tree_node_bytes::<Arc<SelectorCapture>, ()>()?)?;
        out.add(max_model)?;
        Some(out.bytes)
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

    fn get<'a>(&'a self, selector: &'a CompactClaudeSelector) -> Option<&'a SelectorCapture> {
        match selector {
            CompactClaudeSelector::Interned(index) => self.selectors.get(*index as usize),
            CompactClaudeSelector::Inline(selector) => Some(selector),
        }
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
/// name, so a durable record's `L` span is the id alone (M1, SOURCE P2-5).
#[derive(Debug, Clone)]
struct ClaudeToolUse {
    id: String,
    name: String,
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
            tool_uses: tool_uses
                .into_iter()
                .map(|ClaudeToolUse { id, name }| (id, name))
                .collect(),
        })
    }
}

/// Bound the decoded heap without materializing even one decoded record.
/// Borrowed fields use the same HeapLayoutBound implementations as the real
/// ClaudeResponseRecord; moved strings keep their capacity, cloned strings
/// cannot exceed the original capacity. Exhaustive destructuring keeps new
/// compact fields from silently escaping this preflight.
///
/// The record's output term (`RecordBounds::output`) is measured on its own
/// counter against `output_limit`, never against `limit`'s remainder, so it
/// cannot change the decoded bound or its `None` (R1a R1, R2).
fn decoded_record_heap_bound(
    record: &CompactClaudeResponseRecord,
    first: Option<&CompactClaudeResponseRecord>,
    selectors: &ClaudeSelectorTable,
    limit: usize,
    output_limit: usize,
) -> Option<RecordBounds> {
    let CompactClaudeResponseRecord {
        usage: _, // UsageTotals (including costs) is entirely inline.
        slot,
        physical_sequence: _,
        model,
        reasoning_effort,
        request_id,
        timestamp,
        computed_effective_input_context: _,
        selector,
        tool_uses,
    } = record;
    let model = model.get(first.map(|first| &first.model))?;
    let effort = reasoning_effort.get(first.map(|first| &first.reasoning_effort))?;
    let request_id = request_id.get(first.map(|first| &first.request_id))?;
    let mut c = Counter::new(limit);
    model.heap_bound(&mut c)?;
    effort.heap_bound(&mut c)?;
    request_id.heap_bound(&mut c)?;
    timestamp.heap_bound(&mut c)?;
    let selector = selectors.get(selector)?;
    selector.completed_heap_bound(&mut c)?;
    match slot {
        ClaudeSlot::Explicit(slot) => slot.completed_heap_bound(&mut c)?,
        ClaudeSlot::Derived(_) => {
            request_id.heap_bound(&mut c)?;
            timestamp.heap_bound(&mut c)?;
            model.heap_bound(&mut c)?;
            effort.heap_bound(&mut c)?;
        }
    }
    crate::heap_layout_bound::tree_nodes::<String, String>(tool_uses.len(), &mut c)?;
    // Use per-element counters exactly like completed_heap_bound, so the
    // completion preflight does not inherit a per-line history visit wall.
    let mut tool_bytes = 0usize;
    for ClaudeToolUse { id, name } in tool_uses {
        let mut tool = Counter::new(limit.checked_sub(c.bytes)?.checked_sub(tool_bytes)?);
        id.heap_bound(&mut tool)?;
        name.heap_bound(&mut tool)?;
        tool_bytes = tool_bytes.checked_add(tool.bytes)?;
    }
    c.add(tool_bytes)?;
    // BTreeMap's FromIterator can collect/sort a temporary entry vector while
    // the original compact list is still alive. Reserve its realloc/scratch.
    c.add(
        tool_uses
            .len()
            .checked_mul(3 * std::mem::size_of::<(String, String)>())?,
    )?;
    Some(RecordBounds {
        decoded: c.bytes,
        output: record_output(
            RecordText {
                model,
                effort,
                request_id,
                timestamp,
            },
            slot,
            selector,
            tool_uses,
            output_limit,
        ),
    })
}

/// One record's resolved text, as `decoded_record_heap_bound` borrows it.
struct RecordText<'a> {
    model: &'a Option<String>,
    effort: &'a Option<String>,
    request_id: &'a Option<String>,
    timestamp: &'a Option<String>,
}

/// What one record's strings can contribute to the finished output (X_out
/// family R, #665), on a counter of its own: the strings
/// `decoded_record_heap_bound` visits, measured by capacity. A decoded clone
/// (an interned selector, a `Derived` slot's text) cannot exceed it.
fn record_output(
    text: RecordText<'_>,
    slot: &ClaudeSlot,
    selector: &SelectorCapture,
    tool_uses: &[ClaudeToolUse],
    limit: usize,
) -> Option<ResponseOutput> {
    let RecordText {
        model,
        effort,
        request_id,
        timestamp,
    } = text;
    let capacity = |value: &Option<String>| value.as_ref().map_or(0, String::capacity);
    let slot = match slot {
        ClaudeSlot::Explicit(slot) => {
            let mut strings = Counter::new(limit);
            (**slot).completed_heap_bound(&mut strings)?;
            strings.bytes
        }
        // `ClaudeSlot::decode` clones the record's own text.
        ClaudeSlot::Derived(_) => capacity(request_id)
            .checked_add(capacity(timestamp))?
            .checked_add(capacity(model))?
            .checked_add(capacity(effort))?,
    };
    let text = |map: &BTreeMap<String, String>| {
        map.iter().try_fold(0usize, |bytes, (key, value)| {
            bytes
                .checked_add(key.capacity())?
                .checked_add(value.capacity())
        })
    };
    let context_bytes = text(&selector.context)?;
    let selector_bytes = context_bytes.checked_add(text(&selector.sources)?)?;
    let mut tool_bytes = 0usize;
    for ClaudeToolUse { id, name } in tool_uses {
        tool_bytes = tool_bytes
            .checked_add(id.capacity())?
            .checked_add(name.capacity())?;
    }
    let output = ResponseOutput {
        records: 1,
        model: capacity(model),
        effort: capacity(effort),
        request_id: capacity(request_id),
        timestamp: capacity(timestamp),
        slot,
        selector_bytes,
        selector_entries: selector.context.len().checked_add(selector.sources.len())?,
        context_bytes,
        context_entries: selector.context.len(),
        tool_bytes,
        tool_entries: tool_uses.len(),
    };
    let mut out = Counter::new(limit);
    for bytes in [
        output.model,
        output.effort,
        output.request_id,
        output.timestamp,
        output.slot,
        output.selector_bytes,
        output.tool_bytes,
    ] {
        out.add(bytes)?;
    }
    Some(output)
}

/// `decoded_response_peak_bound`'s peak, and the response's merged output
/// term. The output never decides `None` (R1a R1): its failure is
/// `output: None`.
fn decoded_response_bounds(
    records: &OwnedVec<CompactClaudeResponseRecord>,
    selectors: &ClaudeSelectorTable,
    limit: usize,
) -> Option<ResponseBounds> {
    let count = records.len();
    if count == 0 {
        // Resolves to nothing (no first record): no output.
        return Some(ResponseBounds {
            peak: 0,
            output: Some(ResponseOutput::default()),
        });
    }
    // The decoded vector is allocated exactly once. Stable sorting can ask
    // for another count slots. Later, canonical_records grows geometrically
    // while that input vector remains alive; include both old and new buffers
    // during its largest realloc (also covers sorting). No merge code changes.
    let canonical_capacity = count.checked_next_power_of_two()?.max(4);
    let slots = count.checked_add(canonical_capacity.checked_mul(2)?)?;
    let mut bytes = slots.checked_mul(std::mem::size_of::<ClaudeResponseRecord>())?;
    let timestamp_copy = records
        .iter()
        .filter_map(|record| record.timestamp.as_ref().map(String::capacity))
        .max()
        .unwrap_or(0);
    bytes = bytes.checked_add(timestamp_copy)?; // first_timestamp in the resolver
    let mut output = Some(ResponseOutput::default());
    for record in records.iter() {
        let record = decoded_record_heap_bound(
            record,
            records.first(),
            selectors,
            limit.checked_sub(bytes)?,
            limit,
        )?;
        bytes = bytes.checked_add(record.decoded)?;
        output = output
            .zip(record.output)
            .and_then(|(response, record)| response.merge(record));
    }
    (bytes <= limit).then_some(ResponseBounds {
        peak: bytes,
        output,
    })
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

#[cfg(test)]
mod output_tests {
    use super::*;

    /// M1, SOURCE P2-5: a retained tool use is `{L id, U name}`. Its only `L`
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
        let mut e = Enc::bytes(1 << 10);
        tool_uses.put(&mut e).unwrap();
        let body = e.into_bytes();
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

    /// R1a R1, R5, R7: output arithmetic that overflows is `None` (never a
    /// wrap or a panic), and a response that resolves to nothing adds nothing.
    #[test]
    fn output_overflow_is_none_and_empty_responses_add_nothing() {
        let huge = ResponseOutput {
            records: 1,
            request_id: usize::MAX,
            ..ResponseOutput::default()
        };
        assert!(BookOutput::default().add(huge, usize::MAX).is_none());
        let full = ResponseOutput {
            records: usize::MAX,
            ..ResponseOutput::default()
        };
        assert!(full.merge(ResponseOutput::default()).is_some());
        let one = ResponseOutput {
            records: 1,
            ..ResponseOutput::default()
        };
        assert!(full.merge(one).is_none());
        let empty = BookOutput::default()
            .add(ResponseOutput::default(), 0)
            .expect("an empty response adds nothing");
        assert_eq!(empty.responses, 0);
        assert_eq!(empty.strings, 0);
    }

    /// fresh-r2 R2-5: a response keeps one record's text (model, effort,
    /// request id, timestamp, slot), so each takes the largest over its
    /// records, in either order; its selector and tool uses are unions, so
    /// they sum. Each record is the larger in different terms, so a term
    /// summed instead of maxed, maxed instead of summed, or dropped changes
    /// the result.
    #[test]
    fn output_merge_takes_text_maxima_and_union_sums() {
        let first = ResponseOutput {
            records: 1,
            model: 0,
            effort: 4,
            request_id: 30,
            timestamp: 24,
            slot: 7,
            selector_bytes: 40,
            selector_entries: 2,
            context_bytes: 15,
            context_entries: 1,
            tool_bytes: 11,
            tool_entries: 1,
        };
        let late = ResponseOutput {
            records: 1,
            model: 17,
            effort: 9,
            request_id: 12,
            timestamp: 29,
            slot: 3,
            selector_bytes: 26,
            selector_entries: 4,
            context_bytes: 8,
            context_entries: 2,
            tool_bytes: 22,
            tool_entries: 2,
        };
        for (label, a, b) in [("first, late", first, late), ("late, first", late, first)] {
            let merged = a.merge(b).expect("no overflow");
            assert_eq!(
                (
                    merged.records,
                    merged.model,
                    merged.effort,
                    merged.request_id,
                    merged.timestamp,
                    merged.slot,
                ),
                (2, 17, 9, 30, 29, 7),
                "{label}: text terms take the maximum"
            );
            assert_eq!(
                (
                    merged.selector_bytes,
                    merged.selector_entries,
                    merged.context_bytes,
                    merged.context_entries,
                    merged.tool_bytes,
                    merged.tool_entries,
                ),
                (66, 6, 23, 3, 33, 3),
                "{label}: union terms sum"
            );
        }
    }

    /// R2-5, the book's side: a response's model is charged on its
    /// occurrence, on each of its `ROW_COPIES` row copies and as the live
    /// `latest_model` (`ROW_COPIES + 2` times), and its tool bytes twice
    /// (counted, then cloned) plus one tool node and slot per tool entry.
    /// Dropping any one of these charges changes the difference.
    #[test]
    fn output_book_charges_the_model_per_row_copy_and_tools_twice() {
        let bytes = |response: ResponseOutput| {
            BookOutput::default()
                .add(response, usize::MAX)
                .and_then(|book| book.bytes(usize::MAX))
                .expect("bounded")
        };
        let base = ResponseOutput {
            records: 1,
            ..ResponseOutput::default()
        };
        let modelled = ResponseOutput { model: 17, ..base };
        assert_eq!(bytes(modelled) - bytes(base), 17 * (ROW_COPIES + 2));
        let tooled = ResponseOutput {
            tool_bytes: 22,
            tool_entries: 1,
            ..base
        };
        let tool = tree_node_bytes::<String, u64>().unwrap() + size_of::<SnapshotToolUsage>();
        assert_eq!(bytes(tooled) - bytes(base), 2 * 22 + tool);
    }

    /// R2-5 on real records: a three-record response whose first two records
    /// carry no model and whose third carries the late model, each record
    /// with its own selector key and tool use. The output takes the late
    /// model's and the longest timestamp's capacity once, and the selector
    /// and tool bytes and entries of all three records.
    #[test]
    fn output_of_real_records_takes_the_late_model_and_sums_unions() {
        let late = "claude-late-model";
        // Literals, so every capacity is its length.
        let keys = [
            (
                "service_tier",
                "standard",
                "toolu_real_0",
                "2026-10-07T10:00:00Z",
            ),
            (
                "speed_mode",
                "fast",
                "toolu_real_1",
                "2026-10-07T10:00:01.5Z",
            ),
            (
                "region_mode",
                "us",
                "toolu_real_2",
                "2026-10-07T10:00:02.25Z",
            ),
        ];
        let mut selectors = ClaudeSelectorTable::default();
        let mut records = OwnedVec::new();
        let (mut selector_bytes, mut context_bytes, mut tool_bytes) = (0, 0, 0);
        for (index, (key, value, tool_id, timestamp)) in keys.into_iter().enumerate() {
            let mut selector = SelectorCapture::default();
            selector.insert(key, value.to_string(), "usage");
            selector_bytes += 2 * key.len() + value.len() + "usage".len();
            context_bytes += key.len() + value.len();
            tool_bytes += tool_id.len() + "Bash".len();
            records.push(CompactClaudeResponseRecord::encode(
                records.first(),
                index as u16,
                UsageTotals::default(),
                (index == 2).then(|| late.to_string()),
                selectors.intern(selector),
                None,
                Some("req_real".to_string()),
                Some(timestamp.to_string()),
                None,
                BTreeMap::from([(tool_id.to_string(), "Bash".to_string())]),
                RequestSlot::default(),
            ));
        }
        let output = decoded_response_bounds(&records, &selectors, usize::MAX)
            .and_then(|bounds| bounds.output)
            .expect("bounded output");
        assert_eq!(
            (
                output.records,
                output.model,
                output.effort,
                output.request_id,
                output.timestamp,
            ),
            (3, late.len(), 0, "req_real".len(), keys[2].3.len()),
            "text terms: the largest record's"
        );
        assert_eq!(
            (
                output.selector_bytes,
                output.selector_entries,
                output.context_bytes,
                output.context_entries,
                output.tool_bytes,
                output.tool_entries,
            ),
            (selector_bytes, 6, context_bytes, 3, tool_bytes, 3),
            "union terms: every record's"
        );
    }
}
