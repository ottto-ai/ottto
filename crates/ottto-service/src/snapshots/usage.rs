//! Provider price lines: the per-model prompt-length lines every source
//! stamps its per-request `context_bucket` from, and the bucket rule itself.
//!
//! `cache_observations` prepares the cache-observation upload state of one
//! item against its acknowledged predecessor.
//!
//! `UsageTotals` and `UsageCosts` are the token counters and exact cost picos
//! a row accumulates, with their add, monotonic and delta rules.

pub(super) mod cache_observations;

use super::rfc3339_unix_seconds;
use super::scan::limits::in_codex_forward_evidence_epoch;
use super::{usd_picos_string, SnapshotCost, SnapshotItem, SnapshotModelUsage};

/// Effective per-turn input context (uncached input + cache reads + cache
/// writes) above which a Claude turn could only have run with the "(1M
/// context)" window enabled — the regular Claude context cap is 200K tokens.
/// For the flat-priced 1M-window models in `PROVIDER_PRICE_LINES`, turns
/// strictly over this boundary tag `context_bucket=long`; everything at or
/// below tags `short`. 1M usage bills at standard per-token rates but drives
/// cost via token VOLUME, so the product analyzes it separately.
///
/// MUST stay in lockstep with the backend pricing catalog's
/// `context_bucket_threshold_tokens` for the 1M-capable Claude models and the
/// cost projector's `_derive_context_bucket`, which honors this daemon-supplied
/// bucket ahead of its own (request_count==1-gated) derivation.
pub const CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS: u64 = 200_000;

/// How a model's price line bills a request over it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProviderPriceLineKind {
    /// Prompt-length tiered: a request strictly over the line bills ALL of
    /// its tokens at the provider's long-context rate.
    Tiered,
    /// `Tiered`, but only for usage dated from
    /// `CODEX_FORWARD_EVIDENCE_FROM_UNIX_SECONDS`: a line added after usage
    /// was accepted without a bucket must not restate that usage on a re-read.
    TieredForward,
    /// Flat price at every prompt length: the line only separates 1M-window
    /// usage for analysis (the Claude 200K boundary above).
    Analysis,
}

#[cfg(test)]
impl ProviderPriceLineKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Tiered | Self::TieredForward => "tiered",
            Self::Analysis => "analysis",
        }
    }
}

/// Provider prompt-length price lines: the one table every source stamps its
/// per-request `context_bucket` from, keyed by the pricing catalog's canonical
/// model key. A model is listed only where the catalog publishes a
/// `context_bucket_threshold_tokens` for it, at that exact value; every other
/// model (GPT-5.4 mini/nano, codex variants, Claude 4.5 and earlier, unknown
/// models) gets no bucket. The prompt counts uncached input, cache reads and
/// cache writes (Codex `input_tokens` already includes its cached prefix).
///
/// The table is pinned as `fixtures/snapshot-audit/provider-price-lines-v1.json`
/// and the backend compares that artifact with the catalog thresholds
/// (backend/tests/unit/test_daemon_price_line_mirror.py). Change both together.
pub(super) const PROVIDER_PRICE_LINES: &[(&str, u64, ProviderPriceLineKind)] = &[
    // OpenAI: 2x input and cache, 1.5x output for the whole request.
    ("gpt-5-4", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-5-4-pro", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-5-5", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-5-5-pro", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-5-6-luna", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-5-6-sol", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-5-6-terra", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-6-astra", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-6-luna", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-6-sol", 272_000, ProviderPriceLineKind::Tiered),
    ("gpt-6-1-sol", 272_000, ProviderPriceLineKind::Tiered),
    (
        "gpt-6-1-terra",
        272_000,
        ProviderPriceLineKind::TieredForward,
    ),
    (
        "gpt-6-rosalind",
        272_000,
        ProviderPriceLineKind::TieredForward,
    ),
    // Anthropic: every Haiku 5.5 rate 5x above 100K.
    ("claude-haiku-5-5", 100_000, ProviderPriceLineKind::Tiered),
    // Anthropic full 1M window at standard rates.
    (
        "claude-fable-5",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-fable-5-1",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-mythos-5",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-mythos-5-1",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-opus-4-6",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-opus-4-7",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-opus-4-8",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-opus-5",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-opus-5-5",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-sonnet-4-6",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-sonnet-5",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
    (
        "claude-sonnet-5-5",
        CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS,
        ProviderPriceLineKind::Analysis,
    ),
];

/// The catalog's canonical key for a raw model id: provider and Bedrock route
/// prefixes, a Bedrock `-vN:M` suffix, a dated snapshot (`-YYYY-MM-DD`,
/// `-YYYYMMDD`, `@YYYYMMDD`) and `-latest` dropped; dots become dashes.
pub(super) fn provider_price_line_model_key(model: &str) -> String {
    // Byte checks only: model ids come from transcripts and may be non-ASCII,
    // and every cut below lands just before an ASCII `-`/`@`, a char boundary.
    let all_digits = |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
    let mut key = model.trim().to_ascii_lowercase();
    for marker in ["anthropic.", "anthropic/", "openai/"] {
        if let Some(index) = key.find(marker) {
            key = key[index + marker.len()..].to_string();
        }
    }
    if let Some((head, version)) = key.rsplit_once("-v") {
        if version.split_once(':').is_some_and(|(major, minor)| {
            all_digits(major.as_bytes()) && all_digits(minor.as_bytes())
        }) {
            key = head.to_string();
        }
    }
    if let Some(head) = key.strip_suffix("-latest") {
        key = head.to_string();
    }
    let bytes = key.as_bytes();
    let dated_suffix = if bytes.len() > 11
        && bytes[bytes.len() - 11] == b'-'
        && bytes[bytes.len() - 6] == b'-'
        && bytes[bytes.len() - 3] == b'-'
        && all_digits(&bytes[bytes.len() - 10..bytes.len() - 6])
        && all_digits(&bytes[bytes.len() - 5..bytes.len() - 3])
        && all_digits(&bytes[bytes.len() - 2..])
    {
        11
    } else if bytes.len() > 9
        && matches!(bytes[bytes.len() - 9], b'-' | b'@')
        && all_digits(&bytes[bytes.len() - 8..])
    {
        9
    } else {
        0
    };
    key.truncate(key.len() - dated_suffix);
    key.replace('.', "-")
}

pub(super) fn provider_price_line(model: &str) -> Option<(u64, ProviderPriceLineKind)> {
    let key = provider_price_line_model_key(model);
    PROVIDER_PRICE_LINES
        .iter()
        .find(|(listed, _, _)| *listed == key)
        .map(|&(_, tokens, kind)| (tokens, kind))
}

/// Tiered price lines apply to requests whose own usage time is on or after
/// 2026-09-01T00:00:00Z (the start of the previous month at release). Earlier
/// usage keeps exactly the rows it had, even when its file is re-read, so
/// restating the price split never touches older history.
pub(super) const PROVIDER_PRICE_LINE_EFFECTIVE_FROM_UNIX_SECONDS: u64 = 1_788_220_800;

/// One request's bucket from its prompt size, its model and its own usage
/// timestamp. `None` when the model has no catalog line. A tiered line also
/// needs a known, non-zero prompt dated on or after the effective date: an
/// unmeasured request is never silently short. Flat Claude analysis lines keep
/// the stamp they always had (every request, any date).
pub(crate) fn provider_context_bucket(
    model: &str,
    prompt_tokens: u64,
    observed_at: Option<&str>,
) -> Option<&'static str> {
    let (line, kind) = provider_price_line(model)?;
    if kind == ProviderPriceLineKind::Tiered
        && (prompt_tokens == 0
            || observed_at.and_then(rfc3339_unix_seconds)?
                < PROVIDER_PRICE_LINE_EFFECTIVE_FROM_UNIX_SECONDS)
    {
        return None;
    }
    if kind == ProviderPriceLineKind::TieredForward
        && (prompt_tokens == 0 || !in_codex_forward_evidence_epoch(observed_at))
    {
        return None;
    }
    Some(if prompt_tokens > line {
        "long"
    } else {
        "short"
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct UsageTotals {
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    pub(super) cache_read_tokens: u64,
    pub(super) cache_creation_5m_tokens: u64,
    pub(super) cache_creation_1h_tokens: u64,
    pub(super) reasoning_output_tokens: u64,
    pub(super) unattributed_total_tokens: u64,
    pub(super) request_count: u64,
    pub(super) costs: UsageCosts,
}

pub(super) const USD_PICO_SCALE: u128 = 1_000_000_000_000;
pub(super) const PI_COST_FIELD_CEILING_PICOS: u128 = 100_000 * USD_PICO_SCALE;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct UsageCosts {
    pub(super) observed: bool,
    pub(super) reported: bool,
    pub(super) total: Option<u128>,
    pub(super) input: Option<u128>,
    pub(super) output: Option<u128>,
    pub(super) cache_read: Option<u128>,
    pub(super) cache_creation: Option<u128>,
}

impl UsageCosts {
    pub(super) fn add(&mut self, other: &Self) {
        if !other.observed {
            return;
        }
        if !self.observed {
            *self = other.clone();
            return;
        }
        self.reported &= other.reported;
        if !self.reported {
            self.total = None;
            self.input = None;
            self.output = None;
            self.cache_read = None;
            self.cache_creation = None;
            return;
        }
        self.total = add_complete_cost(self.total, other.total);
        self.input = add_complete_cost(self.input, other.input);
        self.output = add_complete_cost(self.output, other.output);
        self.cache_read = add_complete_cost(self.cache_read, other.cache_read);
        self.cache_creation = add_complete_cost(self.cache_creation, other.cache_creation);
    }

    pub(super) fn is_monotonic_after(&self, previous: &Self) -> bool {
        (!previous.observed || self.observed)
            && (!previous.reported || self.reported)
            && cost_is_monotonic(self.total, previous.total)
            && cost_is_monotonic(self.input, previous.input)
            && cost_is_monotonic(self.output, previous.output)
            && cost_is_monotonic(self.cache_read, previous.cache_read)
            && cost_is_monotonic(self.cache_creation, previous.cache_creation)
    }

    fn delta_from(&self, previous: &Self) -> Self {
        Self {
            observed: self.observed,
            reported: self.reported,
            total: cost_delta(self.total, previous.total),
            input: cost_delta(self.input, previous.input),
            output: cost_delta(self.output, previous.output),
            cache_read: cost_delta(self.cache_read, previous.cache_read),
            cache_creation: cost_delta(self.cache_creation, previous.cache_creation),
        }
    }

    pub(super) fn snapshot_cost(&self) -> Option<SnapshotCost> {
        self.reported.then(|| SnapshotCost {
            total_cost_usd: self.total.map(usd_picos_string),
            input_cost_usd: self.input.map(usd_picos_string),
            output_cost_usd: self.output.map(usd_picos_string),
            cache_read_cost_usd: self.cache_read.map(usd_picos_string),
            cache_creation_cost_usd: self.cache_creation.map(usd_picos_string),
            evidence_source: "pi_usage_cost".to_string(),
        })
    }
}

fn add_complete_cost(left: Option<u128>, right: Option<u128>) -> Option<u128> {
    match (left, right) {
        (Some(left), Some(right)) => left.checked_add(right),
        _ => None,
    }
}

fn cost_is_monotonic(current: Option<u128>, previous: Option<u128>) -> bool {
    match (current, previous) {
        (Some(current), Some(previous)) => current >= previous,
        (Some(_), None) | (None, None) => true,
        (None, Some(_)) => false,
    }
}

fn cost_delta(current: Option<u128>, previous: Option<u128>) -> Option<u128> {
    current.map(|current| current - previous.unwrap_or_default())
}

impl UsageTotals {
    pub(super) fn is_zero(&self) -> bool {
        self.total_tokens() == 0 && self.reasoning_output_tokens == 0
    }

    pub(super) fn total_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.output_tokens)
            .saturating_add(self.cache_read_tokens)
            .saturating_add(self.cache_creation_5m_tokens)
            .saturating_add(self.cache_creation_1h_tokens)
            .saturating_add(self.unattributed_total_tokens)
    }

    /// Effective input context for one turn: the prompt size the model actually
    /// saw — uncached input + cache reads + cache writes (5m + 1h TTL). Output
    /// and reasoning tokens are excluded. Mirrors the backend cost projector's
    /// `context_length` (input + cache_read + cache_creation). Drives the
    /// `context_bucket` selector: a value above the 200K regular-context cap
    /// could only have come from the 1M-context window.
    pub(super) fn effective_input_context(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.cache_read_tokens)
            .saturating_add(self.cache_creation_5m_tokens)
            .saturating_add(self.cache_creation_1h_tokens)
    }

    /// Add wire-carried counters atomically. Derived totals may saturate for
    /// thresholding, but a wire field cannot: callers must preserve the prior
    /// exact aggregate and expose the rejected record as loss.
    pub(super) fn add(&mut self, other: &UsageTotals) -> bool {
        let Some(input_tokens) = self.input_tokens.checked_add(other.input_tokens) else {
            return false;
        };
        let Some(output_tokens) = self.output_tokens.checked_add(other.output_tokens) else {
            return false;
        };
        let Some(cache_read_tokens) = self.cache_read_tokens.checked_add(other.cache_read_tokens)
        else {
            return false;
        };
        let Some(cache_creation_5m_tokens) = self
            .cache_creation_5m_tokens
            .checked_add(other.cache_creation_5m_tokens)
        else {
            return false;
        };
        let Some(cache_creation_1h_tokens) = self
            .cache_creation_1h_tokens
            .checked_add(other.cache_creation_1h_tokens)
        else {
            return false;
        };
        let Some(reasoning_output_tokens) = self
            .reasoning_output_tokens
            .checked_add(other.reasoning_output_tokens)
        else {
            return false;
        };
        let Some(unattributed_total_tokens) = self
            .unattributed_total_tokens
            .checked_add(other.unattributed_total_tokens)
        else {
            return false;
        };
        let Some(request_count) = self.request_count.checked_add(other.request_count) else {
            return false;
        };
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
        self.cache_read_tokens = cache_read_tokens;
        self.cache_creation_5m_tokens = cache_creation_5m_tokens;
        self.cache_creation_1h_tokens = cache_creation_1h_tokens;
        self.reasoning_output_tokens = reasoning_output_tokens;
        self.unattributed_total_tokens = unattributed_total_tokens;
        self.request_count = request_count;
        self.costs.add(&other.costs);
        true
    }

    pub(super) fn is_monotonic_after(&self, previous: &UsageTotals) -> bool {
        self.input_tokens >= previous.input_tokens
            && self.output_tokens >= previous.output_tokens
            && self.cache_read_tokens >= previous.cache_read_tokens
            && self.cache_creation_5m_tokens >= previous.cache_creation_5m_tokens
            && self.cache_creation_1h_tokens >= previous.cache_creation_1h_tokens
            && self.reasoning_output_tokens >= previous.reasoning_output_tokens
            && self.unattributed_total_tokens >= previous.unattributed_total_tokens
            && self.request_count >= previous.request_count
            && self.costs.is_monotonic_after(&previous.costs)
    }

    pub(super) fn delta_from(&self, previous: &UsageTotals) -> UsageTotals {
        UsageTotals {
            input_tokens: self.input_tokens - previous.input_tokens,
            output_tokens: self.output_tokens - previous.output_tokens,
            cache_read_tokens: self.cache_read_tokens - previous.cache_read_tokens,
            cache_creation_5m_tokens: self.cache_creation_5m_tokens
                - previous.cache_creation_5m_tokens,
            cache_creation_1h_tokens: self.cache_creation_1h_tokens
                - previous.cache_creation_1h_tokens,
            reasoning_output_tokens: self.reasoning_output_tokens
                - previous.reasoning_output_tokens,
            unattributed_total_tokens: self.unattributed_total_tokens
                - previous.unattributed_total_tokens,
            request_count: self.request_count - previous.request_count,
            costs: self.costs.delta_from(&previous.costs),
        }
    }
}

pub(super) fn usage_totals_from_item(item: &SnapshotItem) -> UsageTotals {
    UsageTotals {
        input_tokens: item.input_tokens,
        output_tokens: item.output_tokens,
        cache_read_tokens: item.cache_read_tokens,
        cache_creation_5m_tokens: item.cache_creation_5m_tokens,
        cache_creation_1h_tokens: item.cache_creation_1h_tokens,
        reasoning_output_tokens: item.reasoning_output_tokens,
        unattributed_total_tokens: item.unattributed_total_tokens,
        request_count: item.request_count,
        costs: UsageCosts::default(),
    }
}

pub(super) fn usage_totals_from_model_usage(row: &SnapshotModelUsage) -> UsageTotals {
    UsageTotals {
        input_tokens: row.input_tokens,
        output_tokens: row.output_tokens,
        cache_read_tokens: row.cache_read_tokens,
        cache_creation_5m_tokens: row.cache_creation_5m_tokens,
        cache_creation_1h_tokens: row.cache_creation_1h_tokens,
        reasoning_output_tokens: row.reasoning_output_tokens,
        unattributed_total_tokens: row.unattributed_total_tokens,
        request_count: row.request_count,
        costs: UsageCosts::default(),
    }
}

pub(super) fn usage_totals_has_usage(totals: &UsageTotals) -> bool {
    !totals.is_zero() || totals.request_count > 0
}

pub(super) fn usage_totals_equal(left: &UsageTotals, right: &UsageTotals) -> bool {
    left.input_tokens == right.input_tokens
        && left.output_tokens == right.output_tokens
        && left.cache_read_tokens == right.cache_read_tokens
        && left.cache_creation_5m_tokens == right.cache_creation_5m_tokens
        && left.cache_creation_1h_tokens == right.cache_creation_1h_tokens
        && left.reasoning_output_tokens == right.reasoning_output_tokens
        && left.unattributed_total_tokens == right.unattributed_total_tokens
        && left.request_count == right.request_count
}

crate::heap_layout_bound::fields!(UsageCosts; observed, reported, total, input, output, cache_read, cache_creation);
crate::durable_tail_codec::durable_struct!(UsageCosts {
    N observed: bool,
    N reported: bool,
    N total: Option<u128>,
    N input: Option<u128>,
    N output: Option<u128>,
    N cache_read: Option<u128>,
    N cache_creation: Option<u128>,
});
crate::heap_layout_bound::fields!(UsageTotals; input_tokens, output_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, reasoning_output_tokens, unattributed_total_tokens, request_count, costs);
crate::durable_tail_codec::durable_struct!(UsageTotals {
    N input_tokens: u64,
    N output_tokens: u64,
    N cache_read_tokens: u64,
    N cache_creation_5m_tokens: u64,
    N cache_creation_1h_tokens: u64,
    N reasoning_output_tokens: u64,
    N unattributed_total_tokens: u64,
    N request_count: u64,
    N costs: UsageCosts,
});
