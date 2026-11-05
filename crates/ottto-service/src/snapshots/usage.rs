//! Provider price lines: the per-model prompt-length lines every source
//! stamps its per-request `context_bucket` from, and the bucket rule itself.
//!
//! `cache_observations` prepares the cache-observation upload state of one
//! item against its acknowledged predecessor.

pub(super) mod cache_observations;

use super::rfc3339_unix_seconds;
use super::scan::limits::in_codex_forward_evidence_epoch;

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
