//! Compact per-request telemetry facts: what the shadow builder needs from
//! each API sidecar row, kept in the root's `otel:` ledger record beside its
//! sorted request hashes (one fact per hash, same order) and built by the
//! telemetry tail as it reads new bytes. A root of any size therefore
//! converges by tailing, and a restart resumes from the persisted offset;
//! nothing rereads a sidecar to price it.
//!
//! A fact is only what the builder reads: the token components, the row's
//! own cost, the event clock and an index into the record's style table
//! (model, speed, effort). The request hash is the record's hash at the same
//! position; the login, client id, query source and app version are never
//! read and are not kept. Two rows for one request keep the winner of the
//! conflict order (`claude_response_conflict_order` over the fact's content
//! digest), so a replay is no conflict.
//!
//! Wire form (base64 in the record's `f` field), all integers LEB128:
//! `version`, the root session id, the base clock, the conflict and refused
//! line counts, the style table, then per fact: style byte, zigzag clock
//! delta from the base, cost + 1 (0: none), then input, output, cache read,
//! cache 5m, cache 1h, unattributed and reasoning tokens. About 20 bytes per
//! row at today's sizes.

use super::{digest_u64, ClaudeMoneyTokens};

const FACTS_VERSION: u64 = 1;
/// Distinct (model, speed, effort) styles one record may name.
pub(crate) const MAX_STYLES: usize = 254;
/// A row whose money could not be read (a contradictory cache split): its
/// hash still claims the request, its root's money is unavailable.
pub(crate) const UNREADABLE_STYLE: u8 = 255;
const MAX_STYLE_BYTES: usize = 192;
const MAX_SESSION_BYTES: usize = 128;
/// The largest encoding of one fact (style, clock, cost, seven tokens).
pub(crate) const MAX_FACT_BYTES: usize = 1 + 10 * 9;
/// The largest header (session, counts and a full style table).
pub(crate) const MAX_HEADER_BYTES: usize =
    1 + 10 + MAX_SESSION_BYTES + 3 * 10 + 10 + MAX_STYLES * (10 + MAX_STYLE_BYTES);

/// One request's money as its row states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaudeFact {
    pub(crate) tokens: ClaudeMoneyTokens,
    pub(crate) cost_micros: Option<u64>,
    pub(crate) clock: u64,
    pub(crate) style: u8,
}

/// A record's header: its root session, the base of the clock deltas, the
/// conflicting and refused lines seen, and the style table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeFactsHeader {
    pub(crate) session: String,
    pub(crate) base_clock: u64,
    pub(crate) conflicts: u64,
    /// Lines refused (invalid, foreign, oversized) or rows whose money could
    /// not be read: the root's rows are never complete while it is nonzero.
    pub(crate) refused: u64,
    /// `model \x1f speed \x1f effort`.
    pub(crate) styles: Vec<String>,
}

impl ClaudeFactsHeader {
    /// The style index of (model, speed, effort), interned; None when the
    /// table is full or the style is too long.
    pub(crate) fn intern(&mut self, model: &str, speed: &str, effort: &str) -> Option<u8> {
        if [model, speed, effort]
            .iter()
            .any(|part| part.contains('\u{1f}'))
        {
            return None;
        }
        let style = format!("{model}\u{1f}{speed}\u{1f}{effort}");
        if let Some(position) = self.styles.iter().position(|known| *known == style) {
            return u8::try_from(position).ok();
        }
        if self.styles.len() >= MAX_STYLES || style.len() > MAX_STYLE_BYTES {
            return None;
        }
        self.styles.push(style);
        u8::try_from(self.styles.len() - 1).ok()
    }

    /// (model, speed, effort) of a style index.
    pub(crate) fn style(&self, index: u8) -> Option<(&str, &str, &str)> {
        let mut parts = self.styles.get(usize::from(index))?.split('\u{1f}');
        Some((parts.next()?, parts.next()?, parts.next()?))
    }
}

/// The content digest of a fact: the conflict order's last tie-break, the
/// same for a live row and a stored fact with the same money.
pub(crate) fn fact_digest(fact: &ClaudeFact, style: (&str, &str, &str)) -> u64 {
    let tokens = &fact.tokens;
    let values = [
        tokens.input,
        tokens.output,
        tokens.cache_read,
        tokens.cache_5m,
        tokens.cache_1h,
        tokens.unattributed,
        tokens.reasoning,
        fact.cost_micros.map_or(0, |cost| cost.saturating_add(1)),
        fact.clock,
    ]
    .map(u64::to_be_bytes);
    let mut parts = values.iter().map(|value| &value[..]).collect::<Vec<_>>();
    parts.extend([style.0.as_bytes(), style.1.as_bytes(), style.2.as_bytes()]);
    digest_u64(b"claude_telemetry_fact:v1\0", &parts)
}

fn put(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn zigzag(value: i128) -> u64 {
    let value = value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    ((value << 1) ^ (value >> 63)) as u64
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

/// A strict reader: every value bounded, nothing past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0_u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            let part = u64::from(byte & 0x7f);
            if shift == 63 && part > 1 {
                return None;
            }
            value |= part << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn text(&mut self, max: usize) -> Option<String> {
        let len = usize::try_from(self.varint()?)
            .ok()
            .filter(|len| *len <= max)?;
        let end = self.at.checked_add(len)?;
        let text = std::str::from_utf8(self.bytes.get(self.at..end)?).ok()?;
        self.at = end;
        Some(text.to_owned())
    }
}

fn encode_header(out: &mut Vec<u8>, header: &ClaudeFactsHeader) {
    put(out, FACTS_VERSION);
    put(out, header.session.len() as u64);
    out.extend_from_slice(header.session.as_bytes());
    put(out, header.base_clock);
    put(out, header.conflicts);
    put(out, header.refused);
    put(out, header.styles.len() as u64);
    for style in &header.styles {
        put(out, style.len() as u64);
        out.extend_from_slice(style.as_bytes());
    }
}

fn decode_header(reader: &mut Reader<'_>) -> Option<ClaudeFactsHeader> {
    if reader.varint()? != FACTS_VERSION {
        return None;
    }
    let session = reader.text(MAX_SESSION_BYTES)?;
    let base_clock = reader.varint()?;
    let conflicts = reader.varint()?;
    let refused = reader.varint()?;
    let count = usize::try_from(reader.varint()?)
        .ok()
        .filter(|count| *count <= MAX_STYLES)?;
    let mut styles = Vec::with_capacity(count);
    for _ in 0..count {
        let style = reader.text(MAX_STYLE_BYTES)?;
        if style.split('\u{1f}').count() != 3 {
            return None;
        }
        styles.push(style);
    }
    Some(ClaudeFactsHeader {
        session,
        base_clock,
        conflicts,
        refused,
        styles,
    })
}

fn encode_fact(out: &mut Vec<u8>, base_clock: u64, fact: &ClaudeFact) {
    out.push(fact.style);
    put(out, zigzag(i128::from(fact.clock) - i128::from(base_clock)));
    put(
        out,
        fact.cost_micros.map_or(0, |cost| cost.saturating_add(1)),
    );
    let tokens = &fact.tokens;
    for value in [
        tokens.input,
        tokens.output,
        tokens.cache_read,
        tokens.cache_5m,
        tokens.cache_1h,
        tokens.unattributed,
        tokens.reasoning,
    ] {
        put(out, value);
    }
}

fn decode_fact(reader: &mut Reader<'_>, header: &ClaudeFactsHeader) -> Option<ClaudeFact> {
    let style = reader.byte()?;
    if style != UNREADABLE_STYLE && usize::from(style) >= header.styles.len() {
        return None;
    }
    let delta = unzigzag(reader.varint()?);
    let clock = u64::try_from(i128::from(header.base_clock) + i128::from(delta)).ok()?;
    let cost = reader.varint()?;
    let mut values = [0_u64; 7];
    for value in &mut values {
        *value = reader.varint()?;
    }
    Some(ClaudeFact {
        tokens: ClaudeMoneyTokens {
            input: values[0],
            output: values[1],
            cache_read: values[2],
            cache_5m: values[3],
            cache_1h: values[4],
            unattributed: values[5],
            reasoning: values[6],
        },
        cost_micros: cost.checked_sub(1),
        clock,
        style,
    })
}

/// Encode a header and its facts (in hash order).
pub(crate) fn encode<'f>(
    header: &ClaudeFactsHeader,
    facts: impl IntoIterator<Item = &'f ClaudeFact>,
    capacity: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    encode_header(&mut out, header);
    for fact in facts {
        encode_fact(&mut out, header.base_clock, fact);
    }
    out
}

/// A record's facts, read in place.
pub(crate) struct ClaudeFacts<'a> {
    pub(crate) header: ClaudeFactsHeader,
    body: Reader<'a>,
}

impl<'a> ClaudeFacts<'a> {
    pub(crate) fn open(blob: &'a [u8]) -> Option<Self> {
        let mut body = Reader { bytes: blob, at: 0 };
        let header = decode_header(&mut body)?;
        Some(Self { header, body })
    }

    /// The next fact; None at the end or on a malformed fact.
    pub(crate) fn next_fact(&mut self) -> Option<ClaudeFact> {
        if self.body.at == self.body.bytes.len() {
            return None;
        }
        decode_fact(&mut self.body, &self.header)
    }

    fn at_end(&self) -> bool {
        self.body.at == self.body.bytes.len()
    }
}

/// The blob holds exactly `count` well-formed facts after a valid header.
pub(crate) fn valid(blob: &[u8], count: usize) -> bool {
    let Some(mut facts) = ClaudeFacts::open(blob) else {
        return false;
    };
    for _ in 0..count {
        if facts.next_fact().is_none() {
            return false;
        }
    }
    facts.at_end()
}

/// Bytes of the facts body (after the header): the per-row size measure.
#[cfg(test)]
pub(crate) fn body_len(blob: &[u8]) -> usize {
    ClaudeFacts::open(blob).map_or(0, |facts| blob.len() - facts.body.at)
}

#[cfg(test)]
pub(crate) fn header_of_for_test(blob: &[u8]) -> Option<ClaudeFactsHeader> {
    ClaudeFacts::open(blob).map(|facts| facts.header)
}
