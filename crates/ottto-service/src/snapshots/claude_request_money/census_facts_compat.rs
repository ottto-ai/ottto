//! Read-only legacy facts validation used by the unchanged census codec.

use super::ClaudeMoneyTokens;

const FACTS_VERSION: u64 = 1;
/// Distinct (model, speed, effort) styles one record may name.
pub(super) const MAX_STYLES: usize = 254;
/// A row whose money could not be read (a contradictory cache split): its
/// hash still claims the request, its root's money is unavailable.
pub(super) const UNREADABLE_STYLE: u8 = 255;
const MAX_STYLE_BYTES: usize = 192;
const MAX_SESSION_BYTES: usize = 128;
/// One request's money as its row states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClaudeFact {
    pub(super) tokens: ClaudeMoneyTokens,
    pub(super) cost_micros: Option<u64>,
    pub(super) clock: u64,
    pub(super) style: u8,
}

/// A record's header: its root session, the base of the clock deltas, the
/// conflicting and refused lines seen, and the style table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ClaudeFactsHeader {
    pub(super) session: String,
    pub(super) base_clock: u64,
    pub(super) conflicts: u64,
    /// Lines refused (invalid, foreign, oversized) or rows whose money could
    /// not be read: the root's rows are never complete while it is nonzero.
    pub(super) refused: u64,
    /// `model \x1f speed \x1f effort`.
    pub(super) styles: Vec<String>,
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

/// A record's facts, read in place.
pub(super) struct ClaudeFacts<'a> {
    pub(super) header: ClaudeFactsHeader,
    body: Reader<'a>,
}

impl<'a> ClaudeFacts<'a> {
    pub(super) fn open(blob: &'a [u8]) -> Option<Self> {
        let mut body = Reader { bytes: blob, at: 0 };
        let header = decode_header(&mut body)?;
        Some(Self { header, body })
    }

    /// The next fact; None at the end or on a malformed fact.
    pub(super) fn next_fact(&mut self) -> Option<ClaudeFact> {
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

/// Synthetic legacy blobs for the kept census-codec regression tests.
#[cfg(test)]
pub(crate) mod fixture {
    use super::super::ClaudeMoneyTokens;
    use super::{ClaudeFact, ClaudeFactsHeader, FACTS_VERSION};

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

    fn encode<'f>(
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

    pub(crate) fn facts(session: &str, count: usize) -> Box<[u8]> {
        let header = ClaudeFactsHeader {
            session: session.to_owned(),
            base_clock: 1_785_000_000,
            styles: vec!["claude-haiku-4-5\u{1f}\u{1f}high".to_owned()],
            ..ClaudeFactsHeader::default()
        };
        let rows = (0..count as u64)
            .map(|number| ClaudeFact {
                tokens: ClaudeMoneyTokens {
                    input: 10 + number,
                    output: 10,
                    ..ClaudeMoneyTokens::default()
                },
                cost_micros: Some(100),
                clock: 1_785_000_000 + number,
                style: 0,
            })
            .collect::<Vec<_>>();
        encode(&header, &rows, 0).into_boxed_slice()
    }
}
