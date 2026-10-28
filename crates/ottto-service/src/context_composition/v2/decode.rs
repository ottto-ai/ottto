//! Typed borrowed views of transcript lines and the text measurement over
//! them.
//!
//! A line is decoded into a struct of borrowed raw fields, so only the parts
//! a handler measures are decoded further and no whole-line `Value` tree is
//! built. The measurement reproduces the kinds_version 1 helpers in
//! `measure` exactly (character counts of the same joined text); shapes the
//! fast path does not handle (duplicate keys, unusual blocks) fall back to
//! those helpers over a `Value` of just that part.

use super::super::measure::python_json_dumps;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use serde_json::Value;
use std::borrow::Cow;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

// -------------------------------------------------------------------------
// Raw fields.
// -------------------------------------------------------------------------

/// One raw JSON field: absent (`None`) or its exact text (`null` included).
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Raw<'a>(pub(super) Option<&'a RawValue>);

impl<'de: 'a, 'a> Deserialize<'de> for Raw<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <&'a RawValue>::deserialize(deserializer).map(|raw| Raw(Some(raw)))
    }
}

impl<'a> Raw<'a> {
    pub(super) fn is_present(self) -> bool {
        self.0.is_some()
    }

    pub(super) fn text(self) -> Option<&'a str> {
        self.0.map(|raw| raw.get().trim_start())
    }

    fn first_byte(self) -> Option<u8> {
        self.text()
            .and_then(|text| text.as_bytes().first().copied())
    }

    /// The string value, `None` for any other JSON type.
    pub(super) fn str(self) -> Option<Cow<'a, str>> {
        let text = self.text()?;
        if !text.starts_with('"') {
            return None;
        }
        match serde_json::from_str::<&'a str>(text) {
            Ok(text) => Some(Cow::Borrowed(text)),
            Err(_) => serde_json::from_str::<String>(text).ok().map(Cow::Owned),
        }
    }

    pub(super) fn bool(self) -> Option<bool> {
        match self.text()?.trim_end() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }

    pub(super) fn u64(self) -> Option<u64> {
        let text = self.text()?;
        if !text.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        serde_json::from_str::<Value>(text).ok()?.as_u64()
    }

    pub(super) fn is_null(self) -> bool {
        self.text().is_some_and(|text| text.starts_with('n'))
    }

    pub(super) fn is_object(self) -> bool {
        self.first_byte() == Some(b'{')
    }

    pub(super) fn is_array(self) -> bool {
        self.first_byte() == Some(b'[')
    }

    /// The field as a `Value` (for small parts the classifier reads whole).
    pub(super) fn value(self) -> Option<Value> {
        serde_json::from_str(self.text()?).ok()
    }

    /// Truthiness as the kinds_version 1 reader defines it.
    pub(super) fn truthy(self) -> bool {
        match self.first_byte() {
            None | Some(b'n') => false,
            Some(b't') => true,
            Some(b'f') => false,
            Some(b'"') => self.str().is_some_and(|text| !text.is_empty()),
            Some(b'[') | Some(b'{') => self
                .value()
                .is_some_and(|value| super::super::measure::is_truthy_json(&value)),
            Some(_) => self.value().and_then(|value| value.as_f64()).unwrap_or(0.0) != 0.0,
        }
    }

    /// The elements of an array field.
    pub(super) fn elements(self) -> Option<Vec<Raw<'a>>> {
        if !self.is_array() {
            return None;
        }
        let items: Vec<&'a RawValue> = serde_json::from_str(self.text()?).ok()?;
        Some(items.into_iter().map(|raw| Raw(Some(raw))).collect())
    }

    /// Text length of the raw field (an upper bound of its content size).
    pub(super) fn raw_len(self) -> usize {
        self.0.map_or(0, |raw| raw.get().len())
    }
}

/// Decode `text` into a view `T`; a line with a duplicate key decodes once
/// more after `Value` keeps the last occurrence, as the v1 reader would.
macro_rules! decode_view {
    ($text:expr, $owned:ident, $ty:ty) => {
        match serde_json::from_str::<$ty>($text) {
            Ok(view) => Some(view),
            Err(_) => {
                $owned = $crate::context_composition::v2::decode::dedup_object($text);
                $owned
                    .as_deref()
                    .and_then(|text| serde_json::from_str::<$ty>(text).ok())
            }
        }
    };
}
pub(super) use decode_view;

pub(super) fn dedup_object(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    value
        .is_object()
        .then(|| serde_json::to_string(&value).ok())
        .flatten()
}

// -------------------------------------------------------------------------
// Line views.
// -------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct ClaudeLine<'a> {
    #[serde(rename = "type", borrow)]
    pub(super) kind: Raw<'a>,
    #[serde(borrow)]
    pub(super) timestamp: Raw<'a>,
    #[serde(borrow)]
    pub(super) ts: Raw<'a>,
    #[serde(borrow)]
    pub(super) uuid: Raw<'a>,
    #[serde(rename = "parentUuid", borrow)]
    pub(super) parent_uuid: Raw<'a>,
    #[serde(rename = "sessionId", borrow)]
    pub(super) session_id: Raw<'a>,
    #[serde(rename = "isSidechain", borrow)]
    pub(super) is_sidechain: Raw<'a>,
    #[serde(rename = "isCompactSummary", borrow)]
    pub(super) is_compact_summary: Raw<'a>,
    #[serde(borrow)]
    pub(super) subtype: Raw<'a>,
    #[serde(borrow)]
    pub(super) message: Raw<'a>,
    #[serde(borrow)]
    pub(super) attachment: Raw<'a>,
    #[serde(borrow)]
    pub(super) cwd: Raw<'a>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct MessageView<'a> {
    #[serde(borrow)]
    pub(super) id: Raw<'a>,
    #[serde(borrow)]
    pub(super) content: Raw<'a>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct BlockView<'a> {
    #[serde(rename = "type", borrow)]
    pub(super) kind: Raw<'a>,
    #[serde(borrow)]
    pub(super) id: Raw<'a>,
    #[serde(borrow)]
    pub(super) name: Raw<'a>,
    #[serde(borrow)]
    pub(super) input: Raw<'a>,
    #[serde(borrow)]
    pub(super) tool_use_id: Raw<'a>,
    #[serde(borrow)]
    pub(super) content: Raw<'a>,
    #[serde(borrow)]
    pub(super) text: Raw<'a>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct CodexLine<'a> {
    #[serde(rename = "type", borrow)]
    pub(super) kind: Raw<'a>,
    #[serde(borrow)]
    pub(super) timestamp: Raw<'a>,
    #[serde(borrow)]
    pub(super) ts: Raw<'a>,
    #[serde(borrow)]
    pub(super) ordinal: Raw<'a>,
    #[serde(borrow)]
    pub(super) payload: Raw<'a>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct CodexPayload<'a> {
    #[serde(rename = "type", borrow)]
    pub(super) kind: Raw<'a>,
    #[serde(borrow)]
    pub(super) role: Raw<'a>,
    #[serde(borrow)]
    pub(super) call_id: Raw<'a>,
    #[serde(borrow)]
    pub(super) name: Raw<'a>,
    #[serde(borrow)]
    pub(super) input: Raw<'a>,
    #[serde(borrow)]
    pub(super) arguments: Raw<'a>,
    #[serde(borrow)]
    pub(super) action: Raw<'a>,
    #[serde(borrow)]
    pub(super) output: Raw<'a>,
    #[serde(borrow)]
    pub(super) invocation: Raw<'a>,
    #[serde(borrow)]
    pub(super) result: Raw<'a>,
    #[serde(borrow)]
    pub(super) content: Raw<'a>,
    #[serde(borrow)]
    pub(super) internal_chat_message_metadata_passthrough: Raw<'a>,
    #[serde(borrow)]
    pub(super) item: Raw<'a>,
    #[serde(borrow)]
    pub(super) cwd: Raw<'a>,
    #[serde(borrow)]
    pub(super) trigger_turn: Raw<'a>,
}

/// The fields of a `session_meta` payload the reader needs.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct SessionMetaView<'a> {
    #[serde(borrow)]
    pub(super) id: Raw<'a>,
    #[serde(borrow)]
    pub(super) session_id: Raw<'a>,
    #[serde(borrow)]
    pub(super) thread_source: Raw<'a>,
    #[serde(borrow)]
    pub(super) source: Raw<'a>,
    #[serde(borrow)]
    pub(super) forked_from_id: Raw<'a>,
    #[serde(borrow)]
    pub(super) history_base: Raw<'a>,
    #[serde(borrow)]
    pub(super) subagent_history_start_ordinal: Raw<'a>,
    #[serde(borrow)]
    pub(super) cwd: Raw<'a>,
}

/// An `item_completed` item (only the item types the reader passes on).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct ItemView<'a> {
    #[serde(rename = "type", borrow)]
    pub(super) kind: Raw<'a>,
    #[serde(borrow)]
    pub(super) command: Raw<'a>,
    #[serde(borrow)]
    pub(super) cwd: Raw<'a>,
    #[serde(borrow)]
    pub(super) parsed_cmd: Raw<'a>,
    #[serde(borrow)]
    pub(super) aggregated_output: Raw<'a>,
    #[serde(borrow)]
    pub(super) server: Raw<'a>,
    #[serde(borrow)]
    pub(super) tool: Raw<'a>,
    #[serde(borrow)]
    pub(super) result: Raw<'a>,
    #[serde(rename = "kind", borrow)]
    pub(super) extension_kind: Raw<'a>,
    #[serde(borrow)]
    pub(super) results: Raw<'a>,
}

// -------------------------------------------------------------------------
// Dates.
// -------------------------------------------------------------------------

/// The line's timestamp: `timestamp`, else `ts` (strings only), in UTC.
pub(super) fn line_timestamp(timestamp: Raw, ts: Raw) -> Option<OffsetDateTime> {
    let text = timestamp.str().or_else(|| ts.str())?;
    OffsetDateTime::parse(&text, &Rfc3339)
        .ok()
        .map(|value| value.to_offset(UtcOffset::UTC))
}

// -------------------------------------------------------------------------
// Text measurement.
// -------------------------------------------------------------------------

/// The character length of texts joined by `\n`.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Joined {
    chars: usize,
    parts: usize,
}

impl Joined {
    pub(super) fn push_chars(&mut self, chars: usize) {
        self.chars += chars;
        self.parts += 1;
    }

    pub(super) fn push(&mut self, text: &str) {
        self.push_chars(text.chars().count());
    }

    pub(super) fn chars(self) -> usize {
        self.chars + self.parts.saturating_sub(1)
    }

    pub(super) fn is_empty(self) -> bool {
        self.chars() == 0
    }
}

/// `ceil(chars / 4)` (the v1 token estimate over a character count).
pub(super) fn tokens_for_chars(chars: usize) -> u64 {
    chars.div_ceil(super::super::CHARS_PER_TOKEN) as u64
}

/// Characters and image count of a tool result or message content, as
/// `measure::extract_blocks_text_and_images` measures them.
pub(super) fn content_chars_and_images(content: Raw) -> (usize, u64) {
    let Some(first) = content.first_byte() else {
        return (0, 0);
    };
    let blocks = match first {
        b'n' => return (0, 0),
        b'"' => return (content.str().map_or(0, |text| text.chars().count()), 0),
        b'[' => match content.elements() {
            Some(blocks) => blocks,
            None => return (0, 0),
        },
        b'{' => vec![content],
        _ => return (dumps_chars(content), 0),
    };
    let mut joined = Joined::default();
    let mut images = 0u64;
    for block in blocks {
        match block.first_byte() {
            Some(b'{') => {}
            Some(b'"') => {
                joined.push(&block.str().unwrap_or_default());
                continue;
            }
            _ => {
                joined.push_chars(dumps_chars(block));
                continue;
            }
        }
        let measured = match block.text() {
            Some(text) => {
                let owned: Option<String>;
                match decode_view!(text, owned, BlockKindView) {
                    Some(view) => measure_block(&view),
                    None => BlockMeasure::Dump,
                }
            }
            None => BlockMeasure::Dump,
        };
        match measured {
            BlockMeasure::Image => images += 1,
            BlockMeasure::Text(chars) => joined.push_chars(chars),
            BlockMeasure::Nothing => {}
            BlockMeasure::Dump => joined.push_chars(dumps_chars(block)),
        }
    }
    (joined.chars(), images)
}

/// A string output counts whole; anything else measures as content.
pub(super) fn output_chars_and_images(output: Raw) -> (usize, u64) {
    match output.str() {
        Some(text) => (text.chars().count(), 0),
        None => content_chars_and_images(output),
    }
}

fn measure_block(view: &BlockKindView) -> BlockMeasure {
    let kind = view.kind.str();
    match kind.as_deref().unwrap_or("") {
        "image" | "input_image" | "output_image" => BlockMeasure::Image,
        "text" | "input_text" | "output_text" => match view.text.str() {
            Some(text) => BlockMeasure::Text(text.chars().count()),
            None => BlockMeasure::Nothing,
        },
        _ => BlockMeasure::Dump,
    }
}

enum BlockMeasure {
    Image,
    Text(usize),
    Nothing,
    Dump,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BlockKindView<'a> {
    #[serde(rename = "type", borrow)]
    kind: Raw<'a>,
    #[serde(borrow)]
    text: Raw<'a>,
}

/// Length of the reference implementation's `json.dumps` of a field.
pub(super) fn dumps_chars(raw: Raw) -> usize {
    raw.value()
        .map_or(0, |value| python_json_dumps(&value).chars().count())
}

// -------------------------------------------------------------------------
// Records that are never counted, recognised before decoding.
// -------------------------------------------------------------------------

/// Claude attachment types never counted: the client's record of the system
/// prompt and tool list, and the bookkeeping for tools loaded later.
const CLAUDE_NEVER_COUNTED: [&[u8]; 2] = [b"prompt_snapshot\"", b"deferred_tools_record\""];
/// Codex top-level record types never counted: the client's state record,
/// token accounting and the compacted-history copy.
const CODEX_NEVER_COUNTED_TYPES: [&[u8]; 3] =
    [b"world_state\"", b"token_usage_record\"", b"compacted\""];
/// Codex payload types never counted (reasoning text is not shown to the
/// model again; token counts are bookkeeping). `item_completed` is read: its
/// inner items split a call's output.
const CODEX_NEVER_COUNTED_PAYLOADS: [&[u8]; 2] = [b"reasoning\"", b"token_count\""];
/// The keys sit near the line start; a later key is not checked.
const PREFIX_WINDOW: usize = 512;

/// Find `needle` in the line head, at the top level: nothing before it may
/// open an object or array (quotes inside strings are escaped, so a match
/// cannot fall inside a string value).
fn top_level_key(line: &[u8], needle: &[u8]) -> Option<usize> {
    let head = &line[..line.len().min(PREFIX_WINDOW)];
    if head.first() != Some(&b'{') {
        return None;
    }
    let index = head
        .windows(needle.len())
        .position(|window| window == needle)?;
    (!head[1..index]
        .iter()
        .any(|byte| matches!(byte, b'{' | b'[')))
    .then_some(index + needle.len())
}

pub(super) fn claude_never_counted(line: &[u8]) -> bool {
    let Some(after) = top_level_key(line, b"\"attachment\":{\"type\":\"") else {
        return false;
    };
    CLAUDE_NEVER_COUNTED
        .iter()
        .any(|kind| line[after..].starts_with(kind))
}

/// The same check on a decoded attachment type, for lines whose keys come in
/// another order.
pub(super) fn claude_never_counted_type(att_type: &str) -> bool {
    CLAUDE_NEVER_COUNTED
        .iter()
        .any(|kind| kind.strip_suffix(b"\"") == Some(att_type.as_bytes()))
}

pub(super) fn codex_never_counted(line: &[u8]) -> bool {
    let Some(after) = top_level_key(line, b"\"type\":\"") else {
        return false;
    };
    let rest = &line[after..];
    if CODEX_NEVER_COUNTED_TYPES
        .iter()
        .any(|kind| rest.starts_with(kind))
    {
        return true;
    }
    let Some(end) = rest.iter().position(|byte| *byte == b'"') else {
        return false;
    };
    let Some(payload) = rest[end..].strip_prefix(b"\",\"payload\":{\"type\":\"".as_slice()) else {
        return false;
    };
    CODEX_NEVER_COUNTED_PAYLOADS
        .iter()
        .any(|kind| payload.starts_with(kind))
}
