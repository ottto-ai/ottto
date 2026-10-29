//! Shared text and token measurement, with test-only residency, line dates
//! and whole-file reading for the V1 parser oracle.

use super::CHARS_PER_TOKEN;
use serde_json::Value;
#[cfg(test)]
use std::fs;
use std::path::Path;
use time::Date;
#[cfg(test)]
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

// -------------------------------------------------------------------------
// Primitive measurement helpers (ported 1:1 from the reference).
// -------------------------------------------------------------------------

/// `ceil(chars / 4)`. Uses Unicode scalar count (Python `len`), not bytes.
pub(crate) fn estimate_text_tokens(text: &str) -> u64 {
    let chars = text.chars().count();
    if chars == 0 {
        return 0;
    }
    chars.div_ceil(CHARS_PER_TOKEN) as u64
}

/// Python-compatible `json.dumps(x, ensure_ascii=False)` LENGTH. Only the
/// character length matters (it feeds `estimate_text_tokens`), and length is
/// independent of object key order, so a sorted-key serialization with Python's
/// default `", "` / `": "` separators produces the same length Python would.
pub(super) fn python_json_dumps(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(_) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(python_json_dumps).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    let key = serde_json::to_string(&Value::String(k.clone()))
                        .unwrap_or_else(|_| "\"\"".to_string());
                    format!("{}: {}", key, python_json_dumps(v))
                })
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Best-effort reconstruction of the text a Claude Code attachment injects.
pub(super) fn serialize_attachment(att: &Value) -> String {
    let Some(obj) = att.as_object() else {
        return python_json_dumps(att);
    };
    let mut parts: Vec<String> = Vec::new();
    for key in [
        "content",
        "snippet",
        "banner",
        "prompt",
        "command",
        "blockingError",
    ] {
        if let Some(Value::String(s)) = obj.get(key) {
            if !s.is_empty() {
                parts.push(s.clone());
            }
        }
    }
    for key in ["addedLines", "addedBlocks", "removedLines"] {
        if let Some(Value::Array(items)) = obj.get(key) {
            if !items.is_empty() {
                for item in items {
                    match item {
                        Value::String(s) => parts.push(s.clone()),
                        other => parts.push(python_json_dumps(other)),
                    }
                }
            }
        }
    }
    if !parts.is_empty() {
        parts.join("\n")
    } else {
        python_json_dumps(att)
    }
}

/// Return `(text, image_count)` for a tool_result / message content value.
pub(super) fn extract_blocks_text_and_images(content: Option<&Value>) -> (String, u64) {
    let content = match content {
        None | Some(Value::Null) => return (String::new(), 0),
        Some(Value::String(s)) => return (s.clone(), 0),
        Some(other) => other,
    };
    // Borrow blocks: image bodies are counted, so copying them serves no purpose.
    let blocks: &[Value] = match content {
        Value::Array(items) => items.as_slice(),
        Value::Object(_) => std::slice::from_ref(content),
        other => return (python_json_dumps(other), 0),
    };
    let mut texts: Vec<String> = Vec::new();
    let mut images: u64 = 0;
    for block in blocks {
        let Some(obj) = block.as_object() else {
            // Non-dict element: str(block). For a JSON string that is the raw
            // string; otherwise the compact python repr length is dominated by
            // the same characters, so a json-length proxy is used.
            match block {
                Value::String(s) => texts.push(s.clone()),
                other => texts.push(python_json_dumps(other)),
            }
            continue;
        };
        let bt = obj.get("type").and_then(Value::as_str).unwrap_or("");
        if matches!(bt, "image" | "input_image" | "output_image") {
            images += 1;
            continue;
        }
        if matches!(bt, "text" | "input_text" | "output_text") {
            if let Some(Value::String(t)) = obj.get("text") {
                texts.push(t.clone());
            }
            continue;
        }
        // tool_reference / unknown structured sub-block -> serialize as text.
        texts.push(python_json_dumps(block));
    }
    (texts.join("\n"), images)
}

// -------------------------------------------------------------------------
// Residency model (ported 1:1).
// -------------------------------------------------------------------------

/// residency_multiplier(L) = number of assistant/model turns strictly after L
/// and strictly before the next compaction boundary.
#[cfg(test)]
pub(super) struct ResidencyModel {
    pub(super) assistant: Vec<usize>,
    pub(super) compaction: Vec<usize>,
}

#[cfg(test)]
impl ResidencyModel {
    pub(super) fn new(mut assistant: Vec<usize>, mut compaction: Vec<usize>) -> Self {
        assistant.sort_unstable();
        compaction.sort_unstable();
        Self {
            assistant,
            compaction,
        }
    }

    pub(super) fn multiplier(&self, ordinal: usize) -> u64 {
        // next compaction boundary strictly after this ordinal (cap).
        let ci = self.compaction.partition_point(|&x| x <= ordinal);
        let cap = self.compaction.get(ci).copied();
        // assistant turns with ordinal in (L, cap).
        let lo = self.assistant.partition_point(|&x| x <= ordinal);
        let hi = match cap {
            Some(c) => self.assistant.partition_point(|&x| x < c),
            None => self.assistant.len(),
        };
        hi.saturating_sub(lo) as u64
    }
}

// -------------------------------------------------------------------------
// Line timestamp / date helpers.
// -------------------------------------------------------------------------

#[cfg(test)]
pub(super) fn parse_timestamp(value: &Value) -> Option<OffsetDateTime> {
    let text = value
        .get("timestamp")
        .and_then(Value::as_str)
        .or_else(|| value.get("ts").and_then(Value::as_str))?;
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|dt| dt.to_offset(UtcOffset::UTC))
}

/// The UTC date to bucket a line under, and its parsed timestamp. Falls back to
/// the transcript file's date when the line carries no parseable timestamp.
#[cfg(test)]
pub(super) fn line_date(value: &Value, fallback: Date) -> (Date, Option<OffsetDateTime>) {
    match parse_timestamp(value) {
        Some(ts) => (ts.date(), Some(ts)),
        None => (fallback, None),
    }
}

pub(super) fn date_ymd(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

#[cfg(test)]
pub(super) fn read_jsonl(path: &Path) -> std::io::Result<Vec<Value>> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for raw in text.lines() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            out.push(value);
        }
    }
    Ok(out)
}

pub(super) fn is_truthy_json(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|v| v != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Null => false,
    }
}

#[cfg(test)]
pub(super) fn basename(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("session")
        .to_string()
}

pub(super) fn basename_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("session")
        .to_string()
}
