//! Exact provider credit amounts at the provider decode boundary.
//!
//! `serde_json::Value` keeps a fractional number only as `f64`, which rounds a
//! credit balance's digits. The three provider decodes that carry credit
//! amounts (the Claude OAuth usage response, the Claude Code config's cached
//! usage, and a Codex app-server message) decode through [`decode`], which
//! re-reads the credit subtrees from the raw text and keeps each fractional
//! number there as its exact lexeme, a JSON string. Every credit amount is then
//! read through [`amount`] / [`amount_at`] (Claude money: the adapter's
//! `claude_oauth_money_cents`) into the one scaler of
//! [`ottto_protocol::CreditAmount`]; a float that bypassed [`decode`] is
//! refused rather than rounded.
//!
//! Every other reader of these subtrees (percentages, times, flags) accepts a
//! numeric string exactly as it accepts the number.

use std::collections::BTreeMap;

use ottto_protocol::CreditAmount;
use serde_json::value::RawValue;
use serde_json::Value;

/// Which provider body a decode reads; each one names its credit subtrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CreditBody {
    /// A Claude OAuth usage body: `spend`, `extra_usage`, and the `*_dollars`
    /// fields of every other top-level object (windows and one-time pools).
    ClaudeUsage,
    /// A Claude Code config: the usage body at
    /// `cachedUsageUtilization.utilization`.
    ClaudeConfig,
    /// One Codex app-server message: every `credits` and `individualLimit`
    /// object, at any object depth.
    CodexMessage,
}

/// Where the walk stands inside a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Walk {
    Body(CreditBody),
    CachedUsage,
    DollarFields,
    Credit,
}

impl Walk {
    /// The walk under `key` of an object at this position; `None` skips it.
    fn child(self, key: &str) -> Option<Self> {
        match self {
            Self::Body(CreditBody::ClaudeUsage) => Some(match key {
                "spend" | "extra_usage" => Self::Credit,
                _ => Self::DollarFields,
            }),
            Self::Body(CreditBody::ClaudeConfig) => {
                (key == "cachedUsageUtilization").then_some(Self::CachedUsage)
            }
            Self::CachedUsage => {
                (key == "utilization").then_some(Self::Body(CreditBody::ClaudeUsage))
            }
            Self::DollarFields => key.ends_with("_dollars").then_some(Self::Credit),
            Self::Body(CreditBody::CodexMessage) => Some(match key {
                "credits" | "individualLimit" | "individual_limit" => Self::Credit,
                _ => self,
            }),
            Self::Credit => Some(self),
        }
    }
}

/// Decode one provider body, keeping every fractional number inside its
/// credit subtrees as its exact lexeme. `None` when `text` is not JSON.
pub(super) fn decode(text: &str, body: CreditBody) -> Option<Value> {
    let mut value = serde_json::from_str::<Value>(text).ok()?;
    let raw = serde_json::from_str::<&RawValue>(text).ok()?;
    keep_lexemes(&mut value, raw, Walk::Body(body));
    Some(value)
}

fn keep_lexemes(value: &mut Value, raw: &RawValue, walk: Walk) {
    if walk == Walk::Credit && matches!(value, Value::Number(number) if number.is_f64()) {
        *value = Value::String(raw.get().to_string());
        return;
    }
    let Value::Object(fields) = value else {
        return;
    };
    let Ok(raw_fields) = serde_json::from_str::<BTreeMap<String, &RawValue>>(raw.get()) else {
        return;
    };
    for (key, field) in fields.iter_mut() {
        if let (Some(walk), Some(raw)) = (walk.child(key), raw_fields.get(key)) {
            keep_lexemes(field, raw, walk);
        }
    }
}

/// A native-unit amount: an integer JSON number or a decimal string. A float
/// number (one that did not come through [`decode`]) is absent.
fn amount(value: &Value) -> Option<CreditAmount> {
    match value {
        Value::Number(number) => CreditAmount::whole(number.as_u64()?),
        Value::String(text) => CreditAmount::from_decimal(text),
        _ => None,
    }
}

/// The amount at the first of `keys` that holds a valid one.
pub(super) fn amount_at(value: &Value, keys: &[&str]) -> Option<CreditAmount> {
    keys.iter().find_map(|key| amount(value.get(*key)?))
}

/// Whether `value` is a number, or a number's lexeme kept by [`decode`].
pub(super) fn is_number(value: &Value) -> bool {
    value.is_number()
        || value
            .as_str()
            .is_some_and(|text| serde_json::from_str::<serde_json::Number>(text).is_ok())
}
