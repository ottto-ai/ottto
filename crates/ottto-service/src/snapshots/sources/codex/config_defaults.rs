//! Codex runtime defaults read from `~/.codex/config.toml`.

use std::collections::BTreeMap;
use toml_edit::{DocumentMut, Item};

use crate::snapshots::codex_config_selector;

/// Display-safe Codex runtime defaults parsed from `~/.codex/config.toml`.
///
/// These are configured defaults, not evidence a session actually ran with
/// them. `selector_context`/`selector_sources` carry the raw config-derived
/// values with their `codex.config.*` provenance so downstream layers can keep
/// defaults separate from observed selector evidence.
#[derive(Debug, Clone, Default)]
pub(crate) struct CodexConfigDefaults {
    pub model: Option<String>,
    pub service_tier: Option<String>,
    pub reasoning_effort: Option<String>,
    pub approval_policy: Option<String>,
    pub fast_mode: Option<bool>,
    pub fast_default_opt_out: bool,
    pub selector_context: BTreeMap<String, String>,
    pub selector_sources: BTreeMap<String, String>,
}

impl CodexConfigDefaults {
    /// Effective Fast default for display. `service_tier` is authoritative when
    /// set; otherwise fall back to the legacy `[features].fast_mode` flag minus
    /// any fast-default opt-out. Returns `None` when nothing in config implies a
    /// tier, so the UI can stay quiet rather than guess.
    pub(crate) fn display_fast_mode(&self) -> Option<bool> {
        if let Some(tier) = self.service_tier.as_deref() {
            match tier.trim().to_ascii_lowercase().as_str() {
                "priority" | "fast" | "premium" => return Some(true),
                "default" | "standard" | "flex" | "batch" => return Some(false),
                _ => {}
            }
        }
        match self.fast_mode {
            Some(true) => Some(!self.fast_default_opt_out),
            Some(false) => Some(false),
            None => {
                if self.fast_default_opt_out {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }
}

pub(crate) fn parse_codex_config_defaults(raw: &str) -> Option<CodexConfigDefaults> {
    let document = raw.parse::<DocumentMut>().ok()?;
    let read_top_str = |key: &str| {
        document
            .get(key)
            .and_then(Item::as_value)
            .and_then(|value| value.as_str())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let model = read_top_str("model").or_else(|| read_top_str("default_model"));
    let service_tier = read_top_str("service_tier");
    let reasoning_effort =
        read_top_str("model_reasoning_effort").or_else(|| read_top_str("reasoning_effort"));
    let approval_policy = read_top_str("approval_policy");
    let fast_mode = document
        .get("features")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_mode"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool());
    let top_level_opt_out = document
        .get("fast_default_opt_out")
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let notice_opt_out = document
        .get("notice")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_default_opt_out"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let fast_default_opt_out = top_level_opt_out || notice_opt_out;
    let selector = codex_config_selector(&document);
    let has_any = model.is_some()
        || service_tier.is_some()
        || reasoning_effort.is_some()
        || approval_policy.is_some()
        || fast_mode.is_some()
        || fast_default_opt_out
        || !selector.context.is_empty();
    if !has_any {
        return None;
    }
    Some(CodexConfigDefaults {
        model,
        service_tier,
        reasoning_effort,
        approval_policy,
        fast_mode,
        fast_default_opt_out,
        selector_context: selector.context,
        selector_sources: selector.sources,
    })
}
