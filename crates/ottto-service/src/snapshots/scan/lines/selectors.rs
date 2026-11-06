//! Selector capture from one transcript line: the model, effort, gateway and
//! rate-limit selector fields Codex, Claude Code and Pi records declare, and
//! the bounded activity, skill and tool-usage counters reported per session.

use crate::snapshots::*;

pub(in crate::snapshots) fn raw_value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

pub(in crate::snapshots) fn normalize_selector_raw(field: &str, value: &Value) -> Option<String> {
    let normalized = match value {
        Value::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.trim().to_ascii_lowercase().replace([' ', '-'], "_"),
        _ => return None,
    };
    if normalized.is_empty() {
        return None;
    }
    let true_values = ["true", "1", "yes", "y", "on", "enabled"];
    let false_values = ["false", "0", "no", "n", "off", "disabled"];
    let standard_values = ["normal", "default", "base"];
    match field {
        "batch_mode" => {
            if true_values.contains(&normalized.as_str()) {
                Some("true".to_string())
            } else if false_values.contains(&normalized.as_str()) {
                Some("false".to_string())
            } else {
                None
            }
        }
        "mode" => {
            if true_values.contains(&normalized.as_str()) || normalized == "fast" {
                Some("fast".to_string())
            } else if false_values.contains(&normalized.as_str())
                || standard_values.contains(&normalized.as_str())
                || normalized == "standard"
            {
                Some("standard".to_string())
            } else if normalized == "priority" || normalized == "flex" {
                Some(normalized)
            } else {
                None
            }
        }
        "service_tier" | "speed_mode" => {
            if standard_values.contains(&normalized.as_str()) {
                Some("standard".to_string())
            } else {
                Some(normalized)
            }
        }
        "region_mode" => match normalized.as_str() {
            "us" | "usa" | "us_only" | "united_states" | "data_residency_us" => {
                Some("us".to_string())
            }
            "eu" | "eu_only" | "european_union" | "data_residency_eu" => Some("eu".to_string()),
            _ => Some(normalized),
        },
        _ => Some(normalized),
    }
}

fn selector_source_path(path: &[&str]) -> String {
    path.join(".")
}

pub(in crate::snapshots) fn insert_selector_raw(
    capture: &mut SelectorCapture,
    field: &str,
    source: &str,
    value: &Value,
) {
    let Some(normalized) = normalize_selector_raw(field, value) else {
        return;
    };
    capture.insert(field, normalized.clone(), source);
    if field == "speed_mode" && normalized == "fast" {
        capture.insert("service_tier", "fast".to_string(), "derived_from_speed");
    }
}

fn insert_selector_at(capture: &mut SelectorCapture, value: &Value, field: &str, path: &[&str]) {
    if let Some(raw) = raw_value_at(value, path) {
        insert_selector_raw(capture, field, selector_source_path(path).as_str(), raw);
    }
}

fn selector_from_object(value: &Value, source_prefix: &str) -> SelectorCapture {
    let mut capture = SelectorCapture::default();
    let Value::Object(map) = value else {
        return capture;
    };
    let aliases: &[(&str, &[&str])] = &[
        (
            "service_tier",
            &[
                "service_tier",
                "serviceTier",
                "service.tier",
                "actual_service_tier",
                "tier",
            ],
        ),
        ("speed_mode", &["speed_mode", "speedMode", "speed"]),
        ("batch_mode", &["batch_mode", "batchMode", "batch"]),
        (
            "region_mode",
            &[
                "region_mode",
                "regionMode",
                "data_residency",
                "dataResidency",
                "inference_geo",
                "inferenceGeo",
                "region",
            ],
        ),
        (
            "context_bucket",
            &[
                "context_bucket",
                "contextBucket",
                "context.bucket",
                "context_length_bucket",
                "contextLengthBucket",
            ],
        ),
        (
            "cache_ttl",
            &[
                "cache_ttl",
                "cacheTtl",
                "cache.ttl",
                "cache_write_ttl",
                "cache_write_ttl_seconds",
            ],
        ),
        (
            "mode",
            &[
                "mode",
                "service_mode",
                "serviceMode",
                "performance_mode",
                "performanceMode",
                "codex_mode",
                "codexMode",
                "fast_mode",
                "fastMode",
                "is_fast_mode",
                "isFastMode",
                "codex_fast_mode",
                "codexFastMode",
                "openai.fast_mode",
            ],
        ),
        (
            "gateway_provider",
            &["gateway_provider", "gatewayProvider", "api"],
        ),
        (
            "model_provider",
            &["model_provider", "modelProvider", "provider"],
        ),
        ("auth_mode", &["auth_mode", "authMode"]),
        ("billing_channel", &["billing_channel", "billingChannel"]),
        (
            "subscription_product",
            &[
                "subscription_product",
                "subscriptionProduct",
                "plan_type",
                "planType",
            ],
        ),
        (
            "plan_window_bucket",
            &["plan_window_bucket", "planWindowBucket"],
        ),
    ];
    for (field, field_aliases) in aliases {
        for alias in *field_aliases {
            let Some(raw) = map.get(*alias) else {
                continue;
            };
            let source = if source_prefix.is_empty() {
                alias.to_string()
            } else {
                format!("{source_prefix}.{alias}")
            };
            insert_selector_raw(&mut capture, field, source.as_str(), raw);
            break;
        }
    }
    for nested_key in ["selector_context", "selector"] {
        if let Some(nested) = map.get(nested_key) {
            let source = if source_prefix.is_empty() {
                nested_key.to_string()
            } else {
                format!("{source_prefix}.{nested_key}")
            };
            capture.merge(selector_from_object(nested, source.as_str()));
        }
    }
    capture
}

fn merge_selector_object_at(capture: &mut SelectorCapture, value: &Value, path: &[&str]) {
    if let Some(raw) = raw_value_at(value, path) {
        capture.merge(selector_from_object(
            raw,
            selector_source_path(path).as_str(),
        ));
    }
}

pub(in crate::snapshots) fn codex_selector_from_line(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    let object_paths: &[&[&str]] = &[
        &[],
        &["payload"],
        &["turn_context", "payload"],
        &["payload", "info"],
        &["token_count", "info"],
        &["payload", "rate_limits"],
        &["token_count", "info", "rate_limits"],
    ];
    for path in object_paths {
        merge_selector_object_at(&mut selector, value, path);
    }
    if let Some(bucket) = codex_plan_window_bucket(value) {
        insert_selector_raw(
            &mut selector,
            "plan_window_bucket",
            "derived_from_rate_limits_secondary_resets_at",
            &Value::Number(bucket.into()),
        );
    }
    codex_extract_quota_window_selectors(value, &mut selector);
    insert_selector_raw(
        &mut selector,
        "model_provider",
        "derived_from_codex_source",
        &Value::String("openai".to_string()),
    );
    let service_tier_paths: &[&[&str]] = &[
        &["token_count", "info", "service_tier"],
        &["payload", "info", "service_tier"],
        &["turn_context", "payload", "service_tier"],
        &["payload", "service_tier"],
        &["service_tier"],
    ];
    for path in service_tier_paths {
        insert_selector_at(&mut selector, value, "service_tier", path);
    }
    let fast_mode_paths: &[&[&str]] = &[
        &["payload", "fast_mode"],
        &["fast_mode"],
        &["codex_fast_mode"],
    ];
    for path in fast_mode_paths {
        insert_selector_at(&mut selector, value, "mode", path);
    }
    let mode_paths: &[&[&str]] = &[&["payload", "mode"], &["mode"]];
    for path in mode_paths {
        insert_selector_at(&mut selector, value, "mode", path);
    }
    let extra_paths: &[(&str, &[&[&str]])] = &[
        (
            "batch_mode",
            &[
                &["payload", "batch_mode"],
                &["payload", "info", "batch_mode"],
                &["batch_mode"],
            ],
        ),
        (
            "region_mode",
            &[
                &["payload", "inference_geo"],
                &["payload", "info", "inference_geo"],
                &["inference_geo"],
            ],
        ),
        (
            "context_bucket",
            &[
                &["payload", "context_bucket"],
                &["payload", "info", "context_bucket"],
                &["context_bucket"],
            ],
        ),
    ];
    for (field, paths) in extra_paths {
        for path in *paths {
            insert_selector_at(&mut selector, value, field, path);
        }
    }
    selector
}

pub(in crate::snapshots) fn claude_code_selector_from_line(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    let usage_paths: &[&[&str]] = &[&["message", "usage"], &["usage"], &["payload", "usage"]];
    for path in usage_paths {
        if let Some(raw) = raw_value_at(value, path) {
            selector.merge(selector_from_object(
                raw,
                selector_source_path(path).as_str(),
            ));
        }
    }
    selector.merge(selector_from_object(value, ""));
    if let Some(gateway) = detect_claude_gateway_provider(value) {
        let raw = Value::String(gateway);
        insert_selector_raw(
            &mut selector,
            "gateway_provider",
            "derived_from_message_id_prefix",
            &raw,
        );
        insert_selector_raw(
            &mut selector,
            "model_provider",
            "derived_from_claude_code_source",
            &Value::String("anthropic".to_string()),
        );
    }
    selector
}

pub(in crate::snapshots) fn detect_claude_gateway_provider(value: &Value) -> Option<String> {
    let id = string_at(value, &["message", "id"]).or_else(|| string_at(value, &["requestId"]))?;
    if id.contains("_vrtx_") {
        return Some("vertex".into());
    }
    if id.contains("_bdrk_") {
        return Some("bedrock".into());
    }
    if id.starts_with("msg_") || id.starts_with("req_") {
        return Some("anthropic".into());
    }
    None
}

pub(in crate::snapshots) fn pi_selector_from_custom(value: &Value) -> Option<SelectorCapture> {
    let custom_type = string_at(value, &["customType"])
        .or_else(|| string_at(value, &["custom_type"]))
        .or_else(|| string_at(value, &["name"]))?;
    if custom_type != "ottto-selector" && custom_type != "ottto.selector" {
        return None;
    }
    let mut selector = SelectorCapture::default();
    if let Some(data) = raw_value_at(value, &["data"]) {
        selector.merge(selector_from_object(data, "data"));
    }
    selector.merge(selector_from_object(value, ""));
    (!selector.is_empty()).then_some(selector)
}

pub(in crate::snapshots) fn pi_selector_from_usage_message(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    selector.merge(selector_from_object(value, ""));
    if let Some(message) = raw_value_at(value, &["message"]) {
        selector.merge(selector_from_object(message, "message"));
    }
    if let Some(usage) = raw_value_at(value, &["message", "usage"]) {
        selector.merge(selector_from_object(usage, "message.usage"));
    }
    selector
}

pub(in crate::snapshots) fn bounded_activity_label(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 96
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        return None;
    }
    Some(value.to_string())
}

pub(in crate::snapshots) fn nested_unified_exec_tools(material: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut remaining = material;
    while let Some(index) = remaining.find("tools.") {
        remaining = &remaining[index + "tools.".len()..];
        let end = remaining
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .unwrap_or(remaining.len());
        let candidate = &remaining[..end];
        let suffix = remaining[end..].trim_start();
        if suffix.starts_with('(') {
            if let Some(name) = bounded_activity_label(candidate) {
                names.push(name);
            }
        }
        remaining = &remaining[end..];
    }
    names
}

pub(in crate::snapshots) const MAX_ACTIVITY_SKILLS: usize = 32;

const SKILL_MD: &str = "SKILL.md";

/// Calls `on_name` with the immediate parent directory of every `…/<name>/SKILL.md`
/// path token in `material` (any root: `.agents/skills`, plugin caches,
/// `skills/.system`, synced buckets, relative paths). Returns false when a
/// SKILL.md reference could not be named (`cat SKILL.md`, `skills/*/SKILL.md`,
/// `"$D/SKILL.md"`). A delimiter scan, not a shell parser; no file is read.
pub(in crate::snapshots) fn for_each_skill_md_reference(
    material: &str,
    mut on_name: impl FnMut(String),
) -> bool {
    let is_delimiter = |ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '=' | '(' | ')' | ';' | '|' | '&' | '<' | '>' | ',' | '`'
            )
    };
    let mut named_all = true;
    for (index, _) in material.match_indices(SKILL_MD) {
        let after = &material[index + SKILL_MD.len()..];
        if after
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
        {
            continue; // SKILL.md.backup, SKILL.mdx
        }
        let before = &material[..index];
        let Some(directory) = before.strip_suffix('/') else {
            if before.chars().next_back().map_or(true, is_delimiter) {
                named_all = false; // bare SKILL.md: a reference to an unknown skill
            }
            continue; // MY_SKILL.md and similar are other files
        };
        // Walk back only over the parent segment: segments of different
        // matches are disjoint, so the whole scan stays linear.
        let parent_start = directory
            .char_indices()
            .rev()
            .find(|&(_, ch)| ch == '/' || is_delimiter(ch))
            .map_or(0, |(at, ch)| at + ch.len_utf8());
        let parent = &directory[parent_start..];
        match bounded_activity_label(parent).filter(|name| name != "." && name != "..") {
            Some(name) => on_name(name),
            None => named_all = false,
        }
    }
    named_all
}

pub(in crate::snapshots) fn bounded_activity_counts(
    counts: &BTreeMap<String, u64>,
    limit: usize,
) -> Vec<SnapshotActivityCount> {
    let mut rows = counts
        .iter()
        .map(|(name, count)| SnapshotActivityCount {
            name: name.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    rows.truncate(limit);
    rows
}

/// Codex `tool_usage`: plain tool names plus `mcp__<server>__<tool>` MCP
/// names, highest counts kept when more than `MAX_TOOL_USAGE_NAMES` exist.
pub(in crate::snapshots) fn codex_tool_usage_rows(
    tool_counts: &BTreeMap<String, u64>,
    mcp_tool_counts: &BTreeMap<String, u64>,
) -> (Vec<SnapshotToolUsage>, bool) {
    let mut merged: BTreeMap<String, u64> = BTreeMap::new();
    for (name, count) in tool_counts.iter().chain(mcp_tool_counts) {
        if *count == 0 {
            continue;
        }
        if let Some(name) = bounded_tool_usage_name(name) {
            let entry = merged.entry(name).or_default();
            *entry = entry.saturating_add(*count);
        }
    }
    let mut rows = bounded_tool_usage_counts(&merged);
    let truncated = rows.len() > MAX_TOOL_USAGE_NAMES;
    rows.truncate(MAX_TOOL_USAGE_NAMES);
    (rows, truncated)
}

pub(in crate::snapshots) fn bounded_tool_usage_counts(
    counts: &BTreeMap<String, u64>,
) -> Vec<SnapshotToolUsage> {
    let mut rows = counts
        .iter()
        .map(|(name, count)| SnapshotToolUsage {
            name: name.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    rows
}

pub(in crate::snapshots) fn bounded_tool_usage_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        return None;
    }
    Some(value.chars().take(MAX_TOOL_USAGE_NAME_LENGTH).collect())
}
