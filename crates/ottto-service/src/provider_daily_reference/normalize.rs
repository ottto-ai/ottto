//! Normalization of a provider payload into contract rows: counters, a closed
//! surface, a bounded model slug and a UTC day. Nothing else from the payload
//! reaches a row; the window also keeps a refresh time and bounded key names
//! for local diagnostics.

use super::batching::parse_day;
use super::provider_read::ProviderReadError;
use super::wire::{
    normalized_model_slug, surface_for_client_id, DailyReferenceRow, Surface,
    PROVIDER_DAY_TOTAL_SURFACE,
};
use super::{timestamp, ALL_MODELS};
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// A counter merge that preserves "not reported".
///
/// Two provider client ids can collapse onto the same local surface (every
/// unrecognized id becomes `other`), so their rows have to combine. `None`
/// means the provider did not report the counter, so it contributes nothing
/// and never turns a reported value back into "not reported".
fn merge_counter(left: Option<u64>, right: Option<u64>, max: u64) -> Option<u64> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value.min(max)),
        (Some(left), Some(right)) => Some(left.saturating_add(right).min(max)),
    }
}

fn merge_credits(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value.min(MAX_CREDITS)),
        (Some(left), Some(right)) => Some((left + right).min(MAX_CREDITS)),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Counters {
    credits_used: Option<f64>,
    uncached_input_tokens: Option<u64>,
    cached_input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    thread_count: Option<u64>,
    turn_count: Option<u64>,
}

const MAX_TOTAL_MISMATCH_DETAILS: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayTotalMismatch {
    pub provider_day: String,
    pub metric: &'static str,
    pub provider_value: String,
    pub recognized_client_value: String,
}

fn compare_day_total(
    provider_day: &str,
    provider: &Counters,
    recognized_clients: &Counters,
    details: &mut Vec<DayTotalMismatch>,
) -> (bool, bool) {
    let mut compared = false;
    let mut mismatched = false;

    let mut record = |metric: &'static str, provider_value: String, client_value: String| {
        compared = true;
        if provider_value != client_value {
            mismatched = true;
            if details.len() < MAX_TOTAL_MISMATCH_DETAILS {
                details.push(DayTotalMismatch {
                    provider_day: provider_day.to_string(),
                    metric,
                    provider_value,
                    recognized_client_value: client_value,
                });
            }
        }
    };

    if let (Some(provider), Some(clients)) =
        (provider.credits_used, recognized_clients.credits_used)
    {
        record(
            "credits_used",
            format_credits(provider),
            format_credits(clients),
        );
    }
    macro_rules! compare_counter {
        ($field:ident) => {
            if let (Some(provider), Some(clients)) = (provider.$field, recognized_clients.$field) {
                record(
                    stringify!($field),
                    provider.to_string(),
                    clients.to_string(),
                );
            }
        };
    }
    compare_counter!(uncached_input_tokens);
    compare_counter!(cached_input_tokens);
    compare_counter!(output_tokens);
    compare_counter!(total_tokens);
    compare_counter!(thread_count);
    compare_counter!(turn_count);

    (compared, mismatched)
}

impl Counters {
    fn merge(&mut self, other: &Counters) {
        self.credits_used = merge_credits(self.credits_used, other.credits_used);
        self.uncached_input_tokens = merge_counter(
            self.uncached_input_tokens,
            other.uncached_input_tokens,
            MAX_TOKEN_COUNTER,
        );
        self.cached_input_tokens = merge_counter(
            self.cached_input_tokens,
            other.cached_input_tokens,
            MAX_TOKEN_COUNTER,
        );
        self.output_tokens =
            merge_counter(self.output_tokens, other.output_tokens, MAX_TOKEN_COUNTER);
        self.total_tokens = merge_counter(self.total_tokens, other.total_tokens, MAX_TOKEN_COUNTER);
        self.thread_count = merge_counter(self.thread_count, other.thread_count, MAX_EVENT_COUNTER);
        self.turn_count = merge_counter(self.turn_count, other.turn_count, MAX_EVENT_COUNTER);
    }

    fn is_empty(&self) -> bool {
        *self == Counters::default()
    }
}

/// Contract ceilings. A value above these is not a large number, it is a
/// payload we have misread - and sending it would 422 the whole batch for
/// every day in the window, permanently.
const MAX_TOKEN_COUNTER: u64 = 1_000_000_000_000_000;
const MAX_EVENT_COUNTER: u64 = 1_000_000_000;
const MAX_CREDITS: f64 = 1e9;

/// Read a non-negative integer counter, only when the provider actually
/// reported it and only when it fits the contract.
///
/// A present-but-unreadable or out-of-range value stays `None` rather than
/// becoming `0`: "not reported" is the honest answer for a number we cannot
/// represent, and `0` would manufacture a reconciliation delta.
fn counter_at(value: &Value, keys: &[&str], max: u64) -> Option<u64> {
    let raw = keys.iter().find_map(|key| value.get(*key))?;
    match raw {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().filter(|v| *v >= 0.0).map(|v| v as u64))
            .filter(|counter| *counter <= max),
        _ => None,
    }
}

fn credits_at(value: &Value, keys: &[&str]) -> Option<f64> {
    let raw = keys.iter().find_map(|key| value.get(*key))?;
    raw.as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0 && *value <= MAX_CREDITS)
}

fn counters_at(value: &Value, include_credits: bool) -> Counters {
    Counters {
        credits_used: include_credits
            .then(|| {
                credits_at(
                    value,
                    &["credits", "credits_used", "credit_usage", "total_credits"],
                )
            })
            .flatten(),
        uncached_input_tokens: counter_at(
            value,
            &[
                "uncached_text_input_tokens",
                "uncached_input_tokens",
                "input_tokens_uncached",
                "text_input_tokens_uncached",
            ],
            MAX_TOKEN_COUNTER,
        ),
        cached_input_tokens: counter_at(
            value,
            &[
                "cached_text_input_tokens",
                "cached_input_tokens",
                "input_tokens_cached",
                "text_input_tokens_cached",
            ],
            MAX_TOKEN_COUNTER,
        ),
        output_tokens: counter_at(
            value,
            &[
                "text_output_tokens",
                "output_tokens",
                "completion_tokens",
                "generated_tokens",
            ],
            MAX_TOKEN_COUNTER,
        ),
        total_tokens: counter_at(
            value,
            &[
                "text_total_tokens",
                "total_tokens",
                "token_count",
                "total_token_count",
                "tokens",
            ],
            MAX_TOKEN_COUNTER,
        ),
        thread_count: counter_at(
            value,
            &["threads", "thread_count", "threads_count", "total_threads"],
            MAX_EVENT_COUNTER,
        ),
        turn_count: counter_at(
            value,
            &["turns", "turn_count", "turns_count", "total_turns"],
            MAX_EVENT_COUNTER,
        ),
    }
}

const DAY_DATE_KEYS: &[&str] = &[
    "date",
    "day",
    "usage_date",
    "bucket_start",
    "start_date",
    "timestamp",
    "created_at",
    "start",
    "period_start",
];
const CLIENT_ARRAY_KEYS: &[&str] = &[
    "clients",
    "client_breakdown",
    "by_client",
    "per_client",
    "client_counts",
    "breakdown",
    "surfaces",
    "clients_data",
    "client_data",
];
const DAY_TOTAL_KEYS: &[&str] = &["totals"];
const USER_COUNT_KEYS: &[&str] = &["users"];
const CLIENT_ID_KEYS: &[&str] = &["client_id", "client", "id", "name", "surface", "surface_id"];
const MODEL_ARRAY_KEYS: &[&str] = &[
    "models",
    "model_breakdown",
    "by_model",
    "per_model",
    "model_list",
    "models_data",
    "model_data",
];
const MODEL_NAME_KEYS: &[&str] = &[
    "model",
    "model_id",
    "model_slug",
    "name",
    "model_name",
    "identifier",
    "slug",
];
const COUNTER_KEYS: &[&str] = &[
    "credits",
    "credits_used",
    "credit_usage",
    "total_credits",
    "uncached_text_input_tokens",
    "uncached_input_tokens",
    "input_tokens_uncached",
    "text_input_tokens_uncached",
    "cached_text_input_tokens",
    "cached_input_tokens",
    "input_tokens_cached",
    "text_input_tokens_cached",
    "text_output_tokens",
    "output_tokens",
    "completion_tokens",
    "generated_tokens",
    "text_total_tokens",
    "total_tokens",
    "token_count",
    "total_token_count",
    "tokens",
    "threads",
    "thread_count",
    "threads_count",
    "total_threads",
    "turns",
    "turn_count",
    "turns_count",
    "total_turns",
];
pub(super) const MAX_UNRECOGNIZED_KEYS: usize = 12;
pub(super) const MAX_REPORTED_KEY_CHARS: usize = 40;

fn record_unrecognized_keys(
    value: &Value,
    recognized_groups: &[&[&str]],
    unrecognized: &mut BTreeSet<String>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for key in object.keys() {
        if recognized_groups
            .iter()
            .any(|group| group.contains(&key.as_str()))
        {
            continue;
        }
        let bounded: String = key.chars().take(MAX_REPORTED_KEY_CHARS).collect();
        unrecognized.insert(bounded);
        if unrecognized.len() > MAX_UNRECOGNIZED_KEYS {
            if let Some(last) = unrecognized.iter().next_back().cloned() {
                unrecognized.remove(&last);
            }
        }
    }
}

fn first_array<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Vec<Value>> {
    if let Value::Array(items) = value {
        return Some(items);
    }
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array))
}

fn first_object<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a serde_json::Map<String, Value>> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_object))
}

fn first_string<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Accept only a plain `YYYY-MM-DD` UTC day, or the date part of a timestamp.
pub(super) fn provider_day(raw: &str) -> Option<String> {
    let candidate = raw.trim();
    let day = candidate.split(['T', ' ']).next()?;
    let bytes = day.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    let shaped = bytes.iter().enumerate().all(|(index, byte)| match index {
        4 | 7 => *byte == b'-',
        _ => byte.is_ascii_digit(),
    });
    if !shaped {
        return None;
    }
    // Reject an impossible day rather than uploading it as a provider fact.
    parse_day(day)?;
    Some(day.to_string())
}

/// What one provider window normalized to.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NormalizedWindow {
    pub rows: Vec<DailyReferenceRow>,
    pub provider_data_refreshed_at: Option<String>,
    /// Model identifiers the contract's slug cannot represent. Counted, never
    /// coerced, and never uploaded.
    pub dropped_model_rows: usize,
    pub days_seen: usize,
    pub days_recognized: usize,
    pub days_out_of_window: usize,
    pub days_no_client_breakdown: usize,
    pub days_used_fallback: usize,
    pub days_missing_date: usize,
    pub clients_seen: usize,
    pub clients_missing_id: usize,
    pub clients_no_model_breakdown: usize,
    pub models_seen: usize,
    pub models_missing_id: usize,
    pub entries_empty_counters: usize,
    pub day_totals_seen: usize,
    pub day_totals_compared: usize,
    pub day_total_mismatch_days: usize,
    pub day_total_mismatches: Vec<DayTotalMismatch>,
    pub user_count_fields_seen: usize,
    pub user_count_fields_unreadable: usize,
    /// Structure-only provider shape hints. These sets contain bounded key
    /// names, never the corresponding values or account identifiers.
    pub unrecognized_day_keys: BTreeSet<String>,
    pub unrecognized_client_keys: BTreeSet<String>,
    pub unrecognized_model_keys: BTreeSet<String>,
}

/// Normalize a provider payload into contract rows.
///
/// Only counters, a closed surface value, a bounded model slug and a UTC day
/// survive. Everything else in the payload - ids, labels, names, links, free
/// text of any kind - is dropped here and never reaches a struct that can be
/// serialized toward the backend.
pub fn normalize_provider_window(
    payload: &Value,
    coverage_start: &str,
    coverage_end: &str,
) -> Result<NormalizedWindow, ProviderReadError> {
    let days = first_array(
        payload,
        &[
            "results", "data", "days", "daily", "buckets", "items", "usage",
        ],
    )
    .ok_or_else(|| ProviderReadError::ResponseShape("no day rows in payload".to_string()))?;

    let refreshed_at = first_string(
        payload,
        &[
            "data_refreshed_at",
            "refreshed_at",
            "last_refreshed_at",
            "updated_at",
        ],
    )
    .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
    .map(timestamp);

    let mut grouped: BTreeMap<(String, &'static str, String), Counters> = BTreeMap::new();
    let mut dropped_model_rows = 0_usize;
    let mut days_recognized = 0_usize;
    let days_seen = days.len();
    let mut days_out_of_window = 0_usize;
    let mut days_no_client_breakdown = 0_usize;
    let mut days_used_fallback = 0_usize;
    let mut days_missing_date = 0_usize;
    let mut clients_seen = 0_usize;
    let mut clients_missing_id = 0_usize;
    let mut clients_no_model_breakdown = 0_usize;
    let mut models_seen = 0_usize;
    let mut models_missing_id = 0_usize;
    let mut entries_empty_counters = 0_usize;
    let mut day_totals_seen = 0_usize;
    let mut day_totals_compared = 0_usize;
    let mut day_total_mismatch_days = 0_usize;
    let mut day_total_mismatches = Vec::new();
    let mut user_count_fields_seen = 0_usize;
    let mut user_count_fields_unreadable = 0_usize;
    let mut unrecognized_day_keys = BTreeSet::new();
    let mut unrecognized_client_keys = BTreeSet::new();
    let mut unrecognized_model_keys = BTreeSet::new();

    for day in days {
        record_unrecognized_keys(
            day,
            &[
                DAY_DATE_KEYS,
                CLIENT_ARRAY_KEYS,
                DAY_TOTAL_KEYS,
                MODEL_ARRAY_KEYS,
                COUNTER_KEYS,
            ],
            &mut unrecognized_day_keys,
        );
        let Some(day_key) = first_string(day, DAY_DATE_KEYS).and_then(provider_day) else {
            days_missing_date += 1;
            continue;
        };
        days_recognized += 1;
        // A provider day outside the window we asked for is not evidence for
        // this batch; the contract rejects it and so do we.
        if day_key.as_str() < coverage_start || day_key.as_str() > coverage_end {
            days_out_of_window += 1;
            continue;
        }
        let mut day_emitted_client_row = false;
        let mut day_emitted_any_row = false;
        let mut recognized_client_totals = Counters::default();
        let day_models = first_array(day, MODEL_ARRAY_KEYS);
        if let Some(clients) = first_array(day, CLIENT_ARRAY_KEYS) {
            for client in clients {
                clients_seen += 1;
                record_unrecognized_keys(
                    client,
                    &[
                        CLIENT_ID_KEYS,
                        MODEL_ARRAY_KEYS,
                        USER_COUNT_KEYS,
                        COUNTER_KEYS,
                    ],
                    &mut unrecognized_client_keys,
                );
                if client.get("users").is_some() {
                    if counter_at(client, USER_COUNT_KEYS, MAX_EVENT_COUNTER).is_some() {
                        user_count_fields_seen += 1;
                    } else {
                        user_count_fields_unreadable += 1;
                    }
                }
                let Some(client_id) = first_string(client, CLIENT_ID_KEYS) else {
                    clients_missing_id += 1;
                    continue;
                };
                let surface = surface_for_client_id(client_id);
                let surface_counters = counters_at(client, true);
                if surface_counters.is_empty() {
                    entries_empty_counters += 1;
                } else {
                    recognized_client_totals.merge(&surface_counters);
                    grouped
                        .entry((day_key.clone(), surface.wire(), ALL_MODELS.to_string()))
                        .or_default()
                        .merge(&surface_counters);
                    day_emitted_client_row = true;
                    day_emitted_any_row = true;
                }
                if let Some(models) = first_array(client, MODEL_ARRAY_KEYS) {
                    for model in models {
                        models_seen += 1;
                        record_unrecognized_keys(
                            model,
                            &[MODEL_NAME_KEYS, USER_COUNT_KEYS, COUNTER_KEYS],
                            &mut unrecognized_model_keys,
                        );
                        if model.get("users").is_some() {
                            if counter_at(model, USER_COUNT_KEYS, MAX_EVENT_COUNTER).is_some() {
                                user_count_fields_seen += 1;
                            } else {
                                user_count_fields_unreadable += 1;
                            }
                        }
                        let Some(raw_model) = first_string(model, MODEL_NAME_KEYS) else {
                            models_missing_id += 1;
                            continue;
                        };
                        let Some(slug) = normalized_model_slug(raw_model) else {
                            dropped_model_rows += 1;
                            continue;
                        };
                        // The provider reports 0.0 for per-model credits, which is not
                        // a real attribution. Per-model rows carry tokens, threads and
                        // turns only; the surface row carries the metered credits.
                        let model_counters = counters_at(model, false);
                        if model_counters.is_empty() {
                            entries_empty_counters += 1;
                            continue;
                        }
                        grouped
                            .entry((day_key.clone(), surface.wire(), slug))
                            .or_default()
                            .merge(&model_counters);
                        day_emitted_any_row = true;
                    }
                } else if day_models.is_none() {
                    clients_no_model_breakdown += 1;
                }
            }
        } else {
            days_no_client_breakdown += 1;
        }

        if let Some(totals) = first_object(day, DAY_TOTAL_KEYS) {
            let totals_value = Value::Object(totals.clone());
            if totals.get("users").is_some() {
                if counter_at(&totals_value, USER_COUNT_KEYS, MAX_EVENT_COUNTER).is_some() {
                    user_count_fields_seen += 1;
                } else {
                    user_count_fields_unreadable += 1;
                }
            }
            let total_counters = counters_at(&totals_value, true);
            if !total_counters.is_empty() {
                day_totals_seen += 1;
                let (compared, mismatched) = compare_day_total(
                    &day_key,
                    &total_counters,
                    &recognized_client_totals,
                    &mut day_total_mismatches,
                );
                day_totals_compared += usize::from(compared);
                day_total_mismatch_days += usize::from(mismatched);
                grouped
                    .entry((
                        day_key.clone(),
                        PROVIDER_DAY_TOTAL_SURFACE,
                        ALL_MODELS.to_string(),
                    ))
                    .or_default()
                    .merge(&total_counters);
                day_emitted_any_row = true;
            }
        }

        if let Some(models) = day_models {
            for model in models {
                models_seen += 1;
                record_unrecognized_keys(
                    model,
                    &[MODEL_NAME_KEYS, USER_COUNT_KEYS, COUNTER_KEYS],
                    &mut unrecognized_model_keys,
                );
                if model.get("users").is_some() {
                    if counter_at(model, USER_COUNT_KEYS, MAX_EVENT_COUNTER).is_some() {
                        user_count_fields_seen += 1;
                    } else {
                        user_count_fields_unreadable += 1;
                    }
                }
                let Some(raw_model) = first_string(model, MODEL_NAME_KEYS) else {
                    models_missing_id += 1;
                    continue;
                };
                let Some(slug) = normalized_model_slug(raw_model) else {
                    dropped_model_rows += 1;
                    continue;
                };
                let model_counters = counters_at(model, false);
                if model_counters.is_empty() {
                    entries_empty_counters += 1;
                    continue;
                }
                grouped
                    .entry((day_key.clone(), PROVIDER_DAY_TOTAL_SURFACE, slug))
                    .or_default()
                    .merge(&model_counters);
                day_emitted_any_row = true;
            }
        }

        if !day_emitted_client_row {
            let day_counters = counters_at(day, true);
            if day_counters.is_empty() {
                if !day_emitted_any_row {
                    entries_empty_counters += 1;
                }
            } else {
                grouped
                    .entry((day_key, Surface::Other.wire(), ALL_MODELS.to_string()))
                    .or_default()
                    .merge(&day_counters);
                days_used_fallback += 1;
            }
        }
    }

    if days_recognized == 0 {
        return Err(ProviderReadError::ResponseShape(
            "no recognizable provider day in payload".to_string(),
        ));
    }

    let rows = grouped
        .into_iter()
        .map(|((day, surface, model), counters)| DailyReferenceRow {
            provider_day: day,
            surface,
            model,
            credits_used: counters.credits_used.map(format_credits),
            uncached_input_tokens: counters.uncached_input_tokens,
            cached_input_tokens: counters.cached_input_tokens,
            output_tokens: counters.output_tokens,
            total_tokens: counters.total_tokens,
            thread_count: counters.thread_count,
            turn_count: counters.turn_count,
        })
        .collect();

    Ok(NormalizedWindow {
        rows,
        provider_data_refreshed_at: refreshed_at,
        dropped_model_rows,
        days_seen,
        days_recognized,
        days_out_of_window,
        days_no_client_breakdown,
        days_used_fallback,
        days_missing_date,
        clients_seen,
        clients_missing_id,
        clients_no_model_breakdown,
        models_seen,
        models_missing_id,
        entries_empty_counters,
        day_totals_seen,
        day_totals_compared,
        day_total_mismatch_days,
        day_total_mismatches,
        user_count_fields_seen,
        user_count_fields_unreadable,
        unrecognized_day_keys,
        unrecognized_client_keys,
        unrecognized_model_keys,
    })
}

/// Render credits at the contract's six decimal places, as a string, so no
/// float formatting surprise reaches the wire.
fn format_credits(value: f64) -> String {
    format!("{value:.6}")
}
