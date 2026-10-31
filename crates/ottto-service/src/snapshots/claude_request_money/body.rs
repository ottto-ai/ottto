//! Shared types and reported enrichment for live E2 money.

use super::super::{insert_selector_raw, SelectorCapture, CLAUDE_EFFORT_TIERS};
use super::ClaudeMoneyTokens;
use serde::Serialize;
use std::collections::BTreeMap;

/// `request_usage_origin` of a grain; None is a transcript grain.
/// The variant names are the reader's wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
#[expect(clippy::enum_variant_names, reason = "names are the wire values")]
pub(crate) enum ClaudeRequestUsageOrigin {
    /// A transcript unit with its API row's own `cost_usd`.
    TelemetryMatched,
    /// A telemetry-only request (side call) with its row's own cost.
    TelemetryReported,
    /// A side call whose row carries no cost.
    TelemetryUnpriced,
}

/// One live bucket row's identity: hour start, model and pricing selectors
/// (the reduced selector context plus the row's billing fields).
pub(crate) type ClaudeLiveKey = (String, String, BTreeMap<String, String>);

/// Reported enrichment for E2 native placement and emitted row effort.
pub(super) struct ReportedInputs<'a> {
    pub(super) selector: SelectorCapture,
    pub(super) effort: Option<&'a str>,
    pub(super) model: &'a str,
    pub(super) timestamp: Option<&'a str>,
}

pub(super) fn reported_inputs<'a>(
    model: &'a str,
    speed: &str,
    effort: &'a str,
    occurrence: Option<&'a super::super::ClaudeTranscriptUsageOccurrence>,
) -> ReportedInputs<'a> {
    let mut selector = occurrence
        .map(|o| SelectorCapture::clone(&o.selector))
        .unwrap_or_default();
    if !speed.trim().is_empty() {
        insert_selector_raw(
            &mut selector,
            "speed_mode",
            "claude_code.api_request.speed",
            &serde_json::Value::String(speed.to_owned()),
        );
    }
    let (model, effort) = reported_model_effort(model, effort, occurrence);
    ReportedInputs {
        selector,
        effort,
        model,
        timestamp: occurrence.and_then(|o| o.timestamp.as_deref()),
    }
}

/// `reported_inputs`' model and effort: the transcript's win; a reported
/// effort tier fills a missing transcript effort.
pub(super) fn reported_model_effort<'a>(
    model: &'a str,
    effort: &'a str,
    occurrence: Option<&'a super::super::ClaudeTranscriptUsageOccurrence>,
) -> (&'a str, Option<&'a str>) {
    (
        occurrence.and_then(|o| o.model.as_deref()).unwrap_or(model),
        occurrence
            .and_then(|o| o.reasoning_effort.as_deref())
            .or_else(|| CLAUDE_EFFORT_TIERS.contains(&effort).then_some(effort)),
    )
}

/// One side of a grain slice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeGrainSide {
    pub(crate) tokens: ClaudeMoneyTokens,
    pub(crate) requests: u64,
    pub(crate) cost_micros: u64,
    /// Contributions without a cost (the side's cost is then unknown).
    pub(crate) unpriced: u64,
    pub(crate) contributions: u64,
    /// Local display only; newest own transcript clock, never serialized.
    pub(crate) last_own_at: Option<i128>,
}

impl ClaudeGrainSide {
    pub(super) fn add(&mut self, tokens: &ClaudeMoneyTokens, requests: u64, cost: Option<u64>) {
        self.tokens.add(tokens);
        self.requests = self.requests.saturating_add(requests);
        self.contributions += 1;
        match cost {
            Some(cost) => self.cost_micros = self.cost_micros.saturating_add(cost),
            None => self.unpriced += 1,
        }
    }

    /// The side's own money, when every contribution carries one.
    pub(crate) fn cost(&self) -> Option<u64> {
        (self.contributions > 0 && self.unpriced == 0).then_some(self.cost_micros)
    }
}
