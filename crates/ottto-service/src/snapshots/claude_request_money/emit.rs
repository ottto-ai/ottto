//! Literal emitter. Callers stage a complete body before changing the item.
use super::super::{
    ClaudeRemovedUsage, SnapshotCost, SnapshotItem, SnapshotModelUsage, SnapshotSource,
    SnapshotUsageBucket,
};
use super::body::{ClaudeEntityBody, ClaudeRequestUsageOrigin};
use super::{ClaudeMoneyTokens, REQUEST_OWNED_CONTRACT};
use std::collections::BTreeMap;

fn dollars(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}
fn removed(tokens: ClaudeMoneyTokens) -> ClaudeRemovedUsage {
    ClaudeRemovedUsage {
        input_tokens: tokens.input,
        output_tokens: tokens.output,
        cache_read_tokens: tokens.cache_read,
        cache_creation_5m_tokens: tokens.cache_5m,
        cache_creation_1h_tokens: tokens.cache_1h,
        unattributed_total_tokens: tokens.unattributed,
        reasoning_output_tokens: tokens.reasoning,
    }
}

pub(super) fn apply(item: &mut SnapshotItem, entity: &ClaudeEntityBody) -> bool {
    if entity.held || !entity.certificate_ok {
        return false;
    }
    const MAX: u64 = (1_u64 << 53) - 1;
    let mut tokens = ClaudeMoneyTokens::default();
    let mut requests = 0_u64;
    let mut cost = None::<u64>;
    let mut buckets = BTreeMap::<String, Vec<SnapshotModelUsage>>::new();
    for ((key, origin), grain) in &entity.grains {
        let mut selector_context = key.2.clone();
        let mut selector_sources = BTreeMap::new();
        if let Some(origin) = origin {
            let name = match origin {
                ClaudeRequestUsageOrigin::TelemetryMatched => "telemetry_matched",
                ClaudeRequestUsageOrigin::TelemetryReported => "telemetry_reported",
                ClaudeRequestUsageOrigin::TelemetryUnpriced => "telemetry_unpriced",
            };
            selector_context.insert("request_usage_origin".into(), name.into());
            selector_sources.insert("request_usage_origin".into(), "claude_api_request".into());
        }
        tokens.add(&grain.tokens);
        requests = match requests.checked_add(grain.requests) {
            Some(n) => n,
            None => return false,
        };
        if let Some(own_cost) = grain.cost() {
            cost = Some(match cost.unwrap_or(0).checked_add(own_cost) {
                Some(n) => n,
                None => return false,
            });
        }
        let row = SnapshotModelUsage {
            model: key.1.clone(),
            input_tokens: grain.tokens.input,
            output_tokens: grain.tokens.output,
            cache_read_tokens: grain.tokens.cache_read,
            cache_creation_5m_tokens: grain.tokens.cache_5m,
            cache_creation_1h_tokens: grain.tokens.cache_1h,
            reasoning_output_tokens: grain.tokens.reasoning,
            unattributed_total_tokens: grain.tokens.unattributed,
            request_count: grain.requests,
            reasoning_effort: selector_context.remove("reasoning_effort"),
            auth_mode: selector_context.remove("auth_mode"),
            billing_channel: selector_context.remove("billing_channel"),
            billing_provider: selector_context.remove("billing_provider"),
            gateway_provider: selector_context.remove("gateway_provider"),
            model_provider: selector_context.remove("model_provider"),
            subscription_product: selector_context.remove("subscription_product"),
            selector_context,
            selector_sources,
            account_identifier_hash: None,
            evidence_ref: None,
            identity_parts: None,
            cost_usd: grain.cost().map(dollars),
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
        };
        buckets.entry(key.0.clone()).or_default().push(row);
    }
    let r = removed(entity.removed);
    if [
        tokens.input,
        tokens.output,
        tokens.cache_read,
        tokens.cache_5m,
        tokens.cache_1h,
        tokens.unattributed,
        tokens.reasoning,
        requests,
        r.input_tokens,
        r.output_tokens,
        r.cache_read_tokens,
        r.cache_creation_5m_tokens,
        r.cache_creation_1h_tokens,
        r.unattributed_total_tokens,
        r.reasoning_output_tokens,
        entity.removed_requests,
    ]
    .iter()
    .any(|n| *n > MAX)
    {
        return false;
    }
    item.input_tokens = tokens.input;
    item.output_tokens = tokens.output;
    item.cache_read_tokens = tokens.cache_read;
    item.cache_creation_5m_tokens = tokens.cache_5m;
    item.cache_creation_1h_tokens = tokens.cache_1h;
    item.unattributed_total_tokens = tokens.unattributed;
    item.reasoning_output_tokens = tokens.reasoning;
    item.request_count = requests;
    let mut activity = entity.bucket_activity.clone();
    for contribution in &entity.counted {
        if !entity.bucket_activity.contains_key(&contribution.key.0) {
            let nanos = i128::from(contribution.clock) * 1_000_000_000;
            let bounds = activity
                .entry(contribution.key.0.clone())
                .or_insert((nanos, nanos));
            bounds.0 = bounds.0.min(nanos);
            bounds.1 = bounds.1.max(nanos);
        }
    }
    let timestamp = |nanos: i128| {
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .ok()
            .and_then(|clock| {
                clock
                    .format(&time::format_description::well_known::Rfc3339)
                    .ok()
            })
    };
    item.usage_buckets = buckets
        .into_iter()
        .map(|(bucket_start, model_usage)| SnapshotUsageBucket {
            first_activity_at: activity
                .get(&bucket_start)
                .and_then(|(first, _)| timestamp(*first)),
            last_activity_at: activity
                .get(&bucket_start)
                .and_then(|(_, last)| timestamp(*last)),
            bucket_start,
            model_usage,
        })
        .collect();
    super::super::rebuild_snapshot_model_usage(item);
    item.cost = cost.map(|micros| SnapshotCost {
        total_cost_usd: Some(dollars(micros)),
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
        evidence_source: "claude_code_api_request".into(),
    });
    item.usage_accounting_contract = Some(REQUEST_OWNED_CONTRACT.into());
    item.removed_request_count = Some(entity.removed_requests);
    item.removed_usage = Some(r);
    item.telemetry_owned_complete = Some(entity.telemetry_owned_complete);
    let latest = entity
        .activity_nanos
        .max(i128::from(entity.activity_unix) * 1_000_000_000);
    if latest
        > item
            .source_last_activity_at
            .as_deref()
            .and_then(super::super::rfc3339_unix_nanos)
            .unwrap_or(0)
    {
        if let Some(clock) = timestamp(latest) {
            item.source_last_activity_at = Some(clock.clone());
            item.source_ended_at = Some(clock);
        }
    }
    item.snapshot_fingerprint =
        super::super::snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::claude_request_money::body::{ClaudeGrainSide, ClaudeRequestUsageOrigin};

    #[test]
    fn literal_emission_preserves_attribution_and_costs_only_own_priced_grains() {
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        let facts = serde_json::to_value(&item.attribution_facts).unwrap();
        let mut entity = ClaudeEntityBody::default();
        for (model, origin, cost, tokens) in [
            ("transcript", None, None, 10),
            (
                "matched",
                Some(ClaudeRequestUsageOrigin::TelemetryMatched),
                Some(125),
                20,
            ),
            (
                "reported",
                Some(ClaudeRequestUsageOrigin::TelemetryReported),
                Some(250),
                30,
            ),
            (
                "unpriced",
                Some(ClaudeRequestUsageOrigin::TelemetryUnpriced),
                None,
                40,
            ),
        ] {
            entity.grains.insert(
                (
                    ("2026-08-02T09:00:00Z".into(), model.into(), BTreeMap::new()),
                    origin,
                ),
                ClaudeGrainSide {
                    tokens: ClaudeMoneyTokens {
                        input: tokens,
                        ..Default::default()
                    },
                    requests: 1,
                    cost_micros: cost.unwrap_or(0),
                    unpriced: u64::from(cost.is_none()),
                    contributions: 1,
                },
            );
        }
        entity.telemetry_owned_complete = false;
        assert!(apply(&mut item, &entity));
        assert_eq!(
            item.usage_accounting_contract.as_deref(),
            Some(REQUEST_OWNED_CONTRACT)
        );
        assert_eq!(item.request_count, 4);
        assert_eq!(item.input_tokens, 100);
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.000375")
        );
        assert_eq!(item.removed_request_count, Some(0));
        assert_eq!(item.removed_usage, Some(ClaudeRemovedUsage::default()));
        assert_eq!(item.telemetry_owned_complete, Some(false));
        assert_eq!(
            serde_json::to_value(&item.attribution_facts).unwrap(),
            facts
        );
        for row in item.model_usage.iter().chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        ) {
            if row.model == "unpriced" {
                assert!(row.cost_usd.is_none());
                assert_eq!(
                    row.selector_context
                        .get("request_usage_origin")
                        .map(String::as_str),
                    Some("telemetry_unpriced")
                );
                assert_eq!(
                    row.selector_sources
                        .get("request_usage_origin")
                        .map(String::as_str),
                    Some("claude_api_request")
                );
            }
        }
    }

    #[test]
    fn uncertified_entity_cannot_mutate_existing_body() {
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        let before = serde_json::to_vec(&item).unwrap();
        let mut entity = ClaudeEntityBody::default();
        entity.certificate_ok = false;
        assert!(!apply(&mut item, &entity));
        assert_eq!(serde_json::to_vec(&item).unwrap(), before);
    }
}
