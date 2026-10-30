//! Literal emitter. Callers stage a complete body before changing the item.
use super::super::claude_history_upgrade::REQUEST_OWNED_USAGE_CONTRACT;
use super::super::{
    exact_session_account_hash, ClaudeRemovedUsage, SnapshotCost, SnapshotItem, SnapshotModelUsage,
    SnapshotSource, SnapshotUsageBucket,
};
use super::body::ClaudeRequestUsageOrigin;
use super::e2::ClaudeEntityBody;
use super::ClaudeMoneyTokens;
use std::collections::BTreeMap;

// Contract-5 reproduction compares the literal row against the canonical
// trimmed spelling; published shadow facts keep their own fixed format.
fn dollars(micros: u64) -> String {
    super::super::usd_picos_string(u128::from(micros) * 1_000_000)
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

pub(super) fn grain_row(
    key: &super::body::ClaudeLiveKey,
    origin: Option<ClaudeRequestUsageOrigin>,
    grain: &super::body::ClaudeGrainSide,
    account: Option<String>,
) -> SnapshotModelUsage {
    let mut selector_context = key.2.clone();
    let copy_unproven = selector_context
        .remove(super::e2::COPY_UNPROVEN_KEY)
        .is_some();
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
    SnapshotModelUsage {
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
        account_identifier_hash: account,
        evidence_ref: None,
        identity_parts: None,
        copy_unproven,
        identity_retained: false,
        cost_usd: grain.cost().map(dollars),
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
    }
}

pub(super) fn apply(item: &mut SnapshotItem, entity: &ClaudeEntityBody) -> bool {
    if entity.held || !entity.certificate_ok {
        return false;
    }
    // Identity belongs to its existing owners, which tag the final rows after
    // emission (T4 order). Rows tagged BEFORE emission cannot be regrouped
    // without orphaning their evidence refs: refuse rather than wipe them.
    if !item.request_evidence.is_empty()
        || item
            .model_usage
            .iter()
            .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
            .any(|row| row.evidence_ref.is_some() || row.identity_parts.is_some())
    {
        return false;
    }
    // The uniform session account the account owner already set on every
    // row carries to the final rows; D1 re-derives it on them afterwards.
    let account = exact_session_account_hash(item);
    const MAX: u64 = (1_u64 << 53) - 1;
    let mut tokens = ClaudeMoneyTokens::default();
    let mut requests = 0_u64;
    let mut cost = None::<u64>;
    // Keep the native key order for single-account bytes. A partition may
    // split an internal grain, but never creates a duplicate wire selector.
    let mut buckets = BTreeMap::<String, Vec<SnapshotModelUsage>>::new();
    let mut positions = BTreeMap::<(String, super::super::RowKey), (usize, Option<u64>)>::new();
    let mut row_costs = BTreeMap::new();
    let mut hashes = super::super::SelectorHashes::default();
    for ((key, origin, _partition), grain) in &entity.grains {
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
        let row = grain_row(key, *origin, grain, account.clone());
        let row_key = hashes.row_key(&row);
        let cost = grain.cost();
        let identity = (key.0.clone(), row_key.clone());
        match row_costs.entry(row_key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(cost);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let next = match (*entry.get(), cost) {
                    (Some(a), Some(b)) => match a.checked_add(b) {
                        Some(sum) => Some(sum),
                        None => return false,
                    },
                    _ => None,
                };
                entry.insert(next);
            }
        }
        let rows = buckets.entry(key.0.clone()).or_default();
        if let Some(&(position, prior)) = positions.get(&identity) {
            let existing = &mut rows[position];
            let mut usage = super::super::usage_totals_from_model_usage(existing);
            if !usage.add(&super::super::usage_totals_from_model_usage(&row)) {
                return false;
            }
            let mut combined = super::super::BucketRowAccumulator {
                selector_context: existing.selector_context.clone(),
                selector_sources: existing.selector_sources.clone(),
                reasoning_effort: existing.reasoning_effort.clone(),
                usage,
            };
            let cost = match (prior, grain.cost()) {
                (Some(a), Some(b)) => match a.checked_add(b) {
                    Some(n) => Some(n),
                    None => return false,
                },
                _ => None,
            };
            positions.insert(identity.clone(), (position, cost));
            combined.usage.costs.total = cost.map(|micros| u128::from(micros) * 1_000_000);
            *existing = super::super::model_usage_from_row(&identity.1, &combined);
            existing.account_identifier_hash = account.clone();
        } else {
            positions.insert(identity, (rows.len(), grain.cost()));
            rows.push(row);
        }
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
        entity.resolver_conflicts,
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
    let activity = &entity.bucket_activity;
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
    super::super::rebuild_snapshot_model_usage_with(item, &mut hashes);
    let mut rows = 0;
    let mut requests = 0;
    for row in item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .filter(|row| row.copy_unproven)
    {
        rows += 1;
        requests += row.request_count;
    }
    item.copy_unproven_counts =
        (rows > 0).then_some(super::super::CopyUnprovenCounts { rows, requests });
    // The ordinary token-only rebuild deliberately drops monetary fields.
    // Literal top rows must retain the exact per-row sum of own costs so
    // contract 5 can reproduce both bucket and top-level rows.
    for row in &mut item.model_usage {
        row.cost_usd = row_costs
            .get(&hashes.row_key(row))
            .copied()
            .flatten()
            .map(dollars);
    }
    item.cost = cost.map(|micros| SnapshotCost {
        total_cost_usd: Some(dollars(micros)),
        input_cost_usd: None,
        output_cost_usd: None,
        cache_read_cost_usd: None,
        cache_creation_cost_usd: None,
        evidence_source: "claude_code_api_request".into(),
    });
    item.usage_accounting_contract = Some(REQUEST_OWNED_USAGE_CONTRACT.into());
    item.removed_request_count = Some(entity.removed_requests);
    item.removed_usage = Some(r);
    item.telemetry_owned_complete = Some(entity.telemetry_owned_complete);
    item.resolver_conflict_count =
        (entity.resolver_conflicts > 0).then_some(entity.resolver_conflicts);
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
        item.attribution_facts = crate::session_attribution::claude_desktop_spawn_facts(
            "94bd328b-f2a9-4c31-bbfe-e174d41b4310",
            "da1dc804-1c50-4401-8c3c-0898b126772f",
            "2026-10-18T10:20:00Z",
        );
        assert!(
            !item.attribution_facts.is_empty(),
            "spawn conservation must be nonvacuous"
        );
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
                    None,
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
                    last_own_at: None,
                },
            );
        }
        entity.telemetry_owned_complete = false;
        assert!(apply(&mut item, &entity));
        assert_eq!(
            item.usage_accounting_contract.as_deref(),
            Some(REQUEST_OWNED_USAGE_CONTRACT)
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

    fn one_grain(conflicts: u64) -> ClaudeEntityBody {
        let mut entity = ClaudeEntityBody::default();
        entity.grains.insert(
            (
                ("2026-08-02T09:00:00Z".into(), "m".into(), BTreeMap::new()),
                None,
                None,
            ),
            ClaudeGrainSide {
                tokens: ClaudeMoneyTokens {
                    input: 3,
                    ..Default::default()
                },
                requests: 1,
                cost_micros: 0,
                unpriced: 1,
                contributions: 1,
                last_own_at: None,
            },
        );
        entity.resolver_conflicts = conflicts;
        entity
    }

    #[test]
    fn emission_keeps_uniform_account_and_refuses_tagged_identity() {
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        assert!(apply(&mut item, &one_grain(0)));
        super::super::super::set_session_account_hash(&mut item, Some("h"));
        assert!(apply(&mut item, &one_grain(0)));
        assert!(!item.model_usage.is_empty());
        assert_eq!(exact_session_account_hash(&item).as_deref(), Some("h"));
        // Rows already tagged with evidence cannot be regrouped: refuse,
        // never wipe the tags.
        item.model_usage[0].evidence_ref = Some(0);
        let before = serde_json::to_vec(&item).unwrap();
        assert!(!apply(&mut item, &one_grain(0)));
        assert_eq!(serde_json::to_vec(&item).unwrap(), before);
    }

    #[test]
    fn resolver_conflicts_emit_nonzero_only_and_change_the_fingerprint() {
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        assert!(apply(&mut item, &one_grain(0)));
        assert_eq!(item.resolver_conflict_count, None);
        assert!(serde_json::to_value(&item)
            .unwrap()
            .get("resolver_conflict_count")
            .is_none());
        let clean = item.snapshot_fingerprint.clone();
        assert!(apply(&mut item, &one_grain(2)));
        assert_eq!(item.resolver_conflict_count, Some(2));
        assert_eq!(
            serde_json::to_value(&item).unwrap()["resolver_conflict_count"],
            serde_json::json!(2)
        );
        assert_ne!(item.snapshot_fingerprint, clean);
    }

    #[test]
    fn uncertified_entity_cannot_mutate_existing_body() {
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        let before = serde_json::to_vec(&item).unwrap();
        let entity = ClaudeEntityBody {
            certificate_ok: false,
            ..Default::default()
        };
        assert!(!apply(&mut item, &entity));
        assert_eq!(serde_json::to_vec(&item).unwrap(), before);
    }
}
