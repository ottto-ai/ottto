//! Aggregation of local session snapshots into per-destination "detected uses".
//!
//! The Companion's "Detected Uses" panel lists every billing destination a
//! source has actually routed to, keyed by
//! `(gateway_provider, plan_fingerprint, account_identifier_hash)` — the same
//! triple the Swift `DetectedUse.id` joins on. This module turns the v6
//! snapshot batch (`usage_buckets` → per-hour `model_usage` rows with hoisted
//! attribution) into that grouped view.
//!
//! Quota fields are intentionally left `Unknown`/`None` here: live quota is the
//! authoritative `agent_status` channel and is overlaid onto the matching
//! destination in the daemon's health assembly (see `lib.rs`), never smeared
//! across historical destinations.
//!
//! The daemon's snapshot scan is incremental — a steady-state cycle only
//! re-parses files that changed — so [`aggregate_detected_uses`] over one
//! cycle's snapshots is a *delta*. [`merge_detected_uses`] folds that delta
//! into the persisted cache so historical destinations are not clobbered.

use std::collections::BTreeMap;

use ottto_protocol::{DetectedUse, DetectedUseQuotaWindowState, DetectedUseTokenSample};

use crate::snapshots::{SnapshotItem, SnapshotModelUsage};

/// Maximum number of token-volume sparkline points retained per destination,
/// most recent first dropped from the front. Bounds the cache file size.
const MAX_TOKEN_SAMPLES: usize = 24;

/// Grouping key matching the Companion's `DetectedUse.id`:
/// `(gateway_provider, plan_fingerprint, account_identifier_hash)`. The daemon
/// never populates `account_identifier_hash` (an identity_probe/backend
/// concern), so the third element is always the empty string here.
type GroupKey = (String, String, String);

/// Aggregate one scan cycle's snapshots into detected uses, one entry per
/// `(gateway_provider, plan_fingerprint, account_identifier_hash)` group.
pub fn aggregate_detected_uses(snapshots: &[SnapshotItem]) -> Vec<DetectedUse> {
    let mut groups: BTreeMap<GroupKey, GroupBuilder> = BTreeMap::new();
    for snapshot in snapshots {
        for bucket in &snapshot.usage_buckets {
            for row in &bucket.model_usage {
                let gateway_provider = row_gateway_provider(row);
                let plan_fingerprint = row_plan_fingerprint(row);
                let subscription_product = row_subscription_product(row);
                let key = (
                    gateway_provider.clone(),
                    plan_fingerprint.clone().unwrap_or_default(),
                    String::new(),
                );
                let builder = groups.entry(key).or_default();
                builder.gateway_provider = gateway_provider;
                if builder.plan_fingerprint.is_none() {
                    builder.plan_fingerprint = plan_fingerprint;
                }
                if builder.subscription_product.is_none() {
                    builder.subscription_product = subscription_product;
                }
                *builder
                    .bucket_tokens
                    .entry(bucket.bucket_start.clone())
                    .or_insert(0) += row_total_tokens(row);
                // last_seen prefers the bucket's last activity, then the
                // snapshot's, then the bucket start so the field is always set.
                let candidate = bucket
                    .last_activity_at
                    .clone()
                    .or_else(|| snapshot.source_last_activity_at.clone())
                    .unwrap_or_else(|| bucket.bucket_start.clone());
                if builder
                    .last_seen_at
                    .as_ref()
                    .map(|current| &candidate > current)
                    .unwrap_or(true)
                {
                    builder.last_seen_at = Some(candidate);
                }
            }
        }
    }

    groups
        .into_values()
        .map(GroupBuilder::into_detected_use)
        .collect()
}

/// Fold a freshly aggregated delta into the persisted detected uses. Groups are
/// unioned by key; for an overlapping group the `fresh` scalar fields win
/// (it is the more recent observation) and token samples are merged by bucket
/// start — a re-scanned bucket overrides the stored value (the daemon recomputes
/// the whole session on any change), while buckets only present in `existing`
/// (older, no longer re-scanned) are retained.
pub fn merge_detected_uses(
    existing: Vec<DetectedUse>,
    fresh: Vec<DetectedUse>,
) -> Vec<DetectedUse> {
    let mut by_key: BTreeMap<GroupKey, DetectedUse> = BTreeMap::new();
    for entry in existing.into_iter().chain(fresh.into_iter()) {
        let key = detected_use_key(&entry);
        match by_key.remove(&key) {
            Some(previous) => {
                by_key.insert(key, merge_pair(previous, entry));
            }
            None => {
                by_key.insert(key, entry);
            }
        }
    }
    by_key.into_values().collect()
}

#[derive(Default)]
struct GroupBuilder {
    gateway_provider: String,
    plan_fingerprint: Option<String>,
    subscription_product: Option<String>,
    bucket_tokens: BTreeMap<String, u64>,
    last_seen_at: Option<String>,
}

impl GroupBuilder {
    fn into_detected_use(self) -> DetectedUse {
        let account_label = self.subscription_product.as_deref().map(humanize_plan);
        DetectedUse {
            gateway_provider: self.gateway_provider,
            plan_fingerprint: self.plan_fingerprint,
            account_identifier_hash: None,
            subscription_product: self.subscription_product,
            account_label,
            last_seen_at: self.last_seen_at.unwrap_or_default(),
            token_volume_recent: recent_samples(self.bucket_tokens),
            quota_window_state: DetectedUseQuotaWindowState::Unknown,
            quota_used_percent: None,
            quota_resets_at: None,
        }
    }
}

fn detected_use_key(entry: &DetectedUse) -> GroupKey {
    (
        entry.gateway_provider.clone(),
        entry.plan_fingerprint.clone().unwrap_or_default(),
        entry.account_identifier_hash.clone().unwrap_or_default(),
    )
}

fn merge_pair(previous: DetectedUse, incoming: DetectedUse) -> DetectedUse {
    let mut samples: BTreeMap<String, u64> = previous
        .token_volume_recent
        .into_iter()
        .map(|sample| (sample.at, sample.tokens))
        .collect();
    for sample in incoming.token_volume_recent {
        samples.insert(sample.at, sample.tokens);
    }
    let last_seen_at = if incoming.last_seen_at >= previous.last_seen_at {
        incoming.last_seen_at
    } else {
        previous.last_seen_at
    };
    DetectedUse {
        gateway_provider: incoming.gateway_provider,
        plan_fingerprint: incoming.plan_fingerprint.or(previous.plan_fingerprint),
        account_identifier_hash: incoming
            .account_identifier_hash
            .or(previous.account_identifier_hash),
        subscription_product: incoming
            .subscription_product
            .or(previous.subscription_product),
        account_label: incoming.account_label.or(previous.account_label),
        last_seen_at,
        token_volume_recent: recent_samples(samples),
        // Quota is overlaid live in the health assembly, not persisted, so the
        // aggregated (Unknown/None) values carry through unchanged.
        quota_window_state: incoming.quota_window_state,
        quota_used_percent: incoming.quota_used_percent,
        quota_resets_at: incoming.quota_resets_at,
    }
}

/// Keep the most recent [`MAX_TOKEN_SAMPLES`] buckets, in chronological order.
/// `BTreeMap` iterates ascending by bucket-start string (RFC3339, so lexical
/// order is chronological).
fn recent_samples(bucket_tokens: BTreeMap<String, u64>) -> Vec<DetectedUseTokenSample> {
    let skip = bucket_tokens.len().saturating_sub(MAX_TOKEN_SAMPLES);
    bucket_tokens
        .into_iter()
        .skip(skip)
        .map(|(at, tokens)| DetectedUseTokenSample { at, tokens })
        .collect()
}

/// Gateway for a row: its own `gateway_provider`, else `model_provider`
/// (Codex rows omit gateway but always carry `model_provider="openai"`), else
/// the Anthropic default.
fn row_gateway_provider(row: &SnapshotModelUsage) -> String {
    row.gateway_provider
        .clone()
        .filter(|value| !value.is_empty())
        .or_else(|| row.model_provider.clone().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "anthropic".to_string())
}

/// `subscription_product` for a row: top-level field first, then the
/// `subscription_product` selector — mirrors the backend's
/// `_subscription_product_from_item`.
fn row_subscription_product(row: &SnapshotModelUsage) -> Option<String> {
    row.subscription_product
        .clone()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            row.selector_context
                .get("subscription_product")
                .filter(|value| !value.is_empty())
                .cloned()
        })
}

/// `plan_fingerprint` for a row, matching the backend formula in
/// `session_snapshots/service.py`: `"{subscription_product}::{plan_window_bucket}"`
/// only when both halves are present and non-empty, else `None`.
fn row_plan_fingerprint(row: &SnapshotModelUsage) -> Option<String> {
    let subscription_product = row_subscription_product(row);
    let plan_window_bucket = row
        .selector_context
        .get("plan_window_bucket")
        .filter(|value| !value.is_empty());
    match (subscription_product, plan_window_bucket) {
        (Some(product), Some(bucket)) => Some(format!("{product}::{bucket}")),
        _ => None,
    }
}

fn row_total_tokens(row: &SnapshotModelUsage) -> u64 {
    row.input_tokens
        .saturating_add(row.output_tokens)
        .saturating_add(row.cache_read_tokens)
        .saturating_add(row.cache_creation_5m_tokens)
        .saturating_add(row.cache_creation_1h_tokens)
        .saturating_add(row.reasoning_output_tokens)
        .saturating_add(row.unattributed_total_tokens)
}

/// Human-readable label for a plan slug. Known plans get a curated label; any
/// other value is title-cased so the panel never shows a bare lowercase slug.
fn humanize_plan(product: &str) -> String {
    match product.trim().to_ascii_lowercase().as_str() {
        "pro" => "Pro".to_string(),
        "team" => "Team".to_string(),
        "plus" => "Plus".to_string(),
        "enterprise" => "Enterprise".to_string(),
        "business" => "Business".to_string(),
        "max" => "Max".to_string(),
        "free" => "Free".to_string(),
        _ => title_case(product),
    }
}

fn title_case(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::{SnapshotProvenance, SnapshotUsageBucket};

    fn model_usage(
        gateway_provider: Option<&str>,
        model_provider: Option<&str>,
        subscription_product: Option<&str>,
        plan_window_bucket: Option<&str>,
        input_tokens: u64,
        output_tokens: u64,
    ) -> SnapshotModelUsage {
        let mut selector_context = BTreeMap::new();
        if let Some(bucket) = plan_window_bucket {
            selector_context.insert("plan_window_bucket".to_string(), bucket.to_string());
        }
        SnapshotModelUsage {
            model: "test-model".to_string(),
            input_tokens,
            output_tokens,
            cache_read_tokens: 0,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            unattributed_total_tokens: 0,
            request_count: 1,
            selector_context,
            selector_sources: BTreeMap::new(),
            auth_mode: None,
            billing_channel: None,
            billing_provider: None,
            gateway_provider: gateway_provider.map(str::to_string),
            model_provider: model_provider.map(str::to_string),
            subscription_product: subscription_product.map(str::to_string),
        }
    }

    fn usage_bucket(
        bucket_start: &str,
        last_activity_at: &str,
        rows: Vec<SnapshotModelUsage>,
    ) -> SnapshotUsageBucket {
        SnapshotUsageBucket {
            bucket_start: bucket_start.to_string(),
            model_usage: rows,
            first_activity_at: Some(bucket_start.to_string()),
            last_activity_at: Some(last_activity_at.to_string()),
        }
    }

    fn snapshot(
        source_session_id: &str,
        source_last_activity_at: &str,
        usage_buckets: Vec<SnapshotUsageBucket>,
    ) -> SnapshotItem {
        SnapshotItem {
            source_session_id: source_session_id.to_string(),
            snapshot_fingerprint: format!("fp-{source_session_id}"),
            status: "active".to_string(),
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            unattributed_total_tokens: 0,
            request_count: 0,
            model_usage: Vec::new(),
            usage_buckets,
            session_display_name: None,
            session_display_name_source: None,
            source_started_at: None,
            source_ended_at: None,
            source_last_activity_at: Some(source_last_activity_at.to_string()),
            collected_at: "2026-05-28T12:00:00Z".to_string(),
            workspace_hash: None,
            workspace_display_label: None,
            workspace_label_source: None,
            source_file_fingerprint: None,
            provenance: SnapshotProvenance {
                collector: "test".to_string(),
                source_file_count: 1,
                input_token_scope: None,
                state_total_tokens: None,
                state_archived: None,
            },
        }
    }

    #[test]
    fn aggregates_vertex_and_subscription_claude_into_two_groups() {
        // A single Claude Code session that mixed providers (the `cvon`/`cvoff`
        // case): some turns billed to Vertex, some to the 1P subscription. Each
        // turn's gateway comes from the message-id prefix; neither carries a
        // plan_window_bucket, so plan_fingerprint is None for both and the two
        // destinations differ only by gateway_provider.
        let snapshots = vec![snapshot(
            "claude-session",
            "2026-05-28T09:30:00Z",
            vec![
                usage_bucket(
                    "2026-05-28T08:00:00Z",
                    "2026-05-28T08:45:00Z",
                    vec![model_usage(
                        Some("vertex"),
                        Some("anthropic"),
                        None,
                        None,
                        1000,
                        200,
                    )],
                ),
                usage_bucket(
                    "2026-05-28T09:00:00Z",
                    "2026-05-28T09:30:00Z",
                    vec![model_usage(
                        Some("anthropic"),
                        Some("anthropic"),
                        None,
                        None,
                        500,
                        100,
                    )],
                ),
            ],
        )];

        let detected = aggregate_detected_uses(&snapshots);
        assert_eq!(detected.len(), 2);

        let vertex = detected
            .iter()
            .find(|use_entry| use_entry.gateway_provider == "vertex")
            .expect("vertex group present");
        assert_eq!(vertex.plan_fingerprint, None);
        assert_eq!(vertex.account_identifier_hash, None);
        assert_eq!(vertex.subscription_product, None);
        assert_eq!(vertex.account_label, None);
        assert_eq!(vertex.last_seen_at, "2026-05-28T08:45:00Z");
        assert_eq!(vertex.token_volume_recent.len(), 1);
        assert_eq!(vertex.token_volume_recent[0].at, "2026-05-28T08:00:00Z");
        assert_eq!(vertex.token_volume_recent[0].tokens, 1200);
        assert_eq!(
            vertex.quota_window_state,
            DetectedUseQuotaWindowState::Unknown
        );
        assert_eq!(vertex.quota_used_percent, None);

        let anthropic = detected
            .iter()
            .find(|use_entry| use_entry.gateway_provider == "anthropic")
            .expect("anthropic group present");
        assert_eq!(anthropic.token_volume_recent[0].tokens, 600);
        assert_eq!(anthropic.last_seen_at, "2026-05-28T09:30:00Z");
    }

    #[test]
    fn codex_personal_pro_and_team_surface_as_separate_detected_uses() {
        // THE KEY CASE: Codex history with a Personal Pro context and a Singular
        // Team context under the same OpenAI identity. plan_type and the
        // secondary-reset day bucket differ, so the plan_fingerprints differ and
        // the two MUST surface as distinct detected uses (never collapsed onto a
        // single account_id). Gateway falls back to model_provider="openai" for
        // both since Codex rows carry no gateway_provider.
        let snapshots = vec![
            snapshot(
                "codex-pro",
                "2026-05-27T10:30:00Z",
                vec![usage_bucket(
                    "2026-05-27T10:00:00Z",
                    "2026-05-27T10:30:00Z",
                    vec![model_usage(
                        None,
                        Some("openai"),
                        Some("pro"),
                        Some("20598"),
                        3000,
                        400,
                    )],
                )],
            ),
            snapshot(
                "codex-team",
                "2026-05-27T14:34:00Z",
                vec![usage_bucket(
                    "2026-05-27T14:00:00Z",
                    "2026-05-27T14:34:00Z",
                    vec![model_usage(
                        None,
                        Some("openai"),
                        Some("team"),
                        Some("20607"),
                        8000,
                        900,
                    )],
                )],
            ),
        ];

        let detected = aggregate_detected_uses(&snapshots);
        assert_eq!(detected.len(), 2);

        let pro = detected
            .iter()
            .find(|use_entry| use_entry.subscription_product.as_deref() == Some("pro"))
            .expect("personal pro group present");
        assert_eq!(pro.gateway_provider, "openai");
        assert_eq!(pro.plan_fingerprint.as_deref(), Some("pro::20598"));
        assert_eq!(pro.account_label.as_deref(), Some("Pro"));
        assert_eq!(pro.account_identifier_hash, None);

        let team = detected
            .iter()
            .find(|use_entry| use_entry.subscription_product.as_deref() == Some("team"))
            .expect("team group present");
        assert_eq!(team.gateway_provider, "openai");
        assert_eq!(team.plan_fingerprint.as_deref(), Some("team::20607"));
        assert_eq!(team.account_label.as_deref(), Some("Team"));

        // Distinct fingerprints prove the dual-destination split holds.
        assert_ne!(pro.plan_fingerprint, team.plan_fingerprint);
    }

    #[test]
    fn subscription_product_falls_back_to_selector_context() {
        // The Codex contract also exposes subscription_product via the selector;
        // a row that only carries it there must still produce a fingerprint.
        let mut row = model_usage(None, Some("openai"), None, Some("20598"), 10, 1);
        row.selector_context
            .insert("subscription_product".to_string(), "pro".to_string());
        let detected = aggregate_detected_uses(&[snapshot(
            "codex",
            "2026-05-27T10:30:00Z",
            vec![usage_bucket(
                "2026-05-27T10:00:00Z",
                "2026-05-27T10:30:00Z",
                vec![row],
            )],
        )]);
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].plan_fingerprint.as_deref(), Some("pro::20598"));
        assert_eq!(detected[0].subscription_product.as_deref(), Some("pro"));
    }

    #[test]
    fn token_volume_recent_keeps_only_the_most_recent_samples() {
        let mut buckets = Vec::new();
        for day in 1..=30u32 {
            let start = format!("2026-05-{day:02}T00:00:00Z");
            let last = format!("2026-05-{day:02}T00:30:00Z");
            buckets.push(usage_bucket(
                &start,
                &last,
                vec![model_usage(
                    Some("vertex"),
                    Some("anthropic"),
                    None,
                    None,
                    day as u64,
                    0,
                )],
            ));
        }
        let detected = aggregate_detected_uses(&[snapshot("s", "2026-05-30T00:30:00Z", buckets)]);
        assert_eq!(detected.len(), 1);
        let samples = &detected[0].token_volume_recent;
        assert_eq!(samples.len(), MAX_TOKEN_SAMPLES);
        // 30 buckets, keep the most recent 24 → days 01..06 dropped.
        assert_eq!(samples.first().unwrap().at, "2026-05-07T00:00:00Z");
        assert_eq!(samples.last().unwrap().at, "2026-05-30T00:00:00Z");
    }

    #[test]
    fn merge_unions_groups_and_refreshes_recent_samples() {
        let existing = vec![DetectedUse {
            gateway_provider: "openai".to_string(),
            plan_fingerprint: Some("pro::20598".to_string()),
            account_identifier_hash: None,
            subscription_product: Some("pro".to_string()),
            account_label: Some("Pro".to_string()),
            last_seen_at: "2026-05-26T10:00:00Z".to_string(),
            token_volume_recent: vec![
                DetectedUseTokenSample {
                    at: "2026-05-26T08:00:00Z".to_string(),
                    tokens: 100,
                },
                DetectedUseTokenSample {
                    at: "2026-05-26T09:00:00Z".to_string(),
                    tokens: 200,
                },
            ],
            quota_window_state: DetectedUseQuotaWindowState::Unknown,
            quota_used_percent: None,
            quota_resets_at: None,
        }];
        // Fresh re-scan: the pro group's 09:00 bucket recomputed (overrides 200),
        // plus a brand-new team group that must be added, not dropped.
        let fresh = aggregate_detected_uses(&[
            snapshot(
                "codex-pro",
                "2026-05-26T11:00:00Z",
                vec![usage_bucket(
                    "2026-05-26T09:00:00Z",
                    "2026-05-26T11:00:00Z",
                    vec![model_usage(
                        None,
                        Some("openai"),
                        Some("pro"),
                        Some("20598"),
                        999,
                        0,
                    )],
                )],
            ),
            snapshot(
                "codex-team",
                "2026-05-27T14:34:00Z",
                vec![usage_bucket(
                    "2026-05-27T14:00:00Z",
                    "2026-05-27T14:34:00Z",
                    vec![model_usage(
                        None,
                        Some("openai"),
                        Some("team"),
                        Some("20607"),
                        8000,
                        900,
                    )],
                )],
            ),
        ]);

        let merged = merge_detected_uses(existing, fresh);
        assert_eq!(merged.len(), 2);

        let pro = merged
            .iter()
            .find(|use_entry| use_entry.subscription_product.as_deref() == Some("pro"))
            .expect("pro group retained");
        assert_eq!(pro.token_volume_recent.len(), 2);
        // 08:00 bucket retained from the cache; 09:00 overridden by the recompute.
        assert_eq!(pro.token_volume_recent[0].at, "2026-05-26T08:00:00Z");
        assert_eq!(pro.token_volume_recent[0].tokens, 100);
        assert_eq!(pro.token_volume_recent[1].at, "2026-05-26T09:00:00Z");
        assert_eq!(pro.token_volume_recent[1].tokens, 999);
        assert_eq!(pro.last_seen_at, "2026-05-26T11:00:00Z");

        assert!(merged
            .iter()
            .any(|use_entry| use_entry.subscription_product.as_deref() == Some("team")));
    }
}
