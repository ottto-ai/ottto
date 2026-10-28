use super::*;
use crate::local_resource_diagnostics::{cache_lifecycle, observe_selector_rejections};

#[test]
fn exact_known_vocabulary_and_each_validator() {
    let expected: BTreeSet<_> = SELECTOR_CONTEXT_ALLOWED
        .iter()
        .chain(ROW_BILLING_FIELDS)
        .copied()
        .chain([
            "plan_window_bucket",
            "agent_quota_primary_used_percent",
            "agent_quota_primary_window_minutes",
            "agent_quota_primary_resets_at",
            "agent_quota_secondary_used_percent",
            "agent_quota_secondary_window_minutes",
            "agent_quota_secondary_resets_at",
            "agent_quota_credits_has_credits",
            "agent_quota_credits_unlimited",
            "agent_quota_credits_balance",
        ])
        .collect();
    assert_eq!(expected.len(), 29);
    assert_eq!(SELECTOR_KEY_RULES.len(), expected.len());
    assert_eq!(
        SELECTOR_KEY_RULES
            .iter()
            .map(|(k, _)| *k)
            .collect::<BTreeSet<_>>(),
        expected
    );
    let (_, counts) = observe_selector_rejections(|| {
        for (key, rule) in SELECTOR_KEY_RULES {
            let raw = match *rule {
                "bool" => json!(true),
                "mode" => json!("priority"),
                "context" => json!("long"),
                "u64" => json!(20598),
                "number" => json!(35.5),
                "ttl" => json!(3600),
                "token" => json!("provider.v1:standard"),
                _ => panic!("unregistered validator"),
            };
            let mut capture = SelectorCapture::default();
            insert_selector_raw(&mut capture, key, "fixture", &raw);
            assert_eq!(
                capture.context.get(*key),
                normalize_selector_raw(key, &raw).as_ref(),
                "{key}"
            );
            assert_eq!(
                capture.sources.get(*key).map(String::as_str),
                Some("fixture")
            );
        }
    });
    assert_eq!(counts.selector_key_rejected_unknown, 0);
    assert_eq!(counts.selector_key_rejected_format, 0);
}

#[test]
fn malformed_values_are_dropped_and_counted_without_content() {
    let mut capture = SelectorCapture::default();
    let (_, counts) = observe_selector_rejections(|| {
        for (key, raw) in [
            ("plan_window_bucket", json!("/tmp/BUCKET_CANARY/private")),
            ("plan_window_bucket", json!("some free text")),
            ("plan_window_bucket", json!("18446744073709551616")),
            ("plan_window_bucket", json!(-1)),
            ("plan_window_bucket", json!(1.5)),
            ("plan_window_bucket", json!(true)),
            ("plan_window_bucket", json!("1e3")),
            ("plan_window_bucket", json!("+1")),
            ("service_tier", json!(["priority"])),
            ("service_tier", json!(42)),
            ("region_mode", json!("/tmp/REGION_CANARY")),
            ("region_mode", json!("a".repeat(129))),
            ("mode", json!("turbo")),
            ("batch_mode", json!({"x":true})),
            ("context_bucket", json!("arbitrary")),
            ("cache_ttl", json!("5mh")),
            ("cache_ttl", json!("forever")),
            ("agent_quota_primary_used_percent", json!("NaN")),
            ("agent_quota_credits_balance", json!("inf")),
            ("agent_quota_secondary_window_minutes", json!(3.5)),
            ("agent_quota_credits_unlimited", json!("enabled")),
        ] {
            insert_selector_raw(&mut capture, key, "private-source", &raw);
        }
        insert_selector_raw(
            &mut capture,
            "/tmp/KEY_CANARY",
            "private-source",
            &json!("VALUE_CANARY"),
        );
    });
    assert!(capture.context.is_empty() && capture.sources.is_empty());
    assert_eq!(counts.selector_key_rejected_format, 18);
    assert_eq!(counts.selector_key_rejected_unknown, 1);
    let (_, logs) = crate::local_resource_diagnostics::capture(|| {
        crate::local_resource_diagnostics::Probe::start().collection(
            "codex",
            crate::local_resource_diagnostics::CollectionCounts {
                scanned_files: 0,
                semantic_noops: 0,
                sampled_acquisition: None,
            },
        );
    });
    let text = serde_json::to_string(&logs).unwrap();
    for secret in [
        "CANARY",
        "private-source",
        "plan_window_bucket",
        "region_mode",
        "NaN",
    ] {
        assert!(!text.contains(secret));
    }
    let counts = logs[0]["counts"]["selector_key_rejected"]
        .as_object()
        .unwrap();
    assert!(counts
        .keys()
        .all(|key| matches!(key.as_str(), "unknown" | "format")));
    assert_eq!(logs[0]["stage"], "native_collection_page");
}

#[test]
fn base_normalizer_absence_is_not_a_new_format_rejection() {
    let (_, counts) = observe_selector_rejections(|| {
        for (key, raw) in [
            ("plan_window_bucket", Value::Null),
            ("plan_window_bucket", json!("  ")),
            ("service_tier", json!(["priority"])),
            ("batch_mode", json!({"x": true})),
            ("batch_mode", json!("maybe")),
            ("mode", json!("turbo")),
        ] {
            assert!(normalize_selector_raw(key, &raw).is_none());
            let mut capture = SelectorCapture::default();
            insert_selector_raw(&mut capture, key, "fixture", &raw);
            assert!(capture.is_empty());
        }
    });
    assert_eq!(counts.selector_key_rejected_format, 0);
    assert_eq!(counts.selector_key_rejected_unknown, 0);
}

#[test]
fn pi_backend_context_values_survive_custom_capture() {
    let (_, counts) = observe_selector_rejections(|| {
        for bucket in ["short", "long", "standard", "unknown"] {
            let selector = pi_selector_from_custom(&json!({"customType":"ottto-selector",
                "data":{"context_bucket":bucket}}))
            .unwrap();
            assert_eq!(
                selector.context.get("context_bucket").map(String::as_str),
                Some(bucket)
            );
        }
    });
    assert_eq!(counts.selector_key_rejected_format, 0);
    assert_eq!(counts.selector_key_rejected_unknown, 0);
}

#[test]
fn scalar_boundaries_preserve_accepted_lexical_values() {
    let (_, counts) = observe_selector_rejections(|| {
        for (key, raw) in [
            ("plan_window_bucket", json!(0)),
            ("plan_window_bucket", json!(u64::MAX)),
            ("plan_window_bucket", json!("00020598")),
            ("batch_mode", json!("enabled")),
            ("batch_mode", json!(0)),
            ("mode", json!(true)),
            ("mode", json!("default")),
            ("context_bucket", json!("standard")),
            ("context_bucket", json!("unknown")),
            ("cache_ttl", json!("5m")),
            ("cache_ttl", json!("1h")),
            ("cache_ttl", json!(3600)),
            ("agent_quota_primary_used_percent", json!(125.5)),
            ("agent_quota_secondary_used_percent", json!(2.0)),
            ("agent_quota_credits_balance", json!("001.50")),
            ("agent_quota_credits_has_credits", json!(false)),
            ("service_tier", json!("a".repeat(128))),
        ] {
            let mut capture = SelectorCapture::default();
            insert_selector_raw(&mut capture, key, "fixture", &raw);
            assert_eq!(
                capture.context.get(key),
                normalize_selector_raw(key, &raw).as_ref()
            );
        }
        for (key, _) in SELECTOR_KEY_RULES {
            let mut capture = SelectorCapture::default();
            insert_selector_raw(&mut capture, key, "fixture", &Value::Null);
            assert!(capture.is_empty());
        }
    });
    assert_eq!(counts.selector_key_rejected_unknown, 0);
    assert_eq!(counts.selector_key_rejected_format, 0);
}

#[test]
fn container_unknowns_alias_precedence_and_existing_capture_inventory() {
    let (capture, counts) = observe_selector_rejections(|| {
        selector_from_object(
            &json!({
                "type":"ordinary-native-event", "unrelated":"native-value",
                "selector_context": {"/tmp/UNKNOWN_CANARY":"secret", "service_tier":[], "serviceTier":"priority",
                    "speedMode":"normal", "batchMode":true, "platform":"macos", "billing_provider":"openai",
                    "attribution_skill":"must-not-bypass-consent", "agent_quota_primary_used_percent":35.5},
                "selector": {"speed_mode":"fast", "speedMode":"standard"}
            }),
            "",
        )
    });
    assert_eq!(counts.selector_key_rejected_unknown, 1);
    assert_eq!(counts.selector_key_rejected_format, 0);
    assert_eq!(
        capture.context.get("speed_mode").map(String::as_str),
        Some("fast")
    );
    assert_eq!(
        capture.context.get("service_tier").map(String::as_str),
        Some("fast")
    );
    assert_eq!(
        capture.sources.get("speed_mode").map(String::as_str),
        Some("selector.speed_mode")
    );
    for ignored in [
        "platform",
        "billing_provider",
        "attribution_skill",
        "agent_quota_primary_used_percent",
    ] {
        assert!(!capture.context.contains_key(ignored));
    }
}

#[test]
fn native_producer_shapes_have_zero_rejections() {
    let (_, counts) = observe_selector_rejections(|| {
        let fields = json!({"serviceTier":"priority", "speed":"normal", "batchMode":true,
            "dataResidency":"US", "contextLengthBucket":"long", "cache_write_ttl_seconds":3600,
            "fastMode":true, "gatewayProvider":"bedrock", "modelProvider":"anthropic",
            "authMode":"API Key", "billingChannel":"subscription", "planType":"pro", "planWindowBucket":20598});
        for path in [
            "",
            "payload",
            "payload.info",
            "turn_context.payload",
            "token_count.info",
            "payload.rate_limits",
            "token_count.info.rate_limits",
        ] {
            let mut line = fields.clone();
            if !path.is_empty() {
                for key in path.split('.').rev() {
                    line = json!({key:line});
                }
            }
            let selector = codex_selector_from_line(&line);
            assert_eq!(
                selector
                    .context
                    .get("plan_window_bucket")
                    .map(String::as_str),
                Some("20598")
            );
        }
        for path in ["", "message.usage", "usage", "payload.usage"] {
            let mut line = fields.clone();
            if !path.is_empty() {
                for key in path.split('.').rev() {
                    line = json!({key:line});
                }
            }
            assert_eq!(claude_code_selector_from_line(&line).context.len(), 13);
        }
        for parent in ["payload", "token_count.info"] {
            let mut limits = json!({"rate_limits":{"plan_type":"pro", "primary":{"used_percent":35.5,"window_minutes":300,"resets_at":1779667300u64},
                "secondary":{"used_percent":2.0,"window_minutes":10080,"resets_at":1779667300u64},
                "credits":{"has_credits":true,"unlimited":false,"balance":"12.50"}}});
            for key in parent.split('.').rev() {
                limits = json!({key:limits});
            }
            let selector = codex_selector_from_line(&limits);
            for key in [
                "plan_window_bucket",
                "agent_quota_primary_used_percent",
                "agent_quota_primary_window_minutes",
                "agent_quota_primary_resets_at",
                "agent_quota_secondary_used_percent",
                "agent_quota_secondary_window_minutes",
                "agent_quota_secondary_resets_at",
                "agent_quota_credits_has_credits",
                "agent_quota_credits_unlimited",
                "agent_quota_credits_balance",
            ] {
                assert!(selector.context.contains_key(key), "{key}");
            }
        }
        for config in [
            "service_tier = 'priority'",
            "[features]\nfast_mode = true",
            "fast_default_opt_out = true",
        ] {
            assert!(!codex_config_selector(&config.parse::<DocumentMut>().unwrap()).is_empty());
        }
        for id in ["msg_example", "msg_vrtx_example", "msg_bdrk_example"] {
            let selector = claude_code_selector_from_line(&json!({"message":{"id":id}}));
            assert_eq!(
                selector.context.get("model_provider").map(String::as_str),
                Some("anthropic")
            );
        }
    });
    assert_eq!(counts.selector_key_rejected_unknown, 0);
    assert_eq!(counts.selector_key_rejected_format, 0);
}

#[test]
fn pi_custom_rejects_before_occurrence_identity() {
    let clean = json!({"customType":"ottto-selector", "data":{"selector_context":{"service_tier":"priority","plan_window_bucket":20598}}});
    let mut dirty = clean.clone();
    dirty["data"]["selector_context"]["plan_window_bucket"] = json!("/tmp/PI_BUCKET_CANARY");
    dirty["data"]["selector_context"]["/tmp/PI_KEY_CANARY"] = json!("PI_VALUE_CANARY");
    let (selector, counts) =
        observe_selector_rejections(|| pi_selector_from_custom(&dirty).unwrap());
    assert_eq!(counts.selector_key_rejected_unknown, 1);
    assert_eq!(counts.selector_key_rejected_format, 1);
    assert!(!selector.context.contains_key("plan_window_bucket"));
    let expected = pi_selector_from_custom(&json!({"customType":"ottto-selector", "data":{"selector_context":{"service_tier":"priority"}}})).unwrap();
    assert_eq!(selector, expected);
    let usage = UsageTotals {
        input_tokens: 10,
        output_tokens: 3,
        ..Default::default()
    };
    assert_eq!(
        pi_usage_occurrence_digest(
            Some("gpt-5.2"),
            &usage,
            &selector,
            Some("2026-10-20T10:00:00Z")
        ),
        pi_usage_occurrence_digest(
            Some("gpt-5.2"),
            &usage,
            &expected,
            Some("2026-10-20T10:00:00Z")
        )
    );
    assert_eq!(
        pi_selector_from_custom(&clean)
            .unwrap()
            .context
            .get("plan_window_bucket")
            .map(String::as_str),
        Some("20598")
    );
}

#[test]
fn all_existing_object_aliases_match_their_expected_formats_and_sources() {
    let (_, counts) = observe_selector_rejections(|| {
        for (field, raw, expected, aliases) in [
            (
                "service_tier",
                json!("default"),
                "standard",
                &[
                    "service_tier",
                    "serviceTier",
                    "service.tier",
                    "actual_service_tier",
                    "tier",
                ][..],
            ),
            (
                "speed_mode",
                json!("normal"),
                "standard",
                &["speed_mode", "speedMode", "speed"],
            ),
            (
                "batch_mode",
                json!(true),
                "true",
                &["batch_mode", "batchMode", "batch"],
            ),
            (
                "region_mode",
                json!("US"),
                "us",
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
                json!("long"),
                "long",
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
                json!(3600),
                "3600",
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
                json!(true),
                "fast",
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
                json!("bedrock"),
                "bedrock",
                &["gateway_provider", "gatewayProvider", "api"],
            ),
            (
                "model_provider",
                json!("openai"),
                "openai",
                &["model_provider", "modelProvider", "provider"],
            ),
            (
                "auth_mode",
                json!("API Key"),
                "api_key",
                &["auth_mode", "authMode"],
            ),
            (
                "billing_channel",
                json!("subscription"),
                "subscription",
                &["billing_channel", "billingChannel"],
            ),
            (
                "subscription_product",
                json!("Pro"),
                "pro",
                &[
                    "subscription_product",
                    "subscriptionProduct",
                    "plan_type",
                    "planType",
                ],
            ),
            (
                "plan_window_bucket",
                json!(20598),
                "20598",
                &["plan_window_bucket", "planWindowBucket"],
            ),
        ] {
            for &alias in aliases {
                let selector = selector_from_object(&json!({alias:raw}), "selector_context");
                assert_eq!(
                    selector.context.get(field).map(String::as_str),
                    Some(expected),
                    "{alias}"
                );
                assert_eq!(
                    selector.sources.get(field),
                    Some(&format!("selector_context.{alias}"))
                );
            }
        }
    });
    assert_eq!(counts.selector_key_rejected_unknown, 0);
    assert_eq!(counts.selector_key_rejected_format, 0);
}

#[test]
fn claude_active_scopes_do_not_duplicate_selector_totals_in_cache_events() {
    use crate::local_resource_diagnostics::{
        capture, claude_reread::Scope, CollectionCounts, NativeDecision, Probe,
    };
    let reject = || {
        claude_code_selector_from_line(&json!({"selector_context":{
            "PRIVATE_CLASS_CANARY":"VALUE_CLASS_CANARY", "plan_window_bucket":"/tmp/BUCKET_CLASS_CANARY"
        }}));
    };
    let (_, logs) = capture(|| {
        let scope = Scope::begin(true);
        cache_lifecycle::record(cache_lifecycle::Event::TakeHit);
        reject();
        let mut probe = Probe::start();
        probe.page_events.merge(scope.finish());
        probe.collection(
            "claude_code",
            CollectionCounts {
                scanned_files: 1,
                semantic_noops: 0,
                sampled_acquisition: None,
            },
        );
        let scope = Scope::begin(true);
        reject();
        NativeDecision::new().emit();
        drop(scope);
    });
    assert_eq!(logs.len(), 2);
    assert_eq!(
        logs[0]["counts"]["retained_cache_page_events"]["take_hit"],
        1
    );
    assert!(
        logs[0]["counts"]["selector_key_rejected"]["unknown"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        logs[0]["counts"]["selector_key_rejected"]["format"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(logs[1]["counts"].get("selector_key_rejected").is_none());
    let text = serde_json::to_string(&logs).unwrap();
    for forbidden in [
        "CLASS_CANARY",
        "selector_key_rejected_unknown",
        "selector_key_rejected_format",
    ] {
        assert!(!text.contains(forbidden));
    }
}
