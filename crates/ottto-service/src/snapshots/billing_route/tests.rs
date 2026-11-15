//! Route annotation oracle rows that live in the daemon: classification,
//! latch, durability, wire gating and money neutrality.
use super::*;
use crate::agent_status::{claude_alternative_auth_layers, claude_login_route_candidate};
use crate::snapshots::tests::valid_v6_batch_request;

const MACHINE: &str = "machine";
const NOW: u64 = 1_800_000_000;
const STARTED: u64 = NOW - 3_600;

fn at(unix: u64) -> String {
    OffsetDateTime::from_unix_timestamp(unix as i64)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// One owned Claude request: (request id, message id, model, desktop,
/// telemetry account, ended at).
struct Req {
    request: &'static str,
    message: &'static str,
    model: &'static str,
    desktop: bool,
    telemetry_account: bool,
    at: u64,
}

fn req(request: &'static str, message: &'static str) -> Req {
    Req {
        request,
        message,
        model: "claude-opus-4-7",
        desktop: false,
        telemetry_account: false,
        at: NOW - 60,
    }
}

fn claude_item(session: &str, requests: &[Req]) -> SnapshotItem {
    let mut item = SnapshotItem {
        source_session_id: session.to_string(),
        ..SnapshotItem::default()
    };
    for (sequence, r) in requests.iter().enumerate() {
        let key = format!("p\u{1f}{}\u{1f}{}", r.message, r.request);
        let (native, third_party) = claude_key_route_ids(&key);
        item.claude_usage_occurrences.insert(
            r.request.to_string(),
            ClaudeTranscriptUsageOccurrence {
                sequence: sequence as u64,
                usage: Default::default(),
                model: Some(r.model.to_string()),
                selector: Default::default(),
                reasoning_effort: None,
                timestamp: Some(at(r.at)),
                event_clock_complete: true,
                desktop_request: r.desktop,
                effective_input_context: 0,
                telemetry_attached: r.telemetry_account,
                route_native_ids: native,
                route_third_party_id: third_party,
                route_telemetry_account: r.telemetry_account,
            },
        );
    }
    item
}

fn context(login: Option<LoginCandidate>) -> RouteContext {
    RouteContext {
        record: true,
        emit: true,
        now_unix: NOW,
        process_started_unix: STARTED,
        claude_login: login.map(|candidate| (candidate, NOW - 120)),
    }
}

fn apply(
    index: &mut ScanIndex,
    source: SnapshotSource,
    item: SnapshotItem,
    context: &RouteContext,
) -> SnapshotItem {
    let mut items = [item];
    index.apply_session_billing_routes(source, MACHINE, &mut items, context);
    let [item] = items;
    item
}

fn route(item: &SnapshotItem) -> Value {
    serde_json::to_value(item.session_billing_route.as_ref().expect("route object")).unwrap()
}

fn known(route: &str, source: &str) -> Value {
    json!({"first_route": route, "routes_seen": [route], "first_route_source": source})
}

fn unknown(reason: &str) -> Value {
    json!({"first_route": null, "routes_seen": [], "unknown_reason": reason})
}

fn claude_route(login: Option<LoginCandidate>, requests: &[Req]) -> Value {
    let mut index = ScanIndex::default();
    route(&apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", requests),
        &context(login),
    ))
}

#[test]
fn claude_subscription_needs_oauth_and_same_session_corroboration() {
    use LoginCandidate as C;
    let desktop = Req {
        desktop: true,
        ..req("req_1", "msg_1")
    };
    let uuid = Req {
        telemetry_account: true,
        ..req("req_1", "msg_1")
    };
    let plain = req("req_1", "msg_1");
    let subscription = known("subscription", "evaluator_snapshot");
    assert_eq!(claude_route(Some(C::Oauth), &[desktop]), subscription);
    assert_eq!(claude_route(Some(C::Oauth), &[uuid]), subscription);
    // OAuth alone, Desktop alone, account alone: never a label.
    assert_eq!(
        claude_route(Some(C::Oauth), &[req("req_1", "msg_1")]),
        unknown("uncorroborated_snapshot")
    );
    let desktop = Req {
        desktop: true,
        ..req("req_1", "id_1")
    };
    assert_eq!(
        claude_route(Some(C::ApiKey), &[desktop]),
        unknown("uncorroborated_snapshot")
    );
    let uuid = Req {
        telemetry_account: true,
        ..req("req_1", "msg_1")
    };
    assert_eq!(
        claude_route(None, &[uuid]),
        unknown("first_request_snapshot_missing")
    );
    // API key alone (no native id pair) and the native pair with OAuth.
    assert_eq!(
        claude_route(Some(C::ApiKey), &[req("req_1", "other_1")]),
        unknown("uncorroborated_snapshot")
    );
    assert_eq!(
        claude_route(Some(C::ApiKey), &[plain]),
        known("direct_api", "evaluator_snapshot")
    );
}

#[test]
fn claude_third_party_and_visible_exclusions_stay_unknown() {
    use LoginCandidate as C;
    let bedrock = Req {
        model: "us.anthropic.claude-sonnet-4-6",
        telemetry_account: true,
        ..req("req_1", "msg_1")
    };
    // A known API candidate (or hidden shell Bedrock under daemon OAuth)
    // with a third-party model in the session: conflict, never a label.
    assert_eq!(
        claude_route(Some(C::ApiKey), &[req("req_0", "msg_0"), bedrock]),
        unknown("signal_conflict")
    );
    let vertex_id = req("req_1", "msg_vrtx_1");
    assert_eq!(
        claude_route(Some(C::Oauth), &[vertex_id]),
        unknown("signal_conflict")
    );
    for (login, reason) in [
        (C::ThirdPartyPending, "3p_classifier_pending"),
        (C::ProxyEndpoint, "proxy_endpoint"),
        (C::ModeUnknown, "mode_unknown"),
        (C::Unsupported, "unsupported_provider_auth"),
        (C::NoUsableLogin, "missing_evidence"),
    ] {
        let desktop = Req {
            desktop: true,
            telemetry_account: true,
            ..req("req_1", "msg_1")
        };
        assert_eq!(claude_route(Some(login), &[desktop]), unknown(reason));
    }
    // Hidden shell override with no corroboration: uncorroborated.
    assert_eq!(
        claude_route(Some(C::Oauth), &[req("req_1", "msg_1")]),
        unknown("uncorroborated_snapshot")
    );
    // Disclosed: a native-looking shell gateway beside a session account
    // still reads as the plan.
    let gateway = Req {
        telemetry_account: true,
        ..req("req_1", "msg_1")
    };
    assert_eq!(
        claude_route(Some(C::Oauth), &[gateway]),
        known("subscription", "evaluator_snapshot")
    );
}

#[test]
fn claude_id_and_model_shapes() {
    assert_eq!(
        claude_key_route_ids("p\u{1f}msg_01\u{1f}req_01"),
        (true, false)
    );
    assert_eq!(
        claude_key_route_ids("p\u{1f}msg_bdrk_01\u{1f}req_01"),
        (false, true)
    );
    assert_eq!(claude_key_route_ids("m\u{1f}msg_01"), (false, false));
    assert_eq!(claude_key_route_ids("r\u{1f}req_01"), (false, false));
    assert_eq!(claude_key_route_ids("u\u{1f}7"), (false, false));
    for model in [
        "us.anthropic.claude-sonnet-4-6",
        "global.anthropic.claude-opus-4-7",
        "arn:aws:bedrock:us-east-1:0:inference-profile/x",
        "anthropic.claude-haiku-4-5",
        "claude-sonnet-4-6@20260101",
    ] {
        assert!(claude_third_party_model(model), "{model}");
    }
    for model in [
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "<synthetic>",
        "gpt-5.5",
    ] {
        assert!(!claude_third_party_model(model), "{model}");
    }
}

#[test]
fn claude_first_request_snapshot_is_live_only_and_never_retaken() {
    // History (first request before this process started): missing, even
    // with today's login available.
    let old = Req {
        desktop: true,
        at: STARTED - 600,
        ..req("req_1", "msg_1")
    };
    assert_eq!(
        claude_route(Some(LoginCandidate::Oauth), &[old]),
        unknown("first_request_snapshot_missing")
    );
    // Live but stale by the window: missing.
    let stale = Req {
        desktop: true,
        at: NOW - LIVE_WINDOW_SECONDS - 1,
        ..req("req_1", "msg_1")
    };
    let mut late = context(Some(LoginCandidate::Oauth));
    late.process_started_unix = 0;
    let mut index = ScanIndex::default();
    let item = apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[stale]),
        &late,
    );
    assert_eq!(route(&item), unknown("first_request_snapshot_missing"));

    // Frozen: the session's latch keeps the first login after settings change.
    let mut index = ScanIndex::default();
    let first = claude_item("s", &[req("req_1", "msg_1")]);
    apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        first,
        &context(Some(LoginCandidate::ApiKey)),
    );
    let later = Req {
        desktop: true,
        ..req("req_2", "msg_2")
    };
    let item = apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[req("req_1", "msg_1"), later]),
        &context(Some(LoginCandidate::Oauth)),
    );
    assert_eq!(route(&item), known("direct_api", "evaluator_snapshot"));
}

#[test]
fn claude_unknown_becomes_known_once_then_freezes() {
    let mut index = ScanIndex::default();
    let oauth = context(Some(LoginCandidate::Oauth));
    let item = apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[req("req_1", "msg_1")]),
        &oauth,
    );
    assert_eq!(route(&item), unknown("uncorroborated_snapshot"));
    // The session's own telemetry account arrives later: the frozen OAuth
    // snapshot is now corroborated.
    let joined = Req {
        telemetry_account: true,
        ..req("req_1", "msg_1")
    };
    let item = apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[joined]),
        &oauth,
    );
    let subscription = known("subscription", "evaluator_snapshot");
    assert_eq!(route(&item), subscription);
    // Later third-party evidence is recorded, never corrected.
    let bedrock = Req {
        model: "global.anthropic.claude-opus-4-7",
        ..req("req_2", "msg_bdrk_2")
    };
    let item = apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[req("req_1", "msg_1"), bedrock]),
        &oauth,
    );
    assert_eq!(route(&item), subscription);
    let fact = index.session_billing_routes.values().next().unwrap();
    assert!(fact.conflict_after_latch);
    assert_eq!(fact.login, Some(LoginCandidate::Oauth));
}

#[test]
fn zero_request_and_synthetic_sessions_get_no_latch() {
    let mut index = ScanIndex::default();
    let oauth = context(Some(LoginCandidate::Oauth));
    let synthetic = Req {
        model: "<synthetic>",
        desktop: true,
        ..req("req_0", "msg_0")
    };
    for item in [claude_item("s", &[]), claude_item("s", &[synthetic])] {
        let item = apply(&mut index, SnapshotSource::ClaudeCode, item, &oauth);
        assert_eq!(route(&item), unknown("missing_evidence"));
        assert!(index.session_billing_routes.is_empty());
    }
    // The first real request is still captured live.
    let desktop = Req {
        desktop: true,
        ..req("req_1", "msg_1")
    };
    let item = apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[desktop]),
        &oauth,
    );
    assert_eq!(route(&item), known("subscription", "evaluator_snapshot"));
}

#[test]
fn latch_survives_crash_after_classification_rollback_and_reupgrade() {
    let mut index = ScanIndex::default();
    let desktop = || Req {
        desktop: true,
        ..req("req_1", "msg_1")
    };
    apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[desktop()]),
        &context(Some(LoginCandidate::Oauth)),
    );
    let saved = index.session_billing_routes.clone();
    // Crash after the committed save: the reloaded index keeps the exact
    // latch and its frozen login.
    let scratch = crate::test_scratch::ScratchDir::new("route-latch");
    let path = scratch.as_ref().join("index.json");
    index.save(&path).unwrap();
    let mut restored = ScanIndex::load(&path).unwrap();
    assert_eq!(restored.session_billing_routes, saved);
    // Rollback to the preservation-only release: nothing recorded or sent,
    // the latch kept as is.
    let off = RouteContext {
        record: false,
        emit: false,
        ..context(Some(LoginCandidate::ApiKey))
    };
    let item = apply(
        &mut restored,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[desktop()]),
        &off,
    );
    assert!(item.session_billing_route.is_none());
    assert_eq!(restored.session_billing_routes, saved);
    // Re-upgrade with a changed login: the same first result.
    let item = apply(
        &mut restored,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[desktop()]),
        &context(Some(LoginCandidate::ApiKey)),
    );
    assert_eq!(route(&item), known("subscription", "evaluator_snapshot"));

    // Crash before the save: no latch survives and the request is history
    // for the restarted process; today's login is never applied to it.
    let mut fresh = ScanIndex::default();
    let mut restarted = context(Some(LoginCandidate::Oauth));
    restarted.process_started_unix = NOW;
    let item = apply(
        &mut fresh,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[desktop()]),
        &restarted,
    );
    assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
}

#[test]
fn latch_is_scoped_by_source_machine_and_session() {
    let mut index = ScanIndex::default();
    let desktop = Req {
        desktop: true,
        ..req("req_1", "msg_1")
    };
    apply(
        &mut index,
        SnapshotSource::ClaudeCode,
        claude_item("a", &[desktop]),
        &context(Some(LoginCandidate::Oauth)),
    );
    // A new destination namespace starts from its own empty index: no carry,
    // and its history is not reclassified from the current login.
    let mut new_destination = ScanIndex::default();
    let old = Req {
        desktop: true,
        at: STARTED - 60,
        ..req("req_1", "msg_1")
    };
    let item = apply(
        &mut new_destination,
        SnapshotSource::ClaudeCode,
        claude_item("a", &[old]),
        &context(Some(LoginCandidate::Oauth)),
    );
    assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
    assert_ne!(
        route_key(SnapshotSource::ClaudeCode, MACHINE, "a"),
        route_key(SnapshotSource::Pi, MACHINE, "a")
    );
}

fn row(model_provider: Option<&str>, auth_mode: Option<&str>) -> SnapshotModelUsage {
    let mut row = valid_v6_batch_request().snapshots[0].model_usage[0].clone();
    row.model_provider = model_provider.map(str::to_string);
    row.auth_mode = auth_mode.map(str::to_string);
    row
}

fn rows_item(rows: Vec<SnapshotModelUsage>) -> SnapshotItem {
    SnapshotItem {
        source_session_id: "s".into(),
        model_usage: rows,
        ..SnapshotItem::default()
    }
}

fn rows_route(source: SnapshotSource, rows: Vec<SnapshotModelUsage>) -> Value {
    let mut index = ScanIndex::default();
    route(&apply(&mut index, source, rows_item(rows), &context(None)))
}

#[test]
fn codex_uses_only_explicit_recorded_auth() {
    use SnapshotSource::Codex;
    let source = "codex_auth_snapshot";
    assert_eq!(
        rows_route(Codex, vec![row(Some("openai"), Some("chatgpt"))]),
        known("subscription", source)
    );
    assert_eq!(
        rows_route(Codex, vec![row(Some("openai"), Some("apikey"))]),
        known("direct_api", source)
    );
    // An API key on a non-native endpoint stays unknown.
    assert_eq!(
        rows_route(Codex, vec![row(Some("custom-proxy"), Some("apikey"))]),
        unknown("proxy_endpoint")
    );
    assert_eq!(
        rows_route(Codex, vec![row(None, Some("apikey"))]),
        unknown("missing_evidence")
    );
    assert_eq!(
        rows_route(Codex, vec![row(Some("openai"), None)]),
        unknown("missing_evidence")
    );
    // Two routes with no request order on the first fold: conflict.
    assert_eq!(
        rows_route(
            Codex,
            vec![
                row(Some("openai"), Some("chatgpt")),
                row(Some("openai"), Some("apikey"))
            ]
        ),
        unknown("signal_conflict")
    );
}

#[test]
fn pi_allowlist_and_mixed_route_union() {
    use SnapshotSource::Pi;
    let source = "pi_provider_auth";
    assert_eq!(
        rows_route(
            Pi,
            vec![row(Some("google-vertex"), Some("service_account"))]
        ),
        known("google_vertex", source)
    );
    for (provider, auth) in [
        (Some("google-vertex"), None),
        (Some("google-vertex"), Some("oauth")),
        (Some("mistral"), Some("service_account")),
        (Some("vercel-ai-gateway"), Some("api_key")),
        (None, None),
    ] {
        assert_eq!(
            rows_route(Pi, vec![row(provider, auth)]),
            unknown("unsupported_provider_auth"),
            "{provider:?} {auth:?}"
        );
    }
    // Mixed: the first route stays; the later one joins routes_seen.
    let mut index = ScanIndex::default();
    let vertex = row(Some("google-vertex"), Some("service_account"));
    let bedrock = row(Some("amazon-bedrock"), Some("service_account"));
    apply(
        &mut index,
        Pi,
        rows_item(vec![vertex.clone()]),
        &context(None),
    );
    let item = apply(
        &mut index,
        Pi,
        rows_item(vec![vertex, bedrock]),
        &context(None),
    );
    assert_eq!(
        route(&item),
        json!({
            "first_route": "google_vertex",
            "routes_seen": ["amazon_bedrock", "google_vertex"],
            "first_route_source": source,
        })
    );
}

/// The annotation never touches existing bytes: off, the upload body is
/// byte-identical; on, the only difference is the added object, and every
/// money, placement and identity field, the fingerprint and the body
/// witness are unchanged.
#[test]
fn upload_bytes_and_money_fields_unchanged_off_and_additive_on() {
    let request = valid_v6_batch_request();
    let base = serde_json::to_string(&request).unwrap();
    for (source, rows) in [
        (
            SnapshotSource::Pi,
            vec![row(Some("google-vertex"), Some("service_account"))],
        ),
        (
            SnapshotSource::Codex,
            vec![row(Some("openai"), Some("chatgpt"))],
        ),
    ] {
        let mut off = request.clone();
        off.snapshots[0].model_usage = rows.clone();
        let mut on = off.clone();
        let before = serde_json::to_value(&off).unwrap();
        let fingerprint = snapshot_fingerprint(source, &off.snapshots[0]);
        let witness = snapshot_upload_body_witness(&off.snapshots[0]);

        let mut index = ScanIndex::default();
        for context in [
            RouteContext {
                record: false,
                emit: false,
                ..context(None)
            },
            RouteContext {
                emit: false,
                ..context(None)
            },
        ] {
            index.apply_session_billing_routes(source, MACHINE, &mut off.snapshots, &context);
            assert_eq!(serde_json::to_value(&off).unwrap(), before);
        }
        index.apply_session_billing_routes(source, MACHINE, &mut on.snapshots, &context(None));
        let mut after = serde_json::to_value(&on).unwrap();
        let added = after["snapshots"][0]
            .as_object_mut()
            .unwrap()
            .remove("session_billing_route")
            .expect("added object");
        assert!(added["first_route"].is_string());
        assert_eq!(after, before);
        assert_eq!(snapshot_fingerprint(source, &on.snapshots[0]), fingerprint);
        assert_eq!(snapshot_upload_body_witness(&on.snapshots[0]), witness);
    }
    // The unchanged fixture itself still serializes to the same bytes.
    assert_eq!(
        serde_json::to_string(&valid_v6_batch_request()).unwrap(),
        base
    );
}

#[test]
fn login_candidate_reads_visible_inputs_and_flags_unknown_mode() {
    use LoginCandidate as C;
    let none = |_: &str| -> Option<String> { None };
    let candidate = |layers: &[Value], oauth: bool| {
        let interactive = claude_alternative_auth_layers(layers, &none, oauth, &[], false);
        let print = claude_alternative_auth_layers(layers, &none, false, &[], false);
        let print = if oauth { print } else { interactive };
        claude_login_route_candidate(layers, &none, oauth, interactive, print)
    };
    assert_eq!(candidate(&[json!({})], true), C::Oauth);
    assert_eq!(candidate(&[json!({})], false), C::NoUsableLogin);
    // A declined key: interactive stays on OAuth, `-p` would use the key.
    let key = json!({"env": {"ANTHROPIC_API_KEY": "sk-test-0000000000000000000000"}});
    assert_eq!(candidate(std::slice::from_ref(&key), true), C::ModeUnknown);
    assert_eq!(candidate(&[key], false), C::ApiKey);
    let bedrock = json!({"env": {"CLAUDE_CODE_USE_BEDROCK": "1"}});
    assert_eq!(candidate(&[bedrock], true), C::ThirdPartyPending);
    let proxy =
        json!({"env": {"ANTHROPIC_BASE_URL": "https://gateway.example"}, "apiKeyHelper": "x"});
    assert_eq!(candidate(&[proxy], true), C::ProxyEndpoint);
    let native =
        json!({"env": {"ANTHROPIC_BASE_URL": "https://api.anthropic.com/"}, "apiKeyHelper": "x"});
    assert_eq!(candidate(&[native], true), C::ApiKey);
    let foundry = json!({"env": {"CLAUDE_CODE_USE_FOUNDRY": "true"}});
    assert_eq!(candidate(&[foundry], true), C::Unsupported);
}
