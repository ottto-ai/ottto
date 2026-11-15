//! Route annotation oracle rows that live in the daemon: classification,
//! evaluator binding, restart and boundary rules, latch lifecycle, wire
//! gating, OFF work, no persisted state and money neutrality.
use super::*;
use crate::agent_status::{claude_alternative_auth_layers, claude_login_route_candidate};
use crate::snapshots::tests::valid_v6_batch_request;

const MACHINE: &str = "machine";
const DEST: &str = "destination";
const SECOND: i64 = 1_000_000_000;

type Latches = BTreeMap<String, SessionBillingRouteFact>;
/// Unix nanoseconds.
const NOW: i64 = 1_800_000_000 * SECOND;
const STARTED: i64 = NOW - 3_600 * SECOND;

fn at(nanos: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// One owned Claude request: ids, model, desktop, telemetry account, and
/// when it started (its preceding record) and ended.
struct Req {
    request: &'static str,
    message: &'static str,
    model: &'static str,
    desktop: bool,
    telemetry_account: bool,
    started: i64,
    ended: i64,
    /// The response's end is stamped.
    stamped: bool,
    /// Every record of the response is stamped.
    complete: bool,
}

fn req(request: &'static str, message: &'static str) -> Req {
    Req {
        request,
        message,
        model: "claude-opus-4-7",
        desktop: false,
        telemetry_account: false,
        started: NOW - 90 * SECOND,
        ended: NOW - 60 * SECOND,
        stamped: true,
        complete: true,
    }
}

fn desktop(request: &'static str, message: &'static str, started: i64, ended: i64) -> Req {
    Req {
        desktop: true,
        started,
        ended,
        ..req(request, message)
    }
}

/// A Claude item whose earliest line is its first request's preceding record
/// and whose first own response is its first request.
fn claude_item(session: &str, requests: &[Req]) -> SnapshotItem {
    claude_item_after(session, None, requests)
}

/// As [`claude_item`], with an id-less response at `idless` (unix
/// nanoseconds) before the requests.
fn claude_item_after(session: &str, idless: Option<i64>, requests: &[Req]) -> SnapshotItem {
    let mut item = SnapshotItem {
        source_session_id: session.to_string(),
        // The start witness `start_witness` sets when the producer is on.
        claude_route_evidence: Some(Box::new(ClaudeRouteEvidence {
            first_line_ns: idless
                .into_iter()
                .chain(requests.iter().map(|r| r.started))
                .min(),
            ..ClaudeRouteEvidence::default()
        })),
        ..SnapshotItem::default()
    };
    if idless.is_some() || !requests.is_empty() {
        item.claude_file_birth.observe_response_at(0, None, 0);
    }
    let offset = usize::from(idless.is_some());
    for (index, r) in requests.iter().enumerate() {
        let sequence = index + offset;
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
                timestamp: r.stamped.then(|| at(r.ended)),
                event_clock_complete: r.complete,
                desktop_request: r.desktop,
                effective_input_context: 0,
                telemetry_attached: r.telemetry_account,
                route_native_ids: native,
                route_third_party_id: third_party,
                route_telemetry_account: r.telemetry_account,
                route_started_ns: Some(r.started),
            },
        );
    }
    item
}

/// A login that changed when this process started and was observed now.
fn login(candidate: LoginCandidate) -> ClaudeLogin {
    ClaudeLogin {
        candidate,
        changed_ns: STARTED,
        observed_ns: NOW,
    }
}

fn context(candidate: Option<LoginCandidate>) -> RouteContext {
    with_login(candidate.map(login))
}

fn with_login(claude_login: Option<ClaudeLogin>) -> RouteContext {
    RouteContext {
        emit: true,
        process_started_ns: STARTED,
        claude_login,
    }
}

fn apply(
    latches: &mut Latches,
    source: SnapshotSource,
    item: SnapshotItem,
    context: &RouteContext,
) -> SnapshotItem {
    let mut items = [item];
    apply_session_billing_routes(latches, DEST, source, MACHINE, &mut items, context);
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

fn claude_route(candidate: Option<LoginCandidate>, requests: &[Req]) -> Value {
    let mut latches = Latches::new();
    route(&apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", requests),
        &context(candidate),
    ))
}

#[test]
fn claude_subscription_needs_oauth_and_same_session_corroboration() {
    use LoginCandidate as C;
    let uuid = || Req {
        telemetry_account: true,
        ..req("req_1", "msg_1")
    };
    let subscription = known("subscription", "evaluator_snapshot");
    assert_eq!(
        claude_route(
            Some(C::Oauth),
            &[desktop(
                "req_1",
                "msg_1",
                NOW - 90 * SECOND,
                NOW - 60 * SECOND
            )]
        ),
        subscription
    );
    // Also the disclosed residual: a native-looking shell gateway beside a
    // session account reads the same and still latches the plan.
    assert_eq!(claude_route(Some(C::Oauth), &[uuid()]), subscription);
    // OAuth alone, Desktop alone, account alone: never a label.
    assert_eq!(
        claude_route(Some(C::Oauth), &[req("req_1", "msg_1")]),
        unknown("uncorroborated_snapshot")
    );
    assert_eq!(
        claude_route(
            Some(C::ApiKey),
            &[desktop(
                "req_1",
                "id_1",
                NOW - 90 * SECOND,
                NOW - 60 * SECOND
            )]
        ),
        unknown("uncorroborated_snapshot")
    );
    // No evaluation published yet: deferred, no object and no latch.
    let mut latches = Latches::new();
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[uuid()]),
        &context(None),
    );
    assert!(item.session_billing_route.is_none());
    assert!(latches.is_empty());
    // API key alone (no native id pair) and the native pair with OAuth.
    assert_eq!(
        claude_route(Some(C::ApiKey), &[req("req_1", "other_1")]),
        unknown("uncorroborated_snapshot")
    );
    assert_eq!(
        claude_route(Some(C::ApiKey), &[req("req_1", "msg_1")]),
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
    assert_eq!(
        claude_route(Some(C::Oauth), &[req("req_1", "msg_vrtx_1")]),
        unknown("signal_conflict")
    );
    for (candidate, reason) in [
        (C::ThirdPartyPending, "3p_classifier_pending"),
        (C::ProxyEndpoint, "proxy_endpoint"),
        (C::ModeUnknown, "mode_unknown"),
        (C::Unsupported, "unsupported_provider_auth"),
        (C::NoUsableLogin, "missing_evidence"),
    ] {
        let corroborated = Req {
            desktop: true,
            telemetry_account: true,
            ..req("req_1", "msg_1")
        };
        assert_eq!(
            claude_route(Some(candidate), &[corroborated]),
            unknown(reason)
        );
    }
}

/// A cloud message or request id on any owned request vetoes both
/// conjunctions, with a native model and full corroboration.
#[test]
fn cloud_id_on_any_request_vetoes_both_conjunctions() {
    use LoginCandidate as C;
    // Native model, own telemetry account and the native pair everywhere
    // else: only the cloud id differs.
    let corroborated = |request, message| Req {
        telemetry_account: true,
        ..req(request, message)
    };
    for (request, message) in [
        ("req_2", "msg_bdrk_2"),
        ("req_2", "msg_vrtx_2"),
        ("req_bdrk_2", "msg_2"),
        ("req_vrtx_2", "msg_2"),
    ] {
        for login in [C::Oauth, C::ApiKey] {
            let requests = [
                corroborated("req_1", "msg_1"),
                corroborated(request, message),
            ];
            assert_eq!(
                claude_route(Some(login), &requests),
                unknown("signal_conflict"),
                "{login:?} {request} {message}"
            );
        }
    }
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
fn claude_unknown_becomes_known_once_then_freezes() {
    let mut latches = Latches::new();
    let oauth = context(Some(LoginCandidate::Oauth));
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[req("req_1", "msg_1")]),
        &oauth,
    );
    assert_eq!(route(&item), unknown("uncorroborated_snapshot"));
    // The session's own telemetry account arrives later: the OAuth snapshot
    // proven for that request is now corroborated.
    let joined = Req {
        telemetry_account: true,
        ..req("req_1", "msg_1")
    };
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[joined]),
        &oauth,
    );
    let subscription = known("subscription", "evaluator_snapshot");
    assert_eq!(route(&item), subscription);
    // Later third-party evidence never corrects a known first route.
    let bedrock = Req {
        model: "global.anthropic.claude-opus-4-7",
        ..req("req_2", "msg_bdrk_2")
    };
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[req("req_1", "msg_1"), bedrock]),
        &oauth,
    );
    assert_eq!(route(&item), subscription);
}

#[test]
fn zero_request_and_synthetic_sessions_get_no_latch() {
    let mut latches = Latches::new();
    let oauth = context(Some(LoginCandidate::Oauth));
    let synthetic = Req {
        model: "<synthetic>",
        desktop: true,
        ..req("req_0", "msg_0")
    };
    for item in [claude_item("s", &[]), claude_item("s", &[synthetic])] {
        let item = apply(&mut latches, SnapshotSource::ClaudeCode, item, &oauth);
        assert_eq!(route(&item), unknown("missing_evidence"));
        assert!(latches.is_empty());
    }
    // The first real request is still captured live.
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item(
            "s",
            &[desktop(
                "req_1",
                "msg_1",
                NOW - 90 * SECOND,
                NOW - 60 * SECOND,
            )],
        ),
        &oauth,
    );
    assert_eq!(route(&item), known("subscription", "evaluator_snapshot"));
}

/// A session whose first own request ended before this process started stays
/// unknown for the whole process, however many proven live requests follow;
/// nothing is latched for it.
#[test]
fn pre_start_first_request_stays_unknown_across_later_live_requests() {
    let mut first_process = Latches::new();
    let first = || desktop("req_1", "msg_1", NOW - 90 * SECOND, NOW - 60 * SECOND);
    let item = apply(
        &mut first_process,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[first()]),
        &context(Some(LoginCandidate::Oauth)),
    );
    assert_eq!(route(&item), known("subscription", "evaluator_snapshot"));

    // Restart after that request; the evaluator is proven for every later
    // request.
    let restarted = RouteContext {
        process_started_ns: NOW,
        claude_login: Some(ClaudeLogin {
            candidate: LoginCandidate::Oauth,
            changed_ns: NOW + SECOND,
            observed_ns: NOW + 1_000 * SECOND,
        }),
        ..context(None)
    };
    let mut latches = Latches::new();
    let mut requests = vec![first()];
    for (n, (request, message)) in [("req_2", "msg_2"), ("req_3", "msg_3"), ("req_4", "msg_4")]
        .into_iter()
        .enumerate()
    {
        let started = NOW + (10 + 100 * n as i64) * SECOND;
        requests.push(desktop(request, message, started, started + 10 * SECOND));
        let item = apply(
            &mut latches,
            SnapshotSource::ClaudeCode,
            claude_item("s", &requests),
            &restarted,
        );
        assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
        assert!(latches.is_empty());
    }
}

/// Precise times: a session whose earliest record falls in the same second
/// as the process start but before it (or exactly at it) is history.
#[test]
fn same_second_boundary_is_compared_precisely() {
    let start = NOW + 700_000_000;
    let started = RouteContext {
        process_started_ns: start,
        claude_login: Some(ClaudeLogin {
            candidate: LoginCandidate::Oauth,
            changed_ns: NOW - 10 * SECOND,
            observed_ns: NOW + 100 * SECOND,
        }),
        ..context(None)
    };
    for first_record in [NOW + 100_000_000, start] {
        let mut latches = Latches::new();
        let item = apply(
            &mut latches,
            SnapshotSource::ClaudeCode,
            claude_item(
                "s",
                &[desktop("req_1", "msg_1", first_record, NOW + 900_000_000)],
            ),
            &started,
        );
        assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
        assert!(latches.is_empty());
    }
    let mut latches = Latches::new();
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item(
            "s",
            &[desktop(
                "req_1",
                "msg_1",
                NOW + 800_000_000,
                NOW + 900_000_000,
            )],
        ),
        &started,
    );
    assert_eq!(route(&item), known("subscription", "evaluator_snapshot"));
}

/// Only the session's first own response names the first route, and only
/// with complete, live evidence; a later request never stands in for it.
#[test]
fn first_request_evidence_must_be_complete() {
    let oauth = context(Some(LoginCandidate::Oauth));
    let later = || desktop("req_1", "msg_1", NOW - 50 * SECOND, NOW - 40 * SECOND);
    let first = || desktop("req_0", "msg_0", NOW - 90 * SECOND, NOW - 60 * SECOND);
    let missing = |item: SnapshotItem| {
        let mut latches = Latches::new();
        let item = apply(&mut latches, SnapshotSource::ClaudeCode, item, &oauth);
        assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
        assert!(latches.is_empty());
    };
    // An id-less first response, before or after the start.
    for idless in [STARTED - 60 * SECOND, NOW - 60 * SECOND] {
        missing(claude_item_after("s", Some(idless), &[later()]));
    }
    // An unstamped first response, then a complete later one.
    let unstamped = Req {
        stamped: false,
        ..first()
    };
    missing(claude_item("s", &[unstamped, later()]));
    // An incomplete clock: a stamped partial, then an unstamped terminal.
    let partial = Req {
        complete: false,
        ..first()
    };
    missing(claude_item("s", &[partial, later()]));
    // A fork whose inherited opening predates the start; and no stamped line.
    for first_line in [Some(STARTED - 60 * SECOND), None] {
        let mut item = claude_item("s", &[first(), later()]);
        item.claude_route_evidence = Some(Box::new(ClaudeRouteEvidence {
            first_line_ns: first_line,
            ..ClaudeRouteEvidence::default()
        }));
        missing(item);
    }
    // A clean session that began after the start.
    assert_eq!(
        claude_route(Some(LoginCandidate::Oauth), &[first(), later()]),
        known("subscription", "evaluator_snapshot")
    );
}

const TRANSCRIPT_SESSION: &str = "11111111-1111-4111-8111-111111111111";

fn user_line(at_ns: i64) -> String {
    json!({
        "type": "user",
        "sessionId": TRANSCRIPT_SESSION,
        "timestamp": at(at_ns),
        "message": {"role": "user", "content": "x"},
    })
    .to_string()
}

fn assistant_line(at_ns: i64, id: &str, output_tokens: u64) -> String {
    json!({
        "type": "assistant",
        "sessionId": TRANSCRIPT_SESSION,
        "timestamp": at(at_ns),
        "entrypoint": "claude-desktop",
        "requestId": format!("req_{id}"),
        "message": {
            "id": format!("msg_{id}"),
            "role": "assistant",
            "model": "claude-opus-4-7",
            "usage": {"input_tokens": 1, "output_tokens": output_tokens},
        },
    })
    .to_string()
}

/// The route of real transcript bytes through the parser, the resolver and
/// capture, the parse-path producer on. The process started at `start`; the
/// OAuth evaluator changed then and was observed 59 s later. Times follow
/// the wall clock so the fixture file's birth never marks them copied.
fn transcript_route(name: &str, start: i64, bytes: &[u8]) -> Value {
    let path = std::env::temp_dir().join(format!(
        "billing-route-{name}-{}-{start}.jsonl",
        std::process::id()
    ));
    std::fs::write(&path, bytes).unwrap();
    let parsed = with_test_producer(|| {
        crate::snapshots::parse_claude_code_jsonl_file(&path, &at(start), "fixture".to_string())
    });
    std::fs::remove_file(&path).ok();
    let mut items = parsed.expect("parse");
    assert_eq!(items.len(), 1);
    let context = RouteContext {
        emit: true,
        process_started_ns: start,
        claude_login: Some(ClaudeLogin {
            candidate: LoginCandidate::Oauth,
            changed_ns: start,
            observed_ns: start + 59 * SECOND,
        }),
    };
    let mut latches = Latches::new();
    apply_session_billing_routes(
        &mut latches,
        DEST,
        SnapshotSource::ClaudeCode,
        MACHINE,
        &mut items,
        &context,
    );
    route(&items[0])
}

/// The process start for a transcript fixture: whole seconds, after now.
fn transcript_start() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp() + 120) * SECOND
}

/// An opening line that fails to decode (oversized or not) hides the
/// session's first response and earliest time: the proof is invalid, and
/// the next request, now response 0, names nothing.
#[test]
fn undecodable_opening_line_invalidates_the_route_proof() {
    let t = transcript_start();
    let tail = format!(
        "{}\n{}\n",
        user_line(t + SECOND),
        assistant_line(t + 2 * SECOND, "1", 1)
    );
    let opening = assistant_line(t - 60 * SECOND, "0", 1);
    let truncated = &opening[..opening.len() - 1];
    for padding in [16 * 1024 * 1024 + 1, 0] {
        let mut bytes = format!("{truncated},\"pad\":\"").into_bytes();
        bytes.resize(bytes.len() + padding, b'x');
        bytes.extend_from_slice(b"\"\n");
        bytes.extend_from_slice(tail.as_bytes());
        assert_eq!(
            transcript_route("malformed-opening", t, &bytes),
            unknown("first_request_snapshot_missing"),
            "padding {padding}"
        );
    }
    // The same session without the opening names its route.
    assert_eq!(
        transcript_route("clean", t, tail.as_bytes()),
        known("subscription", "evaluator_snapshot")
    );
}

/// A first response the resolver cannot settle (its output regresses) is
/// skipped before the first own response is observed; it still precedes
/// the next response, so the proof is invalid.
#[test]
fn unresolved_earlier_response_invalidates_the_route_proof() {
    let t = transcript_start();
    let lines = [
        user_line(t + SECOND),
        assistant_line(t + 2 * SECOND, "0", 2),
        assistant_line(t + 3 * SECOND, "0", 1),
        user_line(t + 4 * SECOND),
        assistant_line(t + 5 * SECOND, "1", 1),
    ];
    let bytes = lines.map(|line| line + "\n").concat();
    assert_eq!(
        transcript_route("unresolved-first", t, bytes.as_bytes()),
        unknown("first_request_snapshot_missing")
    );
}

/// The evaluator changed after the request started: that request has no
/// proven snapshot, so it never names a route.
#[test]
fn evaluator_changed_after_request_start_never_labels_it() {
    let changed_mid_request = with_login(Some(ClaudeLogin {
        candidate: LoginCandidate::Oauth,
        changed_ns: NOW - 70 * SECOND,
        observed_ns: NOW,
    }));
    let mut latches = Latches::new();
    let first = || desktop("req_1", "msg_1", NOW - 90 * SECOND, NOW - 60 * SECOND);
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[first()]),
        &changed_mid_request,
    );
    assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
    // A later request the same evaluation spans never stands in for it.
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item(
            "s",
            &[
                first(),
                desktop("req_2", "msg_2", NOW - 50 * SECOND, NOW - 40 * SECOND),
            ],
        ),
        &changed_mid_request,
    );
    assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
}

/// An evaluation observed before the request ended defers it: no object and
/// no latch until a later status refresh covers it.
#[test]
fn evaluation_observed_before_request_end_defers() {
    let stale = with_login(Some(ClaudeLogin {
        candidate: LoginCandidate::ApiKey,
        changed_ns: STARTED,
        observed_ns: NOW - 70 * SECOND,
    }));
    let mut latches = Latches::new();
    let first = || desktop("req_1", "msg_1", NOW - 90 * SECOND, NOW - 60 * SECOND);
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[first()]),
        &stale,
    );
    assert!(item.session_billing_route.is_none());
    assert!(latches.is_empty());
    // The refresh after the request found OAuth, changed after the request
    // started: unknown, never the stale API key's direct_api.
    let refreshed = with_login(Some(next_login(
        stale.claude_login,
        LoginCandidate::Oauth,
        NOW - 30 * SECOND,
        NOW - 29 * SECOND,
    )));
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[first()]),
        &refreshed,
    );
    assert_eq!(route(&item), unknown("first_request_snapshot_missing"));
}

/// A real login switch after the first route is latched joins routes_seen;
/// the first route stays.
#[test]
fn later_login_switch_joins_routes_seen() {
    let mut latches = Latches::new();
    let api = context(Some(LoginCandidate::ApiKey));
    let first = || req("req_1", "msg_1");
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[first()]),
        &api,
    );
    assert_eq!(route(&item), known("direct_api", "evaluator_snapshot"));
    let oauth = with_login(Some(next_login(
        api.claude_login,
        LoginCandidate::Oauth,
        NOW + 10 * SECOND,
        NOW + 11 * SECOND,
    )));
    let later = desktop("req_2", "msg_2", NOW + 20 * SECOND, NOW + 30 * SECOND);
    let item = apply(
        &mut latches,
        SnapshotSource::ClaudeCode,
        claude_item("s", &[first(), later]),
        &RouteContext {
            claude_login: oauth.claude_login.map(|login| ClaudeLogin {
                observed_ns: NOW + 40 * SECOND,
                ..login
            }),
            ..oauth
        },
    );
    assert_eq!(
        route(&item),
        json!({
            "first_route": "direct_api",
            "routes_seen": ["direct_api", "subscription"],
            "first_route_source": "evaluator_snapshot",
        })
    );
}

#[test]
fn login_span_extends_while_unchanged_and_restarts_on_change() {
    let api = next_login(None, LoginCandidate::ApiKey, 10, 12);
    assert_eq!((api.changed_ns, api.observed_ns), (12, 10));
    let same = next_login(Some(api), LoginCandidate::ApiKey, 300, 302);
    assert_eq!((same.changed_ns, same.observed_ns), (12, 300));
    let switched = next_login(Some(same), LoginCandidate::Oauth, 600, 602);
    assert_eq!(switched.candidate, LoginCandidate::Oauth);
    assert_eq!((switched.changed_ns, switched.observed_ns), (602, 600));
    // An evaluation that started before the published one is ignored.
    assert_eq!(
        next_login(Some(switched), LoginCandidate::ApiKey, 500, 700),
        switched
    );
}

/// Latches follow one destination at a time: annotating for another
/// destination drops the old destination's latches.
#[test]
fn destination_change_drops_latches() {
    let mut state = RouteState {
        claude_login: Some(login(LoginCandidate::Oauth)),
        process_started_ns: Some(STARTED),
        ..RouteState::default()
    };
    let item = || {
        claude_item(
            "a",
            &[desktop(
                "req_1",
                "msg_1",
                NOW - 90 * SECOND,
                NOW - 60 * SECOND,
            )],
        )
    };
    let contract = Some(SESSION_BILLING_ROUTE_CONTRACT);
    let mut items = [item()];
    state.annotate(
        DEST,
        SnapshotSource::ClaudeCode,
        MACHINE,
        &mut items,
        contract,
    );
    assert_eq!(
        route(&items[0]),
        known("subscription", "evaluator_snapshot")
    );
    assert_eq!(state.latches.len(), 1);
    let mut items = [claude_item("b", &[])];
    state.annotate(
        "other-destination",
        SnapshotSource::ClaudeCode,
        MACHINE,
        &mut items,
        contract,
    );
    assert!(state.latches.is_empty());
    assert_eq!(state.destination, "other-destination");
    // Without the contract nothing is attached, though latching runs.
    let mut items = [item()];
    state.annotate(
        "other-destination",
        SnapshotSource::ClaudeCode,
        MACHINE,
        &mut items,
        None,
    );
    assert!(items[0].session_billing_route.is_none());
    assert_eq!(state.latches.len(), 1);
    let base = route_key(DEST, SnapshotSource::ClaudeCode, MACHINE, "a");
    for other in [
        route_key("other", SnapshotSource::ClaudeCode, MACHINE, "a"),
        route_key(DEST, SnapshotSource::Pi, MACHINE, "a"),
        route_key(DEST, SnapshotSource::ClaudeCode, "other", "a"),
        route_key(DEST, SnapshotSource::ClaudeCode, MACHINE, "b"),
    ] {
        assert_ne!(base, other);
    }
}

/// Off, no route work runs: no clock read for the login, no capability copy,
/// no route state and no change to the item.
#[test]
fn off_does_no_route_work() {
    if PRODUCER_ENABLED {
        return;
    }
    assert_eq!(login_read_started(), None);
    assert_eq!(
        crate::snapshot_client::deserialize_route_contract(json!(SESSION_BILLING_ROUTE_CONTRACT))
            .unwrap(),
        None
    );
    let mut items = [claude_item(
        "s",
        &[desktop(
            "req_1",
            "msg_1",
            NOW - 90 * SECOND,
            NOW - 60 * SECOND,
        )],
    )];
    assert!(start_witness(SnapshotSource::ClaudeCode, Some((1, 2))).is_none());
    let evidence = items[0].claude_route_evidence.clone();
    let before = serde_json::to_value(&items[0]).unwrap();
    annotate_session_billing_routes(
        DEST,
        SnapshotSource::ClaudeCode,
        MACHINE,
        &mut items,
        Some(SESSION_BILLING_ROUTE_CONTRACT),
    );
    assert_eq!(items[0].claude_route_evidence, evidence);
    assert_eq!(serde_json::to_value(&items[0]).unwrap(), before);
    with_route_state(|state| {
        assert!(state.process_started_ns.is_none());
        assert!(state.claude_login.is_none());
        assert!(state.latches.is_empty());
    });
}

/// The annotation persists nothing: no `ScanIndex` field, so no state_v2
/// kind, root or presence name.
#[test]
fn annotation_persists_nothing() {
    assert!(!crate::snapshots::lenient_decode::FIELDS
        .iter()
        .any(|field| field.contains("billing") || field.contains("route")));
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
    let mut latches = Latches::new();
    route(&apply(
        &mut latches,
        source,
        rows_item(rows),
        &context(None),
    ))
}

/// A Codex or Pi item in production order: hour buckets in time order, rows
/// within an hour and the merged session rows in row-key order (auth mode
/// before provider for these rows).
fn hours_item(hours: &[&[SnapshotModelUsage]]) -> SnapshotItem {
    let keyed = |rows: &[SnapshotModelUsage]| {
        let mut rows = rows.to_vec();
        rows.sort_by(|a, b| {
            (&a.auth_mode, &a.model_provider).cmp(&(&b.auth_mode, &b.model_provider))
        });
        rows
    };
    SnapshotItem {
        source_session_id: "s".into(),
        model_usage: keyed(&hours.concat()),
        usage_buckets: hours
            .iter()
            .enumerate()
            .map(|(hour, rows)| SnapshotUsageBucket {
                bucket_start: at(NOW + hour as i64 * 3_600 * SECOND),
                model_usage: keyed(rows),
                first_activity_at: None,
                last_activity_at: None,
            })
            .collect(),
        ..SnapshotItem::default()
    }
}

fn hours_route(source: SnapshotSource, hours: &[&[SnapshotModelUsage]]) -> Value {
    route(&apply(
        &mut Latches::new(),
        source,
        hours_item(hours),
        &context(None),
    ))
}

/// The first route comes from time order, not row-key order, and never
/// becomes a different known route as rows grow; Codex and Pi keep no latch.
#[test]
fn codex_and_pi_first_route_holds_as_rows_grow() {
    use SnapshotSource::{Codex, Pi};
    let chatgpt = row(Some("openai"), Some("chatgpt"));
    let apikey = row(Some("openai"), Some("apikey"));
    let codex = "codex_auth_snapshot";
    assert_eq!(
        hours_route(Codex, &[&[chatgpt.clone()]]),
        known("subscription", codex)
    );
    // An API key in the same hour sorts first by row key: the first route is
    // unknown, never direct_api.
    assert_eq!(
        hours_route(Codex, &[&[chatgpt.clone(), apikey.clone()]]),
        unknown("signal_conflict")
    );
    // In a later hour it only joins routes_seen.
    assert_eq!(
        hours_route(Codex, &[&[chatgpt], &[apikey]]),
        json!({
            "first_route": "subscription",
            "routes_seen": ["direct_api", "subscription"],
            "first_route_source": codex,
        })
    );
    // Pi: a later provider that sorts first in the session rows.
    let vertex = row(Some("google-vertex"), Some("service_account"));
    let bedrock = row(Some("amazon-bedrock"), Some("service_account"));
    assert_eq!(
        hours_route(Pi, &[&[vertex.clone()]]),
        known("google_vertex", "pi_provider_auth")
    );
    let mut latches = Latches::new();
    let item = apply(
        &mut latches,
        Pi,
        hours_item(&[&[vertex], &[bedrock]]),
        &context(None),
    );
    assert_eq!(
        item.model_usage[0].model_provider.as_deref(),
        Some("amazon-bedrock")
    );
    assert_eq!(
        route(&item),
        json!({
            "first_route": "google_vertex",
            "routes_seen": ["amazon_bedrock", "google_vertex"],
            "first_route_source": "pi_provider_auth",
        })
    );
    assert!(latches.is_empty());
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
    // Two routes and no time order between them: unknown.
    assert_eq!(
        rows_route(
            Codex,
            vec![
                row(Some("openai"), Some("apikey")),
                row(Some("openai"), Some("chatgpt"))
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
    // Mixed: the earlier hour's route stays first; the later one joins
    // routes_seen.
    let vertex = row(Some("google-vertex"), Some("service_account"));
    let bedrock = row(Some("amazon-bedrock"), Some("service_account"));
    assert_eq!(
        hours_route(Pi, &[&[vertex], &[bedrock]]),
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
        off.snapshots[0].usage_buckets[0].model_usage = rows.clone();
        let mut on = off.clone();
        let before = serde_json::to_value(&off).unwrap();
        let fingerprint = snapshot_fingerprint(source, &off.snapshots[0]);
        let witness = snapshot_upload_body_witness(&off.snapshots[0]);

        // Off (this build's switch): nothing runs.
        if !PRODUCER_ENABLED {
            annotate_session_billing_routes(
                DEST,
                source,
                MACHINE,
                &mut off.snapshots,
                Some(SESSION_BILLING_ROUTE_CONTRACT),
            );
            assert_eq!(serde_json::to_value(&off).unwrap(), before);
        }
        // Latching without the receiver's contract adds nothing either.
        let mut latches = Latches::new();
        let silent = RouteContext {
            emit: false,
            ..context(None)
        };
        apply_session_billing_routes(
            &mut latches,
            DEST,
            source,
            MACHINE,
            &mut off.snapshots,
            &silent,
        );
        assert_eq!(serde_json::to_value(&off).unwrap(), before);
        apply_session_billing_routes(
            &mut latches,
            DEST,
            source,
            MACHINE,
            &mut on.snapshots,
            &context(None),
        );
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
}

#[test]
fn login_candidate_reads_visible_inputs_and_flags_unknown_mode() {
    use LoginCandidate as C;
    let none = |_: &str| -> Option<String> { None };
    let candidate = |layers: &[Value], oauth: bool| {
        let interactive = claude_alternative_auth_layers(layers, &none, oauth, &[], false);
        let print = claude_alternative_auth_layers(layers, &none, false, &[], false);
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
