//! Full synthetic receipts at the Claude usage-collection entry.
//! Each step runs the production usage collector with the production clock
//! function under one fixed test scan clock, then pins the complete outcome,
//! the ordered provider requests and the raw saved files the step left behind.
//! Boundary rows step the clock explicitly between collection calls.
use super::claude_selection_oracle_tests::{emit, outcome_value, OAuthGuard};
use super::*;
use crate::test_effects::{Recording, Scalar};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::PoisonError;

/// 2026-08-05T01:00:00Z. Every clock below is written relative to it.
const T: u64 = 1_785_891_600;
const TOKEN_EXPIRY: &str = "2099-01-01T00:00:00Z";
const ENDPOINT: &str = "https://api.anthropic.com/api/oauth/usage";
const SUCCEEDED: &str = "A supported Claude OAuth quota response was collected successfully.";
const REUSED: &str = "Locally cached quota evidence was reused; no provider check was made.";

// One scripted provider answer per request, consumed in request order. The
// production call site holds the shared responder lock while it calls the
// responder, so a missing answer never panics there: it is counted, answered
// with a synthetic 503, and the step fails after the collection call returns.
static SCRIPT: Mutex<VecDeque<Result<Value, u16>>> = Mutex::new(VecDeque::new());
static SCRIPT_EXHAUSTED: AtomicUsize = AtomicUsize::new(0);

fn scripted_provider(endpoint: &str) -> Result<Value, u16> {
    crate::test_effects::record(
        "provider_request",
        vec![("endpoint", Scalar::Text(endpoint.to_string()))],
    );
    let answer = SCRIPT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .pop_front();
    answer.unwrap_or_else(|| {
        SCRIPT_EXHAUSTED.fetch_add(1, SeqCst);
        Err(503)
    })
}

fn body(session: u8, weekly: u8) -> Value {
    json!({
        "five_hour": {"utilization": session, "resets_at": "2026-08-05T05:00:00Z"},
        "seven_day": {"utilization": weekly, "resets_at": "2026-08-10T00:00:00Z"}
    })
}

// Literal expected wire data, independent of the code under test.
fn window(name: &str, used: u8, observed: &str, pair: (&str, &str), fresh: bool) -> Value {
    let (seconds, started, resets) = if name == "session" {
        (18000, "2026-08-05T00:00:00Z", "2026-08-05T05:00:00Z")
    } else {
        (604800, "2026-08-03T00:00:00Z", "2026-08-10T00:00:00Z")
    };
    json!({
        "name": name, "scope": "account",
        "status": if fresh {"ok"} else {"unknown"}, "freshness": if fresh {"fresh"} else {"stale"},
        "observed_at": observed,
        "account_identifier_hash": pair.0, "organization_identifier_hash": pair.1,
        "window_seconds": seconds, "started_at": started, "started_at_basis": "assumed_duration",
        "resets_at": resets, "quota": null, "remaining": null,
        "used_percent": used, "left_percent": 100 - used
    })
}

fn windows(used: (u8, u8), observed: &str, pair: (&str, &str), fresh: bool) -> Vec<Value> {
    vec![
        window("session", used.0, observed, pair, fresh),
        window("weekly", used.1, observed, pair, fresh),
    ]
}

fn ok(windows: Vec<Value>) -> Value {
    json!({"ok": {"windows": windows, "credits": [],
        "account_weekly_not_offered": false, "account_session_not_offered": false}})
}

fn diagnostic(
    code: &str,
    severity: &str,
    message: &str,
    observed: Option<&str>,
    pair: (&str, &str),
) -> Value {
    let mut value = json!({"code": code, "severity": severity, "message": message,
        "account_identifier_hash": pair.0, "organization_identifier_hash": pair.1});
    if let Some(observed) = observed {
        value["observed_at"] = json!(observed);
    }
    value
}

fn stored(observed: u64, next: u64, windows: Vec<Value>, pair: (&str, &str)) -> Value {
    json!({"schema_version": 4, "account_identifier_hash": pair.0,
        "organization_identifier_hash": pair.1, "observed_at_epoch_seconds": observed,
        "next_refresh_after_epoch_seconds": next, "windows": windows, "credit_balances": []})
}

/// A saved file as it is on disk: absent, or present with its exact JSON.
fn absent() -> Value {
    json!({"present": false})
}

fn present(json: Value) -> Value {
    json!({"present": true, "json": json})
}

fn saved(cache: Value, schedule: Value, breaker: Value) -> Value {
    json!({"cache": cache, "schedule": schedule, "breaker": breaker})
}

fn nothing_saved() -> Value {
    saved(absent(), absent(), absent())
}

fn plain_read(at: u64) -> Value {
    present(json!({"last_plain_read_at": at, "tracked_since": at}))
}

fn step(clock: u64, caller: &str, outcome: Value, requests: usize, saved: Value) -> Value {
    json!({"clock": clock, "caller": caller,
        "outcome": outcome,
        "effects": vec![json!({"label": "provider_request", "fields": [["endpoint", ENDPOINT]]}); requests],
        "saved": saved})
}

/// Read one saved file directly, never through the eligibility readers: they
/// collapse a wrong-identity, wrong-fingerprint or unparseable file to
/// "nothing" and can migrate keys while probing.
fn raw_file(path: &Path) -> Value {
    match fs::read(path) {
        Ok(bytes) => present(
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"unparseable": String::from_utf8_lossy(&bytes)})),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => absent(),
        Err(error) => json!({"unreadable": error.to_string()}),
    }
}

/// The exact pair's three saved files.
fn saved_files(pair: (&str, &str)) -> Value {
    let mut breaker = raw_file(&claude_oauth_usage_breaker_path(pair.0, pair.1));
    // The configuration fingerprint embeds the build's user agent; pin that
    // it is the current one rather than one build's text. Any other value
    // stays verbatim, so a stale-fingerprint file differs from a removed one.
    if breaker["json"]["config_fingerprint"] == json!(claude_oauth_usage_config_fingerprint()) {
        breaker["json"]["config_fingerprint"] = json!("current");
    }
    saved(
        raw_file(&claude_oauth_usage_cache_path(pair.0, pair.1)),
        raw_file(
            &claude_oauth_usage_account_state_dir(pair.0, pair.1)
                .join(claude_credit_pools::CLAUDE_READ_SCHEDULE_FILE),
        ),
        breaker,
    )
}

/// Synthetic homes, the scripted provider and an effect recording. The
/// shared OAuth guard owns the environment, hook, call counter, caller/pass
/// and hold-state cleanup, including on unwind; this fixture only swaps in
/// the scripted responder and clears its own script. No credential is read
/// and no request leaves the test.
struct Collection {
    recording: Recording,
    oauth: OAuthGuard,
}

impl Collection {
    fn new(name: &str, answers: Vec<Result<Value, u16>>) -> Self {
        let oauth = OAuthGuard::new(&format!("collection-{name}"));
        *SCRIPT.lock().unwrap_or_else(PoisonError::into_inner) = answers.into();
        SCRIPT_EXHAUSTED.store(0, SeqCst);
        let responder: ClaudeOAuthTestResponder = scripted_provider;
        // The guard saved and cleared the previous responder and forbade
        // requests; the scripted responder answers every request instead.
        *CLAUDE_OAUTH_TEST_RESPONSE
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(responder);
        CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.store(false, SeqCst);
        Self {
            recording: Recording::start(),
            oauth,
        }
    }

    /// One collection call at `clock`: the full outcome, the provider
    /// requests it made in order, and the exact pair's saved files after it.
    fn step(
        &self,
        clock: u64,
        caller: &str,
        pair: (&str, &str),
        collect: impl FnOnce() -> ClaudeOAuthUsageOutcome,
    ) -> Value {
        let outcome = crate::scan_clock::with_clock(clock, collect);
        // Outside every lock: a request with no scripted answer fails here.
        assert_eq!(
            SCRIPT_EXHAUSTED.swap(0, SeqCst),
            0,
            "a provider request at clock {clock} had no scripted answer"
        );
        json!({"clock": clock, "caller": caller,
            "outcome": outcome_value(&outcome),
            "effects": self.recording.take(),
            "saved": saved_files(pair)})
    }

    fn provider_calls(&self) -> usize {
        CLAUDE_OAUTH_PROVIDER_CALLS.load(SeqCst) - self.oauth.calls
    }
}

impl Drop for Collection {
    fn drop(&mut self) {
        SCRIPT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        SCRIPT_EXHAUSTED.store(0, SeqCst);
    }
}

/// The production entry with the production clock function. `expires` is
/// the credential's access-token expiry metadata; the token is synthetic.
fn collect(
    pair: (&str, &str),
    caller: &ClaudeOAuthUsageCaller,
    expires: &str,
) -> ClaudeOAuthUsageOutcome {
    collect_claude_oauth_usage_with_credential(
        pair.0,
        pair.1,
        Some("synthetic-never-sent".to_string()),
        Some(expires.to_string()),
        caller,
        current_unix_seconds,
    )
}

fn slot(id: &str) -> ClaudeOAuthUsageCaller {
    ClaudeOAuthUsageCaller::RegisteredSlot(id.to_string())
}

// An unchosen setting counts as on, so the off row chooses off explicitly.
fn choose_upkeep_consent(consent: bool) {
    FileClaudeConfigSlotSettingsStore::default()
        .set_upkeep_consent(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            consent,
        )
        .unwrap();
}

mod money_equivalence_tests {
    use super::*;

    const AX: (&str, &str) = ("account-a", "org-x");

    /// [money] A due default read: one request, the success observation and
    /// diagnostic stamped by the production clock, then the next pass reuses
    /// that reading without a request.
    #[test]
    #[serial]
    fn default_due_success() {
        let collection = Collection::new("s01-due", vec![Ok(body(12, 34))]);
        let default = ClaudeOAuthUsageCaller::Default;
        let steps = [
            collection.step(T, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
            collection.step(T + 1, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
        ];
        let reading = windows((12, 34), "2026-08-05T01:00:00Z", AX, true);
        let after = saved(
            present(stored(T, T + 300, reading.clone(), AX)),
            plain_read(T),
            absent(),
        );
        emit(
            "claude_status_s01_due_success",
            json!({"pair": AX, "clocks": [T, T + 1], "callers": ["default", "default"],
                "answers": [body(12, 34)], "token_expiry": TOKEN_EXPIRY, "stored": null}),
            json!({"steps": steps, "provider_calls": collection.provider_calls()}),
            json!({"steps": [
                step(T, "default", json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some("2026-08-05T01:00:00Z"), AX)]}),
                    1, after.clone()),
                step(T + 1, "default", json!({"result": ok(reading), "diagnostics": [
                    diagnostic("claude_oauth_usage_cache_reused", "info", REUSED, Some("2026-08-05T01:00:01Z"), AX)]}),
                    0, after)],
                "provider_calls": 1}),
        );
    }

    /// [money] The next-refresh boundary: one second before it the stale
    /// reading is served without a request; at it the read is made.
    #[test]
    #[serial]
    fn due_boundary() {
        let collection = Collection::new("s01-due-boundary", vec![Ok(body(13, 35))]);
        let seed = stored(
            T - 3000,
            T,
            windows((12, 34), "2026-08-05T00:10:00Z", AX, true),
            AX,
        );
        write_claude_oauth_usage_cache(&serde_json::from_value(seed.clone()).unwrap()).unwrap();
        let default = ClaudeOAuthUsageCaller::Default;
        let steps = [
            collection.step(T - 1, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
            collection.step(T, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
        ];
        let reading = windows((13, 35), "2026-08-05T01:00:00Z", AX, true);
        emit(
            "claude_status_s01_due_boundary",
            json!({"pair": AX, "clocks": [T - 1, T], "stored": seed, "answers": [body(13, 35)]}),
            json!({"steps": steps, "provider_calls": collection.provider_calls()}),
            json!({"steps": [
                step(T - 1, "default", json!({
                    "result": ok(windows((12, 34), "2026-08-05T00:10:00Z", AX, false)),
                    "diagnostics": [diagnostic("claude_oauth_usage_cache_reused", "info", REUSED, Some("2026-08-05T00:59:59Z"), AX)]}),
                    0, saved(present(seed.clone()), absent(), absent())),
                step(T, "default", json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some("2026-08-05T01:00:00Z"), AX)]}),
                    1, saved(present(stored(T, T + 300, reading, AX)), plain_read(T), absent()))],
                "provider_calls": 1}),
        );
    }

    /// [money] The access-expiry margin: a token whose expiry is 61 seconds
    /// away is sent; at exactly the 60-second margin it is never sent.
    #[test]
    #[serial]
    fn expiry_boundary() {
        let collection = Collection::new("s01-expiry-boundary", vec![Ok(body(12, 34))]);
        let expiry = "2026-08-05T01:01:00Z";
        let ay = ("account-a", "org-y");
        let default = ClaudeOAuthUsageCaller::Default;
        let steps = [
            collection.step(T - 1, "default", ay, || collect(ay, &default, expiry)),
            collection.step(T, "default", AX, || collect(AX, &default, expiry)),
        ];
        let reading = windows((12, 34), "2026-08-05T00:59:59Z", ay, true);
        emit(
            "claude_status_s01_expiry_boundary",
            json!({"pairs": [ay, AX], "clocks": [T - 1, T], "token_expiry": expiry, "answers": [body(12, 34)]}),
            json!({"steps": steps, "provider_calls": collection.provider_calls()}),
            json!({"steps": [
                step(T - 1, "default", json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some("2026-08-05T00:59:59Z"), ay)]}),
                    1, saved(present(stored(T - 1, T + 299, reading, ay)), plain_read(T - 1), absent())),
                step(T, "default", json!({
                    "result": {"error": "Claude Code has not refreshed this login since its access token expired."},
                    "diagnostics": [diagnostic("claude_oauth_usage_check_suppressed", "info",
                        "This Claude login's access token has expired locally and Claude Code has not refreshed it yet; no provider request was made, and any served readings are last-known local readings.",
                        Some("2026-08-05T01:00:00Z"), AX)]}),
                    0, nothing_saved())],
                "provider_calls": 1}),
        );
    }

    /// [money] Three exact pairs sharing an account or an organization are
    /// read by their own callers into three separate saved readings. After
    /// the last write all three pairs' files are read again, so an earlier
    /// pair's files overwritten or shared by a later pair fail the row.
    #[test]
    #[serial]
    fn pair_callers() {
        let collection = Collection::new(
            "s05-pairs",
            vec![Ok(body(12, 34)), Ok(body(23, 45)), Ok(body(45, 56))],
        );
        let pairs = [
            ("claude_slot_a", AX, (12, 34)),
            ("claude_slot_b", ("account-a", "org-y"), (23, 45)),
            ("claude_slot_c", ("account-b", "org-x"), (45, 56)),
        ];
        let steps = pairs
            .iter()
            .enumerate()
            .map(|(offset, (id, pair, _))| {
                let caller = slot(id);
                collection.step(T + offset as u64, id, *pair, || {
                    collect(*pair, &caller, TOKEN_EXPIRY)
                })
            })
            .collect::<Vec<_>>();
        let final_files = pairs
            .iter()
            .map(|(id, pair, _)| json!({"caller": id, "pair": pair, "saved": saved_files(*pair)}))
            .collect::<Vec<_>>();
        let expected = pairs
            .iter()
            .enumerate()
            .map(|(offset, (id, pair, used))| {
                let at = T + offset as u64;
                let observed = ["2026-08-05T01:00:00Z", "2026-08-05T01:00:01Z", "2026-08-05T01:00:02Z"][offset];
                let reading = windows(*used, observed, *pair, true);
                step(at, id, json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some(observed), *pair)]}),
                    1, saved(present(stored(at, at + 300, reading, *pair)), plain_read(at), absent()))
            })
            .collect::<Vec<_>>();
        emit(
            "claude_status_s05_pair_callers",
            json!({"pairs": [["claude_slot_a", AX], ["claude_slot_b", ["account-a", "org-y"]],
                ["claude_slot_c", ["account-b", "org-x"]]], "clocks": [T, T + 1, T + 2],
                "answers": [body(12, 34), body(23, 45), body(45, 56)]}),
            json!({"steps": steps, "final_files": final_files,
                "provider_calls": collection.provider_calls()}),
            json!({"steps": expected, "final_files": [
                {"caller": "claude_slot_a", "pair": ["account-a", "org-x"], "saved": saved(
                    present(stored(T, T + 300, windows((12, 34), "2026-08-05T01:00:00Z", AX, true), AX)),
                    plain_read(T), absent())},
                {"caller": "claude_slot_b", "pair": ["account-a", "org-y"], "saved": saved(
                    present(stored(T + 1, T + 301,
                        windows((23, 45), "2026-08-05T01:00:01Z", ("account-a", "org-y"), true),
                        ("account-a", "org-y"))),
                    plain_read(T + 1), absent())},
                {"caller": "claude_slot_c", "pair": ["account-b", "org-x"], "saved": saved(
                    present(stored(T + 2, T + 302,
                        windows((45, 56), "2026-08-05T01:00:02Z", ("account-b", "org-x"), true),
                        ("account-b", "org-x"))),
                    plain_read(T + 2), absent())}],
                "provider_calls": 3}),
        );
    }

    /// [money] The managed slot makes the due request; the deferred default
    /// then serves that exact reading and makes none.
    #[test]
    #[serial]
    fn managed_due_then_deferred() {
        let collection = Collection::new("s09-managed", vec![Ok(body(12, 34))]);
        let managed = slot("claude_slot_a");
        let deferred = ClaudeOAuthUsageCaller::DefaultDeferredToSlot;
        let steps = [
            collection.step(T, "claude_slot_a", AX, || {
                collect(AX, &managed, TOKEN_EXPIRY)
            }),
            collection.step(T + 1, "deferred_default", AX, || {
                collect(AX, &deferred, TOKEN_EXPIRY)
            }),
        ];
        let reading = windows((12, 34), "2026-08-05T01:00:00Z", AX, true);
        let after = saved(
            present(stored(T, T + 300, reading.clone(), AX)),
            plain_read(T),
            absent(),
        );
        emit(
            "claude_status_s09_managed_due",
            json!({"pair": AX, "clocks": [T, T + 1], "callers": ["claude_slot_a", "deferred_default"], "answers": [body(12, 34)]}),
            json!({"steps": steps, "provider_calls": collection.provider_calls()}),
            json!({"steps": [
                step(T, "claude_slot_a", json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some("2026-08-05T01:00:00Z"), AX)]}),
                    1, after.clone()),
                step(T + 1, "deferred_default", json!({"result": ok(reading), "diagnostics": [
                    diagnostic("claude_oauth_usage_deferred_to_registered_slot", "info",
                        "This Claude account's quota is read through its registered account slot; the default Claude Code login made no provider request.", None, AX),
                    diagnostic("claude_oauth_usage_cache_reused", "info",
                        "A locally cached quota reading kept by the registered account slot was reused; no provider check was made.",
                        Some("2026-08-05T01:00:01Z"), AX)]}),
                    0, after)],
                "provider_calls": 1}),
        );
    }

    /// [money] The default's 401 holds only the default: its next attempt
    /// makes no request and has no reading to serve, the registered slot's
    /// success is collected and settled while the default's streak is kept,
    /// and the default then serves the slot's reading without a request.
    #[test]
    #[serial]
    fn auth_then_other_success() {
        let collection = Collection::new("s12-auth-other", vec![Err(401), Ok(body(12, 34))]);
        let default = ClaudeOAuthUsageCaller::Default;
        let other = slot("claude_slot_b");
        let steps = [
            collection.step(T, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
            collection.step(T + 1, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
            collection.step(T + 2, "claude_slot_b", AX, || {
                collect(AX, &other, TOKEN_EXPIRY)
            }),
            collection.step(T + 3, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
        ];
        let held = present(
            json!({"schema_version": 1, "account_identifier_hash": "account-a",
            "organization_identifier_hash": "org-x", "config_fingerprint": "current",
            "auth_failures": 0, "shape_failures": 0, "rate_limit_failures": 0,
            "opened_at_epoch_seconds": 0, "reopen_after_epoch_seconds": 0, "opened_by": "",
            "auth_callers": {"default": {"consecutive_failures": 1, "last_status": 401,
                "last_failure_at_epoch_seconds": T, "backoff_until_epoch_seconds": T + 900,
                "credential_expires_at": TOKEN_EXPIRY}},
            "last_auth_failure": {"caller": "default", "status": 401, "at_epoch_seconds": T}}),
        );
        let reading = windows((12, 34), "2026-08-05T01:00:02Z", AX, true);
        let after = saved(
            present(stored(T + 2, T + 302, reading.clone(), AX)),
            plain_read(T + 2),
            held.clone(),
        );
        emit(
            "claude_status_s12_auth_other_success",
            json!({"pair": AX, "clocks": [T, T + 1, T + 2, T + 3],
                "callers": ["default", "default", "claude_slot_b", "default"],
                "answers": [401, body(12, 34)]}),
            json!({"steps": steps, "provider_calls": collection.provider_calls()}),
            json!({"steps": [
                step(T, "default", json!({
                    "result": {"error": "Claude OAuth usage endpoint rejected the local Claude Code session."},
                    "diagnostics": [
                        diagnostic("claude_oauth_usage_auth_rejected", "warning",
                            "The Claude OAuth usage endpoint rejected the default Claude Code login credential with HTTP 401 at 2026-08-05T01:00:00Z; that credential is not retried until 2026-08-05T01:15:00Z.",
                            Some("2026-08-05T01:00:00Z"), AX),
                        diagnostic("claude_oauth_usage_check_failed", "info",
                            "The latest Claude OAuth quota request failed; any served readings remain locally cached evidence.",
                            Some("2026-08-05T01:00:00Z"), AX)]}),
                    1, saved(absent(), absent(), held.clone())),
                step(T + 1, "default", json!({
                    "result": {"error": "Claude OAuth usage is backing off after this credential was rejected."},
                    "diagnostics": [
                        diagnostic("claude_oauth_usage_auth_backoff", "info",
                            "The default Claude Code login credential was rejected with HTTP 401 at 2026-08-05T01:00:00Z; it is not retried for the next 14 minute(s).",
                            Some("2026-08-05T01:00:01Z"), AX),
                        diagnostic("claude_oauth_usage_check_suppressed", "info",
                            "The local quota breaker suppressed this provider request after this credential was rejected.",
                            Some("2026-08-05T01:00:01Z"), AX)]}),
                    0, saved(absent(), absent(), held)),
                step(T + 2, "claude_slot_b", json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some("2026-08-05T01:00:02Z"), AX)]}),
                    1, after.clone()),
                step(T + 3, "default", json!({"result": ok(reading), "diagnostics": [
                    diagnostic("claude_oauth_usage_cache_reused", "info", REUSED, Some("2026-08-05T01:00:03Z"), AX)]}),
                    0, after)],
                "provider_calls": 2}),
        );
    }

    /// [money] Reverse order: the default's success settles the pair, and the
    /// registered caller serves that reading without a second request.
    #[test]
    #[serial]
    fn reverse_success_then_cache() {
        let collection = Collection::new("s12-reverse", vec![Ok(body(12, 34))]);
        let default = ClaudeOAuthUsageCaller::Default;
        let other = slot("claude_slot_b");
        let steps = [
            collection.step(T, "default", AX, || collect(AX, &default, TOKEN_EXPIRY)),
            collection.step(T + 1, "claude_slot_b", AX, || {
                collect(AX, &other, TOKEN_EXPIRY)
            }),
        ];
        let reading = windows((12, 34), "2026-08-05T01:00:00Z", AX, true);
        let after = saved(
            present(stored(T, T + 300, reading.clone(), AX)),
            plain_read(T),
            absent(),
        );
        emit(
            "claude_status_s12_reverse_cache",
            json!({"pair": AX, "clocks": [T, T + 1], "callers": ["default", "claude_slot_b"], "answers": [body(12, 34)]}),
            json!({"steps": steps, "provider_calls": collection.provider_calls()}),
            json!({"steps": [
                step(T, "default", json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some("2026-08-05T01:00:00Z"), AX)]}),
                    1, after.clone()),
                step(T + 1, "claude_slot_b", json!({"result": ok(reading), "diagnostics": [
                    diagnostic("claude_oauth_usage_cache_reused", "info", REUSED, Some("2026-08-05T01:00:01Z"), AX)]}),
                    0, after)],
                "provider_calls": 1}),
        );
    }

    /// [money] Pass gates before any request: background refresh off without
    /// upkeep consent, and a saved-only status read with consent.
    #[test]
    #[serial]
    fn pass_gates_make_no_request() {
        let default = ClaudeOAuthUsageCaller::Default;
        for (variant, consent, saved_only, expected) in [
            (
                "background_off",
                false,
                false,
                json!({
                "result": {"error": "Claude quota for this account has no stored reading, and background limit refresh is off; use Refresh limits to read it now."},
                "diagnostics": [diagnostic("claude_oauth_usage_check_suppressed", "info",
                    "Background limit refresh is off: no provider request was made, and any served readings are last-known local readings.",
                    Some("2026-08-05T01:00:00Z"), AX)]}),
            ),
            (
                "saved_only",
                true,
                true,
                json!({
                "result": {"error": "Claude quota for this account has no stored reading yet; the daemon reads it shortly."},
                "diagnostics": [diagnostic("claude_oauth_usage_cache_reused", "info",
                    "A status read served the stored quota reading; the daemon's own schedule makes the provider requests.",
                    Some("2026-08-05T01:00:00Z"), AX)]}),
            ),
        ] {
            let collection = Collection::new(&format!("s26-{variant}"), vec![]);
            choose_upkeep_consent(consent);
            let steps = [collection.step(T, "default", AX, || {
                with_claude_pass(saved_only, T, || collect(AX, &default, TOKEN_EXPIRY))
            })];
            emit(
                &format!("claude_status_s26_{variant}"),
                json!({"pair": AX, "clock": T, "pass": {"saved_only": saved_only, "started_at": T},
                    "upkeep_consent": consent, "answers": []}),
                json!({"steps": steps, "provider_calls": collection.provider_calls()}),
                json!({"steps": [step(T, "default", expected, 0, nothing_saved())],
                    "provider_calls": 0}),
            );
        }
    }

    /// [money] A consented background pass reads once; the next-refresh
    /// spacing is anchored at the pass start, not at the request clock.
    #[test]
    #[serial]
    fn consented_pass_anchor() {
        let collection = Collection::new("s26-consented", vec![Ok(body(12, 34))]);
        choose_upkeep_consent(true);
        let default = ClaudeOAuthUsageCaller::Default;
        let steps = [collection.step(T, "default", AX, || {
            with_claude_pass(false, T - 30, || collect(AX, &default, TOKEN_EXPIRY))
        })];
        let reading = windows((12, 34), "2026-08-05T01:00:00Z", AX, true);
        emit(
            "claude_status_s26_consented_pass",
            json!({"pair": AX, "clock": T, "pass": {"saved_only": false, "started_at": T - 30},
                "upkeep_consent": true, "answers": [body(12, 34)]}),
            json!({"steps": steps, "provider_calls": collection.provider_calls()}),
            json!({"steps": [step(T, "default", json!({"result": ok(reading.clone()), "diagnostics": [
                    diagnostic("claude_oauth_usage_check_succeeded", "info", SUCCEEDED, Some("2026-08-05T01:00:00Z"), AX)]}),
                    1, saved(present(stored(T, T + 270, reading, AX)), plain_read(T), absent()))],
                "provider_calls": 1}),
        );
    }
}
