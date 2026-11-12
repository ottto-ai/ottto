use super::*;
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

mod accounts;

const INSTALLATION_ID: &str = "00000000-0000-4000-8000-000000000001";
const GRANT_ID: &str = "00000000-0000-4000-8000-000000000002";
const ORG_SCOPE: &str = "org-fixture-private";
const USER_SCOPE: &str = "user-fixture-private";
const ACCOUNT_SCOPE: &str = "acct-fixture-private";

fn temp_dir(name: &str) -> PathBuf {
    crate::test_scratch::unique_path(&format!("ottto-codex-daily-aggregates-{name}"))
}

/// Every store gets an explicit path, so no test reads or mutates process
/// environment and the suite runs in parallel.
fn collector(name: &str) -> Collector {
    let root = temp_dir(name);
    Collector::new(
        GrantStore::new(root.join("grant.json")),
        StateStore::new(root.join("state.json")),
        root.join(SENTINEL_FILE),
    )
}

fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-07-27T09:00:00Z", &Rfc3339).expect("fixture timestamp")
}

fn setup() -> GrantSetup {
    GrantSetup {
        installation_id: INSTALLATION_ID.to_string(),
        organization_scope: ORG_SCOPE.to_string(),
        effective_user_scope: USER_SCOPE.to_string(),
        provider_account_scope: ACCOUNT_SCOPE.to_string(),
    }
}

fn runtime() -> Runtime {
    Runtime {
        installation_id: INSTALLATION_ID.to_string(),
        provider_account_scope: ACCOUNT_SCOPE.to_string(),
    }
}

/// A live, unidentified login whose header and scope are `scope`.
fn login_with_scope(scope: &str) -> CodexLogin {
    CodexLogin {
        credential: CodexCredential {
            access_token: "fixture-access-token".to_string(),
            account_id: Some(scope.to_string()),
            account_scope: scope.to_string(),
        },
        identity: None,
        lapses_at: u64::MAX,
    }
}

fn login() -> CodexLogin {
    login_with_scope(ACCOUNT_SCOPE)
}

fn grant_response(local: &DailyReferenceGrant, status: &str, version: u64) -> GrantResponse {
    GrantResponse {
        id: GRANT_ID.to_string(),
        installation_id: INSTALLATION_ID.to_string(),
        source: SOURCE.to_string(),
        collector_id: COLLECTOR_ID.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        collector_version: compiled_release_version(),
        release_lane: RELEASE_LANE.to_string(),
        disclosure_version: DISCLOSURE_VERSION.to_string(),
        grant_scope_fingerprint: local.grant_scope_fingerprint.clone(),
        account_fingerprint: local.account_fingerprint.clone(),
        status: status.to_string(),
        grant_version: version,
        server_policy_state: ServerPolicyState::Approved,
    }
}

fn enabled(collector: &Collector) -> DailyReferenceGrant {
    let local = collector
        .grants()
        .enable(&setup(), now())
        .expect("record consent");
    collector
        .grants()
        .bind_backend_grant(&grant_response(&local, "enabled", 1), INSTALLATION_ID)
        .expect("bind backend grant")
}

/// [behaviour] A rejected cached relay token is replaced for the one auth retry;
/// a 403 evicts it for the next batch without adding a retry to that batch.
#[test]
fn relay_transport_reacquires_after_authorization_rejection() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    for rejected in [401, 403] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut uploads = Vec::new();
            for (status, body) in [
                (
                    200,
                    r#"{"token":"daily-ref-old","expires_at":"2099-01-01T00:00:00Z"}"#,
                ),
                (rejected, "{}"),
                (
                    200,
                    r#"{"token":"daily-ref-new","expires_at":"2099-01-01T00:00:00Z"}"#,
                ),
                (200, r#"{"accepted":true}"#),
                (200, r#"{"accepted":true}"#),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    headers.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                let mut body_bytes = vec![0; length];
                reader.read_exact(&mut body_bytes).unwrap();
                if headers.starts_with("POST /api/v1/provider-daily-reference/batches ") {
                    uploads.push((
                        headers,
                        serde_json::from_slice::<Value>(&body_bytes).unwrap(),
                    ));
                } else {
                    assert!(headers.starts_with(&format!(
                        "POST /api/v1/telemetry/devices/{INSTALLATION_ID}/relay-token "
                    )));
                }
                write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            uploads
        });
        let transport = RelayTransport::new(
            format!("http://{address}"),
            LocalDeviceBinding {
                device_id: INSTALLATION_ID.to_string(),
                machine_id: None,
                sources: vec![SOURCE.to_string()],
            },
            "daily-reference-device-secret".to_string(),
        );
        let batch = json!({"schema_version": SCHEMA_VERSION});
        if rejected == 403 {
            assert!(matches!(
                transport.send_batch(&batch),
                Err(UploadError::NotAdmitted(403))
            ));
        }
        assert_eq!(
            transport.send_batch(&batch).unwrap(),
            json!({"accepted": true})
        );
        assert_eq!(
            transport.send_batch(&batch).unwrap(),
            json!({"accepted": true})
        );
        let uploads = server.join().unwrap();
        assert_eq!(uploads.len(), 3);
        assert!(uploads[0].0.contains("Authorization: Bearer daily-ref-old"));
        for (headers, body) in &uploads[1..] {
            assert!(headers.contains("Authorization: Bearer daily-ref-new"));
            assert_eq!(body, &batch);
        }
        assert_eq!(uploads[0].1, batch);
    }
}

// -- fakes ------------------------------------------------------------

struct StaticReader {
    payload: Value,
    calls: Cell<usize>,
}

impl StaticReader {
    fn new(payload: Value) -> Self {
        Self {
            payload,
            calls: Cell::new(0),
        }
    }
}

impl ProviderDailyUsageReader for StaticReader {
    fn fetch_window(
        &self,
        _credential: &CodexCredential,
        _start: &str,
        _end: &str,
    ) -> Result<Value, ProviderReadError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.payload.clone())
    }
}

struct FailingReader {
    errors: RefCell<VecDeque<ProviderReadError>>,
    calls: Cell<usize>,
}

impl FailingReader {
    fn new(errors: Vec<ProviderReadError>) -> Self {
        Self {
            errors: RefCell::new(errors.into()),
            calls: Cell::new(0),
        }
    }
}

impl ProviderDailyUsageReader for FailingReader {
    fn fetch_window(
        &self,
        _credential: &CodexCredential,
        _start: &str,
        _end: &str,
    ) -> Result<Value, ProviderReadError> {
        self.calls.set(self.calls.get() + 1);
        Err(self
            .errors
            .borrow_mut()
            .pop_front()
            .unwrap_or(ProviderReadError::RateLimited))
    }
}

/// A reader that must never be called. Proves a gate ran before the network.
struct ForbiddenReader;

impl ProviderDailyUsageReader for ForbiddenReader {
    fn fetch_window(
        &self,
        _credential: &CodexCredential,
        _start: &str,
        _end: &str,
    ) -> Result<Value, ProviderReadError> {
        panic!("the provider endpoint was contacted while collection was not permitted");
    }
}

fn ack_for(batch: &Value) -> Value {
    let rows = batch["rows"].as_array().map(Vec::len).unwrap_or_default();
    json!({
        "schema_version": ACK_SCHEMA_VERSION,
        "grant_id": GRANT_ID,
        "accepted_row_count": rows,
        "stored_row_count": rows,
        "superseded_row_count": 0,
        "coverage_start": batch["coverage_start"],
        "coverage_end": batch["coverage_end"],
        "fresh_at": batch["collected_at"],
    })
}

#[derive(Default)]
struct RecordingTransport {
    batches: RefCell<Vec<Value>>,
}

impl DailyReferenceTransport for RecordingTransport {
    fn is_configured(&self) -> bool {
        true
    }

    fn send_batch(&self, batch: &Value) -> Result<Value, UploadError> {
        self.batches.borrow_mut().push(batch.clone());
        Ok(ack_for(batch))
    }
}

struct RejectingTransport {
    error: UploadError,
    calls: Cell<usize>,
}

impl RejectingTransport {
    fn new(error: UploadError) -> Self {
        Self {
            error,
            calls: Cell::new(0),
        }
    }
}

impl DailyReferenceTransport for RejectingTransport {
    fn is_configured(&self) -> bool {
        true
    }

    fn send_batch(&self, _batch: &Value) -> Result<Value, UploadError> {
        self.calls.set(self.calls.get() + 1);
        Err(self.error.clone())
    }
}

struct ForbiddenTransport;

impl DailyReferenceTransport for ForbiddenTransport {
    fn is_configured(&self) -> bool {
        true
    }

    fn send_batch(&self, _batch: &Value) -> Result<Value, UploadError> {
        panic!("a batch was uploaded while collection was not permitted");
    }
}

/// A provider payload dense with exactly the material that must never
/// cross the boundary: workspace and client labels, a thread title, a raw
/// account id, a repository path, and a prompt.
fn poisoned_payload() -> Value {
    json!({
        "data_refreshed_at": "2026-07-27T06:00:00Z",
        "workspace_name": "must-not-persist workspace",
        "account_id": "acct-must-not-persist",
        "results": [
            {
                "date": "2026-07-26",
                "totals": {"credits": 100.0, "text_total_tokens": 9_999_999},
                "clients": [
                    {
                        "client_id": "CODEX_WEB",
                        "client_label": "must-not-persist label",
                        "credits": 12.5,
                        "uncached_text_input_tokens": 1000,
                        "cached_text_input_tokens": 500,
                        "text_output_tokens": 250,
                        "text_total_tokens": 1750,
                        "threads": 3,
                        "turns": 9,
                        "models": [
                            {
                                "model": "GPT-5-Codex",
                                "credits": 0.0,
                                "text_total_tokens": 1750,
                                "threads": 3,
                                "turns": 9,
                                "title": "must-not-persist title",
                                "repository": "/Users/someone/must-not-persist-repo",
                                "prompt": "must-not-persist prompt"
                            },
                            {"model": "!!!", "text_total_tokens": 5}
                        ]
                    },
                    {
                        "client_id": "CODEX_SERVICE_EXEC",
                        "credits": 1.0,
                        "text_total_tokens": 40,
                        "threads": 1,
                        "turns": 2
                    },
                    {
                        "client_id": "SOME_NEW_SURFACE",
                        "credits": 2.0,
                        "text_total_tokens": 10
                    },
                    {
                        "client_id": "ANOTHER_NEW_SURFACE",
                        "credits": 3.0,
                        "text_total_tokens": 20
                    }
                ]
            },
            {
                "date": "2026-07-25",
                "clients": [
                    {
                        "client_id": "CODEX_DESKTOP_APP",
                        "credits": 4.0,
                        "text_output_tokens": 0,
                        "threads": 0
                    }
                ]
            }
        ]
    })
}

fn poison_strings() -> [&'static str; 9] {
    [
        "must-not-persist",
        "workspace_name",
        "client_label",
        "title",
        "repository",
        "prompt",
        "SOME_NEW_SURFACE",
        "ANOTHER_NEW_SURFACE",
        "GPT-5-Codex",
    ]
}

fn diagnostic<'a>(cycle: &'a Cycle, code: &str) -> &'a AgentStatusDiagnostic {
    cycle
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == code)
        .unwrap_or_else(|| panic!("expected diagnostic {code}"))
}

fn row_at<'a>(
    rows: &'a [DailyReferenceRow],
    day: &str,
    surface: &str,
    model: &str,
) -> Option<&'a DailyReferenceRow> {
    rows.iter()
        .find(|row| row.provider_day == day && row.surface == surface && row.model == model)
}

// -- normalization: the must-not-persist proof ------------------------

#[test]
fn no_provider_free_text_survives_into_the_uploaded_batch() {
    let (start, end) = collection_window(now());
    let normalized =
        normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
    let batch = DailyReferenceBatch {
        schema_version: SCHEMA_VERSION,
        source: SOURCE,
        collector_id: COLLECTOR_ID,
        collector_version: compiled_release_version(),
        installation_id: INSTALLATION_ID.to_string(),
        grant_scope_fingerprint: format!("hmac-sha256:{}", "a".repeat(64)),
        account_fingerprint: format!("hmac-sha256:{}", "b".repeat(64)),
        grant_version: 1,
        provider_day_timezone: PROVIDER_DAY_TIMEZONE,
        coverage_start: start,
        coverage_end: end,
        collected_at: timestamp(now()),
        provider_data_refreshed_at: normalized.provider_data_refreshed_at.clone(),
        rows: normalized.rows.clone(),
        account_identity: None,
    };
    let encoded = serde_json::to_string(&batch).expect("encode batch");
    for poison in poison_strings() {
        assert!(
            !encoded.contains(poison),
            "the uploaded batch leaked {poison}"
        );
    }
    assert!(!encoded.contains("totals"));
    assert!(!encoded.contains("acct-"));
    let payload = serde_json::to_value(&batch).expect("batch value");
    assert!(wire_payload_is_content_free(&payload));
}

#[test]
fn wire_key_sets_match_the_contract() {
    let (start, end) = collection_window(now());
    let normalized =
        normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
    let batch = DailyReferenceBatch {
        schema_version: SCHEMA_VERSION,
        source: SOURCE,
        collector_id: COLLECTOR_ID,
        collector_version: compiled_release_version(),
        installation_id: INSTALLATION_ID.to_string(),
        grant_scope_fingerprint: format!("hmac-sha256:{}", "a".repeat(64)),
        account_fingerprint: format!("hmac-sha256:{}", "b".repeat(64)),
        grant_version: 1,
        provider_day_timezone: PROVIDER_DAY_TIMEZONE,
        coverage_start: start,
        coverage_end: end,
        collected_at: timestamp(now()),
        provider_data_refreshed_at: None,
        rows: normalized.rows,
        account_identity: None,
    };
    let payload = serde_json::to_value(&batch).expect("batch value");
    let object = payload.as_object().expect("object");
    for key in object.keys() {
        assert!(
            BATCH_KEYS.contains(&key.as_str()),
            "unexpected batch key {key}"
        );
    }
    for row in payload["rows"].as_array().expect("rows") {
        for key in row.as_object().expect("row object").keys() {
            assert!(ROW_KEYS.contains(&key.as_str()), "unexpected row key {key}");
        }
    }
}

#[test]
fn an_injected_extra_key_or_free_text_value_fails_the_content_free_check() {
    let base = json!({
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "collector_id": COLLECTOR_ID,
        "collector_version": compiled_release_version(),
        "installation_id": INSTALLATION_ID,
        "grant_scope_fingerprint": format!("hmac-sha256:{}", "a".repeat(64)),
        "account_fingerprint": format!("hmac-sha256:{}", "b".repeat(64)),
        "grant_version": 1,
        "provider_day_timezone": "UTC",
        "coverage_start": "2026-07-01",
        "coverage_end": "2026-07-26",
        "collected_at": "2026-07-27T09:00:00Z",
        "rows": [{
            "provider_day": "2026-07-26",
            "surface": "codex_web",
            "model": "__all__",
            "total_tokens": 10
        }]
    });
    assert!(wire_payload_is_content_free(&base));

    let mut extra_batch_key = base.clone();
    extra_batch_key["workspace_name"] = json!("must-not-persist");
    assert!(!wire_payload_is_content_free(&extra_batch_key));

    let mut extra_row_key = base.clone();
    extra_row_key["rows"][0]["title"] = json!("must-not-persist");
    assert!(!wire_payload_is_content_free(&extra_row_key));

    let mut invented_surface = base.clone();
    invented_surface["rows"][0]["surface"] = json!("codex_future");
    assert!(!wire_payload_is_content_free(&invented_surface));

    let mut prose_model = base.clone();
    prose_model["rows"][0]["model"] = json!("a prompt that is not a slug");
    assert!(!wire_payload_is_content_free(&prose_model));

    let mut path_model = base.clone();
    path_model["rows"][0]["model"] = json!("/Users/ron/secret");
    assert!(!wire_payload_is_content_free(&path_model));

    let mut bad_fingerprint = base.clone();
    bad_fingerprint["account_fingerprint"] = json!("acct-real-account-id");
    assert!(!wire_payload_is_content_free(&bad_fingerprint));

    let mut local_day = base.clone();
    local_day["provider_day_timezone"] = json!("Asia/Jerusalem");
    assert!(!wire_payload_is_content_free(&local_day));
}

#[test]
fn absent_counters_stay_absent_and_reported_zeros_are_preserved() {
    let (start, end) = collection_window(now());
    let normalized =
        normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
    let desktop = row_at(
        &normalized.rows,
        "2026-07-25",
        "codex_desktop_app",
        "__all__",
    )
    .expect("desktop surface row");
    // The provider reported zero output tokens and zero threads. Zero is a
    // fact; it must not be confused with "not reported".
    assert_eq!(desktop.output_tokens, Some(0));
    assert_eq!(desktop.thread_count, Some(0));
    // It reported no turns at all, so the counter is absent from the wire
    // rather than sent as 0 - that would manufacture a delta.
    assert_eq!(desktop.turn_count, None);
    let encoded = serde_json::to_string(desktop).expect("encode row");
    assert!(!encoded.contains("turn_count"));
    assert!(encoded.contains("\"output_tokens\":0"));
}

#[test]
fn day_level_totals_and_models_use_the_reserved_provider_grain() {
    let payload = json!({
        "results": [{
            "date": "2026-07-26",
            "totals": {
                "credits": 7.5,
                "text_total_tokens": 1200,
                "threads": 8,
                "turns": 20
            },
            "models": [{
                "model": "GPT-5-Codex",
                "credits": 0.0,
                "text_total_tokens": 1200,
                "threads": 8,
                "turns": 20
            }],
            "clients": [{
                "client_id": "CODEX_WEB",
                "credits": 7.5,
                "text_total_tokens": 1200,
                "threads": 8,
                "turns": 20
            }]
        }]
    });

    let normalized =
        normalize_provider_window(&payload, "2026-07-01", "2026-07-26").expect("normalize");
    let total = row_at(
        &normalized.rows,
        "2026-07-26",
        PROVIDER_DAY_TOTAL_SURFACE,
        ALL_MODELS,
    )
    .expect("provider day total");
    assert_eq!(total.credits_used.as_deref(), Some("7.500000"));
    assert_eq!(total.total_tokens, Some(1200));

    let model = row_at(
        &normalized.rows,
        "2026-07-26",
        PROVIDER_DAY_TOTAL_SURFACE,
        "gpt-5-codex",
    )
    .expect("provider day model");
    assert_eq!(model.credits_used, None);
    assert_eq!(model.total_tokens, Some(1200));
    assert_eq!(normalized.day_totals_seen, 1);
    assert_eq!(normalized.day_totals_compared, 1);
    assert_eq!(normalized.day_total_mismatch_days, 0);
    assert!(normalized.day_total_mismatches.is_empty());
    assert_eq!(normalized.clients_no_model_breakdown, 0);
    assert!(!normalized.unrecognized_day_keys.contains("totals"));
    assert!(!normalized.unrecognized_day_keys.contains("models"));
}

#[test]
fn unknown_client_ids_merge_into_one_other_row_per_grain() {
    let (start, end) = collection_window(now());
    let normalized =
        normalize_provider_window(&poisoned_payload(), &start, &end).expect("normalize");
    let other_rows: Vec<_> = normalized
        .rows
        .iter()
        .filter(|row| row.surface == "other" && row.provider_day == "2026-07-26")
        .collect();
    // Two unrecognized client ids collapse onto `other`; the contract
    // rejects a duplicate (day, surface, model) grain, so they must merge.
    assert_eq!(other_rows.len(), 1);
    assert_eq!(other_rows[0].model, "__all__");
    assert_eq!(other_rows[0].credits_used.as_deref(), Some("5.000000"));
    assert_eq!(other_rows[0].total_tokens, Some(30));
    assert_eq!(normalized.dropped_model_rows, 1);
}

#[test]
fn days_outside_the_declared_window_are_dropped() {
    let payload = json!({
        "results": [
            {"date": "2026-07-26", "clients": [{"client_id": "CODEX_WEB", "credits": 1.0}]},
            {"date": "2020-01-01", "clients": [{"client_id": "CODEX_WEB", "credits": 5.0}]},
            {"date": "not-a-day", "clients": [{"client_id": "CODEX_WEB", "credits": 7.0}]},
            {"date": "2026-13-45", "clients": [{"client_id": "CODEX_WEB", "credits": 9.0}]},
            {"date": "2026-02-30", "clients": [{"client_id": "CODEX_WEB", "credits": 11.0}]}
        ]
    });
    let normalized =
        normalize_provider_window(&payload, "2026-07-01", "2026-07-26").expect("normalize");
    assert_eq!(normalized.rows.len(), 1);
    assert_eq!(normalized.rows[0].provider_day, "2026-07-26");
    assert_eq!(normalized.days_seen, 5);
    assert_eq!(normalized.days_recognized, 2);
    assert_eq!(normalized.days_out_of_window, 1);
    assert_eq!(normalized.days_missing_date, 3);
}

#[test]
fn day_totals_without_a_client_breakdown_use_the_other_surface_fallback() {
    let payload = json!({
        "results": [{
            "timestamp": "2026-07-26T00:00:00Z",
            "credits_used": 2.5,
            "total_token_count": 42,
            "threads_count": 3,
            "turns_count": 7
        }]
    });

    let normalized =
        normalize_provider_window(&payload, "2026-07-01", "2026-07-26").expect("normalize");

    assert_eq!(normalized.rows.len(), 1);
    let row = &normalized.rows[0];
    assert_eq!(row.provider_day, "2026-07-26");
    assert_eq!(row.surface, "other");
    assert_eq!(row.model, ALL_MODELS);
    assert_eq!(row.credits_used.as_deref(), Some("2.500000"));
    assert_eq!(row.total_tokens, Some(42));
    assert_eq!(row.thread_count, Some(3));
    assert_eq!(row.turn_count, Some(7));
    assert_eq!(normalized.days_no_client_breakdown, 1);
    assert_eq!(normalized.days_used_fallback, 1);
}

#[test]
fn shape_diagnostics_report_only_bounded_key_names() {
    let payload = json!({
        "results": [{
            "date": "2026-07-26",
            "future_day_field": "secret-day-value",
            "clients": [{
                "client_id": "CODEX_WEB",
                "total_tokens": 3,
                "future_client_field": "secret-client-value",
                "models": [{
                    "model": "gpt-5-codex",
                    "total_tokens": 3,
                    "future_model_field": "secret-model-value"
                }]
            }]
        }]
    });
    let normalized =
        normalize_provider_window(&payload, "2026-07-01", "2026-07-26").expect("normalize");
    let mut diagnostics = Vec::new();
    append_normalization_diagnostics(&normalized, &mut diagnostics);
    let messages = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>()
        .join(" ");

    assert!(messages.contains("future_day_field"));
    assert!(messages.contains("future_client_field"));
    assert!(messages.contains("future_model_field"));
    for secret in [
        "secret-day-value",
        "secret-client-value",
        "secret-model-value",
        "CODEX_WEB",
        "gpt-5-codex",
    ] {
        assert!(!messages.contains(secret), "diagnostic leaked {secret}");
    }
    for keys in [
        &normalized.unrecognized_day_keys,
        &normalized.unrecognized_client_keys,
        &normalized.unrecognized_model_keys,
    ] {
        assert!(keys.len() <= MAX_UNRECOGNIZED_KEYS);
        assert!(keys
            .iter()
            .all(|key| key.chars().count() <= MAX_REPORTED_KEY_CHARS));
    }
}

#[test]
fn a_counter_outside_the_contract_ceiling_reads_as_not_reported() {
    // Not a large number - a payload we have misread. Sending it would 422
    // the whole batch for every day in the window, permanently.
    let payload = json!({
        "results": [{
            "date": "2026-07-26",
            "clients": [{
                "client_id": "CODEX_WEB",
                "credits": 1.5,
                "text_total_tokens": 9_000_000_000_000_000_u64,
                "threads": 9_000_000_000_u64,
                "turns": 4
            }]
        }]
    });
    let normalized =
        normalize_provider_window(&payload, "2026-07-01", "2026-07-26").expect("normalize");
    let row = row_at(&normalized.rows, "2026-07-26", "codex_web", "__all__").expect("row");
    assert_eq!(row.total_tokens, None, "over the token ceiling");
    assert_eq!(row.thread_count, None, "over the event ceiling");
    // The counters we can represent are untouched, and an unrepresentable
    // one never becomes zero.
    assert_eq!(row.turn_count, Some(4));
    assert_eq!(row.credits_used.as_deref(), Some("1.500000"));
    let batch = serde_json::to_string(row).expect("encode");
    assert!(!batch.contains("total_tokens"));
    assert!(!batch.contains("thread_count"));
}

#[test]
fn an_unrecognizable_payload_is_a_shape_failure_not_an_empty_day() {
    // Silently uploading "no usage" for a changed payload shape would read
    // as the customer having stopped working.
    assert!(matches!(
        normalize_provider_window(&json!({"unexpected": true}), "2026-07-01", "2026-07-26"),
        Err(ProviderReadError::ResponseShape(_))
    ));
    assert!(matches!(
        normalize_provider_window(
            &json!({"results": [{"no_date_here": 1}]}),
            "2026-07-01",
            "2026-07-26"
        ),
        Err(ProviderReadError::ResponseShape(_))
    ));
}

// -- windows and batching ---------------------------------------------

#[test]
fn the_collection_window_never_reaches_the_current_utc_day() {
    let (start, end) = collection_window(now());
    assert_eq!(
        end, "2026-07-26",
        "the current UTC day is still accumulating"
    );
    assert_eq!(day_span(&start, &end), Some(LOOKBACK_DAYS));
    assert!(day_span(&start, &end).is_some_and(|span| span <= MAX_COVERAGE_DAYS));
    // Just after midnight UTC the previous day is the newest complete one.
    let midnight = OffsetDateTime::parse("2026-01-01T00:04:00Z", &Rfc3339).expect("fixture");
    let (_, end) = collection_window(midnight);
    assert_eq!(end, "2025-12-31");
}

fn rows_on(day: &str, count: usize) -> Vec<DailyReferenceRow> {
    (0..count)
        .map(|index| DailyReferenceRow {
            provider_day: day.to_string(),
            surface: "codex_web",
            model: format!("model-{index}"),
            credits_used: None,
            uncached_input_tokens: None,
            cached_input_tokens: None,
            output_tokens: None,
            total_tokens: Some(1),
            thread_count: None,
            turn_count: None,
        })
        .collect()
}

#[test]
fn an_idle_window_still_declares_its_coverage() {
    // A genuinely idle account uploads an empty batch covering the window.
    // That is complete, not missing, and the backend distinguishes the two.
    let batches = pack_batches(Vec::new(), "2026-06-01", "2026-07-10").expect("pack");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].0, "2026-06-01");
    assert_eq!(batches[0].1, "2026-07-10");
    assert!(batches[0].2.is_empty());
}

#[test]
fn a_single_day_beyond_the_row_bound_is_refused_not_truncated() {
    let rows = rows_on("2026-07-26", MAX_ROWS_PER_BATCH + 1);
    assert!(pack_batches(rows, "2026-07-26", "2026-07-26").is_err());
}

#[test]
fn batch_windows_abut_exactly_across_a_run_of_idle_days() {
    // Observed days are deliberately far apart. The backend's coverage
    // envelope is one contiguous span, and a window that neither overlaps
    // nor abuts the stored one *replaces* it - so a hole between two
    // batches would silently discard already-uploaded coverage.
    let mut rows = rows_on("2026-06-01", 600);
    rows.extend(rows_on("2026-06-20", 600));
    rows.extend(rows_on("2026-07-05", 600));
    let batches = pack_batches(rows, "2026-06-01", "2026-07-10").expect("pack");
    assert_eq!(batches.len(), 3);
    assert_eq!(batches[0].0, "2026-06-01");
    // Closed the day before the next window opens, not on the last day that
    // happened to carry rows.
    assert_eq!(batches[0].1, "2026-06-19");
    assert_eq!(batches[1].0, "2026-06-20");
    assert_eq!(batches[1].1, "2026-07-04");
    assert_eq!(batches[2].0, "2026-07-05");
    assert_eq!(batches[2].1, "2026-07-10");
    for pair in batches.windows(2) {
        assert_eq!(
            day_span(&pair[0].1, &pair[1].0),
            Some(2),
            "consecutive coverage windows must abut exactly"
        );
    }
}

// -- consent ----------------------------------------------------------

#[test]
fn the_grant_file_persists_only_fingerprints() {
    let collector = collector("grant-fingerprints");
    enabled(&collector);
    let encoded = fs::read_to_string(collector.grants().path()).expect("read persisted grant");
    assert!(!encoded.contains(INSTALLATION_ID));
    assert!(!encoded.contains(ORG_SCOPE));
    assert!(!encoded.contains(USER_SCOPE));
    assert!(!encoded.contains(ACCOUNT_SCOPE));
    assert!(encoded.contains("installation_fingerprint"));
    assert!(encoded.contains("grant_scope_fingerprint"));
    assert!(encoded.contains("account_fingerprint"));
    let grant = collector.grants().load().expect("load").expect("grant");
    assert!(is_fingerprint(&grant.account_fingerprint));
    assert!(is_fingerprint(&grant.grant_scope_fingerprint));
    assert!(is_fingerprint(&grant.installation_fingerprint));
}

#[test]
fn a_backend_grant_epoch_can_repeat_but_cannot_regress() {
    let collector = collector("epoch-advance");
    let grant = enabled(&collector);
    assert!(collector
        .grants()
        .bind_backend_grant(&grant_response(&grant, "enabled", 1), INSTALLATION_ID)
        .is_ok());
    let rebound = collector
        .grants()
        .bind_backend_grant(&grant_response(&grant, "enabled", 2), INSTALLATION_ID)
        .expect("advance epoch");
    assert_eq!(
        rebound
            .backend_binding
            .as_ref()
            .map(|binding| binding.grant_version),
        Some(2)
    );
    // A new epoch never inherits the previous epoch's evidence.
    assert_eq!(rebound.last_success_at, None);
}

#[test]
fn a_mismatched_backend_response_is_refused() {
    let collector = collector("grant-response-mismatch");
    let local = collector.grants().enable(&setup(), now()).expect("enable");
    let mut wrong_account = grant_response(&local, "enabled", 1);
    wrong_account.account_fingerprint = format!("hmac-sha256:{}", "c".repeat(64));
    assert!(collector
        .grants()
        .bind_backend_grant(&wrong_account, INSTALLATION_ID)
        .is_err());
    let mut wrong_disclosure = grant_response(&local, "enabled", 1);
    wrong_disclosure.disclosure_version = DISCLOSURE_VERSION_V1.to_string();
    assert!(collector
        .grants()
        .bind_backend_grant(&wrong_disclosure, INSTALLATION_ID)
        .is_err());
    assert!(collector
        .grants()
        .bind_backend_grant(&grant_response(&local, "enabled", 1), GRANT_ID)
        .is_err());
}

#[test]
fn runtime_readiness_fails_closed_on_every_other_axis() {
    let collector = collector("runtime-readiness-other-axes");
    let grant = enabled(&collector);
    assert!(grant_runtime_ready(&grant));

    // Server policy defaults closed.
    let mut disabled_policy = grant.clone();
    if let Some(binding) = disabled_policy.backend_binding.as_mut() {
        binding.server_policy_state = ServerPolicyState::Disabled;
    }
    assert!(!grant_runtime_ready(&disabled_policy));

    let mut rollout_off = grant.clone();
    if let Some(binding) = rollout_off.backend_binding.as_mut() {
        binding.server_policy_state = ServerPolicyState::RolloutDisabled;
    }
    assert!(!grant_runtime_ready(&rollout_off));

    let mut revoked_by_server = grant.clone();
    if let Some(binding) = revoked_by_server.backend_binding.as_mut() {
        binding.backend_revoked = true;
    }
    assert!(!grant_runtime_ready(&revoked_by_server));

    let mut unbound = grant.clone();
    unbound.backend_binding = None;
    assert!(!grant_runtime_ready(&unbound));

    let mut revoked = grant;
    revoked.status = GrantStatus::Revoked;
    assert!(!grant_runtime_ready(&revoked));
}

#[test]
fn binding_a_raced_create_never_resurrects_a_revoked_grant() {
    let collector = collector("revoked-race-bind");
    let local = collector.grants().enable(&setup(), now()).expect("enable");
    collector.grants().revoke(now()).expect("revoke");

    // The POST committed at the backend just before the local revoke. Its
    // identity is retained so the compensating DELETE has a target, but
    // consent stays withdrawn.
    let bound = collector
        .grants()
        .bind_backend_grant(&grant_response(&local, "enabled", 1), INSTALLATION_ID)
        .expect("bind raced create");

    assert_eq!(bound.status, GrantStatus::Revoked);
    assert!(!grant_runtime_ready(&bound));
    assert_eq!(
        collector.grants().grant_revoke_target().expect("target"),
        GrantRevokeTarget {
            grant_id: GRANT_ID.to_string()
        }
    );
}

#[test]
fn backend_revocation_binds_the_exact_delete_response() {
    let collector = collector("backend-revocation");
    let grant = enabled(&collector);
    collector.grants().revoke(now()).expect("revoke");

    // Wrong id, wrong status, and a regressed epoch are all refused.
    let mut wrong_id = grant_response(&grant, "revoked", 2);
    wrong_id.id = "00000000-0000-4000-8000-0000000000ff".to_string();
    assert!(collector
        .grants()
        .apply_backend_revocation(&wrong_id, INSTALLATION_ID)
        .is_err());
    assert!(collector
        .grants()
        .apply_backend_revocation(&grant_response(&grant, "enabled", 2), INSTALLATION_ID)
        .is_err());
    assert!(collector
        .grants()
        .apply_backend_revocation(&grant_response(&grant, "revoked", 0), INSTALLATION_ID)
        .is_err());
    assert!(collector
        .grants()
        .apply_backend_revocation(&grant_response(&grant, "revoked", 2), GRANT_ID)
        .is_err());

    // The backend's DELETE is idempotent, so an unchanged epoch is accepted
    // where `bind_backend_grant` would require an advance.
    let confirmed = collector
        .grants()
        .apply_backend_revocation(&grant_response(&grant, "revoked", 1), INSTALLATION_ID)
        .expect("confirm revocation");

    assert_eq!(confirmed.status, GrantStatus::Revoked);
    let binding = confirmed.backend_binding.expect("binding");
    assert!(binding.backend_revoked);
    assert_eq!(binding.grant_version, 1);
}

#[test]
fn collector_status_reports_every_stop_before_it_reports_enabled() {
    let collector = collector("collector-status");
    assert_eq!(
        collector_status(collector.grants(), false).reason_code,
        "setup_required"
    );

    collector.grants().enable(&setup(), now()).expect("enable");
    let pending = collector_status(collector.grants(), false);
    assert_eq!(pending.runtime_state, RuntimeState::ConsentRequired);
    assert_eq!(pending.reason_code, "backend_grant_reconciliation_required");
    assert!(pending.backend_create_pending);
    assert!(!pending.provider_read_permitted);

    let local = collector.grants().load().expect("load").expect("grant");
    collector
        .grants()
        .bind_backend_grant(&grant_response(&local, "enabled", 1), INSTALLATION_ID)
        .expect("bind");
    let live = collector_status(collector.grants(), false);
    assert_eq!(live.runtime_state, RuntimeState::Enabled);
    assert_eq!(live.reason_code, "enabled");
    assert!(live.provider_read_permitted);
    assert_eq!(live.schema_version, COLLECTOR_STATUS_SCHEMA_VERSION);
    assert_eq!(live.source, SOURCE);
    assert_eq!(live.collector_id, COLLECTOR_ID);

    // The local off-switch outranks a live grant.
    let switched_off = collector_status(collector.grants(), true);
    assert_eq!(switched_off.runtime_state, RuntimeState::NetworkDisabled);
    assert_eq!(switched_off.reason_code, "network_disabled");
    assert!(!switched_off.provider_read_permitted);
    assert_eq!(switched_off.grant_status, GrantStatus::Enabled);

    collector.grants().revoke(now()).expect("revoke");
    let revoked = collector_status(collector.grants(), false);
    assert_eq!(revoked.runtime_state, RuntimeState::Revoked);
    assert_eq!(revoked.reason_code, "revoked");
    assert!(!revoked.provider_read_permitted);
}

#[test]
fn health_never_resurrects_a_revoked_grant() {
    let collector = collector("revoked-health");
    enabled(&collector);
    collector.grants().revoke(now()).expect("revoke");
    collector
        .grants()
        .record_health(Some("2026-07-27T09:00:00Z"), None)
        .expect("record health");
    let grant = collector.grants().load().expect("load").expect("grant");
    assert_eq!(grant.status, GrantStatus::Revoked);
    assert_eq!(grant.last_success_at, None);
    assert!(!grant_runtime_ready(&grant));
}

// -- gates before the network -----------------------------------------

#[test]
fn absent_consent_is_silent_and_contacts_nothing() {
    let collector = collector("no-consent");
    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &ForbiddenReader,
        &ForbiddenTransport,
        now(),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Disabled);
    assert!(
        cycle.diagnostics.is_empty(),
        "absence of consent is not a fault"
    );
}

#[test]
fn an_unusable_consent_file_says_why_but_stays_disabled() {
    let collector = collector("unusable-consent");
    enabled(&collector);
    let valid = fs::read(collector.grants().path()).expect("read");
    let mut superseded: serde_json::Value = serde_json::from_slice(&valid).expect("decode");
    superseded["schema_version"] = json!("codex_daily_aggregates_grant.v0");
    let mut bad_key: serde_json::Value = serde_json::from_slice(&valid).expect("decode");
    bad_key["hmac_key_hex"] = json!("not-hex");

    for (contents, reason) in [
        (b"{\"truncated".to_vec(), "grant_file_corrupt"),
        (
            serde_json::to_vec(&superseded).expect("encode"),
            "grant_file_schema_unsupported",
        ),
        (
            serde_json::to_vec(&bad_key).expect("encode"),
            "grant_file_key_invalid",
        ),
    ] {
        fs::write(collector.grants().path(), &contents).expect("write");
        let cycle = collector.collect_account(
            &runtime(),
            &login(),
            &ForbiddenReader,
            &ForbiddenTransport,
            now(),
        );
        assert_eq!(cycle.outcome, CycleOutcome::Disabled);
        assert_eq!(cycle.diagnostics.len(), 1);
        assert_eq!(
            cycle.diagnostics[0].code,
            "codex_daily_aggregates_consent_unreadable"
        );
        assert_eq!(
            cycle.diagnostics[0].severity,
            AgentDiagnosticSeverity::Warning
        );
        assert!(
            cycle.diagnostics[0].message.contains(reason),
            "{reason}: {}",
            cycle.diagnostics[0].message
        );
        // The status contract is unchanged: an unusable file is no consent.
        let status = collector_status(collector.grants(), false);
        assert_eq!(status.runtime_state, RuntimeState::Off);
        assert_eq!(status.reason_code, "setup_required");
        assert!(!status.provider_read_permitted);
    }
}

#[test]
fn revoke_stops_collection_before_the_provider_is_contacted() {
    let collector = collector("revoked-collection");
    enabled(&collector);
    collector.grants().revoke(now()).expect("revoke");

    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &ForbiddenReader,
        &ForbiddenTransport,
        now() + TimeDuration::hours(1),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Disabled);
    assert_eq!(
        cycle.diagnostics[0].code,
        "codex_daily_aggregates_consent_not_runtime_ready"
    );
}

#[test]
fn the_sentinel_disables_collection_and_retires_local_state() {
    let collector = collector("sentinel");
    enabled(&collector);
    let transport = RecordingTransport::default();
    let reader = StaticReader::new(poisoned_payload());
    assert_eq!(
        collector
            .collect_account(&runtime(), &login(), &reader, &transport, now())
            .outcome,
        CycleOutcome::Uploaded
    );
    assert!(collector.state_path().is_file());

    fs::write(&collector.sentinel, b"disabled\n").expect("write sentinel");
    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &ForbiddenReader,
        &ForbiddenTransport,
        now() + TimeDuration::days(1),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Disabled);
    assert_eq!(
        cycle.diagnostics[0].code,
        "codex_daily_aggregates_network_disabled"
    );
    assert_eq!(cycle.diagnostics[0].severity, AgentDiagnosticSeverity::Info);
    // The switch turns the data path off, not merely the socket.
    assert!(!collector.state_path().is_file());
}

#[test]
fn an_upload_from_a_different_admitted_build_is_accepted_when_disclosure_matches() {
    let collector = collector("different-admitted-build");
    let grant = enabled(&collector);
    let mut previously_admitted = grant_response(&grant, "enabled", 2);
    previously_admitted.collector_version = if compiled_release_version() == "99.99.99" {
        "98.98.98".to_string()
    } else {
        "99.99.99".to_string()
    };
    let rebound = collector
        .grants()
        .bind_backend_grant(&previously_admitted, INSTALLATION_ID)
        .expect("bind the previously admitted build");
    assert_ne!(rebound.collector_version, compiled_release_version());
    assert_eq!(rebound.disclosure_version, DISCLOSURE_VERSION);

    // The recording transport represents backend acceptance of the
    // running build under its current admission list.
    let reader = StaticReader::new(poisoned_payload());
    let transport = RecordingTransport::default();
    let cycle = collector.collect_account(&runtime(), &login(), &reader, &transport, now());

    assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
    assert_eq!(reader.calls.get(), 1);
    assert_eq!(transport.batches.borrow().len(), 1);
    assert_eq!(
        transport.batches.borrow()[0]["collector_version"],
        compiled_release_version()
    );
}

#[test]
fn an_admitted_build_with_a_different_disclosure_is_refused() {
    let collector = collector("admitted-build-disclosure-mismatch");
    let grant = enabled(&collector);
    let mut previously_admitted = grant_response(&grant, "enabled", 2);
    previously_admitted.collector_version = if compiled_release_version() == "99.99.99" {
        "98.98.98".to_string()
    } else {
        "99.99.99".to_string()
    };
    collector
        .grants()
        .bind_backend_grant(&previously_admitted, INSTALLATION_ID)
        .expect("bind the previously admitted build");

    let mut persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(collector.grants().path()).expect("read"))
            .expect("decode");
    persisted["grant"]["disclosure_version"] =
        serde_json::Value::String("provider_daily_reference_disclosure.future".to_string());
    fs::write(
        collector.grants().path(),
        serde_json::to_vec_pretty(&persisted).expect("encode"),
    )
    .expect("write");

    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &ForbiddenReader,
        &ForbiddenTransport,
        now(),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Disabled);
    let status = collector_status(collector.grants(), false);
    assert_eq!(status.runtime_state, RuntimeState::ConsentRequired);
    assert_eq!(status.reason_code, "consent_required");
    assert!(!status.provider_read_permitted);
}

#[test]
fn a_v1_grant_is_not_silently_widened_after_an_account_switch() {
    // Regression: a live consent that stops collecting used to build this
    // warning and drop it, because the supervisor logged only non-Disabled
    // cycles. On a real Mac that read as "everything is fine, no data".
    let collector = collector("disabled-cycle-logging");
    enabled(&collector);
    let mut persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(collector.grants().path()).expect("read"))
            .expect("decode");
    persisted["grant"]["disclosure_version"] =
        serde_json::Value::String(DISCLOSURE_VERSION_V1.to_string());
    fs::write(
        collector.grants().path(),
        serde_json::to_vec_pretty(&persisted).expect("encode"),
    )
    .expect("write");
    let other_account = login_with_scope("acct-a-completely-different-account");

    let cycle = collector.collect_account(
        &runtime(),
        &other_account,
        &ForbiddenReader,
        &ForbiddenTransport,
        now(),
    );

    assert_eq!(cycle.outcome, CycleOutcome::Disabled);
    let lines = cycle_diagnostic_log_lines(&cycle.diagnostics);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("codex_daily_aggregates_account_mismatch")),
        "a v1 grant must remain confined to its original account: {lines:?}"
    );
}

#[test]
fn v2_uploads_a_different_provider_account_under_its_own_attribution() {
    let collector = collector("account-switch");
    let grant = enabled(&collector);
    let other_account = login_with_scope("acct-a-completely-different-account");
    let reader = StaticReader::new(poisoned_payload());
    let transport = RecordingTransport::default();
    let cycle = collector.collect_account(&runtime(), &other_account, &reader, &transport, now());
    assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
    let batch = &transport.batches.borrow()[0];
    assert_ne!(batch["account_fingerprint"], grant.account_fingerprint);
    let switched_fingerprint = collector
        .grants()
        .account_fingerprint_for(&other_account.credential.account_scope)
        .expect("derive")
        .expect("grant");
    assert_eq!(batch["account_fingerprint"], switched_fingerprint);
}

#[test]
fn excluded_account_is_terminal_visible_and_clearing_restores_collection() {
    let collector = collector("account-exclusion");
    enabled(&collector);
    let current_fingerprint = collector
        .grants()
        .account_fingerprint_for(ACCOUNT_SCOPE)
        .expect("derive")
        .expect("grant");
    let reader = StaticReader::new(poisoned_payload());
    let rejected = RejectingTransport::new(UploadError::AccountExcluded);

    let refused = collector.collect_account(&runtime(), &login(), &reader, &rejected, now());
    assert_eq!(refused.outcome, CycleOutcome::AccountExcluded);
    assert_eq!(rejected.calls.get(), 1);
    assert!(collector
        .grants()
        .account_is_excluded(&current_fingerprint)
        .expect("excluded"));

    let status = status_with_live_binding(
        collector.grants(),
        collector_status(collector.grants(), false),
        Some(&runtime()),
    );
    assert_eq!(status.runtime_state, RuntimeState::AccountExcluded);
    assert_eq!(status.reason_code, "account_excluded");
    assert!(!status.provider_read_permitted);
    assert_eq!(
        status.current_account_fingerprint.as_deref(),
        Some(current_fingerprint.as_str())
    );

    let blocked = collector.collect_account(
        &runtime(),
        &login(),
        &ForbiddenReader,
        &ForbiddenTransport,
        now() + TimeDuration::hours(7),
    );
    assert_eq!(blocked.outcome, CycleOutcome::AccountExcluded);

    collector
        .grants()
        .set_account_excluded(&current_fingerprint, false)
        .expect("include");
    let transport = RecordingTransport::default();
    let restored = collector.collect_account(
        &runtime(),
        &login(),
        &StaticReader::new(poisoned_payload()),
        &transport,
        now() + TimeDuration::days(1),
    );
    assert_eq!(restored.outcome, CycleOutcome::Uploaded);
}

#[test]
fn account_exclusions_survive_fresh_approval() {
    let collector = collector("account-exclusion-reapproval");
    collector
        .grants()
        .enable(&setup(), now())
        .expect("initial approval");
    let account = collector
        .grants()
        .account_fingerprint_for(ACCOUNT_SCOPE)
        .expect("derive")
        .expect("grant");
    collector
        .grants()
        .set_account_excluded(&account, true)
        .expect("exclude");

    collector
        .grants()
        .enable(&setup(), now() + TimeDuration::days(1))
        .expect("fresh approval");
    assert!(collector
        .grants()
        .account_is_excluded(&account)
        .expect("persisted exclusion"));
}

#[test]
fn a_different_installation_can_never_upload_under_this_consent() {
    let collector = collector("installation-mismatch");
    enabled(&collector);
    let other_device = Runtime {
        installation_id: "00000000-0000-4000-8000-0000000000ff".to_string(),
        provider_account_scope: ACCOUNT_SCOPE.to_string(),
    };
    let cycle = collector.collect_account(
        &other_device,
        &login(),
        &ForbiddenReader,
        &ForbiddenTransport,
        now(),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Disabled);
    assert_eq!(
        cycle.diagnostics[0].code,
        "codex_daily_aggregates_installation_mismatch"
    );
}

#[test]
fn an_unconfigured_transport_defers_before_the_provider_is_contacted() {
    let collector = collector("deferred-transport");
    enabled(&collector);
    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &ForbiddenReader,
        &DeferredTransport,
        now(),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Deferred);
    assert_eq!(cycle.diagnostics[0].code, "codex_daily_aggregates_deferred");
    assert!(cycle.diagnostics[0]
        .message
        .contains("transport_not_configured"));
}

// -- cadence ----------------------------------------------------------

#[test]
fn a_second_cycle_inside_the_cadence_window_does_nothing() {
    let collector = collector("cadence-gate");
    enabled(&collector);
    let reader = StaticReader::new(poisoned_payload());
    let transport = RecordingTransport::default();
    assert_eq!(
        collector
            .collect_account(&runtime(), &login(), &reader, &transport, now())
            .outcome,
        CycleOutcome::Uploaded
    );
    assert_eq!(reader.calls.get(), 1);
    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &reader,
        &transport,
        now() + TimeDuration::hours(1),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Noop);
    assert_eq!(reader.calls.get(), 1, "day-grain data is polled sparsely");

    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &reader,
        &transport,
        now() + TimeDuration::hours(7),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
    assert_eq!(reader.calls.get(), 2);
}

// -- circuit breaker ---------------------------------------------------

#[test]
fn failure_classes_do_not_pool_and_transients_never_count() {
    let mut state = CollectorState::default();
    state = state_after_failure(
        state,
        "identity",
        ProviderFailure::AuthRejected,
        "category",
        10,
    );
    state = state_after_failure(
        state,
        "identity",
        ProviderFailure::ResponseShape,
        "category",
        10,
    );
    state = state_after_failure(
        state,
        "identity",
        ProviderFailure::RateLimited,
        "category",
        10,
    );
    assert!(!breaker_is_open(&state, 10), "classes must not pool");

    // Transport failures and 5xx say the network or the vendor had a bad
    // moment, not that we should stop asking.
    assert_eq!(
        ProviderReadError::Transient("boom".to_string()).failure_class(),
        None
    );
    assert_eq!(
        ProviderReadError::AuthRejected(403).failure_class(),
        Some(ProviderFailure::AuthRejected)
    );
}

#[test]
fn one_clean_answer_clears_the_failure_counters() {
    let mut state = CollectorState::default();
    for _ in 0..2 {
        state = state_after_failure(
            state,
            "identity",
            ProviderFailure::AuthRejected,
            "category",
            10,
        );
    }
    assert_eq!(state.auth_failures, 2);
    let state = state_after_success(state, "identity", 20, 4, "2026-03-29", "2026-07-26");
    assert_eq!(state.auth_failures, 0);
    assert_eq!(state.reopen_after_epoch_seconds, 0);
    assert_eq!(state.last_error_category, None);
    assert_eq!(state.last_observed_row_count, Some(4));
    assert_eq!(state.last_coverage_start.as_deref(), Some("2026-03-29"));
    assert_eq!(state.last_coverage_end.as_deref(), Some("2026-07-26"));
}

#[test]
fn old_state_without_observation_fields_loads_with_defaults() {
    let state = StateStore::new(temp_dir("old-state").join("state.json"));
    let identity = "compatible-state-identity";
    fs::create_dir_all(state.path().parent().expect("state parent")).expect("create parent");
    fs::write(
        state.path(),
        serde_json::to_vec_pretty(&json!({
            "schema_version": STATE_FILE_SCHEMA_VERSION,
            "identity": identity,
            "last_fetch_epoch_seconds": 42,
            "last_success_epoch_seconds": 40,
            "auth_failures": 1,
            "shape_failures": 0,
            "rate_limit_failures": 0,
            "reopen_after_epoch_seconds": 0,
            "opened_by": "",
            "last_error_category": "provider_auth_rejected"
        }))
        .expect("encode old state"),
    )
    .expect("write old state");

    let loaded = state.load(identity);
    assert_eq!(loaded.last_fetch_epoch_seconds, 42);
    assert_eq!(loaded.last_success_epoch_seconds, 40);
    assert_eq!(loaded.auth_failures, 1);
    assert_eq!(
        loaded.last_error_category.as_deref(),
        Some("provider_auth_rejected")
    );
    assert_eq!(loaded.last_observed_row_count, None);
    assert_eq!(loaded.last_coverage_start, None);
    assert_eq!(loaded.last_coverage_end, None);
}

#[test]
fn breaker_state_is_scoped_to_the_grant_epoch_and_the_call_configuration() {
    let collector = collector("breaker-scope");
    let grant = enabled(&collector);
    let identity = state_identity(&grant, false);
    let state = state_after_failure(
        CollectorState::default(),
        &identity,
        ProviderFailure::AuthRejected,
        "provider_auth_rejected",
        10,
    );
    collector.state.save(&state).expect("save state");
    assert_eq!(collector.state.load(&identity).auth_failures, 1);
    // A re-consent, an account change, or a change to the endpoint or the
    // User-Agent reads as a clean slate rather than inheriting a verdict.
    assert_eq!(collector.state.load("another-identity").auth_failures, 0);
    assert_ne!(identity, state_identity(&grant, true));
}

#[test]
fn repeated_auth_rejections_open_the_breaker_and_stop_the_provider_call() {
    let collector = collector("breaker-through-cycles");
    enabled(&collector);
    let reader = FailingReader::new(vec![
        ProviderReadError::AuthRejected(401),
        ProviderReadError::AuthRejected(403),
        ProviderReadError::AuthRejected(403),
    ]);
    let transport = RecordingTransport::default();
    let mut clock = now();
    for (consecutive, status) in [(1, 401), (2, 403)] {
        let cycle = collector.collect_account(&runtime(), &login(), &reader, &transport, clock);
        assert_eq!(cycle.outcome, CycleOutcome::Failed);
        // Below the threshold the category is still named.
        assert_eq!(
            cycle.diagnostics[0].code,
            "codex_daily_aggregates_provider_read_failed"
        );
        assert!(cycle.diagnostics[0].message.contains(&format!(
            "category=provider_auth_rejected http_status={status} consecutive={consecutive} pause_at=3;"
        )));
        clock += TimeDuration::hours(7);
    }
    let cycle = collector.collect_account(&runtime(), &login(), &reader, &transport, clock);
    assert_eq!(cycle.outcome, CycleOutcome::CircuitOpen);
    assert_eq!(
        cycle.diagnostics[0].code,
        "codex_daily_aggregates_circuit_open"
    );
    assert_eq!(reader.calls.get(), 3);

    // While open, no request is made at all.
    clock += TimeDuration::hours(7);
    let cycle =
        collector.collect_account(&runtime(), &login(), &ForbiddenReader, &transport, clock);
    assert_eq!(cycle.outcome, CycleOutcome::CircuitOpen);
    assert!(transport.batches.borrow().is_empty());

    // The cool-down closes it.
    let cycle = collector.collect_account(
        &runtime(),
        &login(),
        &StaticReader::new(poisoned_payload()),
        &transport,
        clock + TimeDuration::hours(25),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
}

#[test]
fn a_transient_provider_failure_never_opens_the_breaker() {
    let collector = collector("transient-failures");
    enabled(&collector);
    let reader = FailingReader::new(vec![
        ProviderReadError::Transient("dns".to_string()),
        ProviderReadError::Transient("503".to_string()),
        ProviderReadError::Transient("timeout".to_string()),
        ProviderReadError::Transient("reset".to_string()),
    ]);
    let transport = RecordingTransport::default();
    let mut clock = now();
    for _ in 0..4 {
        let cycle = collector.collect_account(&runtime(), &login(), &reader, &transport, clock);
        assert_eq!(cycle.outcome, CycleOutcome::Failed);
        let message = &cycle.diagnostics[0].message;
        assert!(message.contains("category=provider_unavailable; not counted"));
        // The free-form transient detail can echo provider output.
        for detail in ["dns", "503", "timeout", "reset"] {
            assert!(!message.contains(detail), "{message}");
        }
        clock += TimeDuration::hours(7);
    }
    assert_eq!(reader.calls.get(), 4, "transients must keep being retried");
}

// -- upload ------------------------------------------------------------

#[test]
fn a_not_admitted_answer_is_typed_expected_and_never_trips_the_breaker() {
    let collector = collector("not-admitted");
    enabled(&collector);
    let reader = StaticReader::new(poisoned_payload());
    let transport = RejectingTransport::new(UploadError::NotAdmitted(403));
    let mut clock = now();
    for _ in 0..5 {
        let cycle = collector.collect_account(&runtime(), &login(), &reader, &transport, clock);
        assert_eq!(cycle.outcome, CycleOutcome::NotAdmitted);
        // Expected until a reviewed backend change admits this build, so it
        // is reported at info severity, not as a fault.
        assert_eq!(
            diagnostic(&cycle, "codex_daily_aggregates_collector_not_admitted").severity,
            AgentDiagnosticSeverity::Info
        );
        clock += TimeDuration::hours(7);
    }
    // Five refusals in a row and the provider read is still healthy.
    let state = collector.state.load(&state_identity(
        &collector.grants().load().expect("load").expect("grant"),
        false,
    ));
    assert_eq!(state.auth_failures, 0);
    assert_eq!(state.shape_failures, 0);
    assert_eq!(state.rate_limit_failures, 0);
    assert!(!breaker_is_open(&state, unix_seconds(clock)));
}

#[test]
fn a_stale_consent_epoch_stops_the_cycle_rather_than_retrying() {
    let collector = collector("epoch-conflict");
    enabled(&collector);
    let reader = StaticReader::new(poisoned_payload());
    let transport = RejectingTransport::new(UploadError::GrantEpochConflict);
    let cycle = collector.collect_account(&runtime(), &login(), &reader, &transport, now());
    assert_eq!(cycle.outcome, CycleOutcome::Failed);
    assert_eq!(transport.calls.get(), 1, "only re-consent can fix an epoch");
    let grant = collector.grants().load().expect("load").expect("grant");
    assert_eq!(
        grant.last_error_category.as_deref(),
        Some("grant_epoch_conflict")
    );
}

#[test]
fn typed_backend_account_exclusion_is_not_misclassified_as_an_epoch_conflict() {
    let error = anyhow::Error::new(
        crate::snapshot_client::ProviderDailyReferenceContractRejected {
            status: 409,
            reason:
                crate::snapshot_client::ProviderDailyReferenceContractRejection::AccountExcluded,
        },
    );
    assert_eq!(map_upload_error(&error), UploadError::AccountExcluded);
}

#[test]
fn the_uploaded_batch_declares_the_consented_epoch_and_identity() {
    let collector = collector("batch-envelope");
    let grant = enabled(&collector);
    let reader = StaticReader::new(poisoned_payload());
    let transport = RecordingTransport::default();
    assert_eq!(
        collector
            .collect_account(&runtime(), &login(), &reader, &transport, now())
            .outcome,
        CycleOutcome::Uploaded
    );
    let batches = transport.batches.borrow();
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    assert_eq!(batch["schema_version"], SCHEMA_VERSION);
    assert_eq!(batch["source"], SOURCE);
    assert_eq!(batch["collector_id"], COLLECTOR_ID);
    assert_eq!(batch["collector_version"], compiled_release_version());
    assert_eq!(batch["installation_id"], INSTALLATION_ID);
    assert_eq!(batch["provider_day_timezone"], "UTC");
    assert_eq!(batch["grant_version"], 1);
    assert_eq!(
        batch["grant_scope_fingerprint"],
        grant.grant_scope_fingerprint
    );
    assert_eq!(batch["account_fingerprint"], grant.account_fingerprint);
    assert_eq!(batch["coverage_end"], "2026-07-26");
    assert!(wire_payload_is_content_free(batch));
    let encoded = serde_json::to_string(batch).expect("encode");
    for poison in poison_strings() {
        assert!(!encoded.contains(poison), "the wire leaked {poison}");
    }
    let grant = collector.grants().load().expect("load").expect("grant");
    assert!(grant.last_success_at.is_some());
    assert_eq!(grant.last_error_category, None);
}

#[test]
fn an_acknowledgement_that_does_not_echo_the_batch_is_refused() {
    assert!(validate_ack(
        &json!({
            "schema_version": ACK_SCHEMA_VERSION,
            "grant_id": GRANT_ID,
            "accepted_row_count": 3,
            "coverage_start": "2026-07-01",
            "coverage_end": "2026-07-26",
        }),
        "2026-07-01",
        "2026-07-26"
    )
    .is_ok());
    assert!(validate_ack(
        &json!({
            "schema_version": "something_else.v1",
            "accepted_row_count": 3,
            "coverage_start": "2026-07-01",
            "coverage_end": "2026-07-26",
        }),
        "2026-07-01",
        "2026-07-26"
    )
    .is_err());
    assert!(validate_ack(
        &json!({
            "schema_version": ACK_SCHEMA_VERSION,
            "accepted_row_count": 3,
            "coverage_start": "2026-07-01",
            "coverage_end": "2026-07-20",
        }),
        "2026-07-01",
        "2026-07-26"
    )
    .is_err());
}

// -- credential --------------------------------------------------------

#[test]
fn the_account_scope_is_the_account_not_the_token() {
    let credential = codex_credential_from_auth(&json!({
        "account_id": "acct-123",
        "tokens": {"access_token": "secret-token-value"}
    }))
    .expect("credential");
    assert_eq!(credential.account_scope, "acct-123");
    assert_eq!(credential.account_id.as_deref(), Some("acct-123"));
    // A token rotation must not read as a different account and strand the
    // customer's consent.
    let rotated = codex_credential_from_auth(&json!({
        "account_id": "acct-123",
        "tokens": {"access_token": "a-completely-different-token"}
    }))
    .expect("credential");
    assert_eq!(rotated.account_scope, credential.account_scope);
    assert!(codex_credential_from_auth(&json!({"tokens": {}})).is_none());
    assert!(codex_credential_from_auth(&json!({
        "tokens": {"access_token": "   "}
    }))
    .is_none());
}

#[test]
fn the_account_scope_falls_back_to_the_id_token_claim() {
    // {"https://api.openai.com/auth":{"chatgpt_account_id":"acct-from-claim"}}
    let claim = "eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC1mcm9tLWNsYWltIn19";
    let credential = codex_credential_from_auth(&json!({
        "tokens": {"access_token": "token", "id_token": format!("header.{claim}.signature")}
    }))
    .expect("credential");
    assert_eq!(credential.account_scope, "acct-from-claim");
}

// -- posture -----------------------------------------------------------

#[test]
fn the_capability_reaches_exactly_one_provider_route() {
    assert_eq!(
        PROVIDER_ENDPOINT,
        "https://chatgpt.com/backend-api/wham/analytics/daily-workspace-usage-counts"
    );
    // Content endpoints are permanently out of scope for this capability.
    // Scan production code only, with comments stripped, so the exclusion
    // can be documented in prose without defeating its own guard.
    let source = include_str!("../provider_daily_reference.rs");
    let production = source
        .split("\nmod tests {")
        .next()
        .expect("production source");
    let code_only = production
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with('*')
        })
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "wham/tasks",
        "teleport-events",
        "/v1/sessions",
        "claude_code_shared_session_transcripts",
    ] {
        assert!(
            !code_only.contains(forbidden),
            "this module must never reference {forbidden}"
        );
    }
}

/// [format] Lost ACK/restart recovery preserves key, exclusions, epoch and health.
#[test]
fn rebind_recovers_after_server_commit_without_a_local_write() {
    for disclosure in [DISCLOSURE_VERSION, DISCLOSURE_VERSION_V1] {
        let collector = collector("rebind-crash");
        enabled(&collector);
        let excluded = collector
            .grants
            .account_fingerprint_for("excluded-account")
            .unwrap()
            .unwrap();
        collector
            .grants
            .set_account_excluded(&excluded, true)
            .unwrap();
        collector
            .grants
            .record_health(Some(&timestamp(now())), None)
            .unwrap();
        let mut original = collector.grants.read().unwrap().unwrap();
        original.grant.disclosure_version = disclosure.to_owned();
        atomic_json_write(collector.grants.path(), &original).unwrap();
        let mut target = setup();
        target.installation_id = "00000000-0000-4000-8000-000000000082".to_owned();
        let proposal = collector
            .grants
            .prepare_rebind(&target, "hardware-fixture".to_owned())
            .unwrap()
            .unwrap();
        let mut response = grant_response(&original.grant, "enabled", 1);
        response.disclosure_version = disclosure.to_owned();
        response.installation_id = target.installation_id.clone();
        response.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
        // Server commits, process dies before writing grant.json. Reopen old bytes,
        // repeat the same request, then bind the server's idempotent response.
        let reopened = GrantStore::new(collector.grants.path());
        let recovered = reopened
            .prepare_rebind(&target, "hardware-fixture".to_owned())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&proposal.request).unwrap(),
            serde_json::to_value(&recovered.request).unwrap()
        );
        let rebound = reopened
            .bind_backend_grant_with_rebind(&response, &target.installation_id, Some(&recovered))
            .unwrap();
        assert_eq!(rebound.backend_binding, original.grant.backend_binding);
        assert_eq!(
            rebound.account_fingerprint,
            original.grant.account_fingerprint
        );
        assert_eq!(rebound.disclosure_version, disclosure);
        assert_eq!(rebound.granted_at, original.grant.granted_at);
        assert_eq!(rebound.last_success_at, original.grant.last_success_at);
        let persisted = reopened.read().unwrap().unwrap();
        assert_eq!(persisted.hmac_key_hex, original.hmac_key_hex);
        assert_eq!(
            persisted.excluded_account_fingerprints,
            original.excluded_account_fingerprints
        );
        let bytes = fs::read(reopened.path()).unwrap();
        reopened
            .bind_backend_grant(&response, &target.installation_id)
            .unwrap();
        assert_eq!(fs::read(reopened.path()).unwrap(), bytes);
        assert!(reopened
            .prepare_rebind(&target, "hardware-fixture".to_owned())
            .unwrap()
            .is_none());
    }
}

/// [behaviour] A local revoke during the request wins over a committed rebind.
#[test]
fn revoked_or_disabled_daily_grants_never_rebind() {
    let collector = collector("rebind-revoked");
    let grant = enabled(&collector);
    let mut target = setup();
    target.installation_id = "00000000-0000-4000-8000-000000000083".to_owned();
    let proposal = collector
        .grants
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .unwrap();
    let mut response = grant_response(&grant, "enabled", 1);
    response.installation_id = target.installation_id.clone();
    response.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
    collector.grants.revoke(now()).unwrap();
    assert!(collector
        .grants
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .is_none());
    let retained = collector
        .grants
        .bind_backend_grant_with_rebind(&response, &target.installation_id, Some(&proposal))
        .unwrap();
    assert_eq!(retained.status, GrantStatus::Revoked);
    assert_eq!(
        retained.revoked_at.as_deref(),
        Some(timestamp(now()).as_str())
    );
    assert!(!grant_runtime_ready(&retained));
    let mut deletion = response.clone();
    deletion.status = "revoked".to_owned();
    deletion.grant_version = 2;
    collector
        .grants
        .apply_backend_revocation(&deletion, &target.installation_id)
        .unwrap();
    assert_eq!(
        collector.grants.load().unwrap().unwrap().status,
        GrantStatus::Revoked
    );
    let mut state = collector.grants.read().unwrap().unwrap();
    state.grant.status = GrantStatus::Enabled;
    let binding = state.grant.backend_binding.as_mut().unwrap();
    binding.backend_revoked = false;
    binding.server_policy_state = ServerPolicyState::Disabled;
    atomic_json_write(collector.grants.path(), &state).unwrap();
    assert!(collector
        .grants
        .prepare_rebind(&target, "fixture".to_owned())
        .unwrap()
        .is_none());
}
