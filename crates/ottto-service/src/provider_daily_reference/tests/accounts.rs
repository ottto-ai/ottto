//! Login reads, read identity and the `account_identity` wire field.

use super::*;
use crate::provider_daily_reference::logins::{
    codex_read_identity, read_login, LoginHomeKind, LoginSkip, ReadIdentity, LAPSE_MARGIN_SECONDS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ottto_core::CodexHomeTrust;
use serde::Serialize;
use serde_json::json;

pub(super) const USER: &str = "user-fixture-private";
/// The grant's own account scope, so v1 consent covers this login too.
pub(super) const WORKSPACE: &str = ACCOUNT_SCOPE;
const ACCESS_SECRET: &str = "access-signature-private";

/// A structurally valid Codex JWT naming `user` and `workspace`.
pub(super) fn jwt(user: Option<&str>, workspace: Option<&str>, expires_at: i64) -> String {
    let mut auth = serde_json::Map::new();
    if let Some(user) = user {
        auth.insert("chatgpt_user_id".to_string(), json!(user));
    }
    if let Some(workspace) = workspace {
        auth.insert("chatgpt_account_id".to_string(), json!(workspace));
    }
    let claims = json!({
        "iss": "https://auth.openai.com",
        "aud": ["app_fixture"],
        "exp": expires_at,
        "https://api.openai.com/auth": auth,
    });
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("json"));
    format!(
        "{}.{}.{ACCESS_SECRET}",
        encode(&json!({"alg": "RS256", "typ": "JWT"})),
        encode(&claims)
    )
}

pub(super) fn live() -> i64 {
    now().unix_timestamp() + 86_400
}

pub(super) fn expired() -> i64 {
    now().unix_timestamp() - 86_400
}

pub(super) fn expected_identity(user: &str, workspace: &str) -> AccountIdentityHashes {
    AccountIdentityHashes {
        account_identifier_hash: ottto_core::billing_identity_hash("openai", "account", user)
            .expect("hash"),
        provider_workspace_hash: ottto_core::billing_identity_hash(
            "openai",
            "workspace",
            workspace,
        )
        .expect("hash"),
    }
}

fn identity_of(read: ReadIdentity) -> Option<Option<AccountIdentityHashes>> {
    match read {
        ReadIdentity::Unusable => None,
        ReadIdentity::Usable { identity, .. } => Some(identity),
    }
}

/// [behaviour] Identity and expiry come from the live access token; an id
/// token only cross-checks the pair, even when it has expired.
#[test]
fn read_identity_comes_from_the_access_token_and_the_id_token_only_cross_checks() {
    let access = jwt(Some(USER), Some(WORKSPACE), live());
    let pair = Some(Some(expected_identity(USER, WORKSPACE)));
    let cases = [
        (
            "no id token",
            access.clone(),
            None,
            Some(WORKSPACE),
            pair.clone(),
        ),
        (
            "expired agreeing id token",
            access.clone(),
            Some(jwt(Some(USER), Some(WORKSPACE), expired())),
            Some(WORKSPACE),
            pair.clone(),
        ),
        (
            "expired conflicting id token",
            access.clone(),
            Some(jwt(Some("user-other"), Some(WORKSPACE), expired())),
            Some(WORKSPACE),
            Some(None),
        ),
        (
            "unparseable id token",
            access.clone(),
            Some("not-a-token".to_string()),
            Some(WORKSPACE),
            Some(None),
        ),
        (
            "missing workspace claim",
            jwt(Some(USER), None, live()),
            None,
            Some(WORKSPACE),
            Some(None),
        ),
        (
            "missing user claim",
            jwt(None, Some(WORKSPACE), live()),
            None,
            Some(WORKSPACE),
            Some(None),
        ),
        (
            "header names another workspace",
            access.clone(),
            None,
            Some("ws-other"),
            Some(None),
        ),
        ("no header", access.clone(), None, None, Some(None)),
        (
            "not a token",
            "opaque-token".to_string(),
            None,
            Some(WORKSPACE),
            None,
        ),
    ];
    for (case, access, id_token, header, expected) in cases {
        assert_eq!(
            identity_of(codex_read_identity(&access, id_token.as_deref(), header)),
            expected,
            "{case}"
        );
    }
    // An access token without `exp` is unusable: its lapse cannot be checked.
    let mut no_expiry = json!({
        "iss": "https://auth.openai.com",
        "aud": "app_fixture",
        "https://api.openai.com/auth": {"chatgpt_user_id": USER, "chatgpt_account_id": WORKSPACE},
    });
    let token = |claims: &Value| {
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("json"))
        )
    };
    assert!(identity_of(codex_read_identity(
        &token(&no_expiry),
        None,
        Some(WORKSPACE)
    ))
    .is_none());
    no_expiry["exp"] = json!("tomorrow");
    assert!(identity_of(codex_read_identity(
        &token(&no_expiry),
        None,
        Some(WORKSPACE)
    ))
    .is_none());
}

/// A Codex home holding `auth` as an owner-only `auth.json`.
pub(super) fn home_with(scratch: &Path, name: &str, auth: Option<&Value>, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let home = scratch.join(name);
    fs::create_dir(&home).expect("home");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
    if let Some(auth) = auth {
        let path = home.join("auth.json");
        fs::write(&path, serde_json::to_vec(auth).expect("auth")).expect("write auth");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("auth mode");
    }
    home
}

pub(super) fn auth(access: &str, id_token: Option<&str>, account_id: &str) -> Value {
    let mut tokens = json!({"access_token": access, "account_id": account_id});
    if let Some(id_token) = id_token {
        tokens["id_token"] = json!(id_token);
    }
    json!({"tokens": tokens})
}

/// [behaviour] One secure read per home; every refusal is a closed skip and
/// a token lapsing within the margin is never used.
#[test]
fn read_login_skips_absent_unsafe_unusable_and_lapsing_sign_ins() {
    let scratch = crate::test_scratch::ScratchDir::canonical("pdr-read-login");
    let now_seconds = unix_seconds(now());
    let soon = i64::try_from(now_seconds + LAPSE_MARGIN_SECONDS).expect("time");
    let cases = [
        ("absent", None, 0o600, Some(LoginSkip::Absent)),
        (
            "group readable",
            Some(auth(
                &jwt(Some(USER), Some(WORKSPACE), live()),
                None,
                WORKSPACE,
            )),
            0o640,
            Some(LoginSkip::Unreadable),
        ),
        (
            "no access token",
            Some(json!({"tokens": {}})),
            0o600,
            Some(LoginSkip::Unusable),
        ),
        (
            "not a token",
            Some(auth("opaque-token", None, WORKSPACE)),
            0o600,
            Some(LoginSkip::Unusable),
        ),
        (
            "lapses within the margin",
            Some(auth(
                &jwt(Some(USER), Some(WORKSPACE), soon),
                None,
                WORKSPACE,
            )),
            0o600,
            Some(LoginSkip::Expired),
        ),
        (
            "live",
            Some(auth(
                &jwt(Some(USER), Some(WORKSPACE), live()),
                None,
                WORKSPACE,
            )),
            0o600,
            None,
        ),
    ];
    for (index, (case, auth, mode, expected)) in cases.into_iter().enumerate() {
        let home = home_with(&scratch, &format!("home-{index}"), auth.as_ref(), mode);
        let read = read_login(
            LoginHomeKind::Default,
            &home,
            CodexHomeTrust::ProviderDefault,
            now_seconds,
        );
        assert_eq!(read.as_ref().err().copied(), expected, "{case}");
        if let Ok(login) = read {
            assert_eq!(login.identity, Some(expected_identity(USER, WORKSPACE)));
            assert_eq!(login.credential.account_id.as_deref(), Some(WORKSPACE));
        }
    }
    let missing = scratch.join("no-such-home");
    assert_eq!(
        read_login(
            LoginHomeKind::Default,
            &missing,
            CodexHomeTrust::ProviderDefault,
            now_seconds
        )
        .err(),
        Some(LoginSkip::Absent)
    );
}

/// [behaviour] The header follows today's precedence; identity exists only
/// when the selected header is the token's workspace, so an unused
/// conflicting alias changes nothing while a conflicting selected one does.
#[test]
fn identity_follows_the_selected_header_not_an_unused_alias() {
    let scratch = crate::test_scratch::ScratchDir::canonical("pdr-header-alias");
    let access = jwt(Some(USER), Some(WORKSPACE), live());
    let selected_agrees = json!({
        "account_id": WORKSPACE,
        "tokens": {"access_token": access, "account_id": "ws-unused-alias"},
    });
    let selected_conflicts = json!({
        "account_id": "ws-selected-other",
        "tokens": {"access_token": access, "account_id": WORKSPACE},
    });
    for (case, auth, header, identified) in [
        ("selected header agrees", selected_agrees, WORKSPACE, true),
        (
            "selected header conflicts",
            selected_conflicts,
            "ws-selected-other",
            false,
        ),
    ] {
        let home = home_with(
            &scratch,
            case.replace(' ', "-").as_str(),
            Some(&auth),
            0o600,
        );
        let login = read_login(
            LoginHomeKind::Default,
            &home,
            CodexHomeTrust::ProviderDefault,
            unix_seconds(now()),
        )
        .expect("live login");
        assert_eq!(
            login.credential.account_id.as_deref(),
            Some(header),
            "{case}"
        );
        assert_eq!(
            codex_credential_from_auth(&auth),
            Some(login.credential.clone()),
            "{case}: one parse, today's precedence"
        );
        assert_eq!(login.identity.is_some(), identified, "{case}");
    }
}

/// Records the credential each request carries.
#[derive(Default)]
pub(super) struct CapturingReader {
    pub(super) payload: Value,
    pub(super) headers: RefCell<Vec<(String, Option<String>)>>,
}

impl ProviderDailyUsageReader for CapturingReader {
    fn fetch_window(
        &self,
        credential: &CodexCredential,
        _start: &str,
        _end: &str,
    ) -> Result<Value, ProviderReadError> {
        self.headers.borrow_mut().push((
            credential.access_token.clone(),
            credential.account_id.clone(),
        ));
        Ok(self.payload.clone())
    }
}

/// 120 days of one client with nine models: 1,200 rows, so two batches.
fn split_payload() -> Value {
    let (start, _) = collection_window(now());
    let first = parse_day(&start).expect("start");
    let days = (0..120)
        .map(|offset| {
            let day = first + TimeDuration::days(offset);
            json!({
                "date": format!("{:04}-{:02}-{:02}", day.year(), u8::from(day.month()), day.day()),
                "clients": [{
                    "client_id": "CODEX_WEB",
                    "credits": 1.0,
                    "text_total_tokens": 100,
                    "models": (0..9)
                        .map(|model| json!({"model": format!("gpt-fixture-{model}"), "text_total_tokens": 10}))
                        .collect::<Vec<_>>(),
                }],
            })
        })
        .collect::<Vec<_>>();
    json!({"results": days})
}

pub(super) fn set_disclosure(collector: &Collector, disclosure: &str) {
    let mut persisted: Value =
        serde_json::from_slice(&fs::read(collector.grants().path()).expect("read")).expect("json");
    persisted["grant"]["disclosure_version"] = json!(disclosure);
    fs::write(
        collector.grants().path(),
        serde_json::to_vec(&persisted).expect("encode"),
    )
    .expect("write");
}

/// [money] Live access token with an expired id token on the default home:
/// read, request and upload with the identity on every batch of the read
/// (split and empty included), under one `collected_at`; v1 sends none.
#[test]
fn a_default_home_login_with_an_expired_id_token_uploads_identified_batches() {
    let scratch = crate::test_scratch::ScratchDir::canonical("pdr-default-home-read");
    let access = jwt(Some(USER), Some(WORKSPACE), live());
    let id_token = jwt(Some(USER), Some(WORKSPACE), expired());
    let home = home_with(
        &scratch,
        "codex",
        Some(&auth(&access, Some(&id_token), WORKSPACE)),
        0o600,
    );
    let (_, window_end) = collection_window(now());
    let idle = json!({"results": [{"date": window_end}]});
    for (case, disclosure, payload, batches) in [
        ("split v2 read", DISCLOSURE_VERSION, split_payload(), 2),
        ("empty v2 read", DISCLOSURE_VERSION, idle.clone(), 1),
        ("v1 read", DISCLOSURE_VERSION_V1, idle, 1),
    ] {
        let collector = collector(&format!("default-home-{}", case.replace(' ', "-")));
        enabled(&collector);
        set_disclosure(&collector, disclosure);
        let login = read_login(
            LoginHomeKind::Default,
            &home,
            CodexHomeTrust::ProviderDefault,
            unix_seconds(now()),
        )
        .expect("expired id token never skips a live access token");
        let runtime = runtime();
        let reader = CapturingReader {
            payload,
            ..CapturingReader::default()
        };
        let transport = RecordingTransport::default();
        let cycle = collect_one(&collector, &runtime, &login, &reader, &transport, now());
        assert_eq!(cycle.outcome, CycleOutcome::Uploaded, "{case}");
        assert_eq!(
            *reader.headers.borrow(),
            vec![(access.clone(), Some(WORKSPACE.to_string()))],
            "{case}: one request with the login's own token and header"
        );
        let sent = transport.batches.borrow();
        assert_eq!(sent.len(), batches, "{case}");
        let expected = (disclosure == DISCLOSURE_VERSION)
            .then(|| serde_json::to_value(expected_identity(USER, WORKSPACE)).expect("identity"));
        for batch in sent.iter() {
            assert_eq!(batch.get("account_identity").cloned(), expected, "{case}");
            assert_eq!(batch["collected_at"], json!(timestamp(now())), "{case}");
            assert!(wire_payload_is_content_free(batch), "{case}");
        }
    }
}

/// [money] Each read's `coverage_end` is the last complete UTC day at its
/// own `collected_at`, including one second either side of UTC midnight.
#[test]
fn coverage_end_is_the_last_complete_day_at_collected_at() {
    for instant in [
        "2026-07-27T09:00:00Z",
        "2026-07-27T23:59:59Z",
        "2026-07-28T00:00:00Z",
    ] {
        let clock = OffsetDateTime::parse(instant, &Rfc3339).expect("instant");
        let collector = collector("coverage-end-invariant");
        enabled(&collector);
        let transport = RecordingTransport::default();
        let reader = StaticReader::new(json!({"results": [{"date": "2026-07-20"}]}));
        let cycle = collect_one(&collector, &runtime(), &login(), &reader, &transport, clock);
        assert_eq!(cycle.outcome, CycleOutcome::Uploaded, "{instant}");
        for batch in transport.batches.borrow().iter() {
            let collected = OffsetDateTime::parse(
                batch["collected_at"].as_str().expect("collected_at"),
                &Rfc3339,
            )
            .expect("rfc3339");
            assert_eq!(
                batch["coverage_end"],
                json!(date_string(collected - TimeDuration::days(1))),
                "{instant}"
            );
        }
    }
}

/// [behaviour] A login that lapses after it was read makes no request.
#[test]
fn a_login_lapsing_before_its_request_is_skipped_without_a_read() {
    let collector = collector("lapsed-before-request");
    enabled(&collector);
    let mut lapsing = login();
    lapsing.lapses_at = unix_seconds(now()) + 60;
    let cycle = collect_one(
        &collector,
        &runtime(),
        &lapsing,
        &ForbiddenReader,
        &ForbiddenTransport,
        now(),
    );
    assert_eq!(cycle.outcome, CycleOutcome::Deferred);
    assert!(cycle.diagnostics[0]
        .message
        .contains("codex_sign_in_expired"));
}

/// [behaviour] `account_identity` is exactly the scheme and two lowercase
/// 64-hex hashes; anything else fails the content-free check.
#[test]
fn the_account_identity_wire_field_is_content_free_only_in_its_exact_shape() {
    let mut batch = serde_json::to_value(fixture_batches().remove(0)).expect("batch");
    assert!(wire_payload_is_content_free(&batch));
    let valid = batch["account_identity"].clone();
    for (case, identity) in [
        ("null", Value::Null),
        ("not an object", json!("c".repeat(64))),
        ("wrong scheme", {
            let mut identity = valid.clone();
            identity["identity_hash_scheme"] = json!("provider-sha256:v2");
            identity
        }),
        ("uppercase", {
            let mut identity = valid.clone();
            identity["account_identifier_hash"] = json!("C".repeat(64));
            identity
        }),
        ("short", {
            let mut identity = valid.clone();
            identity["provider_workspace_hash"] = json!("d".repeat(63));
            identity
        }),
        ("raw id", {
            let mut identity = valid.clone();
            identity["provider_workspace_hash"] = json!(WORKSPACE);
            identity
        }),
        ("extra key", {
            let mut identity = valid.clone();
            identity["email"] = json!("c".repeat(64));
            identity
        }),
        ("missing key", {
            let mut identity = valid.clone();
            identity
                .as_object_mut()
                .expect("object")
                .remove("account_identifier_hash");
            identity
        }),
    ] {
        batch["account_identity"] = identity;
        assert!(!wire_payload_is_content_free(&batch), "{case}");
    }
}

/// [behaviour] Formatting a login, credential, identity or batch shows kinds
/// and counts only: no token, header, scope, installation id, fingerprint or
/// identity hash.
#[test]
fn formatted_logins_credentials_and_batches_name_no_identifier() {
    let scratch = crate::test_scratch::ScratchDir::canonical("pdr-poison-format");
    let access = jwt(Some(USER), Some(WORKSPACE), live());
    let home = home_with(
        &scratch,
        "codex",
        Some(&auth(&access, None, WORKSPACE)),
        0o600,
    );
    let login = read_login(
        LoginHomeKind::Default,
        &home,
        CodexHomeTrust::ProviderDefault,
        unix_seconds(now()),
    )
    .expect("login");
    let identity = expected_identity(USER, WORKSPACE);
    let batch = fixture_batches().remove(0);
    let forbidden = [
        ACCESS_SECRET.to_string(),
        access.clone(),
        WORKSPACE.to_string(),
        USER.to_string(),
        identity.account_identifier_hash.clone(),
        identity.provider_workspace_hash.clone(),
        INSTALLATION_ID.to_string(),
        batch.grant_scope_fingerprint.clone(),
        batch.account_fingerprint.clone(),
        "c".repeat(16),
        "d".repeat(16),
    ];
    let formatted = [
        format!("{login:?}"),
        format!("{:?}", login.credential),
        format!("{identity:?}"),
        format!("{batch:?}"),
        format!("{:?}", LoginSkip::Unreadable),
    ];
    for text in &formatted {
        for value in &forbidden {
            assert!(
                !text.contains(value.as_str()),
                "formatted output leaked a value: {text}"
            );
        }
    }
    // The wire still carries every field the upload contract needs.
    let wire = serde_json::to_value(&batch).expect("wire");
    assert_eq!(wire["installation_id"], json!(INSTALLATION_ID));
    assert_eq!(
        wire["account_fingerprint"],
        json!(batch.account_fingerprint)
    );
    assert_eq!(
        wire["account_identity"]["account_identifier_hash"],
        json!("c".repeat(64))
    );
}

fn fixture_identity() -> AccountIdentityHashes {
    AccountIdentityHashes {
        account_identifier_hash: "c".repeat(64),
        provider_workspace_hash: "d".repeat(64),
    }
}

fn fixture_batch(
    rows: Vec<DailyReferenceRow>,
    account_identity: Option<AccountIdentityHashes>,
    provider_data_refreshed_at: Option<&str>,
) -> DailyReferenceBatch {
    DailyReferenceBatch {
        schema_version: SCHEMA_VERSION,
        source: SOURCE,
        collector_id: COLLECTOR_ID,
        collector_version: "0.1.0".to_string(),
        installation_id: INSTALLATION_ID.to_string(),
        grant_scope_fingerprint: format!("hmac-sha256:{}", "a".repeat(64)),
        account_fingerprint: format!("hmac-sha256:{}", "b".repeat(64)),
        grant_version: 3,
        provider_day_timezone: PROVIDER_DAY_TIMEZONE,
        coverage_start: "2026-03-29".to_string(),
        coverage_end: "2026-07-26".to_string(),
        collected_at: "2026-07-27T09:00:00Z".to_string(),
        provider_data_refreshed_at: provider_data_refreshed_at.map(str::to_string),
        rows,
        account_identity,
    }
}

/// Identified, unidentified and empty identified batches, synthetic values.
fn fixture_batches() -> Vec<DailyReferenceBatch> {
    let surface = DailyReferenceRow {
        provider_day: "2026-07-26".to_string(),
        surface: Surface::CodexWeb.wire(),
        model: ALL_MODELS.to_string(),
        credits_used: Some("12.500000".to_string()),
        uncached_input_tokens: Some(1000),
        cached_input_tokens: Some(500),
        output_tokens: Some(250),
        total_tokens: Some(1750),
        thread_count: Some(3),
        turn_count: Some(9),
    };
    let model = DailyReferenceRow {
        model: "gpt-5-codex".to_string(),
        credits_used: None,
        uncached_input_tokens: None,
        cached_input_tokens: None,
        output_tokens: None,
        ..surface.clone()
    };
    vec![
        fixture_batch(
            vec![surface.clone(), model],
            Some(fixture_identity()),
            Some("2026-07-27T06:00:00Z"),
        ),
        fixture_batch(vec![surface], None, None),
        fixture_batch(Vec::new(), Some(fixture_identity()), None),
    ]
}

#[derive(Serialize)]
struct LeafType {
    path: String,
    value_type: &'static str,
}

#[derive(Serialize)]
struct LeafManifest {
    schema_version: u16,
    leaves: Vec<LeafType>,
}

fn collect_leaf_types(value: &Value, path: &str, leaves: &mut Vec<LeafType>) {
    let mut leaf = |value_type| {
        leaves.push(LeafType {
            path: path.to_string(),
            value_type,
        })
    };
    match value {
        Value::Null => leaf("null"),
        Value::Bool(_) => leaf("boolean"),
        Value::Number(_) => leaf("number"),
        Value::String(_) => leaf("string"),
        Value::Array(items) if items.is_empty() => leaf("array"),
        Value::Object(items) if items.is_empty() => leaf("object"),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_leaf_types(item, &format!("{path}[{index}]"), leaves);
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                collect_leaf_types(item, &format!("{path}.{key}"), leaves);
            }
        }
    }
}

/// [format] The producer fixture the backend vendors byte-for-byte: typed
/// identified, unidentified and empty batches, and their leaf-type manifest.
#[test]
fn identity_batches_fixture_and_leaf_manifest_match_typed_wire() {
    let batches = fixture_batches();
    for batch in &batches {
        assert!(wire_payload_is_content_free(
            &serde_json::to_value(batch).expect("batch")
        ));
    }
    let value = serde_json::to_value(&batches).expect("batches");
    let fixture = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("pretty batches")
    );
    assert_eq!(
        fixture,
        include_str!(
            "../../../../../fixtures/provider-daily-reference/provider-daily-reference-identity-batches.v1.json"
        )
    );
    let mut leaves = Vec::new();
    collect_leaf_types(&value, "$", &mut leaves);
    leaves.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = format!(
        "{}\n",
        // Through a `Value`, so keys sort like the fixture's.
        serde_json::to_string_pretty(
            &serde_json::to_value(LeafManifest {
                schema_version: 1,
                leaves,
            })
            .expect("manifest"),
        )
        .expect("pretty manifest")
    );
    assert_eq!(
        manifest,
        include_str!(
            "../../../../../fixtures/provider-daily-reference/provider-daily-reference-identity-leaf-types.v1.json"
        )
    );
}
