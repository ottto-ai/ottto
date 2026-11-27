//! backend http for local control.

pub(crate) mod loopback_base;

use crate::control::backend_error_indicates_account_gone;
use crate::control::json;
use crate::control::redact_inline;
use crate::control::truncate_diagnostic;
use crate::control::BTreeMap;
use crate::control::BackendErrorDetails;
use crate::control::BackendErrorKind;
use crate::control::CliError;
use crate::control::CliErrorCode;
use crate::control::DeserializeOwned;
use crate::control::Duration;
use crate::control::LocalApiError;
use crate::control::RedactedValue;
use crate::control::Serialize;
use crate::control::StableMessage;
use crate::control::StdError;
use crate::control::AGENT_READ_HTTP_TIMEOUT;
use crate::control::BACKEND_REQUEST_TIMEOUT;
use crate::control::DEFAULT_API_BASE_URL;
use crate::control::DIRECT_API_BASE_URL;
use crate::control::LEGACY_API_BASE_URL;
use crate::control::TIMEZONE_OVERRIDE_UNSUPPORTED;

pub(super) fn cli_error(error: LocalApiError) -> CliError {
    let mut details = BTreeMap::new();
    let code = match &error {
        LocalApiError::Unauthorized => CliErrorCode::LocalAuthFailed,
        LocalApiError::LocalClientNotTrusted => CliErrorCode::LocalClientNotTrusted,
        LocalApiError::AccountResetRequired => CliErrorCode::AccountResetRequired,
        LocalApiError::AccountSwitchCandidate {
            current_user_email,
            new_user_email,
            new_organization_name,
            claim_code,
        } => {
            // Same wire code as AccountResetRequired so pre-switch clients keep
            // their existing reset flow; switch-aware clients read these
            // additive details to render a confirm dialog and call
            // `auth_switch_account` with the claim code.
            details.insert("switch_candidate".to_string(), RedactedValue::Bool(true));
            details.insert(
                "current_user_email".to_string(),
                RedactedValue::String(current_user_email.clone()),
            );
            details.insert(
                "new_user_email".to_string(),
                RedactedValue::String(new_user_email.clone()),
            );
            details.insert(
                "new_organization_name".to_string(),
                RedactedValue::String(new_organization_name.clone()),
            );
            details.insert(
                "claim_code".to_string(),
                RedactedValue::String(claim_code.clone()),
            );
            CliErrorCode::AccountResetRequired
        }
        LocalApiError::RepairLocked => CliErrorCode::RepairLocked,
        LocalApiError::StatePoisoned => CliErrorCode::Internal,
        LocalApiError::EmptyControlToken => CliErrorCode::InvalidRequest,
        LocalApiError::NoPendingAuthClaim | LocalApiError::AuthClaimMismatch => {
            CliErrorCode::InvalidRequest
        }
        LocalApiError::SetupRunConnectionMissing => CliErrorCode::NeedsUserAction,
        LocalApiError::SetupRunConnectionMismatch => CliErrorCode::InvalidRequest,
        LocalApiError::CloudSessionCleanupRequired => {
            details.insert(
                "reason_code".to_string(),
                RedactedValue::String("cloud_session_cleanup_required".to_string()),
            );
            CliErrorCode::NeedsUserAction
        }
        LocalApiError::IdentityMutationInProgress => {
            details.insert(
                "reason_code".to_string(),
                RedactedValue::String("identity_mutation_in_progress".to_string()),
            );
            CliErrorCode::NeedsUserAction
        }
        LocalApiError::InvalidRequest(_) | LocalApiError::RetiredCommand(_) => {
            CliErrorCode::InvalidRequest
        }
        LocalApiError::ManualFenceReviewRequired => CliErrorCode::ManualFenceReviewRequired,
        LocalApiError::LocalOperationFailed(_) => CliErrorCode::Internal,
        LocalApiError::NetworkUnavailable => CliErrorCode::NetworkUnavailable,
        LocalApiError::TimedOut(reason) => {
            details.insert("detail".to_string(), RedactedValue::String(reason.clone()));
            CliErrorCode::TimedOut
        }
        LocalApiError::Backend(backend) => {
            details.insert(
                "endpoint".to_string(),
                RedactedValue::String(backend.endpoint.clone()),
            );
            if let Some(status) = backend.status {
                details.insert("status".to_string(), RedactedValue::Number(status as i64));
            }
            if let Some(body_excerpt) = &backend.body_excerpt {
                details.insert(
                    "body_excerpt".to_string(),
                    RedactedValue::String(body_excerpt.clone()),
                );
            }
            if let Some(reason_code) = &backend.reason_code {
                details.insert(
                    "reason_code".to_string(),
                    RedactedValue::String(reason_code.clone()),
                );
            } else if backend_error_means_mac_disconnected(&error) {
                details.insert(
                    "reason_code".to_string(),
                    RedactedValue::String(MAC_DISCONNECTED_REASON_CODE.to_string()),
                );
            }
            match backend.kind {
                BackendErrorKind::Unreachable => CliErrorCode::BackendUnreachable,
                BackendErrorKind::Rejected => CliErrorCode::BackendRejected,
                BackendErrorKind::Unavailable => CliErrorCode::BackendUnavailable,
                BackendErrorKind::ResponseUnexpected => CliErrorCode::BackendResponseUnexpected,
            }
        }
    };

    let message = cli_error_message(&error);
    CliError {
        message,
        retryable: matches!(
            code,
            CliErrorCode::RepairLocked
                | CliErrorCode::Internal
                | CliErrorCode::TimedOut
                | CliErrorCode::BackendUnreachable
                | CliErrorCode::BackendUnavailable
        ),
        code,
        details,
    }
}

pub(super) fn cli_error_message(error: &LocalApiError) -> String {
    match error {
        LocalApiError::SetupRunConnectionMissing => {
            "Setup needs browser approval. Open the Ottto app from Ottto, or run setup with a fresh claim code.".to_string()
        }
        LocalApiError::TimedOut(_) => {
            if let Some(message) = agent_read_timeout_message(error) {
                return message;
            }
            "Timed out waiting for setup to complete. Open the Ottto app from Ottto and retry.".to_string()
        }
        LocalApiError::Backend(backend) => {
            let diagnostics_upload = backend.endpoint.contains("/diagnostics/");
            let logout_disconnect = backend.endpoint.contains("/local-client/disconnect");
            let body = backend
                .body_excerpt
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if body.contains("revoked_cross_account_predecessor") {
                return MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE.to_string();
            }
            if body.contains("cross-account takeover requires the exact active predecessor") {
                return "This Mac still has a live registration for another Ottto account. Complete the takeover from that live installation with its exact saved device credential, or have the prior owner revoke it before the new owner approves Replace it."
                    .to_string();
            }
            if body.contains("requires an explicit relay device") {
                return "This Mac is already registered. Choose Reconnect it in the Ottto app to use the saved device credential, or choose Replace it on the browser claim page.".to_string();
            }
            if body.contains("requires an explicit prior credential") {
                return "This Mac is already registered but its prior device credential is unavailable. Choose Replace it on the browser claim page, then retry `ottto login` or `ottto setup`.".to_string();
            }
            if body.contains("more than one active authority") {
                return "This Mac has multiple active registrations. Choose Replace it on the browser claim page to revoke them and create one fresh device, then retry `ottto login` or `ottto setup`.".to_string();
            }
            match backend.reason_code.as_deref() {
                Some("timezone_query_unsupported") => {
                    return TIMEZONE_OVERRIDE_UNSUPPORTED.to_string();
                }
                Some("machine_filter_unsupported") => {
                    return "Ottto can't filter costs to one Mac yet. Remove --machine-id: the default answer is account-wide and its by_machine rows show each Mac.".to_string();
                }
                Some("no_committed_answer") => {
                    return "Ottto has no numbers for this window yet. They are unavailable, not zero; try again later.".to_string();
                }
                Some("results_not_served") => {
                    return "Ottto could not read these numbers from its current calculation. They are unavailable, not zero; try again later.".to_string();
                }
                // Typed Results refusals: a settled answer, not a setup failure.
                Some(_) if backend.status == Some(422) => {
                    return "Ottto can't answer this read yet.".to_string();
                }
                _ => {}
            }
            // Exact backend detail for a run Ottto no longer accepts. Other
            // text that merely mentions expiry (a short-lived companion token
            // the daemon refreshes, for example) is not a dead setup run.
            if backend.status == Some(401)
                && backend.endpoint.contains("/local-client/")
                && matches!(
                    backend_error_detail(backend).as_deref(),
                    Some(SETUP_RUN_EXPIRED_DETAIL | SETUP_RUN_CANCELLED_DETAIL)
                )
            {
                return "Setup run expired. Run `ottto login` to reconnect this Mac.".to_string();
            }
            if backend.status == Some(401) || backend.status == Some(403) {
                if diagnostics_upload {
                    return "Ottto rejected the diagnostics upload. Sign in again or use a fresh support claim.".to_string();
                }
                if logout_disconnect {
                    return "Ottto rejected the cloud logout for this Mac. Sign in from the Ottto app or use `ottto logout --local-only` only to clear local state.".to_string();
                }
                if backend_error_means_mac_disconnected(error) {
                    return MAC_DISCONNECTED_MESSAGE.to_string();
                }
                return "Ottto rejected the local setup request. Open the Ottto app from Ottto to attach an active setup run.".to_string();
            }
            match backend.kind {
                BackendErrorKind::Unreachable if logout_disconnect => {
                    "Ottto is unreachable, so logout did not clear local credentials. Retry when online or use `ottto logout --local-only` only to clear local state.".to_string()
                }
                BackendErrorKind::Unreachable => "Ottto is unreachable from this Mac.".to_string(),
                BackendErrorKind::Unavailable if logout_disconnect => {
                    "Ottto is temporarily unavailable, so logout did not clear local credentials. Retry or use `ottto logout --local-only` only to clear local state.".to_string()
                }
                BackendErrorKind::Unavailable => "Ottto is temporarily unavailable.".to_string(),
                BackendErrorKind::Rejected if diagnostics_upload => {
                    "Ottto rejected the diagnostics upload.".to_string()
                }
                BackendErrorKind::Rejected if logout_disconnect => {
                    "Ottto rejected the cloud logout for this Mac. Sign in from the Ottto app or use `ottto logout --local-only` only to clear local state.".to_string()
                }
                BackendErrorKind::Rejected => "Ottto rejected the local setup request.".to_string(),
                BackendErrorKind::ResponseUnexpected if diagnostics_upload => {
                    "Ottto returned an unexpected diagnostics upload response.".to_string()
                }
                BackendErrorKind::ResponseUnexpected if logout_disconnect => {
                    "Ottto returned an unexpected logout response, so local credentials were not cleared.".to_string()
                }
                BackendErrorKind::ResponseUnexpected => {
                    "Ottto returned an unexpected setup response.".to_string()
                }
            }
        }
        _ => error.to_string(),
    }
}

/// The string `detail` of a JSON error body excerpt, if it has one.
fn backend_error_detail(backend: &BackendErrorDetails) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(backend.body_excerpt.as_deref()?).ok()?;
    value
        .get("detail")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Plain guidance when Ottto refuses this Mac because its device was revoked
/// or its account was deleted. The generic "rejected the local setup request"
/// line told the user neither what happened nor what to do.
pub(super) const MAC_DISCONNECTED_MESSAGE: &str =
    "This Mac was disconnected from its Ottto account. Sign in to connect it again.";

/// The new owner's sign-in found this Mac's revoked device from another Ottto
/// account (`revoked_cross_account_predecessor`). Replace it on the browser
/// claim page is still the step that binds it to the new account.
pub(super) const MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE: &str = "This Mac was disconnected from its earlier Ottto account. To connect it to your account, choose Replace it on the sign-in page in your browser.";

/// Typed signal for the same case in the error details, so the app and the CLI
/// act on it without matching message text.
const MAC_DISCONNECTED_REASON_CODE: &str = "mac_disconnected";

/// Exact backend `detail` strings that mean Ottto no longer accepts this Mac's
/// device or account. A compatibility path until the backend types them.
const MAC_DISCONNECTED_DETAILS: [&str; 7] = [
    "Telemetry device is not active",
    "Telemetry device is revoked",
    "Telemetry device not found",
    "Telemetry device secret is invalid",
    "Telemetry device was revoked during registration",
    "Setup run owner not found",
    "Setup run organization not found",
];

/// Ottto refused this Mac (401/403) because its device was revoked or its
/// account no longer exists. Diagnostics uploads and cloud logout keep their
/// own guidance.
fn backend_error_means_mac_disconnected(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(backend) = error else {
        return false;
    };
    if !matches!(backend.status, Some(401 | 403))
        || backend.endpoint.contains("/diagnostics/")
        || backend.endpoint.contains("/local-client/disconnect")
    {
        return false;
    }
    backend_error_indicates_account_gone(error)
        || backend_error_detail(backend)
            .is_some_and(|detail| MAC_DISCONNECTED_DETAILS.contains(&detail.as_str()))
}

const SETUP_RUN_EXPIRED_DETAIL: &str = "Setup run expired";

const SETUP_RUN_CANCELLED_DETAIL: &str = "Setup run cancelled";

/// Why a device-secret refresh can never succeed for the current binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalRefreshRejection {
    /// Ottto ended the setup run (expired or cancelled); it is never revived.
    SetupRunEnded,
    /// Ottto no longer accepts this Mac's device credential.
    DeviceRejected,
}

/// An authoritative terminal answer from `/local-client/refresh`. The backend
/// does not type these yet, so this matches its exact JSON `detail` on that
/// endpoint only (a compatibility path, never a substring). Any other 401,
/// including an unrecognized detail, and every transport failure is not proof.
pub(crate) fn terminal_refresh_rejection(
    error: &LocalApiError,
) -> Option<TerminalRefreshRejection> {
    let LocalApiError::Backend(details) = error else {
        return None;
    };
    if details.status != Some(401)
        || !details.endpoint.contains("/api/v1/setup-runs/")
        || !details.endpoint.ends_with("/local-client/refresh")
    {
        return None;
    }
    match backend_error_detail(details).as_deref()? {
        SETUP_RUN_EXPIRED_DETAIL | SETUP_RUN_CANCELLED_DETAIL => {
            Some(TerminalRefreshRejection::SetupRunEnded)
        }
        "Telemetry device is not active"
        | "Telemetry device secret is invalid"
        | "Telemetry device not found" => Some(TerminalRefreshRejection::DeviceRejected),
        _ => None,
    }
}

pub(super) fn bounded_display_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

pub(super) struct ReattachRequiredState {
    pub(super) message: StableMessage,
    pub(super) can_reconnect: bool,
}

pub(super) fn reattach_required_state(error: &LocalApiError) -> Option<ReattachRequiredState> {
    let LocalApiError::Backend(backend) = error else {
        return None;
    };
    let raw = backend.body_excerpt.as_deref().unwrap_or_default();
    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok();
    let detail = parsed.as_ref().and_then(|value| value.get("detail"));
    let detail_object = detail.and_then(serde_json::Value::as_object);
    let backend_message = detail_object
        .and_then(|object| object.get("message"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| detail.and_then(serde_json::Value::as_str))
        .unwrap_or(raw);
    let lower = backend_message.to_ascii_lowercase();
    let reason = detail_object
        .and_then(|object| object.get("reason"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            matches!(
                *value,
                "existing_authority"
                    | "multiple_active_authorities"
                    | "revoked_cross_account_predecessor"
            )
        })
        .or_else(|| {
            lower
                .contains("more than one active authority")
                .then_some("multiple_active_authorities")
        })
        .or_else(|| {
            (lower.contains("requires an explicit relay device")
                || lower.contains("requires an explicit prior credential"))
            .then_some("existing_authority")
        })?;
    let device_name = detail_object
        .and_then(|object| object.get("device_name"))
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded_display_text(value, 80))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "this Mac".to_string());
    let last_seen = detail_object
        .and_then(|object| object.get("last_seen_at"))
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded_display_text(value, 40))
        .filter(|value| !value.is_empty());
    let last_seen_text = last_seen
        .map(|value| format!(" (last seen {value})"))
        .unwrap_or_default();
    let can_reconnect = detail_object
        .and_then(|object| object.get("can_reconnect"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let text = if can_reconnect {
        format!(
            "This Mac is already registered as {device_name}{last_seen_text}. Reconnect it with the saved credential, or approve Replace it in the browser."
        )
    } else {
        MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE.to_string()
    };
    Some(ReattachRequiredState {
        message: StableMessage {
            code: format!("reattach_required:{reason}"),
            text,
        },
        can_reconnect,
    })
}

fn agent_read_timeout_message(error: &LocalApiError) -> Option<String> {
    let LocalApiError::TimedOut(reason) = error else {
        return None;
    };
    if reason.contains("/local-client/agent-context") {
        return Some(
            "Timed out loading Ottto context. Retry in a moment or narrow the query.".to_string(),
        );
    }
    if reason.contains("/local-client/costs") {
        return Some(
            "Timed out loading Ottto costs. Retry in a moment or narrow the query.".to_string(),
        );
    }
    if reason.contains("/local-client/sessions") {
        return Some(
            "Timed out loading Ottto sessions. Retry in a moment or narrow the query.".to_string(),
        );
    }
    if reason.contains("/local-client/recommendations") {
        return Some("Timed out loading Ottto recommendations. Retry in a moment.".to_string());
    }
    if reason.contains("/local-client/provider-impact") {
        return Some("Timed out loading Ottto provider-impact events. Retry in a moment or narrow the query.".to_string());
    }
    None
}

/// A request may name only the backend this Mac's saved setup-run binding
/// uses, so the binding's credentials never go to another one. Connecting to a
/// different backend starts with a sign-out, which clears the binding.
pub(super) fn require_request_base_matches_binding(
    requested: Option<&str>,
    binding_base: Option<&str>,
) -> Result<(), LocalApiError> {
    // The production hosts are one backend.
    let normalize = |value: &str| {
        let value = value.trim().trim_end_matches('/');
        if value == DEFAULT_API_BASE_URL
            || value == DIRECT_API_BASE_URL
            || value == LEGACY_API_BASE_URL
        {
            DEFAULT_API_BASE_URL.to_string()
        } else {
            value.to_string()
        }
    };
    match (requested.map(normalize).filter(|value| !value.is_empty()), binding_base) {
        (Some(requested), Some(binding)) if requested != normalize(binding) => {
            Err(LocalApiError::InvalidRequest(
                "This request names a different Ottto backend than this Mac's saved connection. Sign out first to use another backend."
                    .to_string(),
            ))
        }
        _ => Ok(()),
    }
}

pub(super) fn validated_api_base_url(raw: Option<&str>) -> Result<String, LocalApiError> {
    let env_value = std::env::var("OTTTO_API_BASE_URL").ok();
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(env_value.as_deref())
        .unwrap_or(DEFAULT_API_BASE_URL)
        .trim_end_matches('/');
    if !is_trusted_api_base_url(value) {
        return Err(LocalApiError::NetworkUnavailable);
    }
    Ok(value.to_string())
}

/// Resolve the backend base URL used to validate an apps control token.
///
/// SECURITY: control-token validation is the *only* gate that authorizes an
/// `Untrusted` local peer to mutate telemetry config (write/delete the user's
/// ingest key). That validation must therefore target a backend the untrusted
/// caller cannot choose. Unlike [`validated_api_base_url`], this resolver
/// deliberately IGNORES any request-supplied `api_base_url`: a co-resident
/// local attacker could otherwise point validation at their own
/// `http://localhost:<port>` server that returns HTTP 200 and forge approval of
/// an unsigned token (the local freshness check never verifies the JWT
/// signature — see [`decode_control_token_payload`], which has no pinned public
/// key, so the trusted backend is the cryptographic gate).
///
/// The `http://localhost` / `http://127.0.0.1` allowance exists only for
/// developer and test use, so it is honored ONLY when it arrives through the
/// developer-controlled `OTTTO_API_BASE_URL` environment variable — never from
/// the request body. A request-supplied *production* base (`ottto.net/backend`
/// or `api.ottto.net`) IS honored, because it points at the real ottto backend
/// which rejects a forged/unsigned token; this keeps legitimate production
/// flows (which may target either host) working unchanged. Any other request
/// value (notably a loopback URL) is ignored and validation falls back to the
/// production default. Note the precedence is env > request(production) >
/// default: a daemon configured with a trusted `OTTTO_API_BASE_URL` validates
/// against that, and an *untrusted* env override fails closed (NetworkUnavailable)
/// rather than silently falling back to a request-supplied host.
pub(super) fn control_token_validation_base_url(
    requested: Option<&str>,
) -> Result<String, LocalApiError> {
    // 1. The developer-controlled env override wins outright (it may legitimately
    //    point at a local backend for dev/test).
    if let Some(env_value) = std::env::var("OTTTO_API_BASE_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
    {
        if !is_trusted_api_base_url(&env_value) {
            return Err(LocalApiError::NetworkUnavailable);
        }
        return Ok(env_value);
    }
    // 2. With no env override, honor a request-supplied PRODUCTION backend (safe:
    //    the real backend rejects forged tokens), but IGNORE any non-production
    //    request value — that loopback redirect is the bypass we are closing.
    if let Some(production) = requested
        .map(|value| value.trim().trim_end_matches('/'))
        .filter(|value| !value.is_empty())
        .filter(|value| is_production_api_base_url(value))
    {
        return Ok(production.to_string());
    }
    // 3. Production default.
    Ok(DEFAULT_API_BASE_URL.to_string())
}

/// A production ottto backend URL (`ottto.net/backend` or `api.ottto.net`,
/// optionally with a sub-path). Unlike [`is_trusted_api_base_url`] this excludes
/// the loopback dev allowance, so it is safe to honor even from an untrusted
/// request body when deciding where to validate a control token.
pub(crate) fn is_production_api_base_url(value: &str) -> bool {
    if value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }
    value == DEFAULT_API_BASE_URL
        || value == DIRECT_API_BASE_URL
        || value == LEGACY_API_BASE_URL
        || value.starts_with(&format!("{DEFAULT_API_BASE_URL}/"))
        || value.starts_with(&format!("{DIRECT_API_BASE_URL}/"))
        || value.starts_with(&format!("{LEGACY_API_BASE_URL}/"))
}

fn is_trusted_api_base_url(value: &str) -> bool {
    if value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }

    value == DEFAULT_API_BASE_URL
        || value == DIRECT_API_BASE_URL
        || value == LEGACY_API_BASE_URL
        || value.starts_with(&format!("{LEGACY_API_BASE_URL}/"))
        || developer_loopback_allowed(value)
        || staging_pair().is_some_and(|(api, _)| value == api)
}

/// Plain HTTP only to this Mac, and only for the exact base the developer
/// configured for this daemon process (`OTTTO_API_BASE_URL`); never a base
/// that arrived in a request or a saved connection. Unit tests may also accept
/// an exact loopback base so mock backends keep working; see
/// [`without_test_loopback_allowance`] to test the production rule.
fn developer_loopback_allowed(value: &str) -> bool {
    let developer_override = std::env::var("OTTTO_API_BASE_URL").ok();
    loopback_base::developer_loopback_base(value, developer_override.as_deref())
        || (test_loopback_allowance() && loopback_base::loopback_http_base(value).is_some())
}

#[cfg(test)]
fn test_loopback_allowance() -> bool {
    TEST_LOOPBACK_ALLOWANCE.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn test_loopback_allowance() -> bool {
    false
}

#[cfg(test)]
thread_local! {
    static TEST_LOOPBACK_ALLOWANCE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Runs `test` on this thread with the production loopback rule only.
#[cfg(test)]
pub(super) fn without_test_loopback_allowance<T>(test: impl FnOnce() -> T) -> T {
    TEST_LOOPBACK_ALLOWANCE.with(|cell| cell.set(false));
    let result = test();
    TEST_LOOPBACK_ALLOWANCE.with(|cell| cell.set(true));
    result
}

/// The one staging deployment a non-stable candidate build may trust, as `(API origin, web
/// origin)`. It exists only when the build sets `OTTTO_CLOUD_STAGING_PAIR="<api>|<web>"`; the
/// stable packaging path refuses to build with it set, so stable releases trust production only.
/// Source code names no staging host.
pub(super) fn staging_pair() -> Option<(&'static str, &'static str)> {
    #[cfg(test)]
    let test_pair = TEST_STAGING_PAIR.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let test_pair = None;
    test_pair.or_else(|| option_env!("OTTTO_CLOUD_STAGING_PAIR").and_then(parse_staging_pair))
}

/// `<api>|<web>`: two distinct bare `https://` origins (host and optional port, no path, query,
/// fragment or credentials), neither of them production. Anything else compiles in no pair.
pub(super) fn parse_staging_pair(value: &str) -> Option<(&str, &str)> {
    let (api, web) = value.split_once('|')?;
    let origin = |origin: &str| {
        origin.strip_prefix("https://").is_some_and(|authority| {
            !authority.is_empty()
                && !authority.starts_with([':', '.', '-'])
                && authority
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte))
        })
    };
    (origin(api)
        && origin(web)
        && api != web
        && !is_production_api_base_url(api)
        && web != "https://app.ottto.net")
        .then_some((api, web))
}

#[cfg(test)]
thread_local! {
    static TEST_STAGING_PAIR: std::cell::Cell<Option<(&'static str, &'static str)>> =
        const { std::cell::Cell::new(None) };
}

/// Runs `test` on this thread as if the build had compiled in `pair`.
#[cfg(test)]
pub(super) fn with_test_staging_pair<T>(
    pair: (&'static str, &'static str),
    test: impl FnOnce() -> T,
) -> T {
    let pair = parse_staging_pair(&format!("{}|{}", pair.0, pair.1))
        .map(|_| pair)
        .expect("a well-formed test staging pair");
    TEST_STAGING_PAIR.with(|cell| cell.set(Some(pair)));
    let result = test();
    TEST_STAGING_PAIR.with(|cell| cell.set(None));
    result
}

pub(super) fn api_url_with_base(api_base_url: &str, path: &str) -> String {
    format!("{}{}", api_base_url.trim_end_matches('/'), path)
}

pub(super) fn form_url_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            other => format!("%{other:02X}").chars().collect(),
        })
        .collect()
}

pub(super) fn backend_post_json<T: DeserializeOwned>(
    url: &str,
    body: &impl Serialize,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    backend_post_json_with_timeout(url, body, headers, BACKEND_REQUEST_TIMEOUT)
}

pub(super) fn backend_post_json_with_timeout<T: DeserializeOwned>(
    url: &str,
    body: &impl Serialize,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<T, LocalApiError> {
    // Backend calls carry tokens, secrets or claims in headers or bodies.
    let mut request = crate::retry_tls::credential_agent()
        .post(url)
        .set("Accept", "application/json")
        .timeout(timeout);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    let response = request
        .send_json(body)
        .map_err(|error| backend_error_from_ureq(url, error))?;
    backend_success(url, response)?
        .into_json()
        .map_err(|error| backend_response_unexpected(url, error.to_string()))
}

/// Sends `body` byte for byte (or no body) within `timeout`. A signed write's challenge hashes the
/// exact body, so the HTTP client must not serialize it again. Callers choose how to read a
/// refusal; `backend_send_raw_json` uses the standard backend error.
pub(super) fn backend_send_raw(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<ureq::Response, Box<ureq::Error>> {
    let mut request = crate::retry_tls::credential_agent()
        .request(method, url)
        .set("Accept", "application/json")
        .timeout(timeout);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    match body {
        Some(body) => request
            .set("Content-Type", "application/json")
            .send_bytes(body),
        None => request.call(),
    }
    .map_err(Box::new)
}

/// `backend_send_raw` with the standard backend error. A 2xx answer decodes as JSON, and an empty
/// 204 answer as JSON null.
pub(super) fn backend_send_raw_json<T: DeserializeOwned>(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    let response = backend_send_raw(method, url, body, headers, BACKEND_REQUEST_TIMEOUT)
        .map_err(|error| backend_error_from_ureq(url, *error))?;
    let response = backend_success(url, response)?;
    if response.status() == 204 {
        return serde_json::from_str("null")
            .map_err(|error| backend_response_unexpected(url, error.to_string()));
    }
    response
        .into_json()
        .map_err(|error| backend_response_unexpected(url, error.to_string()))
}

pub(super) fn backend_get_json<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    backend_get_json_with_timeout(url, headers, BACKEND_REQUEST_TIMEOUT)
}

pub(super) fn backend_get_agent_read_json<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<T, LocalApiError> {
    backend_get_json_with_timeout(url, headers, AGENT_READ_HTTP_TIMEOUT)
}

pub(super) fn backend_get_json_with_timeout<T: DeserializeOwned>(
    url: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<T, LocalApiError> {
    // Every caller authenticates with a header credential.
    let mut request = crate::retry_tls::credential_agent()
        .get(url)
        .set("Accept", "application/json")
        .timeout(timeout);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    let response = request
        .call()
        .map_err(|error| backend_error_from_ureq(url, error))?;
    backend_success(url, response)?
        .into_json()
        .map_err(|error| backend_response_unexpected(url, error.to_string()))
}

/// Credential requests never follow a redirect, so ureq returns a 3xx as
/// `Ok`. Only a 2xx response is a backend success worth decoding.
pub(super) fn backend_success(
    url: &str,
    response: ureq::Response,
) -> Result<ureq::Response, LocalApiError> {
    let status = response.status();
    if (200..300).contains(&status) {
        return Ok(response);
    }
    Err(LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::ResponseUnexpected,
        endpoint: safe_backend_endpoint(url),
        status: Some(status),
        body_excerpt: None,
        reason_code: None,
    }))
}

pub(super) fn backend_error_from_ureq(url: &str, error: ureq::Error) -> LocalApiError {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().ok();
            let body_excerpt = body.as_deref().and_then(safe_backend_body_excerpt);
            let reason_code = body.as_deref().and_then(backend_reason_code);
            LocalApiError::Backend(BackendErrorDetails {
                kind: if status >= 500 {
                    BackendErrorKind::Unavailable
                } else {
                    BackendErrorKind::Rejected
                },
                endpoint: safe_backend_endpoint(url),
                status: Some(status),
                body_excerpt,
                reason_code,
            })
        }
        ureq::Error::Transport(transport) if transport_error_timed_out(&transport) => {
            LocalApiError::TimedOut(format!(
                "backend request timed out for {}",
                safe_backend_endpoint(url)
            ))
        }
        ureq::Error::Transport(transport) => LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Unreachable,
            endpoint: safe_backend_endpoint(url),
            status: None,
            body_excerpt: safe_backend_body_excerpt(&transport.to_string()),
            reason_code: None,
        }),
    }
}

fn transport_error_timed_out(transport: &ureq::Transport) -> bool {
    let mut source = StdError::source(transport);
    while let Some(error) = source {
        if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
            return matches!(
                io_error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            );
        }
        source = error.source();
    }
    transport
        .to_string()
        .to_ascii_lowercase()
        .contains("timed out")
}

pub(super) fn backend_response_unexpected(url: &str, detail: String) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::ResponseUnexpected,
        endpoint: safe_backend_endpoint(url),
        status: None,
        body_excerpt: safe_backend_body_excerpt(&detail),
        reason_code: None,
    })
}

pub(super) fn safe_backend_endpoint(url: &str) -> String {
    let endpoint = url.split('?').next().unwrap_or(url);
    for (marker, replacement) in [
        (
            "/api/v1/telemetry/device-credential-preparations/",
            "[preparation]",
        ),
        ("/api/v1/telemetry/devices/", "[device]"),
    ] {
        let Some(start) = endpoint.find(marker) else {
            continue;
        };
        let identifier_start = start + marker.len();
        let suffix = endpoint[identifier_start..]
            .find('/')
            .map(|offset| &endpoint[identifier_start + offset..])
            .unwrap_or_default();
        if marker == "/api/v1/telemetry/devices/" && suffix != "/relay-token" {
            continue;
        }
        return format!("{}{}{}", &endpoint[..identifier_start], replacement, suffix);
    }
    endpoint.to_string()
}

/// The stable machine code an Ottto error body names: a top-level `code`, a
/// `detail.code`, or a `detail` that is itself a code
/// (`{"detail":"timezone_query_unsupported"}`). Only short lowercase
/// snake_case tokens qualify, so free-text detail never becomes a code.
pub(super) fn backend_reason_code(body: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let detail = value.get("detail");
    let named = [
        value.get("code"),
        detail.and_then(|detail| detail.get("code")),
    ]
    .into_iter()
    .flatten()
    .filter_map(serde_json::Value::as_str)
    .find(|code| is_backend_reason_code(code));
    let code = named.or_else(|| {
        detail
            .and_then(serde_json::Value::as_str)
            .filter(|code| code.contains('_') && is_backend_reason_code(code))
    })?;
    Some(code.to_string())
}

fn is_backend_reason_code(value: &str) -> bool {
    value.len() <= 64
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(super) fn safe_backend_body_excerpt(body: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(detail) = value.get("detail").and_then(serde_json::Value::as_object) {
            if detail.get("code").and_then(serde_json::Value::as_str) == Some("reattach_required") {
                let safe = json!({
                    "detail": {
                        "code": "reattach_required",
                        "message": detail.get("message").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 120)),
                        "reason": detail.get("reason").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 40)),
                        "device_name": detail.get("device_name").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 80)),
                        "last_seen_at": detail.get("last_seen_at").and_then(serde_json::Value::as_str).map(|value| bounded_display_text(value, 40)),
                        "can_reconnect": detail.get("can_reconnect").and_then(serde_json::Value::as_bool),
                    }
                });
                return serde_json::to_string(&safe).ok();
            }
        }
    }
    let compact = body
        .split_whitespace()
        .take(40)
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        return None;
    }
    Some(truncate_diagnostic(&redact_inline(&compact)))
}
