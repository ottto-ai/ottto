//! Shared, relay-authenticated continuity for existing enabled collector grants.
use crate::snapshot_client::SnapshotApiClient;
use ottto_core::{FileMachineStore, LocalDeviceBinding};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GrantKind {
    DailyReference,
    CloudSessions,
}

impl GrantKind {
    pub(crate) fn route(self) -> &'static str {
        match self {
            Self::DailyReference => "provider-daily-reference",
            Self::CloudSessions => "cloud-sessions",
        }
    }
}

// No Debug: these identity-bearing values never belong in diagnostics.
#[derive(Clone, Serialize)]
pub(crate) struct RebindRequest {
    pub installation_id: String,
    pub grant_version: u64,
    pub grant_scope_fingerprint: String,
    pub hardware_id: Option<String>,
    pub disclosure_version: String,
}

pub(crate) struct RebindProposal<G> {
    pub expected: G,
    pub installation_fingerprint: String,
    pub request: RebindRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RebindFailure {
    pub code: &'static str,
    pub retryable: bool,
}

impl RebindFailure {
    pub(crate) fn http(status: u16, body: Option<&Value>) -> Self {
        let code = body
            .and_then(|body| body.pointer("/detail/code"))
            .and_then(Value::as_str);
        let code = match (status, code) {
            (403, Some("owner_changed")) => "owner_changed",
            (409, Some("installation_reset")) => "installation_reset",
            (409, Some("hardware_changed")) => "hardware_changed",
            (409, Some("hardware_unknown")) => "hardware_unknown",
            (409, Some("already_approved")) => "already_approved",
            (403, Some("revoked")) => "revoked",
            (403, Some("disabled")) => "disabled",
            (409, Some("stale_binding")) => "stale_binding",
            // A pre-deployment 404 keeps today's stopped-binding behavior.
            (404, _) => "installation_mismatch",
            (429 | 500..=599, _) => "rebind_unavailable",
            _ => "rebind_refused",
        };
        Self {
            code,
            retryable: status == 429 || (500..=599).contains(&status),
        }
    }

    pub(crate) fn unavailable() -> Self {
        Self {
            code: "rebind_unavailable",
            retryable: true,
        }
    }
}

// Terminal failures (including an unavailable endpoint) are not retried in a
// supervisor loop. A new binding/epoch or process restart permits a fresh try.
// Network/429/5xx failures use each collector's existing supervisor cadence.
type AttemptKey = (GrantKind, String, String, u64, String);
fn refusals() -> &'static Mutex<BTreeMap<AttemptKey, RebindFailure>> {
    static REFUSALS: OnceLock<Mutex<BTreeMap<AttemptKey, RebindFailure>>> = OnceLock::new();
    REFUSALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn attempt(
    kind: GrantKind,
    grant_id: &str,
    request: &RebindRequest,
    send: impl FnOnce() -> Result<Value, RebindFailure>,
) -> Result<Value, RebindFailure> {
    let key = (
        kind,
        grant_id.to_owned(),
        request.installation_id.clone(),
        request.grant_version,
        request.grant_scope_fingerprint.clone(),
    );
    if let Some(failure) = refusals()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        return Err(*failure);
    }
    let result = send();
    if let Err(failure) = result {
        if !failure.retryable {
            refusals()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key, failure);
        }
    }
    result
}

pub(crate) fn rebind(
    client: &SnapshotApiClient,
    kind: GrantKind,
    grant_id: &str,
    request: &RebindRequest,
    device: &LocalDeviceBinding,
    secret: &str,
    timeout: Duration,
) -> Result<Value, RebindFailure> {
    attempt(kind, grant_id, request, || {
        // Recheck immediately before rebind, in addition to the collection fence.
        let hardware = verified_live_hardware().map_err(|code| RebindFailure {
            code,
            retryable: false,
        })?;
        if request.hardware_id.as_deref() != Some(hardware.as_str())
            || request.installation_id != device.device_id
        {
            return Err(RebindFailure {
                code: "hardware_changed",
                retryable: false,
            });
        }
        let started = std::time::Instant::now();
        let token = client
            .issue_relay_token_with_timeout(
                device,
                secret,
                crate::snapshots::SnapshotSource::Codex,
                timeout,
            )
            .map_err(|_| RebindFailure::unavailable())?;
        let remaining = timeout
            .checked_sub(started.elapsed())
            .ok_or_else(RebindFailure::unavailable)?;
        client.rebind_collector_grant(kind, grant_id, &token, request, remaining)
    })
}

/// Read the current physical machine. Never fall back to a saved hardware hash.
pub fn live_hardware_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let body = String::from_utf8(output.stdout).ok()?;
        let raw = body.lines().find_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            (key.trim() == "\"IOPlatformUUID\"").then(|| value.trim().trim_matches('"'))
        })?;
        if !crate::hex::is_uuid(raw) {
            return None;
        }
        Some(ottto_core::hashed_hardware_id(raw))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

pub(crate) fn verify_hardware(
    stored: Option<&str>,
    live: Option<&str>,
) -> Result<String, &'static str> {
    let live = live
        .filter(|id| ottto_core::is_hashed_hardware_id(id))
        .ok_or("hardware_unknown")?;
    let stored = stored.ok_or("hardware_unknown")?;
    let stored = if ottto_core::is_hashed_hardware_id(stored) {
        stored.to_owned()
    } else if crate::hex::is_uuid(stored) {
        ottto_core::hashed_hardware_id(stored)
    } else {
        return Err("hardware_unknown");
    };
    if stored != live {
        return Err("hardware_changed");
    }
    Ok(live.to_owned())
}

pub(crate) fn verified_live_hardware() -> Result<String, &'static str> {
    let saved = FileMachineStore::default()
        .load()
        .map_err(|_| "hardware_unknown")?
        .ok_or("hardware_unknown")?;
    verify_hardware(
        saved.hardware_uuid.as_deref(),
        live_hardware_id().as_deref(),
    )
}

pub(crate) fn status_reason(reason: &str) -> Option<&'static str> {
    match reason {
        "rebinding" => Some("rebinding"),
        "owner_changed" => Some("owner_changed"),
        "installation_reset" => Some("installation_reset"),
        "hardware_changed" => Some("hardware_changed"),
        "hardware_unknown" => Some("hardware_unknown"),
        "already_approved" => Some("already_approved"),
        "revoked" => Some("revoked"),
        "disabled" => Some("disabled"),
        "stale_binding" => Some("stale_binding"),
        "installation_mismatch" => Some("installation_mismatch"),
        "rebind_unavailable" => Some("rebind_unavailable"),
        "rebind_refused" => Some("rebind_refused"),
        _ => None,
    }
}

/// Public machine registration/status must not repeat a copied saved hash.
pub fn validated_hardware_id(stored: Option<&str>) -> Option<String> {
    verify_hardware(stored, live_hardware_id().as_deref()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;

    /// [behaviour] Both collectors use the exact five-field request and typed routes.
    #[test]
    fn request_and_routes_match_the_contract() {
        let request = request("wire");
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert!(value.get("previous_installation_id").is_none());
        assert_eq!(value["grant_version"], 1);
        assert_eq!(
            GrantKind::DailyReference.route(),
            "provider-daily-reference"
        );
        assert_eq!(GrantKind::CloudSessions.route(), "cloud-sessions");
    }

    fn request(scope: &str) -> RebindRequest {
        RebindRequest {
            installation_id: "00000000-0000-4000-8000-000000000071".to_owned(),
            grant_version: 1,
            grant_scope_fingerprint: scope.to_owned(),
            hardware_id: None,
            disclosure_version: "fixture".to_owned(),
        }
    }

    /// [behaviour] Closed refusal codes survive without server messages or identities.
    #[test]
    fn every_domain_refusal_and_http_failure_is_closed() {
        for (status, code) in [
            (403, "owner_changed"),
            (409, "installation_reset"),
            (409, "hardware_changed"),
            (409, "hardware_unknown"),
            (409, "already_approved"),
            (403, "revoked"),
            (403, "disabled"),
            (409, "stale_binding"),
        ] {
            let failure = RebindFailure::http(
                status,
                Some(&json!({"detail": {
                    "code": code, "message": "private", "retryable": false
                }})),
            );
            assert_eq!(failure.code, code);
            assert!(!failure.retryable);
        }
        for status in [401, 422, 404, 429, 500, 503] {
            assert_eq!(
                RebindFailure::http(status, None).retryable,
                status == 429 || (500..=599).contains(&status)
            );
        }
        assert_eq!(RebindFailure::http(404, None).code, "installation_mismatch");
        assert_eq!(
            RebindFailure::http(409, Some(&json!({"detail":{"code":"private"}}))).code,
            "rebind_refused"
        );
    }

    /// [regress] A not-yet-deployed endpoint never becomes a busy rebind retry loop.
    #[test]
    fn terminal_failures_are_not_retried_but_transport_errors_are() {
        for (scope, failure, expected) in [
            ("not-found", RebindFailure::http(404, None), 1),
            ("transport", RebindFailure::unavailable(), 2),
        ] {
            let calls = Cell::new(0);
            for _ in 0..2 {
                let _ = attempt(
                    GrantKind::DailyReference,
                    "test-grant-cache",
                    &request(scope),
                    || {
                        calls.set(calls.get() + 1);
                        Err(failure)
                    },
                );
            }
            assert_eq!(calls.get(), expected);
        }
    }

    /// [behaviour] A saved or migrated hash is proof only when LIVE hardware agrees.
    #[test]
    fn live_hardware_is_required_and_copies_are_refused() {
        let first = ottto_core::hashed_hardware_id("00000000-0000-4000-8000-000000000001");
        let second = ottto_core::hashed_hardware_id("00000000-0000-4000-8000-000000000002");
        assert_eq!(
            verify_hardware(Some(&first), Some(&first)),
            Ok(first.clone())
        );
        assert_eq!(
            verify_hardware(Some(&first), Some(&second)),
            Err("hardware_changed")
        );
        assert_eq!(verify_hardware(Some(&first), None), Err("hardware_unknown"));
        assert_eq!(verify_hardware(None, Some(&first)), Err("hardware_unknown"));
        assert_eq!(
            verify_hardware(Some("bad"), Some(&first)),
            Err("hardware_unknown")
        );
        assert_eq!(
            verify_hardware(Some("00000000-0000-4000-8000-000000000001"), Some(&first)),
            Ok(first)
        );
    }
}
