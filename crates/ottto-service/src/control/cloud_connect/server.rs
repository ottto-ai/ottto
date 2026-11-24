//! Server calls for cloud-key enrollment on this Mac's setup-run credential: the key claim and its
//! state, a device challenge, key enrollment and key revoke. Signed writes send the exact bytes
//! their challenge hashed.

use crate::control::api_url_with_base;
use crate::control::backend_get_json;
use crate::control::backend_post_json;
use crate::control::backend_send_raw_json;
use crate::control::refresh_setup_run_token_via_device_secret;
use crate::control::setup_run_token_for_connection;
use crate::control::validated_api_base_url;
use crate::control::LocalConnectionBinding;
use crate::LocalApiError;
use crate::LocalDaemon;
use serde::Deserialize;
use serde::Serialize;

/// The server's answer to a refused run token; any other 401 (a bad proof) is final.
const SETUP_RUN_TOKEN_INVALID: &str = "setup_run_token_invalid";

#[derive(Serialize)]
pub(super) struct ClaimStartBody<'a> {
    pub(super) client_claim_id: &'a str,
    pub(super) device_key_spki_b64: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) approval_key_spki_b64: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClaimStarted {
    pub(super) key_claim_id: String,
    pub(super) claim_url: String,
    pub(super) key_code: String,
    pub(super) expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClaimState {
    pub(super) state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct DeviceChallenge {
    pub(super) challenge_id: String,
    /// The signed payload, unpadded base64url.
    pub(super) payload_bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Enrolled {
    pub(super) device_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) approval_key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Revoked {
    pub(super) reason: String,
}

#[derive(Serialize)]
struct ChallengeBody<'a> {
    operation: &'a str,
    attempt_id: Option<&'a str>,
    request_sha256: &'a str,
}

/// A failed server call as the app sees it: the server's own code when it named one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServerError {
    pub(super) code: String,
    pub(super) status: Option<u16>,
    /// The server may have acted on the request (a timeout, no answer, a 5xx): read the claim
    /// state before trying again.
    pub(super) outcome_unknown: bool,
}

impl ServerError {
    fn local(code: &str) -> Self {
        Self {
            code: code.to_string(),
            status: None,
            outcome_unknown: false,
        }
    }

    fn from_local(error: &LocalApiError) -> Self {
        match error {
            LocalApiError::Backend(details) => Self {
                code: details.reason_code.clone().unwrap_or_else(|| {
                    match details.status {
                        None => "server_unreachable",
                        Some(status) if status >= 500 => "server_unavailable",
                        Some(_) => "server_rejected",
                    }
                    .to_string()
                }),
                status: details.status,
                outcome_unknown: details.status.is_none_or(|status| status >= 500),
            },
            LocalApiError::TimedOut(_) => Self {
                code: "server_timeout".to_string(),
                status: None,
                outcome_unknown: true,
            },
            LocalApiError::SetupRunConnectionMissing => Self::local("not_paired"),
            LocalApiError::NetworkUnavailable => Self::local("server_untrusted"),
            _ => Self::local("local_error"),
        }
    }
}

/// The cloud-key routes the signer channel calls.
pub(super) trait CloudKeyServer {
    /// Starts (or replays) a key claim for these public keys.
    fn start_claim(&self, body: &ClaimStartBody<'_>) -> Result<ClaimStarted, ServerError>;
    fn claim_state(&self, key_claim_id: &str) -> Result<ClaimState, ServerError>;
    /// A challenge committing to `request_sha256` for `operation`.
    fn device_challenge(
        &self,
        operation: &str,
        request_sha256: &str,
    ) -> Result<DeviceChallenge, ServerError>;
    /// Sends the frozen enrollment body once.
    fn enroll(
        &self,
        raw_body: &[u8],
        device_proof: &str,
        approval_proof: Option<&str>,
    ) -> Result<Enrolled, ServerError>;
    /// Revokes this Mac's cloud keys (an empty `DELETE` body).
    fn revoke(&self, device_proof: &str) -> Result<Revoked, ServerError>;
}

/// The routes on the Ottto server this Mac is connected to.
pub(super) struct SetupRunServer<'a> {
    pub(super) daemon: &'a LocalDaemon,
}

impl SetupRunServer<'_> {
    /// Runs `send` with the run's cloud route prefix and run token. A refused run token is
    /// refreshed once with the device secret and the identical request sent again; the server
    /// checks the token before it reads a proof, so nothing was spent.
    fn call<T>(
        &self,
        send: impl Fn(&str, &str) -> Result<T, LocalApiError>,
    ) -> Result<T, ServerError> {
        let connection = self
            .daemon
            .connection_for_authorized_client()
            .map_err(|error| ServerError::from_local(&error))?
            .ok_or_else(|| ServerError::local("not_paired"))?;
        let api_base_url = validated_api_base_url(Some(connection.api_base_url.as_str()))
            .map_err(|error| ServerError::from_local(&error))?;
        let credentials = setup_run_token_for_connection(&api_base_url, &connection)
            .map_err(|error| ServerError::from_local(&error))?;
        let prefix = |connection: &LocalConnectionBinding| {
            api_url_with_base(
                &api_base_url,
                &format!(
                    "/api/v1/setup-runs/{}/local-client/cloud",
                    connection.setup_run_id
                ),
            )
        };
        match send(
            &prefix(&credentials.connection),
            &credentials.setup_run_token,
        ) {
            Err(LocalApiError::Backend(details))
                if details.reason_code.as_deref() == Some(SETUP_RUN_TOKEN_INVALID) =>
            {
                let refreshed = refresh_setup_run_token_via_device_secret(
                    &api_base_url,
                    &credentials.connection,
                )
                .map_err(|error| ServerError::from_local(&error))?;
                send(&prefix(&refreshed.connection), &refreshed.setup_run_token)
                    .map_err(|error| ServerError::from_local(&error))
            }
            result => result.map_err(|error| ServerError::from_local(&error)),
        }
    }
}

impl CloudKeyServer for SetupRunServer<'_> {
    fn start_claim(&self, body: &ClaimStartBody<'_>) -> Result<ClaimStarted, ServerError> {
        self.call(|prefix, token| {
            backend_post_json(
                &format!("{prefix}/key-claims"),
                body,
                &[("X-Ottto-Setup-Run-Token", token)],
            )
        })
    }

    fn claim_state(&self, key_claim_id: &str) -> Result<ClaimState, ServerError> {
        self.call(|prefix, token| {
            backend_get_json(
                &format!("{prefix}/key-claims/{key_claim_id}"),
                &[("X-Ottto-Setup-Run-Token", token)],
            )
        })
    }

    fn device_challenge(
        &self,
        operation: &str,
        request_sha256: &str,
    ) -> Result<DeviceChallenge, ServerError> {
        let body = ChallengeBody {
            operation,
            attempt_id: None,
            request_sha256,
        };
        self.call(|prefix, token| {
            backend_post_json(
                &format!("{prefix}/device-challenges"),
                &body,
                &[("X-Ottto-Setup-Run-Token", token)],
            )
        })
    }

    fn enroll(
        &self,
        raw_body: &[u8],
        device_proof: &str,
        approval_proof: Option<&str>,
    ) -> Result<Enrolled, ServerError> {
        self.call(|prefix, token| {
            let mut headers = vec![
                ("X-Ottto-Setup-Run-Token", token),
                ("X-Ottto-Device-Proof", device_proof),
            ];
            headers.extend(approval_proof.map(|proof| ("X-Ottto-Approval-Proof", proof)));
            backend_send_raw_json("POST", &keys_url(prefix), Some(raw_body), &headers)
        })
    }

    fn revoke(&self, device_proof: &str) -> Result<Revoked, ServerError> {
        self.call(|prefix, token| {
            backend_send_raw_json(
                "DELETE",
                &keys_url(prefix),
                None,
                &[
                    ("X-Ottto-Setup-Run-Token", token),
                    ("X-Ottto-Device-Proof", device_proof),
                ],
            )
        })
    }
}

/// The keys route under `prefix`: the route `wire::KEYS_ROUTE_TEMPLATE` names in the hash.
fn keys_url(prefix: &str) -> String {
    format!("{prefix}/keys")
}
