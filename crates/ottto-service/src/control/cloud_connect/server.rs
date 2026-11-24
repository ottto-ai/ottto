//! Server calls for cloud-key enrollment on this Mac's setup-run credential: the key claim and its
//! state, a device challenge, key enrollment and key revoke. Signed writes send the exact bytes
//! their challenge hashed.

use super::wire::ChallengeRequest;
use crate::control::api_url_with_base;
use crate::control::backend_get_json;
use crate::control::backend_post_json;
use crate::control::backend_send_raw_json;
use crate::control::setup::claims::credentials::refresh_cloud_setup_run_token_checked;
use crate::control::setup::claims::credentials::setup_run_token_for_connection_with_refresh;
use crate::control::validated_api_base_url;
use crate::control::SetupRunRefreshResponse;
use crate::control::DEFAULT_API_BASE_URL;
use crate::LocalApiError;
use crate::LocalDaemon;
use ottto_protocol::cloud_uuid;
use serde::Deserialize;
use serde::Serialize;

/// The server's answer to a refused run token; any other 401 (a bad proof) is final.
const SETUP_RUN_TOKEN_INVALID: &str = "setup_run_token_invalid";

const CLAIM_ORIGIN_PAIRS: [(&str, &str); 2] = [
    (DEFAULT_API_BASE_URL, "https://app.ottto.net"),
    (
        "https://staging.tail21f014.ts.net:8443",
        "https://staging.tail21f014.ts.net",
    ),
];
const CLAIM_WEB_ROUTE: &str = "/setup/cloud-keys?claim=";

/// The compiled (API, web) origin pair for `api_base_url`, if it is a known Ottto deployment.
pub(super) fn claim_origin_pair(api_base_url: &str) -> Option<(&'static str, &'static str)> {
    let api_base_url = api_base_url.trim().trim_end_matches('/');
    CLAIM_ORIGIN_PAIRS
        .into_iter()
        .find(|(api, _)| *api == api_base_url)
}

/// The configured staging API is trusted only for cloud setup-run requests and token refresh.
pub(in crate::control) fn validated_cloud_api_base_url(
    api_base_url: &str,
) -> Result<String, LocalApiError> {
    match claim_origin_pair(api_base_url) {
        Some((api, _)) => Ok(api.to_string()),
        None => validated_api_base_url(Some(api_base_url)),
    }
}

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

/// Validate against the API selected for this request, including any token retry.
pub(super) fn checked_claim_start(
    api_base_url: &str,
    start: impl FnOnce() -> Result<ClaimStarted, ServerError>,
) -> Result<ClaimStarted, ServerError> {
    let untrusted = || ServerError::local("server_untrusted");
    let (_, web_origin) = claim_origin_pair(api_base_url).ok_or_else(untrusted)?;
    let started = start()?;
    let browser_claim = started
        .claim_url
        .strip_prefix(web_origin)
        .and_then(|route| route.strip_prefix(CLAIM_WEB_ROUTE));
    if !cloud_uuid(&started.key_claim_id)
        || browser_claim != Some(started.key_claim_id.as_str())
        || !super::wire::is_key_code(&started.key_code)
    {
        return Err(untrusted());
    }
    Ok(started)
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

/// This Mac's cloud-key identity as the server's challenges name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct DeviceBinding {
    pub(super) device_id: String,
    pub(super) device_generation: u64,
    pub(super) org_id: String,
}

/// What the app reads on every hello. Each field is null when this service cannot tell.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(super) struct HelloFacts {
    pub(super) binding: Option<DeviceBinding>,
    /// The server's `agent_connect` status block, as the server sent it.
    pub(super) agent_connect: Option<serde_json::Value>,
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
    pub(super) fn local(code: &str) -> Self {
        Self {
            code: code.to_string(),
            status: None,
            outcome_unknown: false,
        }
    }

    pub(super) fn from_local(error: &LocalApiError) -> Self {
        match error {
            LocalApiError::Backend(details)
                if details.kind == crate::BackendErrorKind::ResponseUnexpected =>
            {
                Self::local("invalid_server_field")
            }
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
            LocalApiError::SetupRunConnectionMissing
            | LocalApiError::SetupRunConnectionMismatch => Self::local("not_paired"),
            LocalApiError::NetworkUnavailable => Self::local("server_untrusted"),
            _ => Self::local("local_error"),
        }
    }
}

/// The cloud-key routes the signer channel calls.
pub(super) trait CloudKeyServer {
    /// Starts or replays a claim and verifies its browser link against the connected API.
    fn start_claim(&self, body: &ClaimStartBody<'_>) -> Result<ClaimStarted, ServerError>;
    fn claim_state(&self, key_claim_id: &str) -> Result<ClaimState, ServerError>;
    /// A challenge for `request`, with the run and organization it was requested on.
    fn device_challenge(
        &self,
        request: &ChallengeRequest<'_>,
    ) -> Result<(BoundRun, DeviceChallenge), ServerError>;
    /// Sends the frozen enrollment body once.
    fn enroll(
        &self,
        raw_body: &[u8],
        device_proof: &str,
        approval_proof: Option<&str>,
    ) -> Result<Enrolled, ServerError>;
    /// Revokes this Mac's cloud keys (an empty `DELETE` body). The server answers 204.
    fn revoke(&self, device_proof: &str) -> Result<Revoked, ServerError>;
    /// This Mac's device binding and the server's agent connect status, for the app's hello.
    fn hello_facts(&self) -> HelloFacts;
    /// The current Unix time in seconds.
    fn now(&self) -> i64 {
        super::queue::unix_now()
    }
}

/// The routes on the Ottto server this Mac is connected to.
pub(super) struct SetupRunServer<'a> {
    pub(super) daemon: &'a LocalDaemon,
}

/// The setup run, organization and API a request is sent under: what a challenge's signed facts
/// must name, and what a token refresh must keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BoundRun {
    pub(super) id: String,
    pub(super) organization_id: String,
    pub(super) api_base_url: String,
}

impl SetupRunServer<'_> {
    pub(super) fn bound_run(&self) -> Result<BoundRun, ServerError> {
        let (connection, organization_id) = self
            .daemon
            .cloud_connect_binding()
            .map_err(|error| ServerError::from_local(&error))?;
        Ok(BoundRun {
            id: connection.setup_run_id,
            organization_id,
            api_base_url: connection.api_base_url,
        })
    }

    fn call<T>(
        &self,
        send: impl Fn(&str, &str) -> Result<T, LocalApiError>,
    ) -> Result<T, ServerError> {
        self.call_bound(None, send)
    }

    /// The exact signed request may be resent after a refused token if the
    /// refreshed authority still names the same run and organization.
    pub(super) fn call_bound<T>(
        &self,
        run: Option<&BoundRun>,
        send: impl Fn(&str, &str) -> Result<T, LocalApiError>,
    ) -> Result<T, ServerError> {
        let (connection, organization_id) = self
            .daemon
            .cloud_connect_binding()
            .map_err(|error| ServerError::from_local(&error))?;
        if run.is_some_and(|run| {
            run.id != connection.setup_run_id
                || run.organization_id != organization_id
                || run.api_base_url != connection.api_base_url
        }) {
            return Err(ServerError::local("not_paired"));
        }
        let api_base_url = validated_cloud_api_base_url(&connection.api_base_url)
            .map_err(|error| ServerError::from_local(&error))?;
        let refresh = || {
            refresh_cloud_setup_run_token_checked(&api_base_url, &connection, |response| {
                check_refresh_binding(response, &connection.setup_run_id, &organization_id)
            })
        };
        let credentials = setup_run_token_for_connection_with_refresh(&connection, refresh)
            .map_err(|error| ServerError::from_local(&error))?;
        let prefix = api_url_with_base(
            &api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/cloud",
                connection.setup_run_id
            ),
        );
        send_with_refresh(
            &credentials.setup_run_token,
            |token| send(&prefix, token),
            || refresh().map(|refreshed| refreshed.setup_run_token),
        )
    }
}

pub(super) fn check_refresh_binding(
    response: &SetupRunRefreshResponse,
    run_id: &str,
    organization_id: &str,
) -> Result<(), LocalApiError> {
    if response.setup_run_id.as_deref() == Some(run_id)
        && response.run.as_ref().is_some_and(|run| {
            run.id == run_id && run.organization_id.as_deref() == Some(organization_id)
        })
    {
        Ok(())
    } else {
        Err(LocalApiError::SetupRunConnectionMismatch)
    }
}

pub(super) fn send_with_refresh<T>(
    token: &str,
    send: impl Fn(&str) -> Result<T, LocalApiError>,
    refresh: impl FnOnce() -> Result<String, LocalApiError>,
) -> Result<T, ServerError> {
    let result = match send(token) {
        Err(LocalApiError::Backend(details))
            if details.reason_code.as_deref() == Some(SETUP_RUN_TOKEN_INVALID) =>
        {
            refresh().and_then(|fresh_token| send(&fresh_token))
        }
        result => result,
    };
    result.map_err(|error| ServerError::from_local(&error))
}

impl CloudKeyServer for SetupRunServer<'_> {
    fn start_claim(&self, body: &ClaimStartBody<'_>) -> Result<ClaimStarted, ServerError> {
        let run = self.bound_run()?;
        checked_claim_start(&run.api_base_url, || {
            self.call_bound(Some(&run), |prefix, token| {
                backend_post_json(
                    &format!("{prefix}/key-claims"),
                    body,
                    &[("X-Ottto-Setup-Run-Token", token)],
                )
            })
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
        request: &ChallengeRequest<'_>,
    ) -> Result<(BoundRun, DeviceChallenge), ServerError> {
        let run = self.bound_run()?;
        let challenge = self.call_bound(Some(&run), |prefix, token| {
            backend_post_json(
                &format!("{prefix}/device-challenges"),
                request,
                &[("X-Ottto-Setup-Run-Token", token)],
            )
        })?;
        Ok((run, challenge))
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
            backend_send_raw_json::<serde_json::Value>(
                "DELETE",
                &keys_url(prefix),
                None,
                &[
                    ("X-Ottto-Setup-Run-Token", token),
                    ("X-Ottto-Device-Proof", device_proof),
                ],
            )
            .map(|_| Revoked {
                reason: "revoked".into(),
            })
        })
    }

    fn hello_facts(&self) -> HelloFacts {
        let org_id = self
            .daemon
            .cloud_connect_binding()
            .ok()
            .map(|(_, org_id)| org_id);
        let device = ottto_core::FileDeviceStore::default()
            .load_with_credential_generation()
            .ok()
            .flatten()
            .filter(|device| device.credential_generation > 0);
        let binding = org_id.zip(device).map(|(org_id, device)| DeviceBinding {
            device_id: device.device.device_id,
            device_generation: device.credential_generation,
            org_id,
        });
        let agent_connect = crate::control::status::cloud_status(
            self.daemon,
            &crate::control::RequestAuthorization::TrustedCompanionApp,
            None,
        )
        .ok()
        .and_then(|mut status| status.get_mut("agent_connect").map(serde_json::Value::take))
        .filter(serde_json::Value::is_object);
        HelloFacts {
            binding,
            agent_connect,
        }
    }
}

/// The keys route under `prefix`: the route `wire::KEYS_ROUTE_TEMPLATE` names in the hash.
fn keys_url(prefix: &str) -> String {
    format!("{prefix}/keys")
}
