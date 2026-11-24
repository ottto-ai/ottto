//! The signer channel's commands from the Mac app: a hello first on every connection, the sign
//! queue's poll and answer, and cloud-key enrollment and revoke, each with its body and challenge
//! frozen on the connection that prepared it and sent at most once.

use super::queue::SignOutcome;
use super::queue::SignQueue;
use super::server::ClaimStartBody;
use super::server::CloudKeyServer;
use super::server::ServerError;
use super::wire::checked_challenge;
use super::wire::decode_base64url;
use super::wire::encode_base64url;
use super::wire::is_encoded_spki;
use super::wire::is_key_code;
use super::wire::is_p256_der_signature;
use super::wire::is_reverse_code;
use super::wire::proof_header;
use super::wire::request_sha256;
use super::wire::ChallengeRequest;
use super::wire::EnrollBody;
use super::wire::KEYS_ROUTE_TEMPLATE;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// The signer wire's version; the app and the service must agree on it exactly.
pub(super) const SIGNER_PROTOCOL: u16 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerRequest {
    signer_protocol: u16,
    id: String,
    command: String,
    #[serde(default)]
    args: Option<Value>,
}

#[derive(Serialize)]
struct SignerResponse {
    signer_protocol: u16,
    id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Refusal>,
}

/// Why a command did not run. Server refusals keep the server's code and status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Refusal {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    outcome_unknown: bool,
}

impl Refusal {
    fn new(code: &str) -> Self {
        Self {
            code: code.to_string(),
            status: None,
            outcome_unknown: false,
        }
    }
}

impl From<ServerError> for Refusal {
    fn from(error: ServerError) -> Self {
        Self {
            code: error.code,
            status: error.status,
            outcome_unknown: error.outcome_unknown,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignResultArgs {
    request_id: String,
    outcome: String,
    #[serde(default)]
    signature_b64: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimStartArgs {
    client_claim_id: String,
    device_key_spki_b64: String,
    #[serde(default)]
    approval_key_spki_b64: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimStatusArgs {
    key_claim_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollPrepareArgs {
    key_claim_id: String,
    device_key_spki_b64: String,
    #[serde(default)]
    approval_key_spki_b64: Option<String>,
    reverse_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollArgs {
    prepare_id: String,
    device_signature_b64: String,
    #[serde(default)]
    approval_signature_b64: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeArgs {
    #[serde(default)]
    prepare_id: Option<String>,
    #[serde(default)]
    device_signature_b64: Option<String>,
}

/// Open signer connections: a connection is here from its hello until it ends.
#[derive(Default)]
pub(super) struct Connections {
    open: Mutex<BTreeMap<u64, Connection>>,
}

#[derive(Default)]
struct Connection {
    prepared: u64,
    enroll: Option<Prepared>,
    revoke: Option<Prepared>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteKind {
    Enroll,
    Revoke,
}

/// A signed write waiting for the app's signatures: the exact body and the challenge that
/// commits to it.
struct Prepared {
    prepare_id: String,
    challenge_id: String,
    body: Vec<u8>,
    approval_key: bool,
}

impl Connection {
    fn slot(&mut self, kind: WriteKind) -> &mut Option<Prepared> {
        match kind {
            WriteKind::Enroll => &mut self.enroll,
            WriteKind::Revoke => &mut self.revoke,
        }
    }
}

impl Connections {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u64, Connection>> {
        self.open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn open(&self, connection: u64) {
        self.lock().entry(connection).or_default();
    }

    fn is_open(&self, connection: u64) -> bool {
        self.lock().contains_key(&connection)
    }

    /// Forgets the connection and every write it prepared.
    pub(super) fn close(&self, connection: u64) {
        self.lock().remove(&connection);
    }

    /// Keeps one prepared write per kind on the connection; a new one replaces the old.
    fn store(
        &self,
        connection: u64,
        kind: WriteKind,
        challenge_id: String,
        body: Vec<u8>,
        approval_key: bool,
    ) -> Option<String> {
        let mut open = self.lock();
        let entry = open.get_mut(&connection)?;
        entry.prepared += 1;
        let prepare_id = format!("prepare_{connection}_{}", entry.prepared);
        *entry.slot(kind) = Some(Prepared {
            prepare_id: prepare_id.clone(),
            challenge_id,
            body,
            approval_key,
        });
        Some(prepare_id)
    }

    /// Takes the prepared write after the supplied signatures pass local checks.
    fn take(
        &self,
        connection: u64,
        kind: WriteKind,
        prepare_id: &str,
        has_approval_signature: bool,
    ) -> Result<Prepared, Refusal> {
        let mut open = self.lock();
        let missing = || Refusal::new("prepare_not_found");
        let slot = open.get_mut(&connection).ok_or_else(missing)?.slot(kind);
        let prepared = slot
            .as_ref()
            .filter(|prepared| prepared.prepare_id == prepare_id)
            .ok_or_else(missing)?;
        if prepared.approval_key != has_approval_signature {
            return Err(Refusal::new("signature_invalid"));
        }
        slot.take().ok_or_else(missing)
    }
}

/// Runs one signer request from `connection` and returns the JSON response.
pub(super) fn handle(
    queue: &SignQueue,
    connections: &Connections,
    server: &dyn CloudKeyServer,
    connection: u64,
    request_json: &str,
) -> String {
    let (id, result) = match serde_json::from_str::<SignerRequest>(request_json) {
        Ok(request) if request.signer_protocol != SIGNER_PROTOCOL => {
            (request.id, Err(Refusal::new("unsupported_signer_protocol")))
        }
        Ok(request) => {
            let result = dispatch(
                queue,
                connections,
                server,
                connection,
                request.command,
                request.args,
            );
            (request.id, result)
        }
        Err(_) => (String::new(), Err(Refusal::new("invalid_request"))),
    };
    let response = match result {
        Ok(result) => SignerResponse {
            signer_protocol: SIGNER_PROTOCOL,
            id,
            ok: true,
            result: Some(result),
            error: None,
        },
        Err(refusal) => SignerResponse {
            signer_protocol: SIGNER_PROTOCOL,
            id,
            ok: false,
            result: None,
            error: Some(refusal),
        },
    };
    serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(
            r#"{{"signer_protocol":{SIGNER_PROTOCOL},"id":"","ok":false,"error":{{"code":"internal"}}}}"#
        )
    })
}

fn dispatch(
    queue: &SignQueue,
    connections: &Connections,
    server: &dyn CloudKeyServer,
    connection: u64,
    command: String,
    args: Option<Value>,
) -> Result<Value, Refusal> {
    if command == "signer_hello" {
        parse_args::<NoArgs>(args)?;
        connections.open(connection);
        queue.record_hello();
        let facts = server.hello_facts();
        return Ok(json!({
            "signer_protocol": SIGNER_PROTOCOL,
            "binding": facts.binding,
            "agent_connect": facts.agent_connect,
        }));
    }
    // The app sends nothing else before a hello reply on this connection, and the service holds
    // it to that.
    if !connections.is_open(connection) {
        return Err(Refusal::new("hello_required"));
    }
    match command.as_str() {
        "cloud_sign_poll" => {
            parse_args::<NoArgs>(args)?;
            Ok(json!({ "requests": queue.poll(connection) }))
        }
        "cloud_sign_result" => sign_result(queue, connection, parse_args(args)?),
        "cloud_keys_claim_start" => claim_start(server, parse_args(args)?),
        "cloud_keys_claim_status" => {
            let args = parse_args::<ClaimStatusArgs>(args)?;
            if !crate::hex::is_uuid(&args.key_claim_id) {
                return Err(Refusal::new("invalid_argument"));
            }
            to_result(server.claim_state(&args.key_claim_id)?)
        }
        "cloud_keys_enroll_prepare" => {
            enroll_prepare(connections, server, connection, parse_args(args)?)
        }
        "cloud_keys_enroll" => enroll(connections, server, connection, parse_args(args)?),
        "cloud_keys_revoke" => revoke(connections, server, connection, parse_args(args)?),
        _ => Err(Refusal::new("unknown_command")),
    }
}

fn parse_args<T: DeserializeOwned>(args: Option<Value>) -> Result<T, Refusal> {
    serde_json::from_value(args.unwrap_or_else(|| json!({})))
        .map_err(|_| Refusal::new("invalid_argument"))
}

fn to_result(value: impl Serialize) -> Result<Value, Refusal> {
    serde_json::to_value(value).map_err(|_| Refusal::new("internal"))
}

fn signature(encoded: &str) -> Result<Vec<u8>, Refusal> {
    decode_base64url(encoded)
        .filter(|der| is_p256_der_signature(der))
        .ok_or_else(|| Refusal::new("signature_invalid"))
}

fn sign_result(queue: &SignQueue, connection: u64, args: SignResultArgs) -> Result<Value, Refusal> {
    let outcome = match (args.outcome.as_str(), args.signature_b64.as_deref()) {
        ("signed", Some(encoded)) => SignOutcome::Signed(signature(encoded)?),
        ("declined", None) => SignOutcome::Declined,
        ("biometric_unavailable", None) => SignOutcome::BiometricUnavailable,
        ("app_unavailable", None) => SignOutcome::AppUnavailable,
        _ => return Err(Refusal::new("invalid_argument")),
    };
    queue
        .answer(connection, &args.request_id, outcome)
        .map_err(|_| Refusal::new("request_not_live"))?;
    Ok(json!({}))
}

/// Public keys the server can read: a device key and, unless Touch ID is missing, a different
/// approval key.
fn valid_keys(device: &str, approval: Option<&str>) -> bool {
    is_encoded_spki(device)
        && approval.is_none_or(|approval| is_encoded_spki(approval) && approval != device)
}

fn claim_start(server: &dyn CloudKeyServer, args: ClaimStartArgs) -> Result<Value, Refusal> {
    if !crate::hex::is_uuid(&args.client_claim_id)
        || !valid_keys(
            &args.device_key_spki_b64,
            args.approval_key_spki_b64.as_deref(),
        )
    {
        return Err(Refusal::new("invalid_argument"));
    }
    let started = server.start_claim(&ClaimStartBody {
        client_claim_id: &args.client_claim_id,
        device_key_spki_b64: &args.device_key_spki_b64,
        approval_key_spki_b64: args.approval_key_spki_b64.as_deref(),
    })?;
    // The app can open this URL in a browser. Accept only the exact web route
    // and a single claim parameter that names the returned claim.
    let browser_claim = started
        .claim_url
        .strip_prefix("https://app.ottto.net/setup/cloud-keys?claim=");
    if !crate::hex::is_uuid(&started.key_claim_id)
        || browser_claim != Some(started.key_claim_id.as_str())
        || !is_key_code(&started.key_code)
    {
        return Err(Refusal::new("server_untrusted"));
    }
    to_result(started)
}

/// Gets a challenge for `body` and freezes both on the connection.
fn prepare_write(
    connections: &Connections,
    server: &dyn CloudKeyServer,
    connection: u64,
    kind: WriteKind,
    body: Vec<u8>,
    approval_key: bool,
) -> Result<Value, Refusal> {
    let (method, operation) = match kind {
        WriteKind::Enroll => ("POST", "enroll"),
        WriteKind::Revoke => ("DELETE", "revoke"),
    };
    let hash = request_sha256(method, KEYS_ROUTE_TEMPLATE, &body);
    let request = ChallengeRequest {
        operation,
        attempt_id: None,
        request_sha256: &hash,
    };
    let (scope, challenge) = server.device_challenge(&request)?;
    let checked = checked_challenge(
        &challenge.challenge_id,
        &challenge.payload_bytes,
        &request,
        &scope.run_id,
        &scope.org_id,
        server.now(),
    )
    .ok_or_else(|| Refusal::new("challenge_mismatch"))?;
    let body_b64 = encode_base64url(&body);
    let prepare_id = connections
        .store(
            connection,
            kind,
            checked.challenge_id.clone(),
            body,
            approval_key,
        )
        .ok_or_else(|| Refusal::new("hello_required"))?;
    let mut result = json!({
        "prepare_id": prepare_id,
        "challenge_id": checked.challenge_id,
        "challenge_b64": checked.payload_b64,
        "expires_at": checked.expires_at,
    });
    if kind == WriteKind::Enroll {
        result["body_b64"] = Value::String(body_b64);
    }
    Ok(result)
}

fn enroll_prepare(
    connections: &Connections,
    server: &dyn CloudKeyServer,
    connection: u64,
    args: EnrollPrepareArgs,
) -> Result<Value, Refusal> {
    if !crate::hex::is_uuid(&args.key_claim_id)
        || !valid_keys(
            &args.device_key_spki_b64,
            args.approval_key_spki_b64.as_deref(),
        )
        || !is_reverse_code(&args.reverse_code)
    {
        return Err(Refusal::new("invalid_argument"));
    }
    let body = EnrollBody {
        device_key_spki_b64: &args.device_key_spki_b64,
        approval_key_spki_b64: args.approval_key_spki_b64.as_deref(),
        key_claim_id: &args.key_claim_id,
        reverse_code: &args.reverse_code,
    }
    .to_bytes();
    prepare_write(
        connections,
        server,
        connection,
        WriteKind::Enroll,
        body,
        args.approval_key_spki_b64.is_some(),
    )
}

/// Sends the frozen enrollment once. Never retried here: a retry needs the user's Touch ID and
/// may spend a code guess, so after an unknown outcome the app reads the claim state instead.
fn enroll(
    connections: &Connections,
    server: &dyn CloudKeyServer,
    connection: u64,
    args: EnrollArgs,
) -> Result<Value, Refusal> {
    let device_signature = signature(&args.device_signature_b64)?;
    let approval_signature = args
        .approval_signature_b64
        .as_deref()
        .map(signature)
        .transpose()?;
    let prepared = connections.take(
        connection,
        WriteKind::Enroll,
        &args.prepare_id,
        approval_signature.is_some(),
    )?;
    let device_proof = proof_header(&prepared.challenge_id, &device_signature);
    let approval_proof = approval_signature.map(|der| proof_header(&prepared.challenge_id, &der));
    to_result(server.enroll(&prepared.body, &device_proof, approval_proof.as_deref())?)
}

/// Revoke runs in two calls on one connection: without arguments it gets a challenge over the
/// empty body; with that `prepare_id` and the device signature it sends the `DELETE`.
fn revoke(
    connections: &Connections,
    server: &dyn CloudKeyServer,
    connection: u64,
    args: RevokeArgs,
) -> Result<Value, Refusal> {
    match (args.prepare_id, args.device_signature_b64) {
        (None, None) => prepare_write(
            connections,
            server,
            connection,
            WriteKind::Revoke,
            Vec::new(),
            false,
        ),
        (Some(prepare_id), Some(encoded)) => {
            let signature = signature(&encoded)?;
            let prepared = connections.take(connection, WriteKind::Revoke, &prepare_id, false)?;
            let device_proof = proof_header(&prepared.challenge_id, &signature);
            to_result(server.revoke(&device_proof)?)
        }
        _ => Err(Refusal::new("invalid_argument")),
    }
}
