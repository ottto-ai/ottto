use super::queue::unix_now;
use super::queue::SignKind;
use super::queue::SignOutcome;
use super::queue::SignQueue;
use super::queue::SignQueueError;
use super::resolve_signer_start;
use super::server::BoundRun;
use super::server::ClaimStartBody;
use super::server::ClaimStarted;
use super::server::ClaimState;
use super::server::CloudKeyServer;
use super::server::DeviceBinding;
use super::server::DeviceChallenge;
use super::server::Enrolled;
use super::server::HelloFacts;
use super::server::Revoked;
use super::server::ServerError;
use super::server::{
    check_refresh_binding, checked_claim_start, send_with_refresh, validated_cloud_api_base_url,
};
use super::signer;
use super::wake::app_bundle_of;
use super::wire;
use super::wire::ChallengeRequest;
use super::SignerOff;
use super::SignerStartFacts;
use crate::control::SetupRunRefreshResponse;
use crate::{BackendErrorDetails, BackendErrorKind, LocalApiError};
use ottto_protocol::InstallOwner;
use ottto_protocol::LocalControlRequest;
use serde_json::json;
use serde_json::Value;
use std::cell::Cell;
use std::cell::RefCell;
use std::path::Path;
use std::time::Duration;

const CLAIM_ID: &str = "11111111-2222-4333-8444-555555555555";
const CHALLENGE_ID: &str = "99999999-8888-4777-8666-555555555555";
const RUN_ID: &str = "11111111-1111-4111-8111-111111111111";
const ORG_ID: &str = "33333333-3333-4333-8333-333333333333";
const CLAIM_URL: &str =
    "https://app.ottto.net/setup/cloud-keys?claim=11111111-2222-4333-8444-555555555555";
/// `30 06 02 01 01 02 01 01`: r = 1, s = 1.
const DER_SIGNATURE_B64: &str = "MAYCAQECAQE";

/// An enrollment as sent: raw body, device proof, approval proof.
type SentEnrollment = (Vec<u8>, String, Option<String>);

/// Answers like the server's cloud-key routes and records what it was sent.
#[derive(Default)]
struct FakeServer {
    claim_fields: Option<(&'static str, &'static str)>,
    claim_api_base: Option<&'static str>,
    /// Return a challenge whose signed hash differs from the one asked for.
    tamper_challenge: bool,
    challenges: RefCell<Vec<(String, String)>>,
    enrolls: RefCell<Vec<SentEnrollment>>,
    revokes: RefCell<Vec<String>>,
}

impl CloudKeyServer for FakeServer {
    fn start_claim(&self, _body: &ClaimStartBody<'_>) -> Result<ClaimStarted, ServerError> {
        let (claim_url, key_code) = self.claim_fields.unwrap_or((CLAIM_URL, "AB23-EFG7"));
        let api_base = self.claim_api_base.unwrap_or("https://api.ottto.net");
        checked_claim_start(api_base, || {
            Ok(ClaimStarted {
                key_claim_id: CLAIM_ID.to_string(),
                claim_url: claim_url.to_string(),
                key_code: key_code.to_string(),
                expires_at: "2026-11-24T12:00:00Z".to_string(),
            })
        })
    }

    fn claim_state(&self, _key_claim_id: &str) -> Result<ClaimState, ServerError> {
        Ok(ClaimState {
            state: "awaiting_code".to_string(),
        })
    }

    fn device_challenge(
        &self,
        request: &ChallengeRequest<'_>,
    ) -> Result<(BoundRun, DeviceChallenge), ServerError> {
        self.challenges.borrow_mut().push((
            request.operation.to_string(),
            request.request_sha256.to_string(),
        ));
        let signed_hash = if self.tamper_challenge {
            "0".repeat(64)
        } else {
            request.request_sha256.to_string()
        };
        let now = unix_now();
        let payload = device_write(request.operation, None, &signed_hash, now, now + 60);
        Ok((
            run_scope(),
            DeviceChallenge {
                challenge_id: CHALLENGE_ID.to_string(),
                payload_bytes: wire::encode_base64url(payload.to_string().as_bytes()),
            },
        ))
    }

    fn enroll(
        &self,
        raw_body: &[u8],
        device_proof: &str,
        approval_proof: Option<&str>,
    ) -> Result<Enrolled, ServerError> {
        self.enrolls.borrow_mut().push((
            raw_body.to_vec(),
            device_proof.to_string(),
            approval_proof.map(str::to_string),
        ));
        Ok(Enrolled {
            device_key_id: "device-key".to_string(),
            approval_key_id: approval_proof.map(|_| "approval-key".to_string()),
        })
    }

    fn revoke(&self, device_proof: &str) -> Result<Revoked, ServerError> {
        self.revokes.borrow_mut().push(device_proof.to_string());
        Ok(Revoked {
            reason: "revoked".to_string(),
        })
    }

    fn hello_facts(&self) -> HelloFacts {
        HelloFacts {
            binding: None,
            agent_connect: None,
        }
    }
}

fn run_scope() -> BoundRun {
    BoundRun {
        id: RUN_ID.to_string(),
        organization_id: ORG_ID.to_string(),
        api_base_url: "https://api.ottto.net".to_string(),
    }
}

/// The signed facts of a device-write challenge for `operation` on the test run and organization.
fn device_write(
    operation: &str,
    attempt_id: Option<&str>,
    request_sha256: &str,
    iat: i64,
    exp: i64,
) -> Value {
    json!({
        "v": wire::DEVICE_WRITE_VERSION,
        "challenge_id": CHALLENGE_ID,
        "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "run_id": RUN_ID,
        "device_id": "22222222-2222-4222-8222-222222222222",
        "device_generation": 12,
        "org_id": ORG_ID,
        "operation": operation,
        "attempt_id": attempt_id,
        "request_sha256": request_sha256,
        "iat": iat,
        "exp": exp,
    })
}

struct Channel {
    queue: SignQueue,
    connections: signer::Connections,
    server: FakeServer,
}

impl Channel {
    fn new(server: FakeServer) -> Self {
        Self {
            queue: SignQueue::default(),
            connections: signer::Connections::default(),
            server,
        }
    }

    fn send(&self, connection: u64, command: &str, args: Value) -> Value {
        let request = json!({
            "signer_protocol": signer::SIGNER_PROTOCOL,
            "id": "req_1",
            "command": command,
            "args": args,
        });
        let response = signer::handle(
            &self.queue,
            &self.connections,
            &self.server,
            connection,
            &request.to_string(),
        );
        serde_json::from_str(&response).expect("signer response is JSON")
    }

    fn hello(&self, connection: u64) {
        assert_eq!(self.send(connection, "signer_hello", json!({}))["ok"], true);
    }

    fn close(&self, connection: u64) {
        self.connections.close(connection);
        self.queue.release(connection);
    }
}

fn error_code(response: &Value) -> &str {
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["code"].as_str().expect("error code")
}

fn enroll_args() -> Value {
    json!({
        "key_claim_id": CLAIM_ID,
        "device_key_spki_b64": "BBBB",
        "approval_key_spki_b64": "CCCC",
        "reverse_code": "ABC234",
    })
}

/// The server's enrollment vector, vendored byte for byte from the server repository.
const ENROLL_WIRE: &str = include_str!("../../../../../fixtures/cloud_connect/enroll_wire_v1.json");
/// The signer channel's wire, shared with the Mac app's tests.
const SIGNER_WIRE: &str = include_str!("../../../../../fixtures/cloud_connect/signer_wire_v1.json");

fn fixture(text: &str) -> Value {
    serde_json::from_str(text).expect("fixture is JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {value}"))
}

/// The signature half of a `{challenge_id}.{signature}` proof header.
fn proof_signature(proof: &str) -> &str {
    proof.split_once('.').expect("proof header").1
}

/// [behaviour] The enrollment body, request hashes, challenges and proof headers match the
/// server's shared enrollment vector exactly.
#[test]
fn enroll_and_revoke_match_the_server_vector() {
    let vector = fixture(ENROLL_WIRE);
    let enroll = &vector["enroll"];
    let raw_body = text(enroll, "raw_body_utf8");
    let body: Value = serde_json::from_str(raw_body).unwrap();
    let rebuilt = wire::EnrollBody {
        key_claim_id: text(&body, "key_claim_id"),
        device_key_spki_b64: text(&body, "device_key_spki_b64"),
        approval_key_spki_b64: body["approval_key_spki_b64"].as_str(),
        reverse_code: text(&body, "reverse_code"),
    }
    .to_bytes();
    assert_eq!(rebuilt, raw_body.as_bytes());
    assert!(wire::is_reverse_code(text(&body, "reverse_code")));
    for (name, spki, digest) in [
        ("device", "device_key_spki_b64", "device_spki_sha256"),
        ("approval", "approval_key_spki_b64", "approval_spki_sha256"),
    ] {
        let encoded = text(&body, spki);
        assert!(wire::is_encoded_spki(encoded), "{name}");
        assert_eq!(
            crate::hex::sha256_lower(&wire::decode_base64url(encoded).unwrap()),
            text(&vector["key_code"], digest),
            "{name}"
        );
    }
    for code in ["with_approval", "device_only"] {
        assert!(wire::is_key_code(text(&vector["key_code"], code)), "{code}");
    }

    for (operation, write) in [("enroll", enroll), ("revoke", &vector["revoke"])] {
        assert_eq!(text(write, "route_template"), wire::KEYS_ROUTE_TEMPLATE);
        let hash = wire::request_sha256(
            text(write, "method"),
            wire::KEYS_ROUTE_TEMPLATE,
            text(write, "raw_body_utf8").as_bytes(),
        );
        assert_eq!(hash, text(write, "request_sha256"), "{operation}");
        let challenge_id = text(write, "challenge_id");
        let payload: Value =
            serde_json::from_slice(&wire::decode_base64url(text(write, "payload_bytes")).unwrap())
                .unwrap();
        let request = ChallengeRequest {
            operation,
            attempt_id: None,
            request_sha256: &hash,
        };
        let now = payload["iat"].as_i64().unwrap() + 10;
        let checked = wire::checked_challenge(
            challenge_id,
            text(write, "payload_bytes"),
            &request,
            text(&payload, "run_id"),
            text(&payload, "org_id"),
            now,
        )
        .unwrap_or_else(|| panic!("{operation} challenge"));
        assert_eq!(checked.expires_at, payload["exp"].as_i64().unwrap());
        let mut proofs = vec!["device_proof"];
        if operation == "enroll" {
            proofs.push("approval_proof");
        }
        for proof in proofs {
            let proof = text(write, proof);
            let signature = wire::decode_base64url(proof_signature(proof)).unwrap();
            assert!(wire::is_p256_der_signature(&signature), "{operation}");
            assert_eq!(wire::proof_header(challenge_id, &signature), proof);
        }
    }
}

/// [behaviour] A challenge is handed to the app only when its signed facts name the run,
/// organization, operation, attempt and request hash asked for, and expire within the operation's
/// lifetime.
#[test]
fn challenge_facts_must_match_the_request_and_expire_soon() {
    let hash = "a".repeat(64);
    let now = 1_800_000_000;
    let check = |request: &ChallengeRequest<'_>, facts: Value| {
        wire::checked_challenge(
            CHALLENGE_ID,
            &wire::encode_base64url(facts.to_string().as_bytes()),
            request,
            RUN_ID,
            ORG_ID,
            now,
        )
    };
    let revoke = ChallengeRequest {
        operation: "revoke",
        attempt_id: None,
        request_sha256: &hash,
    };
    assert!(check(&revoke, device_write("revoke", None, &hash, now, now + 60)).is_some());
    let enroll = ChallengeRequest {
        operation: "enroll",
        ..revoke
    };
    assert!(check(&enroll, device_write("enroll", None, &hash, now, now + 300)).is_some());
    assert!(check(&revoke, device_write("revoke", None, &hash, now, now + 300)).is_none());
    let attempt = "44444444-4444-4444-8444-444444444444";
    let cancel = ChallengeRequest {
        operation: "cancel",
        attempt_id: Some(attempt),
        request_sha256: &hash,
    };
    assert!(check(
        &cancel,
        device_write("cancel", Some(attempt), &hash, now, now + 60)
    )
    .is_some());
    for (field, value) in [
        ("run_id", json!("55555555-5555-4555-8555-555555555555")),
        ("org_id", json!("55555555-5555-4555-8555-555555555555")),
        ("operation", json!("submit")),
        ("attempt_id", Value::Null),
        ("request_sha256", json!("b".repeat(64))),
        (
            "challenge_id",
            json!("55555555-5555-4555-8555-555555555555"),
        ),
        ("v", json!("ottto.cloud_connect.device_write.v2")),
        ("exp", json!(now)),
        ("exp", json!(now + 200)),
    ] {
        let mut facts = device_write("cancel", Some(attempt), &hash, now, now + 60);
        facts[field] = value;
        assert!(check(&cancel, facts).is_none(), "{field}");
    }
}

/// [behaviour] Every exchange in the shared signer wire fixture gets exactly the fixture's
/// response, and enroll and revoke send the server vector's exact body and proofs.
#[test]
fn signer_wire_matches_the_shared_fixture() {
    let wire_fixture = fixture(SIGNER_WIRE);
    let state = &wire_fixture["service_state"];
    let binding = &state["binding"];
    let server = FixtureServer {
        hello: HelloFacts {
            binding: Some(DeviceBinding {
                device_id: text(binding, "device_id").to_string(),
                device_generation: binding["device_generation"].as_u64().unwrap(),
                org_id: text(binding, "org_id").to_string(),
            }),
            agent_connect: Some(state["agent_connect"].clone()),
        },
        scope: BoundRun {
            id: text(state, "run_id").to_string(),
            organization_id: text(binding, "org_id").to_string(),
            api_base_url: "https://api.ottto.net".to_string(),
        },
        now: state["now"].as_i64().unwrap(),
        vector: fixture(ENROLL_WIRE),
        enrolls: RefCell::default(),
        revokes: RefCell::default(),
    };
    let queue = SignQueue::default();
    let connections = signer::Connections::default();
    let exchanges = wire_fixture["exchanges"].as_array().unwrap();
    assert!(exchanges.len() >= 10);
    for exchange in exchanges {
        let name = text(exchange, "name");
        for queued in exchange["queue_before"].as_array().into_iter().flatten() {
            let kind = match text(queued, "kind") {
                "device_proof" => SignKind::DeviceProof,
                _ => SignKind::Approval {
                    attempt_id: text(queued, "attempt_id").to_string(),
                    approval_id: text(queued, "approval_id").to_string(),
                },
            };
            let payload = wire::decode_base64url(text(queued, "payload_b64")).unwrap();
            queue
                .enqueue(kind, payload, queued["expires_at"].as_i64().unwrap())
                .unwrap();
        }
        let response = signer::handle(
            &queue,
            &connections,
            &server,
            1,
            &exchange["request"].to_string(),
        );
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response, exchange["response"], "{name}");
    }

    let vector = &server.vector;
    assert_eq!(
        server.enrolls.borrow().as_slice(),
        &[(
            text(&vector["enroll"], "raw_body_utf8").as_bytes().to_vec(),
            text(&vector["enroll"], "device_proof").to_string(),
            Some(text(&vector["enroll"], "approval_proof").to_string()),
        )]
    );
    assert_eq!(
        server.revokes.borrow().as_slice(),
        &[text(&vector["revoke"], "device_proof").to_string()]
    );
}

/// Answers like the server for the shared signer wire fixture: its challenges come from the
/// server's enrollment vector.
struct FixtureServer {
    hello: HelloFacts,
    scope: BoundRun,
    now: i64,
    vector: Value,
    enrolls: RefCell<Vec<SentEnrollment>>,
    revokes: RefCell<Vec<String>>,
}

impl CloudKeyServer for FixtureServer {
    fn start_claim(&self, body: &ClaimStartBody<'_>) -> Result<ClaimStarted, ServerError> {
        let enrolled: Value =
            serde_json::from_str(text(&self.vector["enroll"], "raw_body_utf8")).unwrap();
        let key_claim_id = text(&enrolled, "key_claim_id").to_string();
        assert_eq!(
            body.device_key_spki_b64,
            text(&enrolled, "device_key_spki_b64")
        );
        Ok(ClaimStarted {
            claim_url: format!("https://app.ottto.net/setup/cloud-keys?claim={key_claim_id}"),
            key_claim_id,
            key_code: text(&self.vector["key_code"], "with_approval").to_string(),
            expires_at: "2025-11-24T16:05:00Z".to_string(),
        })
    }

    fn claim_state(&self, key_claim_id: &str) -> Result<ClaimState, ServerError> {
        match key_claim_id {
            "00000000-0000-4000-8000-000000000404" => Err(ServerError {
                code: "claim_not_found".to_string(),
                status: Some(404),
                outcome_unknown: false,
            }),
            "00000000-0000-4000-8000-000000000504" => Err(ServerError {
                code: "server_timeout".to_string(),
                status: None,
                outcome_unknown: true,
            }),
            _ => Ok(ClaimState {
                state: "awaiting_code".to_string(),
            }),
        }
    }

    fn device_challenge(
        &self,
        request: &ChallengeRequest<'_>,
    ) -> Result<(BoundRun, DeviceChallenge), ServerError> {
        let write = &self.vector[request.operation];
        Ok((
            self.scope.clone(),
            DeviceChallenge {
                challenge_id: text(write, "challenge_id").to_string(),
                payload_bytes: text(write, "payload_bytes").to_string(),
            },
        ))
    }

    fn enroll(
        &self,
        raw_body: &[u8],
        device_proof: &str,
        approval_proof: Option<&str>,
    ) -> Result<Enrolled, ServerError> {
        self.enrolls.borrow_mut().push((
            raw_body.to_vec(),
            device_proof.to_string(),
            approval_proof.map(str::to_string),
        ));
        Ok(Enrolled {
            device_key_id: "88888888-8888-4888-8888-888888888888".to_string(),
            approval_key_id: approval_proof
                .map(|_| "99999999-9999-4999-8999-999999999999".to_string()),
        })
    }

    fn revoke(&self, device_proof: &str) -> Result<Revoked, ServerError> {
        self.revokes.borrow_mut().push(device_proof.to_string());
        Ok(Revoked {
            reason: "revoked".to_string(),
        })
    }

    fn hello_facts(&self) -> HelloFacts {
        self.hello.clone()
    }

    fn now(&self) -> i64 {
        self.now
    }
}

/// [behaviour] Key revoke's empty 204 answer decodes through the real HTTP sender.
#[test]
fn empty_no_content_answer_decodes_through_the_raw_sender() {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("local port");
    let url = format!("http://{}/keys", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("request");
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            if header == "\r\n" || header.is_empty() {
                break;
            }
        }
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        request_line
    });
    let answer = crate::control::backend_send_raw_json::<Value>(
        "DELETE",
        &url,
        None,
        &[("X-Ottto-Device-Proof", "proof")],
    );
    assert_eq!(answer.unwrap(), Value::Null);
    assert!(server.join().unwrap().starts_with("DELETE /keys "));
}

/// [behaviour] Only canonical unpadded base64url, P-256-sized DER signatures and six-character
/// reverse codes from the code alphabet are accepted.
#[test]
fn wire_shapes_accept_only_canonical_values() {
    assert_eq!(wire::decode_base64url("AA"), Some(vec![0]));
    for encoded in ["", "AA==", "AB", "A+", "A/", "A A"] {
        assert_eq!(wire::decode_base64url(encoded), None, "{encoded}");
    }

    let signature = |bytes: &[u8]| wire::is_p256_der_signature(bytes);
    assert!(signature(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
    // A high-bit integer carries one 0x00 prefix.
    assert!(signature(&[
        0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01
    ]));
    let bad_signatures: [&[u8]; 7] = [
        &[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01],
        &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
        &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
        &[0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00],
        &[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        &[0x30, 0x03, 0x02, 0x01, 0x01],
    ];
    for bad in bad_signatures {
        assert!(!signature(bad), "{bad:02x?}");
    }
    let mut long = vec![0x30, 70, 0x02, 34, 0x00, 0x80];
    long.extend([1; 32]);
    long.extend([0x02, 32]);
    long.extend([1; 32]);
    assert!(!signature(&long));

    assert!(wire::is_reverse_code("ABC234"));
    for code in ["ABC23", "ABC2345", "abc234", "ABC0O1", "ABC-23"] {
        assert!(!wire::is_reverse_code(code), "{code}");
    }
}

/// [behaviour] Every connection says hello first; nothing else runs before it or after the
/// connection ends, and the signer refuses control commands.
#[test]
fn commands_wait_for_a_hello_on_the_same_connection() {
    let channel = Channel::new(FakeServer::default());
    assert_eq!(
        error_code(&channel.send(1, "cloud_sign_poll", json!({}))),
        "hello_required"
    );
    channel.hello(1);
    assert_eq!(channel.send(1, "cloud_sign_poll", json!({}))["ok"], true);
    assert_eq!(
        error_code(&channel.send(2, "cloud_sign_poll", json!({}))),
        "hello_required"
    );
    assert_eq!(
        error_code(&channel.send(1, "status", json!({}))),
        "unknown_command"
    );
    channel.close(1);
    assert_eq!(
        error_code(&channel.send(1, "cloud_sign_poll", json!({}))),
        "hello_required"
    );

    let wrong_version = signer::handle(
        &channel.queue,
        &channel.connections,
        &channel.server,
        3,
        r#"{"signer_protocol":2,"id":"x","command":"signer_hello"}"#,
    );
    let wrong_version: Value = serde_json::from_str(&wrong_version).unwrap();
    assert_eq!(error_code(&wrong_version), "unsupported_signer_protocol");
}

/// [behaviour] The signer commands do not exist on the control channel.
#[test]
fn control_channel_refuses_signer_commands() {
    let request = |command: &str| {
        json!({
            "request_id": "req_1",
            "protocol_version": ottto_protocol::PROTOCOL_VERSION,
            "client_kind": "companion_app",
            "command": command,
        })
    };
    assert!(serde_json::from_value::<LocalControlRequest>(request("status")).is_ok());
    for command in [
        "signer_hello",
        "cloud_sign_poll",
        "cloud_sign_result",
        "cloud_keys_claim_start",
        "cloud_keys_claim_status",
        "cloud_keys_enroll_prepare",
        "cloud_keys_enroll",
        "cloud_keys_revoke",
    ] {
        assert!(
            serde_json::from_value::<LocalControlRequest>(request(command)).is_err(),
            "{command}"
        );
    }
}

/// [behaviour] Enrollment freezes the body and its challenge on the connection, sends those exact
/// bytes once, and never again for the same prepare.
#[test]
fn enrollment_sends_the_frozen_body_once() {
    let channel = Channel::new(FakeServer::default());
    channel.hello(1);
    let prepared = channel.send(1, "cloud_keys_enroll_prepare", enroll_args());
    assert_eq!(prepared["ok"], true, "{prepared}");
    let result = &prepared["result"];
    let body = wire::decode_base64url(result["body_b64"].as_str().unwrap()).unwrap();
    let hash = wire::request_sha256("POST", wire::KEYS_ROUTE_TEMPLATE, &body);
    assert_eq!(
        channel.server.challenges.borrow().as_slice(),
        &[("enroll".to_string(), hash)]
    );
    assert_eq!(result["challenge_id"], CHALLENGE_ID);

    let enroll = json!({
        "prepare_id": result["prepare_id"],
        "device_signature_b64": DER_SIGNATURE_B64,
        "approval_signature_b64": DER_SIGNATURE_B64,
    });
    for field in ["device_signature_b64", "approval_signature_b64"] {
        let mut malformed = enroll.clone();
        malformed[field] = json!("AAAA");
        assert_eq!(
            error_code(&channel.send(1, "cloud_keys_enroll", malformed)),
            "signature_invalid"
        );
    }
    let mut missing = enroll.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("approval_signature_b64");
    assert_eq!(
        error_code(&channel.send(1, "cloud_keys_enroll", missing)),
        "signature_invalid"
    );
    assert!(channel.server.enrolls.borrow().is_empty());

    let enrolled = channel.send(1, "cloud_keys_enroll", enroll.clone());
    assert_eq!(
        enrolled["result"]["approval_key_id"], "approval-key",
        "{enrolled}"
    );
    let proof = format!("{CHALLENGE_ID}.{DER_SIGNATURE_B64}");
    assert_eq!(
        channel.server.enrolls.borrow().as_slice(),
        &[(body, proof.clone(), Some(proof))]
    );

    assert_eq!(
        error_code(&channel.send(1, "cloud_keys_enroll", enroll)),
        "prepare_not_found"
    );
    assert_eq!(channel.server.enrolls.borrow().len(), 1);
}

/// [behaviour] A prepare dies with its connection, a challenge that does not commit to the frozen
/// body is never handed to the app, and malformed input reaches no server route.
#[test]
fn enrollment_refuses_what_it_cannot_send_safely() {
    let channel = Channel::new(FakeServer::default());
    channel.hello(1);
    let prepared = channel.send(1, "cloud_keys_enroll_prepare", enroll_args());
    let prepare_id = prepared["result"]["prepare_id"].clone();
    channel.close(1);
    channel.hello(2);
    let enroll = json!({
        "prepare_id": prepare_id,
        "device_signature_b64": DER_SIGNATURE_B64,
        "approval_signature_b64": DER_SIGNATURE_B64,
    });
    assert_eq!(
        error_code(&channel.send(2, "cloud_keys_enroll", enroll)),
        "prepare_not_found"
    );

    assert!(channel.server.enrolls.borrow().is_empty());

    let calls_before = channel.server.challenges.borrow().len();
    for (field, value) in [
        ("reverse_code", "abc234"),
        ("reverse_code", "ABC23O"),
        ("key_claim_id", "not-a-uuid"),
        ("approval_key_spki_b64", "BBBB"),
        ("device_key_spki_b64", "BB=="),
    ] {
        let mut args = enroll_args();
        args[field] = json!(value);
        assert_eq!(
            error_code(&channel.send(2, "cloud_keys_enroll_prepare", args)),
            "invalid_argument",
            "{field}={value}"
        );
    }
    assert_eq!(channel.server.challenges.borrow().len(), calls_before);

    let tampered = Channel::new(FakeServer {
        tamper_challenge: true,
        ..FakeServer::default()
    });
    tampered.hello(1);
    assert_eq!(
        error_code(&tampered.send(1, "cloud_keys_enroll_prepare", enroll_args())),
        "challenge_mismatch"
    );
}

/// [behaviour] Revoke gets a challenge over the empty `DELETE` body, then sends the device proof
/// on that challenge.
#[test]
fn revoke_signs_the_empty_delete_body() {
    let channel = Channel::new(FakeServer::default());
    channel.hello(1);
    let prepared = channel.send(1, "cloud_keys_revoke", json!({}));
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert!(prepared["result"].get("body_b64").is_none());
    assert_eq!(
        channel.server.challenges.borrow().as_slice(),
        &[(
            "revoke".to_string(),
            wire::request_sha256("DELETE", wire::KEYS_ROUTE_TEMPLATE, b"")
        )]
    );
    let revoke = json!({
        "prepare_id": prepared["result"]["prepare_id"],
        "device_signature_b64": DER_SIGNATURE_B64,
    });
    // One nonzero byte plus 32 more bytes exceeds the width of a P-256 scalar.
    let mut oversized = vec![0x30, 38, 0x02, 33, 0x01];
    oversized.extend([0x00; 32]);
    oversized.extend([0x02, 0x01, 0x01]);
    assert!(!wire::is_p256_der_signature(&oversized));
    let mut malformed = revoke.clone();
    malformed["device_signature_b64"] = json!(wire::encode_base64url(&oversized));
    assert_eq!(
        error_code(&channel.send(1, "cloud_keys_revoke", malformed)),
        "signature_invalid"
    );
    assert!(channel.server.revokes.borrow().is_empty());
    let revoked = channel.send(1, "cloud_keys_revoke", revoke.clone());
    assert_eq!(revoked["result"]["reason"], "revoked", "{revoked}");
    assert_eq!(
        channel.server.revokes.borrow().as_slice(),
        &[format!("{CHALLENGE_ID}.{DER_SIGNATURE_B64}")]
    );
    assert_eq!(
        error_code(&channel.send(1, "cloud_keys_revoke", revoke)),
        "prepare_not_found"
    );
}

/// [behaviour] Claim start and state pass through to the server after a shape check.
#[test]
fn claim_start_and_state_reach_the_server() {
    let channel = Channel::new(FakeServer::default());
    channel.hello(1);
    let started = channel.send(
        1,
        "cloud_keys_claim_start",
        json!({
            "client_claim_id": CLAIM_ID,
            "device_key_spki_b64": "BBBB",
            "approval_key_spki_b64": null,
        }),
    );
    assert_eq!(started["result"]["key_code"], "AB23-EFG7", "{started}");
    assert_eq!(started["result"]["claim_url"], CLAIM_URL);
    let state = channel.send(
        1,
        "cloud_keys_claim_status",
        json!({ "key_claim_id": CLAIM_ID }),
    );
    assert_eq!(state["result"]["state"], "awaiting_code");
    assert_eq!(
        error_code(&channel.send(
            1,
            "cloud_keys_claim_start",
            json!({ "client_claim_id": CLAIM_ID, "device_key_spki_b64": "BBBB", "extra": 1 }),
        )),
        "invalid_argument"
    );
}

/// [behaviour] The signer opens claims only on the web origin for the connected API.
#[test]
fn claim_start_requires_the_connected_apis_compiled_web_origin() {
    const PRODUCTION_API: &str = "https://api.ottto.net";
    const STAGING_API: &str = "https://staging.tail21f014.ts.net:8443";
    const STAGING_CLAIM: &str =
        "https://staging.tail21f014.ts.net/setup/cloud-keys?claim=11111111-2222-4333-8444-555555555555";
    const OTHER_CLAIM: &str =
        "https://example.test/setup/cloud-keys?claim=11111111-2222-4333-8444-555555555555";

    for (api, claim_url, accepted) in [
        (PRODUCTION_API, CLAIM_URL, true),
        (STAGING_API, STAGING_CLAIM, true),
        (PRODUCTION_API, STAGING_CLAIM, false),
        (STAGING_API, CLAIM_URL, false),
        (PRODUCTION_API, OTHER_CLAIM, false),
        (STAGING_API, OTHER_CLAIM, false),
        ("https://example.test", CLAIM_URL, false),
        ("https://staging.tail21f014.ts.net", STAGING_CLAIM, false),
    ] {
        let channel = Channel::new(FakeServer {
            claim_api_base: Some(api),
            claim_fields: Some((claim_url, "AB23-EFG7")),
            ..FakeServer::default()
        });
        channel.hello(1);
        let reply = channel.send(
            1,
            "cloud_keys_claim_start",
            json!({ "client_claim_id": CLAIM_ID, "device_key_spki_b64": "BBBB" }),
        );
        if accepted {
            assert_eq!(reply["result"]["claim_url"], claim_url, "{api}");
        } else {
            assert_eq!(error_code(&reply), "server_untrusted", "{api} {claim_url}");
            assert!(reply.get("result").is_none());
        }
    }

    assert_eq!(
        validated_cloud_api_base_url(STAGING_API).unwrap(),
        STAGING_API
    );
    assert!(crate::control::validated_api_base_url(Some(STAGING_API)).is_err());
    assert!(validated_cloud_api_base_url("https://staging.tail21f014.ts.net:8444").is_err());
}

/// [behaviour] No browser link or forward code is returned until both pass the local checks.
#[test]
fn claim_start_refuses_untrusted_browser_fields() {
    for (url, code) in [
        ("http://app.ottto.net/setup/cloud-keys?claim=11111111-2222-4333-8444-555555555555", "ABCD-EFGH"),
        ("https://app.ottto.net.example.com/setup/cloud-keys?claim=11111111-2222-4333-8444-555555555555", "ABCD-EFGH"),
        ("https://app.ottto.net:8443/setup/cloud-keys?claim=11111111-2222-4333-8444-555555555555", "ABCD-EFGH"),
        ("https://app.ottto.net/other?claim=11111111-2222-4333-8444-555555555555", "ABCD-EFGH"),
        ("https://app.ottto.net/setup/cloud-keys?claim=bogus", "ABCD-EFGH"),
        ("https://app.ottto.net/setup/cloud-keys?claim=99999999-8888-4777-8666-555555555555", "ABCD-EFGH"),
        ("https://app.ottto.net/setup/cloud-keys?claim=11111111-2222-4333-8444-555555555555&claim=99999999-8888-4777-8666-555555555555", "ABCD-EFGH"),
        (CLAIM_URL, "ABCD-EFG8"),
        (CLAIM_URL, "ABCD-efgh"),
        (CLAIM_URL, "ABCDEFGH"),
    ] {
        let channel = Channel::new(FakeServer {
            claim_fields: Some((url, code)),
            ..FakeServer::default()
        });
        channel.hello(1);
        let reply = channel.send(
            1,
            "cloud_keys_claim_start",
            json!({ "client_claim_id": CLAIM_ID, "device_key_spki_b64": "BBBB" }),
        );
        assert_eq!(error_code(&reply), "server_untrusted", "{url} {code}");
        assert!(reply.get("result").is_none());
    }
}

/// [behaviour] A refresh can resend on the original run and org only. Proof errors never refresh.
#[test]
fn refresh_resends_only_on_the_original_run_and_organization() {
    let original = json!({
        "setup_run_id": "run-original",
        "setup_run_token": "refreshed",
        "expires_at": "2026-11-24T12:00:00Z",
        "run": { "id": "run-original", "organization_id": "org-original", "status": "completed" }
    });
    let reject = |reason: &str| {
        LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Rejected,
            endpoint: "/cloud/keys".to_string(),
            status: Some(401),
            body_excerpt: None,
            reason_code: Some(reason.to_string()),
        })
    };
    for (field, value) in [
        ("", Value::Null),
        ("/setup_run_id", json!("run-other")),
        ("/run/id", json!("run-other")),
        ("/run/organization_id", json!("org-other")),
        ("/run/organization_id", Value::Null),
        ("/run", Value::Null),
    ] {
        let mut body = original.clone();
        if !field.is_empty() {
            *body.pointer_mut(field).unwrap() = value;
        }
        let response: SetupRunRefreshResponse = serde_json::from_value(body).unwrap();
        let sends = Cell::new(0);
        let result = send_with_refresh(
            "original",
            |token| {
                sends.set(sends.get() + 1);
                match token {
                    "original" => Err(reject("setup_run_token_invalid")),
                    "refreshed" => Ok(()),
                    _ => panic!("unexpected token"),
                }
            },
            || {
                check_refresh_binding(&response, "run-original", "org-original")?;
                Ok(response.setup_run_token)
            },
        );
        if field.is_empty() {
            assert_eq!(result, Ok(()));
            assert_eq!(sends.get(), 2);
        } else {
            assert_eq!(result.unwrap_err().code, "not_paired", "{field}");
            assert_eq!(sends.get(), 1, "{field}");
        }
    }
    let refused = send_with_refresh::<()>(
        "original",
        |_| Err(reject("device_proof_invalid")),
        || panic!("proof refusals must not refresh credentials"),
    );
    assert_eq!(refused.unwrap_err().code, "device_proof_invalid");
}

/// [behaviour] A queued request goes to the first verified connection that polls it; only that
/// connection's answer counts, a DER check guards signatures, and an ended connection returns its
/// request to the queue.
#[test]
fn sign_results_count_only_from_the_polling_connection() {
    let channel = Channel::new(FakeServer::default());
    let queued = channel
        .queue
        .enqueue(SignKind::DeviceProof, b"payload".to_vec(), unix_now() + 60)
        .unwrap();
    channel.hello(1);
    channel.hello(2);
    let polled = channel.send(1, "cloud_sign_poll", json!({}));
    assert_eq!(
        polled["result"]["requests"][0]["request_id"],
        queued.request_id
    );
    assert_eq!(polled["result"]["requests"][0]["kind"], "device_proof");
    assert_eq!(
        channel.send(2, "cloud_sign_poll", json!({}))["result"]["requests"],
        json!([])
    );

    let answer = |connection, signature: &str| {
        channel.send(
            connection,
            "cloud_sign_result",
            json!({
                "request_id": queued.request_id,
                "outcome": "signed",
                "signature_b64": signature,
            }),
        )
    };
    assert_eq!(
        error_code(&answer(2, DER_SIGNATURE_B64)),
        "request_not_live"
    );
    assert_eq!(error_code(&answer(1, "AAAA")), "signature_invalid");

    channel.close(1);
    assert_eq!(
        channel.send(2, "cloud_sign_poll", json!({}))["result"]["requests"][0]["request_id"],
        queued.request_id
    );
    assert_eq!(answer(2, DER_SIGNATURE_B64)["ok"], true);
    assert_eq!(
        channel.queue.wait(&queued.request_id, Duration::ZERO),
        Some(SignOutcome::Signed(vec![
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
        ]))
    );
}

/// [behaviour] One live request per approval id, a new approval supersedes the attempt's older
/// one, and expired requests are refused.
#[test]
fn queue_supersedes_and_expires() {
    let queue = SignQueue::default();
    let approval = |approval_id: &str| SignKind::Approval {
        attempt_id: "attempt_1".to_string(),
        approval_id: approval_id.to_string(),
    };
    let first = queue
        .enqueue(approval("approval_1"), b"a".to_vec(), unix_now() + 60)
        .unwrap();
    assert!(first.wake_app);
    let again = queue
        .enqueue(approval("approval_1"), b"a".to_vec(), unix_now() + 60)
        .unwrap();
    assert_eq!(again.request_id, first.request_id);
    let renewed = queue
        .enqueue(approval("approval_2"), b"b".to_vec(), unix_now() + 60)
        .unwrap();
    assert_ne!(renewed.request_id, first.request_id);
    assert!(!renewed.wake_app);
    assert_eq!(
        queue.wait(&first.request_id, Duration::ZERO),
        Some(SignOutcome::Superseded)
    );

    queue.record_hello();
    let queued = queue
        .enqueue(SignKind::DeviceProof, b"d".to_vec(), unix_now() + 60)
        .unwrap();
    assert!(!queued.wake_app);
    queue.cancel(&renewed.request_id);
    assert_eq!(
        queue.enqueue(SignKind::DeviceProof, b"d".to_vec(), unix_now()),
        Err(SignQueueError::AlreadyExpired)
    );
    assert_eq!(
        queue.wait(&renewed.request_id, Duration::ZERO),
        Some(SignOutcome::Expired)
    );
    assert_eq!(
        queue.wait("sign_unknown", Duration::ZERO),
        Some(SignOutcome::Expired)
    );
}

/// [behaviour] A rejected renewal keeps the old approval; a valid renewal supersedes it.
#[test]
fn queue_replaces_an_approval_only_after_admission() {
    let queue = SignQueue::default();
    let approval = |attempt: &str, approval: &str| SignKind::Approval {
        attempt_id: attempt.to_string(),
        approval_id: approval.to_string(),
    };
    let old = queue
        .enqueue(approval("attempt", "old"), vec![], unix_now() + 60)
        .unwrap();
    assert_eq!(
        queue.enqueue(approval("attempt", "expired"), vec![], unix_now()),
        Err(SignQueueError::AlreadyExpired)
    );
    assert_eq!(queue.wait(&old.request_id, Duration::ZERO), None);
    assert_eq!(queue.poll(1)[0].request_id, old.request_id);

    let replacement = queue
        .enqueue(approval("attempt", "new"), vec![], unix_now() + 60)
        .unwrap();
    assert_eq!(
        queue.wait(&old.request_id, Duration::ZERO),
        Some(SignOutcome::Superseded)
    );
    let live = queue.poll(1);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].request_id, replacement.request_id);
}

/// [behaviour] The signer opens only in a release-signed service the app installed, with no
/// Companion trust override.
#[test]
fn signer_starts_only_for_the_release_app_service() {
    let facts = |owner, companion_override, release_team, release_service| SignerStartFacts {
        owner,
        companion_override,
        release_team,
        release_service,
    };
    assert_eq!(
        resolve_signer_start(&facts(InstallOwner::AppBundle, false, true, true)),
        Ok(())
    );
    for (case, off) in [
        (
            facts(InstallOwner::Homebrew, false, true, true),
            SignerOff::NotAppInstalled,
        ),
        (
            facts(InstallOwner::Dev, false, true, true),
            SignerOff::NotAppInstalled,
        ),
        (
            facts(InstallOwner::AppBundle, true, true, true),
            SignerOff::CompanionOverride,
        ),
        (
            facts(InstallOwner::AppBundle, false, false, true),
            SignerOff::NoReleaseTeam,
        ),
        (
            facts(InstallOwner::AppBundle, false, true, false),
            SignerOff::NotReleaseService,
        ),
    ] {
        assert_eq!(resolve_signer_start(&case), Err(off));
    }
}

/// [behaviour] Both XPC endpoints require the Apple Developer ID intermediate and the signed
/// identifier. Parse the requirement with the same macOS framework the service uses.
#[cfg(target_os = "macos")]
#[test]
fn signer_requirements_pin_the_developer_id_chain() {
    use crate::control::peer::{companion_signer_code_requirement, service_team_code_requirement};
    use security_framework::os::macos::code_signing::SecRequirement;

    let team = "ABCDE12345";
    for (requirement, identity) in [
        (
            companion_signer_code_requirement(team),
            "net.ottto.Companion",
        ),
        (service_team_code_requirement(team), "ottto-service"),
    ] {
        assert_eq!(
            requirement,
            format!(
                "identifier \"{identity}\" and anchor apple generic \
                 and certificate leaf[field.1.2.840.113635.100.6.1.13] \
                 and certificate leaf[subject.OU] = \"{team}\" \
                 and certificate 1[field.1.2.840.113635.100.6.2.6]"
            )
        );
        assert!(requirement.parse::<SecRequirement>().is_ok());
    }
}

/// [behaviour] Wake opens only the app bundle this service runs inside.
#[test]
fn wake_targets_the_bundle_around_this_service() {
    assert_eq!(
        app_bundle_of(Path::new(
            "/Applications/Ottto.app/Contents/Helpers/ottto-service"
        )),
        Some(Path::new("/Applications/Ottto.app").to_path_buf())
    );
    for executable in [
        "/opt/homebrew/bin/ottto-service",
        "/Applications/Ottto.app/Contents/MacOS/ottto-service",
        "/tmp/Ottto/Contents/Helpers/ottto-service",
    ] {
        assert_eq!(app_bundle_of(Path::new(executable)), None, "{executable}");
    }
}

/// [behaviour] A native approval's answer is retained for its approval id, and a retired attempt
/// keeps its approvals retired.
#[test]
fn queue_keeps_the_retained_native_answer() {
    let channel = Channel::new(FakeServer::default());
    let approval = |index| SignKind::Approval {
        attempt_id: format!("attempt_{index}"),
        approval_id: format!("approval_{index}"),
    };
    channel.hello(1);
    let queue = &channel.queue;
    let deadline = unix_now() + 60;
    let first = queue.enqueue(approval(0), vec![0], deadline).unwrap();
    channel.send(1, "cloud_sign_poll", json!({}));
    assert_eq!(
        channel.send(
            1,
            "cloud_sign_result",
            json!({"request_id": first.request_id, "outcome": "declined"}),
        )["ok"],
        true,
    );
    assert_eq!(
        queue
            .enqueue(approval(0), vec![0], deadline)
            .unwrap()
            .request_id,
        first.request_id,
    );
    assert_eq!(
        queue.approval_outcome(&first.request_id),
        Some(SignOutcome::Declined)
    );
    queue.cancel_attempt("attempt_0");
    let replay = queue.enqueue(approval(0), vec![0], deadline).unwrap();
    assert_eq!(replay.request_id, first.request_id);
    assert_eq!(
        queue.approval_outcome(&replay.request_id),
        Some(SignOutcome::Superseded)
    );
}

/// [behaviour] A browser approval link opens only on the web origin paired with the run's API,
/// for production and staging alike, and never on a crossed pair.
#[test]
fn approval_link_uses_the_runs_paired_web_origin() {
    use super::agent::approval_browser_url;
    let id = "44444444-4444-4444-8444-444444444444";
    let path = format!("/connections/cloud-approve?attempt={id}");
    for (api, web) in [
        ("https://api.ottto.net", "https://app.ottto.net"),
        (
            "https://staging.tail21f014.ts.net:8443",
            "https://staging.tail21f014.ts.net",
        ),
    ] {
        let expected = Some(format!("{web}{path}"));
        assert_eq!(approval_browser_url(api, id, &path), expected, "{api}");
        assert_eq!(
            approval_browser_url(api, id, &format!("{web}{path}")),
            expected,
            "{api}"
        );
    }
    for (api, offered) in [
        (
            "https://api.ottto.net",
            format!("https://staging.tail21f014.ts.net{path}"),
        ),
        (
            "https://staging.tail21f014.ts.net:8443",
            format!("https://app.ottto.net{path}"),
        ),
        (
            "https://api.ottto.net",
            "https://app.ottto.net/connections/cloud-approve?attempt=other".to_string(),
        ),
        ("http://127.0.0.1:8000", path.clone()),
    ] {
        assert_eq!(
            approval_browser_url(api, id, &offered),
            None,
            "{api} {offered}"
        );
    }
}
