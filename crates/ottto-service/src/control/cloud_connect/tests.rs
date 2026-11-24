use super::queue::unix_now;
use super::queue::SignKind;
use super::queue::SignOutcome;
use super::queue::SignQueue;
use super::queue::SignQueueError;
use super::queue::MAX_LIVE_SIGN_REQUESTS;
use super::resolve_signer_start;
use super::server::ClaimStartBody;
use super::server::ClaimStarted;
use super::server::ClaimState;
use super::server::CloudKeyServer;
use super::server::DeviceChallenge;
use super::server::Enrolled;
use super::server::Revoked;
use super::server::ServerError;
use super::server::{check_refresh_binding, send_with_refresh};
use super::signer;
use super::template::template_bytes_match;
use super::template::template_url;
use super::template::TemplateError;
use super::template::TemplatePin;
use super::wake::app_bundle_of;
use super::wire;
use super::SignerOff;
use super::SignerStartFacts;
use super::{verified_template_url, TemplatePinId};
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
    /// Return a challenge whose signed hash differs from the one asked for.
    tamper_challenge: bool,
    challenges: RefCell<Vec<(String, String)>>,
    enrolls: RefCell<Vec<SentEnrollment>>,
    revokes: RefCell<Vec<String>>,
}

impl CloudKeyServer for FakeServer {
    fn start_claim(&self, _body: &ClaimStartBody<'_>) -> Result<ClaimStarted, ServerError> {
        let (claim_url, key_code) = self.claim_fields.unwrap_or((CLAIM_URL, "AB23-EFG7"));
        Ok(ClaimStarted {
            key_claim_id: CLAIM_ID.to_string(),
            claim_url: claim_url.to_string(),
            key_code: key_code.to_string(),
            expires_at: "2026-11-24T12:00:00Z".to_string(),
        })
    }

    fn claim_state(&self, _key_claim_id: &str) -> Result<ClaimState, ServerError> {
        Ok(ClaimState {
            state: "awaiting_code".to_string(),
        })
    }

    fn device_challenge(
        &self,
        operation: &str,
        request_sha256: &str,
    ) -> Result<DeviceChallenge, ServerError> {
        self.challenges
            .borrow_mut()
            .push((operation.to_string(), request_sha256.to_string()));
        let signed_hash = if self.tamper_challenge {
            "0".repeat(64)
        } else {
            request_sha256.to_string()
        };
        let payload = json!({
            "v": wire::DEVICE_WRITE_VERSION,
            "challenge_id": CHALLENGE_ID,
            "operation": operation,
            "request_sha256": signed_hash,
            "exp": unix_now() + 60,
        });
        Ok(DeviceChallenge {
            challenge_id: CHALLENGE_ID.to_string(),
            payload_bytes: wire::encode_base64url(payload.to_string().as_bytes()),
        })
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

/// [behaviour] The request hash covers the method, the literal route template and the raw body
/// (shared vector with the server's formula), and revoke hashes an empty body.
#[test]
fn request_hash_matches_the_server_formula() {
    let body = wire::EnrollBody {
        device_key_spki_b64: "BBBB",
        approval_key_spki_b64: Some("CCCC"),
        key_claim_id: CLAIM_ID,
        reverse_code: "ABC234",
    }
    .to_bytes();
    assert_eq!(
        String::from_utf8(body.clone()).unwrap(),
        r#"{"device_key_spki_b64":"BBBB","approval_key_spki_b64":"CCCC","key_claim_id":"11111111-2222-4333-8444-555555555555","reverse_code":"ABC234"}"#
    );
    assert_eq!(
        wire::request_sha256("POST", wire::KEYS_ROUTE_TEMPLATE, &body),
        "1ee02ddbf0394f813dff846fe9f84916ebbd2a087be38f8d5412d9e4cb59c12f"
    );
    assert_eq!(
        wire::request_sha256("DELETE", wire::KEYS_ROUTE_TEMPLATE, b""),
        "e6c222dbaffc4ee17434df7299139697f56ed4bb0615a9a30f7cfdcaab903dff"
    );
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
    let mut malformed = revoke.clone();
    malformed["device_signature_b64"] = json!("AAAA");
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
/// one, at most four requests are live, and expired requests are refused.
#[test]
fn queue_supersedes_caps_and_expires() {
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
    for _ in 0..3 {
        let queued = queue
            .enqueue(SignKind::DeviceProof, b"d".to_vec(), unix_now() + 60)
            .unwrap();
        assert!(!queued.wake_app);
    }
    assert_eq!(
        queue.enqueue(SignKind::DeviceProof, b"d".to_vec(), unix_now() + 60),
        Err(SignQueueError::Full)
    );
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

/// [behaviour] A rejected renewal keeps the old approval. A valid renewal can reuse its slot.
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
    for _ in 1..super::MAX_LIVE_SIGN_REQUESTS {
        queue
            .enqueue(SignKind::DeviceProof, vec![], unix_now() + 60)
            .unwrap();
    }
    assert_eq!(
        queue.enqueue(approval("attempt", "expired"), vec![], unix_now()),
        Err(SignQueueError::AlreadyExpired)
    );
    assert_eq!(
        queue.enqueue(approval("other", "new"), vec![], unix_now() + 60),
        Err(SignQueueError::Full)
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
    assert_eq!(live.len(), super::MAX_LIVE_SIGN_REQUESTS);
    assert!(live
        .iter()
        .any(|request| request.request_id == replacement.request_id));
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

/// [behaviour] The template URL is built from a pinned key and version only, and the served bytes
/// must hash to the pin.
#[test]
fn template_url_comes_from_the_pin_and_bytes_must_match() {
    let pin = TemplatePin {
        key: "aws/bedrock-cli-read-role/v1.yaml",
        version_id: "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY",
        sha256: "5cde0f1298f41f7d1c8b907a36992a7a513225a2615bd6e307bf1a9149b06b40",
    };
    assert_eq!(
        template_url(&pin).unwrap(),
        "https://ottto-cloud-connect-templates.s3.us-east-1.amazonaws.com/aws/bedrock-cli-read-role/v1.yaml?versionId=3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY"
    );
    assert_eq!(template_bytes_match(&pin, b"template"), Ok(()));
    assert_eq!(
        template_bytes_match(&pin, b"template "),
        Err(TemplateError::DigestMismatch)
    );
    for (key, version_id) in [
        ("aws/../v1.yaml", "v"),
        ("https://evil/v1.yaml", "v"),
        ("aws/role/v1.json", "v"),
        ("aws/role/v1.yaml", "v&x=1"),
        ("aws/role/v1.yaml", ""),
    ] {
        let bad = TemplatePin {
            key,
            version_id,
            ..pin
        };
        assert_eq!(
            template_url(&bad),
            Err(TemplateError::InvalidPin),
            "{key} {version_id}"
        );
    }
}

/// [behaviour] A server cannot enable an unpublished template by supplying a complete pin.
#[test]
fn unpublished_template_has_no_server_fallback() {
    let id = TemplatePinId::BedrockCliReadRoleV1;
    assert!(!id.matches_metadata(
        "aws/bedrock-cli-read-role/v1.yaml",
        "object-version",
        &crate::hex::sha256_lower(b"server-selected bytes")
    ));
    assert_eq!(verified_template_url(id), Err(TemplateError::InvalidPin));
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

#[test]
fn queue_caps_distinct_native_approvals_and_keeps_the_retained_answer() {
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
    for index in 1..MAX_LIVE_SIGN_REQUESTS {
        let next = queue.enqueue(approval(index), vec![0], deadline).unwrap();
        queue.cancel(&next.request_id);
    }
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
    assert_eq!(
        queue.enqueue(approval(MAX_LIVE_SIGN_REQUESTS), vec![0], deadline),
        Err(SignQueueError::ApprovalRateLimited),
    );
    assert!(queue
        .enqueue(SignKind::DeviceProof, vec![0], deadline)
        .is_ok());
    queue.cancel_attempt("attempt_0");
    let replay = queue.enqueue(approval(0), vec![0], deadline).unwrap();
    assert_eq!(replay.request_id, first.request_id);
    assert_eq!(
        queue.approval_outcome(&replay.request_id),
        Some(SignOutcome::Superseded)
    );
}
