//! Byte-exact shapes of the signed cloud-key requests: the request hash over method, route
//! template and raw body, unpadded base64url, the proof header, the P-256 DER signature shape, the
//! frozen enrollment body and the device-write challenge facts the service checks.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use serde::Serialize;

/// The keys route as the server hashes it: the literal `{setup_run_id}` placeholder, never the
/// run id itself.
pub(super) const KEYS_ROUTE_TEMPLATE: &str =
    "/api/v1/setup-runs/{setup_run_id}/local-client/cloud/keys";

/// The `v` of every device-write challenge payload.
pub(super) const DEVICE_WRITE_VERSION: &str = "ottto.cloud_connect.device_write.v1";

/// The reverse code's alphabet: no 0, 1, I, L or O.
const REVERSE_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// The server's limit for one encoded public key.
const MAX_ENCODED_SPKI_CHARS: usize = 128;

/// `sha256(method + "\n" + route_template + "\n" + raw_body)` as lowercase hex: what a device
/// challenge commits to before the body is sent.
pub(super) fn request_sha256(method: &str, route_template: &str, raw_body: &[u8]) -> String {
    let mut message = Vec::with_capacity(method.len() + route_template.len() + 2 + raw_body.len());
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(route_template.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(raw_body);
    crate::hex::sha256_lower(&message)
}

pub(super) fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes unpadded base64url and accepts only its canonical form, the one the server accepts.
pub(super) fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == value).then_some(bytes)
}

/// An encoded public key the server can accept: canonical unpadded base64url, at most 128 chars.
pub(super) fn is_encoded_spki(value: &str) -> bool {
    value.len() <= MAX_ENCODED_SPKI_CHARS && decode_base64url(value).is_some()
}

/// Exactly six characters of the reverse-code alphabet. The app normalizes what the user typed
/// before it sends it.
pub(super) fn is_reverse_code(code: &str) -> bool {
    code.len() == 6
        && code
            .bytes()
            .all(|byte| REVERSE_CODE_ALPHABET.contains(&byte))
}

/// The browser's forward key code is eight RFC 4648 Base32 characters in two groups.
pub(super) fn is_key_code(code: &str) -> bool {
    code.len() == 9
        && code.bytes().enumerate().all(|(index, byte)| {
            if index == 4 {
                byte == b'-'
            } else {
                byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)
            }
        })
}

/// An ASN.1 DER `ECDSA-Sig-Value` the size of a P-256 signature: a SEQUENCE of two positive,
/// minimally encoded INTEGERs of at most 33 bytes each and nothing after them.
pub(super) fn is_p256_der_signature(der: &[u8]) -> bool {
    let [0x30, length, rest @ ..] = der else {
        return false;
    };
    if usize::from(*length) != rest.len() {
        return false;
    }
    der_positive_integer(rest)
        .and_then(der_positive_integer)
        .is_some_and(<[u8]>::is_empty)
}

fn der_positive_integer(input: &[u8]) -> Option<&[u8]> {
    let [0x02, length, rest @ ..] = input else {
        return None;
    };
    let length = usize::from(*length);
    if length == 0 || length > 33 || rest.len() < length {
        return None;
    }
    let (value, rest) = rest.split_at(length);
    let minimal = match value {
        [0x00, next, ..] => next & 0x80 != 0,
        [first, ..] => length <= 32 && first & 0x80 == 0,
        [] => false,
    };
    (minimal && value.iter().any(|byte| *byte != 0)).then_some(rest)
}

/// The `X-Ottto-*-Proof` header value: `{challenge_id}.{base64url(signature)}`.
pub(super) fn proof_header(challenge_id: &str, signature: &[u8]) -> String {
    format!("{challenge_id}.{}", encode_base64url(signature))
}

/// The enrollment body, serialized once and sent byte for byte, in the field order of the shared
/// enrollment fixture.
#[derive(Serialize)]
pub(super) struct EnrollBody<'a> {
    pub(super) key_claim_id: &'a str,
    pub(super) device_key_spki_b64: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) approval_key_spki_b64: Option<&'a str>,
    pub(super) reverse_code: &'a str,
}

impl EnrollBody<'_> {
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("string fields always serialize")
    }
}

/// A device challenge request: `C1 POST device-challenges`. Enroll and revoke send no attempt.
#[derive(Debug, Clone, Copy, Serialize)]
pub(super) struct ChallengeRequest<'a> {
    pub(super) operation: &'a str,
    pub(super) attempt_id: Option<&'a str>,
    pub(super) request_sha256: &'a str,
}

impl ChallengeRequest<'_> {
    /// The longest challenge the server issues for this operation, in seconds.
    fn max_lifetime(&self) -> i64 {
        if self.operation == "enroll" {
            300
        } else {
            60
        }
    }
}

/// How far ahead of this Mac's clock a challenge may expire beyond its lifetime.
const CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Deserialize)]
struct DeviceWriteFacts {
    v: String,
    challenge_id: String,
    run_id: String,
    org_id: String,
    operation: String,
    attempt_id: Option<String>,
    request_sha256: String,
    iat: i64,
    exp: i64,
}

/// A device-write challenge whose signed facts match the request it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CheckedChallenge {
    pub(super) challenge_id: String,
    pub(super) payload_b64: String,
    /// The challenge's expiry, Unix seconds, from the signed payload.
    pub(super) expires_at: i64,
}

/// Checks the payload the server will verify the signature against before the app signs it: the
/// version, the challenge id it was returned with, the run and organization the request was sent
/// on, the operation, attempt and request hash asked for, and a live expiry no longer than the
/// operation allows. The device write and its enroll, revoke and attempt requests share this one
/// check.
pub(super) fn checked_challenge(
    challenge_id: &str,
    payload_b64: &str,
    request: &ChallengeRequest<'_>,
    run_id: &str,
    org_id: &str,
    now: i64,
) -> Option<CheckedChallenge> {
    let payload = decode_base64url(payload_b64)?;
    let facts = serde_json::from_slice::<DeviceWriteFacts>(&payload).ok()?;
    let lifetime = request.max_lifetime();
    (ottto_protocol::cloud_uuid(challenge_id)
        && facts.v == DEVICE_WRITE_VERSION
        && facts.challenge_id == challenge_id
        && facts.run_id == run_id
        && facts.org_id == org_id
        && facts.operation == request.operation
        && facts.attempt_id.as_deref() == request.attempt_id
        && facts.request_sha256 == request.request_sha256
        && facts.exp > now
        && facts.exp <= now + lifetime + CLOCK_SKEW_SECONDS
        && (1..=lifetime).contains(&(facts.exp - facts.iat)))
    .then(|| CheckedChallenge {
        challenge_id: challenge_id.to_string(),
        payload_b64: payload_b64.to_string(),
        expires_at: facts.exp,
    })
}
