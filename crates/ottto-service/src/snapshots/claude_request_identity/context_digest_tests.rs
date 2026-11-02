use super::*;
use hmac::{Hmac, Mac};
use serde_json::json;

const ORG_1: &str = "11111111-1111-4111-8111-111111111111";
const ORG_2: &str = "22222222-2222-4222-8222-222222222222";

fn sentence(email: &str) -> Value {
    json!({"type": "attachment", "attachment": {"type": "session_context", "context": {"userEmail": email}}})
}

fn org(uuid: &str) -> Value {
    json!({"type": "attachment", "attachment": {"type": "credential_org", "organizationUuid": uuid}})
}

fn hmac_hex(key: &[u8; 32], fields: Value) -> String {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(b"ottto:session-attribution:");
    mac.update(&serde_json::to_vec(&fields).unwrap());
    format!("{:x}", mac.finalize().into_bytes())
}

fn attribution(byte: u8) -> crate::session_attribution::SessionAttributionContext {
    use base64::Engine as _;
    crate::session_attribution::SessionAttributionContext::from_activity_hint(
        SnapshotSource::ClaudeCode,
        std::path::Path::new("/nonexistent/context-digest"),
        true,
        Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])),
        Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .unwrap()
}

/// The keyed value against an independent HMAC, the old unkeyed one, a second
/// key and another domain under the same key.
#[test]
fn digest_is_the_keyed_domain_separated_hmac_not_the_plain_sha() {
    let email = "one@example.invalid";
    bind_session_context_key(Some(&attribution(3)));
    let keyed = accepted::session_context_digest(email).unwrap();
    assert_eq!(
        keyed,
        hmac_hex(&[3; 32], json!(["claude_session_context:v1", email]))
    );

    let plain = format!(
        "{:x}",
        sha2::Sha256::new()
            .chain_update(b"ottto-claude-org-marker-context:v1\0")
            .chain_update(email.as_bytes())
            .finalize()
    );
    assert_ne!(keyed, plain);
    assert_ne!(
        keyed,
        hmac_hex(&[3; 32], json!(["claude_folder_login_address:v1", email]))
    );

    bind_session_context_key(Some(&attribution(4)));
    assert_ne!(keyed, accepted::session_context_digest(email).unwrap());
}

/// Without a key nothing is stored and nothing explains an organization change.
/// The first email still qualifies, until a later sentence that cannot be compared.
#[test]
fn no_key_stores_no_field_and_fails_closed() {
    bind_session_context_key(None);
    let mut markers = None;
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
    note_marker_line(&mut markers, &org(ORG_1), 0);
    note_marker_line(&mut markers, &sentence("two@example.invalid"), 2);
    note_marker_line(&mut markers, &org(ORG_2), 2);
    let mut markers = markers.unwrap();
    assert_eq!(markers.context_digest, None);
    assert_eq!(markers.context_position, Some(0));
    assert_eq!(markers.context_flip_position, Some(2));
    markers.home = Some(crate::claude_status_coverage::home_key(
        std::path::Path::new("/synthetic/home"),
    ));
    assert!(markers.email_home(1).is_some());
    assert!(markers.email_home(2).is_none());
    assert!(matches!(
        markers.verdict(0, false),
        MarkerVerdict::Trusted(_)
    ));
    assert_eq!(markers.verdict(2, false), MarkerVerdict::UntrustedFlip);
}

/// Without a key, a second sentence before any marker also ends the email.
#[test]
fn no_key_second_sentence_before_a_marker_ends_the_email() {
    bind_session_context_key(None);
    let mut markers = None;
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
    note_marker_line(&mut markers, &sentence("two@example.invalid"), 1);
    assert_eq!(markers.unwrap().context_flip_position, Some(1));
}

/// A missing digest keeps the first-sentence rule, and a real sentence change
/// under one key still flips and explains the organization change.
#[test]
fn missing_digest_is_a_first_sentence_and_a_real_change_still_flips() {
    let mut markers = None;
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
    let state = markers.as_ref().unwrap();
    assert!(!state.context_changed);
    assert_eq!(state.context_flip_position, None);
    note_marker_line(&mut markers, &org(ORG_1), 0);
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 1);
    assert_eq!(markers.as_ref().unwrap().context_flip_position, None);

    note_marker_line(&mut markers, &sentence("two@example.invalid"), 2);
    let state = markers.as_ref().unwrap();
    assert_eq!(state.context_flip_position, Some(2));
    assert!(state.context_changed);
    note_marker_line(&mut markers, &org(ORG_2), 2);
    assert!(matches!(
        markers.as_ref().unwrap().verdict(2, false),
        MarkerVerdict::Trusted(_)
    ));

    let mut first_after_marker = None;
    note_marker_line(&mut first_after_marker, &org(ORG_1), 0);
    note_marker_line(&mut first_after_marker, &sentence("one@example.invalid"), 1);
    assert!(first_after_marker.as_ref().unwrap().context_changed);
    assert_eq!(first_after_marker.unwrap().context_flip_position, None);
}

/// A key change is reported, and it drops retained parses. A process's first
/// bind is not one: Codex scans first, and must keep what it just retained.
#[test]
fn bind_reports_only_a_key_change() {
    accepted::unbind_test_session_context_key();
    assert_eq!(accepted::session_context_digest("x"), None);
    assert!(!bind_session_context_key(Some(&attribution(1))));
    assert!(accepted::session_context_digest("x").is_some());
    assert!(!bind_session_context_key(Some(&attribution(1))));
    assert!(bind_session_context_key(Some(&attribution(2))));
    assert!(bind_session_context_key(None));
    assert_eq!(accepted::session_context_digest("x"), None);
}
