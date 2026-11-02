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

/// The keyed value against an independent HMAC, the old unkeyed one, a second
/// key and another domain under the same key.
#[test]
fn digest_is_the_keyed_domain_separated_hmac_not_the_plain_sha() {
    let email = "one@example.invalid";
    let key = [3; 32];
    set_test_session_context_key(Some(key));
    let keyed = accepted::session_context_digest(email).unwrap();
    assert_eq!(keyed.len(), 64);
    let domain = "claude_session_context:v1";
    assert_eq!(keyed[..16], hmac_hex(&key, json!([domain]))[..16]);
    assert_eq!(keyed[16..], hmac_hex(&key, json!([domain, email]))[..48]);

    let plain = format!(
        "{:x}",
        sha2::Sha256::new()
            .chain_update(b"ottto-claude-org-marker-context:v1\0")
            .chain_update(email.as_bytes())
            .finalize()
    );
    assert_ne!(keyed, plain);
    assert_ne!(keyed[16..], plain[..48]);
    assert!(!accepted::session_context_digest_is_current(&plain));
    let other_domain = hmac_hex(&key, json!(["claude_folder_login_address:v1", email]));
    assert_ne!(keyed[16..], other_domain[..48]);

    set_test_session_context_key(Some([4; 32]));
    let rotated = accepted::session_context_digest(email).unwrap();
    assert_ne!(keyed[16..], rotated[16..]);
    assert_ne!(keyed[..16], rotated[..16]);
    assert!(!accepted::session_context_digest_is_current(&keyed));
    assert!(accepted::session_context_digest_is_current(&rotated));
}

/// Without a key nothing is stored and nothing explains an organization change:
/// the flip stays refused and no email qualifies.
#[test]
fn no_key_stores_no_field_and_fails_closed() {
    set_test_session_context_key(None);
    let mut markers = None;
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
    note_marker_line(&mut markers, &org(ORG_1), 0);
    note_marker_line(&mut markers, &sentence("two@example.invalid"), 2);
    note_marker_line(&mut markers, &org(ORG_2), 2);
    let markers = markers.unwrap();
    assert_eq!(markers.context_digest, None);
    assert_eq!(markers.context_position, None);
    assert_eq!(markers.context_flip_position, Some(2));
    assert_eq!(markers.email_home(5), None);
    assert!(markers.context_digest_is_current());
    assert!(matches!(
        markers.verdict(0, false),
        MarkerVerdict::Trusted(_)
    ));
    assert_eq!(markers.verdict(2, false), MarkerVerdict::UntrustedFlip);
}

/// A stored digest of the earlier scheme or an earlier key is no previous value:
/// the same sentence then records no flip, and an organization change stays
/// unexplained rather than wrongly trusted. Recompute leaves a current value.
#[test]
fn old_scheme_or_other_key_digest_is_no_previous_and_recomputes() {
    let email = "one@example.invalid";
    let old_scheme = format!(
        "{:x}",
        sha2::Sha256::new()
            .chain_update(b"ottto-claude-org-marker-context:v1\0")
            .chain_update(email.as_bytes())
            .finalize()
    );
    let other_key = accepted::session_context_digest(email).unwrap();
    set_test_session_context_key(Some([9; 32]));
    for stored in [old_scheme, other_key] {
        let mut markers = None;
        note_marker_line(&mut markers, &org(ORG_1), 0);
        let state = markers.as_mut().unwrap();
        state.context_digest = Some(stored);
        assert!(!state.context_digest_is_current());

        note_marker_line(&mut markers, &sentence(email), 1);
        let state = markers.as_ref().unwrap();
        assert_eq!(state.context_flip_position, None, "no flip");
        assert!(!state.context_changed, "no change to trust a flip with");
        assert_eq!(
            state.context_digest,
            accepted::session_context_digest(email),
            "recomputed under the bound key"
        );

        note_marker_line(&mut markers, &org(ORG_2), 2);
        assert_eq!(
            markers.as_ref().unwrap().verdict(2, false),
            MarkerVerdict::UntrustedFlip
        );
    }
}

/// A missing digest keeps today's first-sentence rule, and a real sentence
/// change under one key still flips and explains the organization change.
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

/// Rebinding reports a change of key only; that report drops retained parses.
#[test]
fn bind_reports_only_a_key_change() {
    use base64::Engine as _;
    let context = |byte: u8| {
        crate::session_attribution::SessionAttributionContext::from_activity_hint(
            SnapshotSource::ClaudeCode,
            std::path::Path::new("/nonexistent/context-digest"),
            true,
            Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap()
    };
    assert!(bind_session_context_key(Some(&context(1))));
    assert!(!bind_session_context_key(Some(&context(1))));
    assert!(bind_session_context_key(Some(&context(2))));
    // Fixtures keep a key without attribution; the fail-closed test removes it.
    assert!(!bind_session_context_key(None));
    assert!(accepted::session_context_digest("x").is_some());
}

/// Codex scans before Claude's first prepare, so the first bind of a process is
/// not a change: it must not drop the parses an earlier source just retained.
#[test]
fn the_first_bind_of_a_process_is_no_change() {
    use base64::Engine as _;
    let context = crate::session_attribution::SessionAttributionContext::from_activity_hint(
        SnapshotSource::ClaudeCode,
        std::path::Path::new("/nonexistent/context-digest"),
        true,
        Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1; 32])),
        Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .unwrap();
    unbind_test_session_context_key();
    assert_eq!(accepted::session_context_digest("x"), None);
    assert!(!bind_session_context_key(Some(&context)));
    assert!(accepted::session_context_digest("x").is_some());
    assert!(!bind_session_context_key(Some(&context)));
}
