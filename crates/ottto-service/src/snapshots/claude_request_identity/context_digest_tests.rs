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

    bind_session_context_key(Some(&attribution(4)));
    assert_ne!(keyed, accepted::session_context_digest(email).unwrap());
}

/// Without a key nothing is stored and nothing explains an organization change.
#[test]
fn no_key_stores_no_field_and_fails_closed() {
    bind_session_context_key(None);
    let mut markers = None;
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
    note_marker_line(&mut markers, &org(ORG_1), 0);
    note_marker_line(&mut markers, &sentence("two@example.invalid"), 2);
    note_marker_line(&mut markers, &org(ORG_2), 2);
    let markers = markers.unwrap();
    assert_eq!(markers.context_digest, None);
    assert_eq!(markers.context_position, Some(0));
    assert!(matches!(
        markers.verdict(0, false),
        MarkerVerdict::Trusted(_)
    ));
    assert_eq!(markers.verdict(2, false), MarkerVerdict::UntrustedFlip);
}

/// A missing digest keeps the first-sentence rule, and a real sentence change
/// under one key still flips and explains the organization change.
#[test]
fn missing_digest_is_a_first_sentence_and_a_real_change_still_flips() {
    let mut markers = None;
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
    let state = markers.as_ref().unwrap();
    assert!(!state.context_changed);
    note_marker_line(&mut markers, &org(ORG_1), 0);
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 1);

    note_marker_line(&mut markers, &sentence("two@example.invalid"), 2);
    let state = markers.as_ref().unwrap();
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
}

/// Each post-first-bind key change: a scrubbed parse takes the next sentence as a
/// fresh baseline, so the next org flip is not trusted, even if the sentence did
/// change. With a key, a real change after that baseline still explains a flip.
#[test]
fn scrubbed_digest_is_a_fresh_baseline_and_trusts_no_flip() {
    for (from, to) in [(Some(1), Some(2)), (Some(1), None), (None, Some(2))] {
        for next in ["one@example.invalid", "two@example.invalid"] {
            bind_session_context_key(from.map(attribution).as_ref());
            let mut markers = None;
            note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
            note_marker_line(&mut markers, &org(ORG_1), 0);
            assert!(bind_session_context_key(to.map(attribution).as_ref()));
            markers.as_mut().unwrap().scrub_context_digest();
            let state = markers.as_ref().unwrap();
            assert_eq!(state.context_digest, None);
            assert!(!state.context_changed);
            assert_eq!(state.entries.len(), 1, "markers are kept");
            assert!(matches!(state.verdict(0, false), MarkerVerdict::Trusted(_)));

            note_marker_line(&mut markers, &sentence(next), 1);
            assert!(!markers.as_ref().unwrap().context_changed);
            note_marker_line(&mut markers, &org(ORG_2), 1);
            assert_eq!(
                markers.as_ref().unwrap().verdict(1, false),
                MarkerVerdict::UntrustedFlip
            );

            if to.is_some() {
                note_marker_line(&mut markers, &org(ORG_2), 2);
                note_marker_line(&mut markers, &sentence("three@example.invalid"), 3);
                assert!(markers.as_ref().unwrap().context_changed);
                note_marker_line(&mut markers, &org(ORG_1), 3);
                assert!(matches!(
                    markers.as_ref().unwrap().verdict(3, false),
                    MarkerVerdict::Trusted(_)
                ));
            }
        }
    }
}

/// A change seen under the old key but not yet spent on a flip does not survive
/// the scrub, and neither does a blank sentence's digest pass as a first sentence.
#[test]
fn scrub_drops_a_pending_change_and_remembers_a_blank_sentence() {
    bind_session_context_key(Some(&attribution(1)));
    let mut markers = None;
    note_marker_line(&mut markers, &sentence("one@example.invalid"), 0);
    note_marker_line(&mut markers, &org(ORG_1), 0);
    note_marker_line(&mut markers, &sentence("two@example.invalid"), 1);
    assert!(markers.as_ref().unwrap().context_changed);
    bind_session_context_key(Some(&attribution(2)));
    markers.as_mut().unwrap().scrub_context_digest();
    note_marker_line(&mut markers, &sentence("two@example.invalid"), 2);
    note_marker_line(&mut markers, &org(ORG_2), 2);
    assert_eq!(
        markers.as_ref().unwrap().verdict(2, false),
        MarkerVerdict::UntrustedFlip
    );

    let mut blank = None;
    note_marker_line(&mut blank, &sentence(""), 0);
    note_marker_line(&mut blank, &org(ORG_1), 0);
    bind_session_context_key(Some(&attribution(1)));
    blank.as_mut().unwrap().scrub_context_digest();
    note_marker_line(&mut blank, &sentence(""), 1);
    assert!(!blank.as_ref().unwrap().context_changed);
    note_marker_line(&mut blank, &org(ORG_2), 1);
    let blank = blank.unwrap();
    assert_eq!(blank.verdict(1, false), MarkerVerdict::UntrustedFlip);
}

/// SOURCE condition 1 with no sentence digest to clear: a blank no-key sentence
/// or a lone marker leaves no position, and still no flip is trusted afterwards.
/// One count per scrubbed parse.
#[test]
fn scrub_without_a_digest_still_makes_the_next_sentence_a_baseline() {
    take_context_digest_scrubs_for_test();
    for before in [
        vec![sentence(""), org(ORG_1)],
        vec![sentence("")],
        vec![org(ORG_1)],
    ] {
        bind_session_context_key(None);
        let mut markers = None;
        for line in &before {
            note_marker_line(&mut markers, line, 0);
        }
        assert!(bind_session_context_key(Some(&attribution(1))));
        markers.as_mut().unwrap().scrub_context_digest();
        assert_eq!(take_context_digest_scrubs_for_test(), 1);
        note_marker_line(&mut markers, &org(ORG_1), 0);
        note_marker_line(&mut markers, &sentence("one@example.invalid"), 1);
        assert!(!markers.as_ref().unwrap().context_changed);
        note_marker_line(&mut markers, &org(ORG_2), 1);
        assert_eq!(
            markers.as_ref().unwrap().verdict(1, false),
            MarkerVerdict::UntrustedFlip
        );
    }
    // The count reaches the page line's identity counts.
    OrgMarkers::default().scrub_context_digest();
    assert_eq!(
        serde_json::to_value(take_identity_counts()).unwrap()["claude_context_digest_scrubs"],
        1
    );
}

/// A key change is reported, and it scrubs retained digests. A process's first
/// bind is not one: no Claude parse can exist before it.
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
