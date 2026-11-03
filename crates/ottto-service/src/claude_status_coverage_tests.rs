use super::*;

/// [regress] A subagent file and a project named `projects` map to one folder.
#[test]
fn transcript_paths_map_to_their_config_dir_key() {
    let slot = home_key(Path::new("/Users/someone/.claude-slot"));
    assert_eq!(home_key(Path::new("/Users/someone/.claude-slot/")), slot);
    for transcript in [
        "/Users/someone/.claude-slot/projects/-Users-someone-repo/session.jsonl",
        "/Users/someone/.claude-slot/projects/-Users-someone-projects/session/subagents/agent-a.jsonl",
    ] {
        assert_eq!(transcript_home_key(Path::new(transcript)), Some(slot));
    }
    assert_ne!(
        transcript_home_key(Path::new(
            "/Users/someone/.claude/projects/-x/session.jsonl"
        )),
        Some(slot)
    );
    assert_eq!(
        transcript_home_key(Path::new("/tmp/loose/session.jsonl")),
        None
    );
}

const KEY: [u8; 32] = [0x42; 32];
const ADDRESS: &str = "one@example.test";

fn bind(key: [u8; 32]) -> bool {
    bind_address_key(Some(Zeroizing::new(key)))
}

/// [privacy] Without the key nothing can be tested against the digest.
#[test]
fn the_address_digest_is_keyed_and_has_its_own_domain() {
    bind(KEY);
    let digest = address_digest(" One@Example.test ").unwrap();
    assert_eq!(digest.len(), 64);
    assert_eq!(digest, keyed_text_digest(&KEY, ADDRESS_DOMAIN, ADDRESS));
    assert_ne!(digest, format!("{:x}", Sha256::digest(ADDRESS.as_bytes())));
    assert_ne!(
        digest,
        keyed_text_digest(&KEY, "claude_session_context:v1", ADDRESS)
    );
    assert_ne!(
        digest,
        keyed_text_digest(&KEY, "claude_accepted_key_epoch:v2", ADDRESS)
    );
    assert_ne!(
        digest,
        keyed_text_digest(&[0x43; 32], ADDRESS_DOMAIN, ADDRESS)
    );
}

/// [privacy] No key: no digest, no report email.
#[test]
fn no_key_gives_no_field() {
    forget_addresses();
    assert_eq!(address_digest(ADDRESS), None);
    observe_with_email("folder".into(), OwnerReport::default(), Some(ADDRESS));
    assert_eq!(snapshot()["folder"].email, None);
}

/// [regress] A digest under another key is never compared, and forgetting ends
/// both. Every change is reported, gaining a key too, so retained logins scrub.
#[test]
fn a_key_change_drops_every_report_email_and_forgetting_drops_the_key() {
    forget_addresses();
    assert!(bind(KEY), "gaining a key is a change");
    observe_with_email("folder".into(), OwnerReport::default(), Some(ADDRESS));
    assert_eq!(snapshot()["folder"].email, address_digest(ADDRESS));
    assert!(!bind(KEY), "the same key changes nothing");
    assert_eq!(snapshot()["folder"].email, address_digest(ADDRESS));

    assert!(bind([0x43; 32]));
    assert_eq!(snapshot()["folder"].email, None);

    observe_with_email("folder".into(), OwnerReport::default(), Some(ADDRESS));
    assert!(bind_address_key(None));
    assert_eq!(snapshot()["folder"].email, None);
    assert_eq!(address_digest(ADDRESS), None);
    assert!(!bind_address_key(None));
}
