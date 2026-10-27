//! Pins the canonical FILE set digests byte for byte. Persisted
//! `last_snapshot_fingerprint` / `last_upload_body_witness` values and every
//! reader that compares them depend on this exact encoding, so a change here
//! is an on-disk format change, not a refactor.
use super::*;

/// Finalization's encoding before the shared helpers existed, kept verbatim
/// as the reference the pinned values were taken from.
fn finalization_reference_hex(domain: &[u8], members: &BTreeSet<String>) -> String {
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, domain);
    for member in members {
        update_length_prefixed(&mut digest, member.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn set(members: &[&str]) -> BTreeSet<String> {
    members.iter().copied().map(String::from).collect()
}

#[test]
fn snapshot_file_entity_set_digest_is_pinned() {
    const PINNED: &str = "551e2329baa4465a19faff2a4af8c05f142feb95e7a04d4b715883faef167a84";
    let fingerprints = set(&["z", "entity-bb", "entity-a"]);

    assert_eq!(
        finalization_reference_hex(b"snapshot_file_entity_set:v1", &fingerprints),
        PINNED
    );
    assert_eq!(snapshot_file_entity_set_hex(&fingerprints), PINNED);
    assert_eq!(
        codex_digest_from_hex(PINNED),
        Some(snapshot_file_entity_set_digest(fingerprints))
    );
    // A sorted, deduplicated borrowed slice encodes identically.
    assert_eq!(
        snapshot_file_entity_set_hex(["entity-a", "entity-bb", "z"]),
        PINNED
    );
}

#[test]
fn snapshot_file_upload_body_set_digest_is_pinned() {
    const PINNED: &str = "00a7d33798f252ad239b03bb051a7a899f86fa890cbeac5928c3bc4e8e15fc1e";
    let witnesses = set(&["body:22", "body:1"]);

    assert_eq!(
        finalization_reference_hex(b"snapshot_file_upload_body_set:v1", &witnesses),
        PINNED
    );
    assert_eq!(snapshot_file_upload_body_set_hex(&witnesses), PINNED);
    assert_eq!(
        codex_digest_from_hex(PINNED),
        Some(snapshot_file_upload_body_set_digest(witnesses))
    );
    // `adopted_upload_progress_acks` feeds a sorted, deduplicated Vec<&str>.
    let mut borrowed = vec!["body:22", "body:1", "body:22"];
    borrowed.sort_unstable();
    borrowed.dedup();
    assert_eq!(
        codex_digest_from_hex(PINNED),
        Some(snapshot_file_upload_body_set_digest(borrowed))
    );
}

#[test]
fn file_set_digest_domains_are_distinct() {
    let members = set(&["same"]);
    assert_ne!(
        snapshot_file_entity_set_hex(&members),
        snapshot_file_upload_body_set_hex(members)
    );
}
