use super::*;

/// [regress] Rebinding changes only the route prefix. Physical equality never
/// treats a new plaintext inode as a continuation of the original certificate.
#[test]
fn rebind_preserves_the_certificate_and_replacement_is_not_equivalent() {
    let scratch = crate::test_scratch::ScratchDir::canonical("codex-carry-proof");
    let root = scratch.join("sessions");
    fs::create_dir_all(&root).unwrap();
    let old = root.join("rollout-session.jsonl");
    let new = root.join("moved.jsonl");
    let route = scratch.join("index.json");
    fs::write(&old, b"synthetic usage").unwrap();
    let metadata = fs::metadata(&old).unwrap();
    let body = tail_source::carry_head_for_test(&route, &root, &old, &metadata);
    let rebound = tail_source::carry_codex_head(&route, &root, &old, &root, &new, &body).unwrap();
    assert!(
        tail_source::HeadIdentity::new(&route, SnapshotSource::Codex, &root, &new, true)
            .check(&rebound)
            .is_ok()
    );
    assert!(
        tail_source::HeadIdentity::new(&route, SnapshotSource::Codex, &root, &old, true)
            .check(&rebound)
            .is_err()
    );
    assert_eq!(
        tail_source::certified_content_stamp(&body),
        tail_source::certified_content_stamp(&rebound)
    );
    assert!(tail_source::certified_physical_matches(&rebound, &metadata));
    fs::rename(&old, &new).unwrap();
    assert!(tail_source::certified_physical_matches(
        &rebound,
        &fs::metadata(&new).unwrap()
    ));
    fs::write(&old, b"synthetic usage").unwrap();
    assert!(!tail_source::certified_physical_matches(
        &rebound,
        &fs::metadata(&old).unwrap()
    ));
    assert!(tail_source::carry_codex_head(
        &scratch.join("wrong-index"),
        &root,
        &old,
        &root,
        &new,
        &body
    )
    .is_err());
    // Capture and key-epoch bytes are part of this exact suffix too.
    let changed: Vec<_> = body
        .iter()
        .zip(&rebound)
        .enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i))
        .collect();
    assert!(!changed.is_empty());
    assert!(changed.into_iter().all(|i| i < 32));
}
