// Unlike the older in-memory carry fixtures, scheduling fixtures cross the
// real strict save/load boundary. ACKs must therefore be canonical identities.
fn retry_durable_fixture(held: usize, healthy: usize) -> ScopedRetryFixture {
    let mut fixture = scoped_retry_fixture(0, held + healthy, false);
    // The initial empty start has no carry or scheduling obligation. Its
    // origin is intentionally omitted by the normal writer; seed the same
    // canonical empty shape before asserting exact durable custody below.
    assert!(fixture.index.claude_stale_family_carry.is_empty());
    fixture.index.claude_stale_family_carry = ClaudeStaleFamilyCarry::default();
    fixture.index.accepted_snapshot_fingerprints.clear();
    fixture.index.snapshot_activity_at.clear();
    let keys = fixture.index.files.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let entities = fixture
            .index
            .file_snapshot_fingerprints
            .get_mut(&key)
            .unwrap();
        *entities = entities
            .iter()
            .map(|body| format!("{:x}", Sha256::digest(body.as_bytes())))
            .collect();
        fixture
            .index
            .accepted_snapshot_fingerprints
            .extend(entities.iter().cloned());
        scoped_retry_accept_member(&mut fixture.index, &key);
    }
    for family in fixture.roots.iter().take(held) {
        let key = local_index_key(&fixture._scratch.join(format!("{family}.jsonl")));
        fixture.index.bind_retry_pending_claude_authority_for_test(
            family,
            BTreeMap::from([(
                family.clone(),
                fixture.index.files[&key].source_file_fingerprint.clone(),
            )]),
        );
    }
    fixture
}

fn retry_test_reload(index: &mut ScanIndex, path: &Path) -> ScanIndex {
    let accepted = index.accepted_snapshot_fingerprints.clone();
    let authority = serde_json::to_value(&index.claude_usage_authority_quarantine).unwrap();
    let admission = serde_json::to_value(&index.claude_stale_family_carry.origin).unwrap();
    let drops = claude_authority_drops_for_test();
    index.save(path).unwrap();
    let loaded = ScanIndex::load(path).unwrap();
    assert_eq!(
        loaded.accepted_snapshot_fingerprints, accepted,
        "strict persistence retains every ACK"
    );
    assert_eq!(
        serde_json::to_value(&loaded.claude_usage_authority_quarantine).unwrap(),
        authority,
        "strict persistence retains every bound authority record"
    );
    assert_eq!(
        serde_json::to_value(&loaded.claude_stale_family_carry.origin).unwrap(),
        admission,
        "strict persistence retains runnable admission debt"
    );
    assert_eq!(
        claude_authority_drops_for_test(),
        drops,
        "no malformed fixture authority was discarded"
    );
    loaded
}

fn retry_test_context(index: &mut ScanIndex, root: &Path) {
    let context = scan_traversal_context_fingerprint(
        SnapshotSource::ClaudeCode,
        &[root.to_owned()],
        index,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    traversal.context_fingerprint = context;
    traversal.scan_roots = vec![root.to_owned()];
}

// The classifier runs on Linux too; native carry allocation is intentionally
// separate. Duplicate identities and absent pending members must stay OWED.
#[test]
fn storage_only_refusal_requires_complete_accepted_unique_evidence() {
    let mut fixture = retry_durable_fixture(0, 1);
    let root = fixture.roots[0].clone();
    assert!(claude_retry_singleton_storage_only(&fixture.index, &root));
    let key = fixture.index.files.keys().next().unwrap().clone();
    let accepted = fixture.index.clone();
    fixture
        .index
        .claude_usage_family_pending
        .get_mut(&root)
        .unwrap()
        .invalid = true;
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture
        .index
        .claude_usage_family_pending
        .get_mut(&root)
        .unwrap()
        .member_request_id_hashes
        .insert(format!("{root}_agent-missing"), BTreeSet::new());
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture.index.files.insert(
        format!("/duplicate/{root}.jsonl"),
        fixture.index.files[&key].clone(),
    );
    fixture.index.file_snapshot_fingerprints.insert(
        format!("/duplicate/{root}.jsonl"),
        fixture.index.file_snapshot_fingerprints[&key].clone(),
    );
    let duplicate = format!("/duplicate/{root}.jsonl");
    scoped_retry_accept_member(&mut fixture.index, &duplicate);
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture.index.bind_retry_pending_claude_authority_for_test(
        &root,
        BTreeMap::from([(
            root.clone(),
            fixture.index.files[&key].source_file_fingerprint.clone(),
        )]),
    );
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture
        .index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted;
    fixture.index.accepted_snapshot_fingerprints.clear();
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
}
