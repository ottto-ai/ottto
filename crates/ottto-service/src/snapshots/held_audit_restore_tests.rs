//! Completed restore must not widen authority/family retention by carrying a
//! sealed-prefix tag solely because that different hold restored a previous
//! entry.
use super::*;
/// [behaviour] Completed restore carries a new sealed-prefix tag only for
/// account holds.

#[test]
fn completed_restore_carries_new_sampled_debt_only_for_account_holds() {
    let dir = crate::test_scratch::ScratchDir::new("account-only-sampled-carry");
    let key = local_index_key(&dir.join("session.jsonl"));
    let mut previous = ScanIndex::default();
    let mut entry = super::tests::manifest_index_entry(Some("committed-body"));
    entry.source_file_fingerprint = "committed-source".into();
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
    previous.files.insert(key.clone(), entry);
    previous
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["committed-body".into()]));
    let held = BTreeSet::from(["held-body".to_string()]);
    assert!(!previous.files[&key].has_sampled_tag());
    for (account_held, recorded) in [(false, false), (true, false), (true, true)] {
        let mut working = previous.clone();
        let entry = working.files.get_mut(&key).unwrap();
        entry.source_file_fingerprint = "working-source".into();
        entry.last_snapshot_fingerprint = Some("held-body".into());
        working
            .file_snapshot_fingerprints
            .insert(key.clone(), held.clone());
        assert!(working.mark_sealed_prefix(&key, "working-source"));
        assert!(working.files[&key].has_prefix_provenance());
        if recorded {
            working
                .claude_account_deferred_holds
                .insert(key.clone(), "working-source".into());
        }
        let account_fingerprints = if account_held {
            held.clone()
        } else {
            BTreeSet::new()
        };
        let result =
            working.into_locally_held_keys_reverted(&previous, &held, &account_fingerprints);
        assert_eq!(
            result.files[&key].has_prefix_provenance(),
            account_held,
            "account={account_held}, recorded={recorded}: authority/family hold adds no prefix tag"
        );
        assert_eq!(
            result.file_snapshot_fingerprints.get(&key),
            previous.file_snapshot_fingerprints.get(&key)
        );
        assert_eq!(
            result.accepted_snapshot_fingerprints, previous.accepted_snapshot_fingerprints,
            "restoration grants no ACK"
        );
        assert_eq!(
            result.files[&key].source_file_fingerprint.is_empty(),
            account_held && !recorded,
            "unrecorded account retries keep their genuine reparse debt"
        );
    }
}
