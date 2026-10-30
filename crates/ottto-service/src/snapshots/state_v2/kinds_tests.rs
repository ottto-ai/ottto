//! Integration fixtures; compiled locally, executed only in later CI.
use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn binding() -> super::super::super::scan_index_persistence::Binding {
        super::super::super::scan_index_persistence::Binding {
            source: super::super::super::scan_index_persistence::Source::Claude,
            namespace_hash: "a".repeat(64),
        }
    }
    fn store() -> (Self, sqlite::Sqlite) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-kinds-integration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let mut db = sqlite::Sqlite::create_import(&dir.join("index.v2.sqlite.import")).unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        db.control(
            "identity",
            &Identity {
                format: FORMAT,
                db_id: "synthetic-integration".into(),
                binding: Self::binding(),
                fence_generation: 0,
            },
        )
        .unwrap();
        db.control("generation", &0_u64).unwrap();
        (Self(dir), db)
    }
    fn live_store() -> (Self, sqlite::Sqlite) {
        let (scratch, db) = Self::store();
        db.finish_import().unwrap();
        let mut db = sqlite::Sqlite::open(
            &scratch.0.join("index.v2.sqlite.import"),
            &Identity {
                format: FORMAT,
                db_id: "synthetic-integration".into(),
                binding: Self::binding(),
                fence_generation: 0,
            },
        )
        .unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        (scratch, db)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> ScanIndex {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/scan_index/real-shaped-v1.json"
    ))
    .unwrap();
    let mut index: ScanIndex = serde_json::from_value(fixture["logical"].clone()).unwrap();
    index.generation = 0;
    index.upload_context_fingerprint = Some("/synthetic/exact-context".into());
    index
}
fn commit_populate(db: &mut sqlite::Sqlite, index: &ScanIndex) {
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut cx = KindCx {
        binding: Some(Scratch::binding()),
        ..Default::default()
    };
    populate(index, &mut tx, &mut cx).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
}
#[test]
fn all_groups_share_one_snapshot_and_roundtrip_real_v1_without_losing_context_or_membership() {
    let (_scratch, mut db) = Scratch::store();
    let mut index = fixture();
    commit_populate(&mut db, &index);
    index.generation = 1;
    let (restored, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&index).unwrap()
    );
    assert_eq!(
        restored.decode_holds.v2_provenance(),
        index.decode_holds.v2_provenance()
    );
    assert!(cx.valid && cx.accounts_ready && !cx.misc_rows.is_empty());
    // Account hydration must not replace the common context and discard MISC
    // inventory or the source binding while installing its own resident headers.
    assert_eq!(cx.binding, Some(Scratch::binding()));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let mut after = None;
    let mut owners = 0;
    loop {
        let page = tx
            .scan_kind(
                &RecordKind::parse("family.requests").unwrap(),
                after.as_ref(),
                128,
            )
            .unwrap();
        if page.is_empty() {
            break;
        }
        owners += page.len();
        after = page.last().map(|h| h.key.clone());
    }
    let expected: usize = index
        .claude_usage_family_pending
        .values()
        .map(|p| 1 + p.member_request_id_hashes.len())
        .sum();
    assert_eq!(owners, expected);
}
#[test]
fn incomplete_census_group_cannot_escape_as_a_partially_hydrated_graph() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&RowKey::record("v1_field.census_shadow", Vec::new(), 0).unwrap())
        .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(hydrate(&mut db, Scratch::binding()).is_err());
}
#[test]
fn unchanged_groups_preserve_bytes_and_a_context_error_refuses_reuse() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation = 2;
    let before = cx.account_rows.clone();
    cx.preflight(&prev, &next, &mut kinds_files::NoResumeHooks)
        .unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    delta(&prev, &next, &mut tx, &mut cx, std::iter::empty::<String>()).unwrap();
    let outcome = tx.commit(1, 2);
    assert_eq!(outcome, DurableCommitOutcome::Committed(2));
    cx.post_commit(&outcome, &mut kinds_files::NoResumeHooks)
        .unwrap();
    assert_eq!(cx.account_rows, before);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    assert!(delta(&next, &next, &mut tx, &mut cx, ["unknown_money_class"]).is_err());
    assert!(!cx.valid);
    assert!(delta(&next, &next, &mut tx, &mut cx, std::iter::empty::<String>()).is_err());
}
#[test]
fn noop_resume_adapter_cannot_publish_new_file_progress() {
    let prev = ScanIndex::default();
    let next = fixture();
    let mut cx = KindCx {
        binding: Some(Scratch::binding()),
        ..Default::default()
    };
    assert!(cx
        .preflight(&prev, &next, &mut kinds_files::NoResumeHooks)
        .is_err());
    assert!(cx.prepared.is_none());
}

struct Stored(Vec<u8>);
impl Value for Stored {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&self.0)?;
        Ok(())
    }
}
#[test]
fn last_shared_literal_release_marks_erasure_in_the_deleting_transaction_and_rollback_keeps_it() {
    let (_scratch, mut db) = Scratch::live_store();
    let evidence = interning::RequestEvidence::Account {
        prefixes: "/synthetic/private-prefix",
        fingerprint: "literal/fp",
        identity_revision: Some("literal/rev"),
        hash_count: None,
    };
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let id = interning::intern_request_set(&mut tx, &evidence).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        interning::release_request_set(&mut tx, id).unwrap();
        // Dropping the transaction preserves both the reference and privacy state.
    }
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = tx.get(&RowKey::RequestSet(id)).unwrap().unwrap();
    let mut value = Vec::new();
    tx.read_value(&h, &mut value).unwrap();
    let mut strings = BTreeSet::new();
    private_paths(&h, &Stored(value), &mut |s| {
        strings.insert(s.to_owned());
        Ok(())
    })
    .unwrap();
    assert!(strings.contains("/synthetic/private-prefix"));
    interning::release_request_set(&mut tx, id).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&RowKey::RequestSet(id)).unwrap().is_none());
    let marker = tx
        .get(&RowKey::Meta("erasure_pending".into()))
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    tx.read_value(&marker, &mut bytes).unwrap();
    assert_eq!(serde_json::from_slice::<u64>(&bytes).unwrap(), 2);
}

#[test]
fn foreign_source_and_registered_but_unmapped_money_kinds_refuse_hydration() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let mut other = Scratch::binding();
    other.namespace_hash = "b".repeat(64);
    assert!(hydrate(&mut db, other).is_err());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        key: &RowKey::record("v1_field.census_money_marks", Vec::new(), 0).unwrap(),
        fixed: &Fixed::None,
        value_version: 1,
        value: &Stored(b"null".to_vec()),
    })
    .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(hydrate(&mut db, Scratch::binding())
        .err()
        .unwrap()
        .to_string()
        .contains("state_v2_unmapped_kind"));
}
#[test]
fn shared_privacy_dispatch_preserves_both_census_domains_and_account_exclusion_literals() {
    // Census's numeric domain contains no literal text; the string domain and
    // the independent account exclusion encoding retain exact spellings.
    for (payload, expected, count) in [
        (vec![1, 0, 0, 0, 0, 0, 0, 0, 7], None, 1),
        (
            {
                let mut bytes = vec![2];
                packed::Json(&BTreeSet::from(["/synthetic/private-membership"]))
                    .write(&mut bytes)
                    .unwrap();
                bytes
            },
            Some("/synthetic/private-membership"),
            1,
        ),
        (
            br#"["/synthetic/private-exclusion"]"#.to_vec(),
            Some("/synthetic/private-exclusion"),
            1,
        ),
    ] {
        let (_scratch, mut db) = Scratch::store();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let id = interning::intern_request_set(
            &mut tx,
            &interning::RequestEvidence::Census {
                hashes: &Stored(payload),
                hash_count: Some(count),
            },
        )
        .unwrap();
        let h = tx.get(&RowKey::RequestSet(id)).unwrap().unwrap();
        let mut bytes = Vec::new();
        tx.read_value(&h, &mut bytes).unwrap();
        let mut texts = Vec::new();
        private_paths(&h, &Stored(bytes), &mut |s| {
            texts.push(s.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            texts,
            expected.into_iter().map(str::to_owned).collect::<Vec<_>>()
        );
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    }
}
