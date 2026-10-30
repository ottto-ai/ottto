//! Synthetic production planner/selected-save regressions, executed in CI only.
use super::*;
use import::{ClaudeMapper, Mapper};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf, Identity);
impl Fixture {
    fn new() -> (Self, sqlite::Sqlite, ScanIndex, KindCx) {
        Self::with_presence(BTreeMap::new())
    }
    fn with_presence(
        presence: BTreeMap<String, bool>,
    ) -> (Self, sqlite::Sqlite, ScanIndex, KindCx) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-selected-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let f = Self(
            dir,
            Identity {
                format: FORMAT,
                db_id: "synthetic-selected-custody".into(),
                fence_generation: 0,
                binding: super::super::super::scan_index_persistence::Binding {
                    source: super::super::super::scan_index_persistence::Source::Claude,
                    namespace_hash: "a".repeat(64),
                },
            },
        );
        let mut db = sqlite::Sqlite::create_import(&f.path()).unwrap();
        db.path_extractor(kinds::private_paths);
        db.reference_extractor(kinds::references);
        db.control("identity", &f.1).unwrap();
        let index = ScanIndex::default();
        let mut cx = KindCx::default();
        cx.binding = Some(f.1.binding.clone());
        cx.presence = presence;
        let mut tx = db.begin(TxnMode::Write).unwrap();
        kinds::populate(&index, &mut tx, &mut cx).unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
        db.finish_import().unwrap();
        let mut db = f.open();
        let (index, cx) = kinds::hydrate(&mut db, f.1.binding.clone()).unwrap();
        (f, db, index, cx)
    }
    fn path(&self) -> PathBuf {
        self.0.join("index.v2.sqlite.import")
    }
    fn open(&self) -> sqlite::Sqlite {
        let mut db = sqlite::Sqlite::open(&self.path(), &self.1).unwrap();
        db.path_extractor(kinds::private_paths);
        db.reference_extractor(kinds::references);
        db
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn production_delta_requires_admission_and_committed_context_survives_success() {
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    next.upload_context_fingerprint = Some("synthetic-policy".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    assert!(ClaudeMapper.delta(&mut tx, &next, None).is_err());
    drop(tx);
    assert!(ClaudeMapper
        .selected_save(&mut db, &f.1, &prev, &mut next, &mut cx)
        .unwrap());
    assert_eq!(next.generation, prev.generation + 1);
    let (saved, saved_cx) = kinds::hydrate(&mut db, f.1.binding.clone()).unwrap();
    assert_eq!(
        saved.upload_context_fingerprint,
        next.upload_context_fingerprint
    );
    assert_eq!(cx.misc_rows, saved_cx.misc_rows);
    assert_eq!(cx.committed, saved_cx.committed);
    assert!(
        carry(&mut db.begin(TxnMode::Read).unwrap(), &f.1, next.generation)
            .unwrap()
            .is_none()
    );
}

#[test]
fn selected_subset_keeps_exact_deferred_values_and_tombstones_across_reopen_then_drains() {
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    for n in 0..2_600 {
        next.claude_account_deferred_holds
            .insert(format!("root-{n:05}"), format!("reason-{n:05}"));
    }
    let expected = next.claude_account_deferred_holds.clone();
    let err = ClaudeMapper
        .selected_save(&mut db, &f.1, &prev, &mut next, &mut cx)
        .unwrap_err();
    assert_eq!(err.downcast_ref::<Hold>(), Some(&Hold::SaveAdmission));
    assert!(next.claude_account_deferred_holds.len() < expected.len());
    assert!(!next.claude_account_deferred_holds.is_empty());
    let generation = next.generation;
    drop(db);
    let mut db = f.open();
    let (mut base, mut cx) = kinds::hydrate(&mut db, f.1.binding.clone()).unwrap();
    assert_eq!(base.generation, generation);
    let deferred = carry(&mut db.begin(TxnMode::Read).unwrap(), &f.1, generation)
        .unwrap()
        .unwrap();
    assert!(!deferred.mutations.is_empty());
    let restored = restore(&mut db, &f.1, &base).unwrap().unwrap();
    assert_eq!(restored.claude_account_deferred_holds, expected);
    ClaudeMapper
        .restore_selected(&mut db, &mut base, &mut cx)
        .unwrap();
    assert_eq!(base.claude_account_deferred_holds, expected);
    assert!(restore(&mut db, &f.1, &base).unwrap().is_none());

    // Deletions are custody too: the old values must not reappear after restart.
    let prev = base;
    let mut next = prev.clone();
    next.claude_account_deferred_holds.clear();
    let err = ClaudeMapper
        .selected_save(&mut db, &f.1, &prev, &mut next, &mut cx)
        .unwrap_err();
    assert_eq!(err.downcast_ref::<Hold>(), Some(&Hold::SaveAdmission));
    let deferred = carry(&mut db.begin(TxnMode::Read).unwrap(), &f.1, next.generation)
        .unwrap()
        .unwrap();
    assert!(deferred.mutations.iter().all(|m| m.after.is_none()));
    drop(db);
    let mut db = f.open();
    let (mut base, mut cx) = kinds::hydrate(&mut db, f.1.binding.clone()).unwrap();
    ClaudeMapper
        .restore_selected(&mut db, &mut base, &mut cx)
        .unwrap();
    assert!(base.claude_account_deferred_holds.is_empty());
    assert!(db.read_control::<u64>("erasure_pending").unwrap().is_some());
}

#[test]
fn default_r1_refuses_active_file_advancement_without_any_write_or_custody_publication() {
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    let entry: super::super::super::ScanIndexEntry = serde_json::from_value(serde_json::json!({
        "size_bytes": 17, "modified_unix_seconds": 1,
        "source_file_fingerprint": "synthetic-source", "last_snapshot_fingerprint": ""
    }))
    .unwrap();
    next.files.insert("/synthetic/active".into(), entry);
    let error = ClaudeMapper
        .selected_save(&mut db, &f.1, &prev, &mut next, &mut cx)
        .unwrap_err();
    assert!(error.to_string().contains("state_v2_resume_stage_required"));
    assert_eq!(db.stamp().unwrap().0, prev.generation);
    assert!(restore(&mut db, &f.1, &prev).unwrap().is_none());
    assert!(next.files.contains_key("/synthetic/active"));
}

#[test]
fn deferred_binding_and_before_headers_are_authenticated_before_restoration() {
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    for n in 0..2_600 {
        next.claude_account_deferred_holds
            .insert(format!("root-{n:05}"), "held".into());
    }
    assert!(ClaudeMapper
        .selected_save(&mut db, &f.1, &prev, &mut next, &mut cx)
        .is_err());
    let mut foreign = f.1.clone();
    foreign.db_id = "another-db".into();
    assert!(restore(&mut db, &foreign, &next).is_err());
    let mut old_generation = next.clone();
    old_generation.generation -= 1;
    assert!(restore(&mut db, &f.1, &old_generation).is_err());
    let mut pending = carry(&mut db.begin(TxnMode::Read).unwrap(), &f.1, next.generation)
        .unwrap()
        .unwrap();
    let m = pending.mutations[0].clone();
    let h = m.after.as_ref().unwrap();
    pending.generation += 1;
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        key: &m.key,
        fixed: &h.fixed,
        value_version: h.value_version,
        value: m.value.as_ref().unwrap().as_ref(),
    })
    .unwrap();
    tx.put(RowInput {
        key: &carry_key().unwrap(),
        fixed: &Fixed::None,
        value_version: 1,
        value: &packed::Json(&pending),
    })
    .unwrap();
    assert_eq!(
        tx.commit(next.generation, pending.generation),
        DurableCommitOutcome::Committed(pending.generation)
    );
    next.generation = pending.generation;
    assert!(restore(&mut db, &f.1, &next)
        .unwrap_err()
        .to_string()
        .contains("state_v2_deferred_stale"));
}

#[test]
fn production_writer_capability_check_precedes_r1_planning_and_staging() {
    #[derive(Default)]
    struct Hooks(bool);
    impl kinds_files::ResumeHooks for Hooks {
        fn plan(
            &mut self,
            _: &ScanIndex,
            _: &ScanIndex,
            _: &BTreeMap<String, kinds_files::ResumeCheckpoint>,
        ) -> Result<kinds_files::StagedCheckpoints> {
            self.0 = true;
            Ok(Default::default())
        }
    }
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    let mut hooks = Hooks::default();
    sqlite::future_writer_for_test(&mut db);
    assert!(ClaudeMapper
        .save_admitted(&mut db, &f.1, &prev, &mut next, &mut cx, &mut hooks)
        .is_err());
    assert!(!hooks.0);
    assert_eq!(next.generation, prev.generation);
}

#[test]
fn original_presence_registry_includes_non_misc_groups_without_normalization() {
    // Exercise the same root registry that Original inventories. Missing fields
    // stay explicit false; equality must not discard other owners.
    let presence: BTreeMap<String, bool> = super::super::super::lenient_decode::FIELDS
        .iter()
        .map(|name| {
            (
                (*name).into(),
                matches!(
                    *name,
                    "files"
                        | "generation"
                        | "schema_version"
                        | "claude_account_family_pending"
                        | "claude_request_census"
                ),
            )
        })
        .collect();
    let (f, mut db, _, _) = Fixture::with_presence(presence.clone());
    let (_, cx) = kinds::hydrate(&mut db, f.1.binding.clone()).unwrap();
    assert_eq!(cx.presence, presence);
}

#[test]
fn expanded_custody_admission_precedes_packed_publication() {
    let value = serde_json::json!({"source_file_fingerprint": "a".repeat(64), "version": 1});
    let expanded = serde_json::to_vec(&value).unwrap();
    let mut packed = Vec::new();
    packed::Json(&value).write(&mut packed).unwrap();
    assert!(packed.len() < expanded.len());
    assert!(admit_json(&value, packed.len()).is_err());
    admit_json(&value, expanded.len()).unwrap();
}

#[test]
fn post_commit_callback_error_retains_confirmed_generation_and_requires_reopen() {
    struct FailGc;
    impl kinds_files::ResumeHooks for FailGc {
        fn post_commit(
            &mut self,
            _: u64,
            _: &BTreeMap<String, kinds_files::ResumeCheckpoint>,
        ) -> Result<()> {
            bail!("synthetic_post_commit_error")
        }
    }
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    next.upload_context_fingerprint = Some("confirmed-policy".into());
    assert!(ClaudeMapper
        .save_admitted(&mut db, &f.1, &prev, &mut next, &mut cx, &mut FailGc)
        .is_err());
    assert_eq!(next.generation, prev.generation + 1);
    assert!(cx.ambiguous);
    let (saved, _) = kinds::hydrate(&mut db, f.1.binding.clone()).unwrap();
    assert_eq!(saved.generation, next.generation);
    assert_eq!(
        saved.upload_context_fingerprint.as_deref(),
        Some("confirmed-policy")
    );
}

#[test]
fn overlay_merges_tombstones_with_indexed_kind_family_and_candidate_queries() {
    struct IndexedOnly<'a>(&'a mut dyn Transaction);
    impl Transaction for IndexedOnly<'_> {
        fn get(&mut self, key: &RowKey) -> Result<Option<Header>> {
            self.0.get(key)
        }
        fn read_value(&mut self, h: &Header, out: &mut dyn Write) -> Result<()> {
            self.0.read_value(h, out)
        }
        fn put(&mut self, row: RowInput<'_>) -> Result<Header> {
            self.0.put(row)
        }
        fn delete(&mut self, key: &RowKey) -> Result<bool> {
            self.0.delete(key)
        }
        fn value_matches(&mut self, h: &Header, v: &dyn Value) -> Result<bool> {
            self.0.value_matches(h, v)
        }
        fn request_set_candidates(
            &mut self,
            digest: &[u8; 32],
            after: u64,
            n: usize,
        ) -> Result<Vec<Header>> {
            self.0.request_set_candidates(digest, after, n)
        }
        fn adjust_refs(&mut self, key: &RowKey, delta: i64) -> Result<u64> {
            self.0.adjust_refs(key, delta)
        }
        fn scan_prefix(
            &mut self,
            _: RowPrefix,
            _: Option<&RowKey>,
            _: usize,
        ) -> Result<Vec<Header>> {
            bail!("unexpected_full_table_scan")
        }
        fn scan_kind(
            &mut self,
            k: &RecordKind,
            after: Option<&RowKey>,
            n: usize,
        ) -> Result<Vec<Header>> {
            self.0.scan_kind(k, after, n)
        }
        fn scan_family(
            &mut self,
            k: &RecordKind,
            bytes: &[u8],
            after: Option<u64>,
            n: usize,
        ) -> Result<Vec<Header>> {
            self.0.scan_family(k, bytes, after, n)
        }
        fn commit(self, _: u64, _: u64) -> DurableCommitOutcome {
            DurableCommitOutcome::NotPublished
        }
    }
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    next.claude_account_deferred_holds
        .insert("a".into(), "held-a".into());
    next.claude_account_deferred_holds
        .insert("b".into(), "held-b".into());
    ClaudeMapper
        .selected_save(&mut db, &f.1, &prev, &mut next, &mut cx)
        .unwrap();
    let kind = RecordKind::parse("proof.deferred_account").unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let base = tx.scan_kind(&kind, None, 2).unwrap();
    let mut indexed = IndexedOnly(&mut tx);
    let mut overlay = Recording::new(&mut indexed);
    overlay.delete(&base[0].key).unwrap();
    assert_eq!(
        overlay.scan_kind(&kind, None, 1).unwrap(),
        [base[1].clone()]
    );
    let RowKey::Record { key_bytes, .. } = &base[1].key else {
        unreachable!()
    };
    assert_eq!(
        overlay.scan_family(&kind, key_bytes, None, 1).unwrap(),
        [base[1].clone()]
    );
    assert!(overlay
        .request_set_candidates(&[9; 32], 0, 1)
        .unwrap()
        .is_empty());
}

#[test]
fn streamed_family_units_preserve_more_than_eight_mib_of_deferred_payload() {
    let (f, mut db, prev, mut cx) = Fixture::new();
    let mut next = prev.clone();
    for family in ["large-a", "large-b"] {
        let fingerprints: BTreeMap<_, _> = (0..2_300)
            .map(|n| (format!("member-{n:05}"), "x".repeat(KEY_BYTES)))
            .collect();
        next.claude_account_family_witnesses.insert(
            family.into(),
            serde_json::from_value(serde_json::json!({
                "account_identifier_hash": "a".repeat(64),
                "evidence_request_count": 0,
                "members": {},
                "member_request_id_fingerprints": fingerprints,
            }))
            .unwrap(),
        );
    }
    let expected = next.claude_account_family_witnesses.clone();
    let error = ClaudeMapper
        .selected_save(&mut db, &f.1, &prev, &mut next, &mut cx)
        .unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveAdmission));
    assert_eq!(next.claude_account_family_witnesses.len(), 1);
    let pending = carry(&mut db.begin(TxnMode::Read).unwrap(), &f.1, next.generation)
        .unwrap()
        .unwrap();
    let bytes: u64 = pending
        .mutations
        .iter()
        .filter_map(|m| m.value.as_ref())
        .map(|p| p.len())
        .sum();
    assert!(bytes > SCRATCH as u64);
    drop(pending);
    drop(db);
    let mut db = f.open();
    let (mut base, mut cx) = kinds::hydrate(&mut db, f.1.binding.clone()).unwrap();
    let restored = restore(&mut db, &f.1, &base).unwrap().unwrap();
    assert_eq!(restored.claude_account_family_witnesses, expected);
    ClaudeMapper
        .restore_selected(&mut db, &mut base, &mut cx)
        .unwrap();
    assert_eq!(base.claude_account_family_witnesses, expected);
    assert!(restore(&mut db, &f.1, &base).unwrap().is_none());
}
