//! Recovery-only selection over synthetic stores; never live provider state.
use super::*;

const PARENT: &str = "00000000-0000-4000-8000-000000000091";
const OTHER: &str = "00000000-0000-4000-8000-000000000092";

fn account_identity_bytes(item: &SnapshotItem) -> Vec<u8> {
    // Whole usage rows include account_identifier_hash, evidence_ref and every
    // identity_part. Exclude the deliberately changed lineage/display hashes.
    serde_json::to_vec(&json!({
        "source_session_id": item.source_session_id,
        "session_account_evidence": item.session_account_evidence,
        "model_usage": item.model_usage,
        "usage_buckets": item.usage_buckets,
        "request_evidence": item.request_evidence,
        "request_identity_refusals": item.request_identity_refusals,
        "cost": item.cost,
    }))
    .unwrap()
}

struct DesktopFixture {
    home: crate::test_scratch::ScratchDir,
    native: Fixture,
    store: PathBuf,
}
impl DesktopFixture {
    fn new() -> Self {
        let home = crate::test_scratch::ScratchDir::new("desktop-lineage-projection");
        let mut native = Fixture::new(1);
        let old = native.dir.clone();
        native.dir = home.join(".claude/projects");
        fs::create_dir_all(&native.dir).unwrap();
        let path = native.dir.join(format!("{}.jsonl", native.session));
        fs::rename(&native.path, &path).unwrap();
        native.path = path;
        fs::remove_dir_all(old).unwrap();
        // Direct store records carry no native account UUID. This isolates
        // selection from the independent new-owner completeness hold.
        let store = home.join("Library/Application Support/Claude/claude-code-sessions");
        fs::create_dir_all(&store).unwrap();
        for (id, desktop) in [(PARENT, "local_parent"), (OTHER, "local_other")] {
            fs::write(native.dir.join(format!("{id}.jsonl")), json!({
                "timestamp":"2026-08-02T06:59:00Z", "type":"assistant", "sessionId":id,
                "requestId":id, "message":{"model":"claude-haiku-4-5", "usage":{"input_tokens":3,"output_tokens":2}}
            }).to_string()+"\n").unwrap();
            fs::write(
                store.join(format!("{id}.json")),
                json!({
                    "cliSessionId":id,"sessionId":desktop
                })
                .to_string(),
            )
            .unwrap();
        }
        let f = Self {
            home,
            native,
            store,
        };
        f.edge(Some("local_parent"));
        f
    }
    fn edge(&self, parent: Option<&str>) {
        let mut row = json!({"cliSessionId":self.native.session,"sessionId":"local_child"});
        if let Some(parent) = parent {
            row["spawnedFrom"] = json!({"sessionId":parent});
        }
        fs::write(self.store.join("child.json"), row.to_string()).unwrap();
    }
    fn incomplete(index: &mut ScanIndex) {
        index.claude_desktop_identity_census_complete = false;
        index.claude_desktop_lineage_census_complete = false;
        index.claude_desktop_census_witness = None;
        index.claude_desktop_store_retry_not_before_unix_seconds =
            rfc3339_unix_seconds("2026-08-02T07:11:00Z");
    }
    fn run(&self, index: ScanIndex, at: &str) -> (Run, (u64, u64)) {
        let (run, rows) = crate::local_resource_diagnostics::capture(|| {
            // A fresh cache each time proves the consumed-byte upper path.
            let mut run = raw_scan_at(
                &self.native,
                index,
                Some(Arc::new(SharedCache::default())),
                true,
                at,
                |_| {},
            );
            finalize_scan_after_policy_with_body_witness(
                SOURCE,
                &mut run.result,
                &mut run.index,
                snapshot_upload_body_witness,
            );
            run
        });
        let sum = |field: &str| {
            rows.iter()
                .filter_map(|row| {
                    row["counts"]["desktop_metadata"]["lineage_edge_reoffer"][field].as_u64()
                })
                .sum()
        };
        (run, (sum("files"), sum("bytes")))
    }
    fn child_only(&self, run: &Run, parent: Option<&str>) {
        assert_eq!(
            run.result.snapshots.len(),
            1,
            "zero parent/unrelated offers"
        );
        let item = &run.result.snapshots[0];
        assert_eq!(item.source_session_id, self.native.session);
        let edge = item.attribution_facts.iter().find(|fact| {
            fact.field == "parent_session_ref"
                && fact.evidence.source_version == "claude_desktop_spawn:v1"
        });
        assert_eq!(edge.map(|fact| fact.value.as_str()), parent);
    }
    fn quiet_three(&self, mut index: ScanIndex) {
        for at in [
            "2026-08-02T07:14:00Z",
            "2026-08-02T07:16:00Z",
            "2026-08-02T07:18:00Z",
        ] {
            let (run, counts) = self.run(index, at);
            assert!(run.result.snapshots.is_empty());
            assert_eq!(run.native_bytes, 0);
            assert_eq!(counts, (0, 0));
            index = run.index;
        }
    }
}

#[test]
fn desktop_lineage_coverage_recovery_reoffers_one_parentless_child_then_quiet() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = DesktopFixture::new();
    let mut index = ScanIndex::default();
    let complete = ClaudeTitleMetadata::load_from_roots_with_index(
        std::slice::from_ref(&f.native.dir),
        &mut index,
        COLLECTED,
        true,
    );
    let dependencies = complete.lineage_revisions.clone();
    index.claude_desktop_completed_lineage = None;
    DesktopFixture::incomplete(&mut index);
    let (first, counts) = f.run(index, COLLECTED);
    assert_eq!(first.result.snapshots.len(), 3);
    assert_eq!(counts, (0, 0));
    let child = first
        .result
        .snapshots
        .iter()
        .find(|item| item.source_session_id == f.native.session)
        .unwrap();
    assert!(!child
        .attribution_facts
        .iter()
        .any(|fact| fact.field == "parent_session_ref"));
    let before_identity = account_identity_bytes(child);
    let index = settle(first);
    let mut proof = index.clone();
    let recovered_metadata = ClaudeTitleMetadata::load_from_roots_with_index(
        std::slice::from_ref(&f.native.dir),
        &mut proof,
        "2026-08-02T07:12:00Z",
        true,
    );
    assert_eq!(
        recovered_metadata.lineage_revisions, dependencies,
        "coverage alone recovers; no changed parent metadata trigger"
    );
    let (recovered, counts) = f.run(index, "2026-08-02T07:12:00Z");
    f.child_only(&recovered, Some(PARENT));
    assert_eq!(
        account_identity_bytes(&recovered.result.snapshots[0]),
        before_identity
    );
    let bytes = fs::metadata(&f.native.path).unwrap().len();
    assert_eq!(recovered.native_bytes, bytes);
    assert_eq!(counts, (1, bytes));
    f.quiet_three(settle(recovered));
}

#[test]
fn desktop_lineage_facts_preserve_account_identity_at_fixed_identity_coverage() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = DesktopFixture::new();
    let account = "a".repeat(64);
    let original = ClaudeDesktopIdentityEvidence {
        account_identifier_hash: Some(account.clone()),
        provider_workspace_hash: Some("b".repeat(64)),
        source_created_at: Some("2026-08-02T06:00:00Z".into()),
        imported: false,
    };
    let mut carriers = Vec::new();
    for identity_incomplete in [false, true] {
        let mut metadata = ClaudeTitleMetadata {
            account_identifier_hashes: BTreeMap::from([(
                f.native.session.clone(),
                BTreeSet::from([account.clone()]),
            )]),
            original_identity_evidence: BTreeMap::from([(
                f.native.session.clone(),
                BTreeSet::from([original.clone()]),
            )]),
            original_identity_census_incomplete: identity_incomplete,
            sidecar_census_incomplete: true,
            ..Default::default()
        };
        let parse = |metadata: &ClaudeTitleMetadata| {
            parse_claude_code_jsonl_file_with_title_metadata(
                &f.native.path,
                COLLECTED,
                "f".repeat(64),
                metadata,
                false,
            )
            .unwrap()
            .remove(0)
        };
        let before = parse(&metadata);
        assert!(!before
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "parent_session_ref"));
        metadata.sidecar_census_incomplete = false;
        metadata.spawn_lineage.insert(
            f.native.session.clone(),
            ClaudeDesktopSpawnLineage {
                parent_session_id: PARENT.into(),
            },
        );
        let after = parse(&metadata);
        for (field, value) in [
            ("parent_session_ref", PARENT),
            ("origin_kind", "agent_spawn"),
            ("agent_kind", "claude_desktop_session"),
        ] {
            assert!(after
                .attribution_facts
                .iter()
                .any(|fact| fact.field == field && fact.value == value));
        }
        assert!(!claude_snapshot_belongs_to_family(&after, PARENT));
        assert_eq!(
            account_identity_bytes(&before),
            account_identity_bytes(&after)
        );
        assert_eq!(
            exact_session_account_hash(&after).as_deref(),
            Some(account.as_str())
        );
        carriers.push(after.session_account_evidence.unwrap());
    }
    // Identity coverage is a different input: unlike lineage coverage, it
    // intentionally changes the creator disposition, never the account pair.
    assert_eq!(carriers[0].identity_disposition, Some("complete"));
    assert_eq!(carriers[1].identity_disposition, Some("missing"));
    carriers[1].identity_disposition = Some("complete");
    assert_eq!(
        serde_json::to_vec(&carriers[0]).unwrap(),
        serde_json::to_vec(&carriers[1]).unwrap()
    );
}

#[test]
fn desktop_lineage_flap_and_restart_keep_frozen_selector_without_reoffers() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = DesktopFixture::new();
    let (first, _) = f.run(ScanIndex::default(), COLLECTED);
    let fingerprint = first.metadata_fingerprint.clone();
    let mut index = settle(first);
    let frozen = index.claude_desktop_completed_lineage.clone();
    DesktopFixture::incomplete(&mut index);
    let path = f.home.join("index.json");
    index.save(&path).unwrap();
    let index = ScanIndex::load(&path).unwrap();
    assert_eq!(index.claude_desktop_completed_lineage, frozen);
    let (partial, counts) = f.run(index, "2026-08-02T07:10:10Z");
    assert_eq!(partial.metadata_fingerprint, fingerprint);
    assert_eq!(partial.index.claude_desktop_completed_lineage, frozen);
    assert!(partial.result.snapshots.is_empty());
    assert_eq!((partial.native_bytes, counts), (0, (0, 0)));
    let (recovered, counts) = f.run(partial.index, "2026-08-02T07:12:00Z");
    assert_eq!(recovered.metadata_fingerprint, fingerprint);
    assert!(recovered.result.snapshots.is_empty());
    assert_eq!((recovered.native_bytes, counts), (0, (0, 0)));
    f.quiet_three(recovered.index);
}

#[test]
fn desktop_lineage_complete_edge_change_and_removal_each_reoffer_once() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    for (next, parent) in [(Some("local_other"), Some(OTHER)), (None, None)] {
        let f = DesktopFixture::new();
        let (first, _) = f.run(ScanIndex::default(), COLLECTED);
        let index = settle(first);
        f.edge(next);
        let (changed, counts) = f.run(index, "2026-08-02T07:12:00Z");
        f.child_only(&changed, parent);
        let bytes = fs::metadata(&f.native.path).unwrap().len();
        assert_eq!(counts, (1, bytes));
        if parent.is_none() {
            assert_eq!(
                changed.index.claude_desktop_completed_lineage,
                Some(BTreeMap::new())
            );
        }
        f.quiet_three(settle(changed));
    }
}

#[test]
fn desktop_lineage_growth_while_incomplete_requires_one_recovery_offer_even_with_frozen_edge() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = DesktopFixture::new();
    let (first, _) = f.run(ScanIndex::default(), COLLECTED);
    let mut index = settle(first);
    DesktopFixture::incomplete(&mut index);
    f.native.append_transcript(1);
    let (partial, counts) = f.run(index, "2026-08-02T07:10:10Z");
    f.child_only(&partial, None);
    assert_eq!(counts, (0, 0));
    let index = settle(partial);
    let (recovered, counts) = f.run(index, "2026-08-02T07:12:00Z");
    f.child_only(&recovered, Some(PARENT));
    assert_eq!(counts, (1, fs::metadata(&f.native.path).unwrap().len()));
    f.quiet_three(settle(recovered));
}

#[test]
fn desktop_lineage_legacy_upgrade_and_old_save_dropping_selector_fields_are_bounded() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = DesktopFixture::new();
    let (first, _) = f.run(ScanIndex::default(), COLLECTED);
    let mut index = settle(first);
    // Reconstruct the released metadata-dependency hash, with no projection.
    let mut metadata = ClaudeTitleMetadata::load_from_roots_with_index(
        std::slice::from_ref(&f.native.dir),
        &mut index,
        "2026-08-02T07:12:00Z",
        true,
    );
    metadata.completed_lineage = None;
    let mut candidate = f.native.candidate(&f.native.path);
    prepare_owned_scan_candidate(
        SOURCE,
        &mut candidate,
        &CodexTitleMetadata::default(),
        &metadata,
        Some(&f.native.support),
    );
    let (candidate, _) = open_and_identify_scan_candidate(
        SOURCE,
        candidate,
        &mut ScanCensus::default(),
        rfc3339_unix_seconds(COLLECTED),
        BACKFILL_WINDOW_DAYS,
        crate::snapshots::DiscoveryRetention::unverified(&index.files),
    )
    .unwrap();
    let entry = index
        .files
        .get_mut(&local_index_key(&f.native.path))
        .unwrap();
    entry.source_file_fingerprint = candidate.source_file_fingerprint;
    index.claude_desktop_lineage_file_edges.clear();
    index.claude_desktop_completed_lineage = None;
    let (upgraded, counts) = f.run(index, "2026-08-02T07:12:00Z");
    // The already correct body can be suppressed as a semantic no-op. The
    // actual source revision is revisited once, never every unrelated file.
    assert_eq!(
        upgraded.native_bytes,
        fs::metadata(&f.native.path).unwrap().len()
    );
    assert!(upgraded.result.snapshots.len() <= 1);
    assert!(counts.0 <= 1);
    let index = settle(upgraded);
    let mut old_save = serde_json::to_value(&index).unwrap();
    old_save
        .as_object_mut()
        .unwrap()
        .remove("claude_desktop_completed_lineage");
    old_save
        .as_object_mut()
        .unwrap()
        .remove("claude_desktop_lineage_file_edges");
    let index: ScanIndex = serde_json::from_value(old_save).unwrap();
    f.edge(Some("local_other"));
    let (changed, counts) = f.run(index, "2026-08-02T07:13:00Z");
    f.child_only(&changed, Some(OTHER));
    assert_eq!(counts, (1, fs::metadata(&f.native.path).unwrap().len()));
    f.quiet_three(settle(changed));
}

#[test]
fn desktop_lineage_selector_canaries_never_reach_diagnostics_or_upload() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = DesktopFixture::new();
    let canary_child = "00000000-0000-4000-8000-00000000ca01";
    let canary_parent = "00000000-0000-4000-8000-00000000ca02";
    let mut index = ScanIndex {
        claude_desktop_completed_lineage: Some(BTreeMap::from([(
            canary_child.into(),
            canary_parent.into(),
        )])),
        ..ScanIndex::default()
    };
    DesktopFixture::incomplete(&mut index);
    let (run, rows) = crate::local_resource_diagnostics::capture(|| {
        let mut run = raw_scan_at(
            &f.native,
            index,
            Some(Arc::new(SharedCache::default())),
            true,
            COLLECTED,
            |_| {},
        );
        finalize_scan_after_policy_with_body_witness(
            SOURCE,
            &mut run.result,
            &mut run.index,
            snapshot_upload_body_witness,
        );
        run
    });
    let wire = serde_json::to_string(&batch(&run.result.snapshots)).unwrap();
    let diagnostics = serde_json::to_string(&rows).unwrap();
    let persisted = serde_json::to_string(&run.index).unwrap();
    for canary in [canary_child, canary_parent] {
        assert!(persisted.contains(canary));
        assert!(!wire.contains(canary));
        assert!(!diagnostics.contains(canary));
    }
}

#[test]
fn desktop_lineage_confirmed_empty_child_settles_edge_across_cold_restart() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = DesktopFixture::new();
    fs::write(
        &f.native.path,
        json!({
            "timestamp":"2026-08-02T06:59:00Z", "type":"user", "sessionId":f.native.session
        })
        .to_string()
            + "\n",
    )
    .unwrap();
    let (first, counts) = f.run(ScanIndex::default(), COLLECTED);
    assert_eq!(
        first.result.snapshots.len(),
        2,
        "only the usage-bearing parents emit"
    );
    assert_eq!(counts, (0, 0));
    let key = local_index_key(&f.native.path);
    assert!(first.index.confirmed_empty_files.contains(&key));
    assert_eq!(
        first.index.claude_desktop_lineage_file_edges[&key],
        desktop_lineage::edge_fingerprint(Some(PARENT))
    );
    let mut index = settle(first);
    let path = f.home.join("empty-index.json");
    index.save(&path).unwrap();
    let index = ScanIndex::load(&path).unwrap();
    f.quiet_three(index);
}
