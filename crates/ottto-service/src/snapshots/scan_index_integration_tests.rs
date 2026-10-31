use super::*;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    scratch: PathBuf,
    root: PathBuf,
    shards: PathBuf,
    manifest: Value,
}
impl Fixture {
    fn new() -> Self {
        let scratch = crate::test_scratch::private_dir("scanindex-integrated-unknown");
        let namespace = scratch.join("a".repeat(64));
        fs::create_dir(&namespace).unwrap();
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
        let root = namespace.join("claude_code-scan-index-v3.json");
        let shards = namespace.join("claude_code-scan-index-v3.json.shards");
        fs::create_dir(&shards).unwrap();
        fs::set_permissions(&shards, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/scan_index/real-shaped-v1.json"
        ))
        .unwrap();
        for (name, text) in fixture["payloads"].as_object().unwrap() {
            let path = shards.join(name);
            fs::write(&path, text.as_str().unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let manifest = serde_json::from_str(fixture["root"].as_str().unwrap()).unwrap();
        let value = Self {
            scratch,
            root,
            shards,
            manifest,
        };
        value.write_root();
        value
    }
    fn write_root(&self) {
        fs::write(&self.root, serde_json::to_vec(&self.manifest).unwrap()).unwrap();
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn bucket_path(&self, map: usize) -> PathBuf {
        let object = &self.manifest["objects"][map + 1];
        self.shards.join(format!(
            "{}-{:02x}-{}.json",
            ["account", "usage", "census"][map],
            object["slot"]["bucket"].as_u64().unwrap(),
            object["digest"].as_str().unwrap()
        ))
    }
    fn metadata_path(&self) -> PathBuf {
        self.shards.join(format!(
            "metadata-{}.json",
            self.manifest["objects"][0]["digest"].as_str().unwrap()
        ))
    }
    fn semantic_damage(&mut self, map: usize) {
        let old = self.bucket_path(map);
        let original: Value = serde_json::from_slice(&fs::read(&old).unwrap()).unwrap();
        let key = original.as_object().unwrap().keys().next().unwrap();
        let payload = serde_json::to_vec(&json!({key: null})).unwrap();
        self.rebind_object(map + 1, &payload);
        let new = self.bucket_path(map);
        fs::rename(old, &new).unwrap();
        fs::write(new, payload).unwrap();
    }
    fn rebind_object(&mut self, position: usize, payload: &[u8]) {
        let binding: scan_index_persistence::Binding =
            serde_json::from_value(self.manifest["binding"].clone()).unwrap();
        let object = &mut self.manifest["objects"][position];
        let slot: scan_index_persistence::Slot =
            serde_json::from_value(object["slot"].clone()).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"ottto.scan-index.storage.v1\0object\0");
        hash.update(serde_json::to_vec(&(binding, slot)).unwrap());
        hash.update([0]);
        hash.update(payload);
        hash.update((payload.len() as u64).to_le_bytes());
        object["digest"] = json!(format!("{:x}", hash.finalize()));
        object["bytes"] = json!(payload.len());
    }
    fn load(&self) -> ScanIndex {
        ScanIndex::load_for_snapshot_source_with_origin(
            &self.root,
            SnapshotSource::ClaudeCode,
            &self.scratch,
        )
        .unwrap()
        .0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.scratch).unwrap();
    }
}

#[test]
fn integrated_each_map_and_cause_retains_custody_without_release_retirement_fence_or_reread() {
    use scan_index_persistence::{Field, UnavailableCause};
    let fields = [
        Field::AccountPending,
        Field::UsagePending,
        Field::RequestCensus,
    ];
    let causes = [
        UnavailableCause::Missing,
        UnavailableCause::Generation,
        UnavailableCause::Digest,
        UnavailableCause::Decode,
        UnavailableCause::Descriptor,
        UnavailableCause::Unsafe,
    ];
    for (map, field) in fields.into_iter().enumerate() {
        for cause in causes {
            let mut fixture = Fixture::new();
            let healthy = fixture.load();
            assert!(healthy.persistence_available());
            match cause {
                UnavailableCause::Missing => fs::remove_file(fixture.bucket_path(map)).unwrap(),
                UnavailableCause::Generation => {
                    fixture.manifest["objects"][map + 1]["generation"] = json!(6)
                }
                UnavailableCause::Digest => {
                    fs::write(fixture.bucket_path(map), b"{broken}").unwrap()
                }
                UnavailableCause::Decode => fixture.semantic_damage(map),
                UnavailableCause::Descriptor => {
                    fixture.manifest["objects"]
                        .as_array_mut()
                        .unwrap()
                        .remove(map + 1);
                }
                UnavailableCause::Unsafe => {
                    fs::set_permissions(fixture.bucket_path(map), fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
            }
            fixture.write_root();
            let before = fs::read(&fixture.root).unwrap();
            crate::local_resource_diagnostics::take_scan_index_storage_observations();
            let mut loaded = fixture.load();
            assert!(!loaded.persistence_available());
            assert_eq!(
                loaded.persistence_unavailable[map],
                Some(scan_index_persistence::MapUnavailable { map: field, cause })
            );
            for sibling in 0..3 {
                if sibling != map {
                    assert!(loaded.persistence_unavailable[sibling].is_none());
                }
            }
            assert_eq!(
                serde_json::to_vec(&loaded.files).unwrap(),
                serde_json::to_vec(&healthy.files).unwrap()
            );
            assert_eq!(
                loaded.accepted_snapshot_fingerprints,
                healthy.accepted_snapshot_fingerprints
            );
            assert_eq!(
                loaded.upload_context_fingerprint,
                healthy.upload_context_fingerprint
            );
            if map != 0 {
                assert_eq!(
                    loaded.claude_account_family_pending,
                    healthy.claude_account_family_pending
                );
            }
            if map != 1 {
                assert_eq!(
                    loaded.claude_usage_family_pending,
                    healthy.claude_usage_family_pending
                );
            }
            if map != 2 {
                assert_eq!(
                    serde_json::to_vec(&loaded.claude_request_census).unwrap(),
                    serde_json::to_vec(&healthy.claude_request_census).unwrap()
                );
            }
            let stats = crate::local_resource_diagnostics::take_scan_index_storage_observations();
            assert_eq!(
                stats
                    .iter()
                    .flat_map(|(_, counts, _)| counts.iter().flatten())
                    .sum::<u64>(),
                1
            );
            assert_eq!(
                stats
                    .iter()
                    .map(|(_, c, _)| c[map][cause as usize])
                    .sum::<u64>(),
                1
            );
            assert!(loaded.decode_holds_family("arbitrary-family"));
            assert!(loaded.decode_holds_entity("arbitrary-body"));
            let pending_before = loaded.claude_account_family_pending.clone();
            loaded.retire_committed_claude_account_pending_windows();
            assert_eq!(loaded.claude_account_family_pending, pending_before);
            assert_eq!(
                loaded.retire_absent_retry_pending_claude_families(
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                    "fixture"
                ),
                0
            );
            assert!(matches!(
                loaded.lower_claude_retired_family_tombstone_fence(
                    &BTreeSet::new(),
                    &BTreeSet::new()
                ),
                ClaudeTombstoneFenceRepair::Kept { .. }
            ));
            assert!(!claude_stale_rearm_can_reopen_fence(
                &loaded,
                &BTreeSet::new()
            ));
            assert!(!claude_fence_held_only_by_witnessed_families(
                &loaded,
                "2026-10-29T00:00:00Z"
            ));
            let old_move_hold = loaded.claude_history_move_released;
            loaded.note_claude_history_cutoff(PriorHistory::Moved, true, false);
            assert_eq!(loaded.claude_history_move_released, old_move_hold);
            let clone = loaded.clone();
            assert_eq!(
                clone.persistence_unavailable,
                loaded.persistence_unavailable
            );
            let subset = loaded.committable_subset_with_local_holds(
                &healthy,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &BTreeSet::new(),
            );
            assert_eq!(
                subset.persistence_unavailable,
                loaded.persistence_unavailable
            );
            let mut recovered = healthy.clone();
            recovered.retain_persistence_baseline_from(&subset);
            assert_eq!(
                recovered.persistence_unavailable,
                loaded.persistence_unavailable
            );
            assert!(serde_json::to_vec(&subset).is_err());
            assert!(loaded.save(&fixture.root).is_err());
            let (result, reads) = terminal_contract_retry::source_acquisitions(|| {
                with_transcript_io_denied(|| {
                    scan_source_roots(
                        SnapshotSource::ClaudeCode,
                        std::slice::from_ref(&fixture.scratch),
                        &mut loaded,
                        "2026-10-29T00:00:00Z",
                        30,
                    )
                })
            });
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("scan_index_map_unavailable"));
            assert!(reads.is_empty());
            assert_eq!(fs::read(&fixture.root).unwrap(), before);
        }
    }
}

#[test]
fn integrated_reader_loads_shards_and_still_writes_legacy_with_committed_generation() {
    let fixture = Fixture::new();
    let mut loaded = fixture.load();
    assert!(loaded.persistence_available());
    let old_generation = loaded.generation;
    loaded.save(&fixture.root).unwrap();
    assert_eq!(loaded.generation, old_generation + 1);
    let raw: Value = serde_json::from_slice(&fs::read(&fixture.root).unwrap()).unwrap();
    assert_eq!(raw["schema_version"], 2);
    assert!(raw.get("storage_format").is_none());
    let restored = fixture.load();
    assert_eq!(restored.generation, loaded.generation);
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&loaded).unwrap()
    );
}

/// The downgrade contract of a later shard writer: `ObjectKeys` admits only
/// registered names, so this key must be registered before anything writes it.
#[test]
fn integrated_sharded_metadata_carrying_the_desktop_inventory_loads_and_saves_without_it() {
    let mut fixture = Fixture::new();
    let healthy = serde_json::to_vec(&fixture.load()).unwrap();
    let old = fixture.metadata_path();
    let mut metadata: Value = serde_json::from_slice(&fs::read(&old).unwrap()).unwrap();
    metadata["claude_desktop_store_inventory"] = json!("a".repeat(64));
    let payload = serde_json::to_vec(&metadata).unwrap();
    fixture.rebind_object(0, &payload);
    let new = fixture.metadata_path();
    fs::rename(old, &new).unwrap();
    fs::write(new, payload).unwrap();
    fixture.write_root();
    let mut loaded = fixture.load();
    assert!(loaded.persistence_available());
    assert_eq!(loaded.claude_desktop_store_inventory, Some("a".repeat(64)));
    assert_eq!(serde_json::to_vec(&loaded).unwrap(), healthy);
    loaded.save(&fixture.root).unwrap();
    let raw: Value = serde_json::from_slice(&fs::read(&fixture.root).unwrap()).unwrap();
    assert!(raw.get("claude_desktop_store_inventory").is_none());
}

#[test]
fn integrated_fresh_init_orphans_are_discarded_and_failure_observations_are_drained() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.root).unwrap();
    crate::local_resource_diagnostics::take_scan_index_storage_observations();
    let loaded = fixture.load();
    assert!(loaded.persistence_available());
    assert!(!fixture.shards.exists());
    let observations = crate::local_resource_diagnostics::take_scan_index_storage_observations();
    assert_eq!(observations.iter().map(|(n, _, _)| n).sum::<u64>(), 1);
    let fixture = Fixture::new();
    fs::remove_file(fixture.shards.join(format!(
        "metadata-{}.json",
        fixture.manifest["objects"][0]["digest"].as_str().unwrap()
    )))
    .unwrap();
    crate::local_resource_diagnostics::take_scan_index_storage_observations();
    assert!(ScanIndex::load(&fixture.root).is_err());
    let observations = crate::local_resource_diagnostics::take_scan_index_storage_observations();
    assert_eq!(
        observations.len(),
        1,
        "error exits pass the same stats drain"
    );
    assert!(fixture.root.exists());
}

#[test]
fn integrated_storage_controls_admission_and_native_heap_layout_keep_entry_pin() {
    let fixture = Fixture::new();
    let loaded = fixture.load();
    assert!(lenient_decode::persistence_controls(&loaded, 0).is_err());
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Follows the canonical pin (claude_request_census_tests SCAN_INDEX_ENTRY_BYTES = 560
    // after #901); #894's storage controls add 0 bytes per entry.
    assert!(std::mem::size_of::<ScanIndexEntry>() <= 560);
    let with = crate::heap_layout_bound::completed_bound(&loaded, 8 * 1024 * 1024).unwrap();
    let mut without = loaded.clone();
    without.persistence_root = None;
    without.persistence_controls = None;
    let base = crate::heap_layout_bound::completed_bound(&without, 8 * 1024 * 1024).unwrap();
    assert!(with > base);
    eprintln!(
        "scan_index_storage_layout index={} entry={} availability={} retained_increment={}",
        std::mem::size_of::<ScanIndex>(),
        std::mem::size_of::<ScanIndexEntry>(),
        std::mem::size_of_val(&loaded.persistence_unavailable),
        with - base
    );
}

#[test]
fn fresh_init_allows_the_real_progress_lock_but_never_prior_progress_state() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.root).unwrap();
    fs::remove_dir_all(&fixture.shards).unwrap();
    let progress_lock = fixture
        .root
        .with_file_name("claude_code-scan-index-v3-upload-progress.lock");
    fs::write(&progress_lock, []).unwrap();
    fs::set_permissions(&progress_lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(fixture.load().generation, 0);
    let progress_state = fixture
        .root
        .with_file_name("claude_code-scan-index-v3-upload-progress.json");
    fs::write(progress_state, b"{}").unwrap();
    assert!(ScanIndex::load(&fixture.root).is_err());
}

#[test]
fn authorized_legacy_quarantine_rebuild_keeps_opaque_custody_until_replacement() {
    let fixture = Fixture::new();
    fs::remove_dir_all(&fixture.shards).unwrap();
    fs::write(
        &fixture.root,
        b"{\"schema_version\":2,\"files\":{},\"generation\":\"broken",
    )
    .unwrap();
    let mut rebuilt = fixture.load();
    assert_eq!(rebuilt.generation, 0);
    assert!(rebuilt.persistence_legacy_recovery.is_some());
    assert!(!fixture.root.exists());
    let mut clone = rebuilt.clone();
    clone.retain_persistence_baseline_from(&rebuilt);
    assert!(clone.persistence_legacy_recovery.is_some());
    // Arbitrary missing-root loads cannot manufacture the authorized token.
    assert!(ScanIndex::load(&fixture.root).is_err());
    rebuilt.save(&fixture.root).unwrap();
    assert_eq!(rebuilt.generation, 1);
    assert!(rebuilt.persistence_legacy_recovery.is_none());
    assert_eq!(fixture.load().generation, 1);
    // Captured recovery adopts the publication and must use ordinary CAS on
    // its next checkpoint, rather than retrying the spent first-save grant.
    let mut adopted = clone.clone();
    adopted.generation = rebuilt.generation;
    adopted.retain_persistence_baseline_from(&rebuilt);
    assert!(adopted.persistence_legacy_recovery.is_none());
    adopted.save(&fixture.root).unwrap();
    assert_eq!(adopted.generation, 2);
    assert_eq!(fixture.load().generation, 2);
    // A stale clone cannot re-use the spent recovery grant.
    assert!(clone.save(&fixture.root).is_err());
    fs::remove_file(&fixture.root).unwrap();
    assert!(clone.save(&fixture.root).is_err());
    assert!(
        !fixture.root.exists(),
        "spent Arc custody never resets a lost root"
    );
}

#[test]
fn partial_negative_metadata_holds_keep_their_fund_when_a_map_is_missing() {
    let mut fixture = Fixture::new();
    let metadata = &fixture.manifest["objects"][0];
    let old = fixture.shards.join(format!(
        "metadata-{}.json",
        metadata["digest"].as_str().unwrap()
    ));
    let mut payload: Value = serde_json::from_slice(&fs::read(&old).unwrap()).unwrap();
    payload["files"]["held-negative-file"] = json!({"size_bytes": "x".repeat(2 * 1024 * 1024)});
    let bytes = serde_json::to_vec(&payload).unwrap();
    let binding: scan_index_persistence::Binding =
        serde_json::from_value(fixture.manifest["binding"].clone()).unwrap();
    let slot = scan_index_persistence::Slot::Metadata;
    let mut hash = Sha256::new();
    hash.update(b"ottto.scan-index.storage.v1\0object\0");
    hash.update(serde_json::to_vec(&(binding, slot)).unwrap());
    hash.update([0]);
    hash.update(&bytes);
    hash.update((bytes.len() as u64).to_le_bytes());
    fixture.manifest["objects"][0]["digest"] = json!(format!("{:x}", hash.finalize()));
    fixture.manifest["objects"][0]["bytes"] = json!(bytes.len());
    let new = fixture.shards.join(format!(
        "metadata-{}.json",
        fixture.manifest["objects"][0]["digest"].as_str().unwrap()
    ));
    fs::rename(old, &new).unwrap();
    fs::write(new, bytes).unwrap();
    fs::remove_file(fixture.bucket_path(0)).unwrap();
    fixture.write_root();
    let index = fixture.load();
    assert!(!index.persistence_available());
    assert!(index.decode_holds.contains("files", "held-negative-file"));
    assert!(index.decode_holds.held_bytes() > 2 * 1024 * 1024);
    assert!(index.decode_holds.held_bytes() <= 8 * 1024 * 1024);
}

#[test]
fn completed_storage_controls_keep_many_small_negative_holds_with_one_byte_budget() {
    let files = (0..1500)
        .map(|i| (format!("held-{i}"), json!({"size_bytes": "invalid"})))
        .collect::<serde_json::Map<_, _>>();
    let bytes = serde_json::to_vec(&json!({
        "schema_version": 2,
        "generation": 1,
        "files": files,
        "fixture_padding": " ".repeat(4 * 1024 * 1024),
    }))
    .unwrap();
    let index = lenient_decode::read(
        std::io::Cursor::new(bytes),
        "many-small-held-controls",
        "claude_code",
    )
    .unwrap();
    assert_eq!(index.decode_holds.file_keys().count(), 1500);
    assert!(lenient_decode::persistence_controls(&index, 8 * 1024 * 1024).is_ok());
    assert!(lenient_decode::persistence_controls(&index, 1).is_err());
}

#[test]
fn observed_fresh_load_keeps_first_save_custody_across_same_pass_progress() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.root).unwrap();
    fs::remove_dir_all(&fixture.shards).unwrap();
    let mut fresh = fixture.load();
    assert_eq!(fresh.generation, 0);
    assert!(fresh.persistence_root.is_some());
    let mut stale = fresh.clone();
    let progress = fixture
        .root
        .with_file_name("claude_code-scan-index-v3-upload-progress.json");
    fs::write(&progress, b"{}").unwrap();
    // The real finish boundary persists progress before its first index save.
    fresh.save(&fixture.root).unwrap();
    assert_eq!(fixture.load().generation, 1);
    fs::remove_file(&fixture.root).unwrap();
    assert!(stale.save(&fixture.root).is_err());
    assert!(
        !fixture.root.exists(),
        "a prior publication marker forbids resetting a lost root"
    );
}

#[test]
fn integrated_manifest_refuses_each_unknown_map_and_counts_before_window_parsing() {
    for map in 0..3 {
        let fixture = Fixture::new();
        fs::remove_file(fixture.bucket_path(map)).unwrap();
        let index = fixture.load();
        let (result, rows) = crate::local_resource_diagnostics::capture(|| {
            index.manifest_for_window(SnapshotSource::ClaudeCode, "invalid", "invalid")
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "scan_index_map_unavailable"
        );
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0]["counts"]["scanindex_manifest_unavailable_refused"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(rows[0]["source"], "claude_code");
        assert_eq!(rows[0]["counts"].as_object().unwrap().len(), 1);
    }
}

// A retained, already parsed page is the input at the evidence/finalization
// seam. Preparation happens ONCE before damage, never on held/restored paths.
fn prepared_recovery_page(
    fixture: &Fixture,
    index: &ScanIndex,
) -> (
    Vec<SnapshotItem>,
    crate::claude_local_otel::ClaudeApiEvidenceRead,
) {
    use claude_request_money::e2;
    const ROOT: &str = "a0000000-0000-4000-8000-00000000000a";
    let path = fixture.scratch.join(format!("{ROOT}.jsonl"));
    fs::write(&path, b"synthetic retained page\n").unwrap();
    let opened = File::open(&path).unwrap().metadata().unwrap();
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    accumulator.claude_file_birth = ClaudeFileBirth::observe(&path, Some(&opened));
    accumulator
        .claude_file_birth
        .set_birth_for_test(rfc3339_unix_nanos("2026-08-02T07:00:00Z").unwrap());
    apply_claude_code_line(
        &json!({
            "type":"assistant", "version":"2.1.309", "sessionId":ROOT,
            "timestamp":"2026-08-02T07:00:01Z", "requestId":"r9-request",
            "message":{"id":"r9-message", "model":"claude-haiku-4-5",
                "usage":{"input_tokens":37,"output_tokens":7}}
        }),
        &mut accumulator,
    );
    accumulator.finalize_claude_responses_e2(Some(e2::ReadContext {
        index,
        path: &path,
        twins: &Default::default(),
    }));
    let items = accumulator.into_items(&path, "2026-08-02T09:00:00Z", "f".repeat(64), None);
    let row = crate::snapshots::tests::complete_api_row(ROOT, "r9-request", 1, 37, 7, 0);
    let dir = fixture.scratch.join(crate::claude_local_otel::STORE_DIR);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes()))),
        serde_json::to_string(&row).unwrap() + "\n",
    )
    .unwrap();
    let evidence =
        crate::claude_local_otel::ClaudeApiEvidenceRead::load(&fixture.scratch, [ROOT.to_owned()])
            .unwrap();
    (items, evidence)
}
fn recovery_emission_boundaries(
    mut items: Vec<SnapshotItem>,
    evidence: &crate::claude_local_otel::ClaudeApiEvidenceRead,
    index: &mut ScanIndex,
) -> (
    SourceScanResult,
    Result<SnapshotSourceManifest>,
    BTreeSet<String>,
) {
    use claude_request_money::e2;
    // Mirror ordinary preparation before the evidence/finalization seam. A
    // loaded index starts with active revision 0; S-726-1 intentionally vetoes
    // E2's request-owned literal there, even for an undamaged control. This
    // activation is also done by snapshot_sync before any production scan.
    let revision =
        crate::snapshot_sync::effective_upload_body_witness_revision(SnapshotSource::ClaudeCode);
    index.activate_effective_upload_body_witness_revision(revision);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    e2::decide_page_copies(&mut items, index);
    e2::attach_page(&mut items, evidence);
    let unresolved = e2::side_calls_page(
        &mut items,
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: evidence.evidence.clone(),
            health: Default::default(),
        },
        &Default::default(),
        index,
    );
    let held = e2::finish_page(&mut items, index, e2::TelemetryRead::Loaded);
    if index.persistence_available() {
        assert_eq!(items.len(), 1, "positive E2 body before finalization");
        assert!(matches!(
            index.claude_literal_guard(&items),
            claude_history_upgrade::LiteralGuard::Open
        ));
        // Frozen reproduction of round 9's bad control setup: turning off
        // the active revision rejects this same literal without any damage.
        let mut inactive = index.clone();
        inactive.active_effective_upload_body_witness_revision = 0;
        assert!(matches!(
            inactive.claude_literal_guard(&items),
            claude_history_upgrade::LiteralGuard::DenyAll
        ));
        let mut vetoed = items.clone();
        assert_eq!(
            inactive.veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut vetoed),
            1
        );
        assert!(vetoed.is_empty());
    }
    if !index.persistence_available() {
        assert_eq!(unresolved, held);
    }
    let mut scan = SourceScanResult::empty(SnapshotSource::ClaudeCode);
    scan.snapshots = items;
    scan.census_complete = true;
    scan.pending_finalization.push(PendingIndexFinalization {
        restored_behind_accepted: false,
        sampled_audit_verified: false,
        codex_pending_recovery: false,
        index_key: "synthetic-file".into(),
        source_file_fingerprint: "f".repeat(64),
        previous_snapshot_fingerprint: None,
        previous_upload_body_witness: None,
        parse_complete: true,
        diagnostic_reason: FileReason::Complete,
        parsed_snapshot_count: 1,
        effective_upload_body_witness_revision: revision,
    });
    index.activate_upload_context("r9-complete-context".into());
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, index);
    let manifest = index.manifest_for_window(
        SnapshotSource::ClaudeCode,
        "2026-08-02T00:00:00Z",
        "2026-08-03T00:00:00Z",
    );
    (scan, manifest, held)
}

#[test]
fn integrated_each_damaged_map_holds_then_restores_equal_money_without_transcript_reads() {
    use claude_request_money::e2;
    for map in 0..3 {
        let fixture = Fixture::new();
        let healthy = fixture.load();
        let (prepared, evidence) = e2::with_enabled(|| prepared_recovery_page(&fixture, &healthy));
        assert_eq!(prepared.len(), 1, "positive prepared E2 page");
        let mut control = healthy.clone();
        let ((control_scan, control_manifest, control_held), reads) =
            terminal_contract_retry::source_acquisitions(|| {
                with_transcript_io_denied(|| {
                    e2::with_enabled(|| {
                        recovery_emission_boundaries(prepared.clone(), &evidence, &mut control)
                    })
                })
            });
        assert!(reads.is_empty());
        assert!(control_held.is_empty());
        assert_eq!(control_scan.snapshots.len(), 1);
        let emitted = &control_scan.snapshots[0];
        assert_eq!(emitted.input_tokens, 37);
        assert_eq!(emitted.output_tokens, 7);
        assert_eq!(emitted.request_count, 1);
        assert_eq!(
            emitted.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.0001")
        );
        let control_manifest = control_manifest.unwrap();
        assert!(control_manifest.entity_count > 0);
        assert_eq!(
            control.upload_context_fingerprint.as_deref(),
            Some("r9-complete-context")
        );

        let payload = fixture.bucket_path(map);
        let original = fs::read(&payload).unwrap();
        fs::write(&payload, b"{damaged}").unwrap();
        let mut unknown = fixture.load();
        assert!(!unknown.persistence_available());
        assert_eq!(
            unknown.persistence_unavailable[map].unwrap().cause,
            scan_index_persistence::UnavailableCause::Digest
        );
        let old_context = unknown.upload_context_fingerprint.clone();
        let old_pending = unknown.claude_account_family_pending.clone();
        let old_release = unknown.claude_history_move_released;
        let old_files = serde_json::to_vec(&unknown.files).unwrap();
        let ((held_scan, manifest, held), reads) =
            terminal_contract_retry::source_acquisitions(|| {
                with_transcript_io_denied(|| {
                    e2::with_enabled(|| {
                        unknown.retire_committed_claude_account_pending_windows();
                        assert!(matches!(
                            unknown.lower_claude_retired_family_tombstone_fence(
                                &BTreeSet::new(),
                                &BTreeSet::new()
                            ),
                            ClaudeTombstoneFenceRepair::Kept { .. }
                        ));
                        assert!(!claude_stale_rearm_can_reopen_fence(
                            &unknown,
                            &BTreeSet::new()
                        ));
                        recovery_emission_boundaries(prepared.clone(), &evidence, &mut unknown)
                    })
                })
            });
        assert!(
            reads.is_empty(),
            "held evidence never causes transcript acquisition"
        );
        assert!(!held.is_empty());
        assert!(held_scan.snapshots.is_empty());
        assert!(!held_scan.census_complete);
        assert!(manifest
            .unwrap_err()
            .to_string()
            .contains("scan_index_map_unavailable"));
        assert_eq!(unknown.upload_context_fingerprint, old_context);
        assert_eq!(unknown.claude_account_family_pending, old_pending);
        assert_eq!(unknown.claude_history_move_released, old_release);
        assert_eq!(serde_json::to_vec(&unknown.files).unwrap(), old_files);

        fs::write(&payload, original).unwrap();
        let ((restored, resumed_scan, resumed_manifest, resumed_held), reads) =
            terminal_contract_retry::source_acquisitions(|| {
                with_transcript_io_denied(|| {
                    let mut restored = fixture.load();
                    assert!(restored.persistence_available());
                    assert!(
                        !unknown.persistence_available(),
                        "old views never clear in place"
                    );
                    let (scan, manifest, held) = e2::with_enabled(|| {
                        recovery_emission_boundaries(prepared.clone(), &evidence, &mut restored)
                    });
                    (restored, scan, manifest.unwrap(), held)
                })
            });
        assert!(
            reads.is_empty(),
            "restored evidence reuses the retained page"
        );
        assert!(resumed_held.is_empty());
        // Exact emitted body equality covers tokens, cost, requests, account,
        // evidence references, attribution and semantic fingerprints together.
        assert_eq!(
            serde_json::to_vec(&resumed_scan.snapshots).unwrap(),
            serde_json::to_vec(&control_scan.snapshots).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&resumed_manifest).unwrap(),
            serde_json::to_vec(&control_manifest).unwrap()
        );
        assert_eq!(
            restored.upload_context_fingerprint,
            control.upload_context_fingerprint
        );
        assert_eq!(restored.generation, healthy.generation);
    }
}

#[test]
fn integrated_missing_root_reserved_only_stalls_before_default_save_or_transcript_read() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.root).unwrap();
    fs::remove_dir_all(&fixture.shards).unwrap();
    fs::create_dir(&fixture.shards).unwrap();
    fs::set_permissions(&fixture.shards, fs::Permissions::from_mode(0o700)).unwrap();
    let files = [
        fixture
            .shards
            .join(format!("prior-root-{:020}-{}.json", 5, "a".repeat(64))),
        fixture.shards.join("verified-complete.json"),
    ];
    for path in &files {
        fs::write(path, b"opaque future control").unwrap();
    }
    crate::local_resource_diagnostics::take_scan_index_storage_observations();
    let (result, reads) = terminal_contract_retry::source_acquisitions(|| {
        with_transcript_io_denied(|| {
            ScanIndex::load_for_snapshot_source_with_origin(
                &fixture.root,
                SnapshotSource::ClaudeCode,
                &fixture.scratch,
            )
        })
    });
    assert!(reads.is_empty());
    let error = result.expect_err("missing root must refuse before default index");
    assert!(format!("{error:#}").contains("scan_index_root_missing_with_shards"));
    assert!(!fixture.root.exists(), "no fresh save");
    assert_eq!(fs::read_dir(&fixture.shards).unwrap().count(), 2);
    for path in files {
        assert_eq!(fs::read(path).unwrap(), b"opaque future control");
    }
    let observations = crate::local_resource_diagnostics::take_scan_index_storage_observations();
    assert_eq!(observations.iter().map(|(_, _, n)| n).sum::<u64>(), 1);
    assert_eq!(observations.iter().map(|(n, _, _)| n).sum::<u64>(), 0);
}

#[test]
fn integrated_no_store_true_first_install_still_initializes_without_transcript_reads() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.root).unwrap();
    fs::remove_dir_all(&fixture.shards).unwrap();
    crate::local_resource_diagnostics::take_scan_index_storage_observations();
    let ((), reads) = terminal_contract_retry::source_acquisitions(|| {
        with_transcript_io_denied(|| {
            let (mut index, origin) = ScanIndex::load_for_snapshot_source_with_origin(
                &fixture.root,
                SnapshotSource::ClaudeCode,
                &fixture.scratch,
            )
            .unwrap();
            assert!(matches!(origin, ScanIndexLoadOrigin::Missing));
            assert_eq!(index.generation, 0);
            assert!(index.files.is_empty());
            index.save(&fixture.root).unwrap();
            assert!(fixture.root.exists());
        })
    });
    assert!(reads.is_empty());
    let observations = crate::local_resource_diagnostics::take_scan_index_storage_observations();
    assert_eq!(observations.iter().map(|(_, _, n)| n).sum::<u64>(), 0);
}

/// [off=main] off large v1 manifest load cas and containment match compact v1.
#[test]
fn off_large_v1_manifest_load_cas_and_containment_match_compact_v1() {
    let compact = Fixture::new();
    let large = Fixture::new();
    assert_eq!(large.manifest["storage_format"], json!(1));
    let mut bytes = fs::read(&large.root).unwrap();
    bytes.extend_from_slice(&vec![b' '; 8192]);
    assert!(bytes.len() > 4096);
    assert!(bytes.len() < scan_index_persistence::MAX_ROOT_BYTES);
    fs::write(&large.root, &bytes).unwrap();
    // No sentinel or environment opt-in: exercise the real source-aware OFF
    // route, v1 CAS writer, and the shared containment admission guard.
    let mut expected = compact.load();
    let mut actual = large.load();
    assert!(actual.v2().persistence_v2.is_none());
    assert!(actual.persistence_available());
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_eq!(fs::read(&large.root).unwrap(), bytes);
    {
        let _lock = CheckpointLock::acquire(&large.root).unwrap();
        state_v2::guard_containment_locked(&large.root).unwrap();
    }
    expected.save(&compact.root).unwrap();
    actual.save(&large.root).unwrap();
    assert_eq!(
        fs::read(&large.root).unwrap(),
        fs::read(&compact.root).unwrap()
    );
    assert!(large.load().persistence_available());
    assert!(!large.root.with_extension("json.v2.sqlite").exists());
}

// Snapshot every file in this bounded synthetic index, including storage
// controls and in-flight publication files, to detect accidental recovery.
fn inspection_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            files.extend(inspection_files(&entry.path()));
        } else {
            files.insert(entry.path(), fs::read(entry.path()).unwrap());
        }
    }
    files
}

#[test]
fn estimate_index_reader_never_creates_or_repairs_prior_marker() {
    let fixture = Fixture::new();
    let prior = fixture
        .root
        .with_file_name("claude_code-scan-index-v3.json.storage-prior");
    for marker in [None, Some(b"scan_index_".as_slice())] {
        if let Some(marker) = marker {
            fs::write(&prior, marker).unwrap();
            fs::set_permissions(&prior, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let before = inspection_files(&fixture.scratch);
        let index = scan_index_integration::read_scan_index_representation_read_only(
            &fixture.root,
            "estimate",
            "claude_code",
        )
        .unwrap();
        assert!(index.persistence_available());
        assert_eq!(inspection_files(&fixture.scratch), before);
        assert!(!fixture.root.with_extension("json.lock").exists());
    }
}

#[test]
fn estimate_index_reader_refuses_unpublished_init_without_removing_files() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.root).unwrap();
    let temporary = fixture.root.with_file_name(format!(
        "claude_code-scan-index-v3.json.storage-tmp-{}",
        "b".repeat(32),
    ));
    fs::write(&temporary, b"in-flight publication").unwrap();
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
    let before = inspection_files(&fixture.scratch);
    assert!(
        scan_index_integration::read_scan_index_representation_read_only(
            &fixture.root,
            "estimate",
            "claude_code",
        )
        .is_err()
    );
    assert_eq!(inspection_files(&fixture.scratch), before);
    assert!(fixture.shards.is_dir());
    assert!(!fixture.root.exists());
}

// F10: count surviving complete offers at the real post-policy finalizer.
// Parser completion and an equal body suppressed as a semantic noop are not
// publication. This runs portably; production Pi registration remains E5's.
