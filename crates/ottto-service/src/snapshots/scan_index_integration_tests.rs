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
    fn semantic_damage(&mut self, map: usize) {
        let old = self.bucket_path(map);
        let original: Value = serde_json::from_slice(&fs::read(&old).unwrap()).unwrap();
        let key = original.as_object().unwrap().keys().next().unwrap();
        let payload = serde_json::to_vec(&json!({key: null})).unwrap();
        let binding: scan_index_persistence::Binding =
            serde_json::from_value(self.manifest["binding"].clone()).unwrap();
        let object = &mut self.manifest["objects"][map + 1];
        let slot: scan_index_persistence::Slot =
            serde_json::from_value(object["slot"].clone()).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"ottto.scan-index.storage.v1\0object\0");
        hash.update(serde_json::to_vec(&(binding, slot)).unwrap());
        hash.update([0]);
        hash.update(&payload);
        hash.update((payload.len() as u64).to_le_bytes());
        object["digest"] = json!(format!("{:x}", hash.finalize()));
        object["bytes"] = json!(payload.len());
        let new = self.bucket_path(map);
        fs::rename(old, &new).unwrap();
        fs::write(new, payload).unwrap();
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
                    .flat_map(|(_, counts)| counts.iter().flatten())
                    .sum::<u64>(),
                1
            );
            assert_eq!(
                stats
                    .iter()
                    .map(|(_, c)| c[map][cause as usize])
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

#[test]
fn integrated_fresh_init_orphans_are_discarded_and_failure_observations_are_drained() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.root).unwrap();
    crate::local_resource_diagnostics::take_scan_index_storage_observations();
    let loaded = fixture.load();
    assert!(loaded.persistence_available());
    assert!(!fixture.shards.exists());
    let observations = crate::local_resource_diagnostics::take_scan_index_storage_observations();
    assert_eq!(observations.iter().map(|(n, _)| n).sum::<u64>(), 1);
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
    assert!(std::mem::size_of::<ScanIndexEntry>() <= 480);
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
