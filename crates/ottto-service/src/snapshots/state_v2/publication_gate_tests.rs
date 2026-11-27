//! Collection admission and same-process publication recovery over synthetic input.
use super::*;
use crate::snapshots::{self as s, SnapshotSource};
use std::os::unix::fs::PermissionsExt;

const SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::ClaudeCode,
    SnapshotSource::Codex,
    SnapshotSource::Pi,
];

fn fixture(source: SnapshotSource) -> tests::Fixture {
    let mut fixture = tests::Fixture::new();
    fixture
        .path
        .set_file_name(format!("{}-test-scan-index.json", source.api_slug()));
    fixture
}

#[test]
fn all_sources_resume_a_latched_publication_before_collection_then_save_and_reload() {
    for (slot, source) in SOURCES.into_iter().enumerate() {
        let f = fixture(source);
        let mut seed = ScanIndex::default();
        seed.accepted_snapshot_fingerprints.insert("a".repeat(64));
        seed.historical_replay_generation = Some("kept-replay".into());
        let input = serde_json::to_vec(&seed).unwrap();
        fs::write(&f.path, &input).unwrap();
        fence::FAIL_BEFORE_RENAME.set(true);
        let error = ScanIndex::load_for_snapshot_source_with_origin(&f.path, source, &f.support)
            .unwrap_err();
        assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
        assert_eq!(fs::read(&f.path).unwrap(), input);
        assert!(s::scan_index_health::observations()[2][slot].0.is_some());
        assert!(published(&f.path).unwrap(), "custody remains latched");

        let (mut index, _) =
            ScanIndex::load_for_snapshot_source_with_origin(&f.path, source, &f.support).unwrap();
        assert!(index.v2().persistence_v2.is_some());
        assert_eq!(
            index.accepted_snapshot_fingerprints,
            seed.accepted_snapshot_fingerprints
        );
        assert_eq!(
            index.historical_replay_generation,
            seed.historical_replay_generation
        );
        assert!(s::scan_index_health::observations()[2][slot].0.is_none());
        index.historical_replay_generation = Some("saved-replay".into());
        index.save(&f.path).unwrap();
        drop(index);
        cold_close_for_test(&f.path).unwrap();
        let (index, _) =
            ScanIndex::load_for_snapshot_source_with_origin(&f.path, source, &f.support).unwrap();
        assert_eq!(
            index.historical_replay_generation.as_deref(),
            Some("saved-replay")
        );
        assert_eq!(
            index.accepted_snapshot_fingerprints,
            seed.accepted_snapshot_fingerprints
        );
    }
}

#[test]
fn deterministic_inventory_refusals_keep_input_and_require_support() {
    for source in SOURCES {
        let f = fixture(source);
        let mut wire = serde_json::to_value(ScanIndex::default()).unwrap();
        wire["unrecognized_input_class"] = serde_json::json!({"kept": true});
        let input = serde_json::to_vec(&wire).unwrap();
        fs::write(&f.path, &input).unwrap();
        for _ in 0..2 {
            let error =
                ScanIndex::load_for_snapshot_source_with_origin(&f.path, source, &f.support)
                    .unwrap_err();
            assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::DbUnavailable));
            assert_eq!(
                s::scan_index_health::state_v2_reason(&error)
                    .unwrap()
                    .action(),
                "contact_support"
            );
            assert_eq!(fs::read(&f.path).unwrap(), input);
            assert!(!published(&f.path).unwrap());
        }
    }
}

#[test]
fn missing_store_adoption_clears_the_blocker_and_recovers_orphan_shards() {
    for (slot, source) in SOURCES.into_iter().enumerate() {
        let f = fixture(source);
        fs::create_dir(fence::sibling(&f.path, ".shards")).unwrap();
        fs::set_permissions(
            fence::sibling(&f.path, ".shards"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        s::scan_index_health::observe(source, &Err(Hold::ReloadRequired.into()));
        assert!(s::scan_index_health::observations()[2][slot].0.is_some());
        let (index, origin) =
            ScanIndex::load_for_snapshot_source_with_origin(&f.path, source, &f.support).unwrap();
        assert!(matches!(origin, s::ScanIndexLoadOrigin::Missing));
        assert_eq!(index.generation, 0);
        assert!(index.v2().persistence_v2.is_some());
        assert!(!fence::sibling(&f.path, ".shards").exists());
        assert!(s::scan_index_health::observations()[2][slot].0.is_none());
    }
}

#[test]
fn claude_raw_hold_survives_a_native_save_and_cold_reload() {
    let f = fixture(SnapshotSource::ClaudeCode);
    let held = s::lenient_decode::read(
        std::io::Cursor::new(
            br#"{"schema_version":2,"accepted_snapshot_fingerprint_ledger_version":2,"files":{"opaque":{"size_bytes":[]}}}"#,
        ),
        "cas",
        "unattributed",
    )
    .unwrap();
    assert!(!held.decode_holds.is_empty());
    let raw: Vec<_> = held
        .decode_holds
        .v2_entries()
        .map(|(field, key, bytes, _, _)| (field.to_owned(), key.to_owned(), bytes.to_vec()))
        .collect();
    // Raw holds are admitted custody, not new damage introduced after the
    // pass adopted a clean baseline. Seed that custody through the mapper.
    let mut index = s::e2_pipeline_scan_fixture::seed_index_for_test(&held, &f.path);
    index.save(&f.path).unwrap();
    drop(index);
    cold_close_for_test(&f.path).unwrap();
    let (index, _) = ScanIndex::load_for_snapshot_source_with_origin(
        &f.path,
        SnapshotSource::ClaudeCode,
        &f.support,
    )
    .unwrap();
    let restored: Vec<_> = index
        .decode_holds
        .v2_entries()
        .map(|(field, key, bytes, _, _)| (field.to_owned(), key.to_owned(), bytes.to_vec()))
        .collect();
    assert_eq!(restored, raw);
}

#[test]
fn unbound_load_cannot_save_and_unadopted_bound_graph_requires_reload() {
    let f = fixture(SnapshotSource::ClaudeCode);
    let unbound = f.support.join("unbound.json");
    let input = serde_json::to_vec(&ScanIndex::default()).unwrap();
    fs::write(&unbound, &input).unwrap();
    let mut index = ScanIndex::load(&unbound).unwrap();
    assert_eq!(
        index.save(&unbound).unwrap_err().downcast_ref::<Hold>(),
        Some(&Hold::ForeignBinding)
    );
    assert_eq!(fs::read(&unbound).unwrap(), input);
    assert_eq!(
        index.save(&f.path).unwrap_err().downcast_ref::<Hold>(),
        Some(&Hold::ReloadRequired)
    );
    assert!(!f.path.exists());
}

#[test]
fn fresh_import_retries_unpublished_initialization_after_restart_without_losing_baselines() {
    let f = fixture(SnapshotSource::ClaudeCode);
    // A failed initialization has no semantic rows or fence, but leaves the
    // engine owner and import file. The next process must still initialize.
    let db = sqlite::Sqlite::create_import(&fence::sibling(&f.path, ".v2.sqlite.import")).unwrap();
    drop(db);
    let (index, _) = ScanIndex::load_for_snapshot_source_with_origin(
        &f.path,
        SnapshotSource::ClaudeCode,
        &f.support,
    )
    .unwrap();
    assert_eq!(index.generation, 0);
    assert!(index.v2().persistence_v2.is_some());
    let f = fixture(SnapshotSource::ClaudeCode);
    let baseline = fence::sibling(&f.path, ".v1-readonly");
    fs::write(&baseline, b"prior-state-baseline").unwrap();
    assert!(ScanIndex::load_for_snapshot_source_with_origin(
        &f.path,
        SnapshotSource::ClaudeCode,
        &f.support,
    )
    .is_err());
    assert_eq!(fs::read(&baseline).unwrap(), b"prior-state-baseline");
}
