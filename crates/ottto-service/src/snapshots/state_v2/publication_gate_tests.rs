//! Collection admission and same-process publication recovery over synthetic input.
use super::*;
use crate::snapshots::{self as s, SnapshotSource};

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
    let (mut index, _) = ScanIndex::load_for_snapshot_source_with_origin(
        &f.path,
        SnapshotSource::ClaudeCode,
        &f.support,
    )
    .unwrap();
    let held = s::lenient_decode::read_bounded(
        br#"{"schema_version":2,"files":{"opaque":{"size_bytes":[]}}}"#,
    )
    .unwrap();
    assert!(!held.decode_holds.is_empty());
    let raw: Vec<_> = held
        .decode_holds
        .v2_entries()
        .map(|(field, key, bytes, _, _)| (field.to_owned(), key.to_owned(), bytes.to_vec()))
        .collect();
    index.decode_holds = held.decode_holds;
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
