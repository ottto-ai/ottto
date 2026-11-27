// Compact scan-index writer. Only the whitespace of the saved file changes:
// every reader accepts both the older pretty files and the compact ones, and
// the restart hold admission is measured on the exact bytes the save writes.
// Synthetic fixtures only.
use crate::snapshots::lenient_decode_tests::raw_slot;
use crate::snapshots::*;
use std::io::Cursor;

/// The shape of a live Claude index: per-file entries, fingerprints and
/// activity.
fn synthetic_index(families: usize) -> ScanIndex {
    let mut index = ScanIndex::default();
    for n in 0..families {
        let root = format!("{n:08x}-0000-4000-8000-{n:012x}");
        let key = format!("/synthetic/projects/p/{root}.jsonl");
        let fingerprint = format!("{n:064x}");
        index
            .files
            .insert(key.clone(), tests::manifest_index_entry(Some(&fingerprint)));
        index
            .file_snapshot_fingerprints
            .insert(key, BTreeSet::from([fingerprint.clone()]));
        index
            .snapshot_activity_at
            .insert(fingerprint.clone(), Some("2026-10-22T00:00:00Z".into()));
        index.accepted_snapshot_fingerprints.insert(fingerprint);
    }
    index
}

fn assert_same_state(actual: &ScanIndex, expected: &ScanIndex, label: &str) {
    assert_eq!(actual.generation, expected.generation, "{label}");
    assert_eq!(actual.files.len(), expected.files.len(), "{label}");
    assert_eq!(
        actual.accepted_snapshot_fingerprints, expected.accepted_snapshot_fingerprints,
        "{label}"
    );
    assert_eq!(
        actual.snapshot_activity_at, expected.snapshot_activity_at,
        "{label}"
    );
}

#[test]
fn pretty_and_compact_files_decode_identically_through_every_reader() {
    // A saved seed carries every save-owned marker, so a public load of
    // either layout settles nothing and re-encodes to the same bytes.
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-readers");
    let index = synthetic_index(8);
    let compact = serde_json::to_vec(&index).unwrap();
    let pretty = serde_json::to_vec_pretty(&index).unwrap();
    assert!(compact.len() < pretty.len());
    for (layout, bytes) in [("pretty", &pretty), ("compact", &compact)] {
        let path = scratch.as_ref().join(format!("{layout}.json"));
        fs::write(&path, bytes).unwrap();
        let decoded = [
            // Plain readers: released serde loaders and the census token reader.
            ("serde", serde_json::from_slice::<ScanIndex>(bytes).unwrap()),
            (
                "census_stream",
                claude_request_census::decode_index(Cursor::new(bytes)).unwrap(),
            ),
            // Streaming lenient reader: ScanIndex::load and a direct legacy decode probe.
            ("load", ScanIndex::load(&path).unwrap()),
            (
                "legacy_decode",
                lenient_decode::read_file(File::open(&path).unwrap(), "cas", "unattributed")
                    .unwrap(),
            ),
        ];
        for (reader, decoded) in decoded {
            let label = format!("{layout}/{reader}");
            assert_same_state(&decoded, &index, &label);
            assert!(decoded.decode_holds.is_empty(), "{label}");
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), compact, "{label}");
        }
        assert_eq!(&fs::read(&path).unwrap(), bytes);
        let mut unbound = ScanIndex::load(&path).unwrap();
        assert_eq!(
            unbound
                .save(&path)
                .unwrap_err()
                .downcast_ref::<state_v2::Hold>(),
            Some(&state_v2::Hold::ForeignBinding)
        );
        assert_eq!(&fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn held_slots_cross_both_layouts_and_save_counts_the_written_bytes() {
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-held");
    let path = scratch.as_ref().join("index.json");
    let seed = synthetic_index(16);
    let mut value = serde_json::to_value(&seed).unwrap();
    value["files"]["held-opaque"] = serde_json::json!({"unknown": "x".repeat(64 * 1024)});
    for (layout, bytes) in [
        ("pretty", serde_json::to_vec_pretty(&value).unwrap()),
        ("compact", serde_json::to_vec(&value).unwrap()),
    ] {
        let original = raw_slot(&bytes, "files", "held-opaque");
        fs::write(&path, &bytes).unwrap();
        let streamed =
            lenient_decode::read_file(File::open(&path).unwrap(), "cas", "unattributed").unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        for (reader, decoded) in [("legacy_decode", &streamed), ("load", &loaded)] {
            let label = format!("{layout}/{reader}");
            assert!(decoded.decode_holds_file("held-opaque"), "{label}");
            assert!(
                decoded.decode_holds.same_as(&loaded.decode_holds),
                "{label}"
            );
            assert_eq!(
                decoded.decode_holds.held_bytes(),
                loaded.decode_holds.held_bytes(),
                "{label}"
            );
            assert_same_state(decoded, &seed, &label);
        }
        let native = crate::test_scratch::ScratchDir::canonical("held-layout-native");
        let (session, mut routed) = state_v2::money_test_support::ColdSession::publish(
            scan_index_persistence::Source::Claude,
            &loaded,
            native.as_ref(),
        );
        let restarted = session.save_reload(&mut routed);
        assert!(restarted.decode_holds.same_as(&loaded.decode_holds));
        let saved = serde_json::to_vec(&restarted).unwrap();
        assert_eq!(raw_slot(&saved, "files", "held-opaque"), original);
        assert_eq!(restarted.files.len(), loaded.files.len());
    }
}
