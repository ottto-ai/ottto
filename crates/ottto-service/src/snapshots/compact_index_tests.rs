// Compact scan-index writer. Only the whitespace of the saved file changes:
// every reader accepts both the older pretty files and the compact ones, and
// the restart hold admission is measured on the exact bytes the save writes.
// Synthetic fixtures only.
use super::*;
use std::io::Cursor;

const WINDOW_END: &str = "2026-10-25T18:18:19Z";

/// The shape that dominates a live Claude index: per-family usage pending
/// with per-request occurrences, account pending hashes and one file entry.
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
        let hashes = (0..8)
            .map(|request| format!("{:x}", Sha256::digest(format!("{n}:{request}").as_bytes())))
            .collect::<BTreeSet<_>>();
        let occurrences = hashes
            .iter()
            .enumerate()
            .map(|(sequence, hash)| {
                (
                    hash.clone(),
                    ClaudeTranscriptUsageOccurrenceWitness {
                        sequence: sequence as u64,
                        input_tokens: 3,
                        output_tokens: 1_200,
                        cache_read_tokens: 150_000,
                        cache_creation_5m_tokens: 0,
                        cache_creation_1h_tokens: 2_400,
                        reasoning_output_tokens: 0,
                        model: Some("synthetic-model".into()),
                        speed_mode: None,
                        reasoning_effort: Some("high".into()),
                    },
                )
            })
            .collect();
        index.claude_usage_family_pending.insert(
            root.clone(),
            ClaudeUsageFamilyPending {
                census_window_end: WINDOW_END.into(),
                member_request_id_hashes: BTreeMap::from([(root.clone(), hashes.clone())]),
                member_occurrences: BTreeMap::from([(root.clone(), occurrences)]),
                invalid: false,
                idless_revision: None,
                identity_contract: None,
            },
        );
        index.claude_account_family_pending.insert(
            root.clone(),
            ClaudeAccountFamilyPending {
                current: ClaudeAccountFamilyPendingWindow {
                    version: CLAUDE_ACCOUNT_REQUEST_SET_VERSION.into(),
                    census_window_end: WINDOW_END.into(),
                    account_identifier_hash: "a".repeat(64),
                    evidence_request_count: 8,
                    census_complete: false,
                    members: BTreeMap::from([(root.clone(), 8)]),
                    member_requests: BTreeMap::from([(
                        root,
                        ClaudeAccountRequestSet::from_full_hashes(&hashes)
                            .expect("synthetic hashes have distinct prefixes"),
                    )]),
                    invalid: false,
                },
                previous_windows: Vec::new(),
                confirmed_absent_members: BTreeSet::new(),
            },
        );
    }
    index
}

fn raw_slot(bytes: &[u8], field: &str, key: &str) -> String {
    let root: BTreeMap<String, &serde_json::value::RawValue> =
        serde_json::from_slice(bytes).unwrap();
    let slots: BTreeMap<String, &serde_json::value::RawValue> =
        serde_json::from_str(root[field].get()).unwrap();
    slots[key].get().to_owned()
}

fn assert_same_state(actual: &ScanIndex, expected: &ScanIndex, label: &str) {
    assert_eq!(actual.generation, expected.generation, "{label}");
    assert_eq!(actual.files.len(), expected.files.len(), "{label}");
    assert_eq!(
        actual.claude_usage_family_pending, expected.claude_usage_family_pending,
        "{label}"
    );
    assert_eq!(
        actual.claude_account_family_pending, expected.claude_account_family_pending,
        "{label}"
    );
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
    let mut index = synthetic_index(8);
    index.save(&scratch.as_ref().join("seed.json")).unwrap();
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
            // Streaming lenient reader: ScanIndex::load and the unbounded CAS.
            ("load", ScanIndex::load(&path).unwrap()),
            (
                "streaming_cas",
                lenient_decode::read_file(File::open(&path).unwrap(), "cas", "unattributed")
                    .unwrap(),
            ),
            // Bounded reader: the save_with_read_limit CAS.
            (
                "bounded_cas",
                claude_request_census::decode_bounded_index(bytes).unwrap(),
            ),
        ];
        for (reader, decoded) in decoded {
            let label = format!("{layout}/{reader}");
            assert_same_state(&decoded, &index, &label);
            assert!(decoded.decode_holds.is_empty(), "{label}");
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), compact, "{label}");
        }
        // Loading never rewrites; the next save writes compact and still fences.
        assert_eq!(&fs::read(&path).unwrap(), bytes);
        for bounded in [false, true] {
            fs::write(&path, bytes).unwrap();
            let mut current = ScanIndex::load(&path).unwrap();
            let mut stale = ScanIndex::load(&path).unwrap();
            if bounded {
                current.save_with_read_limit(&path, 1024 * 1024).unwrap();
            } else {
                current.save(&path).unwrap();
            }
            assert_eq!(current.generation, index.generation + 1);
            let saved = fs::read(&path).unwrap();
            assert_eq!(saved, serde_json::to_vec(&current).unwrap(), "{layout}");
            stale.resume_after_path = Some("stale".into());
            assert!(stale.save(&path).is_err());
            assert!(stale.save_with_read_limit(&path, 1024 * 1024).is_err());
            assert_eq!(stale.generation, index.generation);
            assert_eq!(fs::read(&path).unwrap(), saved);
            assert_same_state(&ScanIndex::load(&path).unwrap(), &current, layout);
        }
    }
}

#[test]
fn held_slots_cross_both_layouts_and_save_counts_the_written_bytes() {
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-held");
    let path = scratch.as_ref().join("index.json");
    let mut seed = synthetic_index(16);
    seed.save(&path).unwrap();
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
        let bounded = claude_request_census::decode_bounded_index(&bytes).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        for (reader, decoded) in [
            ("streaming_cas", &streamed),
            ("bounded_cas", &bounded),
            ("load", &loaded),
        ] {
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
        for bounded in [false, true] {
            if bounded {
                loaded
                    .save_with_read_limit(&path, 32 * 1024 * 1024)
                    .unwrap();
            } else {
                loaded.save(&path).unwrap();
            }
            let saved = fs::read(&path).unwrap();
            // The admission check counted exactly the bytes the save wrote,
            // and the next restart measures its budget on those same bytes.
            assert_eq!(
                lenient_decode::written_len(&loaded).unwrap(),
                saved.len() as u64,
                "{layout}"
            );
            assert_eq!(
                saved,
                serde_json::to_vec_pretty(&loaded).unwrap(),
                "{layout}"
            );
            assert_eq!(raw_slot(&saved, "files", "held-opaque"), original);
            let restarted = ScanIndex::load(&path).unwrap();
            assert!(restarted.decode_holds.same_as(&loaded.decode_holds));
            assert_same_state(&restarted, &loaded, layout);
        }
    }
}

#[test]
fn hold_funded_by_legacy_pretty_whitespace_still_saves() {
    // Above the 1 MiB floor the restart admission is input bytes / 8. Build
    // a hold that an older pretty file funds but compact output of the same
    // state would not: saving must neither refuse every cycle nor shrink it.
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-legacy-hold");
    let path = scratch.as_ref().join("index.json");
    let mut seed = synthetic_index(2048);
    seed.save(&path).unwrap();
    let mut value = serde_json::to_value(&seed).unwrap();
    let pretty_base = serde_json::to_vec_pretty(&value).unwrap().len();
    let compact_base = serde_json::to_vec(&value).unwrap().len();
    value["files"]["legacy-held"] =
        serde_json::json!({"unknown": "x".repeat((pretty_base + compact_base) / 14)});
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.decode_holds_file("legacy-held"));
    let held = loaded.decode_holds.held_bytes();
    let compact_len = serde_json::to_vec(&loaded).unwrap().len() as u64;
    assert!(held > 1024 * 1024);
    assert!(held <= lenient_decode::hold_bytes_limit(bytes.len() as u64));
    assert!(
        held > lenient_decode::hold_bytes_limit(compact_len),
        "held={held} compact={compact_len} pretty={}",
        bytes.len()
    );
    // Plain save only: this corpus is far over the bounded reader's node cap.
    for _ in 0..2 {
        loaded.save(&path).unwrap();
        let saved = fs::read(&path).unwrap();
        assert_eq!(saved, serde_json::to_vec_pretty(&loaded).unwrap());
        assert_eq!(
            raw_slot(&saved, "files", "legacy-held"),
            raw_slot(&bytes, "files", "legacy-held")
        );
        let restarted = ScanIndex::load(&path).unwrap();
        assert!(restarted.decode_holds.same_as(&loaded.decode_holds));
    }
}
