// Runs on Linux: no funded decoder, native layout or runtime input is needed.
const ARCHIVE_RELEASED_DECODERS: [(&str, &str); 3] = [
    ("0.1.201", "7997fe740064273ffc145d2168c299f5d8b9ee3d"),
    ("R1", "0061a4b0cd2bb71510e67586e949a0362609e6ee"),
    ("R1-main", "ff914a4a036c6a25666fbcca46c45220bd3c4d97"),
];

// The released lenient decoder's files lane invokes this exact typed entry
// deserializer. Successful entries never enter its raw-hold/quarantine fallback.
// The harness preserves unrelated top-level slots opaquely; it does not vendor
// the whole historical loader or simulate its unrelated repair/GC paths.
fn decode_released_archive_index(bytes: &[u8], pin: &str) -> Value {
    assert!(ARCHIVE_RELEASED_DECODERS.iter().any(|(_, sha)| *sha == pin));
    let mut index: Value = serde_json::from_slice(bytes).unwrap();
    // Both pinned load_inner_with_support gates, without reset/fallback.
    assert_eq!(index["schema_version"], 2);
    assert!(
        index["accepted_snapshot_fingerprint_ledger_version"]
            .as_u64()
            .unwrap()
            <= 2
    );
    let files = index["files"].as_object_mut().unwrap();
    assert!(
        !files.is_empty(),
        "must actually decode branch-written entries"
    );
    for raw in files.values_mut() {
        let entry: released_archive_entry::ScanIndexEntry =
            serde_json::from_value(raw.clone()).expect("released entry decoder loads");
        // This is also a downgrade save: the released writer drops unknown
        // archive evidence while preserving every field it actually understood.
        *raw = serde_json::to_value(entry).unwrap();
    }
    index
}

fn archive_downgrade_index(f: &ArchiveFixture, extra: Option<CodexZstCause>) -> ScanIndex {
    let mut dispositions = vec![
        ArchiveDisposition::Held {
            cause: CodexZstCause::DecodeBudget,
        },
        ArchiveDisposition::Held {
            cause: CodexZstCause::AdmissionStarved,
        },
        ArchiveDisposition::Held {
            cause: CodexZstCause::SettlementStuck,
        },
        ArchiveDisposition::Held {
            cause: CodexZstCause::OutputHeld,
        },
        ArchiveDisposition::Refused {
            cause: CodexZstCause::DecodeFailed,
        },
        ArchiveDisposition::Pending {
            attempts: 6,
            retry_after: 42,
        },
        ArchiveDisposition::Acquired,
        ArchiveDisposition::Empty,
        ArchiveDisposition::HeaderValidated,
    ];
    if let Some(cause) = extra {
        dispositions.push(ArchiveDisposition::Held { cause });
    }
    let mut index = ScanIndex::default();
    for (n, disposition) in dispositions.into_iter().enumerate() {
        let mut archive = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
        archive.disposition = disposition;
        archive.decode_attempts = 6;
        archive.terminal_failures = 2;
        archive.terminal_attempt = 5;
        archive.body_witness = Some(format!("retained-body-{n}"));
        let entry = ScanIndexEntry {
            size_bytes: 123 + n as u64,
            modified_unix_seconds: 42,
            modified_unix_nanos: Some(17),
            source_file_fingerprint: format!("source-{n}"),
            last_snapshot_fingerprint: Some(format!("retained-entity-{n}")),
            last_upload_body_witness: archive.body_witness.clone(),
            effective_upload_body_witness_revision: 7,
            codex_counting_v2: true,
            codex_counting_owner: Some("a".repeat(64)),
            codex_protected_owner: Some("b".repeat(64)),
            codex_applied_tier_receipt: serde_json::from_value(json!({
                "version": 1, "derivation": "synthetic", "scope": "c".repeat(64),
                "records": 3, "prefix_digest": "d".repeat(64), "tiers": {"e": "f"}
            }))
            .unwrap(),
            codex_applied_tier_receipt_required: true,
            opened_changed_nanos: 19,
            opened_birth_nanos: 23,
            archive: Some(Box::new(archive)),
            ..Default::default()
        };
        let key = local_index_key(&f.0.with_file_name(format!("rollout-downgrade-{n}.jsonl.zst")));
        index.file_snapshot_fingerprints.insert(
            key.clone(),
            BTreeSet::from([format!("retained-entity-{n}")]),
        );
        index.files.insert(key, entry);
    }
    index
}

fn assert_released_archive_roundtrip(mut index: ScanIndex, f: &ArchiveFixture) {
    let path = f.0.parent().unwrap().join("branch-written-index.json");
    index.save(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    let written: Value = serde_json::from_slice(&bytes).unwrap();
    for (release, pin) in ARCHIVE_RELEASED_DECODERS {
        let old = decode_released_archive_index(&bytes, pin);
        assert_eq!(old["generation"], written["generation"]);
        assert_eq!(old["files"].as_object().unwrap().len(), index.files.len());
        assert_eq!(
            old["file_snapshot_fingerprints"],
            written["file_snapshot_fingerprints"]
        );
        for (key, raw) in written["files"].as_object().unwrap() {
            assert!(
                raw["archive"].is_object(),
                "branch writer premise: {release}"
            );
            let mut expected = raw.clone();
            expected.as_object_mut().unwrap().remove("archive");
            assert_eq!(old["files"][key], expected, "custody retained: {release}");
            assert!(old["files"][key].get("archive").is_none());
        }
        let old_path =
            f.0.parent()
                .unwrap()
                .join(format!("{release}-saved-index.json"));
        fs::write(&old_path, serde_json::to_vec(&old).unwrap()).unwrap();
        let (upgraded, origin) =
            ScanIndex::load_inner(&old_path, Some(SnapshotSource::Codex)).unwrap();
        assert!(
            matches!(origin, LoadOrigin::Loaded(_)),
            "no reset/quarantine: {release}"
        );
        assert!(upgraded.decode_held_file_keys().next().is_none());
        assert_eq!(upgraded.files.len(), index.files.len());
        assert_eq!(
            upgraded.file_snapshot_fingerprints,
            index.file_snapshot_fingerprints
        );
        assert!(upgraded.files.values().all(|entry| entry.archive.is_none()));
    }
    // Negative control: known released fields still use the actual strict type
    // decoder; replacing it with a Value-only fake would incorrectly accept this.
    let mut damaged = written["files"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    damaged["size_bytes"] = json!({"invalid": true});
    assert!(serde_json::from_value::<released_archive_entry::ScanIndexEntry>(damaged).is_err());
}

#[test]
fn branch_written_archive_index_loads_in_0201_and_r1_entry_decoders() {
    let f = ArchiveFixture::new(b"synthetic-metadata-only");
    assert_released_archive_roundtrip(archive_downgrade_index(&f, None), &f);
}
