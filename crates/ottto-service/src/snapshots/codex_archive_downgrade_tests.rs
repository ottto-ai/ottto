// Rollback boundary, as checked bytes. The released writers 0.1.201
// (7997fe740064273ffc145d2168c299f5d8b9ee3d), R1 (0061a4b0cd2bb71510e67586e949a0362609e6ee)
// and R1-main (ff914a4a036c6a25666fbcca46c45220bd3c4d97) share one ScanIndexEntry
// without `archive` or `codex_compressed_hold`. Executing those old loaders is
// scripts/test_codex_zst_downgrade.py's job; these tests run no released code.

/// One scan index as the released writers save it: every released entry field
/// set, file incidence, and no archive custody.
fn released_index(entries: &[(String, Value)]) -> Value {
    let files: serde_json::Map<_, _> = entries.iter().cloned().collect();
    let incidence: serde_json::Map<_, _> = entries
        .iter()
        .map(|(key, entry)| (key.clone(), json!([entry["last_snapshot_fingerprint"]])))
        .collect();
    json!({
        "schema_version": 2,
        "generation": 1,
        "accepted_snapshot_fingerprint_ledger_version": 2,
        "files": files,
        "file_snapshot_fingerprints": incidence,
    })
}

fn released_entry(n: usize) -> Value {
    json!({
        "size_bytes": 123 + n,
        "modified_unix_seconds": 42,
        "modified_unix_nanos": 17,
        "source_file_fingerprint": format!("source-{n}"),
        "last_snapshot_fingerprint": format!("retained-entity-{n}"),
        "last_upload_body_witness": format!("retained-body-{n}"),
        "effective_upload_body_witness_revision": 7,
        "codex_protected_owner": "b".repeat(64),
        "codex_applied_tier_receipt": {
            "version": 1, "derivation": "synthetic", "scope": "c".repeat(64),
            "records": 3, "prefix_digest": "d".repeat(64), "tiers": {"e": "f"}
        },
        "codex_applied_tier_receipt_required": true,
        "codex_counting_v2": true,
        "codex_counting_owner": "a".repeat(64),
        "opened_changed_nanos": 19,
        "opened_birth_nanos": 23,
    })
}

fn load_released(f: &ArchiveFixture, released: &Value, name: &str) -> (ScanIndex, PathBuf) {
    let path = f.0.parent().unwrap().join(name);
    fs::write(&path, serde_json::to_vec(released).unwrap()).unwrap();
    let (index, origin) = ScanIndex::load_inner(&path, Some(SnapshotSource::Codex)).unwrap();
    assert!(
        matches!(origin, LoadOrigin::Loaded(_)),
        "no reset/quarantine"
    );
    assert!(index.decode_held_file_keys().next().is_none());
    assert!(index.files.values().all(|entry| entry.archive.is_none()));
    (index, path)
}

/// [format] The branch writer keeps released index bytes and adds archive
/// custody only under each entry's `archive` key, for every disposition and
/// with or without an owed correction: a released loader that skips unknown
/// keys sees exactly the released bytes.
#[test]
fn branch_writer_adds_only_archive_to_released_index_bytes() {
    let causes = [
        CodexZstCause::DecodeBudget,
        CodexZstCause::AdmissionStarved,
        CodexZstCause::SettlementStuck,
        CodexZstCause::OutputHeld,
        CodexZstCause::CorrectionUnapplied,
    ];
    let dispositions: Vec<_> = causes
        .into_iter()
        .map(|cause| ArchiveDisposition::Held { cause })
        .chain([
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
        ])
        .collect();
    for correction in [false, true] {
        let f = ArchiveFixture::new(b"synthetic-metadata-only");
        let entries: Vec<_> = (0..dispositions.len())
            .map(|n| {
                let path =
                    f.0.with_file_name(format!("rollout-downgrade-{n}.jsonl.zst"));
                (local_index_key(&path), released_entry(n))
            })
            .collect();
        let released = released_index(&entries);
        let (mut index, path) = load_released(&f, &released, "released-index.json");
        for (n, ((key, _), disposition)) in entries.iter().zip(&dispositions).enumerate() {
            let mut archive =
                ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
            archive.disposition = disposition.clone();
            archive.header_bound_reached = true;
            archive.decode_attempts = 6;
            archive.terminal_failures = 2;
            archive.terminal_attempt = 5;
            archive.body_witness = Some(format!("retained-body-{n}"));
            if correction {
                archive.user_change = true;
                archive.user_context = Some(user_context("A"));
                archive.user_generation = 7;
                archive.user_change_spent = 7;
            }
            index.files.get_mut(key).unwrap().archive = Some(Box::new(archive));
        }
        index.save(&path).unwrap();
        let mut written: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            written["file_snapshot_fingerprints"],
            released["file_snapshot_fingerprints"]
        );
        for (key, entry) in written["files"].as_object_mut().unwrap() {
            let archive = entry.as_object_mut().unwrap().remove("archive");
            assert!(archive.is_some_and(|a| a["header_bound_reached"] == true));
            assert_eq!(*entry, released["files"][key], "custody retained: {key}");
        }
    }
}

/// [format] Released-writer bytes carry no archive or correction fields.
/// Re-upgrading imports them without reset or hold, and three unfunded passes
/// with a user-context activation decode nothing, keep the settled entity and
/// body, and strand no correction.
#[test]
fn released_writer_index_cannot_strand_an_owed_correction() {
    let f = ArchiveFixture::new(b"synthetic-metadata-only");
    let key = local_index_key(&f.0);
    let released = released_index(&[(
        key.clone(),
        json!({
            "size_bytes": fs::metadata(&f.0).unwrap().len(),
            "modified_unix_seconds": 42,
            "source_file_fingerprint": "synthetic-released-file",
            "last_snapshot_fingerprint": "retained-entity",
            "last_upload_body_witness": "retained-body",
        }),
    )]);
    let (_, path) = load_released(&f, &released, "released-writer.json");
    for _ in 0..3 {
        let (mut restored, origin) =
            ScanIndex::load_inner(&path, Some(SnapshotSource::Codex)).unwrap();
        assert!(matches!(origin, LoadOrigin::Loaded(_)));
        restored.activate_archive_user_context(user_context("unchanged-policy"));
        assert!(
            restored.files[&key].archive.is_none(),
            "activation grants nothing"
        );
        let (mut restored, _, rows, _) = archive_pass(&f, restored, false, None);
        assert_eq!(decodes(&rows), 0, "unfunded, no A3 or recovery decode");
        assert!(!rows
            .iter()
            .any(|r| r["counts"]["compressed_user_change"].as_u64().unwrap_or(0) > 0));
        let entry = &restored.files[&key];
        assert!(entry.archive.is_none(), "no stranded correction hold");
        assert_eq!(
            entry.last_snapshot_fingerprint.as_deref(),
            Some("retained-entity")
        );
        assert_eq!(
            entry.last_upload_body_witness.as_deref(),
            Some("retained-body")
        );
        restored.save(&path).unwrap();
    }
}
