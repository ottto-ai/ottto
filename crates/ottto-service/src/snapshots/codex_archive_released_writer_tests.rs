#[test]
fn correction_index_loads_in_both_released_entry_decoders() {
    let f = ArchiveFixture::new(b"synthetic-metadata-only");
    let mut index = archive_downgrade_index(&f, Some(CodexZstCause::CorrectionUnapplied));
    for entry in index.files.values_mut() {
        let archive = entry.archive.as_mut().unwrap();
        archive.user_change = true;
        archive.user_context = Some(user_context("A"));
        archive.user_generation = 7;
        archive.user_change_spent = 7;
    }
    assert_released_archive_roundtrip(index, &f);
}

#[test]
fn released_writer_without_archive_cannot_strand_an_owed_correction() {
    let f = ArchiveFixture::new(b"synthetic-metadata-only");
    let key = local_index_key(&f.0);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        ScanIndexEntry {
            size_bytes: fs::metadata(&f.0).unwrap().len(),
            modified_unix_seconds: 42,
            source_file_fingerprint: "synthetic-released-file".into(),
            last_snapshot_fingerprint: Some("retained-entity".into()),
            last_upload_body_witness: Some("retained-body".into()),
            ..Default::default()
        },
    );
    index
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["retained-entity".into()]));
    let bytes = serde_json::to_vec(&index).unwrap();
    for (release, pin) in ARCHIVE_RELEASED_DECODERS {
        let old = decode_released_archive_index(&bytes, pin);
        let entry = old["files"][&key].as_object().unwrap();
        assert!(!entry.contains_key("archive"), "real released-writer shape");
        assert!(!entry.contains_key("codex_compressed_hold"));
        for name in [
            "user_context",
            "user_change",
            "user_generation",
            "user_change_spent",
        ] {
            assert!(!entry.contains_key(name));
        }
        let path =
            f.0.parent()
                .unwrap()
                .join(format!("{release}-released-writer.json"));
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        for _ in 0..3 {
            let (mut restored, origin) =
                ScanIndex::load_inner(&path, Some(SnapshotSource::Codex)).unwrap();
            assert!(matches!(origin, LoadOrigin::Loaded(_)));
            assert!(restored.files[&key].archive.is_none());
            restored.activate_archive_user_context(user_context("unchanged-policy"));
            assert!(
                restored.files[&key].archive.is_none(),
                "activation grants nothing: {release}"
            );
            let (mut restored, _, rows, _) = archive_pass(&f, restored, false, None);
            assert_eq!(decodes(&rows), 0, "unfunded, no A3 or recovery decode");
            assert!(!rows
                .iter()
                .any(|r| r["counts"]["compressed_user_change"].as_u64().unwrap_or(0) > 0));
            assert!(
                restored.files[&key].archive.is_none(),
                "no stranded correction hold: {release}"
            );
            assert_eq!(
                restored.files[&key].last_snapshot_fingerprint.as_deref(),
                Some("retained-entity")
            );
            assert_eq!(
                restored.files[&key].last_upload_body_witness.as_deref(),
                Some("retained-body")
            );
            restored.save(&path).unwrap();
        }
    }
}
