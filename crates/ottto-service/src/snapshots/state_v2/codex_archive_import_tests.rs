use super::*;

/// [format] production Claude imports retain pre-archive presence bytes and row commitments.
#[test]
fn production_import_preserves_pre_archive_presence_and_rows() {
    // Preserve the historical inventory boundary independently of the
    // production exclusion predicate and its appended v1 decoder slots.
    let historical = &crate::snapshots::lenient_decode::FIELDS[..89];
    assert_eq!(historical.last(), Some(&"upload_context_proof"));
    // Claude fields appended after the archive slots stay in presence.
    let fields: Vec<&str> = historical
        .iter()
        .copied()
        .chain(["copy_prefix_last_accepted_nonce"])
        .collect();
    let positional = original_presence(b"[2,0,null,{}]".as_slice()).unwrap();
    let positional_expected: BTreeMap<String, bool> = fields
        .iter()
        .enumerate()
        .map(|(slot, name)| ((*name).into(), slot < 4))
        .collect();
    assert_eq!(positional, positional_expected);
    for shape in ["object", "sharded"] {
        let c = Corpus::new();
        let logical = if shape == "sharded" {
            c.sharded();
            let fixture: serde_json::Value = serde_json::from_str(include_str!(
                "../../../tests/fixtures/scan_index/real-shaped-v1.json"
            ))
            .unwrap();
            fixture["logical"].clone()
        } else {
            let value = serde_json::json!({
                "schema_version": 2, "generation": 0,
                "upload_context_fingerprint": null, "files": {}
            });
            ottto_core::write_owner_only_file_atomic(&c.path, &serde_json::to_vec(&value).unwrap())
                .unwrap();
            value
        };
        let expected: BTreeMap<String, bool> = fields
            .iter()
            .map(|name| ((*name).into(), logical.get(*name).is_some()))
            .collect();
        let original = Original::read(&c.path).unwrap();
        assert_eq!(original.presence, expected, "{shape}");
        let index = ScanIndex::load(&c.path).unwrap();
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&c.path, ".v2.sqlite.import")).unwrap();
        db.path_extractor(kinds::private_paths);
        db.reference_extractor(kinds::references);
        db.control(
            "identity",
            &Identity {
                format: FORMAT,
                db_id: "synthetic-proof".into(),
                binding: c.binding(),
                fence_generation: index.generation + 1,
            },
        )
        .unwrap();
        db.control("generation", &index.generation).unwrap();
        import_graph(&mut db, &index, Some(&original)).unwrap();
        let presence: BTreeMap<String, bool> = db.read_control("field_presence").unwrap().unwrap();
        assert_eq!(
            serde_json::to_vec(&presence).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        // Hydration accepts only original names; layout 3 adds the nonce.
        assert!(presence.keys().all(|name| fields.contains(&name.as_str())));
        let (restored, mut actual) = hydrate_context(&mut db).unwrap();
        let mut control = KindCx::default();
        control.binding = Some(c.binding());
        control.presence = expected;
        control.layout = actual.layout;
        control.layout_recorded = actual.layout_recorded;
        // Baseline enumeration consumes the hydrated ordinal inventory;
        // both projections refer to this same committed store's windows.
        control.account_ids = actual.account_ids.clone();
        control.account_controls = actual.account_controls;
        let actual = kinds::baseline(&restored, &mut actual).unwrap().rows;
        let mut control_index = index.clone();
        control_index.generation += 1;
        let control = kinds::baseline(&control_index, &mut control).unwrap().rows;
        assert_eq!(actual, control, "{shape}: every row value commitment");
    }
}
