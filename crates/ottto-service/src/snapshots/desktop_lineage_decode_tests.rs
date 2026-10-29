use super::*;
include!("desktop_lineage_legacy_fields.rs");

const CHILD: &str = "00000000-0000-4000-8000-000000000081";
const PARENT: &str = "00000000-0000-4000-8000-000000000082";

fn seed() -> ScanIndex {
    let mut index = ScanIndex::default();
    index.files.insert(
        "/synthetic/child.jsonl".into(),
        super::super::tests::manifest_index_entry(Some(&"a".repeat(64))),
    );
    index.claude_desktop_completed_lineage = Some(BTreeMap::from([(CHILD.into(), PARENT.into())]));
    index.claude_desktop_lineage_file_edges.insert(
        "/synthetic/child.jsonl".into(),
        desktop_lineage::edge_fingerprint(Some(PARENT)),
    );
    index
}

fn read_registry(bytes: &[u8], fields: &'static [&'static str]) -> ScanIndex {
    let mut reader = std::io::Cursor::new(bytes);
    let census_resources = validate_original(&mut reader).unwrap();
    let mut decoder = Decoder {
        reader,
        input_len: bytes.len() as u64,
        held_bytes: 0,
        held_count: 0,
        holds: Holds::default(),
        counts: Counts::default(),
        family_spans: BTreeMap::new(),
        census_resources,
    };
    decoder.index_fields(Pass::Full, fields).unwrap()
}

#[test]
fn desktop_lineage_old_201_202_203_name_registries_ignore_and_drop_new_root_fields() {
    // These use the unchanged production unknown-name/span/seek code with
    // source-pinned release FIELDS. They do not execute historical binaries or
    // certify unrelated old record codecs. Object writes only: old positional
    // readers deliberately reject an appended slot.
    let seed = seed();
    let bytes = serde_json::to_vec(&seed).unwrap();
    for (version, fields) in [
        ("0.1.201", FIELDS_201),
        ("0.1.202", FIELDS_202_203),
        ("0.1.203", FIELDS_202_203),
    ] {
        let old = read_registry(&bytes, fields);
        assert!(old.claude_desktop_completed_lineage.is_none(), "{version}");
        assert!(
            old.claude_desktop_lineage_file_edges.is_empty(),
            "{version}"
        );
        assert_eq!(
            old.files["/synthetic/child.jsonl"].source_file_fingerprint,
            seed.files["/synthetic/child.jsonl"].source_file_fingerprint
        );
        let old_save = serde_json::to_vec(&old).unwrap();
        assert!(!String::from_utf8_lossy(&old_save).contains("claude_desktop_completed_lineage"));
        let upgraded = read(std::io::Cursor::new(old_save), "load", "claude_code").unwrap();
        assert!(upgraded.claude_desktop_completed_lineage.is_none());
    }
}

#[test]
fn desktop_lineage_unknown_and_complete_empty_roundtrip_without_changing_entry_layout() {
    let mut index = seed();
    for edges in [
        None,
        Some(BTreeMap::new()),
        Some(BTreeMap::from([(CHILD.into(), PARENT.into())])),
    ] {
        index.claude_desktop_completed_lineage = edges.clone();
        let bytes = serde_json::to_vec(&index).unwrap();
        let loaded = read(std::io::Cursor::new(&bytes), "load", "claude_code").unwrap();
        assert_eq!(loaded.claude_desktop_completed_lineage, edges);
        assert_eq!(
            loaded.claude_desktop_lineage_file_edges,
            index.claude_desktop_lineage_file_edges
        );
        assert_eq!(
            read_bounded(&bytes)
                .unwrap()
                .claude_desktop_completed_lineage,
            edges
        );
    }
    // Independent native pin; no baseline was added to the file entry.
    #[cfg(target_pointer_width = "64")]
    assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 480);
}

#[test]
fn desktop_lineage_malformed_and_oversized_projection_defaults_unknown_and_counts_drops() {
    for bad in [
        json!([CHILD, PARENT]),
        json!({"not-a-uuid": PARENT}),
        json!({CHILD: CHILD}),
        json!({CHILD: 3}),
        json!({CHILD:"x".repeat(desktop_lineage::MAX_DECODE_BYTES as usize)}),
    ] {
        let mut value = serde_json::to_value(seed()).unwrap();
        value["claude_desktop_completed_lineage"] = bad;
        let (loaded, rows) = crate::local_resource_diagnostics::capture(|| {
            read(
                std::io::Cursor::new(serde_json::to_vec(&value).unwrap()),
                "load",
                "claude_code",
            )
            .unwrap()
        });
        assert!(loaded.claude_desktop_completed_lineage.is_none());
        assert_eq!(loaded.files.len(), 1, "selector damage never loses custody");
        assert_eq!(
            rows.iter()
                .filter_map(
                    |row| row["counts"]["desktop_metadata"]["lineage_selector_drops"].as_u64()
                )
                .sum::<u64>(),
            1
        );
    }
}

#[test]
fn desktop_lineage_projection_cap_is_enforced_on_decode_and_complete_write() {
    let edges: BTreeMap<String, String> = (0..=desktop_lineage::MAX_EDGES)
        .map(|n| {
            (
                format!("{n:08x}-0000-4000-8000-000000000001"),
                PARENT.to_owned(),
            )
        })
        .collect();
    let mut value = serde_json::to_value(seed()).unwrap();
    value["claude_desktop_completed_lineage"] = serde_json::to_value(&edges).unwrap();
    let loaded = read(
        std::io::Cursor::new(serde_json::to_vec(&value).unwrap()),
        "load",
        "claude_code",
    )
    .unwrap();
    assert!(loaded.claude_desktop_completed_lineage.is_none());
    let mut index = seed();
    index.claude_desktop_lineage_census_complete = true;
    let mut metadata = ClaudeTitleMetadata {
        spawn_lineage: edges
            .iter()
            .map(|(child, parent)| {
                (
                    child.clone(),
                    ClaudeDesktopSpawnLineage {
                        parent_session_id: parent.clone(),
                    },
                )
            })
            .collect(),
        ..Default::default()
    };
    metadata.install_completed_lineage(&mut index);
    assert!(index.claude_desktop_completed_lineage.is_none());
    metadata.spawn_lineage.pop_first();
    metadata.install_completed_lineage(&mut index);
    assert_eq!(
        index
            .claude_desktop_completed_lineage
            .as_ref()
            .unwrap()
            .len(),
        desktop_lineage::MAX_EDGES
    );
    let bytes = serde_json::to_vec(&index.claude_desktop_completed_lineage).unwrap();
    assert!(
        bytes.len() <= 319_489,
        "4096 canonical UUID pairs fit the stated compact JSON bound"
    );
}

#[test]
fn desktop_lineage_incomplete_page_freezes_projection_and_partial_save_keeps_old_file_baseline() {
    let previous = seed();
    let mut working = previous.clone();
    let old = working.claude_desktop_completed_lineage.clone();
    working.claude_desktop_lineage_census_complete = false;
    let mut metadata = ClaudeTitleMetadata::default();
    metadata.install_completed_lineage(&mut working);
    assert_eq!(working.claude_desktop_completed_lineage, old);
    // Complete replacement is root metadata; an unaccepted file still keeps
    // its own previous baseline, even after save and restart.
    working.claude_desktop_lineage_census_complete = true;
    metadata.install_completed_lineage(&mut working);
    working
        .files
        .get_mut("/synthetic/child.jsonl")
        .unwrap()
        .last_snapshot_fingerprint = Some("b".repeat(64));
    working.file_snapshot_fingerprints.insert(
        "/synthetic/child.jsonl".into(),
        BTreeSet::from(["b".repeat(64)]),
    );
    working.claude_desktop_lineage_file_edges.insert(
        "/synthetic/child.jsonl".into(),
        desktop_lineage::edge_fingerprint(None),
    );
    let subset = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        subset.claude_desktop_completed_lineage,
        Some(BTreeMap::new())
    );
    assert_eq!(
        subset.claude_desktop_lineage_file_edges,
        previous.claude_desktop_lineage_file_edges
    );
    let loaded = read(
        std::io::Cursor::new(serde_json::to_vec(&subset).unwrap()),
        "load",
        "claude_code",
    )
    .unwrap();
    assert_eq!(
        loaded.claude_desktop_lineage_file_edges,
        previous.claude_desktop_lineage_file_edges
    );
}
