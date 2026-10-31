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
    read_registry_pass(bytes, fields, Pass::Full)
}
fn read_registry_pass(bytes: &[u8], fields: &'static [&'static str], pass: Pass) -> ScanIndex {
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
        persistence_map: false,
    };
    decoder.index_fields(pass, fields).unwrap()
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
        for key in [
            "claude_desktop_completed_lineage",
            "claude_desktop_lineage_file_edges",
        ] {
            assert!(
                !String::from_utf8_lossy(&old_save).contains(key),
                "{version}: {key}"
            );
        }
        let upgraded = read(std::io::Cursor::new(old_save), "load", "claude_code").unwrap();
        assert!(upgraded.claude_desktop_completed_lineage.is_none());
        assert!(upgraded.claude_desktop_lineage_file_edges.is_empty());
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
    assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 560);
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
        bytes.len() <= desktop_lineage::MAX_PROJECTION_JSON_BYTES,
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
    // Commit and reload root metadata BEFORE reaching the unchanged child.
    let root_committed = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        root_committed.claude_desktop_completed_lineage,
        Some(BTreeMap::new())
    );
    assert_eq!(
        root_committed.claude_desktop_lineage_file_edges,
        previous.claude_desktop_lineage_file_edges
    );
    let root_committed = read(
        std::io::Cursor::new(serde_json::to_vec(&root_committed).unwrap()),
        "load",
        "claude_code",
    )
    .unwrap();
    let mut working = root_committed.clone();
    // The walk now reaches the child, but its replacement is unaccepted.
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
    let subset = working.committable_subset(&root_committed, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        subset.claude_desktop_completed_lineage,
        Some(BTreeMap::new())
    );
    assert_eq!(
        subset.files["/synthetic/child.jsonl"].last_snapshot_fingerprint,
        previous.files["/synthetic/child.jsonl"].last_snapshot_fingerprint
    );
    assert!(!subset
        .accepted_snapshot_fingerprints
        .contains(&"b".repeat(64)));
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

#[test]
fn desktop_lineage_repair_capture_carries_selectors_without_census_authority() {
    let seed = seed();
    let carry = read_registry_pass(
        &serde_json::to_vec(&seed).unwrap(),
        FIELDS,
        Pass::IdentityCarry,
    );
    assert_eq!(
        carry.claude_desktop_completed_lineage,
        seed.claude_desktop_completed_lineage
    );
    assert_eq!(
        carry.claude_desktop_lineage_file_edges,
        seed.claude_desktop_lineage_file_edges
    );
    let mut repaired = ScanIndex::default();
    repaired.carry_identity_from(carry).unwrap();
    assert_eq!(
        repaired.claude_desktop_completed_lineage,
        seed.claude_desktop_completed_lineage
    );
    assert_eq!(
        repaired.claude_desktop_lineage_file_edges,
        seed.claude_desktop_lineage_file_edges
    );
    assert!(!repaired.claude_desktop_lineage_census_complete);
    assert!(repaired.files.is_empty());
}

#[test]
fn desktop_lineage_malformed_file_baselines_default_empty_and_count_without_losing_projection() {
    let over_count: BTreeMap<_, _> = (0..=desktop_lineage::MAX_EDGES)
        .map(|n| (format!("/synthetic/{n}.jsonl"), "a".repeat(64)))
        .collect();
    for bad in [
        json!(["wrong shape"]),
        json!({"/synthetic/child.jsonl":"not-a-digest"}),
        json!({"/synthetic/child.jsonl":3}),
        json!({("k".repeat(8193)):"a".repeat(64)}),
        json!({"/synthetic/child.jsonl":"a".repeat(desktop_lineage::MAX_DECODE_BYTES as usize)}),
        serde_json::to_value(over_count).unwrap(),
    ] {
        let original = seed();
        let mut value = serde_json::to_value(&original).unwrap();
        value["claude_desktop_lineage_file_edges"] = bad;
        let (loaded, rows) = crate::local_resource_diagnostics::capture(|| {
            read(
                std::io::Cursor::new(serde_json::to_vec(&value).unwrap()),
                "load",
                "claude_code",
            )
            .unwrap()
        });
        assert!(loaded.claude_desktop_lineage_file_edges.is_empty());
        assert_eq!(
            loaded.claude_desktop_completed_lineage,
            original.claude_desktop_completed_lineage
        );
        assert_eq!(loaded.files.len(), original.files.len());
        assert_eq!(selector_drops(&rows), 1);
    }
}

fn selector_drops(rows: &[Value]) -> u64 {
    rows.iter()
        .filter_map(|row| row["counts"]["desktop_metadata"]["lineage_selector_drops"].as_u64())
        .sum()
}

#[test]
fn desktop_lineage_nested_optional_damage_preserves_load_cas_and_identity_custody() {
    let fields = [
        "claude_desktop_completed_lineage",
        "claude_desktop_lineage_file_edges",
    ];
    let mut original = seed();
    original
        .accepted_snapshot_fingerprints
        .insert("a".repeat(64));
    original.file_snapshot_fingerprints.insert(
        "/synthetic/child.jsonl".into(),
        BTreeSet::from(["a".repeat(64)]),
    );
    original.session_account_bindings.insert(
        "sibling-session".into(),
        SessionAccountBinding {
            account_identifier_hash: "a".repeat(64),
            workspace_identifier_hash: Some("b".repeat(64)),
        },
    );
    let owner = codex_protected_owner("synthetic-owner");
    original
        .files
        .get_mut("/synthetic/child.jsonl")
        .unwrap()
        .codex_protected_owner = Some(owner.clone());
    let scratch = crate::test_scratch::ScratchDir::new("desktop-lineage-depth");
    let path = scratch.join("index.json");
    // 65 also exercises wrong-shape normalization BEFORE bounded_shape's
    // depth-64 gate; 257 is valid JSON above the optional resource depth cap.
    for depth in [65, 257] {
        let nested = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        for damaged in [&fields[..1], &fields[1..], &fields[..]] {
            let mut value = serde_json::to_value(&original).unwrap();
            for field in damaged {
                value.as_object_mut().unwrap().remove(*field);
            }
            let mut bytes = serde_json::to_vec(&value).unwrap();
            assert_eq!(bytes.pop(), Some(b'}'));
            for field in damaged {
                bytes.extend_from_slice(format!(",\"{field}\":{nested}").as_bytes());
            }
            bytes.push(b'}');
            fs::write(&path, &bytes).unwrap();
            for mode in ["load", "streaming_cas", "bounded_cas", "identity"] {
                let (loaded, rows) = crate::local_resource_diagnostics::capture(|| match mode {
                    "load" => ScanIndex::load(&path).unwrap(),
                    "streaming_cas" => {
                        read_file(File::open(&path).unwrap(), "cas", "claude_code").unwrap()
                    }
                    "bounded_cas" => read_bounded(&bytes).unwrap(),
                    _ => read_identity_carry(File::open(&path).unwrap(), "claude_code").unwrap(),
                });
                assert_eq!(
                    selector_drops(&rows),
                    damaged.len() as u64,
                    "{mode}/{depth}"
                );
                assert_eq!(
                    loaded.session_account_bindings,
                    original.session_account_bindings
                );
                assert_eq!(
                    loaded.accepted_snapshot_fingerprints,
                    original.accepted_snapshot_fingerprints
                );
                assert_eq!(
                    loaded.file_snapshot_fingerprints,
                    original.file_snapshot_fingerprints
                );
                assert!(loaded.decode_holds.is_empty());
                if mode == "identity" {
                    // Identity capture intentionally skips file records; it
                    // retains ACK/owner bindings and never rewrites the source.
                    assert!(loaded.files.is_empty());
                } else {
                    assert_eq!(loaded.files.len(), original.files.len());
                    assert_eq!(
                        loaded.files["/synthetic/child.jsonl"].codex_protected_owner,
                        Some(owner.clone())
                    );
                    for (key, file) in &original.files {
                        assert_eq!(
                            loaded.files[key].source_file_fingerprint,
                            file.source_file_fingerprint
                        );
                    }
                }
                assert_eq!(
                    loaded.claude_desktop_completed_lineage,
                    if damaged.contains(&fields[0]) {
                        None
                    } else {
                        original.claude_desktop_completed_lineage.clone()
                    }
                );
                assert_eq!(
                    loaded.claude_desktop_lineage_file_edges,
                    if damaged.contains(&fields[1]) {
                        BTreeMap::new()
                    } else {
                        original.claude_desktop_lineage_file_edges.clone()
                    }
                );
                assert_eq!(fs::read(&path).unwrap(), bytes);
            }
        }
    }
}

#[test]
fn desktop_lineage_full_record_budget_refuses_only_new_baseline_on_existing_diagnostic_line() {
    let mut index = seed();
    index.claude_desktop_lineage_file_edges.clear();
    let entry = index.files["/synthetic/child.jsonl"].clone();
    let edge = desktop_lineage::edge_fingerprint(Some(PARENT));
    for n in 0..desktop_lineage::MAX_EDGES {
        let key = format!("/synthetic/{n}.jsonl");
        index.files.insert(key.clone(), entry.clone());
        index
            .claude_desktop_lineage_file_edges
            .insert(key, edge.clone());
    }
    let previous = index.claude_desktop_lineage_file_edges.clone();
    let key = "/synthetic/child.jsonl";
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.record_desktop_lineage_file_edge(key, edge.clone())
    });
    assert_eq!(index.claude_desktop_lineage_file_edges, previous);
    assert_eq!(selector_drops(&rows), 1);
    assert!(rows
        .iter()
        .any(|row| row["stage"] == "native_collection_page"));
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.record_desktop_lineage_file_edge(
            "/synthetic/0.jsonl",
            desktop_lineage::edge_fingerprint(None),
        )
    });
    assert_eq!(
        selector_drops(&rows),
        0,
        "existing baselines remain updateable at capacity"
    );
    assert_eq!(
        index.claude_desktop_lineage_file_edges.len(),
        desktop_lineage::MAX_EDGES
    );
}

#[test]
fn desktop_lineage_file_byte_budget_roundtrips_and_refuses_one_more_without_eviction() {
    let mut index = seed();
    index.claude_desktop_lineage_file_edges.clear();
    let entry = index.files["/synthetic/child.jsonl"].clone();
    // Escaped path bytes discriminate the JSON budget from raw key lengths.
    let keys: Vec<_> = (0..128)
        .map(|n| format!("/synthetic/{n:03}/{}", "\\".repeat(8000)))
        .collect();
    for key in &keys {
        index.files.insert(key.clone(), entry.clone());
    }
    let edge = desktop_lineage::edge_fingerprint(Some(PARENT));
    let mut refused = false;
    for key in &keys {
        let before = index.claude_desktop_lineage_file_edges.clone();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            index.record_desktop_lineage_file_edge(key, edge.clone())
        });
        if !index.claude_desktop_lineage_file_edges.contains_key(key) {
            assert_eq!(index.claude_desktop_lineage_file_edges, before);
            assert_eq!(selector_drops(&rows), 1);
            assert!(rows
                .iter()
                .any(|row| row["stage"] == "native_collection_page"));
            refused = true;
            break;
        }
        assert_eq!(selector_drops(&rows), 0);
    }
    assert!(refused, "byte budget must bind before the record cap");
    assert!(index.claude_desktop_lineage_file_edges.len() < desktop_lineage::MAX_EDGES);
    let map_bytes = serde_json::to_vec(&index.claude_desktop_lineage_file_edges).unwrap();
    assert!(map_bytes.len() as u64 <= desktop_lineage::MAX_DECODE_BYTES);
    assert!(
        map_bytes.len() > desktop_lineage::MAX_DECODE_BYTES as usize - 20_000,
        "the accepted map reaches the byte budget within one escaped record"
    );
    let scratch = crate::test_scratch::ScratchDir::new("desktop-lineage-byte-budget");
    let path = scratch.join("index.json");
    index.save(&path).unwrap();
    let (loaded, rows) =
        crate::local_resource_diagnostics::capture(|| ScanIndex::load(&path).unwrap());
    assert_eq!(selector_drops(&rows), 0);
    assert_eq!(
        loaded.claude_desktop_lineage_file_edges,
        index.claude_desktop_lineage_file_edges
    );
    assert_eq!(
        loaded.claude_desktop_completed_lineage,
        index.claude_desktop_completed_lineage
    );
    assert_compact_to_held_transition_keeps_admitted_baselines();
}

fn assert_compact_to_held_transition_keeps_admitted_baselines() {
    let mut index = seed();
    index.claude_desktop_lineage_file_edges.clear();
    let entry = index.files["/synthetic/child.jsonl"].clone();
    let edge = desktop_lineage::edge_fingerprint(Some(PARENT));
    // Reproduce a previously admitted compact map: these medium keys fit the
    // compact cap, but root-level pretty indentation takes it above 1 MiB.
    let keys: Vec<_> = (0..desktop_lineage::MAX_EDGES)
        .map(|n| format!("/synthetic/{n:04}/{}", "k".repeat(169)))
        .collect();
    for key in &keys {
        assert_eq!(key.len(), 185);
        index.files.insert(key.clone(), entry.clone());
        if key != keys.last().unwrap() {
            index
                .claude_desktop_lineage_file_edges
                .insert(key.clone(), edge.clone());
        }
    }
    // Exercise actual admission of the final pair, rather than only seeding
    // a map whose size the writer might never have allowed.
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.record_desktop_lineage_file_edge(keys.last().unwrap(), edge)
    });
    assert_eq!(selector_drops(&rows), 0);
    assert_eq!(
        index.claude_desktop_lineage_file_edges.len(),
        desktop_lineage::MAX_EDGES
    );
    let expected = index.claude_desktop_lineage_file_edges.clone();
    let compact = serde_json::to_vec(&expected).unwrap();
    assert_eq!(compact.len(), 1_044_481);
    let scratch = crate::test_scratch::ScratchDir::new("desktop-lineage-held-byte-budget");
    let path = scratch.join("index.json");
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(ScanIndex::load(&path).unwrap()).unwrap();
    value["files"]["opaque-held"] =
        json!({"size_bytes":[], "codex_protected_owner":codex_protected_owner("held-owner")});
    // Prove this fixture discriminates ordinary recursive pretty formatting.
    let recursively_pretty = serde_json::to_vec_pretty(&value).unwrap();
    let root: BTreeMap<String, &RawValue> = serde_json::from_slice(&recursively_pretty).unwrap();
    assert_eq!(
        root["claude_desktop_lineage_file_edges"].get().len(),
        1_069_060
    );
    assert!(
        root["claude_desktop_lineage_file_edges"].get().len() as u64
            > desktop_lineage::MAX_DECODE_BYTES
    );
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut held = ScanIndex::load(&path).unwrap();
    assert!(!held.decode_holds.is_empty());
    assert_eq!(held.claude_desktop_lineage_file_edges, expected);
    held.save(&path).unwrap();
    let written = fs::read(&path).unwrap();
    let root: BTreeMap<String, &RawValue> = serde_json::from_slice(&written).unwrap();
    assert_eq!(
        root["claude_desktop_lineage_file_edges"].get().as_bytes(),
        compact
    );
    let (reloaded, rows) =
        crate::local_resource_diagnostics::capture(|| ScanIndex::load(&path).unwrap());
    assert_eq!(selector_drops(&rows), 0);
    assert_eq!(reloaded.claude_desktop_lineage_file_edges, expected);
    assert_eq!(
        reloaded.claude_desktop_completed_lineage,
        held.claude_desktop_completed_lineage
    );
    assert!(reloaded.decode_holds.same_as(&held.decode_holds));
    assert!(reloaded.decode_holds_file("opaque-held"));
}
