use super::*;
fn bytes(reader: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}
fn manifest(s: &Scratch) -> Value {
    serde_json::from_slice(&fs::read(s.root()).unwrap()).unwrap()
}
fn replace_manifest(s: &Scratch, value: &Value) {
    fs::write(s.root(), serde_json::to_vec(value).unwrap()).unwrap();
}
fn object_path(s: &Scratch, object: &Value) -> PathBuf {
    let slot = &object["slot"];
    let label = if slot["kind"] == "metadata" {
        "metadata".to_string()
    } else {
        let tag = match slot["field"].as_str().unwrap() {
            "account_pending" => "account",
            "usage_pending" => "usage",
            "request_census" => "census",
            _ => panic!(),
        };
        format!("{tag}-{:02x}", slot["bucket"].as_u64().unwrap())
    };
    s.0.join("scan-index.json.shards").join(format!(
        "{label}-{}.json",
        object["digest"].as_str().unwrap()
    ))
}
#[test]
fn each_missing_stale_or_corrupt_map_is_unknown_and_siblings_and_metadata_survive() {
    let fields = [
        Field::AccountPending,
        Field::UsagePending,
        Field::RequestCensus,
    ];
    for (affected, field) in fields.into_iter().enumerate() {
        for damage in 0..8 {
            let s = Scratch::new();
            let logical = s.install();
            let mut root = manifest(&s);
            let index = root["objects"]
                .as_array()
                .unwrap()
                .iter()
                .position(|o| {
                    o["slot"]["field"]
                        == ["account_pending", "usage_pending", "request_census"][affected]
                })
                .unwrap();
            let path = object_path(&s, &root["objects"][index]);
            match damage {
                0 => fs::remove_file(path).unwrap(),
                1 => {
                    root["objects"][index]["generation"] = json!(6);
                    replace_manifest(&s, &root);
                }
                2 => fs::write(path, b"{corrupt}").unwrap(),
                3 => {
                    root["objects"][index]["digest"] = json!("0".repeat(64));
                    replace_manifest(&s, &root);
                }
                4 => {
                    root["maps"].as_array_mut().unwrap().remove(affected);
                    replace_manifest(&s, &root);
                }
                5 | 6 => {
                    // Lost descriptors cannot establish an empty map, whether
                    // its paired inventory is also lost or still names a bucket.
                    fs::remove_file(path).unwrap();
                    root["objects"].as_array_mut().unwrap().remove(index);
                    if damage == 5 {
                        root["maps"].as_array_mut().unwrap().remove(affected);
                    }
                    replace_manifest(&s, &root);
                }
                7 => {
                    root["objects"][index]
                        .as_object_mut()
                        .unwrap()
                        .remove("generation");
                    replace_manifest(&s, &root);
                }
                _ => unreachable!(),
            }
            let before = fs::read(s.root()).unwrap();
            let store = s.store();
            let Opened::Partial(mut partial, witness) = store.open().unwrap() else {
                panic!("map must become unknown")
            };
            assert_eq!(witness.generation(), Some(7));
            let metadata: Value = serde_json::from_slice(&bytes(&mut partial.metadata)).unwrap();
            assert_eq!(
                metadata["schema_version"],
                json!(3),
                "partial metadata cannot masquerade as a complete logical-2 index"
            );
            assert_eq!(metadata["files"], logical["files"]);
            assert_eq!(
                metadata["accepted_snapshot_fingerprints"],
                logical["accepted_snapshot_fingerprints"]
            );
            assert_eq!(metadata["opaque"], logical["opaque"]);
            for (i, map) in partial.maps.iter_mut().enumerate() {
                match map {
                    MapAvailability::Unknown(unavailable) => {
                        assert_eq!(i, affected);
                        assert_eq!(unavailable.map, field);
                        assert!(!unavailable.cause.label().is_empty());
                    }
                    MapAvailability::Known(reader) => {
                        assert_ne!(i, affected);
                        let actual: Value = serde_json::from_slice(&bytes(reader)).unwrap();
                        assert_eq!(
                            serde_json::to_vec(&actual[fields[i].name()]).unwrap(),
                            serde_json::to_vec(&logical[fields[i].name()]).unwrap()
                        );
                    }
                }
            }
            let stats = store.take_read_stats();
            assert_eq!(
                stats.index_shard_unavailable.iter().flatten().sum::<u64>(),
                1
            );
            assert_eq!(
                stats.index_shard_unavailable[affected].iter().sum::<u64>(),
                1
            );
            assert!(store
                .write_legacy(&witness, 8, |_| panic!("unknown maps must not publish"))
                .is_err());
            assert_eq!(fs::read(s.root()).unwrap(), before);
        }
    }
}
#[test]
fn byte_exact_logical2_legacy_serializer_round_trip_for_all_moved_maps() {
    let s = Scratch::new();
    let legacy = s.install();
    let (actual, _) = opened(&s.store());
    // The SAME legacy serializer after decode, not a string/tree equality check.
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&legacy).unwrap()
    );
    for field in [
        Field::AccountPending,
        Field::UsagePending,
        Field::RequestCensus,
    ] {
        assert_eq!(
            serde_json::to_vec(&actual[field.name()]).unwrap(),
            serde_json::to_vec(&legacy[field.name()]).unwrap()
        );
    }
}
#[test]
fn fresh_orphans_discard_but_prior_quarantine_legacy_marker_or_observed_root_refuse() {
    let s = Scratch::new();
    s.install();
    fs::remove_file(s.root()).unwrap();
    let store = s.store();
    assert!(matches!(store.open().unwrap(), Opened::Missing(_)));
    assert!(!s.0.join("scan-index.json.shards").exists());
    assert_eq!(store.take_read_stats().scanindex_orphan_init_discarded, 1);
    for witness in [
        "scan-index.corrupt.1.2.json",
        "scan-index.legacy.json",
        "scan-index.json.storage-prior",
    ] {
        let s = Scratch::new();
        s.install();
        fs::remove_file(s.root()).unwrap();
        fs::write(s.0.join(witness), b"prior state").unwrap();
        let before = fs::read_dir(s.0.join("scan-index.json.shards"))
            .unwrap()
            .count();
        let store = s.store();
        assert!(store.open().is_err());
        assert_eq!(store.take_read_stats().scanindex_orphan_init_discarded, 0);
        assert_eq!(
            fs::read_dir(s.0.join("scan-index.json.shards"))
                .unwrap()
                .count(),
            before
        );
    }
    let s = Scratch::new();
    s.install();
    let store = s.store();
    let _ = opened(&store);
    fs::remove_file(s.root()).unwrap();
    assert!(store.open().is_err());
}
#[test]
fn undeclared_inventory_is_unknown_while_declared_empty_is_known_empty() {
    let s = Scratch::new();
    s.install();
    let mut root = manifest(&s);
    root.as_object_mut().unwrap().remove("maps");
    replace_manifest(&s, &root);
    let Opened::Partial(partial, _) = s.store().open().unwrap() else {
        panic!()
    };
    assert!(partial
        .maps
        .iter()
        .all(|m| matches!(m, MapAvailability::Unknown(_))));
}
#[test]
fn semantic_decoder_failure_is_unknown_and_does_not_erase_the_other_maps() {
    let s = Scratch::new();
    s.install();
    let store = s.store();
    let Opened::Partial(partial, _) = store
        .open_with_map_validator(&mut |field, reader| {
            let _: Value = serde_json::from_reader(reader)?;
            if field == Field::UsagePending {
                anyhow::bail!("fixture existing codec refused")
            }
            Ok(())
        })
        .unwrap()
    else {
        panic!()
    };
    assert!(matches!(partial.maps[0], MapAvailability::Known(_)));
    assert!(matches!(
        partial.maps[1],
        MapAvailability::Unknown(MapUnavailable {
            cause: UnavailableCause::Decode,
            ..
        })
    ));
    assert!(matches!(partial.maps[2], MapAvailability::Known(_)));
    assert_eq!(
        store.take_read_stats().index_shard_unavailable[1][UnavailableCause::Decode as usize],
        1
    );
}

#[test]
fn recognized_committed_root_survives_restart_as_prior_state_evidence() {
    let s = Scratch::new();
    s.install();
    let first = s.store();
    let _ = opened(&first);
    drop(first);
    assert!(s.0.join("scan-index.json.storage-prior").exists());
    fs::remove_file(s.root()).unwrap();
    let restarted = s.store();
    assert!(restarted.open().is_err());
    assert_eq!(
        restarted.take_read_stats().scanindex_orphan_init_discarded,
        0
    );
    assert_eq!(
        fs::read_dir(s.0.join("scan-index.json.shards"))
            .unwrap()
            .count(),
        4
    );
}
#[test]
fn unshipped_draft_never_infers_reference_generations_or_empty_inventories() {
    for affected in 0..3 {
        let fixture: Value = serde_json::from_str(include_str!(
            "../fixtures/scan_index/sharded-format1-original.json"
        ))
        .unwrap();
        let s = Scratch::new();
        let logical = s.install();
        let mut root: Value = serde_json::from_str(fixture["root"].as_str().unwrap()).unwrap();
        let index = affected + 1;
        fs::remove_file(object_path(&s, &root["objects"][index])).unwrap();
        root["objects"].as_array_mut().unwrap().remove(index);
        replace_manifest(&s, &root);
        // Even metadata is unpaired in the unshipped draft: do not invent it.
        assert!(s.store().open().is_err());
        // With metadata explicitly paired, it remains usable, but no absent
        // inventory (including the descriptor-free map) becomes known empty.
        root["objects"][0]["generation"] = root["generation"].clone();
        replace_manifest(&s, &root);
        let before = fs::read(s.root()).unwrap();
        let store = s.store();
        let Opened::Partial(mut partial, witness) = store.open().unwrap() else {
            panic!("unshipped draft maps must remain unknown")
        };
        let metadata: Value = serde_json::from_slice(&bytes(&mut partial.metadata)).unwrap();
        assert_eq!(metadata["files"], logical["files"]);
        for (i, field) in [
            Field::AccountPending,
            Field::UsagePending,
            Field::RequestCensus,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                matches!(partial.maps[i], MapAvailability::Unknown(MapUnavailable {
                map, cause: UnavailableCause::Descriptor,
            }) if map == field)
            );
        }
        let stats = store.take_read_stats();
        for counts in stats.index_shard_unavailable {
            assert_eq!(counts.iter().sum::<u64>(), 1);
            assert_eq!(counts[UnavailableCause::Descriptor as usize], 1);
        }
        assert!(store.compare(&witness).is_err());
        assert!(store
            .write_legacy(&witness, 8, |_| panic!("unknown maps must not export"))
            .is_err());
        assert_eq!(fs::read(s.root()).unwrap(), before);
    }
}

#[test]
fn root_presence_is_recorded_even_if_metadata_cannot_be_read() {
    let s = Scratch::new();
    s.install();
    let root = manifest(&s);
    fs::remove_file(object_path(&s, &root["objects"][0])).unwrap();
    assert!(s.store().open().is_err());
    assert!(s.0.join("scan-index.json.storage-prior").exists());
    fs::remove_file(s.root()).unwrap();
    let restarted = s.store();
    assert!(restarted.open().is_err());
    assert_eq!(
        fs::read_dir(s.0.join("scan-index.json.shards"))
            .unwrap()
            .count(),
        3
    );
    assert_eq!(
        restarted.take_read_stats().scanindex_orphan_init_discarded,
        0
    );
}
#[test]
fn interrupted_prior_marker_is_atomically_repaired_without_losing_the_index() {
    for marker in [b"".as_slice(), b"scan_index_prior_root_v1".as_slice()] {
        let s = Scratch::new();
        let expected = s.install();
        let path = s.0.join("scan-index.json.storage-prior");
        fs::write(&path, marker).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(opened(&s.store()).0, expected);
        assert_eq!(fs::read(path).unwrap(), b"scan_index_prior_root_v1\n");
    }
}
#[test]
fn explicit_empty_inventory_is_known_empty_even_when_an_old_bucket_is_an_orphan() {
    let s = Scratch::new();
    s.install();
    let mut root = manifest(&s);
    root["maps"][0]["buckets"] = json!([]);
    root["objects"]
        .as_array_mut()
        .unwrap()
        .retain(|o| o["slot"]["field"] != "account_pending");
    replace_manifest(&s, &root);
    let store = s.store();
    let (logical, _) = opened(&store);
    assert_eq!(logical[Field::AccountPending.name()], json!({}));
    assert!(!logical[Field::UsagePending.name()]
        .as_object()
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .take_read_stats()
            .index_shard_unavailable
            .iter()
            .flatten()
            .sum::<u64>(),
        0
    );
}
