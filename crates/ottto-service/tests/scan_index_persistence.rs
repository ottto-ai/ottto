//! Isolated component qualification; no live daemon, credentials or transcripts.
//! The production old reader in this binary is intentionally UNMODIFIED; shared
//! load/save registration is delivered separately to the integration owner.
#[path = "../src/snapshots/scan_index_persistence.rs"]
mod persistence;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use persistence::*;
use serde_json::{json, Value};

const FIELDS: &[&str] = &[
    "files",
    "traversal",
    "quarantined_snapshot_fingerprints",
    "opaque",
    "accepted_snapshot_fingerprints",
];
const EDGES: [Edge; 13] = [
    Edge::PayloadTempCreated,
    Edge::PayloadPartialWrite,
    Edge::PayloadFlush,
    Edge::PayloadSync,
    Edge::PayloadRename,
    Edge::PayloadDirectorySync,
    Edge::RootTempCreated,
    Edge::RootPartialWrite,
    Edge::RootFlush,
    Edge::RootSync,
    Edge::RootRename,
    Edge::ParentSync,
    Edge::BeforeReturn,
];

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "scanindex-storage-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn root(&self) -> PathBuf {
        self.0.join("scan-index.json")
    }
    fn store(&self) -> LockedStore {
        store(&self.root())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn store(path: &Path) -> LockedStore {
    LockedStore::new(
        path,
        Binding {
            source: Source::Claude,
            namespace_hash: "a".repeat(64),
        },
        FIELDS,
    )
    .unwrap()
}
fn missing(store: &LockedStore) -> LoadedRoot {
    match store.open().unwrap() {
        Opened::Missing(root) => root,
        _ => panic!("expected missing"),
    }
}
fn load(store: &LockedStore) -> (Value, LoadedRoot) {
    match store.open().unwrap() {
        Opened::Sharded(mut reader, root) => {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            (serde_json::from_slice(&bytes).unwrap(), root)
        }
        _ => panic!("expected complete sharded generation"),
    }
}
struct Fixture {
    metadata: Value,
    maps: [BTreeMap<String, Value>; 3],
}
impl Fixture {
    fn new(revision: u64, count: usize) -> Self {
        let maps = std::array::from_fn(|field| {
            (0..count).map(|i| {
            (format!("synthetic-{i:06}"), json!({
                "revision": revision,
                "previous_windows": [{"members": ["synthetic"], "requests": [1, 7, 19], "window": i}],
                "member_occurrences": {"synthetic": [i, i+1]}, "field": field,
            }))
        }).collect()
        });
        Self {
            metadata: json!({"files": {}, "traversal": {"page": revision},
            "accepted_snapshot_fingerprints": ["synthetic-accepted"],
            "quarantined_snapshot_fingerprints": {"synthetic": {"attempt": revision}},
            "opaque": {"nondefault": 113, "retired_neighbor": 191}}),
            maps,
        }
    }
    fn plan(&self) -> Plan<'_> {
        let mut budget = usize::MAX;
        Plan {
            fixture: self,
            buckets: std::array::from_fn(|i| {
                BucketMap::new(
                    self.maps[i].iter().map(|(k, v)| (k.as_str(), v)),
                    &mut budget,
                )
                .unwrap()
            }),
            pretty: false,
        }
    }
    fn logical(&self, generation: u64) -> Value {
        let mut value = self.metadata.clone();
        value["schema_version"] = json!(LOGICAL_SCHEMA);
        value["generation"] = json!(generation);
        for (i, field) in [
            Field::AccountPending,
            Field::UsagePending,
            Field::RequestCensus,
        ]
        .iter()
        .enumerate()
        {
            value[field.name()] = serde_json::to_value(&self.maps[i]).unwrap();
        }
        value
    }
}
struct Plan<'a> {
    fixture: &'a Fixture,
    buckets: [BucketMap<'a, &'a Value>; 3],
    pretty: bool,
}
impl Fragments for Plan<'_> {
    fn minimum_logical_bytes(&self, generation: u64) -> Result<u64> {
        if self.pretty {
            Ok(serde_json::to_vec_pretty(&self.fixture.logical(generation))?.len() as u64)
        } else {
            Ok(0)
        }
    }
    fn slots(&self) -> Vec<Slot> {
        let mut slots = vec![Slot::Metadata];
        for (i, field) in [
            Field::AccountPending,
            Field::UsagePending,
            Field::RequestCensus,
        ]
        .iter()
        .enumerate()
        {
            slots.extend(self.buckets[i].buckets().map(|bucket| Slot::Bucket {
                field: *field,
                bucket,
            }));
        }
        slots
    }
    fn write(&self, slot: Slot, output: &mut dyn Write) -> Result<()> {
        match slot {
            Slot::Metadata if self.pretty => {
                serde_json::to_writer_pretty(output, &self.fixture.metadata)?
            }
            Slot::Metadata => serde_json::to_writer(output, &self.fixture.metadata)?,
            Slot::Bucket { field, bucket } => {
                let i = match field {
                    Field::AccountPending => 0,
                    Field::UsagePending => 1,
                    Field::RequestCensus => 2,
                };
                self.buckets[i].write(bucket, self.pretty, output)?;
            }
        }
        Ok(())
    }
}

#[test]
fn legacy_migration_seek_restart_sparse_noop_and_gc() {
    let scratch = Scratch::new();
    let fixture = Fixture::new(1, 500);
    let legacy = serde_json::to_vec(&fixture.logical(7)).unwrap();
    fs::write(scratch.root(), &legacy).unwrap();
    let store = scratch.store();
    let baseline = match store.open().unwrap() {
        Opened::Legacy(mut file, root) => {
            assert!(root.is_legacy());
            assert_eq!(root.generation(), Some(7));
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, legacy);
            root
        }
        _ => panic!("expected legacy"),
    };
    assert!(store.commit(&baseline, 7, &fixture.plan()).is_err());
    let first = store.commit(&baseline, 8, &fixture.plan()).unwrap();
    assert!(first.stats.written_bytes > legacy.len() as u64 / 2);
    assert!(first.stats.written_objects > 32);
    assert!(first.stats.root_bytes < MAX_ROOT_BYTES as u64);
    assert_eq!(load(&store).0, fixture.logical(8));
    let next = store.commit(&first.root, 9, &fixture.plan()).unwrap();
    assert_eq!(next.stats.written_bytes, 0);
    assert_eq!(next.stats.written_objects, 0);
    assert_eq!(next.stats.unchanged_objects, first.stats.written_objects);
    assert_eq!(load(&store).0, fixture.logical(9));
    let mut changed = Fixture::new(1, 500);
    changed.maps[0].get_mut("synthetic-000000").unwrap()["revision"] = json!(2);
    let sparse = store.commit(&next.root, 10, &changed.plan()).unwrap();
    eprintln!("scanindex_fixture_sizes legacy={} full_payload={} full_root={} sparse_payload={} sparse_root={} noop_payload={} noop_root={}", legacy.len(), first.stats.written_bytes, first.stats.root_bytes, sparse.stats.written_bytes, sparse.stats.root_bytes, next.stats.written_bytes, next.stats.root_bytes);
    assert_eq!(sparse.stats.written_objects, 1);
    assert!(sparse.stats.written_bytes * 10 < first.stats.written_bytes);
    assert_eq!(load(&store).0, changed.logical(10));
    let mut reader = match store.open().unwrap() {
        Opened::Sharded(reader, _) => reader,
        _ => unreachable!(),
    };
    let expected = serde_json::to_vec(&changed.logical(10)).unwrap();
    let end = reader.seek(SeekFrom::End(0)).unwrap();
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(end, bytes.len() as u64);
    // Compare byte slices from the same logical stream at every boundary and
    // interior; semantic JSON ordering need not equal serde Value ordering.
    for position in (0..bytes.len()).step_by(137) {
        reader.seek(SeekFrom::Start(position as u64)).unwrap();
        let mut tail = Vec::new();
        reader.by_ref().take(31).read_to_end(&mut tail).unwrap();
        assert_eq!(tail, bytes[position..(position + 31).min(bytes.len())]);
    }
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        serde_json::from_slice::<Value>(&expected).unwrap()
    );
    assert!(reader.seek(SeekFrom::End(-(end as i64) - 1)).is_err());
    assert!(reader.stream_position().unwrap() <= end);
    let gc = store
        .collect(
            &sparse.root,
            GcBudget {
                entries: 10_000,
                bytes: u64::MAX,
            },
            &mut GcCursor::default(),
        )
        .unwrap();
    assert_eq!(gc.removed, 1);
    assert!(gc.bytes > 0);
    assert!(!gc.incomplete);
    assert_eq!(load(&store).0, changed.logical(10));
    assert_eq!(load(&store).0, changed.logical(10));
}

#[test]
fn equal_generation_different_root_stale_clone_missing_and_binding_refuse() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let fixture = Fixture::new(1, 8);
    let missing_root = missing(&store);
    let first = store.commit(&missing_root, 1, &fixture.plan()).unwrap();
    let cloned = first.root.clone();
    assert!(store.commit(&cloned, 1, &fixture.plan()).is_err());
    assert!(store.commit(&missing_root, 1, &fixture.plan()).is_err());
    let mut root: Value = serde_json::from_slice(&fs::read(scratch.root()).unwrap()).unwrap();
    root["objects"].as_array_mut().unwrap().pop(); // Same generation, different manifest identity.
    fs::write(scratch.root(), serde_json::to_vec(&root).unwrap()).unwrap();
    let before = fs::read(scratch.root()).unwrap();
    assert!(store.commit(&cloned, 2, &fixture.plan()).is_err());
    assert_eq!(fs::read(scratch.root()).unwrap(), before);
    let wrong = LockedStore::new(
        &scratch.root(),
        Binding {
            source: Source::Codex,
            namespace_hash: "a".repeat(64),
        },
        FIELDS,
    )
    .unwrap();
    assert!(wrong.open().is_err());
    fs::remove_file(scratch.root()).unwrap();
    assert!(store.commit(&cloned, 2, &fixture.plan()).is_err());
    assert!(store
        .collect(
            &cloned,
            GcBudget {
                entries: 5,
                bytes: 500
            },
            &mut GcCursor::default()
        )
        .is_err());
}

fn object_paths(scratch: &Scratch) -> Vec<PathBuf> {
    fs::read_dir(scratch.0.join("scan-index.json.shards"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect()
}
#[test]
fn corrupt_missing_truncated_symlink_and_mode_refuse_without_gc() {
    for damage in 0..5 {
        let scratch = Scratch::new();
        let store = scratch.store();
        let fixture = Fixture::new(1, 5);
        let committed = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
        let path = object_paths(&scratch).pop().unwrap();
        match damage {
            0 => fs::write(&path, b"{}bad").unwrap(),
            1 => fs::remove_file(&path).unwrap(),
            2 => {
                let mut bytes = fs::read(&path).unwrap();
                let i = bytes.len() / 2;
                bytes[i] ^= 1;
                fs::write(&path, bytes).unwrap();
            }
            3 => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(scratch.root(), &path).unwrap();
            }
            4 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => unreachable!(),
        }
        let before = object_paths(&scratch).len();
        let root = fs::read(scratch.root()).unwrap();
        assert!(matches!(store.open(), Err(_) | Ok(Opened::Partial(_, _))));
        assert!(store
            .collect(
                &committed.root,
                GcBudget {
                    entries: 100,
                    bytes: u64::MAX
                },
                &mut GcCursor::default()
            )
            .is_err());
        assert_eq!(object_paths(&scratch).len(), before);
        assert_eq!(fs::read(scratch.root()).unwrap(), root);
    }
}
#[test]
fn malformed_future_manifest_never_mutates() {
    for damage in 0..7 {
        let scratch = Scratch::new();
        let store = scratch.store();
        let fixture = Fixture::new(1, 1);
        let committed = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
        let mut root: Value = serde_json::from_slice(&fs::read(scratch.root()).unwrap()).unwrap();
        match damage {
            0 => root["schema_version"] = json!(65535),
            1 => root["storage_format"] = json!(15),
            2 => root["future"] = json!("unknown-tag"),
            3 => {
                let duplicate = root["objects"][1].clone();
                root["objects"].as_array_mut().unwrap().push(duplicate);
            }
            4 => root["objects"][1]["digest"] = json!("../unsafe"),
            5 => root["objects"][1]["bytes"] = json!(u64::MAX),
            6 => root["logical_schema_version"] = json!(3),
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&root).unwrap();
        fs::write(scratch.root(), &bytes).unwrap();
        let count = object_paths(&scratch).len();
        assert!(matches!(store.open(), Err(_) | Ok(Opened::Partial(_, _))));
        assert!(store
            .collect(
                &committed.root,
                GcBudget {
                    entries: 100,
                    bytes: u64::MAX
                },
                &mut GcCursor::default()
            )
            .is_err());
        assert_eq!(fs::read(scratch.root()).unwrap(), bytes);
        assert_eq!(object_paths(&scratch).len(), count);
    }
}

#[test]
fn post_publication_error_carries_durable_generation_and_requires_reload() {
    for edge in EDGES {
        let scratch = Scratch::new();
        let store = scratch.store();
        let fixture = Fixture::new(1, 3);
        let first = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
        let changed = Fixture::new(2, 3);
        let result = store.commit_observed(&first.root, 2, &changed.plan(), &mut |at| {
            if at == edge {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        });
        let error = result.err().expect("edge must be reached");
        let published = matches!(
            edge,
            Edge::RootRename | Edge::ParentSync | Edge::BeforeReturn
        );
        if published {
            let status = error
                .downcast_ref::<CommitPublished>()
                .expect("typed published error");
            assert_eq!(status.generation, 2);
            assert!(status.verified);
            assert_eq!(load(&store).0, changed.logical(2));
            assert!(store.commit(&first.root, 2, &changed.plan()).is_err());
            let (_, reloaded) = load(&store);
            assert!(store.commit(&reloaded, 3, &changed.plan()).is_ok());
        } else {
            assert!(error.downcast_ref::<CommitPublished>().is_none());
            assert_eq!(load(&store).0, fixture.logical(1));
            assert!(store.commit(&first.root, 2, &changed.plan()).is_ok());
        }
    }
}

#[test]
fn crash_child() {
    let Ok(root) = std::env::var("SCANINDEX_CRASH_ROOT") else {
        return;
    };
    let edge = std::env::var("SCANINDEX_CRASH_EDGE")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let store = store(Path::new(&root));
    let baseline = match store.open().unwrap() {
        Opened::Legacy(_, root) | Opened::Sharded(_, root) => root,
        _ => panic!("baseline missing"),
    };
    let changed = Fixture::new(2, 12);
    let _ = store.commit_observed(&baseline, 2, &changed.plan(), &mut |at| {
        if at == EDGES[edge] {
            fs::write(
                Path::new(&root).with_extension("reached"),
                format!("{at:?}"),
            )
            .unwrap();
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
            panic!("SIGKILL returned");
        }
        Ok(())
    });
    panic!("requested crash edge was not reached");
}
#[test]
fn sigkill_each_write_edge_recovers_one_complete_generation_twice() {
    for legacy in [false, true] {
        for (index, edge) in EDGES.iter().enumerate() {
            let scratch = Scratch::new();
            let store = scratch.store();
            let fixture = Fixture::new(1, 12);
            if legacy {
                fs::write(
                    scratch.root(),
                    serde_json::to_vec(&fixture.logical(1)).unwrap(),
                )
                .unwrap();
            } else {
                store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
            }
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "crash_child", "--nocapture"])
                .env("SCANINDEX_CRASH_ROOT", scratch.root())
                .env("SCANINDEX_CRASH_EDGE", index.to_string())
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL), "{edge:?}");
            assert_eq!(
                fs::read_to_string(scratch.root().with_extension("reached")).unwrap(),
                format!("{edge:?}")
            );
            for _ in 0..2 {
                let value: Value = match store.open().unwrap() {
                    Opened::Sharded(reader, _) => serde_json::from_reader(reader).unwrap(),
                    Opened::Legacy(file, _) => serde_json::from_reader(file).unwrap(),
                    _ => panic!("crash lost root"),
                };
                if matches!(
                    edge,
                    Edge::RootRename | Edge::ParentSync | Edge::BeforeReturn
                ) {
                    assert_eq!(value, Fixture::new(2, 12).logical(2));
                } else {
                    assert_eq!(value, fixture.logical(1));
                }
            }
        }
    }
}

#[test]
fn old_reader_child() {
    let Ok(path) = std::env::var("SCANINDEX_OLD_READER_ROOT") else {
        return;
    };
    // Genuine production reader compiled into a separate process; NOT a
    // synthetic copy of its schema check and NOT serde_json::from_value.
    let result = ottto_service::snapshots::ScanIndex::load(Path::new(&path));
    let error = result.expect_err("old reader must refuse manifest");
    assert!(
        format!("{error:#}").contains("scan index refused: schema_version"),
        "{error:#}"
    );
}
#[test]
fn supported_old_reader_refuses_then_new_reader_reopens_exact_state() {
    let scratch = Scratch::new();
    let store = scratch.store();
    // Genuine legacy writer before migration: this remains a usable supported
    // old read/write path until the integration patch is applied.
    let mut old = ottto_service::snapshots::ScanIndex::default();
    old.save(&scratch.root()).unwrap();
    assert_eq!(
        ottto_service::snapshots::ScanIndex::load(&scratch.root())
            .unwrap()
            .generation,
        1
    );
    let baseline = match store.open().unwrap() {
        Opened::Legacy(_, root) => root,
        _ => panic!("expected genuine legacy"),
    };
    let fixture = Fixture::new(1, 7);
    store.commit(&baseline, 2, &fixture.plan()).unwrap();
    let bytes = fs::read(scratch.root()).unwrap();
    let count = object_paths(&scratch).len();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "old_reader_child", "--nocapture"])
        .env("SCANINDEX_OLD_READER_ROOT", scratch.root())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(scratch.root()).unwrap(), bytes);
    assert_eq!(object_paths(&scratch).len(), count);
    assert_eq!(load(&store).0, fixture.logical(2));
    assert_eq!(load(&store).0, fixture.logical(2));
}

#[test]
fn bucket_charge_precedes_allocation_and_rejects_duplicates() {
    let map: BTreeMap<_, _> = [(
        "synthetic".to_string(),
        json!({"large": "x".repeat(100000)}),
    )]
    .into();
    let mut budget = 0;
    assert!(BucketMap::new(map.iter().map(|(k, v)| (k.as_str(), v)), &mut budget).is_err());
    let mut bounded_budget = 1024;
    let borrowed = BucketMap::new_bounded(
        map.iter().map(|(k, v)| (k.as_str(), v)),
        2,
        &mut bounded_budget,
    )
    .unwrap();
    assert_eq!(borrowed.buckets().count(), 1);
    let mut budget = 1024;
    assert!(BucketMap::new(
        [("same", &json!(1)), ("same", &json!(2))].into_iter(),
        &mut budget
    )
    .is_err());
}

#[test]
fn invalid_fragments_refuse_before_root_and_never_overwrite_predecessor() {
    struct Bad {
        slot: Slot,
        bytes: &'static [u8],
    }
    impl Fragments for Bad {
        fn slots(&self) -> Vec<Slot> {
            vec![Slot::Metadata, self.slot]
        }
        fn write(&self, slot: Slot, out: &mut dyn Write) -> Result<()> {
            if slot == Slot::Metadata {
                out.write_all(b"{}")?;
            } else {
                out.write_all(self.bytes)?;
            }
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let store = scratch.store();
    let fixture = Fixture::new(1, 1);
    let first = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
    let slot = Slot::Bucket {
        field: Field::AccountPending,
        bucket: bucket_for("a"),
    };
    for bytes in [
        b"{}".as_slice(),
        b"{\"a\":1,\"a\":2}",
        b"{\"a\":1} ",
        b"{\"unexpected\":1}",
    ] {
        assert!(store.commit(&first.root, 2, &Bad { slot, bytes }).is_err());
        assert_eq!(load(&store).0, fixture.logical(1));
    }
}

#[test]
fn pretty_holds_empty_maps_and_dense_to_empty_gc() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let mut fixture = Fixture::new(1, 100);
    fixture.metadata["opaque"] = json!({"unknown_valid_record": {"held": "x".repeat(100_000)}});
    let mut plan = fixture.plan();
    plan.pretty = true;
    let first = store.commit(&missing(&store), 1, &plan).unwrap();
    assert_eq!(load(&store).0, fixture.logical(1));
    let empty = Fixture::new(2, 0);
    let next = store.commit(&first.root, 2, &empty.plan()).unwrap();
    assert_eq!(load(&store).0, empty.logical(2));
    let zero = store
        .collect(
            &next.root,
            GcBudget {
                entries: 0,
                bytes: 0,
            },
            &mut GcCursor::default(),
        )
        .unwrap();
    assert!(zero.incomplete);
    assert_eq!(zero.removed, 0);
    let gc = store
        .collect(
            &next.root,
            GcBudget {
                entries: 10000,
                bytes: u64::MAX,
            },
            &mut GcCursor::default(),
        )
        .unwrap();
    assert_eq!(gc.removed, first.stats.written_objects);
    assert_eq!(object_paths(&scratch).len(), 1);
    assert_eq!(load(&store).0, empty.logical(2));
}

#[test]
fn enospc_and_changing_fragment_never_publish() {
    struct Change(std::cell::Cell<u64>);
    impl Fragments for Change {
        fn slots(&self) -> Vec<Slot> {
            vec![Slot::Metadata]
        }
        fn write(&self, _: Slot, output: &mut dyn Write) -> Result<()> {
            let n = self.0.get();
            self.0.set(n + 1);
            serde_json::to_writer(output, &json!({"opaque": n}))?;
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let store = scratch.store();
    let fixture = Fixture::new(1, 1);
    let first = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
    assert!(store
        .commit(&first.root, 2, &Change(std::cell::Cell::new(0)))
        .is_err());
    let error = store
        .commit_observed(&first.root, 2, &Fixture::new(2, 1).plan(), &mut |edge| {
            if edge == Edge::PayloadPartialWrite {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    assert!(error.downcast_ref::<CommitPublished>().is_none());
    assert_eq!(load(&store).0, fixture.logical(1));
}

#[test]
fn sources_and_metadata_routing_coverage_are_explicit() {
    for source in [Source::Claude, Source::Codex, Source::Pi] {
        let scratch = Scratch::new();
        let store = LockedStore::new(
            &scratch.root(),
            Binding {
                source,
                namespace_hash: "a".repeat(64),
            },
            FIELDS,
        )
        .unwrap();
        let fixture = Fixture::new(1, 0);
        let result = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
        assert_eq!(result.stats.written_objects, 1);
        assert_eq!(load(&store).0, fixture.logical(1));
    }
    struct Unrouted;
    impl Fragments for Unrouted {
        fn slots(&self) -> Vec<Slot> {
            vec![Slot::Metadata]
        }
        fn write(&self, _: Slot, output: &mut dyn Write) -> Result<()> {
            output.write_all(b"{\"new_semantic_field\":19}")?;
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let store = scratch.store();
    assert!(store.commit(&missing(&store), 1, &Unrouted).is_err());
    // The failed first save left an immutable orphan, not evidence of a
    // never-initialized store. Preserve it and refuse a fresh scan.
    assert!(matches!(store.open(), Err(_) | Ok(Opened::Partial(_, _))));
    assert!(!scratch.root().exists());
    assert!(!object_paths(&scratch).is_empty());
}

#[test]
fn held_depth_200_survives_legacy_probe_migration_and_logical_view() {
    struct Deep(Vec<u8>);
    impl Fragments for Deep {
        fn slots(&self) -> Vec<Slot> {
            vec![Slot::Metadata]
        }
        fn write(&self, _: Slot, output: &mut dyn Write) -> Result<()> {
            output.write_all(&self.0)?;
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let store = scratch.store();
    let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    let original = format!("{{\"opaque\":{deep},\"schema_version\":2,\"generation\":1}}");
    fs::write(scratch.root(), original.as_bytes()).unwrap();
    let baseline = match store.open().unwrap() {
        Opened::Legacy(_, root) => root,
        _ => panic!("legacy depth must remain admitted"),
    };
    let plan = Deep(format!("{{\"opaque\":{deep}}}").into_bytes());
    store.commit(&baseline, 2, &plan).unwrap();
    for _ in 0..2 {
        let mut reader = match store.open().unwrap() {
            Opened::Sharded(reader, _) => reader,
            _ => panic!("sharded depth must remain admitted"),
        };
        let mut logical = String::new();
        reader.read_to_string(&mut logical).unwrap();
        assert!(logical.contains(&format!("\"opaque\":{deep}")));
        assert!(logical.contains("\"generation\":2"));
    }
}

#[test]
fn oversized_legacy_header_key_refuses_without_allocation_or_mutation() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let bytes = format!(
        "{{\"{}\":0,\"schema_version\":2,\"generation\":1}}",
        "x".repeat(1024 * 1024)
    );
    fs::write(scratch.root(), &bytes).unwrap();
    let error = match store.open() {
        Err(error) => error,
        Ok(_) => panic!("oversized header must refuse"),
    };
    assert!(format!("{error:#}").contains("scan_index_key_size"));
    assert_eq!(fs::read_to_string(scratch.root()).unwrap(), bytes);
    assert!(!scratch.0.join("scan-index.json.shards").exists());
}

#[test]
fn one_entry_gc_quanta_reach_orphans_and_root_temps() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let fixture = Fixture::new(1, 50);
    let first = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
    let next = store
        .commit(&first.root, 2, &Fixture::new(2, 0).plan())
        .unwrap();
    let root_temp = scratch
        .0
        .join(format!("scan-index.json.storage-tmp-{}", "0".repeat(32)));
    fs::write(&root_temp, b"incomplete root").unwrap();
    fs::set_permissions(&root_temp, fs::Permissions::from_mode(0o600)).unwrap();
    // Unrelated names and retained metadata must not permanently starve GC.
    let unrelated = scratch.0.join("not-a-storage-object");
    fs::write(&unrelated, b"keep").unwrap();
    let mut cursor = GcCursor::default();
    let mut removed = 0;
    let mut completed = false;
    for _ in 0..(first.stats.written_objects + 20) * 3 {
        let counts = store
            .collect(
                &next.root,
                GcBudget {
                    entries: 1,
                    bytes: u64::MAX,
                },
                &mut cursor,
            )
            .unwrap();
        assert!(counts.scanned <= 1);
        removed += counts.removed;
        if !counts.incomplete {
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert_eq!(removed, first.stats.written_objects + 1);
    assert_eq!(object_paths(&scratch).len(), 1);
    assert!(!root_temp.exists());
    assert_eq!(fs::read(&unrelated).unwrap(), b"keep");
    assert_eq!(load(&store).0, Fixture::new(2, 0).logical(2));
}

#[test]
fn gc_byte_deferrals_survive_later_entry_quanta() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let committed = store
        .commit(&missing(&store), 1, &Fixture::new(1, 0).plan())
        .unwrap();
    let dir = scratch.0.join("scan-index.json.shards");
    for i in 0..10 {
        let name = dir.join(format!("account-{i:02x}-{}.json", "0".repeat(64)));
        fs::write(&name, [b' '; 60]).unwrap();
        fs::set_permissions(&name, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut cursor = GcCursor::default();
    let mut removed = 0;
    let mut completed = false;
    for _ in 0..200 {
        let counts = store
            .collect(
                &committed.root,
                GcBudget {
                    entries: 3,
                    bytes: 100,
                },
                &mut cursor,
            )
            .unwrap();
        assert!(counts.scanned <= 3);
        assert!(counts.bytes <= 100);
        removed += counts.removed;
        if !counts.incomplete {
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert_eq!(removed, 10);
    assert_eq!(object_paths(&scratch).len(), 1);
}

#[test]
fn gc_retry_never_skips_an_orphan_that_failed_validation() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let committed = store
        .commit(&missing(&store), 1, &Fixture::new(1, 0).plan())
        .unwrap();
    let orphan = scratch
        .0
        .join("scan-index.json.shards")
        .join(format!("usage-00-{}.json", "0".repeat(64)));
    fs::write(&orphan, b"owned orphan").unwrap();
    fs::set_permissions(&orphan, fs::Permissions::from_mode(0o644)).unwrap();
    let mut cursor = GcCursor::default();
    for _ in 0..3 {
        assert!(store
            .collect(
                &committed.root,
                GcBudget {
                    entries: 100,
                    bytes: 1000
                },
                &mut cursor
            )
            .is_err());
        assert!(orphan.exists());
    }
    fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
    let receipt = store
        .collect(
            &committed.root,
            GcBudget {
                entries: 100,
                bytes: 1000,
            },
            &mut cursor,
        )
        .unwrap();
    assert!(!receipt.incomplete);
    assert_eq!(receipt.removed, 1);
    assert!(!orphan.exists());
    assert_eq!(load(&store).0, Fixture::new(1, 0).logical(1));
}

#[test]
fn refused_headers_and_manifest_errors_never_echo_input() {
    const CANARY: &str = "private-canary-path-or-title";
    for damage in 0..4 {
        let scratch = Scratch::new();
        let store = scratch.store();
        store
            .commit(&missing(&store), 1, &Fixture::new(1, 0).plan())
            .unwrap();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(scratch.root()).unwrap()).unwrap();
        match damage {
            0 => manifest[CANARY] = json!(true),
            1 => manifest["binding"]["source"] = json!(CANARY),
            2 => manifest["schema_version"] = json!(CANARY.repeat(20_000)),
            3 => manifest["generation"] = json!(CANARY.repeat(20_000)),
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(scratch.root(), &bytes).unwrap();
        let error = match store.open() {
            Err(error) => error,
            Ok(_) => panic!("malformed input must refuse"),
        };
        assert!(!format!("{error:#}").contains(CANARY));
        assert_eq!(fs::read(scratch.root()).unwrap(), bytes);
    }
    // Escaped control-name aliases and positional headers have the same bound.
    for bytes in [
        format!("{{\"schema\\u005fversion\":\"{}\"}}", CANARY.repeat(20_000)),
        format!("[2,\"{}\"]", CANARY.repeat(20_000)),
    ] {
        let scratch = Scratch::new();
        let store = scratch.store();
        fs::write(scratch.root(), &bytes).unwrap();
        let error = match store.open() {
            Err(error) => error,
            Ok(Opened::Legacy(_, _)) => ottto_service::snapshots::ScanIndex::load(&scratch.root())
                .expect_err("legacy scalar must refuse"),
            Ok(_) => panic!("invalid header string must refuse"),
        };
        assert!(!format!("{error:#}").contains(CANARY));
        assert_eq!(fs::read_to_string(scratch.root()).unwrap(), bytes);
    }
}

#[test]
fn compatibility_sentinel_is_not_logical_files_and_orphan_reuse_is_not_a_write() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let mut fixture = Fixture::new(1, 0);
    fixture.metadata["files"] = json!({"synthetic-nondefault-file": {"size": 191, "offset": 113}});
    let first = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
    let manifest: Value = serde_json::from_slice(&fs::read(scratch.root()).unwrap()).unwrap();
    assert_eq!(manifest["files"], json!({}));
    assert!(!fixture.metadata["files"].as_object().unwrap().is_empty());
    assert_eq!(load(&store).0, fixture.logical(1));
    let mut changed = Fixture::new(2, 0);
    changed.metadata["files"] = fixture.metadata["files"].clone();
    let error = store
        .commit_observed(&first.root, 2, &changed.plan(), &mut |edge| {
            if edge == Edge::PayloadRename {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    assert!(error.downcast_ref::<CommitPublished>().is_none());
    assert_eq!(load(&store).0, fixture.logical(1));
    // A failed payload-first attempt has already consumed the payload disk
    // space. A retry with only the root reserve left MUST reuse that verified
    // orphan; charging it again would permanently stall under disk pressure.
    let recovered = with_available_space_for_test(MAX_ROOT_BYTES as u128, || {
        store.commit(&first.root, 2, &changed.plan())
    })
    .unwrap();
    assert_eq!(recovered.stats.written_objects, 0);
    assert_eq!(recovered.stats.written_bytes, 0);
    assert_eq!(recovered.stats.unchanged_objects, 1);
    assert_eq!(load(&store).0, changed.logical(2));
    let mut invalid: Value = serde_json::from_slice(&fs::read(scratch.root()).unwrap()).unwrap();
    invalid["files"] = json!({"synthetic-forbidden": {}});
    let bytes = serde_json::to_vec(&invalid).unwrap();
    fs::write(scratch.root(), &bytes).unwrap();
    assert!(matches!(store.open(), Err(_) | Ok(Opened::Partial(_, _))));
    assert_eq!(fs::read(scratch.root()).unwrap(), bytes);
}

impl Scratch {
    fn install(&self) -> Value {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/scan_index/sharded-v1.json")).unwrap();
        let dir = self.root().with_file_name("scan-index.json.shards");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in fixture["payloads"].as_object().unwrap() {
            let path = dir.join(name);
            fs::write(&path, bytes.as_str().unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(self.root(), fixture["root"].as_str().unwrap()).unwrap();
        fs::set_permissions(self.root(), fs::Permissions::from_mode(0o600)).unwrap();
        fixture["logical"].clone()
    }
}

#[path = "support/scan_index_v201.rs"]
mod v201;

#[test]
fn writer_to_reader_legacy_export_and_writer_remigration_twice() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let fixture = Fixture::new(17, 8);
    let committed = store.commit(&missing(&store), 1, &fixture.plan()).unwrap();
    let mut baseline = committed.root;
    for cycle in 0..2 {
        let generation = 2 + cycle * 2;
        let (mut logical, _) = load(&store);
        logical["generation"] = json!(generation);
        // Exact same implementation shipped by the reader-only PR; no shard
        // writer is needed by N to export a later generation back to legacy.
        let legacy = store
            .write_legacy(&baseline, generation, |output| {
                serde_json::to_writer(output, &logical)?;
                Ok(())
            })
            .unwrap();
        assert!(legacy.is_legacy());
        let Opened::Legacy(file, _) = store.open().unwrap() else {
            panic!()
        };
        assert_eq!(serde_json::from_reader::<_, Value>(file).unwrap(), logical);
        let migrated = store
            .commit(&legacy, generation + 1, &fixture.plan())
            .unwrap();
        assert_eq!(load(&store).0, fixture.logical(generation + 1));
        assert_eq!(load(&store).0, fixture.logical(generation + 1));
        baseline = migrated.root;
    }
}

#[test]
fn legacy_optional_depth_and_syntax_reach_existing_semantic_decoder() {
    let s = Scratch::new();
    let bytes = format!(
        "{{\"schema_version\":2,\"generation\":1,\"files\":{{}},\"claude_request_census\":{}0{}}}",
        "[".repeat(300),
        "]".repeat(300)
    );
    fs::write(s.root(), bytes).unwrap();
    assert!(matches!(s.store().open().unwrap(), Opened::Legacy(_, _)));
    assert!(ottto_service::snapshots::ScanIndex::load(&s.root()).is_ok());
    fs::write(
        s.root(),
        b"{\"files\":{},\"schema_version\":2,\"generation\":\"unterminated",
    )
    .unwrap();
    assert!(matches!(s.store().open().unwrap(), Opened::Legacy(_, _)));
    assert!(ottto_service::snapshots::ScanIndex::load(&s.root()).is_ok());
    assert!(!s.root().exists());
}
#[test]
fn fifo_shard_refuses_without_waiting_for_a_writer() {
    let s = Scratch::new();
    s.install();
    let object = fs::read_dir(s.0.join("scan-index.json.shards"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(&object).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(object.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(matches!(
        s.store().open(),
        Err(_) | Ok(Opened::Partial(_, _))
    ));
}

#[test]
fn storage_tag_without_outer_fence_never_becomes_empty_legacy() {
    for schema in [Some(2), None] {
        let s = Scratch::new();
        s.install();
        let mut manifest: Value = serde_json::from_slice(&fs::read(s.root()).unwrap()).unwrap();
        if let Some(schema) = schema {
            manifest["schema_version"] = json!(schema);
        } else {
            manifest.as_object_mut().unwrap().remove("schema_version");
        }
        fs::write(s.root(), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(matches!(
            s.store().open(),
            Err(_) | Ok(Opened::Partial(_, _))
        ));
    }
    let s = Scratch::new();
    s.install();
    let _ = opened(&s.store());
    fs::write(
        s.0.join("scan-index.corrupt.1.2.json"),
        b"prior root witness",
    )
    .unwrap();
    fs::remove_file(s.root()).unwrap();
    assert!(matches!(
        s.store().open(),
        Err(_) | Ok(Opened::Partial(_, _))
    ));
}
#[test]
fn whitespace_padded_legacy_controls_keep_their_generation() {
    let s = Scratch::new();
    let bytes = format!(
        "{{\"schema_version\":2{},\"generation\":7{},\"files\":{{}}}}",
        " ".repeat(1000),
        " ".repeat(1000)
    );
    fs::write(s.root(), bytes).unwrap();
    let store = s.store();
    let (mut logical, root) = opened(&store);
    assert_eq!(root.generation(), Some(7));
    logical["generation"] = json!(8);
    store
        .write_legacy(&root, 8, |out| {
            serde_json::to_writer(out, &logical)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(opened(&store).0, logical);
}

#[test]
fn syntax_failure_never_erases_an_observed_storage_fence() {
    for bytes in [
        r#"{"files":{},"schema_version":2,"storage_format":1,"#,
        r#"{"files":{},"storage_format":"unterminated"#,
    ] {
        let s = Scratch::new();
        fs::write(s.root(), bytes).unwrap();
        assert!(matches!(
            s.store().open(),
            Err(_) | Ok(Opened::Partial(_, _))
        ));
        assert_eq!(fs::read_to_string(s.root()).unwrap(), bytes);
        assert!(s.0.join("scan-index.json.storage-prior").exists());
        assert_eq!(fs::read_dir(&s.0).unwrap().count(), 2);
    }
}

fn opened(store: &LockedStore) -> (Value, LoadedRoot) {
    let (mut input, root): (Box<dyn Read>, _) = match store.open().unwrap() {
        Opened::Sharded(reader, root) => (Box::new(reader), root),
        Opened::Legacy(file, root) => (Box::new(file), root),
        Opened::Missing(_) => panic!("missing"),
        Opened::Partial(_, _) => panic!("unknown maps are not a complete index"),
    };
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).unwrap();
    (serde_json::from_slice(&bytes).unwrap(), root)
}

#[test]
fn failed_first_publication_without_prior_state_discards_owned_orphans() {
    let s = Scratch::new();
    let store = s.store();
    let root = missing(&store);
    let error = store
        .commit_observed(&root, 1, &Fixture::new(1, 0).plan(), &mut |edge| {
            if edge == Edge::PayloadRename {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    assert!(error.downcast_ref::<CommitPublished>().is_none());
    assert!(!s.root().exists());
    assert!(!object_paths(&s).is_empty());
    assert!(matches!(store.open().unwrap(), Opened::Missing(_)));
    assert_eq!(store.take_read_stats().scanindex_orphan_init_discarded, 1);
    assert!(!s.0.join("scan-index.json.shards").exists());
    assert!(store.compare(&root).is_ok());
    store.commit(&root, 1, &Fixture::new(1, 0).plan()).unwrap();
}
#[test]
fn gc_cursor_restarts_payload_sweep_after_root_change() {
    let s = Scratch::new();
    let store = s.store();
    let first = store
        .commit(&missing(&store), 1, &Fixture::new(1, 0).plan())
        .unwrap();
    let mut cursor = GcCursor::default();
    for _ in 0..2 {
        let counts = store
            .collect(
                &first.root,
                GcBudget {
                    entries: 1,
                    bytes: u64::MAX,
                },
                &mut cursor,
            )
            .unwrap();
        assert!(counts.incomplete);
    }
    // One metadata object was inspected, then the cursor entered the parent.
    let next = store
        .commit(&first.root, 2, &Fixture::new(2, 0).plan())
        .unwrap();
    assert_eq!(object_paths(&s).len(), 2);
    let counts = store
        .collect(
            &next.root,
            GcBudget {
                entries: 1000,
                bytes: u64::MAX,
            },
            &mut cursor,
        )
        .unwrap();
    assert!(!counts.incomplete);
    assert_eq!(counts.removed, 1);
    assert_eq!(object_paths(&s).len(), 1);
    assert_eq!(load(&store).0, Fixture::new(2, 0).logical(2));
}

#[path = "support/scan_index_r3.rs"]
mod r3;
