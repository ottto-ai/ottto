//! Uses the real ScanIndex serializer and real #865 durable store in lib tests.
#[allow(dead_code)] // Remaining component APIs are exercised by the standalone target.
#[path = "snapshots/scan_index_persistence.rs"]
mod persistence;
use crate::durable_tail_store as durable;
use crate::snapshots::ScanIndex;
use persistence::*;
use serde_json::Value;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf};
const MOVED: [&str; 3] = [
    "claude_account_family_pending",
    "claude_usage_family_pending",
    "claude_request_census",
];
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(crate::test_scratch::private_dir(
            "scanindex-storage-contract",
        ))
    }
    fn root(&self) -> PathBuf {
        self.0.join("scan-index.json")
    }
    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/scan_index/real-shaped-v1.json"
        ))
        .unwrap()
    }
    fn fields(value: &Value) -> &'static [&'static str] {
        // Bounded fixture-only strings; the production adapter uses its static field table.
        Box::leak(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(|k| &*Box::leak(k.clone().into_boxed_str()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }
    fn store(&self, logical: &Value) -> LockedStore {
        LockedStore::new(
            &self.root(),
            Binding {
                source: Source::Claude,
                namespace_hash: "a".repeat(64),
            },
            Self::fields(logical),
        )
        .unwrap()
    }
    fn install(&self) -> Value {
        let fixture = Self::fixture();
        let dir = self.0.join("scan-index.json.shards");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in fixture["payloads"].as_object().unwrap() {
            fs::write(dir.join(name), bytes.as_str().unwrap()).unwrap();
            fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(self.root(), fixture["root"].as_str().unwrap()).unwrap();
        fs::set_permissions(self.root(), fs::Permissions::from_mode(0o600)).unwrap();
        fixture["logical"].clone()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn decode(store: &LockedStore) -> (ScanIndex, LoadedRoot) {
    let Opened::Sharded(reader, root) = store.open().unwrap() else {
        panic!("complete shards required")
    };
    (serde_json::from_reader(reader).unwrap(), root)
}
fn assert_same_wire(expected: &ScanIndex, actual: &ScanIndex) {
    assert_eq!(
        serde_json::to_vec(actual).unwrap(),
        serde_json::to_vec(expected).unwrap(),
        "same legacy logical-2 serializer, byte for byte"
    );
    let before = serde_json::to_value(expected).unwrap();
    let after = serde_json::to_value(actual).unwrap();
    for field in MOVED {
        assert!(
            before[field].as_object().is_some_and(|m| !m.is_empty()),
            "fixture map {field} must be populated"
        );
        assert_eq!(
            serde_json::to_vec(&before[field]).unwrap(),
            serde_json::to_vec(&after[field]).unwrap()
        );
    }
}
fn durable_round_trip(s: &Scratch, index: &ScanIndex, generation: u64) {
    use crate::transcript_acquisition::{ReadPlan, Scope};
    let lock = crate::locked_state_dir::LockedStateDir::acquire(&s.0).unwrap();
    let path = s.0.join("synthetic-input.jsonl");
    fs::write(&path, b"{\"synthetic\":1}\n").unwrap();
    let mut file = fs::File::open(&path).unwrap();
    let scope = Scope("synthetic-durable-scope".into());
    let mut plan = ReadPlan::prepare(&mut file, None, &scope, None, 1_800_000_000).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    let checkpoint = plan
        .commit_after_native_completion(&file, &scope, 1_800_000_000)
        .unwrap();
    let certificate = checkpoint
        .durable_certificate(crate::transcript_acquisition::birth_unix_nanos(
            &file.metadata().unwrap(),
        ))
        .unwrap();
    let source = durable::DurableSource::ClaudeCode;
    let allowlist: [u8; 32] = "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c"
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let logical = serde_json::to_value(index).unwrap();
    let entry = index.files.get("synthetic-file").unwrap();
    let context = logical["upload_context_fingerprint"].as_str();
    let binding = durable::Binding {
        source,
        key: durable::key_digest(source, "synthetic-file"),
        context: durable::context_digest(&"a".repeat(64), context),
        scope: durable::scope_digest("synthetic-scope", &allowlist, "identity:v1", "legacy"),
        entry: durable::replay_entry_digest(
            &durable::entry_digest(
                &entry.source_file_fingerprint,
                entry.last_upload_body_witness.as_deref(),
            ),
            entry.effective_upload_body_witness_revision,
            0,
        ),
    };
    let record = durable::PendingRecord {
        binding: binding.clone(),
        certificate,
        body: crate::snapshots::durable_store_fixture_body(
            crate::snapshots::SnapshotSource::ClaudeCode,
            3,
            21,
        ),
        allowlist,
    };
    let dir = durable::store_dir_for_index(&s.root());
    let mut store = durable::DurableTailStore::new(dir.clone(), source);
    assert_eq!(
        store
            .write_after_save(&lock, generation, vec![record.clone()])
            .unwrap()
            .written,
        1
    );
    drop(store);
    // Restart BOTH representations: generation comes from the committed index,
    // never a shard digest, a storage receipt, or a process-local counter.
    let root: Value = serde_json::from_slice(&fs::read(s.root()).unwrap()).unwrap();
    assert_eq!(root["generation"].as_u64(), Some(generation));
    let mut restarted = durable::DurableTailStore::new(dir, source);
    let durable::ReadOutcome::Found(restored) = restarted.read(&binding.key) else {
        panic!("real durable record must restore")
    };
    assert_eq!(restored.index_generation, generation);
    assert_eq!(restored.record, record);
    // The actual #865 admission seam checks entry/context/scope AND generation.
    let expected = durable::Expected {
        binding: binding.clone(),
        committed_generation: root["generation"].as_u64().unwrap(),
    };
    assert!(restored.eligible(&expected).is_ok());
    assert!(restored
        .eligible(&durable::Expected {
            binding: binding.clone(),
            committed_generation: generation - 1
        })
        .is_err());
    assert!(restored
        .eligible(&durable::Expected {
            binding,
            committed_generation: generation + 1
        })
        .is_ok());
    assert!(restored.index_generation <= root["generation"].as_u64().unwrap());
    assert!(crate::snapshots::verify_durable_body(
        &restored.record.body,
        source
    ));
}
#[test]
fn reader_loads_frozen_writer_bytes_and_preserves_logical2_and_durable_generation() {
    let s = Scratch::new();
    let logical = s.install();
    let expected: ScanIndex = serde_json::from_value(logical.clone()).unwrap();
    let store = s.store(&logical);
    let (actual, root) = decode(&store);
    assert_same_wire(&expected, &actual);
    assert_eq!(root.generation(), Some(7));
    durable_round_trip(&s, &actual, root.generation().unwrap());
}
struct RealFragments {
    logical: Value,
    metadata: Value,
    maps: [std::collections::BTreeMap<String, Value>; 3],
}
impl RealFragments {
    fn new(index: &ScanIndex) -> Self {
        let logical = serde_json::to_value(index).unwrap();
        let mut metadata = logical.clone();
        let maps =
            std::array::from_fn(|i| serde_json::from_value(logical[MOVED[i]].clone()).unwrap());
        for field in MOVED.into_iter().chain(["schema_version", "generation"]) {
            metadata.as_object_mut().unwrap().remove(field);
        }
        Self {
            logical,
            metadata,
            maps,
        }
    }
}
impl Fragments for RealFragments {
    fn slots(&self) -> Vec<Slot> {
        let mut slots = vec![Slot::Metadata];
        for (i, field) in [
            Field::AccountPending,
            Field::UsagePending,
            Field::RequestCensus,
        ]
        .into_iter()
        .enumerate()
        {
            let mut budget = usize::MAX;
            slots.extend(
                BucketMap::new(
                    self.maps[i].iter().map(|(k, v)| (k.as_str(), v)),
                    &mut budget,
                )
                .unwrap()
                .buckets()
                .map(|bucket| Slot::Bucket { field, bucket }),
            );
        }
        slots
    }
    fn write(&self, slot: Slot, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
        match slot {
            Slot::Metadata => serde_json::to_writer(out, &self.metadata)?,
            Slot::Bucket { field, bucket } => {
                let i = [
                    Field::AccountPending,
                    Field::UsagePending,
                    Field::RequestCensus,
                ]
                .iter()
                .position(|f| *f == field)
                .unwrap();
                let mut budget = usize::MAX;
                BucketMap::new(
                    self.maps[i].iter().map(|(k, v)| (k.as_str(), v)),
                    &mut budget,
                )?
                .write(bucket, false, out)?;
            }
        }
        Ok(())
    }
}
#[test]
fn actual_sharded_save_keeps_every_other_field_in_metadata_and_binds_durable_generation() {
    let s = Scratch::new();
    let logical = Scratch::fixture()["logical"].clone();
    let mut expected: ScanIndex = serde_json::from_value(logical).unwrap();
    let plan = RealFragments::new(&expected);
    let store = s.store(&plan.logical);
    fs::write(s.root(), serde_json::to_vec(&expected).unwrap()).unwrap();
    let Opened::Legacy(_, baseline) = store.open().unwrap() else {
        panic!()
    };
    let committed = store.commit(&baseline, 8, &plan).unwrap();
    assert_eq!(committed.root.generation(), Some(8));
    expected.generation = 8;
    let (actual, loaded) = decode(&store);
    assert_same_wire(&expected, &actual);
    let manifest: Value = serde_json::from_slice(&fs::read(s.root()).unwrap()).unwrap();
    let metadata = &manifest["objects"][0];
    let filename = format!("metadata-{}.json", metadata["digest"].as_str().unwrap());
    let persisted: Value = serde_json::from_slice(
        &fs::read(s.0.join("scan-index.json.shards").join(filename)).unwrap(),
    )
    .unwrap();
    // Exact exhaustive complement: a newly serialized semantic field routes to
    // metadata automatically; only these THREE existing maps can move out.
    for (name, value) in plan.logical.as_object().unwrap() {
        if MOVED.contains(&name.as_str())
            || ["schema_version", "generation"].contains(&name.as_str())
        {
            assert!(persisted.get(name).is_none());
        } else {
            assert_eq!(persisted.get(name), Some(value), "metadata field {name}");
        }
    }
    for name in [
        "files",
        "upload_context_fingerprint",
        "traversal",
        "claude_desktop_identity_census_complete",
        "claude_desktop_lineage_census_complete",
    ] {
        assert!(persisted.get(name).is_some(), "required metadata {name}");
    }
    assert_eq!(loaded.generation(), Some(8));
    durable_round_trip(&s, &actual, loaded.generation().unwrap());
}

#[test]
fn future_representation_version_is_classified_for_the_health_adapter() {
    let s = Scratch::new();
    let logical = s.install();
    let mut root: Value = serde_json::from_slice(&fs::read(s.root()).unwrap()).unwrap();
    for field in ["schema_version", "storage_format", "logical_schema_version"] {
        let old = root[field].clone();
        root[field] = serde_json::json!(999);
        fs::write(s.root(), serde_json::to_vec(&root).unwrap()).unwrap();
        let error = match s.store(&logical).open() {
            Err(error) => error,
            Ok(_) => panic!("future version admitted"),
        };
        assert!(crate::snapshots::scan_index_health::is_version_refusal(
            &error
        ));
        root[field] = old;
    }
}
