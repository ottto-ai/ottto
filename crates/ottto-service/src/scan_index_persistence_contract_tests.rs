//! Uses the real ScanIndex serializer and real #865 durable store in lib tests.
use crate::durable_tail_store as durable;
#[allow(dead_code)] // Remaining component APIs are exercised by the standalone target.
use crate::snapshots::scan_index_persistence as persistence;
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

fn future_repair_files(s: &Scratch) -> Vec<(PathBuf, Vec<u8>)> {
    // Two prior roots model the N+1 crash window. Invalid JSON / non-object
    // modes prove N treats this class L as opaque, never as payload authority.
    let dir = s.0.join("scan-index.json.shards");
    [
        format!("prior-root-00000000000000000005-{}.json", "a".repeat(64)),
        format!("prior-root-00000000000000000006-{}.json", "b".repeat(64)),
        "verified-complete.json".into(),
    ]
    .into_iter()
    .map(|name| {
        let path = dir.join(name);
        let bytes = b"opaque future repair state, not a payload".to_vec();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        (path, bytes)
    })
    .collect()
}
fn assert_repair_files_kept(files: &[(PathBuf, Vec<u8>)]) {
    for (path, bytes) in files {
        assert_eq!(fs::read(path).unwrap(), *bytes);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

#[test]
fn reader_future_repair_files_leave_complete_and_each_unknown_map_unchanged() {
    for map in 0..3 {
        let control = Scratch::new();
        let candidate = Scratch::new();
        let logical = control.install();
        candidate.install();
        let files = future_repair_files(&candidate);
        let control_store = control.store(&logical);
        let candidate_store = candidate.store(&logical);
        let complete = |store: &LockedStore| {
            let Opened::Sharded(mut reader, root) = store.open().unwrap() else {
                panic!("complete fixture");
            };
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            (root.generation(), bytes)
        };
        assert_eq!(complete(&control_store), complete(&candidate_store));
        let fixture = Scratch::fixture();
        let root: Value = serde_json::from_str(fixture["root"].as_str().unwrap()).unwrap();
        let object = &root["objects"][map + 1];
        let name = format!(
            "{}-{:02x}-{}.json",
            ["account", "usage", "census"][map],
            object["slot"]["bucket"].as_u64().unwrap(),
            object["digest"].as_str().unwrap()
        );
        for s in [&control, &candidate] {
            fs::write(s.0.join("scan-index.json.shards").join(&name), b"{damaged}").unwrap();
        }
        let partial = |store: &LockedStore| {
            let Opened::Partial(mut view, root) = store.open().unwrap() else {
                panic!("UNKNOWN fixture");
            };
            let mut metadata = Vec::new();
            view.metadata.read_to_end(&mut metadata).unwrap();
            let mut states = Vec::new();
            for availability in view.maps {
                states.push(match availability {
                    MapAvailability::Known(mut reader) => {
                        let mut bytes = Vec::new();
                        reader.read_to_end(&mut bytes).unwrap();
                        (None, Some(bytes))
                    }
                    MapAvailability::Unknown(unavailable) => (Some(unavailable), None),
                });
            }
            assert_eq!(states[map].0.unwrap().cause, UnavailableCause::Digest);
            assert_eq!(states.iter().filter(|s| s.0.is_some()).count(), 1);
            (root.generation(), metadata, states)
        };
        assert_eq!(partial(&control_store), partial(&candidate_store));
        assert_repair_files_kept(&files);
    }
}

#[test]
fn reader_missing_root_with_any_reserved_control_stalls_without_cleanup() {
    for only_controls in [false, true] {
        for keep in [0, 1, 2] {
            let s = Scratch::new();
            let logical = s.install();
            fs::remove_file(s.root()).unwrap();
            if only_controls {
                fs::remove_dir_all(s.0.join("scan-index.json.shards")).unwrap();
                fs::create_dir(s.0.join("scan-index.json.shards")).unwrap();
                fs::set_permissions(
                    s.0.join("scan-index.json.shards"),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
            }
            let mut files = future_repair_files(&s);
            // One prior root, the fixed marker alone, or all controls suffice.
            if keep < 2 {
                let retained = if keep == 0 { 0 } else { 2 };
                for (i, (path, _)) in files.iter().enumerate() {
                    if i != retained {
                        fs::remove_file(path).unwrap();
                    }
                }
                files = vec![files.remove(retained)];
            }
            let dir = s.0.join("scan-index.json.shards");
            let before = fs::read_dir(&dir).unwrap().count();
            let store = s.store(&logical);
            let error = store
                .open()
                .err()
                .expect("history must never become Missing");
            assert!(format!("{error:#}").contains("scan_index_root_missing_with_shards"));
            let stats = store.take_read_stats();
            assert_eq!(stats.root_missing_reserved_only, 1);
            assert_eq!(stats.scanindex_orphan_init_discarded, 0);
            assert_eq!(fs::read_dir(&dir).unwrap().count(), before);
            assert!(!s.root().exists());
            assert_repair_files_kept(&files);
        }
    }
}

#[test]
fn reader_no_store_allows_true_first_install_and_legacy_first_save() {
    let s = Scratch::new();
    let mut logical = Scratch::fixture()["logical"].clone();
    let store = s.store(&logical);
    let Opened::Missing(root) = store.open().unwrap() else {
        panic!("true first install");
    };
    assert_eq!(store.take_read_stats().root_missing_reserved_only, 0);
    logical["generation"] = serde_json::json!(1);
    assert!(store
        .write_legacy(&root, 1, |out| {
            serde_json::to_writer(out, &logical)?;
            Ok(())
        })
        .unwrap()
        .is_legacy());
}

#[test]
fn reader_malformed_repair_lookalikes_still_refuse_fresh_init_without_cleanup() {
    for name in [
        format!("prior-root-{}-{}.json", "0".repeat(19), "a".repeat(64)),
        format!("prior-root-{}-{}.json", "0".repeat(20), "a".repeat(63)),
        "verified-complete.json.extra".into(),
    ] {
        let s = Scratch::new();
        let logical = s.install();
        fs::remove_file(s.root()).unwrap();
        let dir = s.0.join("scan-index.json.shards");
        let bad = dir.join(name);
        fs::write(&bad, b"unknown").unwrap();
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read_dir(&dir).unwrap().count();
        let store = s.store(&logical);
        let error = match store.open() {
            Err(e) => e,
            Ok(_) => panic!("lookalike admitted"),
        };
        assert!(format!("{error:#}").contains("scan_index_orphan_unknown"));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), before);
    }
}

#[test]
fn reader_reserved_repair_files_do_not_waive_a_missing_previously_seen_root() {
    let s = Scratch::new();
    let logical = s.install();
    let store = s.store(&logical);
    assert!(matches!(store.open().unwrap(), Opened::Sharded(_, _)));
    let files = future_repair_files(&s);
    fs::remove_file(s.root()).unwrap();
    let error = match s.store(&logical).open() {
        Err(e) => e,
        Ok(_) => panic!("prior state reset"),
    };
    assert!(format!("{error:#}").contains("scan_index_root_missing_with_shards"));
    assert_repair_files_kept(&files);
}

#[test]
fn reader_reserved_directory_cas_refuses_intervening_repair_state() {
    let s = Scratch::new();
    let logical = Scratch::fixture()["logical"].clone();
    let store = s.store(&logical);
    let Opened::Missing(root) = store.open().unwrap() else {
        panic!("fresh init");
    };
    let dir = s.0.join("scan-index.json.shards");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let files = future_repair_files(&s);
    let error = store
        .write_legacy(&root, 1, |_| panic!("CAS must refuse before encoding"))
        .unwrap_err();
    assert!(format!("{error:#}").contains("scan_index_root_missing_with_shards"));
    assert_eq!(store.take_read_stats().root_missing_reserved_only, 1);
    assert!(!s.root().exists());
    assert_repair_files_kept(&files);
}
