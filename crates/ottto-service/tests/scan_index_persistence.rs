//! Reader component only; shared load/save integration is an owner patch.
#[path = "../src/snapshots/scan_index_persistence.rs"]
mod persistence;
use persistence::*;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const FIELDS: &[&str] = &["files", "accepted_snapshot_fingerprints", "opaque"];
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        // Clock granularity can repeat nanos across tests in one process.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "scanindex-reader-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn root(&self) -> PathBuf {
        self.0.join("scan-index.json")
    }
    fn store(&self) -> LockedStore {
        LockedStore::new(
            &self.root(),
            Binding {
                source: Source::Claude,
                namespace_hash: "a".repeat(64),
            },
            FIELDS,
        )
        .unwrap()
    }
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
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
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
fn frozen_sharded_generation_is_seekable_and_next_save_is_legacy() {
    let s = Scratch::new();
    let mut expected = s.install();
    let store = s.store();
    let (actual, root) = opened(&store);
    assert_eq!(actual, expected);
    assert_eq!(root.generation(), Some(7));
    assert!(!root.is_legacy());
    let Opened::Sharded(mut reader, _) = store.open().unwrap() else {
        panic!()
    };
    let end = reader.seek(SeekFrom::End(0)).unwrap();
    reader.seek(SeekFrom::Start(end / 2)).unwrap();
    let mut tail = Vec::new();
    reader.read_to_end(&mut tail).unwrap();
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut all = Vec::new();
    reader.read_to_end(&mut all).unwrap();
    assert_eq!(tail, all[(end / 2) as usize..]);
    drop(reader);
    expected["generation"] = json!(8);
    let next = store
        .write_legacy(&root, 8, |out| {
            serde_json::to_writer(out, &expected)?;
            Ok(())
        })
        .unwrap();
    assert!(next.is_legacy());
    assert_eq!(opened(&store).0, expected);
    assert_eq!(opened(&store).0, expected);
    assert!(store.compare(&root).is_err());
    // N writes no immutable shard files and does not remove predecessor shards.
    assert_eq!(
        fs::read_dir(s.0.join("scan-index.json.shards"))
            .unwrap()
            .count(),
        4
    );
}
#[test]
fn equal_generation_root_change_missing_and_bad_encoder_refuse() {
    let s = Scratch::new();
    s.install();
    let store = s.store();
    let (_, root) = opened(&store);
    let before = fs::read(s.root()).unwrap();
    assert!(store
        .write_legacy(&root, 8, |out| {
            std::io::Write::write_all(
                out,
                b"{\"schema_version\":3,\"files\":{},\"generation\":8}",
            )?;
            Ok(())
        })
        .is_err());
    assert_eq!(fs::read(s.root()).unwrap(), before);
    let mut manifest: Value = serde_json::from_slice(&before).unwrap();
    manifest["padding_bytes"] = json!(1);
    fs::write(s.root(), serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(store.compare(&root).is_err());
    fs::remove_file(s.root()).unwrap();
    assert!(store.compare(&root).is_err());
}
#[test]
fn corrupt_missing_shard_and_future_manifest_never_rebuild() {
    for action in 0..3 {
        let s = Scratch::new();
        s.install();
        let store = s.store();
        let object = fs::read_dir(s.0.join("scan-index.json.shards"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        match action {
            0 => fs::write(object, b"{corrupt}").unwrap(),
            1 => fs::remove_file(object).unwrap(),
            _ => {
                let mut manifest: Value =
                    serde_json::from_slice(&fs::read(s.root()).unwrap()).unwrap();
                manifest["storage_format"] = json!(999);
                fs::write(s.root(), serde_json::to_vec(&manifest).unwrap()).unwrap();
            }
        }
        let before = fs::read(s.root()).unwrap();
        assert!(matches!(store.open(), Err(_) | Ok(Opened::Partial(_, _))));
        assert_eq!(fs::read(s.root()).unwrap(), before);
        assert!(fs::read_dir(&s.0).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("corrupt")));
    }
}
#[test]
fn missing_then_legacy_write_uses_existing_format() {
    let s = Scratch::new();
    let store = s.store();
    let Opened::Missing(root) = store.open().unwrap() else {
        panic!()
    };
    let value = json!({"schema_version":2,"generation":1,"files":{}});
    let root = store
        .write_legacy(&root, 1, |out| {
            serde_json::to_writer(out, &value)?;
            Ok(())
        })
        .unwrap();
    assert!(root.is_legacy());
    assert_eq!(opened(&store).0, value);
    assert!(ottto_service::snapshots::ScanIndex::load(&s.root()).is_ok());
}

#[path = "support/scan_index_v201.rs"]
mod v201;

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

#[path = "support/scan_index_r3.rs"]
mod r3;

/// [format] Optional restore siblings never waive unsafe or unknown prior state,
/// including a witness arriving between Missing and the first save.
#[test]
fn optional_restore_siblings_fail_closed_before_cleanup_or_encoding() {
    use std::os::unix::fs::symlink;
    for late in [false, true] {
        for kind in [
            "symlink",
            "marker_symlink",
            "non_private_dir",
            "file",
            "marker_dir",
            "other",
        ] {
            let s = Scratch::new();
            let store = s.store();
            let baseline = if late {
                let Opened::Missing(root) = store.open().unwrap() else {
                    panic!("fresh")
                };
                Some(root)
            } else {
                None
            };
            let target = s.0.join("outside");
            fs::create_dir(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(target.join("content"), b"untouched").unwrap();
            let witness = s.0.join(match kind {
                "marker_symlink" | "marker_dir" => "scan-index.private-labels",
                "other" => "scan-index.durable-tail.extra",
                _ => "scan-index.durable-tail",
            });
            match kind {
                "symlink" | "marker_symlink" => symlink(&target, &witness).unwrap(),
                "non_private_dir" | "marker_dir" => {
                    fs::create_dir(&witness).unwrap();
                    fs::set_permissions(
                        &witness,
                        fs::Permissions::from_mode(if kind == "non_private_dir" {
                            0o755
                        } else {
                            0o700
                        }),
                    )
                    .unwrap();
                }
                _ => {
                    fs::write(&witness, b"prior state").unwrap();
                    fs::set_permissions(&witness, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            let temp =
                s.0.join(format!("scan-index.json.storage-tmp-{}", "a".repeat(32)));
            fs::write(&temp, b"not discarded").unwrap();
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::read_dir(&s.0)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>();
            if let Some(root) = baseline {
                assert!(
                    store
                        .write_legacy(&root, 1, |_| panic!("must refuse before encoding"))
                        .is_err(),
                    "{kind}"
                );
            } else {
                assert!(store.open().is_err(), "{kind}");
            }
            assert_eq!(fs::read(&temp).unwrap(), b"not discarded");
            assert_eq!(fs::read(target.join("content")).unwrap(), b"untouched");
            assert_eq!(
                before,
                fs::read_dir(&s.0)
                    .unwrap()
                    .map(|e| e.unwrap().file_name())
                    .collect::<std::collections::BTreeSet<_>>(),
                "{kind}"
            );
            assert!(!s.root().exists());
        }
    }
    // The same owned-directory validator rejects a real foreign directory.
    // No root/lock creation occurs: LockedStore validates its parent first.
    if fs::metadata("/").unwrap().uid() != unsafe { libc::geteuid() } {
        assert!(LockedStore::new(
            std::path::Path::new("/scan-index.json"),
            Binding {
                source: Source::Claude,
                namespace_hash: "a".repeat(64),
            },
            FIELDS
        )
        .is_err());
    }
}
