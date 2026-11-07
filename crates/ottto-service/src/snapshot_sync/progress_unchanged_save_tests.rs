//! Upload-progress saves rewrite the ledger and its ACK receipt only when the
//! ledger changed, and write compact JSON that every reader still decodes.
//! Offline; no installed state or providers.
use super::*;
use std::os::unix::fs::MetadataExt;

struct Fixture {
    root: PathBuf,
    index_path: PathBuf,
    path: PathBuf,
    receipt: PathBuf,
    progress: SnapshotUploadProgress,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ottto-progress-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let index_path = root.join("codex-scan-index.json");
        let path = snapshot_upload_progress_path(&index_path);
        let mut receipt = index_path.clone().into_os_string();
        receipt.push(".v2-ack-receipt");
        let mut progress = SnapshotUploadProgress::new(
            format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        );
        // Non-empty, so finish_cycle saves instead of clearing.
        progress
            .accepted_cache_heads
            .insert(cache_session_key("s0"), "a".repeat(64));
        Self {
            root,
            index_path,
            path,
            receipt: receipt.into(),
            progress,
        }
    }

    fn recovery(&self) -> crate::snapshots::ProgressRecovery {
        crate::snapshots::ProgressRecovery::synthetic(
            &self.index_path,
            &self.progress.destination_namespace_hash,
            0,
        )
    }

    /// Seal the saved ledger and save through the exact-receipt path from now on.
    fn bind_receipt(&mut self) -> crate::snapshots::ProgressRecovery {
        let recovery = self.recovery();
        recovery.adopt_synthetic(Some(&std::fs::read(&self.path).unwrap()));
        self.progress.ack_recovery = Some(Box::new(recovery.clone()));
        recovery
    }

    fn load(&self, recovery: Option<crate::snapshots::ProgressRecovery>) -> SnapshotUploadProgress {
        SnapshotUploadProgress::load_with_recovery(
            &self.path,
            &self.progress.destination_namespace_hash,
            snapshot_quarantine_witness(SnapshotSource::Codex),
            recovery,
        )
        .unwrap()
    }

    fn receipt_json(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(&self.receipt).unwrap()).unwrap()
    }

    fn no_temp_files(&self) {
        for entry in std::fs::read_dir(&self.root).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().ends_with(".tmp"),
                "no temp file is left: {name:?}"
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The inode changes on every atomic temp + rename replacement.
fn file(path: &Path) -> (u64, Vec<u8>) {
    (
        std::fs::metadata(path).unwrap().ino(),
        std::fs::read(path).unwrap(),
    )
}

#[test]
fn unchanged_pass_writes_no_progress_or_receipt_bytes() {
    for with_receipt in [false, true] {
        let mut f = Fixture::new("unchanged");
        f.progress.save(&f.path).unwrap();
        if with_receipt {
            f.bind_receipt();
        }
        // A batch persist that changed the ledger writes it.
        f.progress
            .accepted_cache_heads
            .insert(cache_session_key("s1"), "b".repeat(64));
        f.progress.save(&f.path).unwrap();
        let generation = f.progress.generation;
        let progress = file(&f.path);
        let receipt = with_receipt.then(|| file(&f.receipt));
        // Unchanged batch persist, bounded-retry persist and pass end.
        f.progress.save(&f.path).unwrap();
        f.progress
            .save_with_read_limit(&f.path, Some(crate::snapshot_retry::RESPONSE_BYTES))
            .unwrap();
        f.progress.finish_cycle(&f.path).unwrap();
        assert_eq!(f.progress.generation, generation, "no generation claimed");
        assert_eq!(file(&f.path), progress, "progress: 0 bytes written");
        if let Some(receipt) = receipt {
            assert_eq!(file(&f.receipt), receipt, "receipt: 0 bytes written");
        }
        f.no_temp_files();
        // The untouched pair still loads and replays.
        let restored = f.load(with_receipt.then(|| f.recovery()));
        assert_eq!(restored.generation, generation);
        assert_eq!(
            restored.accepted_cache_heads,
            f.progress.accepted_cache_heads
        );
    }
}

#[test]
fn changed_save_after_skip_writes_next_generation_and_keeps_cas() {
    let mut f = Fixture::new("changed");
    f.progress.save(&f.path).unwrap();
    f.bind_receipt();
    let mut stale = f.load(None);
    f.progress.save(&f.path).unwrap();
    assert_eq!(f.progress.generation, 1, "skipped save claims nothing");
    let skipped = file(&f.path);

    f.progress
        .accepted_cache_heads
        .insert(cache_session_key("s1"), "b".repeat(64));
    f.progress.save(&f.path).unwrap();
    assert_eq!(f.progress.generation, 2, "changed save after a skip");
    let (inode, bytes) = file(&f.path);
    assert_ne!(inode, skipped.0, "changed ledger is replaced");
    let saved: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved.generation, 2);
    assert_eq!(saved.accepted_cache_heads, f.progress.accepted_cache_heads);
    let receipt = f.receipt_json();
    assert_eq!(receipt["previous_generation"], 1);
    assert_eq!(receipt["generation"], 2);
    assert_eq!(
        receipt["progress"].as_str().unwrap().as_bytes(),
        bytes,
        "receipt carries the exact saved ledger"
    );

    // A stale writer fails its CAS whether or not it changed anything.
    stale
        .save(&f.path)
        .expect_err("unchanged stale writer is refused");
    stale
        .accepted_cache_heads
        .insert(cache_session_key("s2"), "c".repeat(64));
    stale
        .save(&f.path)
        .expect_err("changed stale writer is refused");
    assert_eq!(stale.generation, 1);
    assert_eq!(file(&f.path), (inode, bytes));

    // The owner keeps going: skip again, then change again.
    f.progress.finish_cycle(&f.path).unwrap();
    assert_eq!(f.progress.generation, 2);
    f.progress
        .accepted_cache_heads
        .insert(cache_session_key("s3"), "d".repeat(64));
    f.progress.finish_cycle(&f.path).unwrap();
    assert_eq!(f.progress.generation, 3);
    assert_eq!(f.receipt_json()["generation"], 3);
    let restored = f.load(Some(f.recovery()));
    assert_eq!(restored.generation, 3);
    assert_eq!(
        restored.accepted_cache_heads,
        f.progress.accepted_cache_heads
    );
}

#[test]
fn compact_progress_and_receipts_replay_across_pretty_writers() {
    // An older daemon's ledger: pretty JSON, sealed by its adopted receipt.
    let mut f = Fixture::new("compat");
    f.progress.generation = 1;
    let pretty_1 = serde_json::to_vec_pretty(&f.progress).unwrap();
    ottto_core::write_owner_only_file_atomic(&f.path, &pretty_1).unwrap();
    let recovery = f.recovery();
    recovery.adopt_synthetic(Some(&pretty_1));
    // It wrote its next exact receipt (pretty) and lost the progress rename.
    f.progress.generation = 2;
    f.progress
        .accepted_cache_heads
        .insert(cache_session_key("s1"), "b".repeat(64));
    let pretty_2 = serde_json::to_vec_pretty(&f.progress).unwrap();
    recovery
        .before_progress_save_bytes(Some(&pretty_1), &pretty_2)
        .unwrap();

    // This daemon replays the old pretty receipt byte-exactly.
    let mut progress = f.load(Some(recovery.clone()));
    assert_eq!(std::fs::read(&f.path).unwrap(), pretty_2);
    assert_eq!(progress.generation, 2);
    assert_eq!(
        progress.accepted_cache_heads,
        f.progress.accepted_cache_heads
    );

    // Its next save seals the pretty predecessor and writes compact JSON once.
    progress.save(&f.path).unwrap();
    assert_eq!(progress.generation, 3);
    let compact_3 = std::fs::read(&f.path).unwrap();
    assert_eq!(compact_3, serde_json::to_vec(&progress).unwrap());
    assert!(!compact_3.contains(&b'\n'), "compact progress");
    assert!(compact_3.len() < pretty_2.len());
    let receipt = f.receipt_json();
    assert_eq!(receipt["previous_generation"], 2);
    assert_eq!(receipt["generation"], 3);
    assert_eq!(receipt["progress"].as_str().unwrap().as_bytes(), compact_3);
    let inode = std::fs::metadata(&f.path).unwrap().ino();
    progress.save(&f.path).unwrap();
    assert_eq!(
        std::fs::metadata(&f.path).unwrap().ino(),
        inode,
        "then skips"
    );

    // A compact receipt replays through the same recovery path older
    // daemons run: the progress rename is lost after the receipt write.
    progress
        .accepted_cache_heads
        .insert(cache_session_key("s2"), "c".repeat(64));
    progress.save(&f.path).unwrap();
    let compact_4 = std::fs::read(&f.path).unwrap();
    ottto_core::write_owner_only_file_atomic(&f.path, &compact_3).unwrap();
    let restored = f.load(Some(recovery.clone()));
    assert_eq!(std::fs::read(&f.path).unwrap(), compact_4);
    assert_eq!(restored.generation, 4);
    assert_eq!(restored.accepted_cache_heads, progress.accepted_cache_heads);

    // Every decode path reads compact bytes: full load, CAS stamp (plain and
    // bounded) and the state-v2 import owner check.
    let namespace = progress.destination_namespace_hash.clone();
    let full: SnapshotUploadProgress = serde_json::from_slice(&compact_4).unwrap();
    assert_eq!(full.generation, 4);
    let cas: SnapshotUploadProgressCas = serde_json::from_slice(&compact_4).unwrap();
    assert_eq!(
        (cas.schema_version, cas.generation),
        (SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION, 4)
    );
    assert_eq!(cas.destination_namespace_hash, namespace);
    let bounded: SnapshotUploadProgressCas =
        crate::snapshot_retry::decode_state(&compact_4).unwrap();
    assert_eq!(bounded.generation, 4);
    validate_state_v2_original_progress(&compact_4, &namespace).unwrap();

    // Downgrade: an older daemon's pretty save over the compact ledger
    // seals it, and this daemon's next save seals that pretty ledger.
    let pretty_5 = pretty_with_generation(&full, 5);
    recovery
        .before_progress_save_bytes(Some(&compact_4), &pretty_5)
        .unwrap();
    ottto_core::write_owner_only_file_atomic(&f.path, &pretty_5).unwrap();
    let mut upgraded = f.load(Some(recovery));
    assert_eq!(upgraded.generation, 5);
    upgraded.save(&f.path).unwrap();
    assert_eq!(upgraded.generation, 6);
    assert_eq!(
        std::fs::read(&f.path).unwrap(),
        serde_json::to_vec(&upgraded).unwrap()
    );
    f.no_temp_files();
}

fn pretty_with_generation(progress: &SnapshotUploadProgress, generation: u64) -> Vec<u8> {
    let mut value = serde_json::to_value(progress).unwrap();
    value["generation"] = generation.into();
    serde_json::to_vec_pretty(&value).unwrap()
}
