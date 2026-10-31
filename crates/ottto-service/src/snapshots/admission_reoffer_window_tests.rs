use super::super::*;
use super::manifest_index_entry;

const MARKER: &str = "claude_admission_reoffer_window_enabled";

fn fixture() -> (crate::test_scratch::ScratchDir, ScanIndex) {
    let scratch = crate::test_scratch::ScratchDir::new("admission-reoffer-window");
    let member = scratch.join("member.jsonl");
    fs::write(&member, b"").unwrap();
    let key = local_index_key(&member);
    let mut index = ScanIndex::default();
    let mut entry = manifest_index_entry(Some("entity"));
    entry.modified_unix_seconds = unix_seconds(SystemTime::now()).unwrap();
    index.files.insert(key.clone(), entry);
    index
        .file_snapshot_fingerprints
        .insert(key, BTreeSet::from(["entity".into()]));
    index.quarantined_snapshot_fingerprints.insert(
        "entity".into(),
        snapshot_quarantine_record(SnapshotSource::ClaudeCode),
    );
    (scratch, index)
}

// Same boolean-to-range composition as the scan caller. The existing replay
// window suite owns scan_request_window_days; these pin its changed input and
// the real traversal-context hash, without copying the old pending predicate.
fn window_and_context(index: &ScanIndex, support: &Path) -> (u64, String) {
    let window = if index.snapshot_admission_reoffer_pending_for_scan(
        SnapshotSource::ClaudeCode,
        support,
        183,
    ) {
        u64::MAX
    } else {
        183
    };
    (
        window,
        scan_traversal_context_fingerprint(SnapshotSource::ClaudeCode, &[], index, window),
    )
}

/// [off=main] Absent/non-file marker preserves main's query and serialized state.
#[test]
fn admission_window_off_matches_main() {
    let (support, index) = fixture();
    let before = serde_json::to_vec(&index).unwrap();
    assert!(index.snapshot_admission_reoffer_pending());
    for directory_marker in [false, true] {
        if directory_marker {
            fs::create_dir(support.join(MARKER)).unwrap();
        }
        assert_eq!(window_and_context(&index, &support).0, u64::MAX);
        assert_eq!(serde_json::to_vec(&index).unwrap(), before);
    }
    fs::remove_dir(support.join(MARKER)).unwrap();
    fs::write(support.join(MARKER), b"").unwrap();
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        assert_eq!(
            index.snapshot_admission_reoffer_pending_for_scan(source, &support, 183),
            index.snapshot_admission_reoffer_pending(),
        );
    }
}

/// [regress] Any in-window current-limit hold must not flip the context twice.
#[test]
fn admission_window_in_window_holds_keep_window_and_context() {
    let (support, mut index) = fixture();
    fs::write(support.join(MARKER), b"").unwrap();
    let ordinary = index
        .quarantined_snapshot_fingerprints
        .remove("entity")
        .unwrap();
    let before = window_and_context(&index, &support);
    assert_eq!(before.0, 183);
    for origin in ["ordinary", "legacy", "admission"] {
        let mut record = ordinary.clone();
        match origin {
            "legacy" => {
                record.failed_reconstruction_count = 0;
                record.retry_after_unix_seconds = 0;
                record.witness.contract = SNAPSHOT_UNPROVEN_RETRY_CONTRACT_VERSION.into();
            }
            "admission" => record.witness.item_wire_byte_limit = 128 * 1024,
            _ => {}
        }
        index
            .quarantined_snapshot_fingerprints
            .insert("entity".into(), record);
        assert_eq!(
            index.prepare_snapshot_admission_reoffer(50),
            origin == "admission"
        );
        assert_eq!(window_and_context(&index, &support), before, "{origin}");
        index
            .quarantined_snapshot_fingerprints
            .get_mut("entity")
            .unwrap()
            .disposition = SnapshotQuarantineDisposition::SupersededTerminal;
        assert_eq!(
            window_and_context(&index, &support),
            before,
            "{origin} settled"
        );
    }
}

/// [money] Outside or unknown current-limit retry incidences always stay wide.
#[test]
fn admission_window_outside_or_unknown_holds_stay_wide() {
    let (support, mut index) = fixture();
    fs::write(support.join(MARKER), b"").unwrap();
    let member = support.join("member.jsonl");
    assert_eq!(window_and_context(&index, &support).0, 183);
    fs::File::open(&member)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH))
        .unwrap();
    // A recent committed mtime cannot conceal an aged-out current file.
    assert_eq!(window_and_context(&index, &support).0, u64::MAX);
    fs::remove_file(&member).unwrap();
    assert_eq!(
        window_and_context(&index, &support).0,
        u64::MAX,
        "stat error"
    );
    fs::create_dir(&member).unwrap();
    assert_eq!(window_and_context(&index, &support).0, u64::MAX, "non-file");
    fs::remove_dir(&member).unwrap();
    fs::write(&member, b"").unwrap();
    index.file_snapshot_fingerprints.clear();
    assert_eq!(
        window_and_context(&index, &support).0,
        u64::MAX,
        "missing incidence"
    );
}
