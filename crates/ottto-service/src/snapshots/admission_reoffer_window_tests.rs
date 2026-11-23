use super::tests::manifest_index_entry;
use super::*;

/// Every source reaches the same admission gate with the same retry records.
const SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::ClaudeCode,
    SnapshotSource::Codex,
    SnapshotSource::Pi,
];

fn fixture(source: SnapshotSource) -> (crate::test_scratch::ScratchDir, ScanIndex) {
    fixture_with(source, "entity")
}

fn fixture_with(
    source: SnapshotSource,
    entity: &str,
) -> (crate::test_scratch::ScratchDir, ScanIndex) {
    let scratch = crate::test_scratch::ScratchDir::new(&format!(
        "admission-reoffer-window-{}",
        source.api_slug()
    ));
    let member = scratch.join("member.jsonl");
    fs::write(&member, b"").unwrap();
    // Comfortably inside the 183-day window.
    set_age(&member, 30 * DAY);
    let key = local_index_key(&member);
    let mut index = ScanIndex::default();
    let mut entry = manifest_index_entry(Some(entity));
    entry.modified_unix_seconds = unix_seconds(SystemTime::now()).unwrap();
    index.files.insert(key.clone(), entry);
    index
        .file_snapshot_fingerprints
        .insert(key, BTreeSet::from([entity.into()]));
    index
        .quarantined_snapshot_fingerprints
        .insert(entity.into(), snapshot_quarantine_record(source));
    (scratch, index)
}

// Same boolean-to-range composition as the scan caller. The existing replay
// window suite owns scan_request_window_days; these pin its changed input and
// the real traversal-context hash, without copying the old pending predicate.
fn window_and_context(index: &ScanIndex, source: SnapshotSource) -> (u64, String) {
    let window = if index.snapshot_admission_reoffer_pending_for_scan(source, 183) {
        u64::MAX
    } else {
        183
    };
    (
        window,
        scan_traversal_context_fingerprint(source, &[], window),
    )
}

const DAY: u64 = 24 * 60 * 60;

fn set_age(path: &Path, seconds: u64) {
    fs::File::open(path)
        .unwrap()
        .set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::now() - std::time::Duration::from_secs(seconds)),
        )
        .unwrap();
}

fn age_out(path: &Path) {
    fs::File::open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH))
        .unwrap();
}

/// [regress] Any in-window current-limit hold must not flip the context twice,
/// for every source.
#[test]
fn admission_window_in_window_holds_keep_window_and_context() {
    for source in SOURCES {
        let (_support, mut index) = fixture(source);
        let ordinary = index
            .quarantined_snapshot_fingerprints
            .remove("entity")
            .unwrap();
        let before = window_and_context(&index, source);
        assert_eq!(before.0, 183, "{source:?}");
        for origin in ["ordinary", "legacy", "admission"] {
            let mut record = ordinary.clone();
            match origin {
                "legacy" => {
                    record.failed_reconstruction_count = 0;
                    record.retry_after_unix_seconds = 0;
                    // A stored record may still carry this contract string.
                    record.witness.contract = "snapshot_unproven_retry:v1".into();
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
            assert_eq!(
                window_and_context(&index, source),
                before,
                "{source:?} {origin}"
            );
            index
                .quarantined_snapshot_fingerprints
                .get_mut("entity")
                .unwrap()
                .disposition = SnapshotQuarantineDisposition::SupersededTerminal;
            assert_eq!(
                window_and_context(&index, source),
                before,
                "{source:?} {origin} settled"
            );
        }
    }
}

/// [money] Outside or unknown current-limit retry incidences always stay wide,
/// for every source.
#[test]
fn admission_window_outside_or_unknown_holds_stay_wide() {
    for source in SOURCES {
        let (support, mut index) = fixture(source);
        let member = support.join("member.jsonl");
        assert_eq!(window_and_context(&index, source).0, 183, "{source:?}");
        // Within a day of the edge widens: a clock step or the gate-to-walk
        // gap cannot age it out of a narrow walk.
        set_age(&member, 183 * DAY - DAY / 2);
        assert_eq!(
            window_and_context(&index, source).0,
            u64::MAX,
            "{source:?} edge margin"
        );
        age_out(&member);
        // A recent committed mtime cannot conceal an aged-out current file.
        assert_eq!(window_and_context(&index, source).0, u64::MAX, "{source:?}");
        fs::remove_file(&member).unwrap();
        assert_eq!(
            window_and_context(&index, source).0,
            u64::MAX,
            "{source:?} stat error"
        );
        fs::create_dir(&member).unwrap();
        assert_eq!(
            window_and_context(&index, source).0,
            u64::MAX,
            "{source:?} non-file"
        );
        fs::remove_dir(&member).unwrap();
        fs::write(&member, b"").unwrap();
        index.file_snapshot_fingerprints.clear();
        assert_eq!(
            window_and_context(&index, source).0,
            u64::MAX,
            "{source:?} missing incidence"
        );
    }
}

/// [money] A resumed or forked Codex session joins several rollout files, and
/// every member's index key records the joined entity. A retry whose owner
/// file is inside the window but whose member file aged out stays wide.
#[test]
fn admission_window_codex_join_member_outside_stays_wide() {
    let source = SnapshotSource::Codex;
    let (support, mut index) = fixture(source);
    let member = support.join("forked-member.jsonl");
    fs::write(&member, b"").unwrap();
    let key = local_index_key(&member);
    index
        .files
        .insert(key.clone(), manifest_index_entry(Some("entity")));
    index
        .file_snapshot_fingerprints
        .insert(key, BTreeSet::from(["entity".into()]));
    assert_eq!(window_and_context(&index, source).0, 183, "both inside");
    age_out(&member);
    assert_eq!(
        window_and_context(&index, source).0,
        u64::MAX,
        "owner inside, member outside"
    );
}

/// [money] A persisted retry is seen on the first cycle after a reload, and an
/// empty incidence map after a reload widens and never narrows.
#[test]
fn admission_window_persisted_retry_is_seen_after_reload() {
    let entity = "e".repeat(64);
    for source in SOURCES {
        let (support, mut index) = fixture_with(source, &entity);
        let member = support.join("member.jsonl");
        for entry in index.files.values_mut() {
            entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
            entry.source_file_fingerprint = "1".repeat(64);
        }
        let path = support.join(format!("{}-scan-index-v3.json", source.api_slug()));
        let reload = |index: &mut ScanIndex| {
            index.save_fixture(&path).unwrap();
            ScanIndex::load_for_snapshot_source(&path, source, &support).unwrap()
        };
        let loaded = reload(&mut index);
        assert_eq!(
            loaded.quarantined_snapshot_fingerprints[&entity].disposition,
            SnapshotQuarantineDisposition::RetryPending,
            "{source:?}"
        );
        assert_eq!(window_and_context(&loaded, source).0, 183, "{source:?}");
        age_out(&member);
        assert_eq!(
            window_and_context(&loaded, source).0,
            u64::MAX,
            "{source:?} reloaded retry is counted"
        );
        fs::write(&member, b"").unwrap();
        index.file_snapshot_fingerprints.clear();
        let loaded = reload(&mut index);
        assert!(loaded.file_snapshot_fingerprints.is_empty(), "{source:?}");
        assert!(
            loaded
                .quarantined_snapshot_fingerprints
                .contains_key(&entity),
            "{source:?}"
        );
        assert_eq!(
            window_and_context(&loaded, source).0,
            u64::MAX,
            "{source:?} empty incidence after reload"
        );
    }
}
