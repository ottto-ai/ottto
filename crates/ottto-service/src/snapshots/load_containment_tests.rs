// Record-local load containment (follow-up to #694). A record that fails a
// per-record `ScanIndex::load` check is dropped or normalized alone: the file
// stays at its path, no `.corrupt.*` sibling appears, the generation is the
// one on disk and every other record survives. Nothing is re-armed: the
// existing candidate gate re-reads a file whose activity clock is missing or
// whose RetryPending refusal is due, and finalize keeps a due refusal out of
// semantic no-op suppression, so no retry obligation or disclosure is lost
// and no accepted body is re-sent. A ledger version from a newer build is
// future state: load refuses it and leaves the file in place. All fixtures
// are synthetic and content-free.
use super::*;

const LC_WINDOW: &str = "2026-10-22T23:00:00Z";

fn lc_hex(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn lc_key(name: &str) -> String {
    format!("/synthetic/load-containment/{name}.jsonl")
}

fn lc_entry(source: char, body: &str) -> ScanIndexEntry {
    let mut entry = manifest_index_entry(Some(body));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    entry.source_file_fingerprint = lc_hex(source);
    entry
}

/// Four indexed files: two accepted bodies, one RetryPending body and one
/// UnprovenTerminal body, each with a semantic activity clock.
fn lc_fixture() -> ScanIndex {
    let mut index = ScanIndex {
        accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
        ..ScanIndex::default()
    };
    for (name, source, body) in [
        ("accepted-a", '1', 'c'),
        ("accepted-b", '2', 'd'),
        ("retry", '3', 'e'),
        ("terminal", '4', 'f'),
    ] {
        let body = lc_hex(body);
        index.files.insert(lc_key(name), lc_entry(source, &body));
        index
            .file_snapshot_fingerprints
            .insert(lc_key(name), BTreeSet::from([body.clone()]));
        index
            .snapshot_activity_at
            .insert(body, Some(LC_WINDOW.to_string()));
    }
    index.accepted_snapshot_fingerprints = BTreeSet::from([lc_hex('c'), lc_hex('d')]);
    index.quarantined_snapshot_fingerprints.insert(
        lc_hex('e'),
        snapshot_quarantine_record(SnapshotSource::ClaudeCode),
    );
    index.quarantined_snapshot_fingerprints.insert(
        lc_hex('f'),
        SnapshotQuarantineRecord {
            witness: snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            retry_after_unix_seconds: 0,
            upload_body_witness: None,
            failed_reconstruction_count: MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
            disposition: SnapshotQuarantineDisposition::UnprovenTerminal,
        },
    );
    index
}

struct LcLoad {
    path: PathBuf,
    written: Vec<u8>,
    generation: u64,
    result: Result<ScanIndex>,
    drops: ScanIndexLoadDrops,
}

/// Save the valid fixture (generation 1), apply one mutation to its bytes
/// the way an older or defective writer would leave them, then load once.
fn lc_load(scratch: &Path, name: &str, mutate: impl FnOnce(&mut Value)) -> LcLoad {
    let path = scratch.join(format!("{name}-claude_code-scan-index-v3.json"));
    let mut index = lc_fixture();
    index.save(&path).expect("persist valid fixture");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let generation = value["generation"].as_u64().expect("saved generation");
    mutate(&mut value);
    let written = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &written).unwrap();
    let before = scan_index_load_drops_for_test();
    let result = ScanIndex::load(&path);
    let after = scan_index_load_drops_for_test();
    LcLoad {
        path,
        written,
        generation,
        result,
        drops: ScanIndexLoadDrops {
            activity: after.activity - before.activity,
            accepted: after.accepted - before.accepted,
            cursor: after.cursor - before.cursor,
            quarantine: after.quarantine - before.quarantine,
        },
    }
}

fn lc_corrupt_siblings(scratch: &Path) -> usize {
    fs::read_dir(scratch)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
        .count()
}

/// The shared contract: the file was neither renamed nor rewritten, no
/// quarantine sibling exists, and the loaded index keeps the on-disk
/// generation and every file entry with its source checkpoint.
fn lc_assert_kept(scratch: &Path, load: LcLoad) -> (ScanIndex, ScanIndexLoadDrops) {
    let LcLoad {
        path,
        written,
        generation,
        result,
        drops,
    } = load;
    assert!(path.exists(), "the index stays at its path");
    assert_eq!(lc_corrupt_siblings(scratch), 0, "no .corrupt.* sibling");
    assert_eq!(fs::read(&path).unwrap(), written, "load never rewrites");
    let index = result.expect("a bad record never fails the load");
    assert_eq!(index.generation, generation, "generation unchanged");
    assert_eq!(index.files.len(), 4, "every file entry survives");
    assert!(
        index
            .files
            .values()
            .all(|entry| !entry.source_file_fingerprint.is_empty()),
        "no source checkpoint is cleared"
    );
    (index, drops)
}

/// The files the existing candidate gate re-reads on the next pass, with
/// the active quarantine witness the daemon installs before scanning.
fn lc_reread(index: &mut ScanIndex) -> BTreeMap<String, Option<CandidateParseReason>> {
    index.activate_quarantine_witness(SnapshotSource::ClaudeCode);
    let mut reread = BTreeMap::new();
    for (key, entry) in &index.files {
        let mut candidate = test_candidate(PathBuf::from(key));
        candidate.size_bytes = entry.size_bytes;
        candidate.modified_unix_seconds = entry.modified_unix_seconds;
        candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap_or_default();
        candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
        let (decision, reason) = index.candidate_decision_with_reason_at(&candidate, 0);
        if decision == CandidateDecision::Parse {
            reread.insert(key.clone(), reason);
        }
    }
    reread
}

fn lc_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn load_keeps_index_with_one_bad_activity_timestamp() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-activity");
    let load = lc_load(&scratch, "activity", |value| {
        value["snapshot_activity_at"][lc_hex('c')] = json!("syntactically-json-but-not-rfc3339");
    });
    let (mut index, drops) = lc_assert_kept(&scratch, load);
    assert!(!index.snapshot_activity_at.contains_key(&lc_hex('c')));
    assert_eq!(index.snapshot_activity_at.len(), 3);
    assert_eq!(
        index.accepted_snapshot_fingerprints,
        BTreeSet::from([lc_hex('c'), lc_hex('d')])
    );
    assert_eq!(index.quarantined_snapshot_fingerprints.len(), 2);
    assert_eq!(
        drops,
        ScanIndexLoadDrops {
            activity: 1,
            ..ScanIndexLoadDrops::default()
        }
    );
    // Re-read to re-derive the clock; the accepted body is a semantic no-op.
    assert_eq!(
        lc_reread(&mut index),
        BTreeMap::from([(
            lc_key("accepted-a"),
            Some(CandidateParseReason::ActivityOrQuarantineRetry)
        )])
    );
}

/// A malformed accepted identity can never equal a real body fingerprint,
/// so dropping it alone loses no acceptance; the ledger version is kept so
/// the valid acceptances are not re-offered.
#[test]
fn load_keeps_index_with_one_malformed_accepted_fingerprint() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-accepted");
    let load = lc_load(&scratch, "accepted", |value| {
        value["accepted_snapshot_fingerprints"]
            .as_array_mut()
            .unwrap()
            .push(json!("not-a-snapshot-fingerprint"));
    });
    let (index, drops) = lc_assert_kept(&scratch, load);
    assert_eq!(
        index.accepted_snapshot_fingerprints,
        BTreeSet::from([lc_hex('c'), lc_hex('d')])
    );
    assert_eq!(
        index.accepted_snapshot_fingerprint_ledger_version,
        SNAPSHOT_ACCEPTED_LEDGER_VERSION
    );
    assert_eq!(
        drops,
        ScanIndexLoadDrops {
            accepted: 1,
            ..ScanIndexLoadDrops::default()
        }
    );
}

/// A malformed sweep cursor restarts the bounded legacy sweep from the
/// lowest identity. The cursor stays present, so a pre-ledger set already
/// being proven is not mistaken for a never-armed one and re-opened whole.
#[test]
fn load_keeps_index_with_one_malformed_legacy_cursor() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-cursor");
    let load = lc_load(&scratch, "cursor", |value| {
        let object = value.as_object_mut().unwrap();
        object.remove("accepted_snapshot_fingerprint_ledger_version");
        object.insert(
            "legacy_settlement_reconcile_after_fingerprint".to_string(),
            json!("not-a-cursor"),
        );
    });
    let (index, drops) = lc_assert_kept(&scratch, load);
    assert_eq!(
        index.legacy_settlement_reconcile_after_fingerprint,
        Some(lc_hex('0'))
    );
    assert!(!index.legacy_settlement_ledger_is_unproven());
    assert_eq!(
        index.accepted_snapshot_fingerprints,
        BTreeSet::from([lc_hex('c'), lc_hex('d')])
    );
    assert_eq!(
        drops,
        ScanIndexLoadDrops {
            cursor: 1,
            ..ScanIndexLoadDrops::default()
        }
    );
}

/// A deadline beyond the bound (clock rollback or damage) becomes due now:
/// the retry obligation is kept, the gate re-reads the file, and finalize's
/// due-retry bypass re-offers the never-accepted body.
#[test]
fn load_keeps_index_with_one_unbounded_retry_pending_quarantine_record() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-retry");
    let load = lc_load(&scratch, "retry", |value| {
        let far = lc_now() + 10 * 24 * 60 * 60;
        value["quarantined_snapshot_fingerprints"][lc_hex('e')]["retry_after_unix_seconds"] =
            json!(far);
    });
    let after_load = lc_now();
    let (mut index, drops) = lc_assert_kept(&scratch, load);
    let record = &index.quarantined_snapshot_fingerprints[&lc_hex('e')];
    assert_eq!(
        record.disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert_eq!(record.failed_reconstruction_count, 1);
    assert!(record.retry_after_unix_seconds <= lc_now());
    assert!(record.retry_after_unix_seconds + 60 >= after_load);
    assert!(snapshot_quarantine_deadline_is_bounded(record));
    assert_eq!(index.snapshot_unproven_terminal_count(), 1);
    assert_eq!(index.snapshot_activity_at.len(), 4);
    assert_eq!(
        drops,
        ScanIndexLoadDrops {
            quarantine: 1,
            ..ScanIndexLoadDrops::default()
        }
    );
    assert_eq!(
        lc_reread(&mut index),
        BTreeMap::from([(
            lc_key("retry"),
            Some(CandidateParseReason::ActivityOrQuarantineRetry)
        )])
    );
    // The same predicate finalize uses to exempt the file from no-op
    // suppression, so the unchanged body is re-offered.
    assert!(index.quarantine_requires_retry(&lc_hex('e')));
}

#[test]
fn load_keeps_index_with_one_retry_pending_count_at_max() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-retry-count");
    let load = lc_load(&scratch, "retry-count", |value| {
        value["quarantined_snapshot_fingerprints"][lc_hex('e')]["failed_reconstruction_count"] =
            json!(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES);
    });
    let (index, drops) = lc_assert_kept(&scratch, load);
    let record = &index.quarantined_snapshot_fingerprints[&lc_hex('e')];
    assert_eq!(
        record.disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert_eq!(
        record.failed_reconstruction_count,
        MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1,
        "one more failed retry makes it terminal"
    );
    assert!(snapshot_quarantine_deadline_is_bounded(record));
    assert_eq!(
        drops,
        ScanIndexLoadDrops {
            quarantine: 1,
            ..ScanIndexLoadDrops::default()
        }
    );
}

/// The disposition is the explicit state; the count and deadline are its
/// invariants. The terminal disclosure is kept in its exact shape.
#[test]
fn load_keeps_index_with_one_unproven_terminal_count_mismatch() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-terminal");
    let load = lc_load(&scratch, "terminal", |value| {
        value["quarantined_snapshot_fingerprints"][lc_hex('f')]["failed_reconstruction_count"] =
            json!(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1);
    });
    let (mut index, drops) = lc_assert_kept(&scratch, load);
    let record = &index.quarantined_snapshot_fingerprints[&lc_hex('f')];
    assert_eq!(
        record.disposition,
        SnapshotQuarantineDisposition::UnprovenTerminal
    );
    assert_eq!(
        record.failed_reconstruction_count,
        MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
    );
    assert_eq!(record.retry_after_unix_seconds, 0);
    assert_eq!(index.snapshot_unproven_terminal_count(), 1);
    assert_eq!(
        drops,
        ScanIndexLoadDrops {
            quarantine: 1,
            ..ScanIndexLoadDrops::default()
        }
    );
    assert!(lc_reread(&mut index).is_empty());
}

/// Every converted check at once: each record is handled alone.
#[test]
fn load_keeps_index_with_one_bad_record_of_every_kind() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-all");
    let load = lc_load(&scratch, "all", |value| {
        value["snapshot_activity_at"][lc_hex('e')] = json!("not-rfc3339");
        value["accepted_snapshot_fingerprints"]
            .as_array_mut()
            .unwrap()
            .push(json!("ABC"));
        value["legacy_settlement_reconcile_after_fingerprint"] = json!("");
        value["quarantined_snapshot_fingerprints"][lc_hex('e')]["failed_reconstruction_count"] =
            json!(u8::MAX);
        value["quarantined_snapshot_fingerprints"][lc_hex('f')]["retry_after_unix_seconds"] =
            json!(1);
    });
    let (mut index, drops) = lc_assert_kept(&scratch, load);
    assert_eq!(index.quarantined_snapshot_fingerprints.len(), 2);
    assert!(index
        .quarantined_snapshot_fingerprints
        .values()
        .all(snapshot_quarantine_deadline_is_bounded));
    assert_eq!(index.snapshot_unproven_terminal_count(), 1);
    assert_eq!(index.accepted_snapshot_fingerprints.len(), 2);
    assert_eq!(
        index.legacy_settlement_reconcile_after_fingerprint,
        Some(lc_hex('0'))
    );
    assert_eq!(
        drops,
        ScanIndexLoadDrops {
            activity: 1,
            accepted: 1,
            cursor: 1,
            quarantine: 2,
        }
    );
    assert_eq!(
        lc_reread(&mut index),
        BTreeMap::from([(
            lc_key("retry"),
            Some(CandidateParseReason::ActivityOrQuarantineRetry)
        )])
    );
}

/// An accepted-ledger version above the supported one was written by a newer
/// build. It is future state, like a schema mismatch: refuse, never rebuild.
#[test]
fn load_refuses_future_ledger_version_without_quarantine() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-future-ledger");
    let load = lc_load(&scratch, "future-ledger", |value| {
        value["accepted_snapshot_fingerprint_ledger_version"] =
            json!(SNAPSHOT_ACCEPTED_LEDGER_VERSION + 1);
    });
    assert!(load.result.is_err(), "future ledger state is refused");
    assert!(load.path.exists(), "the index stays at its path");
    assert_eq!(lc_corrupt_siblings(&scratch), 0, "no .corrupt.* sibling");
    assert_eq!(fs::read(&load.path).unwrap(), load.written);
    assert_eq!(load.drops, ScanIndexLoadDrops::default());
}

/// Structural damage keeps the whole-index rebuild: invalid JSON still
/// quarantines, and a valid index loads with nothing dropped.
#[test]
fn load_still_quarantines_undecodable_index_and_drops_nothing_from_valid_one() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-structural");
    let valid = lc_load(&scratch, "valid", |_| {});
    let (mut index, drops) = lc_assert_kept(&scratch, valid);
    assert_eq!(drops, ScanIndexLoadDrops::default());
    assert!(lc_reread(&mut index).is_empty());

    let path = scratch.join("truncated-claude_code-scan-index-v3.json");
    fs::write(&path, b"{\"schema_version\":").unwrap();
    let rebuilt = ScanIndex::load(&path).expect("undecodable index rebuilds");
    assert!(!path.exists());
    assert_eq!(lc_corrupt_siblings(&scratch), 1);
    assert_eq!(rebuilt.generation, 0);
    assert!(rebuilt.files.is_empty());
}
