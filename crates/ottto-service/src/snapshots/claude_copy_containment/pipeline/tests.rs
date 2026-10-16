use super::*;
use crate::snapshots::*;
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const A: &str = "5f9ab1cc-0000-4000-8000-0000000000aa";
const B: &str = "5f9ab1cc-0000-4000-8000-0000000000bb";
const C: &str = "5f9ab1cc-0000-4000-8000-0000000000cc";
struct Fixture {
    base: PathBuf,
    roots: Vec<PathBuf>,
    now: String,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "ottto-copy-pipeline-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("projects");
        fs::create_dir_all(&root).unwrap();
        Self {
            base,
            roots: vec![root],
            now: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        }
    }
    fn path(&self, session: &str) -> PathBuf {
        self.roots[0].join(format!("{session}.jsonl"))
    }
    fn write(&self, session: &str, requests: &[&str], heavy: bool) {
        let mut file = File::create(self.path(session)).unwrap();
        if heavy {
            let padding = "x".repeat(32 * 1024);
            for _ in 0..32 {
                serde_json::to_writer(
                    &mut file,
                    &json!({"type":"user", "sessionId":session,
                    "timestamp":self.now,"message":{"role":"user","content":padding}}),
                )
                .unwrap();
                file.write_all(b"\n").unwrap();
            }
        }
        for id in requests {
            serde_json::to_writer(
                &mut file,
                &json!({"type":"assistant","sessionId":session,
                "timestamp":self.now,"requestId":id,"message":{"id":format!("msg_{id}"),
                    "model":"claude-fixture-model","role":"assistant",
                    "usage":{"input_tokens":10,"output_tokens":2}}}),
            )
            .unwrap();
            file.write_all(b"\n").unwrap();
        }
    }
    fn scan(&self, index: &mut ScanIndex) -> SourceScanResult {
        scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            &self.roots,
            index,
            &self.now,
            730,
            32,
            false,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn context(key: &str, value: Option<&str>) -> ScanContext {
    ScanContext::new(
        "a".repeat(64),
        BTreeMap::from([(key.to_string(), value.map(str::to_string))]),
    )
    .unwrap()
}
fn install_hold(index: &mut ScanIndex, path: &Path, source: &str, evidence: &str) {
    index.claude_copy_holds.entries.insert(
        local_index_key(path),
        HeldFile {
            revision: HoldRevision::new(
                HoldReason::CopiedOverlapUnproven,
                source.to_string(),
                evidence.to_string(),
                Some(100),
            )
            .unwrap(),
            peers: BTreeSet::from(["e".repeat(64)]),
        },
    );
}

#[test]
fn copy_containment_native_scanner_parks_actual_heavy_file_under_repeated_fingerprint_rearm() {
    let f = Fixture::new();
    f.write(A, &["req_shared"], true);
    f.write(C, &["req_healthy"], false);
    let mut parked = ScanIndex::default();
    let mut first = f.scan(&mut parked);
    assert_eq!(first.scanned_file_count, 2);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut first, &mut parked);
    let key = local_index_key(&f.path(A));
    let evidence = "b".repeat(64);
    let revision = parked.files[&key].source_file_fingerprint.clone();
    install_hold(&mut parked, &f.path(A), &revision, &evidence);
    parked.attach_copy_scan_context(context(&key, Some(&evidence)));
    let mut base = parked.clone();
    base.active_copy_scan = None;
    let mut base_full = 0;
    let mut parked_full = 0;
    for _ in 0..12 {
        // Exact native scanner control: base rearm destroys the committed source
        // fingerprint. It must NOT destroy the separate held opened revision.
        base.files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        parked
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let mut baseline = f.scan(&mut base);
        base_full += baseline.scanned_file_count;
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut baseline, &mut base);
        let mut optimized = f.scan(&mut parked);
        parked_full += optimized.scanned_file_count;
        assert!(optimized
            .snapshots
            .iter()
            .all(|item| item.source_session_id != A));
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut optimized, &mut parked);
    }
    assert_eq!(base_full, 12);
    assert_eq!(parked_full, 0);
    assert_eq!(parked.copy_parked_count(), 12);
    assert_eq!(parked.copy_hold_count(), 1);
    writeln!(std::io::stderr().lock(), "copy_containment_native_scanner: passes=12 base_full_reads={base_full} parked_full_reads={parked_full} fixture_bytes={} normal_skip_certificate=false owner_context_injected=true process_owner_unwired=true sibling_wire_ack_unproved=true",
        fs::metadata(f.path(A)).unwrap().len()).unwrap();
}

#[test]
fn copy_containment_native_scanner_unknown_wake_stays_parked_known_revision_change_reads() {
    let f = Fixture::new();
    f.write(A, &["req_shared"], false);
    let mut index = ScanIndex::default();
    let mut scan = f.scan(&mut index);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    let key = local_index_key(&f.path(A));
    let revision = index.files[&key].source_file_fingerprint.clone();
    let evidence = "b".repeat(64);
    install_hold(&mut index, &f.path(A), &revision, &evidence);
    index.attach_copy_scan_context(context(&key, None));
    f.write(A, &["req_shared", "req_new"], false);
    assert_eq!(f.scan(&mut index).scanned_file_count, 0);
    index.attach_copy_scan_context(context(&key, Some(&evidence)));
    let changed = f.scan(&mut index);
    assert_eq!(changed.scanned_file_count, 1);
    assert_eq!(index.copy_hold_count(), 1); // Parse is not ACK/debt settlement.
}

#[test]
fn copy_containment_partial_selection_restores_old_body_and_carries_new_copy_debt_after_reload() {
    let f = Fixture::new();
    f.write(A, &["req_original"], false);
    let mut previous = ScanIndex::default();
    let mut initial = f.scan(&mut previous);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut initial, &mut previous);
    let accepted = previous.current_snapshot_fingerprints();
    previous.record_accepted_snapshot_fingerprints(&accepted);
    let key = local_index_key(&f.path(A));
    let old = serde_json::to_value(&previous.files[&key]).unwrap();
    let mut working = previous.clone();
    f.write(A, &["req_original", "req_copied"], false);
    f.write(B, &["req_copied"], false);
    let mut changed = f.scan(&mut working);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut changed, &mut working);
    for path in [f.path(A), f.path(B)] {
        let source = working.files[&local_index_key(&path)]
            .source_file_fingerprint
            .clone();
        install_hold(&mut working, &path, &source, &"b".repeat(64));
    }
    let selected = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(serde_json::to_value(&selected.files[&key]).unwrap(), old);
    assert!(!selected.files.contains_key(&local_index_key(&f.path(B))));
    assert_eq!(selected.copy_hold_count(), 2);
    assert_eq!(
        selected.current_snapshot_fingerprints(),
        previous.current_snapshot_fingerprints()
    );
    let mut selected = selected;
    let path = f.base.join("index.json");
    selected.save(&path).unwrap();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(reloaded.copy_hold_count(), 2);
    assert!(reloaded.active_copy_scan.is_none()); // reload never creates a process owner
    assert_eq!(
        reloaded.current_snapshot_fingerprints(),
        previous.current_snapshot_fingerprints()
    );
    assert!(reloaded.claude_account_deferred_holds.is_empty());
    assert!(reloaded.claude_usage_authority_quarantine.is_empty());
}

#[test]
fn copy_containment_unknown_record_fails_load_instead_of_silently_clearing_debt() {
    let f = Fixture::new();
    let path = f.base.join("index.json");
    let mut index = ScanIndex::default();
    install_hold(&mut index, &f.path(A), &"c".repeat(64), &"b".repeat(64));
    let mut encoded = serde_json::to_value(&index).unwrap();
    encoded["claude_copy_holds"][local_index_key(&f.path(A))]["revision"]["version"] = json!(99);
    fs::write(&path, serde_json::to_vec(&encoded).unwrap()).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(loaded.copy_hold_count(), 0);
    assert!(fs::read_dir(&f.base)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().contains("corrupt")));
    // New owner/pre-offer guards are still required on rebuilt indexes. This
    // quarantine alone never claims safety under an older binary.
}

#[test]
fn copy_containment_native_fold_withholds_known_copies_before_healthy_wire_ack_and_save() {
    let f = Fixture::new();
    f.write(A, &["req_shared", "req_original"], false);
    f.write(B, &["req_shared", "req_copy"], false);
    f.write(C, &["req_healthy"], false);
    let previous = ScanIndex::default();
    let mut working = previous.clone();
    let mut scan = f.scan(&mut working);
    assert!(scan.census_complete);
    assert_eq!(scan.snapshots.len(), 3);
    working.attach_copy_scan_context(ScanContext::new("a".repeat(64), BTreeMap::new()).unwrap());
    let authority = apply_claude_reported_usage_to_scan_with_identity(
        &mut scan,
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::new(),
            health: Default::default(),
        },
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        &mut working,
        None,
    );
    assert_eq!(working.copy_hold_count(), 2);
    assert_eq!(
        authority.copied_source_session_ids,
        BTreeSet::from([A.to_string(), B.to_string()])
    );
    authority.retain_copy_uploadable(&mut scan.snapshots);
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].source_session_id, C);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut working);
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "claude_code".into(),
        machine_id: "synthetic-machine".into(),
        collector_version: None,
        snapshots: scan.snapshots,
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let wire = serde_json::to_value(&request).unwrap();
    assert_eq!(wire["snapshots"].as_array().unwrap().len(), 1);
    assert_eq!(wire["snapshots"][0]["source_session_id"], C);
    assert!(!serde_json::to_string(&wire)
        .unwrap()
        .contains("copied_overlap_unproven"));
    let healthy = &request.snapshots[0];
    assert_eq!(snapshot_upload_body_witness_version(healthy), Some(23));
    let ack_wire = json!({"accepted":1,"sessions_reconciled":1,"session_ids":[C],
        "disabled":false,"disabled_reason":null,"entity_ack_contract":"snapshot_entity_ack:v1",
        "accepted_entities":[{"source_session_id":C,"snapshot_fingerprint":healthy.snapshot_fingerprint,
            "body_witness_version":7,"body_witness_digest":snapshot_upload_body_witness(healthy)}],
        "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]});
    let mut wrong_body = ack_wire.clone();
    wrong_body["accepted_entities"][0]["body_witness_digest"] = json!("d".repeat(64));
    let rejected: crate::snapshot_client::SnapshotBatchResponse =
        serde_json::from_value(wrong_body).unwrap();
    assert!(rejected.validate_entity_ack(&request).is_err());
    let response: crate::snapshot_client::SnapshotBatchResponse =
        serde_json::from_value(ack_wire).unwrap();
    response.validate_entity_ack(&request).unwrap();
    let accepted = response
        .accepted_entities
        .into_iter()
        .map(|item| item.snapshot_fingerprint)
        .collect();
    let mut selected = working.committable_subset(&previous, &accepted, &BTreeMap::new());
    selected.record_accepted_snapshot_fingerprints(&accepted);
    let path = f.base.join("accepted-index.json");
    selected.save(&path).unwrap();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(reloaded.copy_hold_count(), 2);
    assert!(reloaded.files.contains_key(&local_index_key(&f.path(C))));
    assert!(!reloaded.files.contains_key(&local_index_key(&f.path(A))));
    assert!(!reloaded.files.contains_key(&local_index_key(&f.path(B))));
    assert_eq!(reloaded.current_snapshot_fingerprints(), accepted);
    writeln!(std::io::stderr().lock(), "copy_containment_native_preoffer: actual_native_fold=true known_copies_held=2 serialized_healthy_bodies=1 actual_entity_ack_validator=true selected_save_reload=true first_unseen_gap_unchanged=true c5_basis_parity_unproved=true runtime_owner_unwired=true").unwrap();
}
