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
    fn scan_with_owner(
        &self,
        index: &mut ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
    ) -> SourceScanResult {
        let mut state = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            &self.roots,
            std::mem::take(index),
            &self.now,
            730,
            32,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(
            cache,
            crate::transcript_acquisition::Scope("copy-fixture".into()),
        );
        loop {
            match state.step(None) {
                OwnedSourceScanStep::Pending(next) => state = next,
                OwnedSourceScanStep::Complete { index: next, scan } => {
                    *index = next;
                    return scan;
                }
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn context(key: &str, value: Option<&str>) -> ScanContext {
    let mut context = ScanContext::new(
        "a".repeat(64),
        BTreeMap::from([(key.to_string(), value.map(str::to_string))]),
    )
    .unwrap();
    context.attempt_scope = Some("a".repeat(64));
    context
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
            observed: HoldObservation::default(),
        },
    );
}

#[test]
fn copy_containment_status_has_unique_park_counts_explicit_unknowns_and_no_content() {
    let f = Fixture::new();
    f.write(A, &["req_status"], false);
    let mut index = ScanIndex::default();
    let mut initial = f.scan(&mut index);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut initial, &mut index);
    let accepted = index.current_snapshot_fingerprints();
    index.record_accepted_snapshot_fingerprints(&accepted);
    let key = local_index_key(&f.path(A));
    let revision = index.files[&key].source_file_fingerprint.clone();
    install_hold(&mut index, &f.path(A), &revision, &"b".repeat(64));
    install_hold(&mut index, &f.path(B), &"c".repeat(64), &"b".repeat(64));
    index
        .claude_copy_holds
        .entries
        .get_mut(&local_index_key(&f.path(B)))
        .unwrap()
        .revision
        .first_observed_unix_seconds = None;
    install_hold(&mut index, &f.path(C), &"c".repeat(64), &"b".repeat(64));
    index
        .claude_copy_holds
        .entries
        .get_mut(&local_index_key(&f.path(C)))
        .unwrap()
        .revision
        .first_observed_unix_seconds = Some(200);
    index.attach_copy_scan_context(context(&key, None));
    let debt = serde_json::to_value(&index).unwrap()["claude_copy_holds"].clone();
    for _ in 0..3 {
        assert_eq!(f.scan(&mut index).scanned_file_count, 0);
    }
    assert_eq!(index.copy_parked_count(), 3);
    let (status, allocations) =
        crate::retry_allocation_probe::measure(|| index.copy_containment_status(Some(130)));
    assert_eq!(
        allocations.allocations, 0,
        "fixed aggregate projection needs no key/ID clones"
    );
    assert_eq!(status.held_revision_count, 3);
    assert_eq!(
        status.parked_held_revision_count,
        Some(1),
        "distinct held keys, not3visits"
    );
    assert_eq!(status.retained_prior_local_ack_count, 1);
    assert_eq!(status.past_acceptance_unknown_count, 2);
    assert_eq!(status.new_without_prior_local_ack_count, None);
    assert_eq!(status.oldest_known_observed_age_seconds, Some(30));
    assert_eq!(
        status.observation_age_unknown_count, 2,
        "unknown/future clocks never become0age"
    );
    assert_eq!(status.parked_while_w4_unavailable_count, Some(1));
    assert_eq!(status.reasons.copied_overlap_unproven, 3);
    assert!(status.marker_settled_suppressed_by_recorded_holds);
    let encoded = serde_json::to_string(&status).unwrap();
    for forbidden in [key.as_str(), A, B, C, revision.as_str(), "req_status"] {
        assert!(!encoded.contains(forbidden));
    }
    assert_eq!(
        serde_json::to_value(&index).unwrap()["claude_copy_holds"],
        debt,
        "ephemeral observations never change held storage"
    );
    let restored: ScanIndex =
        serde_json::from_value(serde_json::to_value(&index).unwrap()).unwrap();
    assert_eq!(
        restored
            .copy_containment_status(Some(130))
            .parked_held_revision_count,
        None
    );
    let mut invalid = serde_json::to_value(&index).unwrap();
    invalid["claude_copy_holds"][&key]["observed"] = json!({"parked":true});
    assert!(
        serde_json::from_value::<ScanIndex>(invalid).is_err(),
        "localflags cannot be injected through durableJSON"
    );
    writeln!(std::io::stderr().lock(), "copy_containment_local_status: holds=3 unique_parked=1 visits=3 prior_local_ack=1 past_acceptance_unknown=2 new_without_ack=UNKNOWN known_oldest_seconds=30 unknown_age=2 projection_allocations=0 no_content=true observations_not_persisted=true").unwrap();
}

#[test]
fn copy_containment_status_exposes_closed_reasons_and_unknown_unrecorded_debt() {
    let f = Fixture::new();
    let mut index = ScanIndex::default();
    install_hold(&mut index, &f.path(A), &"c".repeat(64), &"b".repeat(64));
    let key = local_index_key(&f.path(A));
    let held = index.claude_copy_holds.entries.get_mut(&key).unwrap();
    held.revision.reason = HoldReason::ComparisonUnavailable;
    index.attach_copy_scan_context(context(&key, None));
    let context = index.active_copy_scan.as_mut().unwrap();
    context.hold_record_limit_refusals = 2;
    context.hold_peer_limit_refusals = 1;
    let status = index.copy_containment_status(None);
    assert_eq!(status.reasons.comparison_unavailable, 1);
    assert_eq!(status.reasons.copied_overlap_unproven, 0);
    assert_eq!(status.hold_record_limit_refusals, Some(2));
    assert_eq!(status.hold_peer_limit_refusals, Some(1));
    assert_eq!(
        status.unrecorded_held_revision_count, None,
        "refusals are not a unique-count witness"
    );
    assert_eq!(status.oldest_known_observed_age_seconds, None);
    assert_eq!(status.observation_age_unknown_count, 1);
    assert_eq!(status.new_without_prior_local_ack_count, None);
}

#[test]
fn copy_containment_retained_peer_cap_withholds_native_candidate_without_growing_ledger() {
    let f = Fixture::new();
    f.write(B, &["req_peer_cap"], false);
    let mut index = ScanIndex::default();
    let scan = f.scan(&mut index);
    assert_eq!(scan.snapshots.len(), 1);
    assert!(scan.snapshots[0]
        .claude_usage_request_ids
        .contains("req_peer_cap"));
    let key = local_index_key(&f.path(B));
    let revision = index.files[&key].source_file_fingerprint.clone();
    install_hold(&mut index, &f.path(A), &"c".repeat(64), &"b".repeat(64));
    index
        .claude_copy_holds
        .entries
        .get_mut(&local_index_key(&f.path(A)))
        .unwrap()
        .peers = (0..MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS)
        .map(|n| format!("{n:064x}"))
        .collect();
    assert!(index.claude_copy_holds.valid());
    index.attach_copy_scan_context(context(&key, None));
    index.claude_duplicate_request_owners.insert(
        format!("{:x}", sha2::Sha256::digest(b"req_peer_cap")),
        BTreeSet::from([
            claude_duplicate_request_owner(B, B),
            claude_duplicate_request_owner(C, C),
        ]),
    );
    let withheld =
        index.record_known_copy_holds(&scan.snapshots, &[(&key, &revision)], |_, _| false);
    assert_eq!(withheld, BTreeSet::from([B.to_string()]));
    assert_eq!(index.copy_hold_count(), 1);
    assert!(!index.claude_copy_holds.entries.contains_key(&key));
    assert_eq!(
        index.claude_copy_holds.entries[&local_index_key(&f.path(A))]
            .peers
            .len(),
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
    );
    let status = index.copy_containment_status(None);
    assert_eq!(status.hold_peer_limit_refusals, Some(1));
    assert_eq!(status.hold_record_limit_refusals, Some(0));
    assert_eq!(status.withheld_candidates_observed, Some(true));
    assert_eq!(status.unrecorded_held_revision_count, None);
    assert!(status.marker_settled_suppressed_by_recorded_holds);
    // With zero retained holds the count is0. A valid duplicate map cannot
    // provide more peers than its own owner-link cap, so zero-hold peer-cap
    // refusal is unreachable under production limits (unlike account slots).
    writeln!(std::io::stderr().lock(), "copy_containment_peer_cap: existing_retained_peer_links={} actual_native_candidate_withheld=1 copy_hold_count=1 ledger_growth=0 unrecorded_distinct_count=UNKNOWN no_test_limit_override=true", MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS).unwrap();
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
fn copy_containment_native_scanner_proven_own_change_reads_once_with_other_wakes_unknown() {
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
    assert_eq!(f.scan(&mut index).scanned_file_count, 0);
    let previous = index.clone();
    f.write(A, &["req_shared", "req_new"], false);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    cache.require_copy_containment_for_test();
    let mut changed = f.scan_with_owner(&mut index, cache.clone());
    if !crate::heap_layout_bound::layout_supported() {
        assert_eq!(changed.scanned_file_count, 0);
        assert_eq!(index.copy_hold_count(), 1);
        writeln!(std::io::stderr().lock(), "copy_containment_own_change: layout_unavailable=true actual_attempt_refused=true positive_own_change_save_reload_executed=false original_positive_oracle_unaccepted=true").unwrap();
        return;
    }
    assert_eq!(changed.scanned_file_count, 1);
    assert!(changed
        .pending_finalization
        .iter()
        .all(|pending| pending.parse_complete));
    let authority = apply_claude_reported_usage_to_scan_with_identity(
        &mut changed,
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        &mut index,
        None,
    );
    assert!(authority.copied_source_session_ids.contains(A));
    authority.retain_copy_uploadable(&mut changed.snapshots);
    assert!(
        changed.snapshots.is_empty(),
        "a wake never releases a held body"
    );
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut changed, &mut index);
    let mut selected = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(selected.copy_hold_count(), 1);
    assert_eq!(
        selected.claude_copy_holds.entries[&key]
            .revision
            .first_observed_unix_seconds,
        Some(100)
    );
    let path = f.base.join("own-change-index.json");
    selected.save(&path).unwrap();
    let mut reloaded = ScanIndex::load_for_copy_containment(&path).unwrap();
    reloaded.attach_copy_scan_context(context(&key, None));
    for _ in 0..3 {
        assert_eq!(
            f.scan_with_owner(&mut reloaded, cache.clone())
                .scanned_file_count,
            0,
            "remember native evaluation independently from ACK/hold resolution"
        );
    }
    assert_eq!(reloaded.copy_hold_count(), 1);
    // An unavailable opened own revision is not a positive event.
    fs::remove_file(f.path(A)).unwrap();
    assert_eq!(f.scan(&mut reloaded).scanned_file_count, 0);
    assert_eq!(
        reloaded.copy_hold_count(),
        1,
        "a traversal miss is not absence proof"
    );
    writeln!(std::io::stderr().lock(), "copy_containment_own_change: actual_guarded_native_read=1 unrelated_wakes_unknown=true withheld_bodies=1 offered_bodies=0 selected_save_reload=true unchanged_followup_reads=0 debt_and_age_preserved=true missing_own_revision_no_wake=true failed_save_process_attempt_lifetime_unproved=true").unwrap();
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
fn copy_containment_required_load_preserves_invalid_debt_in_place_and_reads_valid_state() {
    let f = Fixture::new();
    let path = f.base.join("required-index.json");
    let mut index = ScanIndex::default();
    install_hold(&mut index, &f.path(A), &"c".repeat(64), &"b".repeat(64));
    index.save(&path).unwrap();
    assert_eq!(
        ScanIndex::load_for_copy_containment(&path)
            .unwrap()
            .copy_hold_count(),
        1
    );
    let valid = fs::read(&path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
    let key = local_index_key(&f.path(A));
    let mut unknown_version = value.clone();
    unknown_version["claude_copy_holds"][&key]["revision"]["version"] = json!(99);
    let mut unknown_reason = value.clone();
    unknown_reason["claude_copy_holds"][&key]["revision"]["reason"] = json!("future_reason");
    let mut invalid_other_required_fact = value;
    invalid_other_required_fact["accepted_snapshot_fingerprints"] = json!(["not-a-fingerprint"]);
    for bytes in [
        serde_json::to_vec(&unknown_version).unwrap(),
        serde_json::to_vec(&unknown_reason).unwrap(),
        serde_json::to_vec(&invalid_other_required_fact).unwrap(),
        valid[..valid.len() / 2].to_vec(),
    ] {
        fs::write(&path, &bytes).unwrap();
        let error = ScanIndex::load_for_copy_containment(&path).unwrap_err();
        assert!(error
            .to_string()
            .contains("containment-required scan index"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!fs::read_dir(&f.base)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains("corrupt")));
    }
    // Operator/owner recovery of the original valid state restores the debt;
    // the failed loader never invented a fresh index or a new read allowance.
    fs::write(&path, valid).unwrap();
    assert_eq!(
        ScanIndex::load_for_copy_containment(&path)
            .unwrap()
            .copy_hold_count(),
        1
    );
    let directory = f.base.join("unreadable-as-index.json");
    fs::create_dir(&directory).unwrap();
    assert!(ScanIndex::load_for_copy_containment(&directory).is_err());
    assert!(directory.is_dir());
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
