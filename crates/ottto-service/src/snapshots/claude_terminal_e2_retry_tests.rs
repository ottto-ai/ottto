//! A terminal family gets one request-owned recovery through the native scanner.
use super::apply_claude_reported_usage_with_index as fold_authority;
use super::claude_request_money::e2::{finish_page, TelemetryRead};
use super::e2_pipeline_scan_fixture::{write_exclusions, E2ScanFixture};
use super::sampled_scan::transition_fixture::{money_oracle, scan_money};
use super::ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal;
use super::*;

/// [regress] A grown revision-2 root can retry an old terminal verdict exactly once.
#[test]
fn pre_e2_terminal_retries_once_and_matches_cold_full() {
    let scratch = crate::test_scratch::ScratchDir::new("claude-terminal-e2-retry");
    let root = scratch.join("project");
    fs::create_dir_all(&root).unwrap();
    let id = "a0000000-0000-4000-8000-00000000000a";
    let path = root.join(format!("{id}.jsonl"));
    let at = "2026-08-02T07:00:00Z";
    let line = json!({"type":"assistant", "version":"2.1.309", "sessionId":id,
        "timestamp":at, "requestId":"request", "message":{"id":"message",
        "model":"claude-haiku-4-5", "usage":{"input_tokens":10,"output_tokens":1}}});
    fs::write(&path, format!("{line}\n")).unwrap();
    write_exclusions(&scratch, &[]);
    let births = BTreeMap::from([(path.clone(), rfc3339_unix_nanos(at).unwrap())]);
    let source = SnapshotSource::ClaudeCode;
    let api = Default::default();
    let trace = Default::default();
    let fold = |index: &mut ScanIndex, items: &mut [SnapshotItem]| {
        fold_authority(items, &api, &trace, index, false, at)
    };
    let roots = [root];
    let scan = |index, sampled| {
        E2ScanFixture::default().scan(&roots, &scratch, index, 10, sampled, &births, &[])
    };
    let mut fresh = ScanIndex::default();
    fresh.load_claude_reemission_exclusions(&scratch);
    let (mut cold_idx, mut cold_scan, _) = scan(fresh, false);
    let mut index = cold_idx.clone();
    let key = local_index_key(&path);
    let entry = index.files.get_mut(&key).unwrap();
    entry.size_bytes -= 1; // The committed revision-2 body predates this grown extent.
    entry.effective_upload_body_witness_revision = 2;
    index.insert_unproven_terminal_claude_authority_for_test(
        id,
        &cold_idx.files[&key].source_file_fingerprint,
    );
    let hints = [path.clone()];
    let selection = OwnedSourceScan::new(
        source,
        &roots,
        index.clone(),
        at,
        183,
        10,
        false,
        Some(&scratch),
        &hints,
        false,
    );
    let candidate = selection.identified_candidates.front().unwrap();
    let record = index.claude_usage_authority_quarantine.get_mut(id).unwrap();
    record.retry_after_unix_seconds = 0;
    assert_eq!(index.candidate_decision(candidate), CandidateDecision::Skip);
    let record = index.claude_usage_authority_quarantine.get_mut(id).unwrap();
    record.retry_after_unix_seconds = PRE_E2_TERMINAL_DEADLINE_CUTOFF;
    assert_eq!(
        index.candidate_decision(candidate),
        CandidateDecision::Parse
    );
    let (read_index, mut recovered, modes) = scan(index, true);
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(recovered.snapshots.len(), 1);
    let mut failed_idx = read_index.clone();
    let mut failed = recovered.snapshots.clone();
    failed[0].claude_money = None; // A failed E2 fold still takes the existing demotion arm.
    failed[0].usage_accounting_contract = None;
    let held = fold(&mut failed_idx, &mut failed);
    held.retain_uploadable(&mut failed);
    assert!(failed.is_empty());
    let record = &failed_idx.claude_usage_authority_quarantine[id];
    assert_eq!(record.disposition, UnprovenTerminal);
    assert!(record.retry_after_unix_seconds > PRE_E2_TERMINAL_DEADLINE_CUTOFF);
    let saved = scratch.join("scan-index.json");
    failed_idx.save(&saved).unwrap();
    let failed_idx = ScanIndex::load(&saved).unwrap();
    assert_eq!(
        failed_idx.candidate_decision(candidate),
        CandidateDecision::Skip
    );
    let (_, quiet, modes) = scan(failed_idx, true);
    assert_eq!(modes, (0, 0, 0));
    assert!(quiet.snapshots.is_empty());
    let finish = |index: &mut ScanIndex, scan: &mut SourceScanResult| {
        fold(index, &mut scan.snapshots);
        finish_page(
            &mut scan.snapshots,
            index,
            TelemetryRead::Loaded,
            &mut Default::default(),
            &Default::default(),
        );
        scan_money(source, index, scan)
    };
    let cold = finish(&mut cold_idx, &mut cold_scan);
    let mut ok_idx = read_index;
    let success = finish(&mut ok_idx, &mut recovered);
    assert!(!ok_idx.claude_usage_authority_quarantine.contains_key(id));
    money_oracle::assert_equivalent(&cold, &success);
}
