// Page-scoped witness reconstruction. Every finish loads telemetry for all
// witnessed families; only families with an item on the page are rebuilt.
// Synthetic, content-free fixtures. The allocation probe does not depend on
// the validated heap layout, so these assertions execute on every compiler.
use super::*;
use crate::retry_allocation_probe as probe;

const REQUESTS_PER_FAMILY: usize = 16;

struct Families {
    dir: PathBuf,
    index: ScanIndex,
    raw: Vec<SnapshotItem>,
    api: crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace: crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
}

fn family_root(family: usize) -> String {
    format!("{:08x}-7c7c-4000-8000-{family:012x}", 0x5c00_0000 + family)
}

/// `count` single-member families, each with its own requests and exactly
/// paired API/trace rows, proven by one complete census.
fn proven_families(name: &str, count: usize) -> Families {
    let dir = temp_dir(name);
    let mut index = ScanIndex {
        accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
        ..Default::default()
    };
    let mut raw = Vec::new();
    let mut api = BTreeMap::new();
    let mut trace = BTreeMap::new();
    for family in 0..count {
        let root = family_root(family);
        let path = dir.join(format!("{root}.jsonl"));
        let lines = (0..REQUESTS_PER_FAMILY)
            .map(|request| {
                format!(
                    "{{\"timestamp\":\"2026-08-02T07:00:{request:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{root}\",\"requestId\":\"req_{family}_{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
                )
            })
            .collect::<String>();
        fs::write(&path, lines).expect("write family fixture");
        let item =
            parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", format!("source-{family}"))
                .expect("parse family fixture")
                .remove(0);
        index_file(
            &mut index,
            &local_index_key(&path),
            item.source_file_fingerprint.as_ref().unwrap(),
            &item.snapshot_fingerprint,
            WINDOW,
        );
        index
            .accepted_snapshot_fingerprints
            .insert(item.snapshot_fingerprint.clone());
        api.insert(
            root.clone(),
            (0..REQUESTS_PER_FAMILY)
                .map(|request| {
                    complete_api_row(
                        &root,
                        &format!("req_{family}_{request}"),
                        request as u64,
                        10,
                        10,
                        0,
                    )
                })
                .collect::<Vec<_>>(),
        );
        trace.insert(
            root.clone(),
            (0..REQUESTS_PER_FAMILY)
                .map(|request| complete_trace_row(&root, &format!("req_{family}_{request}"), ""))
                .collect::<Vec<_>>(),
        );
        raw.push(item);
    }
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: api,
        health: Default::default(),
    };
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: trace,
        ..Default::default()
    };
    let mut seed = raw.clone();
    apply_claude_reported_usage_with_index(&mut seed, &api, &trace, &mut index, true, WINDOW);
    assert_eq!(index.claude_usage_family_witnesses.len(), count);
    assert!(seed
        .iter()
        .all(|item| item.usage_accounting_contract.as_deref()
            == Some("session_exclusive_reported_usage:v1")));
    Families {
        dir,
        index,
        raw,
        api,
        trace,
    }
}

/// A non-terminal page that parsed only family 0, while the finish loaded
/// every witnessed family's telemetry (the ordinary all-root join).
fn rebuild_first_family(families: &Families) -> SnapshotItem {
    let mut index = families.index.clone();
    let mut page = vec![families.raw[0].clone()];
    let disposition = apply_claude_reported_usage_with_index(
        &mut page,
        &families.api,
        &families.trace,
        &mut index,
        false,
        WINDOW,
    );
    assert!(disposition.quarantined_source_session_ids.is_empty());
    assert_eq!(
        index.claude_usage_family_witnesses,
        families.index.claude_usage_family_witnesses
    );
    page.remove(0)
}

fn rebuild_phase_peak(families: &Families) -> usize {
    let (peak, _) = probe::measure(|| {
        let mut index = families.index.clone();
        let mut page = vec![families.raw[0].clone()];
        probe::phase_begin();
        apply_claude_reported_usage_with_index(
            &mut page,
            &families.api,
            &families.trace,
            &mut index,
            false,
            WINDOW,
        );
        probe::phase_peak()
    });
    peak
}

#[test]
fn unrelated_witnessed_families_do_not_change_page_family_rebuild() {
    let _completion_paths = crate::snapshots::ClaudeCompletionPathsForTest::enable();
    // Legacy reported-body proof/delivery; E2 publishes a request-owned literal instead.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let alone = proven_families("witness-scope-alone", 1);
    let crowded = proven_families("witness-scope-crowded", 9);
    let expected = rebuild_first_family(&alone);
    let actual = rebuild_first_family(&crowded);
    assert_eq!(
        actual.usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    assert_eq!(
        serde_json::to_value(&actual).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    let _ = fs::remove_dir_all(&alone.dir);
    let _ = fs::remove_dir_all(&crowded.dir);
}

#[test]
fn rebuild_retains_no_copy_of_unrelated_family_rows() {
    let _completion_paths = crate::snapshots::ClaudeCompletionPathsForTest::enable();
    // Legacy reported-body proof/delivery; E2 publishes a request-owned literal instead.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let small = proven_families("witness-scope-small", 8);
    let large = proven_families("witness-scope-large", 32);
    let small_peak = rebuild_phase_peak(&small);
    let large_peak = rebuild_phase_peak(&large);
    let per_family = large_peak.saturating_sub(small_peak) / (32 - 8);
    let rows = &large.api.evidence[&family_root(31)];
    let (row_copy, _) = probe::measure(|| {
        probe::phase_begin();
        let copy = rows.clone();
        let peak = probe::phase_peak();
        drop(copy);
        peak
    });
    writeln!(
        std::io::stderr().lock(),
        "witness_reconstruct_scope: requests_per_family={REQUESTS_PER_FAMILY} rebuild_phase_peak_8={small_peak} rebuild_phase_peak_32={large_peak} per_unrelated_family={per_family} one_family_api_row_copy={row_copy} requested_bytes_not_RSS=true"
    )
    .unwrap();
    // Loaded rows, legacy owners and witness fingerprints still scale with the
    // join. A reconstructed family would also hold a copy of its API rows.
    assert!(
        per_family < row_copy,
        "per unrelated family {per_family} B >= one API-row copy {row_copy} B"
    );
    let _ = fs::remove_dir_all(&small.dir);
    let _ = fs::remove_dir_all(&large.dir);
}

/// Both arms start from the SAME N-family native evidence and complete index.
/// The BASE arm changes only the test-only row-retention control; it never
/// removes unrelated witnesses or replaces N-family state with one family.
#[test]
fn terminal_proven_rows_preserve_identical_family_state_with_lower_peak() {
    let _completion_paths = crate::snapshots::ClaudeCompletionPathsForTest::enable();
    // Legacy reported-body proof/delivery; E2 publishes a request-owned literal instead.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    const FAMILIES: usize = 16;
    let families = proven_families("terminal-proven-row-scope", FAMILIES);
    let mut pending_index = families.index.clone();
    let mut native_page = families.raw.clone();
    apply_claude_reported_usage_with_index(
        &mut native_page,
        &families.api,
        &families.trace,
        &mut pending_index,
        false,
        WINDOW,
    );
    assert_eq!(pending_index.claude_usage_family_pending.len(), FAMILIES);

    let run = |retain_all| {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                RETAIN_ALL_CLAUDE_PROVEN_ROWS_FOR_TEST.with(|flag| flag.set(self.0));
            }
        }
        let previous = RETAIN_ALL_CLAUDE_PROVEN_ROWS_FOR_TEST.with(|flag| flag.replace(retain_all));
        let _restore = Restore(previous);
        let mut index = pending_index.clone();
        let mut page = vec![families.raw[0].clone()];
        let (disposition, allocation) = probe::measure_caller_thread(|| {
            apply_claude_reported_usage_with_index(
                &mut page,
                &families.api,
                &families.trace,
                &mut index,
                true,
                WINDOW,
            )
        });
        assert_eq!(index.claude_usage_family_witnesses.len(), FAMILIES);
        assert_eq!(
            page[0].usage_accounting_contract.as_deref(),
            Some("session_exclusive_reported_usage:v1")
        );
        (
            serde_json::to_value(page).unwrap(),
            serde_json::to_value(index).unwrap(),
            disposition,
            allocation.requested_peak_with_overlap,
        )
    };
    let baseline = run(true);
    let candidate = run(false);
    assert_eq!(baseline.0, candidate.0, "same-input page body parity");
    assert_eq!(baseline.1, candidate.1, "entire N-family index, including all witnesses, pending, quarantine, accepted state and debt");
    assert_eq!(
        baseline.2, candidate.2,
        "authority, identity grouping and quarantine disposition parity"
    );
    assert!(
        candidate.3 < baseline.3,
        "candidate {} must retain less than BASE {} requested bytes",
        candidate.3,
        baseline.3
    );
    writeln!(std::io::stderr().lock(), "terminal_proven_row_scope: families={FAMILIES} requests_per_family={REQUESTS_PER_FAMILY} base_requested_peak={} candidate_requested_peak={} same_input_full_index_and_body_parity=true all_family_witnesses_retained=true requested_bytes_not_RSS=true", baseline.3, candidate.3).unwrap();
    let _ = fs::remove_dir_all(&families.dir);
}
