// Page-scoped witness reconstruction. Every finish loads telemetry for all
// witnessed families; only families with an item on the page are rebuilt.
// Synthetic, content-free fixtures. The allocation probe does not depend on
// the validated heap layout, so these assertions execute on every compiler.
use super::*;

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

#[test]
fn unrelated_witnessed_families_do_not_change_page_family_rebuild() {
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
