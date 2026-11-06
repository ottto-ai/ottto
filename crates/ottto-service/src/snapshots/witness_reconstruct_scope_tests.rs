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
/// paired API/trace rows, and the witnesses an older build stored for them
/// (an upgraded store). One fold rebuilds every family.
fn witnessed_families(name: &str, count: usize) -> Families {
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
        // Real paused-adoption input: the family keeps ordinary money, so the
        // reported-usage rebuild below runs on its body.
        let item = crate::snapshots::e2_pipeline_scan_fixture::parse_ordinary(
            &path,
            "2026-08-02T07:01:00Z",
            format!("source-{family}"),
        )
        .expect("parse family fixture")
        .remove(0);
        assert!(item.claude_money.is_none(), "ordinary money");
        if family == 0 {
            // Positive control: without the paused input, `e2` owns the money.
            let request_owned =
                parse_claude_code_jsonl_file(&path, "2026-08-02T07:01:00Z", "control".into())
                    .expect("parse family fixture")
                    .remove(0);
            assert!(request_owned.claude_money.is_some(), "E2 money");
        }
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
    for family in 0..count {
        assert!(index.install_stored_claude_family_witness_for_test(
            &family_root(family),
            &raw,
            &api,
            &trace
        ));
    }
    let mut seed = raw.clone();
    apply_claude_reported_usage_with_index(&mut seed, &api, &trace, &mut index);
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
    // Ordinary-money families (paused input) keep the reported-body rebuild.

    let alone = witnessed_families("witness-scope-alone", 1);
    let crowded = witnessed_families("witness-scope-crowded", 9);
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

/// How an idle (unread) family member's census record and index entry stand.
/// Every case but `none` stores an unverified record at revision `e`.
const IDLE_CASES: [&str; 5] = ["none", "verified", "unverified", "mismatch", "missing"];

/// Stage an idle member of `root`'s family: it is not in the page, so only
/// its own index entry can bind its unverified census record.
fn stage_idle_member(index: &mut ScanIndex, dir: &Path, root: &str, case: &str) {
    use crate::snapshots::claude_request_census::{
        claude_request_hash, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    };
    let key = local_index_key(&dir.join(root).join("subagents/agent-idle.jsonl"));
    if case != "missing" {
        let mut entry = manifest_index_entry(None);
        entry.source_file_fingerprint = hex64(if case == "mismatch" { 'f' } else { 'e' });
        if case == "unverified" {
            entry.set_unverified_deadline(1);
        }
        assert_eq!(entry.has_unverified_source(), case == "unverified");
        index.files.insert(key.clone(), entry);
    }
    if case != "none" {
        let record = ClaudeRequestCensusRecord::synthetic_for_test(
            &hex64('e'),
            1,
            ClaudeRequestCensusShape::Exact,
            vec![claude_request_hash("req_idle")],
        )
        .with_unverified_for_test(true);
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(&key, record);
    }
}

fn context_posture(item: &SnapshotItem) -> [Option<u64>; 4] {
    [
        item.first_turn_context_tokens,
        item.peak_context_fill_tokens,
        item.last_turn_context_tokens,
        item.compaction_count,
    ]
}

/// The page as the strict (pre-binding) gate leaves it: posture cleared and
/// withheld as unknown birth. Everything else must already be equal.
fn posture_withheld(items: &[SnapshotItem]) -> serde_json::Value {
    let items = items
        .iter()
        .cloned()
        .map(|mut item| {
            clear_claude_context_posture(&mut item);
            item.claude_file_birth_verdict = Some(ClaudeFileBirthVerdict::UnknownBirth);
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
            item
        })
        .collect::<Vec<_>>();
    serde_json::to_value(items).unwrap()
}

/// [money] An idle subagent whose own index entry is verified at its census
/// revision no longer clears its family's context posture. An unverified
/// entry, a fingerprint mismatch or no entry still clears it, and the cache
/// rows stay on the strict in-batch rule.
#[test]
fn idle_verified_member_keeps_family_context_posture() {
    let mut withheld = BTreeMap::new();
    for case in IDLE_CASES {
        let (dir, parent, mut items) = claude_account_family_fixture(true);
        let child_agent = "a4d1585d310070d0f";
        let api_rows = (1..=5)
            .map(|n| {
                complete_api_row(
                    &parent,
                    &format!("req_{n}"),
                    n,
                    10,
                    if n == 5 { 1 } else { 10 },
                    0,
                )
            })
            .collect::<Vec<_>>();
        let trace_rows = (1..=5)
            .map(|n| {
                complete_trace_row(
                    &parent,
                    &format!("req_{n}"),
                    if n == 5 { child_agent } else { "" },
                )
            })
            .collect::<Vec<_>>();
        let api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(parent.clone(), api_rows)]),
            health: Default::default(),
        };
        let trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(parent.clone(), trace_rows)]),
            ..Default::default()
        };
        let mut index =
            crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::default());
        for path in [
            dir.join(format!("{parent}.jsonl")),
            dir.join(&parent)
                .join(format!("subagents/agent-{child_agent}.jsonl")),
        ] {
            index
                .files
                .insert(local_index_key(&path), manifest_index_entry(None));
        }
        stage_idle_member(&mut index, &dir, &parent, case);

        let disposition = apply_claude_reported_usage_with_index(
            &mut items,
            &api_report,
            &trace_report,
            &mut index,
        );

        let child = &items[1];
        let kept = matches!(case, "none" | "verified");
        assert_eq!(
            context_posture(child),
            if kept {
                [Some(10), Some(10), Some(10), Some(0)]
            } else {
                [None; 4]
            },
            "{case}"
        );
        assert_eq!(
            child.claude_file_birth_verdict(),
            Some(if kept {
                ClaudeFileBirthVerdict::Admitted
            } else {
                ClaudeFileBirthVerdict::UnknownBirth
            }),
            "{case}"
        );
        // Cache rows keep the strict rule: only the unpoisoned family ships them.
        assert_eq!(child.cache_observations.is_some(), case == "none", "{case}");
        assert!(
            disposition.quarantined_source_session_ids.is_empty(),
            "{case}"
        );
        if matches!(case, "verified" | "unverified") {
            withheld.insert(case, posture_withheld(&items));
        }
        let _ = fs::remove_dir_all(dir);
    }
    // Same index fingerprints, only the entry's verification differs: the
    // bodies are equal except the posture fields.
    assert_eq!(withheld["verified"], withheld["unverified"]);
}

/// [money] On an ordinary-money (excluded) witnessed family, the posture
/// binding alone never releases the reported-usage rebuild or the demotion
/// hold: usage, quarantine and bodies match the strict gate exactly.
#[test]
fn idle_verified_member_leaves_usage_rebuild_and_hold_strict() {
    let mut outcomes = BTreeMap::new();
    for case in ["none", "verified", "unverified"] {
        let families = witnessed_families(&format!("census-posture-usage-{case}"), 1);
        let root = family_root(0);
        let mut index = families.index.clone();
        stage_idle_member(&mut index, &families.dir, &root, case);
        let mut page = vec![families.raw[0].clone()];
        let disposition = apply_claude_reported_usage_with_index(
            &mut page,
            &families.api,
            &families.trace,
            &mut index,
        );
        let rebuilt = case == "none";
        assert_eq!(
            page[0].usage_accounting_contract.as_deref(),
            rebuilt.then_some("session_exclusive_reported_usage:v1"),
            "{case}"
        );
        assert_eq!(
            disposition
                .quarantined_source_session_ids
                .contains(&page[0].source_session_id),
            !rebuilt,
            "{case}"
        );
        assert_eq!(
            index.claude_usage_authority_quarantine.contains_key(&root),
            !rebuilt,
            "{case}"
        );
        let quarantine = index
            .claude_usage_authority_quarantine
            .iter()
            .map(|(root, record)| {
                (
                    root.clone(),
                    (
                        record.proven_witness_fingerprint.clone(),
                        record.member_source_file_fingerprints.clone(),
                        record.failed_reconstruction_count,
                        record.disposition,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        outcomes.insert(
            case,
            (
                posture_withheld(&page),
                disposition.quarantined_source_session_ids,
                quarantine,
            ),
        );
        let _ = fs::remove_dir_all(&families.dir);
    }
    assert_eq!(outcomes["verified"], outcomes["unverified"]);
}
