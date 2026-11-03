//! A forked subagent repeats its parent's last response as its first line.
//! Inside one family that request counts once, at the root (`decide_family`).

use super::*;
use crate::snapshots::claude_history_upgrade::with_max_gated_claude_revision;
use crate::snapshots::e2_pipeline_scan_fixture::{self as fixture, E2ScanFixture};
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, scan_money};
use crate::snapshots::{
    apply_claude_code_line, apply_upload_policy, finalize_scan_after_policy, rfc3339_unix_seconds,
    SnapshotAccumulator, SnapshotSource, SnapshotUploadPolicy, SourceScanResult,
    MAX_BACKFILL_FILES_PER_SOURCE,
};
use crate::test_scratch::ScratchDir;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

const ROOT: &str = "d0000000-0000-4000-8000-00000000000d";
const FORKS: [&str; 3] = ["agent-a1", "agent-a2", "agent-a3"];
const BIRTH: &str = "2026-06-01T07:00:00Z";

fn line(id: &str, clock: &str, input: u64) -> Value {
    json!({"type":"assistant","version":"2.1.229","sessionId":ROOT,"timestamp":clock,
        "requestId":id,"message":{"id":format!("msg-{id}"),"model":"claude-haiku-4-5",
        "usage":{"input_tokens":input,"output_tokens":1}}})
}
/// Two root requests; the second is the response that starts the forks.
fn root_lines() -> Vec<Value> {
    vec![
        line("root-1", "2026-06-01T07:00:10Z", 10),
        line("root-fork", "2026-06-01T07:00:20Z", 20),
    ]
}
/// A fork: `copied` repeats the parent response first, then `own` requests.
fn fork_lines(agent: &str, copied: bool, own: u64) -> Vec<Value> {
    let copy = copied.then(|| root_lines().remove(1));
    copy.into_iter()
        .chain((0..own).map(|n| {
            let clock = format!("2026-06-01T07:01:{:02}Z", 10 + n);
            line(&format!("{agent}-{n}"), &clock, 30)
        }))
        .collect()
}
fn fork_path(project: &Path, agent: &str) -> PathBuf {
    project
        .join(ROOT)
        .join("subagents")
        .join(format!("{agent}.jsonl"))
}
fn write(path: &Path, lines: &[Value], modified: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = lines.iter().map(|l| format!("{l}\n")).collect::<String>();
    fs::write(path, text).unwrap();
    let at = std::time::Duration::from_secs(rfc3339_unix_seconds(modified).unwrap());
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(UNIX_EPOCH + at).unwrap();
}

/// One page of the family, parsed as the scan does: (counted, removed, held)
/// requests per body after the page's copy decision.
fn decide(
    dir: &Path,
    root: bool,
    forks: &[(&str, Vec<Value>)],
) -> BTreeMap<String, (u64, u64, bool)> {
    let index = ScanIndex::default();
    let root_path = dir.join(format!("{ROOT}.jsonl"));
    let files = root.then(|| (root_path, root_lines())).into_iter().chain(
        forks
            .iter()
            .map(|(agent, lines)| (fork_path(dir, agent), lines.clone())),
    );
    let mut items = files
        .map(|(path, lines)| {
            write(&path, &lines, BIRTH);
            let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
            accumulator.claude_file_birth = ClaudeFileBirth::observe(&path, None);
            let birth = rfc3339_unix_nanos(BIRTH).unwrap();
            accumulator.claude_file_birth.set_birth_for_test(birth);
            for value in &lines {
                apply_claude_code_line(value, &mut accumulator);
            }
            let twins = Default::default();
            let context = ReadContext {
                index: &index,
                path: &path,
                twins: &twins,
            };
            accumulator.finalize_claude_responses_e2(Some(context));
            accumulator
                .into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None)
                .remove(0)
        })
        .collect::<Vec<_>>();
    decide_page_copies(&mut items, &index, None);
    items
        .iter()
        .map(|item| {
            let entity = &item.claude_money.as_deref().unwrap().entity;
            let counted = entity.totals().1;
            let decided = (counted, entity.removed_requests, entity.held);
            (item.source_session_id.clone(), decided)
        })
        .collect()
}

/// [regress] Root plus three forks whose first line repeats the root's last
/// response: that request counts once, in the root; each fork keeps its own.
#[test]
fn forked_subagents_count_the_copied_parent_response_once_in_the_root() {
    let dir = ScratchDir::new("e2-family-duplicate-page");
    let forks = FORKS.map(|agent| (agent, fork_lines(agent, true, 2)));
    take_diag();
    let bodies = decide(&dir, true, &forks);
    assert_eq!(bodies[ROOT], (2, 0, false));
    for agent in FORKS {
        assert_eq!(bodies[&format!("{ROOT}_{agent}")], (2, 1, false), "{agent}");
    }
    assert_eq!(take_diag().get("family_duplicate_removed"), Some(&3));
}

/// [regress] A lone subagent is unchanged: with no parent copy, and with a
/// copy but no root to prove it (absent root: the subagent keeps the id).
#[test]
fn lone_subagent_requests_stay_counted() {
    for (root, copied, counted) in [(true, false, 2), (false, true, 3)] {
        let dir = ScratchDir::new("e2-family-duplicate-lone");
        let bodies = decide(
            &dir,
            root,
            &[("agent-lone", fork_lines("agent-lone", copied, 2))],
        );
        assert_eq!(bodies[&format!("{ROOT}_agent-lone")], (counted, 0, false));
    }
}

/// [money] Cold Full equals the sampled route that reads the family, then
/// Tails the grown forks against the root's census record. The family's
/// totals differ from every body counted alone only by the three copies.
#[test]
fn family_duplicate_cold_full_matches_tail_route() {
    with_max_gated_claude_revision(3, || {
        let home = ScratchDir::canonical("e2-family-duplicate-money");
        let (project, support) = (home.join("project"), home.join("support"));
        fixture::write_exclusions(&support, &[]);
        let root = project.join(format!("{ROOT}.jsonl"));
        write(&root, &root_lines(), "2026-06-15T00:00:00Z");
        let grow = |own, modified| {
            for agent in FORKS {
                write(
                    &fork_path(&project, agent),
                    &fork_lines(agent, true, own),
                    modified,
                );
            }
        };
        grow(1, "2026-06-15T00:00:00Z");
        let births = BTreeMap::from([(root, rfc3339_unix_nanos(BIRTH).unwrap())]);
        let scan = |scanner: &E2ScanFixture, mut index: ScanIndex, sampled| {
            index.activate_effective_upload_body_witness_revision(3);
            index.adopt_effective_upload_body_witness_revision_monotonically();
            index.activate_upload_context("family-duplicate-context".into());
            index.load_claude_reemission_exclusions(&support);
            let roots = std::slice::from_ref(&project);
            let limit = MAX_BACKFILL_FILES_PER_SOURCE;
            let (mut index, mut scan, _) =
                scanner.scan(roots, &support, index, limit, sampled, &births, &[]);
            let _ = crate::snapshot_sync::apply_claude_local_evidence_to_scan(
                &support, &mut scan, &mut index,
            );
            let policy = SnapshotUploadPolicy::default();
            apply_upload_policy(SnapshotSource::ClaudeCode, &mut scan.snapshots, policy);
            finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
            let accepted = scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone());
            index.record_accepted_snapshot_fingerprints(&accepted.collect());
            let acks = fixture::exact_acks_for_test(&scan.snapshots);
            fixture::accept_upload_context_acks_for_test(&mut index, &scan.snapshots, &acks);
            (index, scan)
        };
        let by_session = |scan: &SourceScanResult| {
            scan.snapshots
                .iter()
                .map(|s| (s.source_session_id.clone(), s.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        let sampled = E2ScanFixture::default();
        let (index, first) = scan(&sampled, ScanIndex::default(), true);
        grow(2, "2026-06-16T00:00:00Z");
        let (index, mut tail) = scan(&sampled, index, true);
        let mut delivered = by_session(&first);
        delivered.extend(by_session(&tail));
        tail.snapshots = delivered.into_values().collect();
        let (cold_index, mut cold) = scan(&E2ScanFixture::default(), ScanIndex::default(), false);
        cold.snapshots = by_session(&cold).into_values().collect();
        let (counted, removed) = cold.snapshots.iter().fold((0, 0), |(c, r), s| {
            (
                c + s.request_count,
                r + s.removed_request_count.unwrap_or(0),
            )
        });
        assert_eq!((counted, removed), (2 + 3 * 2, 3), "each copy counted once");
        money_oracle::assert_equivalent(
            &scan_money(SnapshotSource::ClaudeCode, &cold_index, &cold),
            &scan_money(SnapshotSource::ClaudeCode, &index, &tail),
        );
    });
}
