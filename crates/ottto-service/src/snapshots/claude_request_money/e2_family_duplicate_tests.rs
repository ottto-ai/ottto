//! A forked subagent repeats its parent's last response as its first line.
//! Inside one family that request counts once, at the root (`decide_family`).

use super::tests::{line, parse, ROOT};
use super::*;
use crate::snapshots::claude_history_upgrade::with_max_gated_claude_revision;
use crate::snapshots::claude_request_census::{
    ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};
use crate::snapshots::e2_pipeline_scan_fixture::{self as fixture, E2ScanFixture};
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, scan_money};
use crate::snapshots::{
    apply_upload_policy, finalize_scan_after_policy, rfc3339_unix_seconds, SnapshotSource,
    SnapshotUploadPolicy, SourceScanResult, MAX_BACKFILL_FILES_PER_SOURCE,
};
use crate::test_scratch::ScratchDir;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

const FORKS: [&str; 3] = ["agent-a1", "agent-a2", "agent-a3"];
const BIRTH: &str = "2026-08-02T07:00:00Z";
const MODIFIED: &str = "2026-08-02T07:30:00Z";

/// Two root requests; the second is the response that starts the forks.
fn root_lines() -> Vec<Value> {
    vec![
        line("root-1", "2026-08-02T07:00:10Z", 10),
        line("root-fork", "2026-08-02T07:00:20Z", 20),
    ]
}
/// A fork: `copied` repeats the parent response first, then `own` requests.
fn fork_lines(agent: &str, copied: bool, own: u64) -> Vec<Value> {
    let copy = copied.then(|| root_lines().remove(1));
    copy.into_iter()
        .chain((0..own).map(|n| {
            let clock = format!("2026-08-02T07:01:{:02}Z", 10 + n);
            line(&format!("{agent}-{n}"), &clock, 30)
        }))
        .collect()
}
fn root_path(project: &Path) -> PathBuf {
    project.join(format!("{ROOT}.jsonl"))
}
fn fork_path(project: &Path, agent: &str) -> PathBuf {
    let subagents = project.join(ROOT).join("subagents");
    subagents.join(format!("{agent}.jsonl"))
}
fn write(path: &Path, lines: &[Value], modified: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = lines.iter().map(|l| format!("{l}\n")).collect::<String>();
    fs::write(path, text).unwrap();
    let at = std::time::Duration::from_secs(rfc3339_unix_seconds(modified).unwrap());
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(UNIX_EPOCH + at).unwrap();
}

/// One page, parsed as the scan does, then its copy decision:
/// (counted, removed, held) requests per body.
fn page(index: &ScanIndex, files: &[(PathBuf, Vec<Value>)]) -> BTreeMap<String, (u64, u64, bool)> {
    let birth = rfc3339_unix_nanos(BIRTH);
    let mut items = files
        .iter()
        .map(|(path, lines)| {
            write(path, lines, MODIFIED);
            parse(path, birth, index, lines)
        })
        .collect::<Vec<_>>();
    decide_page_copies(&mut items, index, None);
    items
        .iter()
        .map(|item| {
            let entity = &item.claude_money.as_deref().unwrap().entity;
            let decided = (entity.totals().1, entity.removed_requests, entity.held);
            (item.source_session_id.clone(), decided)
        })
        .collect()
}
/// An index whose census record of the root holds the root's requests:
/// `modified` other than the file's makes it stale (root not read yet).
fn root_census(project: &Path, modified: Option<u64>) -> ScanIndex {
    let root = root_path(project);
    write(&root, &root_lines(), MODIFIED);
    let key = local_index_key(&root);
    let fingerprint = "a".repeat(64);
    let mut index = ScanIndex::default();
    let entry = json!({"size_bytes":1,"modified_unix_seconds":1,
        "source_file_fingerprint":fingerprint});
    index
        .files
        .insert(key.clone(), serde_json::from_value(entry).unwrap());
    let mut hashes = ["root-1", "root-fork"].map(claude_request_hash).to_vec();
    hashes.sort_unstable();
    let shape = ClaudeRequestCensusShape::Exact;
    let record = ClaudeRequestCensusRecord::synthetic_for_test(&fingerprint, 1, shape, hashes);
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, record.with_modified_for_test(modified));
    index
}

/// [regress] Root plus three forks whose first line repeats the root's last
/// response: that request counts once, in the root; each fork keeps its own.
#[test]
fn forked_subagents_count_the_copied_parent_response_once_in_the_root() {
    let dir = ScratchDir::new("e2-family-duplicate-page");
    let mut files = vec![(root_path(&dir), root_lines())];
    files.extend(FORKS.map(|agent| (fork_path(&dir, agent), fork_lines(agent, true, 2))));
    let bodies = page(&ScanIndex::default(), &files);
    assert_eq!(bodies[ROOT], (2, 0, false));
    for agent in FORKS {
        assert_eq!(bodies[&format!("{ROOT}_{agent}")], (2, 1, false), "{agent}");
    }
}

/// [regress] A root not read at its current revision holds nothing: the fork
/// counts its copy for now, and its next page, with the root's census
/// current, removes it.
#[test]
fn unread_root_leaves_the_copy_counted_until_its_census_is_current() {
    let dir = ScratchDir::new("e2-family-duplicate-unread");
    let fork = [(fork_path(&dir, "agent-a1"), fork_lines("agent-a1", true, 2))];
    let session = format!("{ROOT}_agent-a1");
    take_diag();
    let stale = page(&root_census(&dir, Some(1)), &fork);
    assert_eq!(stale[&session], (3, 0, false), "counted, not held");
    // `parse` decides each file alone, then the page decides again.
    assert_eq!(take_diag().get("family_copy_deferred"), Some(&2));
    let current = page(&root_census(&dir, None), &fork);
    assert_eq!(current[&session], (2, 1, false));
}

/// [control] A lone subagent is unchanged: with no parent copy, and with a
/// copy but no root to prove it (absent root: the subagent keeps the id).
#[test]
fn lone_subagent_requests_stay_counted() {
    for (root, copied, counted) in [(true, false, 2), (false, true, 3)] {
        let dir = ScratchDir::new("e2-family-duplicate-lone");
        let lone = (
            fork_path(&dir, "agent-lone"),
            fork_lines("agent-lone", copied, 2),
        );
        let files = root
            .then(|| (root_path(&dir), root_lines()))
            .into_iter()
            .chain([lone])
            .collect::<Vec<_>>();
        let bodies = page(&ScanIndex::default(), &files);
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
        let root = root_path(&project);
        write(&root, &root_lines(), MODIFIED);
        let grow = |own, modified| {
            for agent in FORKS {
                let lines = fork_lines(agent, true, own);
                write(&fork_path(&project, agent), &lines, modified);
            }
        };
        grow(1, MODIFIED);
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
        grow(2, "2026-08-02T07:40:00Z");
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
