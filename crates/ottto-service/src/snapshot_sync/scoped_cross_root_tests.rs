// The page's Claude evidence scope on the real pipeline: side files are read
// for the page's own roots, their named fork parents and the sessions whose
// transcripts hold a page request. The scope places money and accounts as a
// pass reading every side-file root does (the reference root set).
use super::state_v2_money_tests::tagged_api;
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle::assert_equivalent, RouteResult,
};

const FORK: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const STRAY: &str = "9338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const EARLY: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const LATER: &str = "7338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const ORG_A: &str = "11111111-1111-4111-8111-111111111111";
const ORG_B: &str = "22222222-2222-4222-8222-222222222222";
/// Every side-file root of the fork corpus.
const SIDE_ROOTS: [&str; 3] = [ROOT, FORK, COPY];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    ForkInAnotherDir,
    MovedCwd,
    HelperMove,
    V1ForkAtTerminal,
    /// Compared with the same corpus without the stray session: the reference
    /// would read it, the scope cannot see it (expected to differ from it).
    UnregisteredDir,
    /// Expected to differ from the reference, which names no holder.
    UnhealthyOwner,
}

fn marker(session: &str, org: &str) -> String {
    json!({"type":"attachment", "sessionId":session,
        "attachment":{"type":"credential_org","organizationUuid":org}})
    .to_string()
        + "\n"
}

fn write_in(c: &mut Corpus, dir: &Path, relative: &str, contents: &str, birth: &str) {
    let path = dir.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, contents).unwrap();
    c.births.insert(path, nanos(birth));
}

/// ROOT: a marker on org A, two accounts with a switch (a, then b), a side
/// call on b. FORK names ROOT in its fork line, copies `r1` and adds its own
/// request under a marker on org B. COPY is an evidence gap.
fn fork_corpus(arm: Arm, name: &str) -> (Corpus, Vec<PathBuf>) {
    let mut c = Corpus::new(name);
    let projects = c.root.clone();
    let other = c.base.join("projects-other");
    std::fs::create_dir_all(&other).unwrap();
    let (root_dir, fork_dir) = match arm {
        Arm::MovedCwd | Arm::HelperMove => (projects.join("project-a"), projects.join("project-b")),
        _ => (projects.clone(), other.clone()),
    };
    let account = |name: char| name.to_string().repeat(64);
    let mut rows = vec![
        tagged_api("r1", 10, Some(&account('a'))),
        tagged_api("r-account-a", 40, Some(&account('a'))),
        tagged_api("r-account-b", 50, Some(&account('b'))),
        tagged_api("r-side", 5, Some(&account('b'))),
    ];
    let mut traces = vec![
        trace("r1", ""),
        trace("r-account-a", ""),
        trace("r-account-b", ""),
        trace("r-side", ""),
    ];
    if arm == Arm::HelperMove {
        // The helper's transcript now sits under another project folder.
        let helper = format!("{ROOT}/subagents/agent-000.jsonl");
        write_in(
            &mut c,
            &fork_dir,
            &helper,
            &line(ROOT, "helper", AT, 20),
            AT,
        );
        rows.push(tagged_api("helper", 20, Some(&account('a'))));
        traces.push(trace("helper", "000"));
    }
    let text = marker(ROOT, ORG_A)
        + &line(ROOT, "r1", AT, 10)
        + &line(ROOT, "r-account-a", AT, 40)
        + &line(ROOT, "r-account-b", AT, 50);
    write_in(
        &mut c,
        &root_dir,
        &format!("{ROOT}.jsonl"),
        &text,
        "2026-08-02T07:00:00Z",
    );
    c.evidence(&rows, &traces);
    let text = fork_ref(FORK, ROOT)
        + &marker(FORK, ORG_B)
        + &line(FORK, "r1", AT, 10)
        + &line(FORK, "f-own", "2026-08-02T07:04:00Z", 30);
    write_in(
        &mut c,
        &fork_dir,
        &format!("{FORK}.jsonl"),
        &text,
        "2026-08-02T07:03:00Z",
    );
    c.evidence_for(
        FORK,
        &[api_for(FORK, "f-own", 30, 300)],
        &[trace_for(FORK, "f-own", "")],
    );
    write_in(
        &mut c,
        &projects,
        &format!("{COPY}.jsonl"),
        &line(COPY, "gap-1", AT, 6),
        AT,
    );
    c.evidence_for(COPY, &[api_for(COPY, "gap-1", 6, 60)], &[]);
    if arm == Arm::UnregisteredDir {
        // A session in a folder no scan lists, reporting FORK's request.
        let stray = c.base.join("unregistered");
        let text = line(STRAY, "f-own", AT, 30) + &line(STRAY, "s-own", AT, 8);
        write_in(&mut c, &stray, &format!("{STRAY}.jsonl"), &text, AT);
        c.evidence_for(
            STRAY,
            &[
                api_for(STRAY, "f-own", 30, 300),
                api_for(STRAY, "s-own", 8, 80),
            ],
            &[trace_for(STRAY, "s-own", "")],
        );
    }
    let roots = if fork_dir.starts_with(&projects) {
        vec![projects]
    } else {
        vec![projects, other]
    };
    (c, roots)
}

/// EARLY (no side files, a marker on org A) and LATER (born later, a
/// malformed API file) both hold `held`.
fn held_corpus(name: &str) -> (Corpus, Vec<PathBuf>) {
    let mut c = Corpus::new(name);
    let text = marker(EARLY, ORG_A)
        + &line(EARLY, "held", AT, 10)
        + &line(EARLY, "early-own", "2026-08-02T07:00:20Z", 10);
    c.write_at(&format!("{EARLY}.jsonl"), &text, "2026-08-02T07:00:00Z");
    let text = line(LATER, "held", AT, 10) + &line(LATER, "later-own", "2026-08-02T07:05:10Z", 10);
    c.write_at(&format!("{LATER}.jsonl"), &text, "2026-08-02T07:05:00Z");
    c.evidence_for(
        LATER,
        &[
            api_for(LATER, "held", 10, 100),
            api_for(LATER, "later-own", 10, 100),
        ],
        &[
            trace_for(LATER, "held", ""),
            trace_for(LATER, "later-own", ""),
        ],
    );
    append(
        &c.support
            .join("local-otel/claude-code-effort")
            .join(format!("{:x}.jsonl", Sha256::digest(LATER.as_bytes()))),
        "{malformed\n",
    );
    let roots = vec![c.root.clone()];
    (c, roots)
}

fn page_over(
    c: &Corpus,
    roots: &[PathBuf],
    scanner: &E2ScanFixture,
    index: ScanIndex,
    limit: usize,
) -> Page {
    let mut index = scanner.routed(index, &c.base);
    index.activate_upload_context("e2-synthetic-destination".into());
    index.activate_effective_upload_body_witness_revision(3);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    index.load_claude_reemission_exclusions(&c.support);
    let committed = index.clone();
    let (index, scan, modes) = scanner.scan(roots, &c.support, index, limit, true, &c.births, &[]);
    Page {
        cache: scanner.cache.clone(),
        committed,
        index,
        scan,
        modes,
        disposition: Default::default(),
        released: Default::default(),
        unhealthy: Default::default(),
        stats: Default::default(),
        delivered: None,
        upload_policy: SnapshotUploadPolicy::default(),
    }
}

#[derive(Default)]
struct Run {
    sent: Vec<RouteResult>,
    enriched: Vec<SnapshotItem>,
    finished: Vec<SnapshotItem>,
    terminal: bool,
}

/// Pages of `limit` files until a terminal pass. `reference`: every pass
/// reads these roots too and lets each answer everything, with no holder.
fn run(c: &Corpus, roots: &[PathBuf], reference: Option<&[&str]>, limit: usize) -> Run {
    let scanner = E2ScanFixture::with_identity_capture(true);
    let mut index = ScanIndex::default();
    let mut done = Run::default();
    for _ in 0..12 {
        let mut page = page_over(c, roots, &scanner, index, limit);
        let terminal = page.scan.census_complete;
        crate::snapshot_sync::REFERENCE_ROOTS.with(|slot| {
            *slot.borrow_mut() =
                reference.map(|roots| roots.iter().map(|root| (*root).to_owned()).collect());
        });
        page.enrich(c);
        crate::snapshot_sync::REFERENCE_ROOTS.with(|slot| *slot.borrow_mut() = None);
        if !page.scan.snapshots.is_empty() {
            done.sent.push(sent_money(&page));
            done.enriched.extend(page.scan.snapshots.iter().cloned());
        }
        page.finish();
        done.finished.extend(page.scan.snapshots.iter().cloned());
        index = c.reload(&mut page.index);
        if terminal {
            done.terminal = true;
            break;
        }
    }
    done
}

fn assert_same(scope: &Run, other: &Run, label: &str) {
    assert!(
        scope.terminal && other.terminal,
        "{label}: a terminal pass ran"
    );
    assert!(!scope.sent.is_empty(), "{label}: pages were sent");
    assert_eq!(scope.sent.len(), other.sent.len(), "{label}: page count");
    for (scope, other) in scope.sent.iter().zip(&other.sent) {
        assert_equivalent(scope, other);
    }
}

/// Requests `session` placed on org A.
fn org_a_requests(done: &Run, session: &str) -> u64 {
    let org = ottto_core::billing_identity_hash("anthropic", "organization", ORG_A).unwrap();
    let item = done
        .enriched
        .iter()
        .find(|item| item.source_session_id == session)
        .expect("the session publishes its requests");
    assert_eq!(item.request_count, 2, "both requests count here");
    org_shares(item).get(&org).copied().unwrap_or(0)
}

fn arm_case(arm: Arm) {
    let label = format!("{arm:?}");
    if arm == Arm::UnhealthyOwner {
        let shares = |reference: Option<&[&str]>, name: &str| {
            let (c, roots) = held_corpus(name);
            org_a_requests(&run(&c, &roots, reference, 100), EARLY)
        };
        assert_eq!(
            shares(None, "scoped-unhealthy"),
            1,
            "a request another session holds, whose pair is unreadable, is Unknown"
        );
        assert_eq!(
            shares(Some(&[LATER][..]), "scoped-unhealthy-reference"),
            2,
            "expected to differ: the reference names no holder"
        );
        // Mutation control: the scope without its holder must fail the arm.
        let mutated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(shares(Some(&[][..]), "scoped-unhealthy-mutated"), 1);
        }));
        assert!(
            mutated.is_err(),
            "dropping the holder root changes the answer"
        );
        return;
    }
    let (c, roots) = fork_corpus(arm, &format!("scoped-{label}"));
    let scope = run(&c, &roots, None, 1);
    if arm == Arm::UnregisteredDir {
        let (c, roots) = fork_corpus(Arm::ForkInAnotherDir, "scoped-unregistered-absent");
        assert_same(&scope, &run(&c, &roots, None, 1), &label);
        return;
    }
    let (r, roots) = fork_corpus(arm, &format!("scoped-{label}-reference"));
    assert_same(&scope, &run(&r, &roots, Some(&SIDE_ROOTS[..]), 1), &label);
    if arm != Arm::ForkInAnotherDir {
        return;
    }
    // Positive control: two accounts with a switch, a side call, a gap.
    let rows = || {
        scope.finished.iter().flat_map(|item| {
            item.model_usage.iter().chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage),
            )
        })
    };
    let accounts = rows()
        .flat_map(|row| {
            row.account_identifier_hash.iter().chain(
                row.identity_parts
                    .iter()
                    .flatten()
                    .filter_map(|part| part.account_identifier_hash.as_ref()),
            )
        })
        .collect::<BTreeSet<_>>();
    assert!(accounts.len() >= 2, "positive control: two accounts placed");
    assert!(
        rows().any(|row| row.account_identifier_hash.is_none()
            && row.evidence_ref.is_none()
            && row.identity_parts.is_none()),
        "positive control: an evidence gap"
    );
    assert!(
        scope
            .finished
            .iter()
            .any(|item| item.source_session_id == ROOT && item.request_count == 4),
        "positive control: three transcript requests and the side call"
    );
}

/// [behaviour] The page's evidence scope places money and accounts as a pass
/// over every side-file root does: a fork in another config folder, a moved
/// working folder, a moved helper transcript and a v1 fork child at the
/// terminal. A session in an unlisted folder has no effect. A request another
/// session holds, whose pair is unreadable, is Unknown.
#[test]
fn scoped_evidence_places_like_every_side_file_root() {
    for arm in [
        Arm::ForkInAnotherDir,
        Arm::MovedCwd,
        Arm::HelperMove,
        Arm::V1ForkAtTerminal,
        Arm::UnregisteredDir,
        Arm::UnhealthyOwner,
    ] {
        if arm == Arm::V1ForkAtTerminal {
            arm_case(arm);
        } else {
            with_e2(|| arm_case(arm));
        }
    }
}
