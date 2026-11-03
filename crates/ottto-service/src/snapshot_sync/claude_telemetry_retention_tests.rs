// Claude telemetry retention on the real e2 pipeline fixture: a session's
// API + trace pair is deleted only when no transcript, index or census entry,
// named session, held state or copied request reads it; every surviving body
// is unchanged.
use super::state_v2_money_tests::{routed, tagged_api};
use super::*;
use crate::snapshots::e2_pipeline_scan_fixture::{
    commit_tail_head_for_test, hold_claude_account_for_test,
};
use crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent;
use std::collections::BTreeSet;

const GONE: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const COPIED: &str = "7338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const HALF: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const NAMED: &str = "9338a80a-f36e-4cbc-a5bb-50fc66430ba5";
/// The candidate of a dependency row.
const HELD: &str = "a338a80a-f36e-4cbc-a5bb-50fc66430ba5";

fn member(c: &Corpus, dir: &str, session: &str) -> PathBuf {
    c.support
        .join("local-otel")
        .join(dir)
        .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())))
}

/// Which of a session's (API, trace) members exist.
fn members(c: &Corpus, session: &str) -> (bool, bool) {
    (
        member(c, "claude-code-effort", session).exists(),
        member(c, "claude-code-trace-ownership", session).exists(),
    )
}

fn now_ms() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap() * 1000
}

fn key(c: &Corpus, session: &str) -> String {
    c.root
        .join(format!("{session}.jsonl"))
        .to_string_lossy()
        .into_owned()
}

/// What a complete walk over the corpus lists: every transcript with its mtime.
fn listing(c: &Corpus) -> BTreeMap<String, Option<u64>> {
    fn list(dir: &Path, listed: &mut BTreeMap<String, Option<u64>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                list(&path, listed);
            } else if path.extension().is_some_and(|ext| ext == "jsonl") {
                let mtime = std::fs::metadata(&path)
                    .unwrap()
                    .modified()
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                listed.insert(path.to_string_lossy().into_owned(), Some(mtime));
            }
        }
    }
    let mut listed = BTreeMap::new();
    list(&c.root, &mut listed);
    listed
}

/// A new process whose complete walk, begun at `started_at_ms`, listed `listed`.
fn roster(started_at_ms: u64, listed: BTreeMap<String, Option<u64>>) {
    crate::snapshots::money_freshness::set_roster_for_test(
        SnapshotSource::ClaudeCode,
        Some((started_at_ms, listed)),
    );
}

fn walked(c: &Corpus, started_at_ms: u64) {
    roster(started_at_ms, listing(c));
}

fn retire_with(c: &Corpus, index: &ScanIndex, removed: &BTreeSet<String>, named: &[String]) {
    crate::snapshots::claude_telemetry_retention::retire_claude_telemetry(
        &c.support,
        index,
        std::slice::from_ref(&c.root),
        removed,
        named,
    );
}

fn retire(c: &Corpus, index: &ScanIndex) {
    retire_with(c, index, &BTreeSet::new(), &[NAMED.to_string()]);
}

/// ROOT and COPY have transcripts; COPY copied request g1 of COPIED. GONE,
/// COPIED, NAMED and HALF (API member only) have none.
fn corpus(name: &str) -> (Corpus, Page) {
    let mut c = Corpus::new(name);
    c.root(
        ROOT,
        &(line(ROOT, "r0", AT, 11) + &line(ROOT, "r1", AT, 12)),
    );
    c.root(COPY, &line(COPY, "g1", AT, 13));
    c.evidence(
        &[api("r0", 11, 100), api("r1", 12, 200)],
        &[trace("r0", ""), trace("r1", "")],
    );
    for (session, request, tokens) in [(COPIED, "g1", 13), (GONE, "g2", 14), (NAMED, "g3", 15)] {
        c.evidence_for(
            session,
            &[api_for(session, request, tokens, tokens * 100)],
            &[trace_for(session, request, "")],
        );
    }
    c.evidence_for(HALF, &[api_for(HALF, "g4", 16, 1600)], &[]);
    std::fs::remove_file(member(&c, "claude-code-trace-ownership", HALF)).unwrap();
    let scanner = E2ScanFixture::capturing_identity();
    let mut warm = ready(&c, &scanner, ScanIndex::default(), 100, true);
    warm.finish();
    (c, warm)
}

fn cold(c: &Corpus) -> Page {
    let mut page = c.raw(
        &E2ScanFixture::capturing_identity(),
        ScanIndex::default(),
        100,
        true,
        &[],
    );
    page.enrich(c);
    page.finish();
    page
}

/// [money] Retention deletes exactly the unread pairs (one a half pair) and
/// keeps the transcript's, the copied and the named ones; a cold read of every
/// surviving session then equals the arm without retention (money oracle).
#[test]
fn telemetry_retention_equality_oracle() {
    with_e2(|| {
        let (c, warm) = corpus("telemetry-retention-oracle");
        let before = cold(&c);
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(
            [ROOT, COPIED, NAMED, GONE, HALF].map(|session| members(&c, session)),
            [
                (true, true),
                (true, true),
                (true, true),
                (false, false),
                (false, false)
            ],
        );
        let after = cold(&c);
        assert_equivalent(
            &routed(&before, before.upload_policy),
            &routed(&after, after.upload_policy),
        );
    });
}

/// [money] Positive control: one session on two accounts (a switch mid
/// session, then back) with identity-tagged rows, and an unread pair. After
/// retention deletes the unread pair, a cold read and a restart from the
/// saved index equal the reads with the pair present, and so does a reread
/// after the survivor grows.
#[test]
fn telemetry_retention_positive_control_cold_restart_and_append() {
    with_e2(|| {
        let mut c = Corpus::new("telemetry-retention-positive");
        let marker = serde_json::json!({"type":"attachment", "sessionId":ROOT,
            "attachment":{"type":"credential_org",
                "organizationUuid":"11111111-1111-4111-8111-111111111111"}});
        let path = c.root(
            ROOT,
            &(marker.to_string()
                + "\n"
                + &line(ROOT, "r1", AT, 10)
                + &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20)),
        );
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        c.evidence(
            &[
                tagged_api("r1", 10, Some(&a)),
                tagged_api("r2", 20, Some(&b)),
            ],
            &[trace("r1", ""), trace("r2", "")],
        );
        c.evidence_for(
            GONE,
            &[api_for(GONE, "g0", 14, 140)],
            &[trace_for(GONE, "g0", "")],
        );
        let read = |prior: ScanIndex| {
            let mut page = c.raw(&E2ScanFixture::capturing_identity(), prior, 100, true, &[]);
            page.enrich(&c);
            page.finish();
            routed(&page, page.upload_policy)
        };
        let mut warm = c.raw(
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            100,
            true,
            &[],
        );
        warm.enrich(&c);
        warm.finish();
        assert!(
            warm.scan
                .snapshots
                .iter()
                .any(|item| !item.request_evidence.is_empty()),
            "the fixture carries identity-tagged rows"
        );
        let gone = ["claude-code-effort", "claude-code-trace-ownership"].map(|dir| {
            let path = member(&c, dir, GONE);
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        });
        let restore = || {
            for (path, bytes) in &gone {
                std::fs::write(path, bytes).unwrap();
            }
        };
        let unlink = || {
            for (path, _) in &gone {
                std::fs::remove_file(path).unwrap();
            }
        };

        let before = read(ScanIndex::default());
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(
            [members(&c, ROOT), members(&c, GONE)],
            [(true, true), (false, false)]
        );
        assert_equivalent(&before, &read(ScanIndex::default()));

        // A restart rereads the survivor once its telemetry changes (a side
        // call with no transcript line); an unchanged survivor emits nothing.
        let prior = c.reload(&mut warm.index);
        c.evidence(
            &[
                tagged_api("r1", 10, Some(&a)),
                tagged_api("r2", 20, Some(&b)),
                tagged_api("side", 4, Some(&b)),
            ],
            &[trace("r1", ""), trace("r2", ""), trace("side", "")],
        );
        let restarted = read(prior.clone());
        restore();
        assert_equivalent(&read(prior.clone()), &restarted);
        unlink();

        append(&path, &line(ROOT, "r3", "2026-08-02T07:02:00Z", 30));
        c.evidence(
            &[
                tagged_api("r1", 10, Some(&a)),
                tagged_api("r2", 20, Some(&b)),
                tagged_api("side", 4, Some(&b)),
                tagged_api("r3", 30, Some(&a)),
            ],
            &[
                trace("r1", ""),
                trace("r2", ""),
                trace("side", ""),
                trace("r3", ""),
            ],
        );
        let appended = read(prior.clone());
        restore();
        assert_equivalent(&read(prior), &appended);
    });
}

/// One dependency of the row's candidate, which has no transcript of its own
/// when retention runs.
#[derive(Clone, Copy, Debug)]
enum Dependency {
    /// A subagent transcript of another session holds its request.
    SubagentCopy,
    /// A fork/resume transcript of another session holds its request.
    ResumeCopy,
    /// This page's bodies name it (its main and subagent bodies, read by the
    /// real extraction, then both files are gone).
    NamedByPage,
    /// A pending family witness.
    PendingWitness,
    /// An account hold on its transcript key.
    AccountHold,
    /// A committed Tail head for its transcript key.
    TailHead,
    /// The walk listed its transcript (aged, never indexed or read).
    AgedListedFile,
}

/// [money] Every dependency keeps the candidate's pair; the uncopied gone
/// control retires in every row.
#[test]
fn telemetry_retention_keeps_every_dependency() {
    for row in [
        Dependency::SubagentCopy,
        Dependency::ResumeCopy,
        Dependency::NamedByPage,
        Dependency::PendingWitness,
        Dependency::AccountHold,
        Dependency::TailHead,
        Dependency::AgedListedFile,
    ] {
        with_e2(|| {
            let mut c = Corpus::new(&format!("telemetry-retention-{row:?}"));
            c.root(ROOT, &line(ROOT, "r0", AT, 11));
            c.evidence(&[api("r0", 11, 110)], &[trace("r0", "")]);
            for (session, request) in [(HELD, "x0"), (GONE, "g0")] {
                c.evidence_for(
                    session,
                    &[api_for(session, request, 14, 140)],
                    &[trace_for(session, request, "")],
                );
            }
            match row {
                Dependency::SubagentCopy => {
                    c.agent(1, &line(ROOT, "x0", AT, 14));
                }
                Dependency::ResumeCopy => {
                    c.write_at(
                        &format!("{COPY}.jsonl"),
                        &line(COPY, "x0", AT, 14),
                        "2026-08-02T07:03:00Z",
                    );
                }
                _ => {}
            }
            let mut warm = ready(
                &c,
                &E2ScanFixture::capturing_identity(),
                ScanIndex::default(),
                100,
                true,
            );
            warm.finish();
            let held = key(&c, HELD);
            let mut named = Vec::new();
            match row {
                Dependency::NamedByPage => {
                    c.root(HELD, &line(HELD, "x1", AT, 9));
                    c.write_at(
                        &format!("{HELD}/subagents/agent-001.jsonl"),
                        &line(HELD, "x2", AT, 8),
                        AT,
                    );
                    let mut page = c.raw(
                        &E2ScanFixture::capturing_identity(),
                        ScanIndex::default(),
                        100,
                        false,
                        &[],
                    );
                    // Read where the sync loop reads it: after enrichment.
                    page.enrich(&c);
                    named = crate::snapshot_sync::claude_evidence_session_ids(&page.scan.snapshots);
                    assert!(named.iter().any(|session| session == HELD));
                    std::fs::remove_file(Path::new(&held)).unwrap();
                    std::fs::remove_dir_all(c.root.join(HELD)).unwrap();
                }
                Dependency::PendingWitness => {
                    warm.index
                        .insert_retry_pending_claude_authority_for_test(HELD);
                }
                Dependency::AccountHold => hold_claude_account_for_test(&mut warm.index, &held),
                Dependency::TailHead => {
                    assert!(commit_tail_head_for_test(&mut warm.index, &held));
                }
                Dependency::AgedListedFile => {
                    let path = c.root(HELD, &line(HELD, "x1", AT, 9));
                    std::fs::File::options()
                        .write(true)
                        .open(path)
                        .unwrap()
                        .set_modified(
                            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600),
                        )
                        .unwrap();
                }
                Dependency::SubagentCopy | Dependency::ResumeCopy => {}
            }
            walked(&c, now_ms() + 60_000);
            retire_with(&c, &warm.index, &BTreeSet::new(), &named);
            assert_eq!(
                [members(&c, HELD), members(&c, GONE)],
                [(true, true), (false, false)],
                "{row:?}"
            );
        });
    }
}

/// [money] Retention follows only a completed upload: a rejected, deferred,
/// shed, disabled or failed page drops it even when it settles. (A failed
/// selected save returns before retention.)
#[test]
fn telemetry_retention_follows_only_a_completed_upload() {
    assert!(telemetry_retention_follows(&Ok(
        ResumableUploadResult::Completed
    )));
    let dropped: [Result<ResumableUploadResult>; 5] = [
        Ok(ResumableUploadResult::Rejected { count: 1 }),
        Ok(ResumableUploadResult::Deferred { count: 1 }),
        Ok(ResumableUploadResult::Shed { retry_after: None }),
        Ok(ResumableUploadResult::Disabled(None)),
        Err(anyhow::anyhow!("synthetic upload failure")),
    ];
    for upload in &dropped {
        assert!(!telemetry_retention_follows(upload), "{upload:?}");
    }
}

/// [money] Fail closed: a member that changes after it was read is kept under
/// the lock; no current walk, a pair written after the walk began, a listed
/// transcript whose census record is older than its listed revision (it may
/// hold a copy), a listed transcript without an mtime, and a malformed member
/// all keep the pair.
#[test]
fn telemetry_retention_fails_closed() {
    with_e2(|| {
        let (c, warm) = corpus("telemetry-retention-closed");
        let stem = format!("{:x}", Sha256::digest(HALF.as_bytes()));
        let read = crate::claude_local_otel::read_telemetry_pair(&c.support, &stem).unwrap();
        append(
            &member(&c, "claude-code-effort", HALF),
            &(serde_json::to_string(&api_for(HALF, "g5", 17, 1700)).unwrap() + "\n"),
        );
        assert!(
            !crate::claude_local_otel::unlink_telemetry_pair(&c.support, &stem, &read).unwrap()
        );
        assert_eq!(
            members(&c, HALF),
            (true, false),
            "the appended row survives"
        );

        let gone = || members(&c, GONE);
        crate::snapshots::money_freshness::set_roster_for_test(SnapshotSource::ClaudeCode, None);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "no complete walk in this process");
        walked(&c, 0);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "written after the walk began");

        let mut stale = BTreeMap::new();
        stale.insert(key(&c, COPY), Some(u64::MAX - 1));
        roster(now_ms() + 60_000, stale);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "a stale census record is unknown");

        let mut unknown = listing(&c);
        unknown.insert(key(&c, COPY), None);
        roster(now_ms() + 60_000, unknown);
        retire(&c, &warm.index);
        assert_eq!(
            gone(),
            (true, true),
            "a listed file without an mtime is unknown"
        );

        append(&member(&c, "claude-code-effort", GONE), "{not json\n");
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "a malformed member is a read fault");
    });
}

/// [money] The hint path: a key this pass removed keeps its root's pair while
/// the same relative path still exists (the walk did not list it), and the
/// next run, with no backlog, retires the pair only after a real NotFound.
#[test]
fn telemetry_retention_hint_path_retires_only_after_not_found() {
    with_e2(|| {
        let (c, warm) = corpus("telemetry-retention-hint");
        let path = c.root.join(format!("{GONE}.jsonl"));
        std::fs::write(&path, line(GONE, "g9", AT, 1)).unwrap();
        let mut listed = listing(&c);
        listed.remove(&key(&c, GONE));
        roster(now_ms() + 60_000, listed);
        let removed = BTreeSet::from([key(&c, GONE)]);
        retire_with(&c, &warm.index, &removed, &[]);
        assert_eq!(members(&c, GONE), (true, true), "the same name exists");
        std::fs::remove_file(path).unwrap();
        retire_with(&c, &warm.index, &removed, &[]);
        assert_eq!(members(&c, GONE), (false, false), "proven absent");
        assert_eq!(members(&c, ROOT), (true, true));
    });
}

/// [format] A crash between a pair's two unlinks leaves one member; the next
/// process's first complete walk deletes it.
#[test]
fn telemetry_retention_finishes_a_pair_after_a_crash_between_unlinks() {
    with_e2(|| {
        let (c, warm) = corpus("telemetry-retention-crash");
        // GONE is then the only unread pair; its second unlink fails.
        std::fs::remove_file(member(&c, "claude-code-effort", HALF)).unwrap();
        crate::claude_local_otel::fail_telemetry_unlink_for_test(2);
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(members(&c, GONE), (false, true));
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(members(&c, GONE), (false, false));
        assert_eq!(members(&c, ROOT), (true, true));
    });
}
