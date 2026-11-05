// Claude telemetry retention on the real e2 pipeline fixture. Deletion waits
// for proof that a pair was delivered, so no pair is deleted or read today.
// Once proven (a test seam until then), a session's API + trace pair is
// deleted only when no transcript, index or census entry, named session, held
// state or copied request reads it; every surviving body is unchanged.
use super::state_v2_money_tests::{routed, tagged_api};
use super::*;
use crate::snapshots::e2_pipeline_scan_fixture::{
    commit_tail_head_for_test, hold_claude_account_for_test,
    legacy_owner_of_terminal_family_for_test,
};
use crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent;
use std::collections::BTreeSet;

const GONE: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const COPIED: &str = "7338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const HALF: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const NAMED: &str = "9338a80a-f36e-4cbc-a5bb-50fc66430ba5";
/// The candidate of a dependency row.
const HELD: &str = "a338a80a-f36e-4cbc-a5bb-50fc66430ba5";
/// A listed transcript no page has read (no census record).
const UNREAD: &str = "b338a80a-f36e-4cbc-a5bb-50fc66430ba5";

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

/// A complete walk, begun at `started_at_ms`, listed `listed` and ended (no
/// restart).
fn roster(started_at_ms: u64, listed: BTreeMap<String, Option<u64>>) {
    crate::snapshots::money_freshness::walk_ended_for_test(
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

/// Treat every candidate as delivered (or none, as today) on this thread.
fn proven(proven: bool) {
    crate::snapshots::claude_telemetry_retention::prove_delivery_for_test(proven);
}

/// One retention run's page counters (reads and retention counts), alone.
fn counted(run: impl FnOnce()) -> serde_json::Value {
    crate::local_resource_diagnostics::take_claude_sidecar_reparse_for_test();
    run();
    crate::local_resource_diagnostics::take_claude_sidecar_reparse_for_test()
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

/// [money] Once delivery is proven, retention deletes exactly the unread pairs
/// (one a half pair) and keeps the transcript's, the copied and the named ones;
/// a cold read of every surviving session then equals the arm without
/// retention (money oracle).
#[test]
fn telemetry_retention_equality_oracle() {
    with_e2(|| {
        proven(true);
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
/// retention deletes the proven the unread pair, a cold read and a restart from the
/// saved index equal the reads with the pair present, and so does a reread
/// after the survivor grows.
#[test]
fn telemetry_retention_positive_control_cold_restart_and_append() {
    with_e2(|| {
        proven(true);
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
        // Both accounts' requests survive qualification: one request each.
        let mut placed = BTreeMap::<String, u64>::new();
        for row in warm
            .scan
            .snapshots
            .iter()
            .flat_map(|item| &item.usage_buckets)
            .flat_map(|bucket| &bucket.model_usage)
        {
            let shares = match &row.identity_parts {
                Some(parts) => parts
                    .iter()
                    .map(|part| (&part.account_identifier_hash, part.request_count))
                    .collect(),
                None => vec![(&row.account_identifier_hash, row.request_count)],
            };
            for (account, requests) in shares {
                if let Some(account) = account {
                    *placed.entry(account.clone()).or_default() += requests;
                }
            }
        }
        assert_eq!(
            placed.into_values().collect::<Vec<_>>(),
            [1, 1],
            "each account keeps its own request"
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
    /// Another body of this page names it as parent/root (its subagent's,
    /// through the real extraction; its own main body is left out), then its
    /// files are gone.
    NamedByPage,
    /// A pending family witness.
    PendingWitness,
    /// It is a legacy owner of another root's terminal family witness.
    LegacyOwnerOfTerminalFamily,
    /// An account hold on its transcript key.
    AccountHold,
    /// A committed Tail head for its transcript key.
    TailHead,
    /// The walk listed its transcript (aged, never indexed or read).
    AgedListedFile,
    /// Its login-only rows answer a request (after an org marker) that only
    /// another root's transcript holds.
    LoginOnlyForeignOwner,
    /// Its transcript was read on a page whose upload was never ACKed, then
    /// deleted: the unACKed scan state keeps it.
    UnackedRoot,
    /// Only its excluded subagent journal remains. The journal names no
    /// session and is never read, so it keeps nothing: the pair retires.
    ExcludedFileOnly,
}

/// [money] With delivery proven, every dependency keeps the candidate's pair,
/// except an excluded journal, which reads nothing; the uncopied gone control
/// retires in every row.
#[test]
fn telemetry_retention_keeps_every_dependency() {
    proven(true);
    for (row, keeps) in [
        (Dependency::SubagentCopy, true),
        (Dependency::ResumeCopy, true),
        (Dependency::NamedByPage, true),
        (Dependency::PendingWitness, true),
        (Dependency::LegacyOwnerOfTerminalFamily, true),
        (Dependency::AccountHold, true),
        (Dependency::TailHead, true),
        (Dependency::AgedListedFile, true),
        (Dependency::LoginOnlyForeignOwner, true),
        (Dependency::UnackedRoot, true),
        (Dependency::ExcludedFileOnly, false),
    ] {
        with_e2(|| {
            let mut c = Corpus::new(&format!("telemetry-retention-{row:?}"));
            let foreign = matches!(row, Dependency::LoginOnlyForeignOwner);
            let marker = serde_json::json!({"type":"attachment", "sessionId":ROOT,
                "attachment":{"type":"credential_org",
                    "organizationUuid":"11111111-1111-4111-8111-111111111111"}});
            c.root(
                ROOT,
                &if foreign {
                    marker.to_string()
                        + "\n"
                        + &line(ROOT, "r0", AT, 11)
                        + &line(ROOT, "x0", AT, 14)
                } else {
                    line(ROOT, "r0", AT, 11)
                },
            );
            c.evidence(&[api("r0", 11, 110)], &[trace("r0", "")]);
            for (session, request) in [(HELD, "x0"), (GONE, "g0")] {
                let api_row = if foreign && session == HELD {
                    api_login(session, request, 14, '1', None)
                } else {
                    api_for(session, request, 14, 140)
                };
                c.evidence_for(session, &[api_row], &[trace_for(session, request, "")]);
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
            let scanner = E2ScanFixture::capturing_identity();
            let mut warm = ready(&c, &scanner, ScanIndex::default(), 100, true);
            warm.finish();
            let held = key(&c, HELD);
            let mut named = Vec::new();
            match row {
                Dependency::NamedByPage => {
                    c.root(HELD, &line(HELD, "x1", AT, 9));
                    let mut page = c.raw(
                        &E2ScanFixture::capturing_identity(),
                        ScanIndex::default(),
                        100,
                        false,
                        &[],
                    );
                    // Read where the sync loop reads it: after enrichment.
                    page.enrich(&c);
                    // HELD's own body is left out. ROOT's body names HELD the
                    // way the desktop app records a session it started from
                    // another one (the provider's own producer, real shape).
                    let mut others = page
                        .scan
                        .snapshots
                        .iter()
                        .filter(|item| item.source_session_id != HELD)
                        .cloned()
                        .collect::<Vec<_>>();
                    others
                        .iter_mut()
                        .find(|item| item.source_session_id == ROOT)
                        .expect("the page carries the starting root's body")
                        .attribution_facts
                        .extend(crate::session_attribution::claude_desktop_spawn_facts(
                            HELD, ROOT, AT,
                        ));
                    assert!(
                        others
                            .iter()
                            .any(|item| item.attribution_facts.iter().any(|fact| {
                                matches!(
                                    fact.field.as_str(),
                                    "parent_session_ref" | "root_session_ref"
                                ) && fact.value == HELD
                            })),
                        "another body names it by reference"
                    );
                    named = crate::snapshot_sync::claude_evidence_session_ids(&others);
                    assert!(named.iter().any(|session| session == HELD));
                    std::fs::remove_file(Path::new(&held)).unwrap();
                }
                Dependency::PendingWitness => {
                    warm.index
                        .insert_retry_pending_claude_authority_for_test(HELD);
                }
                Dependency::LegacyOwnerOfTerminalFamily => {
                    legacy_owner_of_terminal_family_for_test(&mut warm.index, ROOT, HELD);
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
                Dependency::UnackedRoot => {
                    let path = c.root(HELD, &line(HELD, "x1", AT, 9));
                    let mut page = c.raw(&scanner, warm.index, 100, true, &[]);
                    page.enrich(&c);
                    page.finish();
                    assert!(page.delivered.is_none(), "no ACK reached this page");
                    std::fs::remove_file(path).unwrap();
                    warm = page;
                }
                Dependency::ExcludedFileOnly => {
                    c.write_at(
                        &format!("{HELD}/subagents/journal.jsonl"),
                        &line(HELD, "x1", AT, 9),
                        AT,
                    );
                }
                Dependency::SubagentCopy
                | Dependency::ResumeCopy
                | Dependency::LoginOnlyForeignOwner => {}
            }
            walked(&c, now_ms() + 60_000);
            retire_with(&c, &warm.index, &BTreeSet::new(), &named);
            assert_eq!(
                [members(&c, HELD), members(&c, GONE)],
                [(keeps, keeps), (false, false)],
                "{row:?}"
            );
        });
    }
}

/// [money] Fail closed, with delivery proven: a member that changes after it
/// was read is kept under
/// the lock; no current walk, a pair written after the walk began, a listed
/// transcript with no census record (it may hold a copy), one without an
/// mtime, and a malformed member all keep the pair. A transcript that grew
/// since its loss-free read is known through that read's ids.
#[test]
fn telemetry_retention_fails_closed() {
    with_e2(|| {
        proven(true);
        let (c, warm) = corpus("telemetry-retention-closed");
        let stem = format!("{:x}", Sha256::digest(HALF.as_bytes()));
        let read = crate::claude_local_otel::read_telemetry_pair(&c.support, &stem)
            .unwrap()
            .unwrap();
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
        crate::snapshots::money_freshness::walk_ended_for_test(SnapshotSource::ClaudeCode, None);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "no complete walk in this process");
        walked(&c, 0);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "written after the walk began");

        let mut unknown = listing(&c);
        unknown.insert(key(&c, UNREAD), Some(u64::MAX - 1));
        roster(now_ms() + 60_000, unknown.clone());
        retire(&c, &warm.index);
        assert_eq!(
            gone(),
            (true, true),
            "a listed file without a census record is unknown"
        );

        unknown.insert(key(&c, UNREAD), None);
        roster(now_ms() + 60_000, unknown);
        retire(&c, &warm.index);
        assert_eq!(
            gone(),
            (true, true),
            "a listed file without an mtime is unknown"
        );

        let api = member(&c, "claude-code-effort", GONE);
        let rows = std::fs::read_to_string(&api).unwrap();
        append(&api, "{not json\n");
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "a malformed member is a read fault");

        std::fs::write(&api, rows).unwrap();
        let mut grown = listing(&c);
        grown.insert(key(&c, COPY), Some(u64::MAX - 1));
        roster(now_ms() + 60_000, grown);
        retire(&c, &warm.index);
        assert_eq!(
            gone(),
            (false, false),
            "a grown transcript is known through its last read"
        );
    });
}

/// [money] The hint path, with delivery proven: a key this pass removed keeps
/// its root's pair while
/// the same relative path still exists (the walk did not list it), and the
/// next run of the same walk, with no backlog, retires the pair only after a
/// real NotFound.
#[test]
fn telemetry_retention_hint_path_retires_only_after_not_found() {
    with_e2(|| {
        proven(true);
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

/// [format] A crash between a pair's two unlinks (delivery proven) leaves one
/// member; without proof the next complete walk, in the same process, holds
/// it. A restart's cold read of every survivor equals the read before
/// retention, both after the crash and after the holding run (money and
/// placement oracle).
#[test]
fn telemetry_retention_holds_a_pair_after_a_crash_between_unlinks() {
    with_e2(|| {
        proven(true);
        let (c, warm) = corpus("telemetry-retention-crash");
        // GONE is then the only unread pair; its second unlink fails.
        std::fs::remove_file(member(&c, "claude-code-effort", HALF)).unwrap();
        let before = cold(&c);
        let before = routed(&before, before.upload_policy);
        crate::claude_local_otel::fail_telemetry_unlink_for_test(2);
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(members(&c, GONE), (false, true));
        let crashed = cold(&c);
        assert_equivalent(&before, &routed(&crashed, crashed.upload_policy));
        proven(false);
        walked(&c, now_ms() + 60_000);
        let counts = counted(|| retire(&c, &warm.index));
        assert_eq!(members(&c, GONE), (false, true), "the remnant is held");
        assert_eq!(members(&c, ROOT), (true, true));
        assert!(counts.get("claude_sidecar_reparse_files").is_none());
        assert!(counts.get("claude_telemetry_retired_roots").is_none());
        let finished = cold(&c);
        assert_equivalent(&before, &routed(&finished, finished.upload_policy));
    });
}

/// [regress] Each complete walk rechecks every stored pair: a pair held at one
/// walk's end is held again after the next walk ends while its delivery is
/// unproven, and counted again.
#[test]
fn telemetry_retention_rechecks_held_pairs_after_each_complete_walk() {
    with_e2(|| {
        let (c, warm) = corpus("telemetry-retention-per-walk");
        walked(&c, 0);
        let first = counted(|| retire(&c, &warm.index));
        assert_eq!(
            members(&c, GONE),
            (true, true),
            "written after walk 1 began"
        );
        walked(&c, now_ms() + 60_000);
        let second = counted(|| retire(&c, &warm.index));
        assert_eq!(members(&c, GONE), (true, true), "walk 2 holds it");
        assert_eq!(members(&c, ROOT), (true, true));
        assert_eq!(first, second, "held counts repeat per complete walk");
        assert_eq!(second["claude_telemetry_held_roots"], 5);
    });
}

/// [regress] Until delivery is proven, retention deletes and reads no pair of
/// any kind across two complete walks and a restart, and counts each held
/// pair (those without a listed transcript, with their metadata bytes).
#[test]
fn telemetry_retention_holds_and_reads_no_pair_until_delivery_is_proven() {
    with_e2(|| {
        proven(false);
        let (c, mut warm) = corpus("telemetry-retention-hold");
        // (session, members, has a listed transcript)
        let kinds = [
            (ROOT, (true, true), true),
            (GONE, (true, true), false),
            (HALF, (true, false), false),
            (COPIED, (true, true), false),
            (NAMED, (true, true), false),
        ];
        let no_transcript_bytes = kinds
            .iter()
            .filter(|(_, _, listed)| !listed)
            .flat_map(|(session, _, _)| {
                ["claude-code-effort", "claude-code-trace-ownership"]
                    .map(|dir| member(&c, dir, session))
            })
            .filter_map(|path| std::fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum::<u64>();
        let expected = serde_json::json!({
            "claude_telemetry_held_roots": kinds.len(),
            "claude_telemetry_held_no_transcript_roots": 4,
            "claude_telemetry_held_no_transcript_bytes": no_transcript_bytes,
        });
        let mut index = warm.index.clone();
        for run in ["walk 1", "walk 2", "restart"] {
            if run == "restart" {
                crate::snapshots::money_freshness::walk_ended_for_test(
                    SnapshotSource::ClaudeCode,
                    None,
                );
                let counts = counted(|| retire(&c, &index));
                assert_eq!(counts, serde_json::json!({}), "no walk since start");
                index = c.reload(&mut warm.index);
            }
            walked(&c, now_ms() + 60_000);
            // Zero body reads: no side-file read and no read fault.
            assert_eq!(counted(|| retire(&c, &index)), expected, "{run}");
            for (session, members_before, _) in kinds {
                assert_eq!(members(&c, session), members_before, "{run}: {session}");
            }
        }
    });
}
