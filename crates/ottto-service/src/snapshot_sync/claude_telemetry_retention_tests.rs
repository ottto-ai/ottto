// Claude telemetry retention on the real e2 pipeline fixture: a session's
// API + trace pair is deleted only when no transcript, index or census entry,
// named session or copied request reads it; every surviving body is unchanged.
use super::state_v2_money_tests::routed;
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent;
use std::collections::BTreeSet;

const GONE: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const COPIED: &str = "7338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const HALF: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const NAMED: &str = "9338a80a-f36e-4cbc-a5bb-50fc66430ba5";

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

/// What a complete walk over the corpus keeps: every transcript with its
/// mtime, begun at `started_at_ms`.
fn walked(c: &Corpus, started_at_ms: u64) {
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
    crate::snapshots::money_freshness::set_roster_for_test(
        SnapshotSource::ClaudeCode,
        Some((started_at_ms, listed)),
    );
}

fn retire(c: &Corpus, index: &ScanIndex) {
    crate::snapshots::claude_telemetry_retention::retire_claude_telemetry(
        &c.support,
        index,
        std::slice::from_ref(&c.root),
        &BTreeSet::new(),
        &[NAMED.to_string()],
    );
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

/// Fail closed: a member that changes after it was read is kept under the
/// lock; no current walk, a pair written after the walk began, a listed
/// transcript whose census record is older than its listed revision (it may
/// hold a copy), and a malformed member all keep the pair.
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
        stale.insert(
            c.root
                .join(format!("{COPY}.jsonl"))
                .to_string_lossy()
                .into_owned(),
            Some(u64::MAX - 1),
        );
        crate::snapshots::money_freshness::set_roster_for_test(
            SnapshotSource::ClaudeCode,
            Some((now_ms() + 60_000, stale)),
        );
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "a stale census record is unknown");

        append(&member(&c, "claude-code-effort", GONE), "{not json\n");
        walked(&c, now_ms() + 60_000);
        retire(&c, &warm.index);
        assert_eq!(gone(), (true, true), "a malformed member is a read fault");
    });
}

/// A crash between a pair's two unlinks leaves one member; the next process's
/// first complete walk deletes it.
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
