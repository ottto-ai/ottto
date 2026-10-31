// Acceptance for the whole-history re-read loop seen on 0.1.193-0.1.195: a
// terminal-unhealthy retry re-reads only what is unsettled. This runs the C1a
// fixture through the real bounded pipeline (scan, local evidence fold,
// account binding, upload, ACK, and a save/reload between pages) on its
// default two-file pages.
//
// - 08:00 is the first complete census. Every file is read and accepted, the
//   family is proven, and the closed fence schedules its next full replay.
// - After 08:00, one RetryPending authority family (the unrelated terminal
//   session, which gains a request) keeps the census open, and an unrelated
//   transcript gains a line that is not JSON, so every later window ends red.
// - Before 08:10, every indexed revision is cleared once, as an earlier
//   whole-history trigger (full re-arm, whole-index quarantine) leaves it.
//   08:10 re-reads everything while the census is open, which leaves every
//   family pending.
// - Each later window is the terminal-unhealthy retry, started at the deadline
//   the previous red terminal saved. A healthy session gains a request before
//   the second retry, and the held family gains one before the third. Retries
//   continue until at least four ran before the fence's replay deadline and
//   two after it, with the census still open, as on a Mac whose census has
//   not completed for longer than its replay delay.
//
// Accepted behaviour:
// - Healthy unchanged files are never read again at a retry.
// - The changed file is read once, in the window after its change.
// - The held family is read at most once a window, is retried, and stays held
//   and disclosed.
// - No file is read more than twice (N3), not counting a read its own change
//   justifies.
//
// Each window writes one count-only `REREAD_ACCEPTANCE` line to stderr.

use super::*;

const AT_MAX_PAGES: usize = 16;
const AT_MAX_RETRIES: usize = 10;
/// 2026-08-02T08:00:00Z.
const AT_BASE_UNIX_SECONDS: i64 = 1_785_657_600;
/// Healthy sessions with no local OTEL proof, as most history is: their
/// families have no witness.
const AT_HEALTHY: [&str; 5] = [
    "e1000000-0000-4000-8000-000000000001",
    "e2000000-0000-4000-8000-000000000002",
    "e3000000-0000-4000-8000-000000000003",
    "e4000000-0000-4000-8000-000000000004",
    "e5000000-0000-4000-8000-000000000005",
];
/// A healthy session that gains a request before the second retry.
const AT_CHANGED: &str = "e6000000-0000-4000-8000-000000000006";

/// Count-only shape of one window.
#[derive(Debug)]
struct AtWindow {
    at: String,
    started_unix_seconds: i64,
    /// The clock of the window's last page.
    ended_unix_seconds: i64,
    /// Parses per session over the window's pages, before any hold.
    reads: BTreeMap<String, usize>,
    start: Option<C1bStart>,
    red: bool,
    census_complete: bool,
    held: Option<crate::snapshots::ClaudeAuthorityRecordForTest>,
    held_head: Option<String>,
}

impl AtWindow {
    fn reads_of(&self, session: &str) -> usize {
        self.reads.get(session).copied().unwrap_or_default()
    }
}

fn at_path(fixture: &RearmFixture, session: &str) -> PathBuf {
    fixture.root.join(format!("{session}.jsonl"))
}

fn at_clock(unix_seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_seconds)
        .expect("a fixture clock")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format the fixture clock")
}

/// A saved index field, as the next process reads it.
fn at_saved_u64(fixture: &RearmFixture, pointer: &str) -> Option<i64> {
    c1a_saved(fixture)
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
}

/// One bounded traversal on one-minute page clocks, from its first page to
/// its complete or red end.
fn at_window(fixture: &RearmFixture, started_unix_seconds: i64) -> AtWindow {
    let mut reads = BTreeMap::new();
    let mut start = None;
    for number in 0..AT_MAX_PAGES {
        let now = started_unix_seconds + 60 * number as i64;
        let (page, rows) = crate::local_resource_diagnostics::capture(|| {
            fixture.page(&at_clock(now), RearmUpload::Accept)
        });
        if start.is_none() {
            start = rows
                .iter()
                .find(|row| {
                    row["stage"] == "bounded_traversal_transition"
                        && row["counts"]["event"] == "starting"
                })
                .map(c1b_start);
        }
        for session in &page.parsed {
            *reads.entry(session.clone()).or_insert(0_usize) += 1;
        }
        let (ended, red) = c1b_traversal_ended(&page.index);
        if ended {
            let window = AtWindow {
                at: at_clock(started_unix_seconds),
                started_unix_seconds,
                ended_unix_seconds: now,
                reads,
                start,
                red,
                census_complete: page.scan.census_complete,
                held: page.index.claude_authority_record_for_test(REARM_TERMINAL),
                held_head: c1b_terminal_head(&page.index),
            };
            writeln!(
                std::io::stderr().lock(),
                "REREAD_ACCEPTANCE case={} at={} pages={} start={:?} red={} \
                 census_complete={} held_terminal={:?} reads={:?}",
                fixture.case,
                window.at,
                number + 1,
                window.start,
                window.red,
                window.census_complete,
                window.held.as_ref().map(|record| record.terminal),
                window.reads
            )
            .unwrap();
            return window;
        }
    }
    panic!("the window ends within {AT_MAX_PAGES} bounded pages");
}

/// The next window after `previous`: when its red terminal's saved retry is
/// due, on a whole minute, and never before the previous window ended.
fn at_next_start(fixture: &RearmFixture, previous: &AtWindow) -> i64 {
    let due = at_saved_u64(
        fixture,
        "/traversal/unhealthy_retry_not_before_unix_seconds",
    )
    .expect("a red terminal saves its retry deadline");
    let earliest = due.max(previous.ended_unix_seconds + 60);
    earliest + (60 - earliest.rem_euclid(60)) % 60
}

#[test]
#[serial(source_manifests)]
fn unhealthy_retries_reread_only_unsettled_files() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion (E2 rule 5).

    if !c1a_layout_supported("unhealthy_retry_reread_acceptance") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = c1a_fixture("unhealthy-retry-reread-acceptance");
    for session in AT_HEALTHY.iter().chain([&AT_CHANGED]) {
        std::fs::write(
            at_path(&fixture, session),
            rearm_transcript_line(session, None, &format!("req_{session}"), 0),
        )
        .expect("write a healthy transcript");
    }
    // Every file that stays healthy and unchanged after its first read.
    let healthy = AT_HEALTHY
        .iter()
        .map(|session| session.to_string())
        .chain(rearm_family_sessions())
        .chain([C1A_INVALID.to_owned()])
        .collect::<BTreeSet<_>>();

    let closing = at_window(&fixture, AT_BASE_UNIX_SECONDS);
    assert!(closing.census_complete, "the first census completes");
    let replay_deadline = at_saved_u64(
        &fixture,
        "/claude_duplicate_fence_next_full_rearm_unix_seconds",
    )
    .expect("the closed fence schedules its next full replay");

    let mut index = ScanIndex::load(&fixture.index_path).unwrap();
    index = crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(index);
    let held_head = c1b_terminal_head(&index);
    assert!(
        held_head.is_some(),
        "the terminal session was accepted once"
    );
    index.insert_retry_pending_claude_authority_for_test(REARM_TERMINAL);
    index.save(&fixture.index_path).unwrap();
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    RearmFixture::append(
        &c1b_terminal_path(&fixture),
        &rearm_transcript_line(REARM_TERMINAL, None, "req_terminal_2", 1),
    );
    // One earlier whole-history trigger: every indexed revision cleared once.
    c1a_edit_index(&fixture, |saved| {
        for entry in saved
            .get_mut("files")
            .and_then(serde_json::Value::as_object_mut)
            .expect("the saved index has files")
            .values_mut()
        {
            entry["source_file_fingerprint"] = "".into();
        }
    });
    let seeded = at_window(&fixture, AT_BASE_UNIX_SECONDS + 600);
    assert!(
        seeded.red && !seeded.census_complete,
        "the held, red window keeps the census open"
    );
    for session in &healthy {
        assert_eq!(
            seeded.reads_of(session),
            1,
            "{session}: the one whole-history re-read reached it"
        );
    }
    let held = seeded.held.clone().expect("the terminal family is held");
    assert!(!held.terminal, "RetryPending after the seeded window");

    let mut retries: Vec<AtWindow> = Vec::new();
    while retries.len() < AT_MAX_RETRIES {
        let before = retries
            .iter()
            .filter(|window| window.ended_unix_seconds < replay_deadline)
            .count();
        let after = retries
            .iter()
            .filter(|window| window.started_unix_seconds >= replay_deadline)
            .count();
        if before >= 4 && after >= 2 {
            break;
        }
        match retries.len() {
            1 => RearmFixture::append(
                &at_path(&fixture, AT_CHANGED),
                &rearm_transcript_line(AT_CHANGED, None, "req_changed_2", 1),
            ),
            2 => RearmFixture::append(
                &c1b_terminal_path(&fixture),
                &rearm_transcript_line(REARM_TERMINAL, None, "req_terminal_3", 2),
            ),
            _ => {}
        }
        let next = at_next_start(&fixture, retries.last().unwrap_or(&seeded));
        retries.push(at_window(&fixture, next));
    }

    // Preconditions: each is a real terminal-unhealthy retry that ends red
    // with the census still open, at least four of them before the replay
    // deadline and two after it.
    for window in &retries {
        let start = window
            .start
            .as_ref()
            .unwrap_or_else(|| panic!("{}: a traversal starts", window.at));
        assert_eq!(start.reason, "terminal_unhealthy_retry", "{}", window.at);
        assert!(
            window.red && !window.census_complete,
            "{}: red, census open",
            window.at
        );
    }
    assert!(
        retries
            .iter()
            .filter(|window| window.ended_unix_seconds < replay_deadline)
            .count()
            >= 4
            && retries
                .iter()
                .filter(|window| window.started_unix_seconds >= replay_deadline)
                .count()
                >= 2,
        "retries straddle the replay deadline {}",
        at_clock(replay_deadline)
    );

    // Every violation is collected, so one run names each remaining path.
    let mut violations = Vec::new();
    let family = rearm_family_sessions();
    let changed_retry = &retries[1];
    // 1. Healthy unchanged files: zero reads at every unhealthy retry.
    for window in &retries {
        let reread = |keep: &dyn Fn(&str) -> bool| {
            window
                .reads
                .keys()
                .filter(|session| healthy.contains(*session) && keep(session.as_str()))
                .cloned()
                .collect::<Vec<_>>()
        };
        let witnessed = reread(&|session| family.contains(session));
        let invalid = reread(&|session| session == C1A_INVALID);
        let unwitnessed = reread(&|session| AT_HEALTHY.contains(&session));
        if !(witnessed.is_empty() && invalid.is_empty() && unwitnessed.is_empty()) {
            violations.push(format!(
                "{} ({} the replay deadline): an unhealthy retry re-read healthy unchanged \
                 files: witnessed family {witnessed:?}, unwitnessed {unwitnessed:?}, invalid \
                 pending {invalid:?} (start {:?})",
                window.at,
                if window.started_unix_seconds >= replay_deadline {
                    "after"
                } else {
                    "before"
                },
                window.start
            ));
        }
    }
    // 2. Only unsettled files are read, each at most once a window: the red
    // producer, the held family, and the changed file after its change.
    for window in &retries {
        let mut allowed = BTreeSet::from([REARM_SIBLING.to_owned(), REARM_TERMINAL.to_owned()]);
        if window.at == changed_retry.at {
            allowed.insert(AT_CHANGED.to_owned());
        }
        for (session, count) in &window.reads {
            if !allowed.contains(session) && !healthy.contains(session) {
                violations.push(format!("{}: {session} read at a retry", window.at));
            }
            if *count > 1 {
                violations.push(format!("{}: {session} read {count} times", window.at));
            }
        }
    }
    // 3. The file that really changed is read once, after its change.
    let changed = retries
        .iter()
        .map(|window| window.reads_of(AT_CHANGED))
        .collect::<Vec<_>>();
    let mut expected = vec![0; retries.len()];
    expected[1] = 1;
    if changed != expected {
        violations.push(format!(
            "the changed file is read once, in the window after its change: {changed:?}"
        ));
    }
    // 4. The held family is retried, at most once a window, and stays held
    // and disclosed: quarantined, never accepted, census open. Its binding
    // does not move while its bytes do not.
    if !retries
        .iter()
        .any(|window| window.reads_of(REARM_TERMINAL) > 0)
    {
        violations.push("the held family is never retried".to_owned());
    }
    for (number, window) in retries.iter().enumerate() {
        let Some(record) = window.held.as_ref() else {
            violations.push(format!("{}: the hold is no longer disclosed", window.at));
            continue;
        };
        if window.held_head != held_head {
            violations.push(format!("{}: the held family was accepted", window.at));
        }
        if number < 2
            && record.member_source_file_fingerprints != held.member_source_file_fingerprints
        {
            violations.push(format!(
                "{}: the unchanged held family lost its binding",
                window.at
            ));
        }
    }
    // 5. N3: at most two reads per file over the run (well inside 7 days),
    // not counting the one read its own change justifies.
    let total = |session: &str| {
        [&closing, &seeded]
            .into_iter()
            .chain(&retries)
            .map(|window| window.reads_of(session))
            .sum::<usize>()
    };
    for session in &healthy {
        if total(session.as_str()) > 2 {
            violations.push(format!(
                "N3: {session} read {} times",
                total(session.as_str())
            ));
        }
    }
    if total(AT_CHANGED) - changed_retry.reads_of(AT_CHANGED) > 2 {
        violations.push(format!("N3: {AT_CHANGED} read {} times", total(AT_CHANGED)));
    }
    assert!(
        violations.is_empty(),
        "{} violation(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}
