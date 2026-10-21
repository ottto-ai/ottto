// C1b: same-context red retries carry unchanged, witnessed Claude families
// instead of re-arming them whole. These run the C1a fixture through the real
// bounded pipeline (scan, local evidence fold, account binding, upload, ACK and
// a save/reload between pages). The duplicate fence closes on the first
// complete census and stays closed.
//
// Shape (the unrelated-red-window baseline): the closing window at 08:00 is a
// full re-arm, so the family is re-read at 08:10. Before 08:10 an unrelated
// session gains a line that is not JSON and the unrelated terminal session
// gains a request, so 08:10 reads the family, both unrelated sessions, and
// ends red. Its retry at 08:20 re-reads the still-broken session and ends red
// again. That session is repaired before the 08:30 retry, which completes, and
// 08:40 is a quiet window. A BASE arm runs the same steps under
// `KeepStaleClaudeFamilyRearmForTest`. Each window writes one count-only
// `C1B_STALE_CARRY` line to stderr, outside the harness capture.

use super::*;

const C1B_MAX_PAGES: usize = 8;

/// Count-only fields of the traversal start that opened a window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct C1bStart {
    reason: String,
    stale_pending_families: Option<u64>,
    rearmed_index_files: Option<u64>,
    carried_pending_families: Option<u64>,
    carried_index_files: Option<u64>,
}

/// Count-only shape of one window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct C1bWindow {
    reads: usize,
    family_reads: usize,
    parsed: BTreeSet<String>,
    red: bool,
    census_complete: bool,
    census_invalid: bool,
    fence_before: bool,
    fence_after: bool,
    full_rearm: bool,
    retry_pending: bool,
    proven: bool,
    start: Option<C1bStart>,
}

/// RetryPending, red, census complete, census invalid, fence before and
/// after, full re-arm and retained proof.
type C1bLiveness = (bool, bool, bool, bool, bool, bool, bool, bool);

impl C1bWindow {
    /// What a family's liveness depends on: RetryPending, red or complete
    /// terminals, the duplicate census's validity, the fence and the retained
    /// proof.
    fn liveness(&self) -> C1bLiveness {
        (
            self.retry_pending,
            self.red,
            self.census_complete,
            self.census_invalid,
            self.fence_before,
            self.fence_after,
            self.full_rearm,
            self.proven,
        )
    }
}

fn c1b_start(row: &serde_json::Value) -> C1bStart {
    let counts = &row["counts"];
    C1bStart {
        reason: counts["reason"].as_str().unwrap_or_default().to_owned(),
        stale_pending_families: counts["stale_pending_families"].as_u64(),
        rearmed_index_files: counts["rearmed_index_files"].as_u64(),
        carried_pending_families: counts["carried_pending_families"].as_u64(),
        carried_index_files: counts["carried_index_files"].as_u64(),
    }
}

/// Whether a page ended its traversal: complete (no traversal is retained) or
/// red (the retained traversal has nothing left to walk).
fn c1b_traversal_ended(index: &ScanIndex) -> (bool, bool) {
    let saved = serde_json::to_value(index).expect("encode the saved index");
    match saved.get("traversal").filter(|value| !value.is_null()) {
        None => (true, false),
        Some(traversal) => {
            let walked = ["pending_directories", "pending_candidates"]
                .iter()
                .all(|queue| traversal[*queue].as_array().is_some_and(Vec::is_empty));
            (walked, walked)
        }
    }
}

/// One bounded traversal on minute clocks, from its start to its complete or
/// red terminal.
fn c1b_generation(fixture: &RearmFixture, arm: &str, (hour, minute): (u32, usize)) -> C1bWindow {
    let mut pages = Vec::new();
    let mut start = None;
    for number in 0..C1B_MAX_PAGES {
        let at = format!("2026-08-02T{hour:02}:{:02}:00Z", minute + number);
        let (page, rows) =
            crate::local_resource_diagnostics::capture(|| fixture.page(&at, RearmUpload::Accept));
        if start.is_none() {
            start = rows
                .iter()
                .find(|row| {
                    row["stage"] == "bounded_traversal_transition"
                        && row["counts"]["event"] == "starting"
                })
                .map(c1b_start);
        }
        let (ended, red) = c1b_traversal_ended(&page.index);
        pages.push(page);
        if ended {
            let family = rearm_family_sessions();
            let parsed = rearm_parsed(&pages);
            let last = pages.last().expect("terminal page");
            let window = C1bWindow {
                reads: rearm_reads(&pages),
                family_reads: parsed.intersection(&family).count(),
                parsed,
                red,
                census_complete: last.scan.census_complete,
                census_invalid: last.duplicate_census.census_invalid,
                fence_before: last.duplicate_census.fence_before,
                fence_after: last.duplicate_census.fence_after,
                full_rearm: last.duplicate_census.full_rearm,
                retry_pending: pages.iter().any(|page| {
                    page.index
                        .claude_authority_record_for_test(REARM_ROOT)
                        .is_some_and(|record| !record.terminal)
                }),
                proven: last
                    .index
                    .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                    .is_some(),
                start,
            };
            writeln!(
                std::io::stderr().lock(),
                "C1B_STALE_CARRY case={} arm={arm} at={hour:02}:{minute:02} {window:?}",
                fixture.case
            )
            .unwrap();
            return window;
        }
    }
    panic!("the window ends within {C1B_MAX_PAGES} bounded pages");
}

fn c1b_sibling_path(fixture: &RearmFixture) -> PathBuf {
    fixture.root.join(format!("{REARM_SIBLING}.jsonl"))
}

fn c1b_terminal_path(fixture: &RearmFixture) -> PathBuf {
    fixture
        .root
        .join("zz-terminal")
        .join("nested")
        .join(format!("{REARM_TERMINAL}.jsonl"))
}

/// The red-chain windows of one arm, with `between` run after the red 08:10
/// window and before its 08:20 retry.
struct C1bRun {
    windows: [C1bWindow; 5],
    heads_after_red: BTreeMap<String, Option<String>>,
    heads_after: BTreeMap<String, Option<String>>,
    witness_after_red: Option<String>,
    witness_after: Option<String>,
    family_pending_after: bool,
}

fn c1b_red_chain(case: &'static str, arm: &str, between: impl FnOnce(&RearmFixture)) -> C1bRun {
    c1b_red_chain_with(c1a_fixture(case), arm, between)
}

fn c1b_red_chain_with(
    fixture: RearmFixture,
    arm: &str,
    between: impl FnOnce(&RearmFixture),
) -> C1bRun {
    let family = rearm_family_sessions().len();
    let closing = c1b_generation(&fixture, arm, (8, 0));
    assert!(closing.census_complete, "{arm}: the first census completes");
    assert!(closing.fence_after && closing.full_rearm, "{arm}");
    assert!(closing.proven, "{arm}: the family is proven");
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    RearmFixture::append(
        &c1b_terminal_path(&fixture),
        &rearm_transcript_line(REARM_TERMINAL, None, "req_terminal_2", 1),
    );
    let red = c1b_generation(&fixture, arm, (8, 10));
    assert!(red.red && !red.census_complete, "{arm}: the window is red");
    assert_eq!(
        red.family_reads, family,
        "{arm}: the re-arm reads the family"
    );
    assert!(
        red.parsed.contains(REARM_TERMINAL),
        "{arm}: and the unrelated session"
    );
    let saved = ScanIndex::load(&fixture.index_path).unwrap();
    let heads_after_red = RearmFixture::family_heads(&saved);
    let witness_after_red = saved.claude_usage_family_witness_digest_for_test(REARM_ROOT);
    between(&fixture);
    let retry = c1b_generation(&fixture, arm, (8, 20));
    std::fs::write(
        c1b_sibling_path(&fixture),
        rearm_transcript_line(REARM_SIBLING, None, &format!("req_{REARM_SIBLING}"), 0)
            + &rearm_transcript_line(REARM_SIBLING, None, "req_sibling_2", 1),
    )
    .expect("repair the unrelated transcript");
    let repaired = c1b_generation(&fixture, arm, (8, 30));
    let quiet = c1b_generation(&fixture, arm, (8, 40));
    let saved = ScanIndex::load(&fixture.index_path).unwrap();
    let family_pending_after = serde_json::to_value(&saved).unwrap()["claude_usage_family_pending"]
        .get(REARM_ROOT)
        .is_some();
    C1bRun {
        windows: [closing, red, retry, repaired, quiet],
        heads_after_red,
        heads_after: RearmFixture::family_heads(&saved),
        witness_after_red,
        witness_after: saved.claude_usage_family_witness_digest_for_test(REARM_ROOT),
        family_pending_after,
    }
}

fn c1b_base_red_chain(case: &'static str, between: impl FnOnce(&RearmFixture)) -> C1bRun {
    let _base = crate::snapshots::KeepStaleClaudeFamilyRearmForTest::new();
    c1b_red_chain(case, "base", between)
}

fn c1b_liveness(run: &C1bRun) -> Vec<C1bLiveness> {
    run.windows.iter().map(C1bWindow::liveness).collect()
}

/// T0/T1, the unrelated-red-window shape: an unrelated session turns the
/// 08:10 window red. BASE re-arms every family parsed there at each retry
/// start, so the unchanged witnessed family is re-read at 08:20 and 08:30
/// only to find semantic no-ops. The fix carries it at both retries and reads
/// only the unrelated sessions, which are unwitnessed and keep the BASE
/// re-arm. Every window's liveness (RetryPending, red or complete terminal,
/// fence, full re-arm, retained proof) equals BASE, the accepted heads and the
/// witness never change, and the complete 08:30 census retires the carried
/// pending. The only other difference is that census's duplicate-validity
/// diagnostic: the carried old-window pending keeps it invalid while the
/// fence stays closed.
#[test]
#[serial(source_manifests)]
fn c1b_unrelated_red_window_carries_unchanged_family_at_retry() {
    if !c1a_layout_supported("c1b_unrelated_red_window") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len() as u64;
    let fix = c1b_red_chain("c1b-red-window", "fix", |_| {});
    let base = c1b_base_red_chain("c1b-red-window-base", |_| {});
    let [_, _, retry, repaired, quiet] = &fix.windows;
    let [_, _, base_retry, base_repaired, _] = &base.windows;
    // Preconditions on BASE: both retries re-arm and re-read the family, and
    // the first one ends red again.
    for window in [base_retry, base_repaired] {
        let start = window.start.as_ref().expect("a retry start");
        assert_eq!(start.reason, "terminal_unhealthy_retry");
        assert_eq!(window.family_reads as u64, family);
    }
    assert!(base_retry.red && base_repaired.census_complete);
    for (window, base_window) in [(retry, base_retry), (repaired, base_repaired)] {
        let start = window.start.as_ref().expect("a retry start");
        let base_start = base_window.start.as_ref().unwrap();
        assert_eq!(start.reason, base_start.reason);
        assert_eq!(
            start.stale_pending_families,
            base_start.stale_pending_families
        );
        assert!(window.parsed.contains(REARM_TERMINAL), "unwitnessed: BASE");
        // FLIPS: BASE re-reads the unchanged family at each retry.
        assert_eq!(window.family_reads, 0, "the carried family is not read");
        assert_eq!(window.reads, base_window.reads - family as usize);
        assert_eq!(start.carried_pending_families, Some(1));
        assert_eq!(start.carried_index_files, Some(family));
        assert_eq!(
            start.rearmed_index_files.map(|files| files + family),
            base_start.rearmed_index_files,
            "every other stale family keeps the BASE re-arm"
        );
    }
    assert_eq!(quiet.reads, 0);
    assert_eq!(
        c1b_liveness(&fix),
        c1b_liveness(&base),
        "liveness is BASE's"
    );
    assert!(fix.windows.iter().all(|window| !window.retry_pending));
    assert!(repaired.census_complete && repaired.fence_before && repaired.fence_after);
    assert!(
        repaired.census_invalid,
        "carried pending keeps the census invalid"
    );
    assert_eq!(
        fix.heads_after, fix.heads_after_red,
        "accepted heads unchanged"
    );
    assert_eq!(fix.heads_after, base.heads_after);
    assert_eq!(
        fix.witness_after, fix.witness_after_red,
        "witness unchanged"
    );
    assert_eq!(fix.witness_after, base.witness_after);
    assert!(!fix.family_pending_after, "the complete census retires it");
    assert!(!base.family_pending_after);
}

/// Q4 strict: the witnessed family's pending from the red window is invalid
/// (the shape a cap or member-change invalidation leaves). The retry re-arms
/// it whole, exactly as BASE.
#[test]
#[serial(source_manifests)]
fn c1b_invalid_pending_keeps_base_rearm() {
    if !c1a_layout_supported("c1b_invalid_pending") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let invalidate = |fixture: &RearmFixture| {
        c1a_edit_index(fixture, |saved| {
            let pending = saved["claude_usage_family_pending"][REARM_ROOT]
                .as_object_mut()
                .expect("the red window keeps the family pending");
            pending.insert("member_request_id_hashes".to_owned(), serde_json::json!({}));
            pending.remove("member_occurrences");
            pending.insert("invalid".to_owned(), serde_json::json!(true));
        });
    };
    let fix = c1b_red_chain("c1b-invalid-pending", "fix", invalidate);
    let base = c1b_base_red_chain("c1b-invalid-pending-base", invalidate);
    let family = rearm_family_sessions().len();
    let retry = &fix.windows[2];
    assert_eq!(retry.family_reads, family, "the invalid family re-arms");
    assert_eq!(retry.family_reads, base.windows[2].family_reads);
    assert_eq!(retry.start, base.windows[2].start, "the start is BASE's");
    assert_eq!(c1b_liveness(&fix), c1b_liveness(&base));
}

/// SI I3 and Condition X(a): after the red window the root's API rows gain
/// account evidence, so the sidecar-inclusive selection fingerprint of every
/// member changes (M1). The carry keeps the committed revisions, the walk
/// re-reads every member exactly as BASE's re-arm does, and every window's
/// liveness equals BASE.
#[test]
#[serial(source_manifests)]
fn c1b_sidecar_changed_family_is_reread_like_base() {
    if !c1a_layout_supported("c1b_sidecar_changed") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let fix = c1b_red_chain("c1b-sidecar-changed", "fix", c1a_late_account_row);
    let base = c1b_base_red_chain("c1b-sidecar-changed-base", c1a_late_account_row);
    let family = rearm_family_sessions().len();
    assert_eq!(
        fix.windows[2].family_reads, family,
        "M1 re-selects every member"
    );
    assert_eq!(base.windows[2].family_reads, family);
    assert_eq!(c1b_liveness(&fix), c1b_liveness(&base));
    for (window, base_window) in fix.windows.iter().zip(&base.windows).skip(3) {
        assert_eq!(window.family_reads, base_window.family_reads);
    }
    assert_eq!(fix.heads_after, base.heads_after);
    assert_eq!(fix.witness_after, base.witness_after);
}

/// SOURCE B9: after the red window one subagent's transcript gains a request
/// without telemetry. The walk re-parses that member at the 08:20 retry
/// (`SourceChanged` instead of BASE's `Rearmed`), which cancels the family's
/// carry so its other members are read in the same window. Its liveness
/// equals BASE in every window.
#[test]
#[serial(source_manifests)]
fn c1b_changed_member_after_carry_is_reparsed() {
    if !c1a_layout_supported("c1b_changed_member") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let grow = |fixture: &RearmFixture| {
        RearmFixture::append(
            &fixture.member_path(Some(REARM_AGENTS[0])),
            &rearm_transcript_line(REARM_ROOT, Some(REARM_AGENTS[0]), "req_agent_a_2", 4),
        );
    };
    let fix = c1b_red_chain("c1b-changed-member", "fix", grow);
    let base = c1b_base_red_chain("c1b-changed-member-base", grow);
    let changed = rearm_member_session(Some(REARM_AGENTS[0]));
    assert!(fix.windows[2].parsed.contains(&changed), "re-parsed");
    assert!(base.windows[2].parsed.contains(&changed));
    assert_eq!(c1b_liveness(&fix), c1b_liveness(&base));
}

/// Condition X(b): the contract-5 record is lost after the red window (a
/// downgrade, then an upgrade). The retry start latches, nothing is carried,
/// and every retry re-reads the family exactly as BASE.
#[test]
#[serial(source_manifests)]
fn c1b_identity_contract_change_keeps_base_rearm() {
    if !c1a_layout_supported("c1b_identity_contract") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let forget = |fixture: &RearmFixture| {
        c1a_edit_index(fixture, |saved| {
            saved.remove("claude_request_identity_contract");
            saved.remove("claude_request_identity_contract_changed");
        });
    };
    let fix = c1b_red_chain("c1b-identity-contract", "fix", forget);
    let base = c1b_base_red_chain("c1b-identity-contract-base", forget);
    let family = rearm_family_sessions().len();
    for (window, base_window) in fix.windows.iter().zip(&base.windows).skip(2).take(2) {
        assert_eq!(window.family_reads, family, "the latch keeps the re-arm");
        assert_eq!(window.family_reads, base_window.family_reads);
        assert_eq!(window.start, base_window.start, "the start is BASE's");
    }
    assert_eq!(c1b_liveness(&fix), c1b_liveness(&base));
}

/// A request the provider ledger records for the first subagent from the
/// start, before its transcript holds it.
const C1B_RECORDED_REQUEST: &str = "req_agent_a_2";

/// The C1a fixture whose paired API and trace sidecars also record
/// `C1B_RECORDED_REQUEST` for the first subagent. Its transcript is a
/// nonempty subset of its assigned requests, so the family still proves.
fn c1b_recorded_request_fixture(case: &'static str, page_files: usize) -> RearmFixture {
    let mut fixture = c1a_fixture(case);
    fixture.native_file_limit = page_files;
    let (api, trace) = rearm_evidence_lines(Some(REARM_AGENTS[0]), C1B_RECORDED_REQUEST, 5);
    RearmFixture::append(&fixture.sidecar_path("claude-code-effort"), &api);
    RearmFixture::append(&fixture.sidecar_path("claude-code-trace-ownership"), &trace);
    fixture
}

/// Between the red window and its retry: the unrelated red producer is
/// repaired, and the first subagent's transcript gains the request its
/// provider ledger already holds, with matching usage. No sidecar changes.
fn c1b_repair_and_gain_recorded_request(fixture: &RearmFixture) {
    std::fs::write(
        c1b_sibling_path(fixture),
        rearm_transcript_line(REARM_SIBLING, None, &format!("req_{REARM_SIBLING}"), 0)
            + &rearm_transcript_line(REARM_SIBLING, None, "req_sibling_2", 1),
    )
    .expect("repair the unrelated transcript");
    RearmFixture::append(
        &fixture.member_path(Some(REARM_AGENTS[0])),
        &rearm_transcript_line(REARM_ROOT, Some(REARM_AGENTS[0]), C1B_RECORDED_REQUEST, 4),
    );
}

/// Runs the recoverable member change in a fix arm and a BASE arm and checks
/// that the 08:20 retry proves exactly as BASE: the carry is decided at the
/// start, the changed member's parse cancels it once, every member is read in
/// that same healthy window, and the proof, RetryPending, liveness, heads and
/// witness all equal BASE's.
fn c1b_assert_recoverable_change_proves_like_base(case: &'static str, page_files: usize) {
    let cancellations = crate::snapshots::claude_stale_family_carry_cancellations_for_test();
    let fix = c1b_red_chain_with(
        c1b_recorded_request_fixture(case, page_files),
        "fix",
        c1b_repair_and_gain_recorded_request,
    );
    assert_eq!(
        crate::snapshots::claude_stale_family_carry_cancellations_for_test(),
        cancellations + 1,
        "the changed member cancels the carry once"
    );
    let base = {
        let _base = crate::snapshots::KeepStaleClaudeFamilyRearmForTest::new();
        c1b_red_chain_with(
            c1b_recorded_request_fixture(case, page_files),
            "base",
            c1b_repair_and_gain_recorded_request,
        )
    };
    let family = rearm_family_sessions().len();
    let retry = &fix.windows[2];
    let base_retry = &base.windows[2];
    // Preconditions on BASE: the healthy retry re-reads the family and
    // re-proves it with the gained request, without RetryPending.
    assert!(base_retry.census_complete && !base_retry.red);
    assert_eq!(base_retry.family_reads, family);
    assert!(base_retry.proven && !base_retry.retry_pending);
    assert_ne!(base.witness_after, base.witness_after_red, "BASE re-proves");
    let start = retry.start.as_ref().expect("a retry start");
    assert_eq!(start.reason, "terminal_unhealthy_retry");
    assert_eq!(start.carried_pending_families, Some(1), "carried at start");
    // FLIPS: without the cancel only the changed member is read, the root's
    // absence fails the fresh proof and the family turns RetryPending.
    assert_eq!(retry.family_reads, family, "the family is co-observed");
    assert_eq!(retry.proven, base_retry.proven);
    assert_eq!(retry.retry_pending, base_retry.retry_pending);
    assert_eq!(c1b_liveness(&fix), c1b_liveness(&base));
    assert_eq!(fix.heads_after, base.heads_after);
    assert_eq!(fix.witness_after, base.witness_after);
}

/// SOURCE B9, the reviewed recoverable case: after the red window the first
/// subagent gains a request its provider ledger already recorded, and the red
/// producer is repaired. The subagent is read on the second page, after the
/// unchanged root was skipped on the first, so the cancel queues the root
/// again for a later bounded page of the same window.
#[test]
#[serial(source_manifests)]
fn c1b_recoverable_member_change_cancels_the_carry_and_proves_like_base() {
    if !c1a_layout_supported("c1b_recoverable_member_change") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    c1b_assert_recoverable_change_proves_like_base(
        "c1b-recoverable-member-change",
        REARM_PAGE_FILES,
    );
}

/// The same recoverable change with every window on one page, so the change
/// is discovered on the page that would have been the healthy terminal. The
/// cancel queues the already skipped root again, so the window gains one
/// bounded page instead of ending there, and the family still proves as BASE.
#[test]
#[serial(source_manifests)]
fn c1b_member_change_on_the_terminal_page_cancels_the_carry_like_base() {
    if !c1a_layout_supported("c1b_terminal_page_member_change") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    c1b_assert_recoverable_change_proves_like_base("c1b-terminal-page-member-change", 64);
}

/// SOURCE B9 held path, the remaining case: a member that disappears after
/// the red window yields no parse in the retry window, so nothing cancels the
/// carry there. BASE re-reads the remaining members; the fix keeps the
/// family's committed revisions and reads none of them, and the family takes
/// the ordinary path from the next start. The later windows are receipts only.
#[test]
#[serial(source_manifests)]
fn c1b_member_removed_after_carry_keeps_the_carry_in_the_window() {
    if !c1a_layout_supported("c1b_member_removed") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let run = |case: &'static str, arm: &str| {
        let fixture = c1a_fixture(case);
        c1b_generation(&fixture, arm, (8, 0));
        RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
        let red = c1b_generation(&fixture, arm, (8, 10));
        assert!(red.red, "{arm}: the window is red");
        std::fs::remove_file(fixture.member_path(Some(REARM_AGENTS[1])))
            .expect("remove the second subagent");
        let retry = c1b_generation(&fixture, arm, (8, 20));
        std::fs::write(
            c1b_sibling_path(&fixture),
            rearm_transcript_line(REARM_SIBLING, None, &format!("req_{REARM_SIBLING}"), 0),
        )
        .expect("repair the unrelated transcript");
        c1b_generation(&fixture, arm, (8, 30));
        retry
    };
    let cancellations = crate::snapshots::claude_stale_family_carry_cancellations_for_test();
    let retry = run("c1b-member-removed", "fix");
    assert_eq!(
        crate::snapshots::claude_stale_family_carry_cancellations_for_test(),
        cancellations,
        "no member parse cancels the carry"
    );
    let base_retry = {
        let _base = crate::snapshots::KeepStaleClaudeFamilyRearmForTest::new();
        run("c1b-member-removed-base", "base")
    };
    let remaining = rearm_family_sessions().len() - 1;
    assert_eq!(base_retry.family_reads, remaining, "BASE reads the rest");
    let start = retry.start.as_ref().expect("a retry start");
    assert_eq!(start.carried_pending_families, Some(1));
    assert_eq!(retry.family_reads, 0, "the carry stands in this window");
    assert_eq!(retry.red, base_retry.red);
}
