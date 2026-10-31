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

#[test]
#[serial(source_manifests)]
fn accepted_retry_no_otel_change_ack_then_carry_again() {
    if !c1a_layout_supported("accepted_body_retry") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = c1a_fixture("accepted-body-retry");
    let session = "e7000000-0000-4000-8000-000000000007";
    let path = fixture.root.join(format!("{session}.jsonl"));
    std::fs::write(
        &path,
        rearm_transcript_line(session, None, "req_accepted_1", 0),
    )
    .unwrap();
    let closing = c1b_generation(&fixture, "accepted", (8, 0));
    assert!(closing.census_complete && closing.full_rearm);
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    let seed = c1b_generation(&fixture, "accepted", (8, 10));
    assert!(seed.red && seed.parsed.contains(session));
    let before = c1a_saved(&fixture);
    assert!(before["claude_usage_family_witnesses"]
        .get(session)
        .is_none());
    let entry = |saved: &serde_json::Value| {
        saved["files"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(key, _)| key.ends_with(&format!("{session}.jsonl")))
            .unwrap()
            .1
            .clone()
    };
    let head = entry(&before)["last_snapshot_fingerprint"].clone();
    let retry = c1b_generation(&fixture, "accepted", (8, 20));
    assert_eq!(
        retry.start.as_ref().unwrap().reason,
        "terminal_unhealthy_retry"
    );
    assert!(
        !retry.parsed.contains(session),
        "no OTEL witness is needed for an accepted body"
    );
    RearmFixture::append(
        &path,
        &rearm_transcript_line(session, None, "req_accepted_2", 1),
    );
    let changed = c1b_generation(&fixture, "accepted", (8, 30));
    assert!(changed.parsed.contains(session));
    let accepted = c1a_saved(&fixture);
    assert_ne!(entry(&accepted)["last_snapshot_fingerprint"], head);
    assert!(entry(&accepted)["last_upload_body_witness"]
        .as_str()
        .is_some());
    let current = accepted["file_snapshot_fingerprints"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(key, _)| key.ends_with(&format!("{session}.jsonl")))
        .unwrap()
        .1
        .as_array()
        .unwrap();
    for fingerprint in current {
        assert!(accepted["accepted_snapshot_fingerprints"]
            .as_array()
            .unwrap()
            .contains(fingerprint));
    }
    let next = c1b_generation(&fixture, "accepted", (8, 40));
    assert_eq!(
        next.start.as_ref().unwrap().reason,
        "terminal_unhealthy_retry"
    );
    assert!(
        !next.parsed.contains(session),
        "the new exact ACK restores eligibility on the next retry"
    );
    assert_eq!(entry(&c1a_saved(&fixture)), entry(&accepted));
}

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
    /// Sessions whose body this window emitted as a request-owned (E2)
    /// literal; a listed family's bodies stay on ordinary money.
    request_owned: BTreeSet<String>,
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
                request_owned: pages
                    .iter()
                    .flat_map(|page| &page.scan.snapshots)
                    .filter(|item| {
                        item.usage_accounting_contract.as_deref()
                            == Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT)
                    })
                    .map(|item| item.source_session_id.clone())
                    .collect(),
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

/// Older C1b controls distinguish the witnessed target from unrelated
/// sessions whose local upload-body witness is unavailable. ACK ledger entries
/// and committed heads remain intact. The accepted-body tests and independent
/// acceptance fixture retain every witness and exercise the widened path.
fn c1b_without_unrelated_upload_witnesses(fixture: &RearmFixture) {
    let index = ScanIndex::load(&fixture.index_path).unwrap();
    let family = RearmFixture::family_keys(&index)
        .into_values()
        .collect::<BTreeSet<_>>();
    c1a_edit_index(fixture, |saved| {
        for (key, entry) in saved["files"].as_object_mut().unwrap() {
            if !family.contains(key) {
                entry
                    .as_object_mut()
                    .unwrap()
                    .remove("last_upload_body_witness");
            }
        }
    });
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
    c1b_without_unrelated_upload_witnesses(&fixture);
    let retry = c1b_generation(&fixture, arm, (8, 20));
    std::fs::write(
        c1b_sibling_path(&fixture),
        rearm_transcript_line(REARM_SIBLING, None, &format!("req_{REARM_SIBLING}"), 0)
            + &rearm_transcript_line(REARM_SIBLING, None, "req_sibling_2", 1),
    )
    .expect("repair the unrelated transcript");
    c1b_without_unrelated_upload_witnesses(&fixture);
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

/// This control measures C1b alone. Fix 2's window/cap has separate pipeline
/// coverage below and intentionally keeps eligible unwitnessed families too.
fn c1b_without_full_rearm_window(fixture: &RearmFixture) {
    c1a_edit_index(fixture, |saved| {
        let progress = saved
            .get_mut("claude_full_rearm_progress")
            .and_then(serde_json::Value::as_object_mut)
            .expect("the preceding full re-arm recorded progress");
        progress.remove("full_rearm_window");
        progress.remove("full_rearm_window_next");
    });
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
    let fix = c1b_red_chain("c1b-red-window", "fix", c1b_without_full_rearm_window);
    let base = c1b_base_red_chain("c1b-red-window-base", c1b_without_full_rearm_window);
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

/// Contract-only debt now defers the exactly ACKed family. Admission refusal
/// still takes BASE's whole re-arm; retain every original read/liveness
/// assertion in that arm, and separately assert the new no-read arm.
#[test]
#[serial(source_manifests)]
fn c1b_identity_contract_change_keeps_base_rearm() {
    if !c1a_layout_supported("c1b_identity_contract") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    for refused in [false, true] {
        let _budget =
            refused.then(|| crate::snapshots::ClaudeStaleFamilyCarryFundingBudgetForTest::new(0));
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
            if refused {
                assert_eq!(window.family_reads, family, "the latch keeps the re-arm");
                assert_eq!(window.family_reads, base_window.family_reads);
                assert_eq!(window.start, base_window.start, "the start is BASE's");
            } else {
                assert_eq!(
                    base_window.family_reads, family,
                    "BASE still reads every member"
                );
                assert_eq!(window.family_reads, 0, "contract-only debt adds no read");
                assert!(window.fence_after && window.census_invalid);
                assert!(!window.full_rearm, "no fresh uniqueness proof");
            }
        }
        if refused {
            assert_eq!(c1b_liveness(&fix), c1b_liveness(&base));
        }
        assert_eq!(fix.heads_after, base.heads_after);
        assert_eq!(fix.witness_after, base.witness_after);
    }
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

/// The recoverable member change in a fix arm and a BASE arm on pages of
/// `page_files` files, as (fix, BASE, cancellations, terminal holds) with the
/// fix arm's counter deltas.
fn c1b_recoverable_change_arms(
    case: &'static str,
    page_files: usize,
) -> (C1bRun, C1bRun, usize, usize) {
    c1b_recoverable_change_arms_listed(case, page_files, false)
}

/// `c1b_recoverable_change_arms`; with `listed`, both arms list the family
/// (a real list the retry's pages load) after the unlisted closing and red
/// windows, so the member change is read on ordinary money.
fn c1b_recoverable_change_arms_listed(
    case: &'static str,
    page_files: usize,
    listed: bool,
) -> (C1bRun, C1bRun, usize, usize) {
    let between = |fixture: &RearmFixture| {
        c1b_repair_and_gain_recorded_request(fixture);
        if listed {
            fixture.list_held(&[REARM_ROOT]);
        }
    };
    let cancellations = crate::snapshots::claude_stale_family_carry_cancellations_for_test();
    let holds = crate::snapshots::claude_stale_family_carry_terminal_holds_for_test();
    let fix = c1b_red_chain_with(
        c1b_recorded_request_fixture(case, page_files),
        "fix",
        between,
    );
    let cancelled =
        crate::snapshots::claude_stale_family_carry_cancellations_for_test() - cancellations;
    let held = crate::snapshots::claude_stale_family_carry_terminal_holds_for_test() - holds;
    let base = {
        let _base = crate::snapshots::KeepStaleClaudeFamilyRearmForTest::new();
        c1b_red_chain_with(
            c1b_recorded_request_fixture(case, page_files),
            "base",
            between,
        )
    };
    (fix, base, cancelled, held)
}

/// SOURCE B9 held path: the same change with every window on one page, so
/// the changed member is parsed on the page that ends the walk after the
/// unchanged root was already passed. BASE reads the whole family on that
/// terminal page and re-proves it there. Queueing the root would end the page
/// without its terminal fold, so the carry stays: only the changed member is
/// read, its pending lacks the root, and the family takes the ordinary path
/// to RetryPending. This is the remaining divergence from BASE.
#[test]
#[serial(source_manifests)]
fn c1b_member_change_on_the_walk_ending_page_keeps_the_held_path() {
    // Terminal-authority hold/rearm policy: E2 literal bodies bypass legacy
    // demotion (E2 rule 5), so the family is listed (ordinary money) after
    // the unlisted closing and red windows.
    if !c1a_layout_supported("c1b_terminal_page_member_change") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let (fix, base, cancelled, held) =
        c1b_recoverable_change_arms_listed("c1b-terminal-page-member-change", 64, true);
    assert_eq!((cancelled, held), (0, 1), "one hold, no cancel");
    let family = rearm_family_sessions().len();
    let retry = &fix.windows[2];
    let base_retry = &base.windows[2];
    // The listed retry reads the family on ordinary money; the unlisted
    // closing window (positive control) emitted request-owned bodies.
    for (arm, run) in [("fix", &fix), ("base", &base)] {
        assert!(
            rearm_family_sessions().is_subset(&run.windows[0].request_owned),
            "{arm}: unlisted family bodies are request-owned"
        );
        assert!(run.windows[2].family_reads > 0, "{arm}");
        assert!(
            run.windows[2]
                .request_owned
                .is_disjoint(&rearm_family_sessions()),
            "{arm}: no listed family body is request-owned"
        );
    }
    // BASE: the healthy terminal page re-reads and re-proves the family.
    assert!(base_retry.census_complete && !base_retry.red);
    assert_eq!(base_retry.family_reads, family);
    assert!(base_retry.proven && !base_retry.retry_pending);
    let start = retry.start.as_ref().expect("a retry start");
    assert_eq!(start.carried_pending_families, Some(1), "carried at start");
    assert_eq!(retry.family_reads, 1, "only the changed member is read");
    assert!(retry.retry_pending, "the ordinary path holds the family");
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
        c1b_without_unrelated_upload_witnesses(&fixture);
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

// Path-(a) bridge, corrected option (ii): a RetryPending authority family
// keeps its hold and quarantine and withholds the census, but authority debt
// alone no longer marks the bounded sweep unsettled. A same-context red retry
// may therefore carry unrelated, unchanged, witnessed families, while the
// held family itself is never carried, every other cause still marks the
// sweep, and the contract-5 latch and the unchanged-proof skip keep their
// meaning.

/// The unrelated terminal session's accepted head.
fn c1b_terminal_head(index: &ScanIndex) -> Option<String> {
    let suffix = format!("{REARM_TERMINAL}.jsonl");
    let key = index
        .files
        .keys()
        .find(|key| key.ends_with(&suffix))
        .expect("the unrelated terminal session is indexed");
    index.files[key].last_snapshot_fingerprint.clone()
}

struct C1bHeldRun {
    red: C1bWindow,
    retry: C1bWindow,
    marked_after_red: bool,
    record_after_red: Option<crate::snapshots::ClaudeAuthorityRecordForTest>,
    record_after_retry: Option<crate::snapshots::ClaudeAuthorityRecordForTest>,
    head_before: Option<String>,
    head_after: Option<String>,
}

/// The red chain with the unrelated terminal session made a RetryPending
/// authority family before the red window: its new revision is read there and
/// held. `before_retry` runs between the red window and its retry.
///
/// A request-owned (E2) body settles authority whatever the proof's health
/// (E2 rule 5), so the held family is listed after the unlisted closing
/// window: its later revisions are read on ordinary money and the legacy
/// authority hold applies, as for a protected family in production.
fn c1b_held_retry_chain(
    case: &'static str,
    arm: &str,
    before_retry: impl FnOnce(&RearmFixture),
) -> C1bHeldRun {
    let fixture = c1a_fixture(case);
    let closing = c1b_generation(&fixture, arm, (8, 0));
    assert!(closing.census_complete, "{arm}: the first census completes");
    assert!(closing.fence_after && closing.proven, "{arm}");
    assert!(
        closing.request_owned.contains(REARM_TERMINAL),
        "{arm}: positive control, the unlisted body is request-owned"
    );
    fixture.list_held(&[REARM_TERMINAL]);
    let mut index = ScanIndex::load(&fixture.index_path).unwrap();
    let head_before = c1b_terminal_head(&index);
    index.insert_retry_pending_claude_authority_for_test(REARM_TERMINAL);
    index.save(&fixture.index_path).unwrap();
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    RearmFixture::append(
        &c1b_terminal_path(&fixture),
        &rearm_transcript_line(REARM_TERMINAL, None, "req_terminal_2", 1),
    );
    let red = c1b_generation(&fixture, arm, (8, 10));
    assert!(red.red && !red.census_complete, "{arm}: the window is red");
    assert!(
        red.parsed.contains(REARM_TERMINAL),
        "{arm}: the held family's new revision is read"
    );
    assert!(
        !red.request_owned.contains(REARM_TERMINAL),
        "{arm}: the listed family is read on ordinary money"
    );
    let saved = ScanIndex::load(&fixture.index_path).unwrap();
    let marked_after_red = saved.bounded_sweep_had_unsettled_upload();
    let record_after_red = saved.claude_authority_record_for_test(REARM_TERMINAL);
    before_retry(&fixture);
    c1b_without_unrelated_upload_witnesses(&fixture);
    let retry = c1b_generation(&fixture, arm, (8, 20));
    let saved = ScanIndex::load(&fixture.index_path).unwrap();
    C1bHeldRun {
        red,
        retry,
        marked_after_red,
        record_after_red,
        record_after_retry: saved.claude_authority_record_for_test(REARM_TERMINAL),
        head_before,
        head_after: c1b_terminal_head(&saved),
    }
}

/// SOURCE, SI P2 and COST: an authority-only hold beside an unrelated
/// unchanged witnessed family. The red window holds the RetryPending family's
/// new revision without marking the sweep, so the same-context retry carries
/// the witnessed family (not read) while the held family is never carried: it
/// is read, held and kept exactly as the BASE arm does, its body is never
/// accepted, and its quarantine keeps its failure count and binding.
#[test]
#[serial(source_manifests)]
fn c1b_retry_pending_family_beside_witnessed_family_carries_only_the_witnessed_one() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion (E2 rule 5).

    if !c1a_layout_supported("c1b_retry_pending_beside_witnessed") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let fix = c1b_held_retry_chain("c1b-held-beside-witnessed", "fix", |_| {});
    let base = {
        let _base = crate::snapshots::KeepStaleClaudeFamilyRearmForTest::new();
        c1b_held_retry_chain("c1b-held-beside-witnessed-base", "base", |_| {})
    };
    for (arm, run) in [("fix", &fix), ("base", &base)] {
        // FLIPS on the pre-bridge head: authority debt marked every page.
        assert!(!run.marked_after_red, "{arm}: authority debt alone");
        let record = run.record_after_red.as_ref().expect("held family");
        assert!(
            !record.terminal && record.bound_to_retained_witness,
            "{arm}"
        );
        assert_eq!(record.failed_reconstruction_count, 2, "{arm}");
        let kept = run.record_after_retry.as_ref().expect("still quarantined");
        assert!(!kept.terminal && kept.bound_to_retained_witness, "{arm}");
        assert_eq!(
            (
                kept.failed_reconstruction_count,
                &kept.member_source_file_fingerprints
            ),
            (
                record.failed_reconstruction_count,
                &record.member_source_file_fingerprints
            ),
            "{arm}: no extra failure, same binding"
        );
        assert_eq!(run.head_after, run.head_before, "{arm}: never accepted");
        assert!(run.retry.red, "{arm}: the retry ends red again");
    }
    let start = fix.retry.start.as_ref().expect("a retry start");
    let base_start = base.retry.start.as_ref().expect("a retry start");
    assert_eq!(start.reason, "terminal_unhealthy_retry");
    assert_eq!(base_start.reason, start.reason);
    assert_eq!(
        start.carried_pending_families,
        Some(1),
        "the witnessed family"
    );
    assert_eq!(fix.retry.family_reads, 0, "the carried family is not read");
    assert_eq!(base.retry.family_reads, family, "BASE re-reads it");
    assert_eq!(
        fix.retry.parsed.contains(REARM_TERMINAL),
        base.retry.parsed.contains(REARM_TERMINAL),
        "the held family takes BASE's path"
    );
    assert_eq!(fix.red, base.red, "the red window is BASE's");
    assert_eq!(fix.retry.liveness(), base.retry.liveness());
}

/// COST: authority debt beside another cause on an ordinary red retry,
/// outside Fix 2's full-rearm-window exception. An unsettled mark already
/// left by another producer stays set; the retry carries nothing and re-reads
/// the witnessed family as BASE does.
#[test]
#[serial(source_manifests)]
fn c1b_retry_pending_debt_beside_an_existing_mark_keeps_base_rearm() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion (E2 rule 5).

    if !c1a_layout_supported("c1b_retry_pending_existing_mark") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let mark = |fixture: &RearmFixture| {
        c1a_edit_index(fixture, |saved| {
            assert!(
                saved.get("traversal").is_some(),
                "the red retry retains its walk"
            );
            assert!(
                saved.get("claude_stale_family_carry").is_none(),
                "no carry is retained yet"
            );
            // Missing independent request evidence keeps this refusal control
            // on BASE under the per-family relaxation too. Preserve all its
            // original no-carry/read/hold assertions. A companion below keeps
            // the evidence and verifies the newly approved carry instead.
            saved.remove("claude_request_census");
            // Absence of census/OTEL evidence is now allowed when the exact
            // upload-body witness is retained. This negative control lacks
            // that durable witness too; its original refusal assertions stay.
            for entry in saved["files"].as_object_mut().unwrap().values_mut() {
                entry
                    .as_object_mut()
                    .unwrap()
                    .remove("last_upload_body_witness");
            }

            // Select the ordinary C1b retry, outside Fix 2's window.
            let progress = saved
                .get_mut("claude_full_rearm_progress")
                .and_then(serde_json::Value::as_object_mut)
                .expect("the preceding full re-arm recorded its progress");
            assert!(
                progress.remove("full_rearm_window").is_some(),
                "explicitly leave Fix 2's window"
            );
            progress.remove("full_rearm_window_next");
            saved.insert(
                "bounded_sweep_had_unsettled_upload".to_owned(),
                serde_json::json!(true),
            );
        });
    };
    let run = c1b_held_retry_chain("c1b-held-existing-mark", "fix", mark);
    let start = run.retry.start.as_ref().expect("a retry start");
    assert_eq!(
        start.carried_pending_families,
        Some(0),
        "nothing is carried"
    );
    assert_eq!(run.retry.family_reads, rearm_family_sessions().len());
    assert!(run
        .record_after_retry
        .is_some_and(|record| !record.terminal));
}

/// Fix 2's exception remains active beside #705 authority debt and another
/// producer's unsettled mark: carry only the unchanged witnessed family,
/// retain the held family's proof debt, and match BASE's liveness/acceptance.
#[test]
#[serial(source_manifests)]
fn c1b_retry_pending_debt_beside_a_mark_in_a_full_rearm_window_keeps_fix2_carry() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion (E2 rule 5).

    if !c1a_layout_supported("c1b_held_mark_full_rearm_window") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let mark = |fixture: &RearmFixture| {
        c1a_edit_index(fixture, |saved| {
            assert!(
                saved
                    .get("claude_full_rearm_progress")
                    .and_then(|progress| progress.get("full_rearm_window"))
                    .is_some(),
                "retain Fix 2's full-rearm window"
            );
            saved.insert(
                "bounded_sweep_had_unsettled_upload".to_owned(),
                serde_json::json!(true),
            );
            // An unchanged, not-yet-due authority record normally skips its
            // transcript. Give this arm an independent parser-upgrade read
            // obligation so it also proves that a real held-family read is
            // never carried or accepted. Keep its revision, witness, retry
            // deadline and failure budget intact.
            let terminal_key = saved["files"]
                .as_object()
                .unwrap()
                .keys()
                .find(|key| key.ends_with(&format!("{REARM_TERMINAL}.jsonl")))
                .expect("the held terminal is indexed")
                .clone();
            let revision = saved["files"][&terminal_key]["source_file_fingerprint"].clone();
            let dispositions = saved
                .entry("terminal_jsonl_dispositions".to_owned())
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .unwrap();
            assert!(dispositions
                .insert(
                    terminal_key,
                    serde_json::json!({
                        "source_file_fingerprint": revision,
                        "parser_generation": "previous-parser-generation",
                        "loss": {}
                    }),
                )
                .is_none());
        });
    };
    let fix = c1b_held_retry_chain("c1b-held-mark-full-window", "fix", mark);
    let base = {
        let _base = crate::snapshots::KeepStaleClaudeFamilyRearmForTest::new();
        c1b_held_retry_chain("c1b-held-mark-full-window-base", "base", mark)
    };
    assert_eq!(
        fix.retry.start.as_ref().unwrap().carried_pending_families,
        Some(1)
    );
    assert_eq!(
        base.retry.start.as_ref().unwrap().carried_pending_families,
        Some(0)
    );
    assert_eq!(fix.retry.family_reads, 0, "the unchanged family is carried");
    assert_eq!(base.retry.family_reads, rearm_family_sessions().len());
    for (arm, run) in [("fix", &fix), ("base", &base)] {
        assert!(
            !run.marked_after_red,
            "{arm}: authority debt itself never marks the sweep"
        );
        assert!(
            run.retry.parsed.contains(REARM_TERMINAL),
            "{arm}: the held family is read"
        );
        let before = run
            .record_after_red
            .as_ref()
            .expect("authority debt before retry");
        let after = run
            .record_after_retry
            .as_ref()
            .expect("authority debt remains");
        assert!(!after.terminal && after.bound_to_retained_witness, "{arm}");
        assert_eq!(
            after.failed_reconstruction_count,
            before.failed_reconstruction_count
        );
        assert_eq!(
            after.member_source_file_fingerprints,
            before.member_source_file_fingerprints
        );
        assert_eq!(
            run.head_after, run.head_before,
            "{arm}: the held revision is never accepted"
        );
        assert!(
            run.retry.red && !after.terminal,
            "{arm}: the terminal family stays RetryPending"
        );
    }
    assert_eq!(fix.retry.liveness(), base.retry.liveness());
}

/// SI P1: after a contract change, a full re-arm terminal with one
/// RetryPending family keeps the contract-5 latch (and with it C1a's and
/// C1b's skips off) although that debt no longer marks the sweep. Once the
/// hold is released, the next clean terminal clears it.
#[test]
#[serial(source_manifests)]
fn c1a_contract_latch_survives_a_full_rearm_terminal_with_retry_pending_debt() {
    // Terminal-authority hold/rearm policy: E2 literal bodies bypass legacy
    // demotion (E2 rule 5), so the held family is listed (ordinary money)
    // after the unlisted closing window.
    if !c1a_layout_supported("c1a_latch_retry_pending_debt") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let fixture = c1a_fixture("c1a-latch-retry-pending-debt");
    let closing = c1a_window(&c1a_generation(&fixture, "fix", (8, 0)));
    assert!(closing.census_complete && closing.full_rearm && closing.fence_after);
    assert_eq!(c1a_latch(&fixture), (c1a_collector(), false));
    c1a_edit_index(&fixture, |saved| {
        saved.remove("claude_request_identity_contract");
        saved.remove("claude_request_identity_contract_changed");
    });
    fixture.list_held(&[REARM_TERMINAL]);
    let mut index = ScanIndex::load(&fixture.index_path).unwrap();
    index.insert_retry_pending_claude_authority_for_test(REARM_TERMINAL);
    index.save(&fixture.index_path).unwrap();
    c1a_full_rearm_due(&fixture);
    let held = c1a_window(&c1a_generation(&fixture, "fix", (8, 10)));
    assert_eq!(held.family_reads, family);
    assert!(!held.census_complete, "the census stays withheld");
    let saved = ScanIndex::load(&fixture.index_path).unwrap();
    assert!(saved
        .claude_authority_record_for_test(REARM_TERMINAL)
        .is_some_and(|record| !record.terminal && record.bound_to_retained_witness));
    // FLIPS on the pre-bridge head: the debt marked the sweep.
    assert!(!saved.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        c1a_latch(&fixture),
        (c1a_collector(), true),
        "authority debt keeps the latch"
    );
    c1a_edit_index(&fixture, |saved| {
        for field in [
            "claude_usage_authority_quarantine",
            "claude_usage_family_witnesses",
        ] {
            saved[field]
                .as_object_mut()
                .expect("a persisted map")
                .remove(REARM_TERMINAL);
        }
    });
    let cleared = c1a_window(&c1a_generation(&fixture, "fix", (8, 20)));
    assert!(cleared.census_complete);
    assert_eq!(
        c1a_latch(&fixture),
        (c1a_collector(), false),
        "the next clean terminal clears it"
    );
}

/// Fix 2's clean follow-up: the red 08:10 window, the full-rearm window the
/// 08:00 full re-arm opened, instead finished needing a clean follow-up (a
/// page of it settled partially), so the 08:20 start is a fresh walk.
fn fix2_clean_followup(fixture: &RearmFixture) {
    c1a_edit_index(fixture, |saved| {
        assert!(
            saved
                .get("claude_full_rearm_progress")
                .and_then(|progress| progress.get("full_rearm_window"))
                .is_some(),
            "the 08:10 start opened a full-rearm window"
        );
        saved.remove("traversal");
        saved.insert(
            "bounded_sweep_had_unsettled_upload".to_owned(),
            serde_json::json!(true),
        );
    });
}

/// Fix 2, real pipeline: the clean follow-up after the full-rearm window
/// carries the unchanged witnessed family, where BASE re-arms every stale
/// family. Unwitnessed sessions keep the re-arm, nothing is credited (the
/// census stays invalid while the fence stays closed), the accepted heads and
/// the witness never change, and every window's liveness equals BASE.
#[test]
#[serial(source_manifests)]
fn fix2_clean_followup_after_full_rearm_carries_unchanged_family() {
    if !c1a_layout_supported("fix2_clean_followup") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len() as u64;
    let fix = c1b_red_chain("fix2-clean-followup", "fix", fix2_clean_followup);
    let base = c1b_base_red_chain("fix2-clean-followup-base", fix2_clean_followup);
    let [_, _, followup, repaired, _] = &fix.windows;
    let [_, _, base_followup, _, _] = &base.windows;
    let start = followup.start.as_ref().expect("a follow-up start");
    let base_start = base_followup.start.as_ref().expect("a follow-up start");
    assert_eq!(start.reason, base_start.reason);
    assert_ne!(
        start.reason, "terminal_unhealthy_retry",
        "a clean follow-up"
    );
    assert_eq!(
        start.stale_pending_families,
        base_start.stale_pending_families
    );
    // Preconditions on BASE: the clean follow-up re-reads the family.
    assert_eq!(base_followup.family_reads as u64, family);
    assert_eq!(base_start.carried_pending_families, Some(0));
    // FLIPS: the unchanged family is carried, not re-read.
    assert_eq!(followup.family_reads, 0, "the carried family is not read");
    assert!(
        followup.parsed.contains(REARM_TERMINAL),
        "unwitnessed: BASE"
    );
    assert_eq!(start.carried_pending_families, Some(1));
    assert_eq!(start.carried_index_files, Some(family));
    assert_eq!(
        start.rearmed_index_files.map(|files| files + family),
        base_start.rearmed_index_files,
        "every other stale family keeps the BASE re-arm"
    );
    assert_eq!(
        c1b_liveness(&fix),
        c1b_liveness(&base),
        "liveness is BASE's"
    );
    assert!(repaired.census_complete && repaired.fence_before && repaired.fence_after);
    assert!(
        repaired.census_invalid,
        "no credit: the census stays invalid"
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
}

/// Exercise Condition X through the widened carry, using actual sidecars,
/// bounded scanner, proof fold, uploads, ACKs and save/reload between pages.
#[test]
#[serial(source_manifests)]
fn scoped_unhealthy_retry_late_identity_rows_reselect_and_emit_tagged_bodies() {
    // Contract-5 tagging oracle on ordinary money: a markerless single-account
    // request-owned (E2) body keeps the D1 wire shape without row tags, so the
    // family is listed before the late identity rows arrive.
    use sha2::{Digest, Sha256};
    if !c1a_layout_supported("scoped_retry_late_identity") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let mut fixture = c1a_fixture("scoped-retry-late-identity");
    let closing = c1b_generation(&fixture, "scoped", (8, 0));
    assert!(closing.census_complete && closing.proven && closing.full_rearm);
    assert!(
        closing.request_owned.contains(REARM_ROOT),
        "positive control: the unlisted root body is request-owned"
    );
    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
    RearmFixture::append(
        &c1b_terminal_path(&fixture),
        &rearm_transcript_line(REARM_TERMINAL, None, "req_terminal_2", 1),
    );
    let red = c1b_generation(&fixture, "scoped", (8, 10));
    assert!(red.red && red.proven);
    let unsettled = || {
        c1b_without_full_rearm_window(&fixture);
        c1b_without_unrelated_upload_witnesses(&fixture);
        let mut index = ScanIndex::load(&fixture.index_path).unwrap();
        index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::RejectedWithHolds);
        index.save(&fixture.index_path).unwrap();
    };
    unsettled();
    let retry = c1b_generation(&fixture, "scoped", (8, 20));
    assert_eq!(
        retry.start.as_ref().unwrap().carried_pending_families,
        Some(1)
    );
    assert_eq!(
        retry.family_reads, 0,
        "the independently accepted family is carried"
    );
    assert!(retry.red && retry.census_invalid && retry.fence_after);
    unsettled();
    // The family is listed after the unlisted baseline, so the late rows'
    // re-selected bodies are built on ordinary money.
    fixture.list_held(&[REARM_ROOT]);

    let login = "a".repeat(64);
    let org = "d".repeat(64);
    let path = fixture.sidecar_path("claude-code-effort");
    let rows = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            let mut row: crate::claude_local_otel::ClaudeLocalOtelEvidence =
                serde_json::from_str(line).unwrap();
            row.account_identity_checked = true;
            row.account_identifier_hash = Some(login.clone());
            row.request_identity = Some(serde_json::from_value(serde_json::json!({
            "identity_hash_scheme":"provider-sha256:v1", "disposition":"complete",
            "account":{"disposition":"complete", "origin":"log_record", "log_record_hash":login},
            "organization":{"disposition":"complete", "origin":"log_record", "log_record_hash":org},
        })).unwrap());
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            serde_json::to_string(&row).unwrap() + "\n"
        })
        .collect::<String>();
    std::fs::write(&path, rows).unwrap();
    // The changed API fingerprint needs a new complete family proof. Repair
    // the unrelated malformed file and co-observe the family in one normal
    // page, as the existing late-identity control does. Otherwise the old
    // witness correctly holds these revisions while the census stays red.
    std::fs::write(
        c1b_sibling_path(&fixture),
        rearm_transcript_line(REARM_SIBLING, None, &format!("req_{REARM_SIBLING}"), 0)
            + &rearm_transcript_line(REARM_SIBLING, None, "req_sibling_2", 1),
    )
    .unwrap();
    fixture.native_file_limit = 64;

    let mut parsed = BTreeSet::new();
    let mut tagged_root = None;
    let mut late = Vec::new();
    for number in 0..C1B_MAX_PAGES {
        let page = fixture.page(
            &format!("2026-08-02T08:{:02}:00Z", 30 + number),
            RearmUpload::Accept,
        );
        parsed.extend(page.parsed.iter().cloned());
        if let Some(item) = page
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == REARM_ROOT)
        {
            assert!(page.offered.contains(&item.snapshot_fingerprint));
            assert!(page.uploaded.contains(&item.snapshot_fingerprint));
            assert_ne!(
                item.usage_accounting_contract.as_deref(),
                Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT),
                "the listed root is on ordinary money"
            );
            assert!(!item.request_evidence.is_empty());
            assert!(item.request_evidence.iter().all(|evidence| {
                evidence.identity_basis == crate::snapshots::claude_request_identity::TELEMETRY
                    && evidence.provider_workspace_hash.as_deref() == Some(org.as_str())
            }));
            tagged_root = Some(item.snapshot_fingerprint.clone());
        }
        let ended = c1b_traversal_ended(&page.index).0;
        late.push(page);
        if ended {
            break;
        }
    }
    assert_eq!(
        parsed.intersection(&rearm_family_sessions()).count(),
        rearm_family_sessions().len(),
        "M1 re-selects every member"
    );
    let root =
        tagged_root.expect("late identity evidence emits and ACKs the tagged root in this retry");
    // Transferred from the deleted late-row controls (E2-054
    // c1a_late_identity_row_reselects_and_tags_skipped_family, E2-055
    // c1a_late_row_between_windows_equals_base, E2-065
    // c1b_sidecar_changed_family_is_reread_like_base, E2-071
    // fix2_late_api_row_rereads_the_family_like_base): the late evidence is
    // taken at normal cadence behind a closed fence, nothing is left
    // RetryPending, and the re-emitted root body is the durable accepted head
    // of a retained family proof (the heads/witness BASE's re-arm reaches).
    let last = late.last().expect("the late window has a page");
    assert!(
        !last.duplicate_census.full_rearm,
        "normal cadence, not the daily re-read"
    );
    assert!(last.duplicate_census.fence_before && last.duplicate_census.fence_after);
    assert!(
        late.iter().all(|page| !page
            .index
            .claude_authority_record_for_test(REARM_ROOT)
            .is_some_and(|record| !record.terminal)),
        "the late evidence leaves no RetryPending hold"
    );
    assert!(
        last.index.accepted_snapshot_fingerprint_recorded(&root),
        "durable accepted body"
    );
    let heads = RearmFixture::family_heads(&last.index);
    assert_eq!(
        heads[REARM_ROOT].as_deref(),
        Some(root.as_str()),
        "the re-emitted root is the accepted head"
    );
    assert!(
        last.index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .is_some(),
        "the family proof is retained"
    );
}

/// The approved complement of the existing missing-evidence refusal: a
/// global unsettled mark no longer makes a separately accepted family read
/// again; the unrelated RetryPending family keeps its binding and old head.
#[test]
#[serial(source_manifests)]
fn scoped_unhealthy_retry_beside_a_mark_and_authority_debt_carries_accepted_family() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion (E2 rule 5).

    if !c1a_layout_supported("scoped_retry_mark_and_authority") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let mark = |fixture: &RearmFixture| {
        c1b_without_full_rearm_window(fixture);
        c1a_edit_index(fixture, |saved| {
            saved.insert(
                "bounded_sweep_had_unsettled_upload".into(),
                serde_json::json!(true),
            );
        });
    };
    let run = c1b_held_retry_chain("scoped-retry-mark-and-authority", "scoped", mark);
    let start = run.retry.start.as_ref().unwrap();
    assert_eq!(start.reason, "terminal_unhealthy_retry");
    assert_eq!(start.carried_pending_families, Some(1));
    assert_eq!(run.retry.family_reads, 0);
    assert_eq!(run.record_after_retry, run.record_after_red);
    assert!(run
        .record_after_retry
        .as_ref()
        .is_some_and(|record| { !record.terminal && record.bound_to_retained_witness }));
    assert_eq!(run.head_after, run.head_before);
    assert!(run.retry.red && !run.retry.census_complete && run.retry.fence_after);
}

include!("retry_admission_pipeline_tests.rs");

// Mirror prepare's existing baseline ordering, then use the shared full pipeline
// and save/reload every synthetic page. No fixture alters acquisition policy.
fn latch_contract_generation(fixture: &RearmFixture, minute: usize) -> Vec<RearmPage> {
    source_latch_generation(fixture, minute, RearmUpload::Accept, None).0
}

fn source_latch_generation(
    fixture: &RearmFixture,
    minute: usize,
    upload: RearmUpload,
    target: Option<&str>,
) -> (Vec<RearmPage>, Vec<serde_json::Value>) {
    let mut pages = Vec::new();
    let mut diagnostics = Vec::new();
    for number in 0..C1B_MAX_PAGES {
        let mut index = ScanIndex::load(&fixture.index_path).unwrap();
        index.activate_effective_upload_body_witness_revision(cycle_body_witness_revision(
            SnapshotSource::ClaudeCode,
        ));
        // The page adopts, loads the real exclusion list and applies the
        // money rules (`RearmFixture::load_exclusion_list`), in
        // `finish_sync_source`'s order, on this index.
        index.observe_claude_request_identity_contract(fixture.request_identity);
        let (mut page, rows) = crate::local_resource_diagnostics::capture(|| {
            let fold_diagnostics =
                crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            let page = fixture.page_with_input_index(
                &format!("2026-08-02T08:{:02}:00Z", minute + number),
                upload,
                target,
                Some(index),
            );
            // Observe the real terminal fold, outside the scanner's nested
            // scopes, on the existing diagnostic carrier (test harness only).
            crate::local_resource_diagnostics::claude_reread::emit_without_lease(
                fold_diagnostics.finish(),
            );
            page
        });
        diagnostics.extend(rows);
        page.index.save(&fixture.index_path).unwrap();
        let ended = c1b_traversal_ended(&page.index).0;
        let interrupted = !matches!(upload, RearmUpload::Accept)
            && !page.fully_settled
            && page.offered.iter().any(|fp| !page.uploaded.contains(fp));
        pages.push(page);
        if ended || interrupted {
            return (pages, diagnostics);
        }
    }
    panic!("bounded fixture ends");
}

#[test]
#[serial(source_manifests)]
fn latch_contract_money_both_arms_preserve_accepted_grown_held_and_listed_bodies() {
    if !c1a_layout_supported("latch-contract-money") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    // Production's only cycle contract: the COLLECTOR (gate-off) arm is
    // unreachable with the gate retired (`compiled_cycle_contract` always
    // yields E2_GROUPING), and listing a session is not gate-off.
    {
        let contract = crate::snapshots::claude_request_identity::E2_GROUPING;
        crate::snapshots::claude_request_identity::with_cycle_contract_for_test(contract, || {
            for case in ["accepted", "held", "listed"] {
                for base in [false, true] {
                    let _base = base.then(crate::snapshots::KeepStaleClaudeFamilyRearmForTest::new);
                    let mut fixture = c1a_fixture("e3-latch-contract-money");
                    fixture.owned_base_preparation = true;
                    fixture.native_file_limit = 100;
                    let session = "e7000000-0000-4000-8000-000000000007";
                    let path = fixture.root.join(format!("{session}.jsonl"));
                    std::fs::write(
                        &path,
                        rearm_transcript_line(session, None, "req_latch_1", 0),
                    )
                    .unwrap();
                    if case == "held" {
                        fixture.local_holds.insert(session.to_owned());
                    }
                    let list = fixture
                        .support
                        .join("snapshots/claude_code-reemission-exclusions.txt");
                    std::fs::create_dir_all(list.parent().unwrap()).unwrap();
                    let listed = if case == "listed" {
                        format!("{:x}\n", sha2::Sha256::digest(session.as_bytes()))
                    } else {
                        String::new()
                    };
                    std::fs::write(list, listed).unwrap();
                    latch_contract_generation(&fixture, 0);
                    RearmFixture::append(&c1b_sibling_path(&fixture), "not-json\n");
                    c1a_edit_index(&fixture, |saved| {
                        for entry in saved["files"].as_object_mut().unwrap().values_mut() {
                            entry["source_file_fingerprint"] = serde_json::json!("");
                        }
                    });
                    latch_contract_generation(&fixture, 10);
                    let accepted = fixture.body_trace.borrow().finalizer_bodies[session].clone();
                    assert_eq!(accepted["input_tokens"], 10, "{case}/{base}/e2");
                    assert_eq!(accepted["output_tokens"], 10);
                    assert_eq!(accepted["request_count"], 1);
                    c1a_edit_index(&fixture, |saved| {
                        saved.insert(
                            "claude_request_identity_contract_changed".into(),
                            serde_json::json!(true),
                        );
                    });
                    let retry = latch_contract_generation(&fixture, 20);
                    let reads = rearm_parsed(&retry).contains(session);
                    if case == "accepted" {
                        assert_eq!(reads, base, "exact-ACK unchanged {base}/e2");
                        if !base {
                            assert_eq!(
                                fixture.body_trace.borrow().finalizer_bodies[session],
                                accepted
                            );
                        }
                    } else if case == "held" {
                        assert!(reads, "held keeps today's path {base}/e2");
                        assert!(retry.iter().all(|page| !page
                            .uploaded
                            .contains(accepted["snapshot_fingerprint"].as_str().unwrap())));
                    } else {
                        assert_eq!(
                            fixture.body_trace.borrow().finalizer_bodies[session]["input_tokens"],
                            10
                        );
                        assert_ne!(
                            fixture.body_trace.borrow().finalizer_bodies[session]
                                ["usage_accounting_contract"],
                            crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT
                        );
                    }
                    let saved = c1a_saved(&fixture);
                    assert_eq!(saved["claude_request_identity_contract_changed"], true);
                    assert_eq!(saved["claude_duplicate_request_witness_overflowed"], true);
                    assert!(retry.iter().all(|page| !page.scan.census_complete));
                    if case == "accepted" {
                        RearmFixture::append(
                            &path,
                            &rearm_transcript_line(session, None, "req_latch_2", 1),
                        );
                        let grown = latch_contract_generation(&fixture, 30);
                        assert!(rearm_parsed(&grown).contains(session));
                        let body = fixture.body_trace.borrow().finalizer_bodies[session].clone();
                        let cold = native_comparison_independent_history(&fixture);
                        let full = latch_contract_generation(&cold, 30);
                        assert!(rearm_parsed(&full).contains(session));
                        let expected = cold.body_trace.borrow().finalizer_bodies[session].clone();
                        assert_eq!(body["input_tokens"], 20);
                        assert_eq!(body["output_tokens"], 20);
                        assert_eq!(body["request_count"], 2);
                        assert_eq!(
                            body, expected,
                            "grown accepted body equals cold Full {base}/e2"
                        );
                    }
                }
            }
        });
    }
}

fn source_latch_clear_count(rows: &[serde_json::Value]) -> u64 {
    rows.iter()
        .filter_map(|row| row["counts"]["identity_contract_latch"]["cleared"].as_u64())
        .sum()
}

// SOURCE T1: a genuine Started record must not make a later mid-walk flip
// eligible for terminal clearing, even when the last page runs under B.
#[test]
#[serial(source_manifests)]
fn source_t1_started_a_then_b_keeps_placeholder_through_terminal() {
    if !c1a_layout_supported("source-t1-started-a-b") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    let mut fixture = c1a_fixture("source-t1-started-a-b");
    fixture.owned_base_preparation = true;
    fixture.request_identity = false;
    c1a_generation(&fixture, "A", (8, 0));
    assert_eq!(c1a_latch(&fixture), (Some(String::new()), false));
    let mut ended = false;
    for number in 0..C1A_MAX_PAGES {
        fixture.request_identity = number != 0;
        let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let page = fixture.page(
            &format!("2026-08-02T08:{:02}:00Z", 10 + number),
            RearmUpload::Accept,
        );
        let counts = diagnostics.finish().contract;
        ended = !page.index.scan_traversal_in_progress_for_test();
        if number == 0 {
            assert!(!ended, "B must arrive inside the Started A traversal");
            assert_eq!(c1a_latch(&fixture), (Some(String::new()), false));
        } else {
            assert_eq!(
                c1a_latch(&fixture),
                (Some(C1A_MID_TRAVERSAL.to_owned()), true)
            );
            assert_eq!(
                serde_json::to_value(&page.index).unwrap()
                    ["claude_request_identity_contract_changed"],
                true,
                "the durable save retains the latch"
            );
        }
        if ended {
            assert!(page.scan.census_complete && page.fully_settled);
            assert!(page.duplicate_census.fence_before && page.duplicate_census.fence_after);
            assert_eq!(
                counts.identity_contract_latch.cleared, 0,
                "the real fold cannot clear, independently of partial-save OR"
            );
            break;
        }
    }
    assert!(ended, "the B terminal was actually exercised");
    assert_eq!(
        c1a_latch(&fixture),
        (Some(C1A_MID_TRAVERSAL.to_owned()), true)
    );
}

// SOURCE T2: finish the invariant/current-contract G first while F remains
// owed. The next debt retry carries G, but must read and ACK F's new body.
#[test]
#[serial(source_manifests)]
fn source_t2_carried_g_cannot_clear_owed_f_before_new_body_ack() {
    if !c1a_layout_supported("source-t2-owed-f-invariant-g") {
        return;
    }
    let _manifests = SourceManifestTestGuard::new();
    for (upload, keep_held) in [
        (RearmUpload::Accept, false),
        (RearmUpload::AckLost, false),
        (RearmUpload::Accept, true),
    ] {
        let mut fixture = c1a_fixture("source-t2-owed-f-invariant-g");
        fixture.owned_base_preparation = true;
        fixture.native_file_limit = 2;
        c1a_add_family_request_identity(&fixture);
        {
            crate::snapshots::claude_request_identity::with_cycle_contract_for_test(
                crate::snapshots::claude_request_identity::COLLECTOR,
                || {
                    // Unlisted baseline: every file reaches revision 3 and
                    // the closing census re-arms them. Then F's and G's
                    // families are listed, so the re-read builds their
                    // contract-A bodies on ordinary money (the older daemon's
                    // state that A -> B migrates from).
                    latch_contract_generation(&fixture, 0);
                    fixture.list_held(&[REARM_ROOT, REARM_SIBLING]);
                    latch_contract_generation(&fixture, 10);
                },
            );
        }
        let old_f = fixture.body_trace.borrow().finalizer_bodies[REARM_ROOT].clone();
        for session in [REARM_ROOT, REARM_SIBLING] {
            assert_ne!(
                fixture.body_trace.borrow().finalizer_bodies[session]["usage_accounting_contract"],
                crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT,
                "{session}: the listed contract-A body is ordinary"
            );
        }
        // Keep the migration traversal red so G's accepted pending remains
        // available for the next start; only this unrelated file is repaired.
        RearmFixture::append(&c1b_terminal_path(&fixture), "not-json\n");

        crate::snapshots::claude_request_identity::with_cycle_contract_for_test(
            crate::snapshots::claude_request_identity::E2_GROUPING,
            || {
                fixture.local_holds.insert(REARM_ROOT.to_owned());
                // B runs unlisted: an installed, empty list.
                fixture.list_held(&[]);
                // #825 (card G (b)): A -> B itself re-owes nothing now. Owe
                // every file as its removed adoption loop did; another re-owe
                // path (path B, a money rule) leaves the same owed state.
                let mut owed = ScanIndex::load(&fixture.index_path).unwrap();
                for key in owed.files.keys().cloned().collect::<Vec<_>>() {
                    owed.re_owe_effective_upload_body_witness_revision(&key, 2);
                }
                owed.save(&fixture.index_path).unwrap();
                let migrated = latch_contract_generation(&fixture, 20);
                assert!(c1a_latch(&fixture).1, "F is still owed after A -> B");
                let saved = c1a_saved(&fixture);
                let f_key = fixture.member_path(None).to_string_lossy().into_owned();
                let g_key = c1b_sibling_path(&fixture).to_string_lossy().into_owned();
                assert_eq!(
                    saved["files"][&f_key]["effective_upload_body_witness_revision"],
                    2
                );
                assert_eq!(
                    saved["files"][&g_key]["effective_upload_body_witness_revision"],
                    3
                );
                let invariant_g =
                    fixture.body_trace.borrow().finalizer_bodies[REARM_SIBLING].clone();
                assert_eq!(
                    invariant_g["usage_accounting_contract"],
                    crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT,
                    "positive control: unlisted under B, G's body is request-owned"
                );
                let g_fp = invariant_g["snapshot_fingerprint"].as_str().unwrap();
                assert!(saved["claude_request_census"].get(&g_key).is_some());
                assert!(migrated.iter().any(|page| page.uploaded.contains(g_fp)));
                // An id-less companion settles its own revision but cannot
                // carry under contract debt: G must be the only such family.
                std::fs::write(
                    c1b_terminal_path(&fixture),
                    serde_json::json!({
                        "timestamp":"2026-08-02T07:00:00Z", "type":"assistant",
                        "sessionId":REARM_TERMINAL,
                        "message":{"model":"claude-haiku-4-5",
                            "usage":{"input_tokens":10,"output_tokens":10}},
                    })
                    .to_string()
                        + "\n",
                )
                .unwrap();
                // The repaired terminal also owes B's revision. Its fold
                // runs BEFORE its ACK stamps revision 3, so settle it while
                // F is still held: the target retry must owe only F, rather
                // than correctly retain the latch for this unrelated file.
                // Keep this warm-up incomplete: a complete fold retires G's
                // stale pending (:9924), which the target retry must carry.
                let invalid_path = c1a_invalid_path(&fixture);
                let invalid_body = std::fs::read(&invalid_path).unwrap();
                RearmFixture::append(&invalid_path, "not-json\n");
                let (prepared, prepared_rows) =
                    source_latch_generation(&fixture, 25, RearmUpload::Accept, None);
                assert!(!prepared.last().unwrap().scan.census_complete);
                assert!(!rearm_parsed(&prepared).contains(REARM_SIBLING));
                assert!(c1a_latch(&fixture).1, "held F still forbids clearing");
                assert_eq!(source_latch_clear_count(&prepared_rows), 0);
                let prepared_index = c1a_saved(&fixture);
                assert_eq!(
                    prepared_index["files"][&f_key]["effective_upload_body_witness_revision"],
                    2
                );
                assert!(prepared_index["claude_usage_family_pending"]
                    .get(REARM_SIBLING)
                    .is_some());
                assert_eq!(
                    prepared_index["claude_usage_family_pending"][REARM_TERMINAL]["invalid"], true,
                    "the paid companion must remain ineligible for contract-debt carry"
                );
                for path in [c1a_invalid_path(&fixture), c1b_terminal_path(&fixture)] {
                    assert_eq!(
                        prepared_index["files"][path.to_string_lossy().as_ref()]
                            ["effective_upload_body_witness_revision"],
                        3
                    );
                }
                for (key, entry) in prepared_index["files"].as_object().unwrap() {
                    assert_eq!(
                        entry["effective_upload_body_witness_revision"],
                        if key == &f_key { 2 } else { 3 },
                        "only F may remain owed before the target retry"
                    );
                }
                assert_eq!(
                    prepared_index["claude_request_census"].get(&g_key),
                    saved["claude_request_census"].get(&g_key),
                    "preparing the unrelated terminal gives G no new credit"
                );
                std::fs::write(invalid_path, invalid_body).unwrap();
                if !keep_held {
                    fixture.local_holds.clear();
                } else {
                    // An earlier-page hold withholds the effective census
                    // (:30247). Put the held probe on one page so its fold
                    // actually reaches the owed-revision terminal veto.
                    fixture.native_file_limit = 64;
                }
                let (retry, rows) = source_latch_generation(&fixture, 30, upload, Some(REARM_ROOT));
                let carried = rows
                    .iter()
                    .filter(|row| {
                        row["stage"] == "bounded_traversal_transition"
                            && row["counts"]["event"] == "starting"
                    })
                    .map(|row| {
                        row["counts"]["carried_pending_families"]
                            .as_u64()
                            .unwrap_or(0)
                    })
                    .sum::<u64>();
                assert_eq!(carried, 1, "only invariant G can be carried");
                assert!(
                    !rearm_parsed(&retry).contains(REARM_SIBLING),
                    "G adds no read"
                );
                assert!(
                    rearm_parsed(&retry).contains(REARM_ROOT),
                    "owed F cannot carry"
                );
                let new_f = fixture.body_trace.borrow().finalizer_bodies[REARM_ROOT].clone();
                let f_fp = new_f["snapshot_fingerprint"].as_str().unwrap();
                if !keep_held {
                    assert_ne!(new_f["snapshot_fingerprint"], old_f["snapshot_fingerprint"]);
                }
                assert_eq!(
                    fixture.body_trace.borrow().finalizer_bodies[REARM_SIBLING],
                    invariant_g
                );
                if !keep_held {
                    assert!(
                        retry.iter().any(|page| page.offered.contains(f_fp)),
                        "F re-emits"
                    );
                }
                assert!(retry.iter().all(|page| page.duplicate_census.fence_after));
                assert!(retry.iter().all(|page| !page.duplicate_census.full_rearm));
                assert!(
                    !retry.last().unwrap().transcript_ownership_complete,
                    "G supplies no current-contract ownership/projection completeness"
                );
                let mut acked_f = false;
                for page in &retry {
                    acked_f |= page.uploaded.contains(f_fp);
                    let state = serde_json::to_value(&page.index).unwrap();
                    if !acked_f {
                        assert_eq!(state["claude_request_identity_contract_changed"], true);
                    }
                    // G's retained accepted body is never current-window
                    // request projection or fence/uniqueness evidence.
                    let record = state["claude_request_census"]
                        .get(&g_key)
                        .expect("G keeps its old census record");
                    assert_eq!(record, saved["claude_request_census"].get(&g_key).unwrap());
                }
                if keep_held {
                    let terminal = retry.last().unwrap();
                    assert!(
                        terminal.scan.census_complete,
                        "exercise a real terminal clear decision"
                    );
                    assert!(!terminal.fully_settled);
                    assert!(!terminal.duplicate_census.coverage_complete);
                    assert!(!acked_f);
                    assert!(c1a_latch(&fixture).1);
                    let held = c1a_saved(&fixture);
                    assert_eq!(
                        held["files"][&f_key]["effective_upload_body_witness_revision"],
                        2
                    );
                    // snapshots.rs:9730 (e2_identity_owed) vetoes; :9722
                    // adds a veto when an earlier page recorded F's hold.
                    let cleared = source_latch_clear_count(&rows);
                    assert_eq!(cleared, 0, "partial-save OR cannot mask an in-memory clear");
                    fixture.local_holds.clear();
                    // F's ACK must precede the terminal fold, which checks
                    // owed revisions before this page's upload can stamp.
                    fixture.native_file_limit = 1;
                    let (accepted, release_rows) =
                        source_latch_generation(&fixture, 40, RearmUpload::Accept, None);
                    assert!(!accepted.first().unwrap().scan.census_complete);
                    assert!(accepted.last().unwrap().scan.census_complete);
                    assert_eq!(
                        source_latch_clear_count(&release_rows),
                        1,
                        "positive control: the real fold clear is observable"
                    );
                    let body = fixture.body_trace.borrow().finalizer_bodies[REARM_ROOT].clone();
                    let fp = body["snapshot_fingerprint"].as_str().unwrap();
                    assert_ne!(body["snapshot_fingerprint"], old_f["snapshot_fingerprint"]);
                    assert!(accepted.first().unwrap().uploaded.contains(fp));
                    assert!(accepted.iter().any(|page| page.uploaded.contains(fp)));
                    assert!(
                        !c1a_latch(&fixture).1,
                        "clear only after the release's exact ACK"
                    );
                    assert_eq!(
                        c1a_saved(&fixture)["files"][&f_key]
                            ["effective_upload_body_witness_revision"],
                        3
                    );
                    return;
                }
                match upload {
                    RearmUpload::Accept => {
                        assert!(acked_f);
                        assert!(!c1a_latch(&fixture).1, "clear follows F's exact ACK");
                        let accepted = c1a_saved(&fixture);
                        assert_eq!(
                            accepted["files"][&f_key]["effective_upload_body_witness_revision"],
                            3
                        );
                        assert_eq!(
                            accepted["claude_request_identity_contract"],
                            crate::snapshots::claude_request_identity::E2_GROUPING
                        );
                    }
                    RearmUpload::AckLost => {
                        assert!(!acked_f);
                        assert!(c1a_latch(&fixture).1, "partial save preserves owed F");
                        let saved = c1a_saved(&fixture);
                        assert_eq!(
                            saved["files"][&f_key]["effective_upload_body_witness_revision"],
                            2
                        );
                    }
                    RearmUpload::Shed => unreachable!(),
                }
            },
        );
    }
}
