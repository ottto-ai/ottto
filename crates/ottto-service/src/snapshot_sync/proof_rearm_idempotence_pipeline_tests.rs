// C1a: idempotent terminal proof re-arm while the duplicate fence stays
// closed. These run the stable-proof re-arm fixture (`RearmFixture`) through
// the real bounded pipeline, with real local OTEL sidecars, in-process ACKs and
// a save/reload between pages. One extra transcript has an assistant usage
// line without a `requestId`; its family pending is invalid, so the first
// complete census closes the duplicate fence and every later one keeps it
// closed. Generations run on minute clocks so that no closed-fence full
// re-arm deadline (one hour after the first close) falls inside a test unless
// the test moves it.
//
// A "BASE arm" runs the same steps under `RefuseClaudeUnchangedProofBudgetForTest`,
// which refuses the unchanged-proof scratch budget and therefore takes the
// BASE proof re-arm at every terminal. Each generation writes one count-only
// `C1A_PROOF_REARM` line to stderr, outside the harness capture.

use super::*;

const C1A_MAX_PAGES: usize = 8;
/// Request-id-less transcript that keeps the duplicate fence closed. It sits
/// on the terminal page beside the unrelated terminal session.
const C1A_INVALID: &str = "c0000000-0000-4000-8000-000000000000";
const C1A_IMPORT: &str = "d4444444-4444-4444-8444-444444444444";
const C1A_MID_TRAVERSAL: &str = "changed_within_traversal";

/// Count-only shape of one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct C1aWindow {
    pages: usize,
    reads: usize,
    family_reads: usize,
    family_offered: usize,
    semantic_noops: usize,
    debt: usize,
    census_complete: bool,
    fence_before: bool,
    fence_after: bool,
    full_rearm: bool,
    retry_pending: bool,
    proven: bool,
}

fn c1a_window(pages: &[RearmPage]) -> C1aWindow {
    let family = rearm_family_sessions();
    let last = pages.last().expect("terminal page");
    C1aWindow {
        pages: pages.len(),
        reads: rearm_reads(pages),
        family_reads: rearm_parsed(pages).intersection(&family).count(),
        family_offered: pages
            .iter()
            .map(|page| {
                page.scan
                    .snapshots
                    .iter()
                    .filter(|item| {
                        family.contains(&item.source_session_id)
                            && page.offered.contains(&item.snapshot_fingerprint)
                    })
                    .count()
            })
            .sum(),
        semantic_noops: pages.iter().map(|page| page.scan.semantic_noop_count).sum(),
        debt: RearmFixture::family_rearm_debt(&last.index),
        census_complete: last.scan.census_complete,
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
    }
}

fn c1a_receipt(fixture: &RearmFixture, arm: &str, at: &str, window: &C1aWindow) {
    let (contract, latched) = c1a_latch(fixture);
    writeln!(
        std::io::stderr().lock(),
        "C1A_PROOF_REARM case={} arm={arm} at={at} contract_recorded={} contract_latched={latched} {window:?}",
        fixture.case,
        contract.is_some()
    )
    .unwrap();
}

fn c1a_layout_supported(test: &str) -> bool {
    if crate::heap_layout_bound::layout_supported() {
        return true;
    }
    writeln!(
        std::io::stderr().lock(),
        "C1A_PROOF_REARM test={test} supported_positive=UNEXECUTED"
    )
    .unwrap();
    false
}

fn c1a_invalid_path(fixture: &RearmFixture) -> PathBuf {
    fixture
        .root
        .join("zz-terminal")
        .join("nested")
        .join(format!("{C1A_INVALID}.jsonl"))
}

/// The re-arm fixture plus the request-id-less transcript, under a contract-5
/// identity permit unless the test changes it. No exclusion list is installed
/// (production's always-on path); a test that needs a family on ordinary
/// money lists only that family with `list_held` after an unlisted baseline.
fn c1a_fixture(case: &'static str) -> RearmFixture {
    let mut fixture = RearmFixture::new(case);
    fixture.request_identity = true;
    std::fs::write(
        c1a_invalid_path(&fixture),
        format!(
            "{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{C1A_INVALID}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
        ),
    )
    .expect("write the request-id-less transcript");
    fixture
}

/// One bounded traversal on minute clocks. `interrupt` sheds or loses the
/// ACK of the batch holding that session on page `number`; `before` runs
/// before every later page with that page's number.
fn c1a_generation_with(
    fixture: &RearmFixture,
    arm: &str,
    (hour, minute): (u32, usize),
    interrupt: Option<(usize, RearmUpload, &str)>,
    mut before: impl FnMut(usize),
) -> Vec<RearmPage> {
    let mut pages = Vec::new();
    for number in 0..C1A_MAX_PAGES {
        if number > 0 {
            before(number);
        }
        let at = format!("2026-08-02T{hour:02}:{:02}:00Z", minute + number);
        let page = match interrupt {
            Some((page_number, upload, session)) if page_number == number => {
                fixture.page_with_targeted_upload(&at, upload, Some(session))
            }
            _ => fixture.page(&at, RearmUpload::Accept),
        };
        let ended = !page.index.scan_traversal_in_progress_for_test();
        pages.push(page);
        if ended {
            let at = format!("2026-08-02T{hour:02}:{minute:02}:00Z");
            c1a_receipt(fixture, arm, &at, &c1a_window(&pages));
            return pages;
        }
    }
    panic!("the generation ends within {C1A_MAX_PAGES} bounded pages");
}

fn c1a_generation(fixture: &RearmFixture, arm: &str, clock: (u32, usize)) -> Vec<RearmPage> {
    c1a_generation_with(fixture, arm, clock, None, |_| {})
}

/// One traversal whose page `n` runs with `identity[n]` (the last entry for
/// later pages) as its contract-5 permit.
fn c1a_generation_with_identity(
    fixture: &mut RearmFixture,
    arm: &str,
    (hour, minute): (u32, usize),
    identity: &[bool],
) -> Vec<RearmPage> {
    let mut pages = Vec::new();
    for number in 0..C1A_MAX_PAGES {
        fixture.request_identity = identity[number.min(identity.len() - 1)];
        let at = format!("2026-08-02T{hour:02}:{:02}:00Z", minute + number);
        let page = fixture.page(&at, RearmUpload::Accept);
        let ended = !page.index.scan_traversal_in_progress_for_test();
        pages.push(page);
        if ended {
            let at = format!("2026-08-02T{hour:02}:{minute:02}:00Z");
            c1a_receipt(fixture, arm, &at, &c1a_window(&pages));
            return pages;
        }
    }
    panic!("the generation ends within {C1A_MAX_PAGES} bounded pages");
}

fn c1a_saved(fixture: &RearmFixture) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(&fixture.index_path).expect("read the saved index"))
        .expect("decode the saved index")
}

/// The saved contract-5 record and latch, as the next process reads them.
fn c1a_latch(fixture: &RearmFixture) -> (Option<String>, bool) {
    let saved = c1a_saved(fixture);
    (
        saved
            .get("claude_request_identity_contract")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        saved
            .get("claude_request_identity_contract_changed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    )
}

fn c1a_edit_index(
    fixture: &RearmFixture,
    edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) {
    let mut saved = c1a_saved(fixture);
    edit(saved.as_object_mut().expect("the saved index is an object"));
    std::fs::write(
        &fixture.index_path,
        serde_json::to_vec(&saved).expect("encode the edited index"),
    )
    .expect("write the edited index");
}

/// Make the closed-fence full re-arm due at the next complete census.
fn c1a_full_rearm_due(fixture: &RearmFixture) {
    c1a_edit_index(fixture, |saved| {
        saved.insert(
            "claude_duplicate_fence_next_full_rearm_unix_seconds".to_owned(),
            serde_json::json!(1),
        );
    });
}

fn c1a_collector() -> Option<String> {
    Some(crate::snapshots::claude_request_identity::COLLECTOR.to_owned())
}

/// Shared first two generations: the fence closes on the first complete
/// census (a full re-arm), and the second re-proves the family with every
/// member read and the fence closed before and after.
fn c1a_close_and_reprove(fixture: &RearmFixture, arm: &str) -> (C1aWindow, C1aWindow) {
    let family = rearm_family_sessions().len();
    let closing = c1a_window(&c1a_generation(fixture, arm, (8, 0)));
    assert!(closing.census_complete, "{arm}: first census completes");
    assert!(!closing.fence_before, "{arm}: the fence starts open");
    assert!(closing.fence_after, "{arm}: the invalid census closes it");
    assert!(closing.full_rearm, "{arm}: the close is a full re-arm");
    assert!(closing.proven, "{arm}: the family is proven");
    assert_eq!(closing.debt, family, "{arm}: the first proof re-arms");
    let reproved = c1a_window(&c1a_generation(fixture, arm, (8, 10)));
    assert!(reproved.census_complete, "{arm}");
    assert!(reproved.fence_before && reproved.fence_after, "{arm}");
    assert!(!reproved.full_rearm, "{arm}: no deadline is due");
    assert!(reproved.proven, "{arm}");
    assert!(!reproved.retry_pending, "{arm}");
    assert_eq!(reproved.family_reads, family, "{arm}: every member read");
    (closing, reproved)
}

/// T1, closed fence: once an unchanged proof was re-proved from members read
/// in its own window and their bodies were accepted, the terminal re-arms
/// nothing and the next window reads nothing. The BASE arm re-arms all three
/// members at every terminal and re-reads them as semantic no-ops.
#[test]
#[serial(source_manifests)]
fn c1a_closed_fence_unchanged_proof_rearms_nothing_after_its_reproof() {
    if !c1a_layout_supported("c1a_closed_fence_unchanged_proof") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();

    let fixture = c1a_fixture("c1a-closed-fence-skip");
    let (closing, reproved) = c1a_close_and_reprove(&fixture, "fix");
    let proof = ScanIndex::load(&fixture.index_path)
        .unwrap()
        .claude_usage_family_witness_digest_for_test(REARM_ROOT);
    let heads = RearmFixture::family_heads(&ScanIndex::load(&fixture.index_path).unwrap());
    assert_eq!(c1a_latch(&fixture), (c1a_collector(), false));
    // FLIPS on BASE: the unchanged proof keeps its earlier-page members.
    assert_eq!(reproved.debt, 0, "the unchanged re-proof re-arms nothing");
    let quiet = c1a_generation(&fixture, "fix", (8, 20));
    let quiet_window = c1a_window(&quiet);
    assert_eq!(quiet_window.family_reads, 0);
    assert_eq!(quiet_window.reads, 0, "nothing else changed either");
    assert_eq!(quiet_window.debt, 0);
    assert!(quiet_window.fence_before && quiet_window.fence_after);
    assert!(!quiet_window.full_rearm);
    assert!(!quiet_window.retry_pending);
    let last = &quiet.last().unwrap().index;
    assert_eq!(
        last.claude_usage_family_witness_digest_for_test(REARM_ROOT),
        proof
    );
    assert_eq!(RearmFixture::family_heads(last), heads);

    let base = c1a_fixture("c1a-closed-fence-base");
    let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
    let fallbacks = crate::snapshots::claude_unchanged_proof_budget_fallbacks_for_test();
    let (base_closing, base_reproved) = c1a_close_and_reprove(&base, "base");
    assert_eq!(base_closing, closing, "the closing window is BASE's");
    assert_eq!(
        C1aWindow {
            debt: reproved.debt,
            ..base_reproved.clone()
        },
        reproved,
        "the re-proof window differs from BASE only in its terminal debt"
    );
    assert_eq!(base_reproved.debt, family, "BASE re-arms every member");
    let base_quiet = c1a_window(&c1a_generation(&base, "base", (8, 20)));
    assert_eq!(base_quiet.family_reads, family);
    assert_eq!(
        base_quiet.family_offered, 0,
        "BASE re-reads semantic no-ops"
    );
    assert_eq!(base_quiet.semantic_noops, family);
    assert_eq!(base_quiet.debt, family);
    assert!(
        crate::snapshots::claude_unchanged_proof_budget_fallbacks_for_test() > fallbacks,
        "the refused arm took the counted BASE fallback"
    );
}

/// Fallback equals BASE: with the unchanged-proof scratch refused, every
/// window equals the BASE windows this fixture produced on the baseline
/// commit (its `C1A_PROOF_REARM case=c1a-fallback-refused` receipts), and the
/// fallback is counted.
#[test]
#[serial(source_manifests)]
fn c1a_refused_budget_fallback_equals_base() {
    // BASE (recorded gate-off) re-offered the unchanged family at 08:10. On
    // the always-on path the re-read family is a semantic no-op: no re-upload,
    // so the accepted heads stay those of 08:00.
    if !c1a_layout_supported("c1a_refused_budget_fallback") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let window = |reads, family_offered, semantic_noops, fence_before, full_rearm| C1aWindow {
        pages: 3,
        reads,
        family_reads: 3,
        family_offered,
        semantic_noops,
        debt: 3,
        census_complete: true,
        fence_before,
        fence_after: true,
        full_rearm,
        retry_pending: false,
        proven: true,
    };
    let base = [
        window(6, 3, 0, false, true),
        window(6, 0, 6, true, false),
        window(3, 0, 3, true, false),
    ];
    let refused = c1a_fixture("c1a-fallback-refused");
    let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
    let fallbacks = crate::snapshots::claude_unchanged_proof_budget_fallbacks_for_test();
    let mut heads = Vec::new();
    let windows = [(8, 0), (8, 10), (8, 20)].map(|clock| {
        let pages = c1a_generation(&refused, "refused", clock);
        heads.push(RearmFixture::family_heads(
            &pages.last().expect("terminal page").index,
        ));
        c1a_window(&pages)
    });
    assert_eq!(windows, base, "the refused fallback is BASE");
    assert_eq!(heads[0].len(), rearm_family_sessions().len());
    assert!(
        heads[0].values().all(Option::is_some),
        "08:00 accepts every member's body"
    );
    assert_eq!(heads[1], heads[0], "08:10 re-uploads nothing");
    assert_eq!(heads[2], heads[0], "08:20 re-uploads nothing");
    assert!(
        crate::snapshots::claude_unchanged_proof_budget_fallbacks_for_test() > fallbacks,
        "the fallback is counted"
    );
}

/// Positive control, changed witness: in a closed-fence window that reads
/// every member, a subagent gains a request after the family pages and before
/// the terminal page. The window reads and proves exactly as under BASE, and
/// when the terminal's witness changed every member re-arms.
#[test]
#[serial(source_manifests)]
fn c1a_changed_witness_rearms_like_base() {
    if !c1a_layout_supported("c1a_changed_witness") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let digest = |fixture: &RearmFixture| {
        ScanIndex::load(&fixture.index_path)
            .unwrap()
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
    };
    let run = |fixture: &RearmFixture, arm: &str| {
        let closing = c1a_window(&c1a_generation(fixture, arm, (8, 0)));
        let before = digest(fixture);
        let changed = c1a_window(&c1a_generation_with(
            fixture,
            arm,
            (8, 10),
            None,
            |number| {
                if number == 2 {
                    fixture.append_family_request(Some(REARM_AGENTS[0]), "req_agent_a_2", 4, 5);
                }
            },
        ));
        let witness_changed = changed.proven && digest(fixture) != before;
        let after = c1a_window(&c1a_generation(fixture, arm, (8, 20)));
        (closing, changed, witness_changed, after)
    };
    let fixture = c1a_fixture("c1a-changed-witness");
    let (closing, changed, witness_changed, after) = run(&fixture, "fix");
    let base = c1a_fixture("c1a-changed-witness-base");
    let (base_closing, base_changed, base_witness_changed, base_after) = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    assert_eq!(closing, base_closing);
    assert_eq!(changed.family_reads, family, "both arms read every member");
    assert_eq!(witness_changed, base_witness_changed);
    assert_eq!(
        C1aWindow {
            debt: changed.debt,
            ..base_changed.clone()
        },
        changed,
        "the changed window reads and proves as BASE"
    );
    if witness_changed {
        assert_eq!(
            changed.debt, family,
            "a changed witness re-arms every member"
        );
    }
    // The next window re-selects the changed members (M1 and the source
    // change) in both arms and settles them identically.
    assert_eq!(after.family_reads, base_after.family_reads);
    assert_eq!(after.retry_pending, base_after.retry_pending);
    assert_eq!(after.proven, base_after.proven);
}

/// X(b), contract change after the skip is active: the changed contract
/// latches at the next traversal start, nothing skips, and that traversal's
/// complete closed-fence terminal re-arms every family file, including the
/// members the skip left unread, then clears the latch. The next window
/// re-reads them under the new contract and the skip resumes.
#[test]
#[serial(source_manifests)]
fn c1a_contract_off_to_on_rearms_skipped_family() {
    if !c1a_layout_supported("c1a_contract_change") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let mut fixture = c1a_fixture("c1a-contract-off-to-on");
    fixture.request_identity = false;
    fixture.owned_base_preparation = true;
    let before = Some(String::new());
    let (_, reproved) = c1a_close_and_reprove(&fixture, "fix");
    assert_eq!(c1a_latch(&fixture), (before, false));
    assert_eq!(reproved.debt, 0, "the skip is active");
    let quiet = c1a_window(&c1a_generation(&fixture, "fix", (8, 20)));
    assert_eq!(quiet.family_reads, 0);
    fixture.request_identity = true;
    let changed = c1a_window(&c1a_generation(&fixture, "fix", (8, 30)));
    assert!(changed.fence_before && changed.fence_after && !changed.full_rearm);
    assert_eq!(changed.family_reads, 0, "nothing re-selected the family");
    assert_eq!(changed.debt, family, "the latch re-arms the skipped family");
    assert_eq!(c1a_latch(&fixture), (c1a_collector(), false));
    let reread = c1a_window(&c1a_generation(&fixture, "fix", (8, 40)));
    assert_eq!(
        reread.family_reads, family,
        "re-read under the new contract"
    );
    // The skip resumes at once unless the new contract changed the proof
    // itself; then the changed proof re-arms one more time.
    let next = c1a_window(&c1a_generation(&fixture, "fix", (8, 45)));
    let quiet = if reread.debt == 0 {
        next
    } else {
        assert_eq!(next.debt, 0, "the skip resumes after the changed proof");
        c1a_window(&c1a_generation(&fixture, "fix", (8, 52)))
    };
    assert_eq!(quiet.family_reads, 0);
}

/// X(b), A-B-A within one traversal: off, on, off across its pages. The
/// terminal sees the same contract as the traversal start, but the record
/// marks the traversal changed, so nothing skips and nothing clears. The next
/// traversal records the contract again; its terminal re-arms every family
/// file and clears the latch, and the skip resumes after that.
#[test]
#[serial(source_manifests)]
fn c1a_contract_change_within_traversal_keeps_latch() {
    if !c1a_layout_supported("c1a_contract_aba") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let mut fixture = c1a_fixture("c1a-contract-aba");
    fixture.request_identity = false;
    fixture.owned_base_preparation = true;
    let closing = c1a_window(&c1a_generation(&fixture, "fix", (8, 0)));
    assert!(closing.full_rearm);
    assert_eq!(c1a_latch(&fixture), (Some(String::new()), false));
    let aba = c1a_window(&c1a_generation_with_identity(
        &mut fixture,
        "fix",
        (8, 10),
        &[false, true, false],
    ));
    assert!(aba.pages >= 3, "the toggles fall inside one traversal");
    assert_eq!(aba.family_reads, family);
    assert_eq!(aba.debt, family, "no skip after a mid-traversal change");
    assert_eq!(
        c1a_latch(&fixture),
        (Some(C1A_MID_TRAVERSAL.to_owned()), true)
    );
    let restarted = c1a_window(&c1a_generation(&fixture, "fix", (8, 20)));
    assert!(!restarted.full_rearm);
    assert_eq!(
        restarted.debt, family,
        "the latch re-arms every family file"
    );
    assert_eq!(c1a_latch(&fixture), (Some(String::new()), false));
    let resumed = c1a_window(&c1a_generation(&fixture, "fix", (8, 30)));
    assert_eq!(resumed.family_reads, family);
    assert_eq!(resumed.debt, 0);
}

/// X(b) lifecycle and partial work. A traversal with a shed or lost-ACK page
/// drops its census (the follow-up walk starts clean), so it never reaches a
/// complete terminal and keeps the latch it set. When the interrupted page is
/// itself a full re-arm terminal, its fold clears the latch in memory, but the
/// partial save keeps the committed latch.
fn c1a_unsettled_traversal_keeps_latch(upload: RearmUpload) {
    if !c1a_layout_supported("c1a_unsettled") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let fixture = c1a_fixture(match upload {
        RearmUpload::Shed => "c1a-unsettled-shed",
        RearmUpload::AckLost => "c1a-unsettled-ack-lost",
        RearmUpload::Accept => unreachable!(),
    });
    let interrupted = c1a_generation_with(
        &fixture,
        "fix",
        (8, 0),
        Some((0, upload, REARM_ROOT)),
        |_| {},
    );
    assert!(
        !interrupted[0].fully_settled,
        "the first page was interrupted"
    );
    assert!(!c1a_window(&interrupted).census_complete);
    assert_eq!(
        c1a_latch(&fixture),
        (c1a_collector(), true),
        "an interrupted traversal keeps the latch"
    );
    let closing = c1a_window(&c1a_generation(&fixture, "fix", (8, 10)));
    assert!(closing.census_complete && closing.full_rearm && closing.fence_after);
    assert_eq!(c1a_latch(&fixture), (c1a_collector(), false));

    // Unknown record again, then a full re-arm terminal whose own page is
    // interrupted: it offers a changed unrelated body.
    c1a_edit_index(&fixture, |saved| {
        saved.remove("claude_request_identity_contract");
        saved.remove("claude_request_identity_contract_changed");
    });
    c1a_full_rearm_due(&fixture);
    RearmFixture::append(
        &fixture
            .root
            .join("zz-terminal")
            .join("nested")
            .join(format!("{REARM_TERMINAL}.jsonl")),
        &rearm_transcript_line(REARM_TERMINAL, None, "req_terminal_2", 1),
    );
    let terminal = c1a_generation_with(
        &fixture,
        "fix",
        (8, 20),
        Some((2, upload, REARM_TERMINAL)),
        |_| {},
    );
    assert!(
        !terminal[2].fully_settled,
        "the full re-arm terminal page was interrupted"
    );
    assert_eq!(
        c1a_latch(&fixture),
        (c1a_collector(), true),
        "a partial save of the clearing terminal keeps the latch"
    );
    let cleared = c1a_window(&c1a_generation(&fixture, "fix", (8, 30)));
    assert!(cleared.census_complete);
    assert_eq!(
        cleared.debt, family,
        "the clearing terminal re-arms every file"
    );
    assert_eq!(c1a_latch(&fixture), (c1a_collector(), false));
    let resumed = c1a_window(&c1a_generation(&fixture, "fix", (8, 40)));
    assert_eq!(resumed.family_reads, family);
    assert_eq!(resumed.debt, 0, "the skip resumes after a settled clear");
}

#[test]
#[serial(source_manifests)]
fn c1a_ack_lost_traversal_keeps_latch() {
    c1a_unsettled_traversal_keeps_latch(RearmUpload::AckLost);
}

/// Fence recovery: the invalid transcript is fixed while the skip is active,
/// and the families the skip left unread are all that keep the fence closed.
/// BASE re-read them anyway and reopens in that window; the fix re-arms every
/// family file there and reopens one window later, not at the closed-fence
/// full re-arm deadline. Only the family and the invalid transcript exist,
/// three files per page, so the transcript is alone on the terminal page.
#[test]
#[serial(source_manifests)]
fn c1a_fixed_invalid_transcript_reopens_fence_without_deadline() {
    if !c1a_layout_supported("c1a_fence_recovery") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let fixture = |case: &'static str| {
        let mut fixture = c1a_fixture(case);
        fixture.native_file_limit = 3;
        std::fs::remove_file(fixture.root.join(format!("{REARM_SIBLING}.jsonl"))).unwrap();
        std::fs::remove_file(
            fixture
                .root
                .join("zz-terminal")
                .join("nested")
                .join(format!("{REARM_TERMINAL}.jsonl")),
        )
        .unwrap();
        fixture
    };
    let run = |fixture: &RearmFixture, arm: &str| {
        let windows = [(8, 0), (8, 10), (8, 20)]
            .map(|clock| c1a_window(&c1a_generation(fixture, arm, clock)));
        std::fs::write(
            c1a_invalid_path(fixture),
            rearm_transcript_line(C1A_INVALID, None, "req_c1a_valid", 0),
        )
        .unwrap();
        let fixed = c1a_window(&c1a_generation(fixture, arm, (8, 30)));
        let after = c1a_window(&c1a_generation(fixture, arm, (8, 40)));
        (windows, fixed, after)
    };
    let recovered = fixture("c1a-fence-recovery");
    let (windows, fixed, after) = run(&recovered, "fix");
    let base = fixture("c1a-fence-recovery-base");
    let (base_windows, base_fixed, _) = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    // Preconditions: the layout and the active skip.
    assert_eq!(windows[1].pages, 2);
    assert!(windows[1].fence_before && windows[1].fence_after);
    assert_eq!(windows[1].debt, 0, "the skip is active");
    assert_eq!(windows[2].family_reads, 0);
    assert_eq!(base_windows[2].family_reads, family);
    // BASE re-read the family and reopens in the fixed window.
    assert!(!base_fixed.fence_after, "BASE reopens at once");
    // The fix reads only the fixed transcript, re-arms every family file and
    // reopens in the next window.
    assert_eq!(fixed.family_reads, 0);
    assert!(fixed.fence_after && !fixed.full_rearm);
    assert_eq!(fixed.debt, family, "the recovery re-arms the unread family");
    assert_eq!(after.family_reads, family);
    assert!(after.fence_before && !after.fence_after, "reopened");
}

/// Late copied import while the skip is active: a new transcript in an
/// unrelated directory copies one of the family's requests. Its posture is
/// withheld exactly as under BASE while the fence stays closed, and once the
/// invalid transcript is fixed and the closed-fence full re-arm runs, the
/// census sees both owners of the copied request.
#[test]
#[serial(source_manifests)]
fn c1a_late_copied_import_stays_suppressed_while_skip_active() {
    use sha2::{Digest, Sha256};
    if !c1a_layout_supported("c1a_late_copied_import") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let import_posture = |pages: &[RearmPage]| {
        pages
            .iter()
            .flat_map(|page| &page.scan.snapshots)
            .filter(|item| item.source_session_id == C1A_IMPORT)
            .map(|item| {
                (
                    item.first_turn_context_tokens,
                    item.peak_context_fill_tokens,
                    item.last_turn_context_tokens,
                )
            })
            .collect::<Vec<_>>()
    };
    let run = |fixture: &RearmFixture, arm: &str| {
        let (_, reproved) = c1a_close_and_reprove(fixture, arm);
        native_comparison_add_import(fixture, C1A_IMPORT, "req_root_1");
        let imported = c1a_generation(fixture, arm, (8, 20));
        let imported_window = c1a_window(&imported);
        assert!(imported_window.fence_after, "{arm}: the fence stays closed");
        assert!(
            rearm_parsed(&imported).contains(C1A_IMPORT),
            "{arm}: the copy is read"
        );
        let mut postures = import_posture(&imported);
        assert!(!postures.is_empty(), "{arm}: the copy is offered");
        // Fix the invalid transcript; the closed-fence deadline (an hour
        // after the close) then re-arms every family file.
        std::fs::write(
            c1a_invalid_path(fixture),
            rearm_transcript_line(C1A_INVALID, None, "req_c1a_valid", 0),
        )
        .unwrap();
        let rearmed = c1a_generation(fixture, arm, (9, 10));
        assert!(c1a_window(&rearmed).full_rearm, "{arm}");
        postures.extend(import_posture(&rearmed));
        let opened = c1a_generation(fixture, arm, (9, 20));
        let opened_window = c1a_window(&opened);
        postures.extend(import_posture(&opened));
        assert!(!opened_window.fence_after, "{arm}: full coverage opens it");
        let saved = serde_json::to_value(&opened.last().unwrap().index).unwrap();
        let owners = saved["claude_duplicate_request_owners"]
            .as_object()
            .expect("the copied request has a duplicate witness");
        let hash = format!("{:x}", Sha256::digest("req_root_1".as_bytes()));
        assert_eq!(
            owners[&hash].as_array().unwrap().len(),
            2,
            "{arm}: both owners of the copied request are detected"
        );
        assert!(
            postures
                .iter()
                .all(|posture| *posture == (None, None, None)),
            "{arm}: the copy never gets unique posture"
        );
        (reproved, imported_window, postures)
    };
    let fixture = c1a_fixture("c1a-late-copy");
    let (reproved, imported, postures) = run(&fixture, "fix");
    let base = c1a_fixture("c1a-late-copy-base");
    let (_, base_imported, base_postures) = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    // Precondition: the skip was active when the copy appeared.
    assert_eq!(reproved.debt, 0);
    assert_eq!(imported.family_reads, 0);
    assert_eq!(base_imported.family_reads, rearm_family_sessions().len());
    assert_eq!(postures, base_postures);
}

fn c1a_family_bodies(
    pages: &[RearmPage],
) -> BTreeMap<String, (&RearmPage, crate::snapshots::SnapshotItem)> {
    let family = rearm_family_sessions();
    pages
        .iter()
        .flat_map(|page| {
            page.scan
                .snapshots
                .iter()
                .filter(|item| family.contains(&item.source_session_id))
                .map(move |item| (item.source_session_id.clone(), (page, item.clone())))
        })
        .collect()
}

/// Synthetic identity on every family request, installed before any scan so
/// neither transition can rely on a sidecar change to select the family.
fn c1a_add_family_request_identity(fixture: &RearmFixture) {
    use sha2::{Digest, Sha256};
    let path = fixture.sidecar_path("claude-code-effort");
    let rows = std::fs::read_to_string(&path)
        .expect("read synthetic API sidecar")
        .lines()
        .map(|line| {
            let mut row: crate::claude_local_otel::ClaudeLocalOtelEvidence =
                serde_json::from_str(line).expect("synthetic API row");
            row.account_identity_checked = true;
            row.account_identifier_hash = Some("a".repeat(64));
            row.request_identity = Some(
                serde_json::from_value(serde_json::json!({
                    "identity_hash_scheme":"provider-sha256:v1", "disposition":"complete",
                    "account":{"disposition":"complete", "origin":"log_record", "log_record_hash":"a".repeat(64)},
                    "organization":{"disposition":"complete", "origin":"log_record", "log_record_hash":"d".repeat(64)},
                }))
                .unwrap(),
            );
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            serde_json::to_string(&row).unwrap() + "\n"
        })
        .collect::<String>();
    std::fs::write(path, rows).expect("write synthetic identity rows");
}

fn c1a_assert_family_emitted_and_tagged(
    pages: &[RearmPage],
    collector: &str,
    previous: &BTreeMap<String, crate::snapshots::SnapshotItem>,
) {
    let bodies = c1a_family_bodies(pages);
    assert_eq!(bodies.len(), rearm_family_sessions().len());
    for (session, (page, item)) in bodies {
        assert_eq!(item.provenance.collector, collector, "{session}");
        assert_ne!(
            item.snapshot_fingerprint, previous[&session].snapshot_fingerprint,
            "{session}: new contract must change the accepted body"
        );
        assert!(
            page.offered.contains(&item.snapshot_fingerprint),
            "{session}: re-emitted"
        );
        assert!(
            page.uploaded.contains(&item.snapshot_fingerprint),
            "{session}: acknowledged"
        );
        assert!(
            page.index
                .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint),
            "{session}: durable accepted body"
        );
        assert!(
            !item.request_evidence.is_empty(),
            "{session}: identity evidence"
        );
        assert_eq!(item.request_identity_refusals, 0, "{session}");
        assert!(
            !item.model_usage.is_empty() && !item.usage_buckets.is_empty(),
            "{session}"
        );
        for row in item
            .model_usage
            .iter()
            .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
        {
            assert_eq!(
                row.account_identifier_hash.as_deref(),
                Some("a".repeat(64).as_str()),
                "{session}: login tag"
            );
            let evidence = &item.request_evidence[usize::from(
                row.evidence_ref
                    .expect("every usage row has an identity tag"),
            )];
            assert_eq!(
                evidence.identity_basis,
                crate::snapshots::claude_request_identity::TELEMETRY,
                "{session}"
            );
            assert_eq!(
                evidence.provider_workspace_hash.as_deref(),
                Some("d".repeat(64).as_str()),
                "{session}: org tag"
            );
        }
    }
    assert_eq!(
        c1a_window(pages).family_offered,
        rearm_family_sessions().len()
    );
}

/// X(b) v1→v2: only the collector token changes. A v2→v1→v2 flip inside
/// the first traversal keeps the latch even though its terminal sees v2.
/// Only the next complete traversal, wholly under v2, clears it after
/// re-arming every Claude file. The next window re-emits all family bodies
/// with v2 provenance and contract-5 row tags, rather than deduping the v1 body.
#[test]
#[serial(source_manifests)]
fn c1a_contract_v1_to_v2_reemits_tagged_bodies_after_unchanged_terminal() {
    // Contract-5 tagging oracle on ordinary money: a markerless single-account
    // request-owned (E2) body keeps the D1 wire shape and never carries the
    // cycle collector. The family is listed after an unlisted baseline, as a
    // protected family is in production; listed bodies take the cycle
    // contract and its row tags.
    use crate::snapshots::claude_request_identity::with_cycle_contract_for_test;
    if !c1a_layout_supported("c1a_contract_v1_to_v2_reemits") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    const V1: &str = "claude_code_jsonl:own_request_identity_rows:v1";
    const V2: &str = "claude_code_jsonl:own_request_identity_rows:v2";
    let fixture = c1a_fixture("c1a-contract-v1-to-v2-reemits");
    c1a_add_family_request_identity(&fixture);
    let family = rearm_family_sessions();
    // Unlisted baseline: the first complete census closes the fence with a
    // full re-arm, so the next window re-reads every member.
    let baseline = with_cycle_contract_for_test(V1, || c1a_generation(&fixture, "v1", (7, 55)));
    let baseline_window = c1a_window(&baseline);
    assert!(baseline_window.census_complete && baseline_window.full_rearm);
    assert_eq!(
        baseline_window.debt,
        family.len(),
        "the first proof re-arms"
    );
    // Positive control for the listed collector below: unlisted, the same
    // family bodies are request-owned and never carry the V1 collector.
    let unlisted_bodies = c1a_family_bodies(&baseline);
    assert_eq!(unlisted_bodies.len(), family.len());
    for (session, (_, item)) in &unlisted_bodies {
        assert_eq!(
            item.usage_accounting_contract.as_deref(),
            Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT),
            "{session}: unlisted body is request-owned"
        );
        assert_ne!(item.provenance.collector, V1, "{session}");
    }
    fixture.list_held(&[REARM_ROOT]);
    let closing = with_cycle_contract_for_test(V1, || c1a_generation(&fixture, "v1", (8, 0)));
    let v1_bodies = c1a_family_bodies(&closing)
        .into_iter()
        .map(|(session, (_, item))| {
            assert_eq!(item.provenance.collector, V1);
            assert!(!item.request_evidence.is_empty());
            assert_ne!(
                item.usage_accounting_contract.as_deref(),
                Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT),
                "{session}: the listed family is on ordinary money"
            );
            (session, item)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(v1_bodies.len(), family.len());
    let reproved = with_cycle_contract_for_test(V1, || c1a_generation(&fixture, "v1", (8, 10)));
    assert_eq!(c1a_window(&reproved).debt, 0, "the skip is active");
    let quiet = with_cycle_contract_for_test(V1, || c1a_generation(&fixture, "v1", (8, 20)));
    assert_eq!(c1a_window(&quiet).family_reads, 0);
    assert_eq!(c1a_latch(&fixture), (Some(V1.to_owned()), false));
    let transcript_bytes = std::iter::once(None)
        .chain(REARM_AGENTS.iter().map(|agent| Some(*agent)))
        .map(|agent| {
            let path = fixture.member_path(agent);
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect::<BTreeMap<_, _>>();
    let api_bytes = std::fs::read(fixture.sidecar_path("claude-code-effort")).unwrap();

    let mut changed = Vec::new();
    for number in 0..C1A_MAX_PAGES {
        let contract = if number == 1 { V1 } else { V2 };
        let page = with_cycle_contract_for_test(contract, || {
            fixture.page(
                &format!("2026-08-02T08:{:02}:00Z", 30 + number),
                RearmUpload::Accept,
            )
        });
        let ended = !page.index.scan_traversal_in_progress_for_test();
        assert!(
            c1a_latch(&fixture).1,
            "a changing or incomplete traversal cannot clear the latch"
        );
        if number == 0 {
            assert!(!ended && !page.scan.census_complete);
            assert_eq!(c1a_latch(&fixture), (Some(V2.to_owned()), true));
        } else {
            assert_eq!(
                c1a_latch(&fixture),
                (Some(C1A_MID_TRAVERSAL.to_owned()), true)
            );
        }
        changed.push(page);
        if ended {
            break;
        }
    }
    assert!(changed.len() >= 3);
    assert!(!changed
        .last()
        .unwrap()
        .index
        .scan_traversal_in_progress_for_test());
    let changed_window = c1a_window(&changed);
    assert!(changed_window.census_complete);
    assert!(
        !changed_window.full_rearm,
        "no scheduled full re-arm masks the latch"
    );
    assert_eq!(
        changed_window.family_reads, 0,
        "unchanged family remains unread until re-armed"
    );

    let mut stable = Vec::new();
    with_cycle_contract_for_test(V2, || {
        for number in 0..C1A_MAX_PAGES {
            let page = fixture.page(
                &format!("2026-08-02T08:{:02}:00Z", 40 + number),
                RearmUpload::Accept,
            );
            let ended = !page.index.scan_traversal_in_progress_for_test();
            assert_eq!(c1a_latch(&fixture), (Some(V2.to_owned()), !ended));
            if ended {
                assert!(page.scan.census_complete && page.fully_settled);
                for (key, entry) in &page.index.files {
                    assert!(
                        entry.source_file_fingerprint.is_empty(),
                        "every Claude file is re-armed: {key}"
                    );
                }
            } else {
                assert!(!page.scan.census_complete);
            }
            stable.push(page);
            if ended {
                break;
            }
        }
    });
    let stable_window = c1a_window(&stable);
    assert!(stable_window.census_complete && !stable_window.full_rearm);
    assert_eq!(
        stable_window.debt,
        family.len(),
        "clearing terminal skips no family member"
    );
    assert_eq!(c1a_latch(&fixture), (Some(V2.to_owned()), false));
    let reread = with_cycle_contract_for_test(V2, || c1a_generation(&fixture, "v2", (8, 50)));
    assert_eq!(c1a_window(&reread).family_reads, family.len());
    c1a_assert_family_emitted_and_tagged(&reread, V2, &v1_bodies);
    for (path, before) in transcript_bytes {
        assert_eq!(std::fs::read(path).unwrap(), before, "unchanged transcript");
    }
    assert_eq!(
        std::fs::read(fixture.sidecar_path("claude-code-effort")).unwrap(),
        api_bytes,
        "unchanged identity input"
    );
}

const C1A_SUCCESSOR: &str = "e5555555-5555-4555-8555-555555555555";

/// A new legacy copied-prefix successor (a fork or takeover written without
/// `forkedFrom`): its transcript copies the family root's first request, then
/// makes one request of its own, which only its own sidecars report.
fn c1a_add_copied_prefix_successor(fixture: &RearmFixture) {
    let path = fixture
        .root
        .join("zz-import")
        .join("nested")
        .join(format!("{C1A_SUCCESSOR}.jsonl"));
    RearmFixture::append(
        &path,
        &rearm_transcript_line(C1A_SUCCESSOR, None, "req_root_1", 0),
    );
    native_comparison_add_import(fixture, C1A_SUCCESSOR, "req_successor_1");
}

/// Count-only state of the successor after one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct C1aSuccessorWindow {
    window: C1aWindow,
    successor_read: bool,
    successor_proven: bool,
    successor_rearmed: bool,
    full_rearm_deferred_until: Option<u64>,
    census_unix_seconds: u64,
    hold: crate::snapshots::ClaudeFirstProofHoldCounts,
}

fn c1a_successor_generation(
    fixture: &RearmFixture,
    arm: &str,
    clock: (u32, usize),
) -> C1aSuccessorWindow {
    let pages = c1a_generation(fixture, arm, clock);
    let hold = crate::snapshots::claude_first_proof_hold_for_test();
    let last = pages.last().expect("terminal page");
    let successor_key = format!("{C1A_SUCCESSOR}.jsonl");
    let window = C1aSuccessorWindow {
        window: c1a_window(&pages),
        successor_read: rearm_parsed(&pages).contains(C1A_SUCCESSOR),
        successor_proven: last
            .index
            .claude_usage_family_witness_digest_for_test(C1A_SUCCESSOR)
            .is_some(),
        successor_rearmed: last.index.files.iter().any(|(key, entry)| {
            key.ends_with(successor_key.as_str()) && entry.source_file_fingerprint.is_empty()
        }),
        full_rearm_deferred_until: last.duplicate_census.full_rearm_deferred_until,
        census_unix_seconds: time::OffsetDateTime::parse(
            &last.scan.census_window_end,
            &time::format_description::well_known::Rfc3339,
        )
        .expect("census window end")
        .unix_timestamp() as u64,
        hold,
    };
    writeln!(
        std::io::stderr().lock(),
        "C1A_PROOF_REARM successor case={} arm={arm} successor_read={} successor_proven={} successor_rearmed={} full_rearm_deferred_until={:?} hold={}",
        fixture.case,
        window.successor_read,
        window.successor_proven,
        window.successor_rearmed,
        window.full_rearm_deferred_until,
        serde_json::to_string(&window.hold).unwrap(),
    )
    .unwrap();
    window
}

/// SOURCE F1 receipt, real pipeline: the skip leaves owner family O unread,
/// and a new copied-prefix successor of O appears. The successor can derive
/// its legacy exclusion only in a window that also reads O, so while O stays
/// skipped it stays unproven, and the first-proof hold counter names it with
/// its age bucket. The closed-fence full re-arm still runs when due, re-arms
/// every family file (O and the successor), and the next window proves the
/// successor. BASE re-reads O in the window the successor appears and proves
/// it at once.
#[test]
#[serial(source_manifests)]
fn c1a_dormant_owner_copied_prefix_successor_proves_after_full_rearm() {
    use crate::snapshots::ClaudeFirstProofHoldAge;
    if !c1a_layout_supported("c1a_dormant_owner_successor") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let run = |fixture: &RearmFixture, arm: &str| {
        let (_, reproved) = c1a_close_and_reprove(fixture, arm);
        c1a_add_copied_prefix_successor(fixture);
        let appeared = c1a_successor_generation(fixture, arm, (8, 20));
        let held = c1a_successor_generation(fixture, arm, (8, 30));
        c1a_full_rearm_due(fixture);
        let rearm = c1a_successor_generation(fixture, arm, (8, 40));
        let proof = c1a_successor_generation(fixture, arm, (8, 50));
        (reproved, [appeared, held, rearm, proof])
    };
    let fixture = c1a_fixture("c1a-dormant-owner-successor");
    let (reproved, [appeared, held, rearm, proof]) = run(&fixture, "fix");
    let base = c1a_fixture("c1a-dormant-owner-successor-base");
    let (_, [base_appeared, ..]) = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    for window in [&appeared, &held, &rearm, &proof, &base_appeared] {
        assert!(window.window.census_complete, "{window:?}");
        assert!(
            window.window.fence_before && window.window.fence_after,
            "the fence stays closed: {window:?}"
        );
    }
    // Preconditions: the skip was active, so O is dormant when the
    // successor appears; BASE re-reads O there and proves the successor.
    assert_eq!(reproved.debt, 0, "the skip is active");
    assert_eq!(appeared.window.family_reads, 0, "O is dormant");
    assert!(appeared.successor_read, "the successor is read");
    assert_eq!(base_appeared.window.family_reads, family);
    assert!(base_appeared.successor_read && base_appeared.successor_proven);
    assert_eq!(
        base_appeared.hold,
        crate::snapshots::ClaudeFirstProofHoldCounts::default(),
        "BASE holds nothing"
    );
    // Held while O is skipped, and counted with its age bucket (its own
    // request is 07:00:01, under two hours before the census).
    assert!(!appeared.successor_proven, "unproven while O is skipped");
    assert_eq!(appeared.hold.dormant_owner_successor_family_count, 1);
    assert_eq!(
        appeared.hold.oldest_dormant_owner_successor_age,
        Some(ClaudeFirstProofHoldAge::From1hTo6h)
    );
    assert_eq!(held.window.family_reads, 0, "O is still dormant");
    assert!(!held.window.full_rearm, "no full re-arm is due yet");
    assert!(!held.successor_proven, "still held");
    // The daily closed-fence full re-arm is intact: it runs when due,
    // re-arms every family file including the successor's, and sets the
    // next deadline no more than a day ahead.
    assert!(rearm.window.full_rearm, "the due full re-arm runs");
    assert_eq!(rearm.window.debt, family, "it re-arms O");
    assert!(rearm.successor_rearmed, "it re-arms the successor");
    let deadline = rearm
        .full_rearm_deferred_until
        .expect("the next full re-arm deadline");
    assert!(
        deadline > rearm.census_unix_seconds && deadline <= rearm.census_unix_seconds + 86_400,
        "the next full re-arm is due within a day: {rearm:?}"
    );
    // The window after the full re-arm reads O and the successor together
    // and proves the successor; nothing is held any more.
    assert_eq!(proof.window.family_reads, family);
    assert!(proof.successor_read, "the successor is re-read");
    assert!(proof.successor_proven, "proved after the full re-arm");
    assert_eq!(proof.hold.dormant_owner_successor_family_count, 0);
    assert_eq!(proof.hold.oldest_dormant_owner_successor_age, None);
}

// SOURCE 2026-10-27, option A: a `Completed` page that holds an entity locally
// scopes the sweep's unsettled marker to the held entity's own families for
// the terminal unchanged-proof skip. These arms run with native comparison on,
// as in production: the hold withholds the scan census, but the native census
// still completes, so the terminal fold runs its proof re-arm. Every held arm
// is compared with the same steps and no hold. Holds use the production E2
// hold (`hold_request_owned`), which no authority record binds.

/// Two unrelated single-session transcripts in their own directory. The
/// breadth-first walk puts them alone on the second page, between the family
/// root's page and the subagents' page, so a hold there touches no family key.
const C1A_HELD: &str = "d7000000-0000-4000-8000-000000000007";
const C1A_HELD_NEIGHBOR: &str = "d8000000-0000-4000-8000-000000000008";
/// Pages of one held-arm window: root and sibling, the held page, both
/// subagents, then the invalid and terminal transcripts.
const C1A_HELD_ARM_PAGES: usize = 4;

/// One arm: 08:00 closes the fence and proves the family with every file read
/// (a full re-arm). The held transcript then gains a request in every arm, so
/// its 08:10 body is a real change rather than a semantic no-op (finalization
/// drops a no-op before any hold applies). 08:10 reads every file again and
/// re-proves the family, with `holds` held on every page that reads them.
/// `before` runs before every later 08:10 page with that page's number.
fn c1a_held_arm(
    case: &'static str,
    holds: &[&str],
    mut before: impl FnMut(&RearmFixture, usize),
) -> (RearmFixture, C1aWindow, Vec<RearmPage>) {
    let mut fixture = c1a_fixture(case);
    for session in [C1A_HELD, C1A_HELD_NEIGHBOR] {
        RearmFixture::append(
            &fixture
                .root
                .join("held-project")
                .join(format!("{session}.jsonl")),
            &rearm_transcript_line(session, None, &format!("req_{session}"), 0),
        );
    }
    let closing = c1a_window(&c1a_generation(&fixture, "fix", (8, 0)));
    assert!(
        closing.census_complete && closing.fence_after && closing.full_rearm && closing.proven,
        "{case}: {closing:?}"
    );
    RearmFixture::append(
        &fixture
            .root
            .join("held-project")
            .join(format!("{C1A_HELD}.jsonl")),
        &rearm_transcript_line(C1A_HELD, None, "req_held_2", 1),
    );
    fixture.local_holds = holds.iter().map(|session| (*session).to_owned()).collect();
    let pages = c1a_generation_with(&fixture, "fix", (8, 10), None, |number| {
        before(&fixture, number)
    });
    assert_eq!(pages.len(), C1A_HELD_ARM_PAGES, "{case}: page layout");
    let window = c1a_window(&pages);
    (fixture, window, pages)
}

/// Exactly one page held, before the terminal page, and its saved marker is
/// `completed_blocking_holds` alone, scoped to the families it names.
fn c1a_assert_scoped_hold(pages: &[RearmPage], arm: &str) {
    let held = pages
        .iter()
        .enumerate()
        .filter(|(_, page)| !page.held.is_empty())
        .map(|(number, _)| number)
        .collect::<Vec<_>>();
    assert_eq!(held.len(), 1, "{arm}: one page holds");
    assert!(held[0] + 1 < pages.len(), "{arm}: before the terminal page");
    let index = &pages[held[0]].index;
    assert_eq!(
        index.bounded_sweep_unsettled_cause_names(),
        ["completed_blocking_holds"],
        "{arm}"
    );
    assert!(
        index
            .unchanged_proof_unsettled_families()
            .is_some_and(|families| !families.is_empty()),
        "{arm}: the saved marker names its held families"
    );
}

/// The window an arm would have without its census withhold. Only the
/// census status may differ between a held arm and its no-hold arm.
fn c1a_census_as(window: &C1aWindow, control: &C1aWindow) -> C1aWindow {
    C1aWindow {
        census_complete: control.census_complete,
        ..window.clone()
    }
}

/// Make an account hold for the first subagent durable once its page is
/// behind (before every page from the subagents' page on, so the terminal
/// fold sees it), as `c1a_account_held_member_keeps_base_rearm` does.
fn c1a_account_hold_after_subagents(fixture: &RearmFixture, number: usize) {
    if number >= 2 {
        let index = ScanIndex::load(&fixture.index_path).unwrap();
        let key =
            RearmFixture::family_keys(&index)[&rearm_member_session(Some(REARM_AGENTS[0]))].clone();
        let revision = index.files[&key].source_file_fingerprint.clone();
        c1a_edit_index(fixture, |saved| {
            saved.insert(
                "claude_account_deferred_holds".to_owned(),
                serde_json::json!({ key: revision }),
            );
        });
    }
}

/// SOURCE option A, tests (b) and (c), unbound hold: an entity no authority
/// record binds, held on a page with no family key, neither blocks nor
/// unlocks another family. The proven family skips exactly as without the
/// hold, and an account-held member keeps its family's re-arm exactly as
/// without the hold. The held entity stays held, is re-offered at the next
/// read, and keeps the census from completing (condition 1).
#[test]
#[serial(source_manifests)]
fn c1a_unbound_hold_neither_blocks_nor_unlocks_another_family() {
    if !c1a_layout_supported("c1a_unbound_hold") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let family = rearm_family_sessions().len();

    let (_, control, control_pages) = c1a_held_arm("c1a-hold-control", &[], |_, _| {});
    assert!(control_pages.iter().all(|page| page.held.is_empty()));
    assert!(control.census_complete && control.proven, "{control:?}");
    assert_eq!(control.family_reads, family);
    assert_eq!(control.debt, 0, "the settled unchanged re-proof skips");

    let (held_fixture, held, held_pages) =
        c1a_held_arm("c1a-hold-unrelated", &[C1A_HELD], |_, _| {});
    c1a_assert_scoped_hold(&held_pages, "unrelated");
    assert!(rearm_parsed(&held_pages).contains(C1A_HELD));
    assert!(
        !held.census_complete,
        "the held entity withholds the census"
    );
    // FLIPS on the sweep-wide marker, which re-armed every member here.
    assert_eq!(
        c1a_census_as(&held, &control),
        control,
        "the unrelated hold does not block the proven family's skip"
    );
    // Its revision was never committed, so the next window reads and holds
    // it again; the skipped family stays unread and owes nothing.
    let next = c1a_generation(&held_fixture, "fix", (8, 20));
    assert!(rearm_parsed(&next).contains(C1A_HELD), "re-offered");
    assert!(next.iter().any(|page| !page.held.is_empty()), "held again");
    let next = c1a_window(&next);
    assert_eq!((next.family_reads, next.debt), (0, 0));

    let (_, account, _) = c1a_held_arm(
        "c1a-hold-account-control",
        &[],
        c1a_account_hold_after_subagents,
    );
    assert!(account.proven, "{account:?}");
    assert!(account.debt > 0, "an account-held member keeps the re-arm");
    let (_, held_account, held_account_pages) = c1a_held_arm(
        "c1a-hold-account",
        &[C1A_HELD],
        c1a_account_hold_after_subagents,
    );
    c1a_assert_scoped_hold(&held_account_pages, "account");
    assert_eq!(
        c1a_census_as(&held_account, &account),
        account,
        "the unrelated hold does not unlock a family whose own member is unsettled"
    );
}

/// SOURCE option A, test (a): a held family still re-arms its own members,
/// even when its held member's committed revision passes every per-member
/// settlement check. After the skip is active, the root transcript gains a
/// user turn (a changed body, no new request) and both subagents are re-armed,
/// so 08:20 reads and re-proves the whole family with an unchanged witness.
/// Without a hold the changed root body is accepted and the re-proof skips;
/// with the root held, its committed revision (accepted, non-empty) is
/// restored and the family re-arms every member.
#[test]
#[serial(source_manifests)]
fn c1a_held_family_rearms_its_own_members() {
    if !c1a_layout_supported("c1a_held_family") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let family = rearm_family_sessions().len();
    let run = |case: &'static str, holds: &[&str]| {
        let (mut fixture, reproved, _) = c1a_held_arm(case, &[], |_, _| {});
        assert_eq!(reproved.debt, 0, "{case}: the skip is active");
        let keys = RearmFixture::family_keys(&ScanIndex::load(&fixture.index_path).unwrap());
        c1a_edit_index(&fixture, |saved| {
            for (session, key) in &keys {
                if session != REARM_ROOT {
                    saved["files"][key.as_str()]["source_file_fingerprint"] = serde_json::json!("");
                }
            }
        });
        RearmFixture::append(
            &fixture.member_path(None),
            &format!(
                "{{\"timestamp\":\"2026-08-02T07:00:30Z\",\"type\":\"user\",\"sessionId\":\"{REARM_ROOT}\",\"message\":{{\"role\":\"user\",\"content\":\"continue\"}}}}\n"
            ),
        );
        fixture.local_holds = holds.iter().map(|session| (*session).to_owned()).collect();
        let pages = c1a_generation(&fixture, "fix", (8, 20));
        (c1a_window(&pages), pages)
    };
    let (control, control_pages) = run("c1a-held-family-control", &[]);
    assert!(control_pages.iter().all(|page| page.held.is_empty()));
    assert_eq!(control.family_reads, family);
    assert!(control.census_complete && control.proven, "{control:?}");
    assert_eq!(control.debt, 0, "the unchanged re-proof skips");
    let (held, held_pages) = run("c1a-held-family", &[REARM_ROOT]);
    c1a_assert_scoped_hold(&held_pages, "held family");
    assert_eq!(held.family_reads, family);
    assert!(held.proven, "{held:?}");
    assert!(
        !held.census_complete,
        "the held member withholds the census"
    );
    assert_eq!(held.debt, family, "the held family re-arms every member");
}
