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
/// identity permit unless the test changes it.
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
        window(6, 3, 3, true, false),
        window(3, 0, 3, true, false),
    ];
    let refused = c1a_fixture("c1a-fallback-refused");
    let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
    let fallbacks = crate::snapshots::claude_unchanged_proof_budget_fallbacks_for_test();
    let windows = [(8, 0), (8, 10), (8, 20)]
        .map(|clock| c1a_window(&c1a_generation(&refused, "refused", clock)));
    assert_eq!(windows, base, "the refused fallback is BASE");
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

/// Positive control, same window: a changed multi-member family whose every
/// member is on the terminal page (a single-page window) re-proves in that
/// window exactly as under BASE, with no RetryPending entry.
#[test]
#[serial(source_manifests)]
fn c1a_changed_family_reproves_in_window_like_base() {
    if !c1a_layout_supported("c1a_changed_family_in_window") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let run = |fixture: &mut RearmFixture, arm: &str| {
        fixture.native_file_limit = 64;
        let first = c1a_window(&c1a_generation(fixture, arm, (8, 0)));
        let second = c1a_window(&c1a_generation(fixture, arm, (8, 10)));
        fixture.append_family_request(Some(REARM_AGENTS[1]), "req_agent_b_2", 4, 5);
        let changed = c1a_window(&c1a_generation(fixture, arm, (8, 20)));
        [first, second, changed]
    };
    let mut fixture = c1a_fixture("c1a-in-window");
    let windows = run(&mut fixture, "fix");
    let mut base = c1a_fixture("c1a-in-window-base");
    let base_windows = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&mut base, "base")
    };
    assert_eq!(windows, base_windows);
    let changed = &windows[2];
    assert_eq!(changed.pages, 1);
    assert!(changed.fence_before && changed.fence_after);
    assert_eq!(changed.family_reads, family);
    assert!(changed.proven, "the changed family re-proves in its window");
    assert!(!changed.retry_pending, "no RetryPending entry");
}

/// Positive control, split family: with three files per page the root and
/// one subagent sit on the first page and the other subagent on the terminal
/// page. A family with a member on the terminal page never skips, so every
/// window equals BASE.
#[test]
#[serial(source_manifests)]
fn c1a_family_with_terminal_page_member_keeps_base_rearm() {
    if !c1a_layout_supported("c1a_split_family") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let run = |fixture: &mut RearmFixture, arm: &str| {
        fixture.native_file_limit = 3;
        let fixture: &RearmFixture = fixture;
        [(8, 0), (8, 10), (8, 20)].map(|clock| c1a_window(&c1a_generation(fixture, arm, clock)))
    };
    let mut fixture = c1a_fixture("c1a-split-family");
    let windows = run(&mut fixture, "fix");
    let mut base = c1a_fixture("c1a-split-family-base");
    let base_windows = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&mut base, "base")
    };
    assert_eq!(windows, base_windows);
    assert!(windows[1].proven && windows[1].fence_before && windows[1].fence_after);
    assert!(windows[1].debt > 0, "earlier-page members keep re-arming");
}

/// X(a), M1: with the skip active, a changed `claude_api_request:v2` root row
/// that adds request identity re-selects every family member at the next
/// visit (the sidecar-inclusive selection fingerprint), and the re-emitted
/// root body carries TELEMETRY tags with the organization in the same window
/// as under BASE, with no full re-arm.
#[test]
#[serial(source_manifests)]
fn c1a_late_identity_row_reselects_and_tags_skipped_family() {
    use sha2::{Digest, Sha256};
    if !c1a_layout_supported("c1a_late_identity_row") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let login = "a".repeat(64);
    let org = "d".repeat(64);
    let upgrade = |fixture: &RearmFixture| {
        let path = fixture.sidecar_path("claude-code-effort");
        let rows = std::fs::read_to_string(&path)
            .expect("read the root API sidecar")
            .lines()
            .map(|line| {
                let mut row: crate::claude_local_otel::ClaudeLocalOtelEvidence =
                    serde_json::from_str(line).expect("synthetic API row");
                row.account_identity_checked = true;
                row.account_identifier_hash = Some(login.clone());
                row.request_identity = Some(
                    serde_json::from_value(serde_json::json!({
                        "identity_hash_scheme":"provider-sha256:v1", "disposition":"complete",
                        "account":{"disposition":"complete", "origin":"log_record", "log_record_hash":login},
                        "organization":{"disposition":"complete", "origin":"log_record", "log_record_hash":org},
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
        std::fs::write(&path, rows).expect("rewrite the root API sidecar");
    };
    let run = |fixture: &mut RearmFixture, arm: &str| {
        c1a_close_and_reprove(fixture, arm);
        let quiet = c1a_window(&c1a_generation(fixture, arm, (8, 20)));
        upgrade(fixture);
        // One page, so the changed evidence is re-proved on the terminal page.
        fixture.native_file_limit = 64;
        let pages = c1a_generation(fixture, arm, (8, 30));
        let late = c1a_window(&pages);
        let root = pages
            .iter()
            .find_map(|page| {
                page.scan
                    .snapshots
                    .iter()
                    .find(|item| item.source_session_id == REARM_ROOT)
                    .map(|item| (page, item.clone()))
            })
            .map(|(page, item)| {
                assert!(page.offered.contains(&item.snapshot_fingerprint), "{arm}");
                assert!(page.uploaded.contains(&item.snapshot_fingerprint), "{arm}");
                item
            })
            .expect("the root body is re-emitted");
        (quiet, late, root)
    };
    let mut fixture = c1a_fixture("c1a-late-identity-row");
    let (quiet, late, root) = run(&mut fixture, "fix");
    let mut base = c1a_fixture("c1a-late-identity-row-base");
    let (base_quiet, base_late, base_root) = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&mut base, "base")
    };
    // Precondition: the skip was active, so nothing re-armed the family.
    assert_eq!(quiet.family_reads, 0);
    assert_eq!(quiet.debt, 0);
    assert_eq!(base_quiet.family_reads, family);
    for (arm, window, item) in [("fix", &late, &root), ("base", &base_late, &base_root)] {
        assert_eq!(
            window.family_reads, family,
            "{arm}: M1 re-selects every member"
        );
        assert!(
            !window.full_rearm,
            "{arm}: normal cadence, not the daily re-read"
        );
        assert!(window.fence_before && window.fence_after, "{arm}");
        assert!(!window.retry_pending, "{arm}");
        assert!(
            !item.request_evidence.is_empty()
                && item.request_evidence.iter().all(|evidence| {
                    evidence.identity_basis == crate::snapshots::claude_request_identity::TELEMETRY
                        && evidence.provider_workspace_hash.as_deref() == Some(org.as_str())
                }),
            "{arm}: the re-emitted root body is tagged"
        );
    }
    assert_eq!(late, base_late, "the late window equals BASE");
}

#[derive(Debug, Clone, Copy)]
enum C1aContractChange {
    /// No permit when the fence closed, a permit from the next cycle on.
    OffToOn,
    /// A record left by an older collector token.
    OlderCollector,
    /// No record: an index from before the field, or one an older decoder
    /// rewrote without it (downgrade, then upgrade).
    Unknown,
    /// A record that names no contract.
    Malformed,
}

/// X(b), contract change after the skip is active: the changed contract
/// latches at the next traversal start, nothing skips, and that traversal's
/// complete closed-fence terminal re-arms every family file, including the
/// members the skip left unread, then clears the latch. The next window
/// re-reads them under the new contract and the skip resumes.
fn c1a_contract_change_rearms_skipped_family(change: C1aContractChange) {
    if !c1a_layout_supported("c1a_contract_change") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let mut fixture = c1a_fixture(match change {
        C1aContractChange::OffToOn => "c1a-contract-off-to-on",
        C1aContractChange::OlderCollector => "c1a-contract-older-collector",
        C1aContractChange::Unknown => "c1a-contract-unknown",
        C1aContractChange::Malformed => "c1a-contract-malformed",
    });
    let before = if matches!(change, C1aContractChange::OffToOn) {
        fixture.request_identity = false;
        fixture.owned_base_preparation = true;
        Some(String::new())
    } else {
        c1a_collector()
    };
    let (_, reproved) = c1a_close_and_reprove(&fixture, "fix");
    assert_eq!(c1a_latch(&fixture), (before, false));
    assert_eq!(reproved.debt, 0, "the skip is active");
    let quiet = c1a_window(&c1a_generation(&fixture, "fix", (8, 20)));
    assert_eq!(quiet.family_reads, 0);
    match change {
        C1aContractChange::OffToOn => fixture.request_identity = true,
        C1aContractChange::OlderCollector => c1a_edit_index(&fixture, |saved| {
            saved.insert(
                "claude_request_identity_contract".to_owned(),
                serde_json::json!("claude_code_jsonl:own_request_identity_rows:v0"),
            );
        }),
        C1aContractChange::Unknown => c1a_edit_index(&fixture, |saved| {
            saved.remove("claude_request_identity_contract");
            saved.remove("claude_request_identity_contract_changed");
        }),
        C1aContractChange::Malformed => c1a_edit_index(&fixture, |saved| {
            saved.insert(
                "claude_request_identity_contract".to_owned(),
                serde_json::json!("not a contract"),
            );
        }),
    }
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

#[test]
#[serial(source_manifests)]
fn c1a_contract_off_to_on_rearms_skipped_family() {
    c1a_contract_change_rearms_skipped_family(C1aContractChange::OffToOn);
}

#[test]
#[serial(source_manifests)]
fn c1a_contract_older_collector_rearms_skipped_family() {
    c1a_contract_change_rearms_skipped_family(C1aContractChange::OlderCollector);
}

#[test]
#[serial(source_manifests)]
fn c1a_contract_unknown_after_downgrade_rearms_skipped_family() {
    c1a_contract_change_rearms_skipped_family(C1aContractChange::Unknown);
}

#[test]
#[serial(source_manifests)]
fn c1a_contract_malformed_rearms_skipped_family() {
    c1a_contract_change_rearms_skipped_family(C1aContractChange::Malformed);
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
fn c1a_shed_traversal_keeps_latch() {
    c1a_unsettled_traversal_keeps_latch(RearmUpload::Shed);
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

/// Positive control, account hold: a family member that is account-held when
/// the terminal folds keeps the whole family on the BASE re-arm.
#[test]
#[serial(source_manifests)]
fn c1a_account_held_member_keeps_base_rearm() {
    if !c1a_layout_supported("c1a_account_hold") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let run = |fixture: &RearmFixture, arm: &str| {
        let family = rearm_family_sessions().len();
        let closing = c1a_window(&c1a_generation(fixture, arm, (8, 0)));
        assert!(closing.fence_after, "{arm}");
        let held = c1a_window(&c1a_generation_with(
            fixture,
            arm,
            (8, 10),
            None,
            |number| {
                // After both family pages, before the terminal page.
                if number == 2 {
                    let index = ScanIndex::load(&fixture.index_path).unwrap();
                    let key = RearmFixture::family_keys(&index)
                        [&rearm_member_session(Some(REARM_AGENTS[0]))]
                        .clone();
                    let revision = index.files[&key].source_file_fingerprint.clone();
                    c1a_edit_index(fixture, |saved| {
                        saved.insert(
                            "claude_account_deferred_holds".to_owned(),
                            serde_json::json!({ key: revision }),
                        );
                    });
                }
            },
        ));
        assert_eq!(held.family_reads, family, "{arm}");
        held
    };
    let fixture = c1a_fixture("c1a-account-hold");
    let held = run(&fixture, "fix");
    let base = c1a_fixture("c1a-account-hold-base");
    let base_held = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    assert_eq!(held, base_held, "a held member keeps the BASE re-arm");
    assert!(held.debt > 0);
}

/// Positive control, twin keys: a second index path for one subagent makes
/// the family incomplete, so neither arm proves it and every window equals
/// BASE.
#[test]
#[serial(source_manifests)]
fn c1a_twin_member_key_keeps_base_parity() {
    if !c1a_layout_supported("c1a_twin_keys") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let run = |fixture: &RearmFixture, arm: &str| {
        let twin = fixture
            .root
            .join("other-project")
            .join(REARM_ROOT)
            .join("subagents")
            .join(format!("agent-{}.jsonl", REARM_AGENTS[0]));
        RearmFixture::append(
            &twin,
            &std::fs::read_to_string(fixture.member_path(Some(REARM_AGENTS[0]))).unwrap(),
        );
        [(8, 0), (8, 10), (8, 20)].map(|clock| c1a_window(&c1a_generation(fixture, arm, clock)))
    };
    let fixture = c1a_fixture("c1a-twin-keys");
    let windows = run(&fixture, "fix");
    let base = c1a_fixture("c1a-twin-keys-base");
    let base_windows = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    assert!(
        base_windows.iter().all(|window| !window.proven),
        "a twin key leaves the family unproven"
    );
    assert_eq!(windows, base_windows);
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

/// Rewrite the root API sidecar so that every row gains account evidence.
/// The reduced evidence fingerprint changes, so a retained witness no longer
/// reconstructs, and the sidecar stats change, so M1 re-selects the family.
fn c1a_late_account_row(fixture: &RearmFixture) {
    use sha2::{Digest, Sha256};
    let path = fixture.sidecar_path("claude-code-effort");
    let rows = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            let mut row: crate::claude_local_otel::ClaudeLocalOtelEvidence =
                serde_json::from_str(line).unwrap();
            row.account_identity_checked = true;
            row.account_identifier_hash = Some("a".repeat(64));
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            serde_json::to_string(&row).unwrap() + "\n"
        })
        .collect::<String>();
    std::fs::write(&path, rows).unwrap();
}

/// Each window's liveness state: RetryPending, census completion and family
/// bodies offered.
fn c1a_liveness(windows: &[C1aWindow]) -> Vec<(bool, bool, usize)> {
    windows
        .iter()
        .map(|window| {
            (
                window.retry_pending,
                window.census_complete,
                window.family_offered,
            )
        })
        .collect()
}

/// Liveness control, option (c)'s case: the root API rows change after the
/// family's pages and before the terminal page of a window that reads the
/// family. That terminal re-proves the family from this window's pending and
/// the new rows, so its witness changes and the unchanged-proof check keeps
/// the BASE re-arm; the next window reconstructs against the new witness. No
/// arm goes to RetryPending and every window is complete, as under BASE.
#[test]
#[serial(source_manifests)]
fn c1a_late_row_in_read_window_rearms_like_base() {
    if !c1a_layout_supported("c1a_late_row_in_read_window") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let family = rearm_family_sessions().len();
    let run = |fixture: &RearmFixture, arm: &str| {
        let closing = c1a_window(&c1a_generation(fixture, arm, (8, 0)));
        assert!(closing.fence_after && closing.full_rearm, "{arm}");
        let changed = c1a_window(&c1a_generation_with(
            fixture,
            arm,
            (8, 10),
            None,
            |number| {
                // After both family pages, before the terminal page.
                if number == 2 {
                    c1a_late_account_row(fixture);
                }
            },
        ));
        let [next, after] =
            [(8, 20), (8, 30)].map(|clock| c1a_window(&c1a_generation(fixture, arm, clock)));
        [changed, next, after]
    };
    let fixture = c1a_fixture("c1a-late-row-read-window");
    let windows = run(&fixture, "fix");
    let base = c1a_fixture("c1a-late-row-read-window-base");
    let base_windows = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    // The changed window equals BASE, re-arm included.
    assert_eq!(windows[0], base_windows[0]);
    assert!(windows[0].fence_before && windows[0].fence_after);
    assert_eq!(windows[0].family_reads, family);
    assert_eq!(windows[0].debt, family, "a changed witness never skips");
    assert_eq!(c1a_liveness(&windows), c1a_liveness(&base_windows));
    assert!(
        windows
            .iter()
            .all(|window| !window.retry_pending && window.census_complete),
        "no RetryPending entry and every census completes"
    );
    assert_eq!(windows[1].family_offered, family, "re-emitted at once");
}

/// Liveness control, between windows: with the skip active, the root API
/// rows change after one terminal and before the next window. Both arms
/// re-select the family through M1 and reconstruct it against the witness the
/// earlier terminal proved, so both hold it identically. Only the re-arm debt
/// differs: BASE re-armed the family at that terminal and the fix skipped it.
#[test]
#[serial(source_manifests)]
fn c1a_late_row_between_windows_equals_base() {
    if !c1a_layout_supported("c1a_late_row_between_windows") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let run = |fixture: &RearmFixture, arm: &str| {
        c1a_close_and_reprove(fixture, arm);
        c1a_late_account_row(fixture);
        [(8, 20), (8, 30), (8, 40)].map(|clock| c1a_window(&c1a_generation(fixture, arm, clock)))
    };
    let fixture = c1a_fixture("c1a-late-row-between");
    let windows = run(&fixture, "fix");
    let base = c1a_fixture("c1a-late-row-between-base");
    let base_windows = {
        let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
        run(&base, "base")
    };
    for (window, base_window) in windows.iter().zip(&base_windows) {
        assert_eq!(
            C1aWindow {
                debt: base_window.debt,
                ..window.clone()
            },
            *base_window
        );
    }
    assert_eq!(windows[0].family_reads, rearm_family_sessions().len());
}

/// Disclosure, not a pass/fail claim on either arm: the dormant-window
/// residual. The skip at 08:10 leaves the family unread at 08:20. A change
/// to it then lands after its directory was walked and before the 08:20
/// terminal page: the root API rows gain account evidence (`late_row`), or
/// one subagent gains a request in its transcript and both sidecars
/// (`member_growth`). BASE read the family on 08:20's earlier pages, so its
/// terminal re-proves the family from that window's pending and the new rows.
/// The fix has no 08:20 pending for the family, so its next window
/// reconstructs against the 08:10 witness. A re-arm at the 08:20 terminal
/// would not change that: the between-windows control shows a re-armed
/// family going to RetryPending the same way. The receipts record both arms'
/// state per window for the report.
#[test]
#[serial(source_manifests)]
fn c1a_residual_dormant_family_change_receipt() {
    if !c1a_layout_supported("c1a_residual_dormant_change") {
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let run = |fixture: &RearmFixture, arm: &str, member_growth: bool| {
        c1a_close_and_reprove(fixture, arm);
        [(8, 20), (8, 30), (8, 40)].map(|clock| {
            c1a_window(&c1a_generation_with(fixture, arm, clock, None, |number| {
                if clock == (8, 20) && number == 2 {
                    if member_growth {
                        fixture.append_family_request(Some(REARM_AGENTS[0]), "req_agent_a_2", 4, 5);
                    } else {
                        c1a_late_account_row(fixture);
                    }
                }
            }))
        })
    };
    for (change, member_growth) in [("late_row", false), ("member_growth", true)] {
        let fixture = c1a_fixture(if member_growth {
            "c1a-residual-dormant-growth"
        } else {
            "c1a-residual-dormant-row"
        });
        let fix = run(&fixture, "fix", member_growth);
        let base = c1a_fixture(if member_growth {
            "c1a-residual-dormant-growth-base"
        } else {
            "c1a-residual-dormant-row-base"
        });
        let base = {
            let _refused = crate::snapshots::RefuseClaudeUnchangedProofBudgetForTest::new();
            run(&base, "base", member_growth)
        };
        writeln!(
            std::io::stderr().lock(),
            "C1A_PROOF_REARM residual=dormant_change change={change} fix_retry_pending={:?} base_retry_pending={:?} fix_census_complete={:?} base_census_complete={:?} fix_family_reads={:?} base_family_reads={:?} fix_family_offered={:?} base_family_offered={:?}",
            fix.each_ref().map(|window| window.retry_pending),
            base.each_ref().map(|window| window.retry_pending),
            fix.each_ref().map(|window| window.census_complete),
            base.each_ref().map(|window| window.census_complete),
            fix.each_ref().map(|window| window.family_reads),
            base.each_ref().map(|window| window.family_reads),
            fix.each_ref().map(|window| window.family_offered),
            base.each_ref().map(|window| window.family_offered),
        )
        .unwrap();
    }
}
