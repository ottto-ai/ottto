//! Tests for the Claude history re-send gate.

use super::*;

const EXTENT: FileExtent = FileExtent {
    size_bytes: 10,
    modified_unix_seconds: 100,
    modified_unix_nanos: Some(100_000_000_000),
};

fn installed(text: &str) -> ReemissionExclusions {
    ReemissionExclusions::parse(text.as_bytes())
}

fn inputs(exclusions: &ReemissionExclusions, listed: bool, active: u64) -> PolicyInputs<'_> {
    PolicyInputs {
        exclusions,
        listed,
        birth_unix_seconds: Some(u64::MAX),
        latched: false,
        active_revision: active,
        history_cutoff_unix_seconds: None,
        no_list_policy: NoListPolicy::Pace,
    }
}

/// F5: a same-size file whose mtime alone moved (seconds or nanos) is
/// not a genuine change; it is unchanged history, so it is gated.
#[test]
fn a_same_size_mtime_only_change_is_not_a_genuine_change() {
    with_max_gated_claude_revision(3, || {
        for touched in [
            FileExtent {
                modified_unix_nanos: Some(100_000_000_001),
                ..EXTENT
            },
            FileExtent {
                modified_unix_seconds: 101,
                modified_unix_nanos: Some(101_000_000_000),
                ..EXTENT
            },
        ] {
            assert_eq!(
                classify(Some(EXTENT), touched, true, None, None),
                HistoryKind::Owed
            );
            assert_eq!(
                classify(Some(EXTENT), touched, false, None, None),
                HistoryKind::Settled
            );
        }
        let list = installed("");
        let mut page = HistoryPage::default();
        let touched = classify(
            Some(EXTENT),
            FileExtent {
                modified_unix_seconds: 101,
                ..EXTENT
            },
            true,
            None,
            None,
        );
        assert_eq!(
            decide(touched, &inputs(&list, true, 3), &mut page, "k", 1),
            HistoryDecision::Held(HistoryHold::Listed),
            "a touched listed file is held history, not a listed change"
        );
    });
}

#[test]
fn new_files_are_history_only_before_a_known_cutoff() {
    assert_eq!(
        classify(None, EXTENT, true, None, None),
        HistoryKind::Fresh,
        "a genuine first install ingests normally"
    );
    assert_eq!(
        classify(None, EXTENT, true, Some(500), Some(499)),
        HistoryKind::Owed
    );
    assert_eq!(
        classify(None, EXTENT, true, Some(500), None),
        HistoryKind::Owed,
        "unknown birth under a cutoff is history"
    );
    assert_eq!(
        classify(None, EXTENT, true, Some(500), Some(500)),
        HistoryKind::Owed,
        "born within the cutoff second is history (fail closed)"
    );
    assert_eq!(
        classify(None, EXTENT, true, Some(500), Some(501)),
        HistoryKind::Fresh,
        "born after the cutoff is new"
    );
    assert_eq!(
        classify(None, EXTENT, false, Some(500), Some(1)),
        HistoryKind::Fresh,
        "no active revision, nothing to gate"
    );
}

/// Where no list is
/// intended, old and unknown-birth history is paced unless the Mac is
/// unverified (`no_list_birth`) or the history was moved under a claim
/// policy other than `full` (`move_not_full`). An intended list (an
/// installed list, or a marker with the list gone) applies its own rules
/// whatever the policy.
#[test]
fn no_list_policy_paces_unless_unverified_or_a_move_not_full() {
    let not_installed = ReemissionExclusions::default();
    let list = installed("");
    let missing = ReemissionExclusions::with_state(ListState::MissingAfterInstall);
    for (policy, expected) in [
        (NoListPolicy::Pace, HistoryDecision::Owed),
        (
            NoListPolicy::HoldUnverified,
            HistoryDecision::Held(HistoryHold::NoListBirth),
        ),
        (
            NoListPolicy::HoldMoveNotFull,
            HistoryDecision::Held(HistoryHold::MoveNotFull),
        ),
    ] {
        for birth in [None, Some(1), Some(u64::MAX - 1)] {
            let mut old = inputs(&not_installed, false, 2);
            old.birth_unix_seconds = birth;
            old.history_cutoff_unix_seconds = Some(u64::MAX - 1);
            old.no_list_policy = policy;
            assert_eq!(
                decide(HistoryKind::Owed, &old, &mut HistoryPage::default(), "k", 1),
                expected,
                "{policy:?} {birth:?}"
            );
            let mut intended = inputs(&list, false, 2);
            intended.birth_unix_seconds = birth;
            intended.no_list_policy = policy;
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &intended,
                    &mut HistoryPage::default(),
                    "k",
                    1
                ),
                HistoryDecision::Owed,
                "an installed list paces unlisted history: {policy:?}"
            );
            let mut paused = inputs(&missing, false, 2);
            paused.no_list_policy = policy;
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &paused,
                    &mut HistoryPage::default(),
                    "k",
                    1
                ),
                HistoryDecision::Held(HistoryHold::ListPaused)
            );
        }
    }
}

/// F4b: where the no-list policy holds, the birth hold reads the active
/// revision's own cutoff.
#[test]
fn the_no_list_birth_hold_is_per_revision() {
    with_max_gated_claude_revision(3, || {
        let not_installed = ReemissionExclusions::default();
        let born_after_revision_2_cutoff = Some(1_792_540_800 + 60);
        let mut page = HistoryPage::default();
        for (revision, held) in [(2, false), (3, true)] {
            let mut owed = inputs(&not_installed, false, revision);
            owed.no_list_policy = NoListPolicy::HoldUnverified;
            owed.birth_unix_seconds = born_after_revision_2_cutoff;
            let decision = decide(HistoryKind::Owed, &owed, &mut page, "k", 1);
            assert_eq!(
                decision == HistoryDecision::Held(HistoryHold::NoListBirth),
                held,
                "revision {revision}: {decision:?}"
            );
        }
    });
}

#[test]
fn listed_change_emits_under_revision_two_and_only_its_literal_is_denied_under_three() {
    with_max_gated_claude_revision(3, || {
        let list = installed("");
        let mut page = HistoryPage::default();
        assert_eq!(
            decide(
                HistoryKind::Changed,
                &inputs(&list, true, 2),
                &mut page,
                "k",
                1
            ),
            HistoryDecision::NotOwed
        );
        assert_eq!(
            decide(
                HistoryKind::Changed,
                &inputs(&list, true, 3),
                &mut page,
                "k",
                1
            ),
            HistoryDecision::LiteralDenied,
            "the ordinary body emits; only the request-owned literal is denied"
        );
        assert_eq!(
            decide(
                HistoryKind::Fresh,
                &inputs(&list, true, 3),
                &mut page,
                "k",
                1
            ),
            HistoryDecision::LiteralDenied,
            "a listed root's new file never carries the literal either"
        );
        assert_eq!(page.denied_for_reason(LISTED_LITERAL_REASON), 2);
        assert!(page.denied_summary().contains("listed_literal:installed=2"));
        assert_eq!(
            decide(
                HistoryKind::Changed,
                &inputs(&list, false, 3),
                &mut page,
                "k",
                1
            ),
            HistoryDecision::NotOwed,
            "an unlisted change always syncs"
        );
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&list, false, 4),
                &mut page,
                "k",
                1
            ),
            HistoryDecision::Held(HistoryHold::UngatedRevision)
        );
        assert_eq!(
            decide(
                HistoryKind::Changed,
                &inputs(&list, true, 4),
                &mut page,
                "k",
                1
            ),
            HistoryDecision::Held(HistoryHold::UngatedRevision)
        );
    });
}

const PAUSED: [ListState; 4] = [
    ListState::Unreadable,
    ListState::MissingAfterInstall,
    ListState::MarkerUnwritable,
    ListState::ClosureOverflow,
];

/// [money] A paused list holds adoption only (G1, G2, G4): owed history
/// is held, while a genuine change or a new file decides exactly as under
/// the installed list, listed or not.
#[test]
fn a_paused_list_holds_owed_history_and_decides_changes_as_installed() {
    with_max_gated_claude_revision(3, || {
        let list = installed("");
        for paused in PAUSED {
            let paused_list = list.clone().with_state_for_test(paused);
            for kind in [HistoryKind::Fresh, HistoryKind::Changed] {
                for listed in [false, true] {
                    assert_eq!(
                        decide(
                            kind,
                            &inputs(&paused_list, listed, 3),
                            &mut HistoryPage::default(),
                            "k",
                            1
                        ),
                        decide(
                            kind,
                            &inputs(&list, listed, 3),
                            &mut HistoryPage::default(),
                            "k",
                            1
                        ),
                        "{paused:?} {kind:?} listed={listed}"
                    );
                }
            }
            assert_eq!(
                decide(
                    HistoryKind::Owed,
                    &inputs(&paused_list, false, 3),
                    &mut HistoryPage::default(),
                    "k",
                    1
                ),
                HistoryDecision::Held(HistoryHold::ListPaused),
                "{paused:?}"
            );
        }
    });
}

/// The literal guard reads the active row, the list and
/// the index, never this cycle's decisions; unknown sources fail closed.
#[test]
fn literal_guard_ignores_this_cycles_decisions() {
    with_max_gated_claude_revision(3, || {
        let item = |file: Option<&str>, literal: bool| {
            let mut item = crate::snapshots::tests::sample_session_artifact_item();
            item.source_file_fingerprint = file.map(Into::into);
            item.usage_accounting_contract =
                literal.then(|| REQUEST_OWNED_USAGE_CONTRACT.into());
            item
        };
        let items = [item(Some("open"), true), item(Some("listed"), true)];
        let files = || {
            [
                ("open.jsonl", "open"),
                ("listed.jsonl", "listed"),
                ("alias.jsonl", "open"),
            ]
            .into_iter()
        };
        let listed = |key: &str| key != "open.jsonl";
        let list = installed("");
        let guard = |revision: u64, list: &ReemissionExclusions| {
            LiteralGuard::for_items(&items, revision, list, files(), listed)
        };
        let populated = ReemissionExclusions::parse(format!("{}\n", "a".repeat(64)).as_bytes());
        // S-726-1: below revision 3 no literal passes, listed or not.
        for below in [&populated, &list, &ReemissionExclusions::default()] {
            assert_eq!(guard(2, below), LiteralGuard::DenyAll);
        }
        with_max_gated_claude_revision(2, || {
            assert_eq!(guard(3, &list), LiteralGuard::DenyAll, "rowless");
        });
        assert_eq!(guard(3, &list), LiteralGuard::Open, "nothing is listed");
        assert_eq!(
            guard(3, &ReemissionExclusions::default()),
            LiteralGuard::Open,
            "a list never installed lists nothing"
        );
        // A pause holds adoption only: a paused list without digests
        // lists nothing, and one that kept its digests denies exactly
        // what it denies installed.
        for paused in PAUSED {
            let empty = ReemissionExclusions::default().with_state_for_test(paused);
            assert_eq!(guard(3, &empty), LiteralGuard::Open, "{paused:?}");
            let kept = populated.clone().with_state_for_test(paused);
            assert_eq!(guard(3, &kept), guard(3, &populated), "{paused:?}");
        }
        let only = guard(3, &populated);
        assert_eq!(
            only,
            LiteralGuard::Only(BTreeSet::new()),
            "a source any listed key carries is denied, an alias included"
        );
        let only_open = LiteralGuard::for_items(&items, 3, &populated, files(), |key| {
            key == "listed.jsonl"
        });
        assert!(only_open.permits(&item(Some("open"), true)));
        assert!(!only_open.permits(&item(Some("listed"), true)));
        assert!(!only_open.permits(&item(Some("unindexed"), true)));
        assert!(!only_open.permits(&item(None, true)));
        assert!(
            only_open.permits(&item(Some("listed"), false)),
            "the body stays"
        );
        with_max_gated_claude_revision(2, || {
            assert!(
                denies_request_owned_literal(3),
                "a rowless revision fails closed"
            );
        });
        assert!(!denies_request_owned_literal(2));
    });
}

#[test]
fn literal_denial_removes_only_request_owned_items() {
    let mut emission = HistoryEmission::default();
    emission.files.insert(
        "denied".into(),
        GatedHistory {
            literal_denied: true,
            ..GatedHistory::default()
        },
    );
    emission.files.insert(
        "held".into(),
        GatedHistory {
            held: Some(HistoryHold::Listed),
            ..GatedHistory::default()
        },
    );
    let item = |file: &str, literal: bool| {
        let mut item = crate::snapshots::tests::sample_session_artifact_item();
        item.source_file_fingerprint = Some(file.into());
        item.usage_accounting_contract = literal.then(|| REQUEST_OWNED_USAGE_CONTRACT.into());
        item
    };
    let open = LiteralGuard::Open;
    assert!(emission.permits(&item("denied", false), &open));
    assert!(!emission.permits(&item("denied", true), &open));
    assert!(!emission.permits(&item("held", false), &open));
    assert!(emission.permits(&item("other", true), &open));
    let mut ordinary = item("denied", false);
    ordinary.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".into());
    assert!(
        emission.permits(&ordinary, &open),
        "session_exclusive v1 on the ordinary body keeps today's rules"
    );
    assert!(!emission.permits(&item("other", true), &LiteralGuard::DenyAll));
    assert!(emission.permits(&item("other", false), &LiteralGuard::DenyAll));
    assert!(emission.literal_denied("denied"));
    assert_eq!(
        emission.hold_permitted_for_latch(),
        0,
        "never latched as an upgrade"
    );
    assert!(emission.literal_denied("denied"));
}

#[test]
fn re_owe_only_lowers_below_the_active_revision_and_counts() {
    with_max_gated_claude_revision(3, || {
        let before = local_count(LocalCount::Reowed);
        let mut stored = 3;
        assert!(!re_owe(&mut stored, 3, 3), "not a lowering");
        assert!(!re_owe(&mut stored, 4, 3), "never raises");
        let mut low = 1;
        assert!(!re_owe(&mut low, 2, 3), "never raises");
        let mut at_active = 3;
        assert!(
            !re_owe(&mut at_active, 2, 2),
            "must end below the active revision"
        );
        assert_eq!(at_active, 3);
        assert!(re_owe(&mut stored, 2, 3));
        assert_eq!(stored, 2);
        let mut decoded = 3;
        assert!(
            re_owe(&mut decoded, 2, 0),
            "before activation the bound is the highest revision with a row"
        );
        with_max_gated_claude_revision(2, || {
            let mut decoded = 3;
            assert!(!re_owe(&mut decoded, 2, 0));
        });
        assert_eq!(local_count(LocalCount::Reowed), before + 2);
    });
}

#[test]
fn owed_history_passes_list_birth_latch_and_budget_in_order() {
    let not_installed = ReemissionExclusions::default();
    let mut page = HistoryPage::default();
    let mut old = inputs(&not_installed, false, 2);
    old.birth_unix_seconds = None;
    old.no_list_policy = NoListPolicy::HoldUnverified;
    assert_eq!(
        decide(HistoryKind::Owed, &old, &mut page, "a", 1),
        HistoryDecision::Held(HistoryHold::NoListBirth)
    );
    let paused = installed("not-a-digest\n");
    assert_eq!(
        decide(
            HistoryKind::Owed,
            &inputs(&paused, false, 2),
            &mut page,
            "a",
            1
        ),
        HistoryDecision::Held(HistoryHold::ListPaused)
    );
    let list = installed("");
    assert_eq!(
        decide(
            HistoryKind::Owed,
            &inputs(&list, true, 2),
            &mut page,
            "a",
            1
        ),
        HistoryDecision::Held(HistoryHold::Listed)
    );
    let mut latched = inputs(&list, false, 2);
    latched.latched = true;
    assert_eq!(
        decide(HistoryKind::Owed, &latched, &mut page, "a", 1),
        HistoryDecision::Held(HistoryHold::Latched)
    );
    assert_eq!(page.permitted, 0, "no held file spends the budget");
    super::super::with_body_witness_adoption_page_budget(1, || {
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&list, false, 2),
                &mut page,
                "a",
                1
            ),
            HistoryDecision::Owed
        );
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&list, false, 2),
                &mut page,
                "a",
                1
            ),
            HistoryDecision::Owed,
            "a file already reserved on this page is not charged twice"
        );
        assert_eq!(
            decide(
                HistoryKind::Owed,
                &inputs(&list, false, 2),
                &mut page,
                "b",
                1
            ),
            HistoryDecision::Held(HistoryHold::Budget)
        );
    });
    assert_eq!(page.owed, 7);
    assert_eq!(page.denied_for(&[HistoryHold::Budget]), 1);
    assert!(page
        .denied_summary()
        .contains("no_list_birth:not_installed=1"));
}

/// [regress] History over one page makes progress as the first unit.
#[test]
fn the_byte_budget_admits_the_first_large_history_file() {
    let list = installed("");
    let mut page = HistoryPage::default();
    assert_eq!(
        decide(
            HistoryKind::Owed,
            &inputs(&list, false, 2),
            &mut page,
            "huge",
            HISTORY_UPGRADE_BYTES_PER_PAGE + 1
        ),
        HistoryDecision::Owed
    );
    // Codex and Pi adoption-only pacing keeps progress for a transcript
    // above the byte budget: only a page's first file passes over it.
    let huge = HISTORY_UPGRADE_BYTES_PER_PAGE + 1;
    let mut codex = HistoryPage::default();
    assert!(codex.reserve_admitting_first_file("codex-huge", huge));
    assert!(!codex.reserve_admitting_first_file("codex-second", 1));
    let mut codex = HistoryPage::default();
    assert!(codex.reserve_admitting_first_file("codex-small", 1));
    assert!(!codex.reserve_admitting_first_file("codex-huge", huge));
}

fn twin_index(sizes: &[(&str, u64)]) -> super::super::ScanIndex {
    let mut index = super::super::ScanIndex::default();
    for (key, size) in sizes {
        let mut entry = super::super::tests::manifest_index_entry(None);
        entry.size_bytes = *size;
        index.files.insert((*key).to_owned(), entry);
    }
    index
}

const TWIN_A: &str = "/h/.claude/projects/-a/11111111-1111-4111-8111-111111111111.jsonl";
const TWIN_B: &str = "/h/slot/projects/-b/11111111-1111-4111-8111-111111111111.jsonl";
const OTHER: &str = "/h/.claude/projects/-a/22222222-2222-4222-8222-222222222222.jsonl";
const AGENT: &str =
    "/h/.claude/projects/-a/11111111-1111-4111-8111-111111111111/subagents/agent-x.jsonl";

/// `e2` path twins: a pair is reserved both or neither, and a page's first
/// group passes the file count, so under a budget of one or two files a
/// pair held by another file's reservation settles on the next page.
#[test]
fn path_twins_reserve_both_or_neither_and_settle_within_two_pages() {
    let mut index = twin_index(&[(TWIN_A, 10), (TWIN_B, 12), (OTHER, 5), (AGENT, 7)]);
    let list = installed("");
    let mut staged = HistoryPage::default();
    index.stage_claude_history_twins(TWIN_A, &mut staged);
    assert_eq!(
        staged.staged_twins,
        Some((TWIN_A.to_owned(), vec![(TWIN_B.to_owned(), 12)])),
        "same member file under another project; the agent and other sessions are not twins"
    );
    index.stage_claude_history_twins(OTHER, &mut staged);
    assert_eq!(staged.staged_twins, Some((OTHER.to_owned(), Vec::new())));
    assert!(index.claude_money_birth_store.staged(TWIN_A));
    assert!(index.claude_money_birth_store.staged(TWIN_B));
    assert!(
        !index.claude_money_birth_store.staged(OTHER),
        "a lone root pays no metadata probe"
    );
    assert!(
        !index.claude_money_birth_store.staged(AGENT),
        "a lone agent pays no metadata probe"
    );
    let mut owed = |page: &mut HistoryPage, key: &str, size: u64| {
        index.stage_claude_history_twins(key, page);
        decide(HistoryKind::Owed, &inputs(&list, false, 2), page, key, size)
    };
    for budget in [1, 2] {
        super::super::with_body_witness_adoption_page_budget(budget, || {
            // Page 1: another owed file takes the page first.
            let mut page = HistoryPage::default();
            assert_eq!(owed(&mut page, OTHER, 5), HistoryDecision::Owed);
            assert_eq!(
                owed(&mut page, TWIN_A, 10),
                HistoryDecision::Held(HistoryHold::Budget),
                "budget {budget}: a twin is never reserved without its sibling"
            );
            assert_eq!(
                owed(&mut page, TWIN_B, 12),
                HistoryDecision::Held(HistoryHold::Budget),
                "budget {budget}: neither twin is reserved"
            );
            assert_eq!((page.files, page.bytes), (1, 5));
            // Page 2: the settled file is no longer owed; the pair goes first.
            let mut page = HistoryPage::default();
            assert_eq!(owed(&mut page, TWIN_A, 10), HistoryDecision::Owed);
            assert_eq!(owed(&mut page, TWIN_B, 12), HistoryDecision::Owed);
            assert_eq!((page.files, page.bytes), (2, 22), "budget {budget}");
            assert_eq!(page.permitted, 2);
        });
    }
    // The first native twin group also passes the byte budget.
    super::super::with_body_witness_adoption_byte_budget(21, || {
        let mut page = HistoryPage::default();
        assert_eq!(owed(&mut page, TWIN_B, 12), HistoryDecision::Owed);
        assert_eq!(page.reserved.len(), 2);
    });
    // A single file keeps the previous rule exactly (no group exception).
    super::super::with_body_witness_adoption_page_budget(1, || {
        let mut page = HistoryPage::default();
        assert!(page.reserve(OTHER, 5));
        assert!(!page.reserve(AGENT, 7));
        assert!(
            page.reserve(OTHER, 5),
            "a reserved file is not charged twice"
        );
    });
}

/// `e2`: a failed telemetry read holds every permitted owed upgrade of the
/// cycle (it stays owed), never a held or literal-denied file's state.
#[test]
fn unread_telemetry_holds_permitted_upgrades_only() {
    let mut index = super::super::ScanIndex::default();
    let gated = |held: Option<HistoryHold>, literal_denied: bool| GatedHistory {
        index_key: "k".into(),
        held,
        permitted: held.is_none() && !literal_denied,
        literal_denied,
        previous: None,
        local: BTreeSet::new(),
    };
    let files = &mut index.claude_history_emission.files;
    files.insert("permitted".into(), gated(None, false));
    files.insert("budget".into(), gated(Some(HistoryHold::Budget), false));
    files.insert("denied".into(), gated(None, true));
    assert_eq!(index.hold_claude_history_for_unread_telemetry(), 1);
    let emission = &index.claude_history_emission;
    assert_eq!(
        emission.held("permitted"),
        Some(HistoryHold::TelemetryUnread)
    );
    assert_eq!(emission.held("budget"), Some(HistoryHold::Budget));
    assert_eq!(emission.held("denied"), None);
    assert!(emission.literal_denied("denied"));
    assert_eq!(HistoryHold::TelemetryUnread.as_str(), "telemetry_unread");
}
