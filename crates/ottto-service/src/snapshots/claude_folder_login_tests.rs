// Recorded-login naming per folder. Synthetic hashes and addresses only; the
// sentence and the line keys follow the real transcript shape.
use super::*;
use crate::snapshots::claude_request_money::e2::with_fixture_birth;
use crate::snapshots::{
    apply_claude_code_line, opened_object_identity, parse_claude_code_jsonl_file, sampled_scan,
    ClaudeTitleMetadata, CodexTitleMetadata, OwnedJsonlParser, ScanIndexEntry, SnapshotSource,
};
use serde_json::json;

const ORG_UUID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_ORG_UUID: &str = "22222222-2222-4222-8222-222222222222";
const SESSION_A: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const SESSION_B: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const ADDRESS: &str = "one.login+tag@Example.test";
const OTHER_ADDRESS: &str = "second@example.test";
const EARLY_BIRTH: u64 = 1_785_542_400_000_000_000;
const LATE_BIRTH: u64 = 1_785_801_600_000_000_000;

fn login() -> String {
    "a".repeat(64)
}

fn org_of(uuid: &str) -> String {
    marker_org_hash(&json!({ "organizationUuid": uuid })).unwrap()
}

/// The recorded wording, with a synthetic address.
fn sentence(address: &str) -> String {
    format!(
        "The user's email address is {address}. Use it only to identify the user, such as for \
         authorship, attribution, or filtering their own work. Never send it to an unrelated \
         service, such as in a request header, URL, or payload, unless the user explicitly asks."
    )
}

fn context_text(text: &str, session: &str) -> Value {
    json!({"type": "attachment", "sessionId": session, "timestamp": "2026-08-02T06:59:58Z",
        "isSidechain": false, "entrypoint": "cli", "attachment": {"type": "session_context",
            "context": {"userEmail": text, "gitStatus": ""}}})
}

fn context(address: &str, session: &str) -> Value {
    context_text(&sentence(address), session)
}

fn marker(uuid: &str, session: &str) -> Value {
    json!({"type": "attachment", "sessionId": session, "timestamp": "2026-08-02T06:59:59Z",
        "attachment": {"type": "credential_org", "organizationUuid": uuid}})
}

fn assistant(session: &str, request: &str, at: &str) -> Value {
    json!({"type": "assistant", "sessionId": session, "timestamp": at, "requestId": request,
        "message": {"id": format!("msg_{request}"), "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 10, "output_tokens": 1}}})
}

fn own_lines(session: &str, request: &str) -> Vec<Value> {
    vec![
        context(ADDRESS, session),
        marker(ORG_UUID, session),
        assistant(session, request, "2026-08-02T07:00:00Z"),
    ]
}

fn folder_report() -> OwnerReport {
    let pair = (login(), org_of(ORG_UUID));
    OwnerReport {
        slot: false,
        pair: Some(pair.clone()),
        proven: Some(pair),
        email: Some(address_digest(ADDRESS)),
        other_account: false,
    }
}

fn slot_report() -> OwnerReport {
    OwnerReport {
        slot: true,
        proven: None,
        ..folder_report()
    }
}

struct Folder {
    root: PathBuf,
    key: String,
}

fn folder(name: &str) -> Folder {
    let dir = crate::test_scratch::private_dir(name);
    let root = dir.join("cfg/projects");
    std::fs::create_dir_all(root.join("p")).unwrap();
    Folder {
        key: folder_key(&dir.join("cfg")),
        root,
    }
}

impl Folder {
    fn path(&self, session: &str) -> PathBuf {
        self.root.join("p").join(format!("{session}.jsonl"))
    }

    /// A real whole read of one transcript.
    fn read(&self, session: &str, lines: &[Value]) -> Vec<SnapshotItem> {
        self.read_born(EARLY_BIRTH, session, lines)
    }

    fn read_born(&self, birth: u64, session: &str, lines: &[Value]) -> Vec<SnapshotItem> {
        let path = self.path(session);
        let body: String = lines.iter().map(|line| format!("{line}\n")).collect();
        std::fs::write(&path, body).unwrap();
        with_fixture_birth(birth, || {
            parse_claude_code_jsonl_file(&path, "2026-08-02T07:10:00Z", "fingerprint".to_string())
                .unwrap()
        })
    }

    fn begin(&self, index: &mut ScanIndex, report: OwnerReport) {
        begin_page(
            index,
            &ScanIndex::default(),
            std::slice::from_ref(&self.root),
            true,
        );
        observe_owner(self.key.clone(), report);
    }

    /// A folder whose first read predates the record.
    fn begin_upgraded(&self, index: &mut ScanIndex, report: OwnerReport) {
        let mut committed = ScanIndex::default();
        committed.files.insert(
            local_index_key(&self.path("old")),
            ScanIndexEntry::default(),
        );
        begin_page(index, &committed, std::slice::from_ref(&self.root), true);
        observe_owner(self.key.clone(), report);
    }

    fn record<'i>(&self, index: &'i ScanIndex) -> &'i FolderRecord {
        &index.claude_folder_login_ledger[&self.key]
    }
}

fn page(index: &mut ScanIndex, items: &mut [SnapshotItem], clean: bool) {
    let api = ClaudeLocalOtelLoadReport::default();
    note_page(index, items, &api, clean);
    stamp_page(items, index, &api, &AcceptedBuckets::for_test());
}

fn witness(items: &[SnapshotItem]) -> Option<SoleLoginWitness> {
    items[0]
        .claude_money
        .as_deref()?
        .folder_trace
        .as_deref()?
        .qualified()
        .map(|folder| folder.witness.clone())
}

/// A file the index already holds at the active revision.
fn seed(index: &mut ScanIndex, path: &Path, bytes: u64) {
    index.active_effective_upload_body_witness_revision = 3;
    index.files.insert(
        local_index_key(path),
        ScanIndexEntry {
            size_bytes: bytes,
            effective_upload_body_witness_revision: 3,
            ..ScanIndexEntry::default()
        },
    );
}

fn owed(index: &ScanIndex) -> BTreeSet<String> {
    index
        .files
        .keys()
        .filter(|key| index.effective_upload_body_witness_revision_requires_adoption(key))
        .cloned()
        .collect()
}

/// The history gate let every owed file through.
fn settle(index: &mut ScanIndex) {
    for entry in index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 3;
    }
}

#[test]
fn only_one_well_formed_address_in_the_sentence_is_an_answer() {
    assert_eq!(
        recorded_address(&sentence(ADDRESS)).as_deref(),
        Some("one.login+tag@example.test")
    );
    assert_eq!(
        recorded_address(&format!("Mail <{ADDRESS}>, please")).as_deref(),
        Some("one.login+tag@example.test")
    );
    for text in [
        "no address at all",
        "two a@example.test and b@example.test here",
        "@example.test",
        "a@b",
        "a@@example.test",
        "a@.test",
    ] {
        assert_eq!(recorded_address(text), None, "{text}");
    }
}

#[test]
fn the_real_sentence_matches_the_login_email_and_nothing_is_sticky() {
    let mut trace = FolderTrace::default();
    trace.note_line(&context(ADDRESS, SESSION_A), false);
    trace.note_line(&marker(ORG_UUID, SESSION_A), false);
    assert!(read_matches(&trace, &folder_report()));
    let mut record = FolderRecord::default();
    record.absorb_owner(&folder_report());
    assert!(!record.mixed);
}

#[test]
fn an_unreadable_sentence_is_untagged_without_a_verdict() {
    let f = folder("recorded-unreadable");
    let mut index = ScanIndex::default();
    f.begin(&mut index, folder_report());
    let mut items = f.read(
        SESSION_A,
        &[
            context_text("two a@example.test b@example.test", SESSION_A),
            marker(ORG_UUID, SESSION_A),
            assistant(SESSION_A, "req_1", "2026-08-02T07:00:00Z"),
        ],
    );
    page(&mut index, &mut items, true);
    assert_eq!(witness(&items), None);
    assert!(!f.record(&index).mixed);
}

/// A real multi-page first walk: only the last page can be tagged at upload,
/// and the single re-offer brings the earlier page to 100%.
#[test]
fn fresh_install_history_is_named_by_one_re_offer_across_pages() {
    let f = folder("recorded-multi-page");
    let mut index = ScanIndex::default();
    f.begin(&mut index, folder_report());
    let mut first = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut first, false);
    assert_eq!(witness(&first), None, "before the census completes");
    let mut last = f.read(SESSION_B, &own_lines(SESSION_B, "req_b"));
    page(&mut index, &mut last, true);
    let tagged = witness(&last).expect("the page completing qualification");
    assert_eq!(tagged.v, 1);
    assert_eq!(tagged.kind, "folder");
    assert_eq!(tagged.covered_from, "2026-08-02T07:00:00Z");

    seed(&mut index, &f.path(SESSION_A), 100);
    seed(&mut index, &f.path(SESSION_B), 100);
    seed(&mut index, &f.path("no-own-marker"), 100);
    step_reoffers(&mut index, false);
    assert!(owed(&index).is_empty(), "off offers nothing");
    step_reoffers(&mut index, true);
    assert_eq!(
        owed(&index),
        BTreeSet::from([
            local_index_key(&f.path(SESSION_A)),
            local_index_key(&f.path(SESSION_B))
        ]),
        "only matched own files are offered"
    );
    step_reoffers(&mut index, true);
    settle(&mut index);
    step_reoffers(&mut index, true);
    assert_eq!(f.record(&index).reoffer, REOFFER_DONE);
    assert!(owed(&index).is_empty());
    step_reoffers(&mut index, true);
    assert!(owed(&index).is_empty(), "never repeats");

    let mut again = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut again, true);
    assert!(witness(&again).is_some(), "the re-offered read is named");
}

#[test]
fn a_late_proof_starts_the_re_offer_and_a_failed_one_is_only_not_yet() {
    let f = folder("recorded-late-proof");
    let mut index = ScanIndex::default();
    f.begin(
        &mut index,
        OwnerReport {
            proven: None,
            ..folder_report()
        },
    );
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut items, true);
    assert_eq!(witness(&items), None);
    assert!(!f.record(&index).mixed);
    seed(&mut index, &f.path(SESSION_A), 100);
    step_reoffers(&mut index, true);
    assert!(owed(&index).is_empty());

    observe_owner(f.key.clone(), folder_report());
    page(&mut index, &mut [], true);
    step_reoffers(&mut index, true);
    assert_eq!(owed(&index).len(), 1);
}

#[test]
fn two_folders_are_judged_alone_and_the_mixed_one_stays_owed() {
    let one = folder("recorded-one-login");
    let two = folder("recorded-two-logins");
    let mut index = ScanIndex::default();
    begin_page(
        &mut index,
        &ScanIndex::default(),
        &[one.root.clone(), two.root.clone()],
        true,
    );
    observe_owner(one.key.clone(), folder_report());
    observe_owner(two.key.clone(), folder_report());
    let mut clean = one.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    let mut foreign = two.read(
        SESSION_A,
        &[
            context(OTHER_ADDRESS, SESSION_A),
            marker(ORG_UUID, SESSION_A),
            assistant(SESSION_A, "req_b", "2026-08-02T07:00:00Z"),
        ],
    );
    let mut own_in_mixed = two.read(SESSION_B, &own_lines(SESSION_B, "req_c"));
    clean.append(&mut foreign);
    clean.append(&mut own_in_mixed);
    page(&mut index, &mut clean, true);
    assert!(witness(&clean[..1]).is_some());
    assert_eq!(witness(&clean[1..2]), None);
    assert_eq!(witness(&clean[2..]), None, "a matching session stays owed");
    assert!(two.record(&index).mixed);
    assert!(two.record(&index).matched.is_empty());
    assert!(!one.record(&index).mixed);
    assert!(!proof_wanted_after_page(&mut index, &two));
}

fn proof_wanted_after_page(index: &mut ScanIndex, f: &Folder) -> bool {
    begin_page(index, &ScanIndex::default(), &[f.root.clone()], true);
    proof_wanted(&f.key)
}

#[test]
fn a_mid_session_swap_is_never_tagged_and_org_must_match_too() {
    let f = folder("recorded-swap");
    let mut index = ScanIndex::default();
    f.begin(&mut index, folder_report());
    let mut swapped = f.read(
        SESSION_A,
        &[
            context(ADDRESS, SESSION_A),
            marker(ORG_UUID, SESSION_A),
            assistant(SESSION_A, "req_1", "2026-08-02T07:00:00Z"),
            context(OTHER_ADDRESS, SESSION_A),
            assistant(SESSION_A, "req_2", "2026-08-02T07:05:00Z"),
        ],
    );
    page(&mut index, &mut swapped, true);
    assert_eq!(witness(&swapped), None);
    assert!(f.record(&index).mixed);

    let g = folder("recorded-other-org");
    let mut index = ScanIndex::default();
    g.begin(&mut index, folder_report());
    let mut other_org = g.read(
        SESSION_A,
        &[
            context(ADDRESS, SESSION_A),
            marker(OTHER_ORG_UUID, SESSION_A),
            assistant(SESSION_A, "req_1", "2026-08-02T07:00:00Z"),
        ],
    );
    page(&mut index, &mut other_org, true);
    assert_eq!(witness(&other_org), None);
    assert!(g.record(&index).mixed);
}

#[test]
fn a_login_change_stops_later_names_and_is_counted() {
    let f = folder("recorded-login-change");
    let mut index = ScanIndex::default();
    f.begin(&mut index, folder_report());
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut items, true);
    assert!(witness(&items).is_some());

    let other = ("b".repeat(64), org_of(ORG_UUID));
    observe_owner(
        f.key.clone(),
        OwnerReport {
            pair: Some(other.clone()),
            proven: Some(other),
            ..folder_report()
        },
    );
    let mut later = f.read(SESSION_B, &own_lines(SESSION_B, "req_b"));
    page(&mut index, &mut later, true);
    assert_eq!(witness(&later), None);
    assert!(f.record(&index).mixed);
    assert_eq!(f.record(&index).late_contradictions, 1);

    observe_owner(f.key.clone(), folder_report());
    let mut back = f.read(SESSION_B, &own_lines(SESSION_B, "req_b"));
    page(&mut index, &mut back, true);
    assert_eq!(
        witness(&back),
        None,
        "the first login returning lifts nothing"
    );
    assert_eq!(f.record(&index).late_contradictions, 1);

    // A proof naming another owner than `.claude.json` is a split login.
    let g = folder("recorded-split");
    let mut index = ScanIndex::default();
    g.begin(
        &mut index,
        OwnerReport {
            proven: Some(("c".repeat(64), org_of(ORG_UUID))),
            ..folder_report()
        },
    );
    page(&mut index, &mut [], true);
    assert!(g.record(&index).mixed);
}

#[test]
fn a_new_slot_names_from_its_first_read_and_never_needs_a_re_offer() {
    let f = folder("recorded-new-slot");
    let mut index = ScanIndex::default();
    f.begin(&mut index, slot_report());
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut items, false);
    assert_eq!(witness(&items).expect("named").kind, "slot");
    seed(&mut index, &f.path(SESSION_A), 100);
    step_reoffers(&mut index, true);
    assert_eq!(f.record(&index).reoffer, REOFFER_DONE);
    assert!(owed(&index).is_empty());

    observe_owner(
        f.key.clone(),
        OwnerReport {
            slot: true,
            other_account: true,
            ..OwnerReport::default()
        },
    );
    let mut later = f.read(SESSION_B, &own_lines(SESSION_B, "req_b"));
    page(&mut index, &mut later, false);
    assert_eq!(
        witness(&later),
        None,
        "another account in the slot is sticky"
    );
    assert!(f.record(&index).mixed);
}

#[test]
fn an_upgraded_slot_needs_every_session_to_match() {
    let f = folder("recorded-upgraded-slot");
    let mut index = ScanIndex::default();
    f.begin_upgraded(&mut index, slot_report());
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut items, true);
    assert_eq!(witness(&items), None, "no census yet");
    assert!(!f.record(&index).census_complete);

    let mut silent = f.read(
        SESSION_B,
        &[assistant(SESSION_B, "req_b", "2026-08-02T07:00:00Z")],
    );
    page(&mut index, &mut silent, true);
    assert!(f.record(&index).mixed, "a session with no recorded login");
}

/// Upgraded history: one wire-silent census read, then one tag read of the
/// matched files only, each stepped and capped.
#[test]
fn an_upgraded_folder_reads_its_census_first_then_re_offers_its_own_files() {
    let f = folder("recorded-upgraded");
    let mut index = ScanIndex::default();
    f.begin_upgraded(&mut index, folder_report());
    seed(&mut index, &f.path(SESSION_A), 100);
    seed(&mut index, &f.path("no-own-marker"), 100);
    step_reoffers(&mut index, true);
    assert_eq!(owed(&index).len(), 2, "the census reads every file");
    let mut read = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut read, false);
    assert_eq!(witness(&read), None);
    settle(&mut index);
    step_reoffers(&mut index, true);
    assert!(f.record(&index).census_complete);
    step_reoffers(&mut index, true);
    assert_eq!(
        owed(&index),
        BTreeSet::from([local_index_key(&f.path(SESSION_A))])
    );
    assert_eq!(f.record(&index).reoffer, REOFFER_TAG);
    let mut named = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut named, false);
    assert!(witness(&named).is_some());
}

#[test]
fn a_re_offer_is_capped_stepped_and_stops_at_a_sticky_verdict() {
    let f = folder("recorded-caps");
    let mut index = ScanIndex::default();
    f.begin_upgraded(&mut index, folder_report());
    seed(&mut index, &f.path("huge"), MAX_REOFFER_BYTES + 1);
    step_reoffers(&mut index, true);
    assert_eq!(f.record(&index).reoffer, REOFFER_TOO_BIG);
    assert!(owed(&index).is_empty(), "a too-big folder stays owed");

    let g = folder("recorded-steps");
    let mut index = ScanIndex::default();
    g.begin_upgraded(&mut index, folder_report());
    for file in 0..REOFFER_STEP_FILES + 1 {
        seed(&mut index, &g.path(&format!("{file:05}")), 1);
    }
    step_reoffers(&mut index, true);
    assert_eq!(owed(&index).len(), REOFFER_STEP_FILES);
    step_reoffers(&mut index, true);
    assert_eq!(
        owed(&index).len(),
        REOFFER_STEP_FILES,
        "earlier steps first"
    );
    settle(&mut index);
    index
        .claude_folder_login_ledger
        .get_mut(&g.key)
        .unwrap()
        .set_mixed();
    step_reoffers(&mut index, true);
    assert!(
        owed(&index).is_empty(),
        "a sticky folder is offered no more"
    );
}

#[test]
fn off_writes_nothing_and_asks_nothing() {
    let f = folder("recorded-off");
    let mut index = ScanIndex::default();
    begin_page(
        &mut index,
        &ScanIndex::default(),
        std::slice::from_ref(&f.root),
        true,
    );
    assert!(proof_wanted(&f.key));
    let mut off = ScanIndex::default();
    begin_page(
        &mut off,
        &ScanIndex::default(),
        std::slice::from_ref(&f.root),
        false,
    );
    assert!(off.claude_folder_login_ledger.is_empty());
    assert!(!proof_wanted(&f.key));
}

#[test]
fn a_session_copied_in_never_passes_the_own_session_gate() {
    let f = folder("recorded-copied");
    let lines = own_lines(SESSION_A, "req_1");
    let api = ClaudeLocalOtelLoadReport::default();
    let items = f.read(SESSION_A, &lines);
    let index = ScanIndex::default();
    assert!(own_session(&items[0], &index, &api));

    // Source present: another transcript carries the request.
    let mut duplicated = ScanIndex::default();
    duplicated.claude_duplicate_request_owners.insert(
        format!("{:x}", sha2::Sha256::digest(b"req_1")),
        BTreeSet::new(),
    );
    assert!(!own_session(&items[0], &duplicated, &api));

    // Source deleted: the file's birth is later than its responses.
    let copied = f.read_born(LATE_BIRTH, SESSION_A, &lines);
    assert!(copied.iter().all(|item| !own_session(item, &index, &api)));
}

type Reduction =
    crate::transcript_cache::Retained<crate::snapshots::sampled_jsonl::CachedJsonlReduction>;

/// One real read of the file through the resumable parser: whole with no
/// checkpoint, from the tail with one.
fn resumable_read(
    path: &Path,
    old: Option<Reduction>,
    now: u64,
) -> (
    Option<Reduction>,
    crate::transcript_acquisition::ReadMode,
    Vec<SnapshotItem>,
) {
    with_fixture_birth(EARLY_BIRTH, || {
        let scope = crate::transcript_acquisition::Scope("recorded-login-tail".into());
        let mut file = std::fs::File::open(path).unwrap();
        let expected = opened_object_identity(SnapshotSource::ClaudeCode, &mut file).unwrap();
        let mut parser = OwnedJsonlParser::new(
            file,
            path,
            SnapshotSource::ClaudeCode,
            apply_claude_code_line,
            Some(&CodexTitleMetadata::default()),
            None,
            None,
            false,
        )
        .unwrap();
        let debt = old.as_ref().and_then(|old| old.checkpoint.audit_debt());
        let mode = parser.prepare_acquisition(old, &scope, debt, now).unwrap();
        while !parser.step().unwrap() {}
        let acquisition = parser
            .retain_reduction(
                &scope,
                now,
                sampled_scan::RetainBudget::granted_unclassified(
                    crate::transcript_cache::ENTRY_BYTES,
                ),
            )
            .unwrap()
            .unwrap();
        let retained = acquisition.reduction.map(|state| Reduction {
            checkpoint: acquisition.checkpoint,
            state,
        });
        let parsed = parser
            .finish(
                &expected,
                path,
                "2026-08-02T07:10:00Z",
                "fingerprint".into(),
                Some(&CodexTitleMetadata::default()),
                Some(&ClaudeTitleMetadata::default()),
                None,
            )
            .unwrap();
        (retained, mode, parsed.snapshots)
    })
}

fn append(path: &Path, lines: &[Value]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    for line in lines {
        writeln!(file, "{line}").unwrap();
    }
}

/// The ledger as a restart reads it, in a process that has heard no report yet.
fn restored(index: &ScanIndex, f: &Folder) -> ScanIndex {
    let mut restored = ScanIndex::default();
    restored.claude_folder_login_ledger.extend(
        serde_json::from_value::<BTreeMap<String, FolderRecord>>(
            serde_json::to_value(&index.claude_folder_login_ledger).unwrap(),
        )
        .unwrap(),
    );
    begin_page(&mut restored, index, std::slice::from_ref(&f.root), true);
    restored
}

/// First a whole read names the session; returns its checkpoint.
fn named_session(f: &Folder, index: &mut ScanIndex) -> Option<Reduction> {
    f.begin(index, folder_report());
    let path = f.path(SESSION_A);
    let body: String = own_lines(SESSION_A, "req_1")
        .iter()
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(&path, body).unwrap();
    let (retained, _, mut items) = resumable_read(&path, None, 100);
    page(index, &mut items, true);
    assert!(witness(&items).is_some());
    assert!(retained.is_some());
    retained
}

#[test]
fn a_tail_read_after_restore_keeps_the_result_without_the_sentence() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = folder("recorded-tail");
    let mut index = ScanIndex::default();
    let retained = named_session(&f, &mut index);
    let path = f.path(SESSION_A);
    append(
        &path,
        &[assistant(SESSION_A, "req_2", "2026-08-02T07:05:00Z")],
    );
    let (_, mode, mut tailed) = resumable_read(&path, retained, 101);
    assert_eq!(mode, crate::transcript_acquisition::ReadMode::Tail);
    let trace = tailed[0]
        .claude_money
        .as_deref()
        .and_then(|fold| fold.folder_trace.as_deref())
        .unwrap();
    assert!(!trace.whole);
    assert_eq!(trace.email, None, "the sentence is not in this read");

    let mut index = restored(&index, &f);
    observe_owner(f.key.clone(), folder_report());
    page(&mut index, &mut tailed, false);
    assert!(
        witness(&tailed).is_some(),
        "the persisted result carries it"
    );
    assert!(!serde_json::to_string(&index.claude_folder_login_ledger)
        .unwrap()
        .contains(&address_digest(ADDRESS)));
}

#[test]
fn a_fork_reference_growing_by_tail_ends_the_name_and_never_returns() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = folder("recorded-tail-fork");
    let mut index = ScanIndex::default();
    let retained = named_session(&f, &mut index);
    let path = f.path(SESSION_A);
    append(
        &path,
        &[
            json!({"type": "fork-context-ref", "sessionId": SESSION_A,
                "timestamp": "2026-08-02T07:04:00Z"}),
            assistant(SESSION_A, "req_2", "2026-08-02T07:05:00Z"),
        ],
    );
    let (retained, mode, mut tailed) = resumable_read(&path, retained, 101);
    assert_eq!(mode, crate::transcript_acquisition::ReadMode::Tail);
    page(&mut index, &mut tailed, false);
    assert_eq!(witness(&tailed), None);
    assert!(f.record(&index).matched.is_empty());

    // Restored, and growing with its own marker lines again: a tail read never
    // saw the start of the file, so it cannot earn the result back.
    let mut index = restored(&index, &f);
    observe_owner(f.key.clone(), folder_report());
    append(
        &path,
        &[
            context(ADDRESS, SESSION_A),
            marker(ORG_UUID, SESSION_A),
            assistant(SESSION_A, "req_3", "2026-08-02T07:06:00Z"),
        ],
    );
    let (_, mode, mut again) = resumable_read(&path, retained, 102);
    assert_eq!(mode, crate::transcript_acquisition::ReadMode::Tail);
    page(&mut index, &mut again, false);
    assert_eq!(witness(&again), None);
}

#[test]
fn later_real_telemetry_replaces_the_name_for_good() {
    let f = folder("recorded-correction");
    let mut index = ScanIndex::default();
    f.begin(&mut index, folder_report());
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_1"));
    page(&mut index, &mut items, true);
    assert!(witness(&items).is_some());

    let root = crate::snapshots::claude_snapshot_family_root_ref(&items[0]).to_owned();
    let mut api = ClaudeLocalOtelLoadReport::default();
    api.evidence.insert(
        root,
        vec![crate::claude_local_otel::ClaudeLocalOtelEvidence {
            request_id: "req_1".to_string(),
            ..Default::default()
        }],
    );
    note_page(&mut index, &items, &api, true);
    stamp_page(&mut items, &index, &api, &AcceptedBuckets::for_test());
    assert_eq!(witness(&items), None, "this file's own row owns it now");
    assert!(f.record(&index).matched.is_empty());

    // A re-offered later read sees no file left to offer.
    seed(&mut index, &f.path(SESSION_A), 100);
    step_reoffers(&mut index, true);
    assert!(owed(&index).is_empty());
}
