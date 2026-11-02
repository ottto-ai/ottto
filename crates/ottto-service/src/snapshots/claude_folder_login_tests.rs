// Recorded-login naming per folder. Synthetic hashes and addresses only; the
// sentence and the line keys follow the real transcript shape.
use super::*;
use crate::claude_status_coverage::{observe, proof_wanted};
use crate::snapshots::claude_request_identity::marker_org_hash;
use crate::snapshots::claude_request_money::e2::with_fixture_birth;
use crate::snapshots::claude_response_compaction_tests::acquire_items;
use crate::snapshots::{parse_claude_code_jsonl_file, ScanIndexEntry};
use serde_json::{json, Value};

const ORG_UUID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_ORG_UUID: &str = "22222222-2222-4222-8222-222222222222";
const SESSION_A: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const SESSION_B: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const ADDRESS: &str = "one.login+tag@Example.test";
const OTHER_ADDRESS: &str = "second@example.test";
const EARLY_BIRTH: u64 = 1_785_542_400_000_000_000;
const LATE_BIRTH: u64 = 1_785_801_600_000_000_000;
const NOW: i64 = 1_785_801_600;

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

fn context(address: &str, session: &str) -> Value {
    json!({"type": "attachment", "sessionId": session, "timestamp": "2026-08-02T06:59:58Z",
        "isSidechain": false, "entrypoint": "cli", "attachment": {"type": "session_context",
            "context": {"userEmail": sentence(address), "gitStatus": ""}}})
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
        observe(self.key.clone(), report);
    }

    /// A folder whose first read predates the record.
    fn begin_upgraded(&self, index: &mut ScanIndex, report: OwnerReport) {
        let mut committed = ScanIndex::default();
        committed.files.insert(
            local_index_key(&self.path("old")),
            ScanIndexEntry::default(),
        );
        begin_page(index, &committed, std::slice::from_ref(&self.root), true);
        observe(self.key.clone(), report);
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

/// [money] A real multi-page first walk: only the last page can be tagged at
/// upload, and the single re-offer brings the earlier page to 100%.
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
    apply_reoffers(&mut index, false, NOW);
    assert!(owed(&index).is_empty(), "off offers nothing");
    apply_reoffers(&mut index, true, NOW);
    assert_eq!(
        owed(&index),
        BTreeSet::from([
            local_index_key(&f.path(SESSION_A)),
            local_index_key(&f.path(SESSION_B))
        ]),
        "only matched own files are offered"
    );
    apply_reoffers(&mut index, true, NOW);
    settle(&mut index);
    apply_reoffers(&mut index, true, NOW);
    assert_eq!(f.record(&index).reoffer, REOFFER_DONE);
    assert!(owed(&index).is_empty());
    apply_reoffers(&mut index, true, NOW);
    assert!(owed(&index).is_empty(), "never repeats");

    let mut again = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut again, true);
    assert!(witness(&again).is_some(), "the re-offered read is named");
}

/// [regress]
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
    apply_reoffers(&mut index, true, NOW);
    assert!(owed(&index).is_empty());

    observe(f.key.clone(), folder_report());
    page(&mut index, &mut [], true);
    apply_reoffers(&mut index, true, NOW);
    assert_eq!(owed(&index).len(), 1);
}

/// [regress]
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
    observe(one.key.clone(), folder_report());
    observe(two.key.clone(), folder_report());
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
    begin_page(
        index,
        &ScanIndex::default(),
        std::slice::from_ref(&f.root),
        true,
    );
    proof_wanted(&f.key)
}

/// [money]
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

/// [regress]
#[test]
fn a_login_change_stops_later_names() {
    let f = folder("recorded-login-change");
    let mut index = ScanIndex::default();
    f.begin(&mut index, folder_report());
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut items, true);
    assert!(witness(&items).is_some());

    let other = ("b".repeat(64), org_of(ORG_UUID));
    observe(
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

    observe(f.key.clone(), folder_report());
    let mut back = f.read(SESSION_B, &own_lines(SESSION_B, "req_b"));
    page(&mut index, &mut back, true);
    assert_eq!(
        witness(&back),
        None,
        "the first login returning lifts nothing"
    );

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

/// [money]
#[test]
fn a_new_slot_names_from_its_first_read_and_never_needs_a_re_offer() {
    let f = folder("recorded-new-slot");
    let mut index = ScanIndex::default();
    f.begin(&mut index, slot_report());
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut items, false);
    assert_eq!(witness(&items).expect("named").kind, "slot");
    seed(&mut index, &f.path(SESSION_A), 100);
    apply_reoffers(&mut index, true, NOW);
    assert_eq!(f.record(&index).reoffer, REOFFER_DONE);
    assert!(owed(&index).is_empty());

    observe(
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

/// [money]
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

/// [money] Upgraded history: one wire-silent census read, then one tag read of
/// the matched files only.
#[test]
fn an_upgraded_folder_reads_its_census_first_then_re_offers_its_own_files() {
    let f = folder("recorded-upgraded");
    let mut index = ScanIndex::default();
    f.begin_upgraded(&mut index, folder_report());
    seed(&mut index, &f.path(SESSION_A), 100);
    seed(&mut index, &f.path("no-own-marker"), 100);
    apply_reoffers(&mut index, true, NOW);
    assert_eq!(owed(&index).len(), 2, "the census reads every file");
    let mut read = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut read, false);
    assert_eq!(witness(&read), None);
    settle(&mut index);
    apply_reoffers(&mut index, true, NOW);
    assert!(f.record(&index).census_complete);
    apply_reoffers(&mut index, true, NOW);
    assert_eq!(
        owed(&index),
        BTreeSet::from([local_index_key(&f.path(SESSION_A))])
    );
    assert_eq!(f.record(&index).reoffer, REOFFER_TAG);
    let mut named = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut named, false);
    assert!(witness(&named).is_some());
}

/// [regress]
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

/// [money]
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

type Reduction =
    crate::transcript_cache::Retained<crate::snapshots::sampled_jsonl::CachedJsonlReduction>;

fn resumable_read(
    path: &Path,
    old: Option<Reduction>,
    now: u64,
) -> (
    Option<Reduction>,
    crate::transcript_acquisition::ReadMode,
    Vec<SnapshotItem>,
) {
    with_fixture_birth(EARLY_BIRTH, || acquire_items(path, old, now))
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

/// [regress]
#[test]
fn a_tail_read_after_a_restart_stays_named() {
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
    let mut index = restored(&index, &f);
    observe(f.key.clone(), folder_report());
    page(&mut index, &mut tailed, false);
    assert!(
        witness(&tailed).is_some(),
        "the retained markers carry the sentence"
    );
    assert!(!serde_json::to_string(&index.claude_folder_login_ledger)
        .unwrap()
        .contains(&address_digest(ADDRESS)));
}

/// [regress]
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

    // Restored, and growing with its own marker lines again: the retained fork
    // reference keeps it out for good.
    let mut index = restored(&index, &f);
    observe(f.key.clone(), folder_report());
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

/// [money]
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
    apply_reoffers(&mut index, true, NOW);
    assert!(owed(&index).is_empty());
}

/// [regress] Counts only, with the 8-hex key; a stalled re-offer warns, never stops.
#[test]
fn a_re_offer_reports_counts_and_warns_only_when_it_stalls() {
    let home = "ab".repeat(32);
    let mut record = FolderRecord {
        reoffer: REOFFER_CENSUS,
        ..FolderRecord::default()
    };
    let tally = ReofferTally {
        files: 2_001,
        bytes: 3 * HISTORY_UPGRADE_BYTES_PER_PAGE,
        owed_files: 2_001,
        owed_bytes: 3 * HISTORY_UPGRADE_BYTES_PER_PAGE,
        ..ReofferTally::default()
    };
    assert_eq!(
        reoffer_line(&home, &mut record, &tally, NOW).unwrap(),
        format!(
            "ottto-service: claude folder re-offer folder=abababab phase=census files_read=0 \
             bytes_read=0 files_released=0 bytes_released=0 files_remaining=2001 \
             bytes_remaining={} eta_minutes=15",
            3 * HISTORY_UPGRADE_BYTES_PER_PAGE
        )
    );
    assert_eq!(reoffer_line(&home, &mut record, &tally, NOW + 300), None);
    let warning = reoffer_line(&home, &mut record, &tally, NOW + STALL_SECONDS).unwrap();
    assert!(warning.contains("warning") && warning.contains("folder=abababab"));
    assert_eq!(
        reoffer_line(&home, &mut record, &tally, NOW + STALL_SECONDS + 300),
        None,
        "bounded"
    );
}

/// [regress] A damaged ledger keeps every folder first seen after it sticky.
#[test]
fn a_damaged_ledger_fails_closed() {
    let f = folder("recorded-damaged");
    let mut index = ScanIndex {
        claude_folder_login_ledger: damaged_ledger(),
        ..ScanIndex::default()
    };
    f.begin(&mut index, folder_report());
    assert!(f.record(&index).mixed);
    let mut items = f.read(SESSION_A, &own_lines(SESSION_A, "req_a"));
    page(&mut index, &mut items, true);
    assert_eq!(witness(&items), None);
    seed(&mut index, &f.path(SESSION_A), 100);
    apply_reoffers(&mut index, true, NOW);
    assert!(owed(&index).is_empty());
}

/// [money] A folder turning sticky hands back only what its own census lowered;
/// a file owed for any other reason keeps its read, and a qualifying folder's
/// census goes on.
#[test]
fn a_sticky_folder_releases_only_its_own_census_files() {
    let f = folder("recorded-release");
    let g = folder("recorded-release-other");
    let mut index = ScanIndex::default();
    f.begin_upgraded(&mut index, folder_report());
    g.begin_upgraded(&mut index, folder_report());
    let key = |name: &str| local_index_key(&f.path(name));
    for name in [SESSION_A, "unread", "re-owed", "owed-before"] {
        seed(&mut index, &f.path(name), 100);
    }
    seed(&mut index, &g.path(SESSION_B), 100);
    index
        .files
        .get_mut(&key("owed-before"))
        .unwrap()
        .effective_upload_body_witness_revision = 2;
    apply_reoffers(&mut index, true, NOW);
    assert_eq!(owed(&index).len(), 5);
    index.re_owe_effective_upload_body_witness_revision(&key("re-owed"), 2);

    let mut first = f.read(
        SESSION_A,
        &[
            context(OTHER_ADDRESS, SESSION_A),
            marker(ORG_UUID, SESSION_A),
            assistant(SESSION_A, "req_a", "2026-08-02T07:00:00Z"),
        ],
    );
    page(&mut index, &mut first, false);
    assert!(f.record(&index).mixed);
    apply_reoffers(&mut index, true, NOW + 300);
    assert_eq!(
        owed(&index),
        BTreeSet::from([
            key("re-owed"),
            key("owed-before"),
            local_index_key(&g.path(SESSION_B)),
        ]),
    );
    assert!(f.record(&index).reoffer_owed.is_empty());
    assert_eq!(g.record(&index).reoffer, REOFFER_CENSUS);
    apply_reoffers(&mut index, true, NOW + 600);
    assert_eq!(owed(&index).len(), 3, "released once, never owed again");
}

/// [money] A newer revision since the census began owes the file for real.
#[test]
fn a_revision_change_keeps_a_sticky_folders_files_owed() {
    let f = folder("recorded-release-revision");
    let mut index = ScanIndex::default();
    f.begin_upgraded(&mut index, folder_report());
    seed(&mut index, &f.path(SESSION_A), 100);
    apply_reoffers(&mut index, true, NOW);
    index
        .claude_folder_login_ledger
        .get_mut(&f.key)
        .unwrap()
        .set_mixed();
    index.active_effective_upload_body_witness_revision = 4;
    apply_reoffers(&mut index, true, NOW + 300);
    assert_eq!(owed(&index).len(), 1);
    assert!(f.record(&index).reoffer_owed.is_empty());
}
