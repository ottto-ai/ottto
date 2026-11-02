// The folder ledger and its pure verdict. Synthetic hashes only.
use super::*;
use serde_json::json;

const ORG_UUID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_ORG_UUID: &str = "22222222-2222-4222-8222-222222222222";
const SESSION: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const EARLY_BIRTH: u64 = 1_785_542_400_000_000_000;
const LATE_BIRTH: u64 = 1_785_801_600_000_000_000;

fn login() -> String {
    "a".repeat(64)
}

fn org_of(uuid: &str) -> String {
    marker_org_hash(&json!({ "organizationUuid": uuid })).unwrap()
}

fn marker(uuid: &str) -> Value {
    json!({"type": "attachment", "attachment": {"type": "credential_org", "organizationUuid": uuid}})
}

fn email(text: &str) -> Value {
    json!({"type": "attachment", "attachment": {"type": "session_context", "context": {"userEmail": text}}})
}

fn owner() -> OwnerReport {
    let pair = (login(), org_of(ORG_UUID));
    OwnerReport {
        slot_digest: slot_key("default"),
        cached: Some(pair.clone()),
        proven: Some(pair),
        email_digest: None,
        foreign_backup: false,
    }
}

fn traced(lines: &[Value]) -> FolderTrace {
    let mut trace = FolderTrace::default();
    for line in lines {
        trace.note_line(line, false);
    }
    trace
}

/// A fresh folder whose census saw one marker and one proven owner.
fn clean() -> FolderRecord {
    let mut record = FolderRecord {
        fresh: true,
        ..FolderRecord::default()
    };
    record.note_trace(&traced(&[marker(ORG_UUID)]));
    record.covered_from = Some(1_785_654_000);
    record.absorb_owner(&owner());
    record.census_complete = true;
    record
}

fn verdict(record: &FolderRecord) -> bool {
    qualify(record, true, Some(&owner())).is_some()
}

#[test]
fn one_login_one_folder_clean_census_qualifies_with_an_opaque_witness() {
    let record = clean();
    let org = org_of(ORG_UUID);
    let login = login();
    assert_eq!(
        qualify(&record, true, Some(&owner())),
        Some((login.as_str(), org.as_str(), 1_785_654_000))
    );
    assert_eq!(
        covered_from_text(1_785_654_000).unwrap(),
        "2026-08-02T07:00:00Z"
    );
    let accepted = AcceptedBuckets::for_test();
    let folder = accepted.folder_token("folder-a").unwrap();
    assert_eq!(folder.len(), 8);
    assert!(folder.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(folder, accepted.folder_token("folder-b").unwrap());
    assert_eq!(AcceptedBuckets::default().folder_token("folder-a"), None);
}

#[test]
fn every_unmet_condition_withholds_the_name() {
    let record = clean();
    assert!(qualify(&record, false, Some(&owner())).is_none());
    assert!(qualify(&record, true, None).is_none());
    for change in [
        (|record: &mut FolderRecord| record.fresh = false) as fn(&mut FolderRecord),
        |record: &mut FolderRecord| record.census_complete = false,
        |record: &mut FolderRecord| record.covered_from = None,
        |record: &mut FolderRecord| record.seen_org = None,
    ] {
        let mut changed = clean();
        change(&mut changed);
        assert!(!verdict(&changed));
    }
    // The current token not yet proven, or the cached pair not matching it.
    let unproven = OwnerReport {
        proven: None,
        ..owner()
    };
    assert!(qualify(&record, true, Some(&unproven)).is_none());
    let unconfirmed = OwnerReport {
        cached: None,
        ..owner()
    };
    assert!(qualify(&record, true, Some(&unconfirmed)).is_none());
}

#[test]
fn a_foreign_org_marker_is_sticky() {
    let mut record = clean();
    record.note_trace(&traced(&[marker(ORG_UUID), marker(OTHER_ORG_UUID)]));
    assert!(!verdict(&record));
    assert_eq!(record.late_contradictions, 1);
    record.absorb_owner(&owner());
    assert!(!verdict(&record));

    // One malformed organization is a contradiction of its own.
    let mut malformed = clean();
    malformed.note_trace(&traced(&[marker("not-a-uuid")]));
    assert!(!verdict(&malformed));
}

#[test]
fn a_second_seat_trace_in_one_org_is_sticky_case_by_case() {
    let org = org_of(ORG_UUID);
    let other = "b".repeat(64);

    let mut sidecar = clean();
    sidecar.note_pair(Some(&login()), Some(&org));
    assert!(verdict(&sidecar), "the same seat is no contradiction");
    sidecar.note_pair(Some(&other), Some(&org));
    assert!(!verdict(&sidecar));

    let mut sole_mismatch = clean();
    sole_mismatch.note_pair(Some(&other), Some(&org));
    sole_mismatch.absorb_owner(&owner());
    assert!(!verdict(&sole_mismatch));

    let mut emails = clean();
    emails.note_trace(&traced(&[
        email("one@example.test"),
        email("two@example.test"),
    ]));
    assert!(!verdict(&emails));

    let mut across_files = clean();
    across_files.note_trace(&traced(&[email("one@example.test")]));
    across_files.note_trace(&traced(&[email("two@example.test")]));
    assert!(!verdict(&across_files));

    let mut cached_email = clean();
    cached_email.note_trace(&traced(&[email("one@example.test")]));
    cached_email.absorb_owner(&OwnerReport {
        email_digest: Some(marker_email_digest("two@example.test")),
        ..owner()
    });
    assert!(!verdict(&cached_email));

    let mut backup = clean();
    backup.absorb_owner(&OwnerReport {
        foreign_backup: true,
        ..owner()
    });
    assert!(!verdict(&backup));

    // Desktop's pair reaches the ledger the same way a sidecar pair does.
    let mut desktop = clean();
    desktop.note_pair(Some(&other), Some(&"e".repeat(64)));
    assert!(!verdict(&desktop));
}

#[test]
fn another_slot_or_owner_or_split_login_is_sticky_but_no_proof_is_only_not_yet() {
    let mut slot = clean();
    slot.absorb_owner(&OwnerReport {
        slot_digest: slot_key("slot-2"),
        ..owner()
    });
    assert!(!verdict(&slot));

    let mut split = clean();
    split.absorb_owner(&OwnerReport {
        cached: Some(("c".repeat(64), org_of(ORG_UUID))),
        ..owner()
    });
    assert!(!verdict(&split));

    let mut not_yet = clean();
    not_yet.absorb_owner(&OwnerReport {
        cached: Some(("c".repeat(64), org_of(ORG_UUID))),
        proven: None,
        ..owner()
    });
    assert_eq!(not_yet.disqualified, 0);
    assert!(verdict(&not_yet));
}

#[test]
fn a_second_login_after_tags_stops_later_tags_and_is_counted() {
    let mut record = clean();
    assert!(verdict(&record));
    let other = ("b".repeat(64), org_of(ORG_UUID));
    let second = OwnerReport {
        cached: Some(other.clone()),
        proven: Some(other),
        ..owner()
    };
    record.absorb_owner(&second);
    assert!(!verdict(&record));
    assert_eq!(record.late_contradictions, 1);
    // The first login returning never lifts it.
    record.absorb_owner(&owner());
    assert!(!verdict(&record));
    assert_eq!(record.late_contradictions, 1);
}

#[test]
fn two_folders_are_judged_alone() {
    let clean_folder = clean();
    let mut mixed = clean();
    mixed.note_trace(&traced(&[marker(OTHER_ORG_UUID)]));
    assert!(verdict(&clean_folder));
    assert!(!verdict(&mixed));
    let accepted = AcceptedBuckets::for_test();
    assert_ne!(
        accepted.folder_token("folder-a"),
        accepted.folder_token("folder-b")
    );
}

#[test]
fn trace_lines_keep_inherited_markers_and_mark_a_fork() {
    assert!(!line_matters(&json!({"type": "assistant"}), false));
    assert!(line_matters(&json!({"type": "assistant"}), true));
    assert!(line_matters(&marker(ORG_UUID), false));
    assert!(line_matters(&json!({"type": "fork-context-ref"}), false));

    let mut trace = FolderTrace::default();
    trace.note_line(&marker(ORG_UUID), false);
    assert!(!trace.forked);
    trace.note_line(&marker(OTHER_ORG_UUID), true);
    assert!(
        trace.forked && trace.other_org,
        "an inherited marker counts"
    );

    let mut referenced = FolderTrace::default();
    referenced.note_line(&json!({"type": "fork-context-ref"}), false);
    assert!(referenced.forked);

    let mut blank = FolderTrace::default();
    blank.note_line(&email("   "), false);
    assert_eq!(blank.email, None, "a blank email proves nothing");
}

fn assistant(request: &str, at: &str) -> Value {
    json!({"type": "assistant", "sessionId": SESSION, "timestamp": at, "requestId": request,
        "message": {"id": format!("msg_{request}"), "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 10, "output_tokens": 1}}})
}

/// A real read of one transcript under `<scratch>/cfg/projects/p`.
fn parsed(birth: u64, lines: &[Value]) -> (PathBuf, Vec<SnapshotItem>) {
    let scratch = crate::test_scratch::private_dir("claude-folder-login");
    let project = scratch.join("cfg/projects/p");
    std::fs::create_dir_all(&project).unwrap();
    let path = project.join(format!("{SESSION}.jsonl"));
    let body: String = lines.iter().map(|line| format!("{line}\n")).collect();
    std::fs::write(&path, body).unwrap();
    let items = crate::snapshots::claude_request_money::e2::with_fixture_birth(birth, || {
        // The plain parser: an ordinary-money fixture builds no fold.
        crate::snapshots::parse_claude_code_jsonl_file(
            &path,
            "2026-08-02T07:10:00Z",
            "fingerprint".to_string(),
        )
        .unwrap()
    });
    (scratch, items)
}

#[test]
fn a_real_read_feeds_the_ledger_and_stamps_its_own_session() {
    let lines = [
        marker(ORG_UUID),
        assistant("req_1", "2026-08-02T07:00:00Z"),
        assistant("req_2", "2026-08-02T08:20:00Z"),
    ];
    let (scratch, mut items) = parsed(EARLY_BIRTH, &lines);
    let root = scratch.join("cfg/projects");
    let key = folder_key(&scratch.join("cfg"));
    let mut index = ScanIndex::default();
    begin_page(&mut index, &ScanIndex::default(), &[root], true);
    assert!(is_candidate(&key));
    observe_owner(key.clone(), owner());
    let api = ClaudeLocalOtelLoadReport::default();
    note_page(&mut index, &items, &api, &BTreeMap::new(), true);
    let accepted = AcceptedBuckets::for_test();
    stamp_page(&mut items, &index, &api, &accepted);
    let fold = items[0].claude_money.as_deref().unwrap();
    let sole = fold
        .folder_trace
        .as_deref()
        .and_then(FolderTrace::sole)
        .unwrap();
    assert_eq!(sole.login, login());
    assert_eq!(sole.org, org_of(ORG_UUID));
    assert_eq!(sole.witness.v, 1);
    assert_eq!(sole.witness.covered_from, "2026-08-02T07:00:00Z");
    assert_eq!(sole.witness.folder, accepted.folder_token(&key).unwrap());
}

#[test]
fn a_folder_read_before_the_ledger_existed_stays_owed() {
    let (scratch, mut items) = parsed(
        EARLY_BIRTH,
        &[marker(ORG_UUID), assistant("req_1", "2026-08-02T07:00:00Z")],
    );
    let root = scratch.join("cfg/projects");
    let key = folder_key(&scratch.join("cfg"));
    let committed: ScanIndex = serde_json::from_value(json!({"files": {
        format!("{}/p/old.jsonl", root.display()):
            serde_json::to_value(crate::snapshots::ScanIndexEntry::default()).unwrap()
    }}))
    .unwrap();
    let mut index = ScanIndex::default();
    begin_page(&mut index, &committed, &[root], true);
    assert!(!is_candidate(&key), "no proof is ever asked for it");
    observe_owner(key, owner());
    let api = ClaudeLocalOtelLoadReport::default();
    note_page(&mut index, &items, &api, &BTreeMap::new(), true);
    stamp_page(&mut items, &index, &api, &AcceptedBuckets::for_test());
    let fold = items[0].claude_money.as_deref().unwrap();
    assert!(fold.folder_trace.as_deref().unwrap().sole().is_none());
}

#[test]
fn off_writes_nothing_and_asks_nothing() {
    let scratch = crate::test_scratch::private_dir("claude-folder-login-off");
    let root = scratch.join("cfg/projects");
    let mut index = ScanIndex::default();
    begin_page(
        &mut index,
        &ScanIndex::default(),
        std::slice::from_ref(&root),
        true,
    );
    assert!(is_candidate(&folder_key(&scratch.join("cfg"))));
    let mut off = ScanIndex::default();
    begin_page(&mut off, &ScanIndex::default(), &[root], false);
    assert!(off.claude_folder_login_ledger.is_empty());
    assert!(!is_candidate(&folder_key(&scratch.join("cfg"))));
}

#[test]
fn a_session_copied_in_never_passes_the_own_session_gate() {
    let lines = [assistant("req_1", "2026-08-02T07:00:00Z")];
    let api = ClaudeLocalOtelLoadReport::default();
    let (_scratch, items) = parsed(EARLY_BIRTH, &lines);
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
    let (_scratch, copied) = parsed(LATE_BIRTH, &lines);
    assert!(copied.iter().all(|item| !own_session(item, &index, &api)));
}
