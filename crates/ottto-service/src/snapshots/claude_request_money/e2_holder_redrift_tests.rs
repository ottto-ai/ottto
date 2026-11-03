//! The Holders copy decision rebuilds a file's accounts without its copied
//! markers. An own request whose account that flips moves with the rebuild,
//! whether or not it was staged; only placement changes, never its money.

use super::*;
use crate::claude_local_otel::ClaudeTraceOwnershipLoadReport;
use crate::snapshots::claude_money_birth_store::location_key;
use crate::snapshots::claude_request_census::{
    ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};
use crate::snapshots::tests::complete_api_row;
use crate::snapshots::upload_context_receipt::{EntityStamp, Receipt, RECEIPT_REPLAY_EPOCH};
use crate::snapshots::{apply_claude_code_line, SnapshotAccumulator, SnapshotSource};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const ROOT: &str = "b0000000-0000-4000-8000-00000000000b";
/// The earlier session of the same directory that holds the copied requests.
const HOLDER: &str = "c0000000-0000-4000-8000-00000000000c";
const T0: &str = "2026-08-02T07:00:00Z";
const ORG_A: &str = "11111111-1111-4111-8111-111111111111";
const ORG_B: &str = "22222222-2222-4222-8222-222222222222";
/// Outside the writer allowlist, so the copied prefix needs a Holders proof.
const UNCERTIFIED_WRITER: &str = "2.1.289";
const MATCHED: Option<ClaudeRequestUsageOrigin> = Some(ClaudeRequestUsageOrigin::TelemetryMatched);

fn t0() -> i128 {
    rfc3339_unix_nanos(T0).unwrap()
}
fn at(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(t0() + i128::from(seconds) * 1_000_000_000)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
fn line(id: &str, clock: &str, input: u64) -> Value {
    json!({"type":"assistant","version":UNCERTIFIED_WRITER,"sessionId":ROOT,"timestamp":clock,
        "requestId":id,"message":{"id":format!("msg-{id}"),"model":"claude-haiku-4-5",
        "usage":{"input_tokens":input,"output_tokens":1}}})
}
fn org_marker(org: &str) -> Value {
    json!({"type":"attachment","sessionId":ROOT,
        "attachment":{"type":"credential_org","organizationUuid":org}})
}
fn org_hash(org: &str) -> String {
    ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap()
}
fn scratch() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ottto-e2-redrift-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}
/// A scan index whose earlier main file proves `copied` by request id.
fn index_holding(dir: &Path, copied: &[&str]) -> ScanIndex {
    let holder = dir.join(format!("{HOLDER}.jsonl"));
    fs::write(&holder, b"fixture\n").unwrap();
    let key = local_index_key(&holder);
    let fingerprint = "a".repeat(64);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(json!({"size_bytes":8,"modified_unix_seconds":1,
            "source_file_fingerprint":fingerprint}))
        .unwrap(),
    );
    index
        .claude_money_birth_store
        .record_observation(HOLDER, &key, t0());
    let mut hashes = copied
        .iter()
        .map(|id| claude_request_hash(id))
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    index.claude_request_census_mut_for_test().insert_for_test(
        &key,
        ClaudeRequestCensusRecord::synthetic_for_test(
            &fingerprint,
            1,
            ClaudeRequestCensusShape::Exact,
            hashes,
        ),
    );
    index
}
/// Parse a resumed file born at T0+100s, as the scan does.
fn read_file(path: &Path, index: &ScanIndex, lines: &[Value]) -> Vec<SnapshotItem> {
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    accumulator.claude_file_birth = ClaudeFileBirth::observe(path, None);
    accumulator
        .claude_file_birth
        .set_birth_for_test(t0() + 100_000_000_000);
    for value in lines {
        apply_claude_code_line(value, &mut accumulator);
    }
    accumulator.finalize_claude_responses_e2(Some(ReadContext {
        index,
        path,
        twins: &Default::default(),
    }));
    accumulator.into_items(path, "2026-08-02T09:00:00Z", "fixture".into(), None)
}
/// The live sidecar reader over exactly these rows for ROOT.
fn sidecar(rows: &[ClaudeLocalOtelEvidence]) -> ClaudeApiEvidenceRead {
    let support = scratch();
    let dir = support.join(crate::claude_local_otel::STORE_DIR);
    fs::create_dir_all(&dir).unwrap();
    let body = rows
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    fs::write(
        dir.join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes()))),
        body,
    )
    .unwrap();
    let read = ClaudeApiEvidenceRead::load(&support, [ROOT.to_owned()]).unwrap();
    fs::remove_dir_all(support).unwrap();
    read
}
fn entity(items: &[SnapshotItem]) -> &ClaudeEntityBody {
    &items[0].claude_money.as_deref().unwrap().entity
}
/// Requests on the grains of `org`'s transcript account.
fn on_org(items: &[SnapshotItem], org: &str) -> u64 {
    let org = org_hash(org);
    entity(items)
        .grains
        .iter()
        .filter(|((_, _, account), _)| {
            account.as_ref().and_then(|key| key.org.as_deref()) == Some(org.as_str())
        })
        .map(|(_, grain)| grain.requests)
        .sum()
}
fn matched(items: &[SnapshotItem]) -> u64 {
    entity(items)
        .grains
        .iter()
        .filter(|((_, origin, _), _)| *origin == MATCHED)
        .map(|(_, grain)| grain.requests)
        .sum()
}
fn cost_micros(items: &[SnapshotItem]) -> u64 {
    entity(items)
        .grains
        .values()
        .map(|grain| grain.cost_micros)
        .sum()
}
fn lent(items: &[SnapshotItem]) -> Vec<LentSlot> {
    items[0]
        .claude_money
        .as_deref()
        .and_then(|fold| fold.accounts.as_deref())
        .unwrap()
        .copied_marker_lent
        .values()
        .cloned()
        .collect()
}

/// What a body carries of a request's money.
#[derive(Debug, PartialEq)]
struct Money {
    requests: u64,
    input: u64,
    output: u64,
    removed: Option<u64>,
    cost: Option<String>,
}

/// One page's copy decision, attachment and reconcile, then the emitted body.
/// `check` sees the fold between attachment and reconcile.
fn run_page(
    copied: &[&str],
    lines: &[Value],
    rows: &[ClaudeLocalOtelEvidence],
    check: impl FnOnce(&[SnapshotItem]),
) -> Money {
    let dir = scratch();
    let path = dir.join(format!("{ROOT}.jsonl"));
    fs::write(&path, b"fixture\n").unwrap();
    let mut index = index_holding(&dir, copied);
    accepted_receipt(&mut index, &dir);
    let mut items = read_file(&path, &index, lines);
    decide_page_copies(&mut items, &index, None);
    let read = sidecar(rows);
    attach_page(&mut items, &read);
    check(&items);
    let before = entity(&items).totals();
    let cost = cost_micros(&items);
    let api = ClaudeLocalOtelLoadReport {
        evidence: read.evidence.clone(),
        health: Default::default(),
    };
    let trace = ClaudeTraceOwnershipLoadReport::default();
    let evidence = claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
    claude_request_identity::reconcile_request_accounts(&mut items, &evidence);
    assert!(
        entity(&items).certificate_ok,
        "{:?}",
        entity(&items).certificate_failure.map(|f| f.hold_reason())
    );
    assert_eq!(entity(&items).totals(), before, "reconcile moves no tokens");
    assert_eq!(cost_micros(&items), cost, "reconcile moves no cost");
    let slots = lent(&items);
    assert!(
        slots.iter().all(|slot| entity(&items)
            .grains
            .keys()
            .any(|(key, origin, _)| *key == slot.key && *origin == slot.origin)),
        "#944 reads the row each lent request ended on"
    );
    let mut reasons = BTreeMap::new();
    let withheld = finish_page(
        &mut items,
        &index,
        TelemetryRead::Loaded,
        &mut reasons,
        &Default::default(),
    );
    assert!(withheld.is_empty(), "{reasons:?}");
    let item = &items[0];
    let money = Money {
        requests: item.request_count,
        input: item.input_tokens,
        output: item.output_tokens,
        removed: item.removed_request_count,
        cost: item
            .cost
            .as_ref()
            .and_then(|cost| cost.total_cost_usd.clone()),
    };
    let _ = fs::remove_dir_all(dir);
    money
}

fn own_row(id: &str, sequence: u64, input: u64) -> ClaudeLocalOtelEvidence {
    complete_api_row(ROOT, id, sequence, input, 1, 0)
}

/// Markers A(copied), B(copied), B(own), A(own). The original policy keeps A
/// throughout, so the requests after the last A are unstaged on A. Without
/// the copied markers B starts the file and that A is rejected: they belong
/// on B. Left on A they would lose their telemetry and uncertify the body
/// (`identity_grain.request.other_account`).
#[test]
fn e2_holder_rebuild_moves_unstaged_own_requests_and_conserves_money() {
    let copied = ["copy-a", "copy-b"];
    let rows = [
        own_row("own-b", 2, 20),
        own_row("own-a1", 3, 30),
        own_row("own-a2", 4, 40),
    ];
    let requests = [
        line("copy-a", &at(1), 10),
        line("copy-b", &at(2), 11),
        line("own-b", &at(101), 20),
        line("own-a1", &at(102), 30),
        line("own-a2", &at(103), 40),
    ];
    let [copy_a, copy_b, own_b, own_a1, own_a2] = requests.clone();
    let redrift = run_page(
        &copied,
        &[
            org_marker(ORG_A),
            copy_a,
            org_marker(ORG_B),
            copy_b,
            org_marker(ORG_B),
            own_b,
            org_marker(ORG_A),
            own_a1,
            own_a2,
        ],
        &rows,
        |items| {
            assert_eq!(on_org(items, ORG_A), 0, "nothing stays on the old account");
            assert_eq!(on_org(items, ORG_B), 3);
            assert_eq!(matched(items), 3, "every request attaches to its telemetry");
            assert_eq!(cost_micros(items), 300);
            let slots = lent(items);
            assert_eq!(slots.len(), 3, "#944 records all three loans");
            assert!(slots.iter().all(|slot| slot.lent.org.as_deref()
                == Some(org_hash(ORG_A).as_str())
                && slot.origin == MATCHED));
        },
    );
    // The same requests with no marker to drift: identical money.
    let oracle = run_page(&copied, &requests, &rows, |items| {
        assert_eq!(matched(items), 3);
        assert_eq!(cost_micros(items), 300);
        assert!(lent(items).is_empty());
    });
    assert_eq!(redrift, oracle);
    assert_eq!(
        (redrift.requests, redrift.input, redrift.removed),
        (3, 90, Some(2))
    );
}

/// Control: markers A(copied), B(own). Every own request is staged under the
/// B marker and moves once, through the existing repartition.
#[test]
fn e2_holder_rebuild_leaves_staged_only_drift_to_its_repartition() {
    let copied = ["copy-a"];
    let rows = [own_row("own-1", 1, 20), own_row("own-2", 2, 30)];
    let requests = [
        line("copy-a", &at(1), 10),
        line("own-1", &at(101), 20),
        line("own-2", &at(102), 30),
    ];
    let [copy_a, own_1, own_2] = requests.clone();
    let staged = run_page(
        &copied,
        &[org_marker(ORG_A), copy_a, org_marker(ORG_B), own_1, own_2],
        &rows,
        |items| {
            assert_eq!(on_org(items, ORG_A), 0);
            assert_eq!(on_org(items, ORG_B), 2);
            assert_eq!(matched(items), 2);
            assert_eq!(cost_micros(items), 200);
        },
    );
    let oracle = run_page(&copied, &requests, &rows, |_| {});
    assert_eq!(staged, oracle);
    assert_eq!(
        (staged.requests, staged.input, staged.removed),
        (2, 50, Some(1))
    );
}

/// The copied ids, an own turn, and one more page's copy decision on `index`.
fn decide_pass(index: &mut ScanIndex, path: &Path) -> Vec<SnapshotItem> {
    let lines = [
        line("copy-a", &at(1), 10),
        line("copy-b", &at(2), 11),
        line("own", &at(101), 20),
    ];
    let mut items = read_file(path, index, &lines);
    decide_page_copies(&mut items, index, None).apply(index);
    items
}
fn fold(items: &[SnapshotItem]) -> &FileFold {
    items[0].claude_money.as_deref().unwrap()
}
fn holder_key(dir: &Path) -> String {
    local_index_key(&dir.join(format!("{HOLDER}.jsonl")))
}
fn copy_at(dir: &Path) -> PathBuf {
    let path = dir.join(format!("{ROOT}.jsonl"));
    fs::write(&path, b"fixture\n").unwrap();
    path
}
fn accepted_receipt(index: &mut ScanIndex, dir: &Path) {
    crate::snapshots::e2_pipeline_scan_fixture::origin_accepted_for_test(index, &holder_key(dir));
}

/// [regress] A holder with no accepted body in any context (its census alone
/// proves nothing): the prefix waits at most `HOLD_PASSES`, then counts,
/// flagged. A later acceptance removes it once, on the copy's next read, and
/// names that read in one counter.
#[test]
fn copy_keeps_prefix_flagged_until_origin_has_an_accepted_body() {
    let dir = scratch();
    let path = copy_at(&dir);
    let mut index = index_holding(&dir, &["copy-a", "copy-b"]);
    for _ in 1..super::super::copy_removals::HOLD_PASSES {
        let held = decide_pass(&mut index, &path);
        assert_eq!(fold(&held).prefix.held_requests, 2);
        assert_eq!(fold(&held).disclosed, 0);
    }
    let kept = decide_pass(&mut index, &path);
    assert_eq!(fold(&kept).entity.removed_requests, 0);
    assert_eq!(fold(&kept).prefix.unproven_requests, 2, "flagged");
    assert_eq!(fold(&kept).prefix.hold_expired, 2);
    assert_eq!(fold(&kept).entity.totals().1, 3, "nothing counted nowhere");

    let copy_key = local_index_key(&path);
    index
        .claude_money_birth_store
        .set_money_marks(&copy_key, money_mark::DISCLOSED);
    accepted_receipt(&mut index, &dir);
    take_diag();
    let removed = decide_pass(&mut index, &path);
    assert_eq!(fold(&removed).entity.removed_requests, 2);
    assert_eq!(fold(&removed).entity.totals().1, 1);
    assert_eq!(fold(&removed).disclosed, 0);
    assert_eq!(take_diag().get("copy_prefix_late_origin_removed"), Some(&2));
    let _ = fs::remove_dir_all(dir);
}

/// [regress] First read: the origin's body is not ACKed yet, so the existing
/// proof wait holds the prefix (never a double count beside that body). The
/// pass after the origin's ACK removes it and leaves no debt.
#[test]
fn first_read_defers_then_removes_on_the_pass_after_the_origin_ack() {
    let dir = scratch();
    let path = copy_at(&dir);
    let mut index = index_holding(&dir, &["copy-a", "copy-b"]);
    let first = decide_pass(&mut index, &path);
    assert_eq!(fold(&first).prefix.held_requests, 2);
    assert_eq!(fold(&first).entity.totals().1, 1, "own turn emits");
    let file = fold(&first).copy_order().unwrap().1;
    assert!(
        index.claude_copy_removals.pending(file),
        "debt reselects it"
    );

    accepted_receipt(&mut index, &dir);
    let next = decide_pass(&mut index, &path);
    assert_eq!(fold(&next).entity.removed_requests, 2);
    assert_eq!(fold(&next).prefix.held_requests, 0);
    assert_eq!(fold(&next).disclosed, 0);
    assert!(!index.claude_copy_removals.pending(file));
    let _ = fs::remove_dir_all(dir);
}

/// [regress] A saved removal of an indexed holder with no accepted body stays
/// recorded but removes nothing; each kind of accepted body, in another
/// context, lets the prefix go.
#[test]
fn accepted_body_in_any_context_decides_and_saved_removal_stays_recorded() {
    let dir = scratch();
    let path = copy_at(&dir);
    let mut index = index_holding(&dir, &["copy-a", "copy-b"]);
    let key = holder_key(&dir);
    assert!(!index.file_has_accepted_body(&key));
    let file = location_key(&local_index_key(&path));
    let hashes = ["copy-a", "copy-b"].map(claude_request_hash);
    index.claude_copy_removals.store(
        file,
        BTreeMap::from([(location_key(&key), hashes.into_iter().collect())]),
    );
    let saved = decide_pass(&mut index, &path);
    assert_eq!(fold(&saved).entity.removed_requests, 0);
    assert_eq!(fold(&saved).prefix.held_requests, 2);
    assert!(!index.claude_copy_removals.get(file).is_empty());

    accepted_receipt(&mut index, &dir);
    assert!(index.file_has_accepted_body(&key), "receipt");
    assert_eq!(
        fold(&decide_pass(&mut index, &path))
            .entity
            .removed_requests,
        2
    );
    index.files.get_mut(&key).unwrap().upload_context_receipt = None;
    assert!(!index.file_has_accepted_body(&key));
    index
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["entity".to_string()]));
    index.upload_context_proof.entity_stamps.insert(
        "entity".to_string(),
        EntityStamp {
            context_fingerprint: "another-upload-context".into(),
            body_witness: "b".repeat(64),
        },
    );
    assert!(index.file_has_accepted_body(&key), "stamp");
    let _ = fs::remove_dir_all(dir);
}

/// [regress] A below-floor or empty settlement reaches revision 3 with no body
/// accepted, and only a local empty proof: the prefix waits, then counts.
#[test]
fn below_floor_settlement_is_not_an_accepted_origin() {
    let dir = scratch();
    let path = copy_at(&dir);
    let mut index = index_holding(&dir, &["copy-a", "copy-b"]);
    let entry = index.files.get_mut(&holder_key(&dir)).unwrap();
    entry.effective_upload_body_witness_revision = 3;
    entry.upload_context_receipt = Some(Receipt {
        context_fingerprint: "another-upload-context".into(),
        replay_generation: RECEIPT_REPLAY_EPOCH,
        source_witness: "a".repeat(64),
        body_witness: String::new(),
    });
    assert!(!index.file_has_accepted_body(&holder_key(&dir)));
    take_diag();
    let held = decide_pass(&mut index, &path);
    assert_eq!(fold(&held).entity.removed_requests, 0);
    assert_eq!(fold(&held).prefix.held_requests, 2);
    let diag = take_diag();
    assert_eq!(diag.get("copy_prefix_origin_unaccepted_copies"), Some(&1));
    assert_eq!(diag.get("copy_prefix_origin_unaccepted_passes"), Some(&1));
    let second = decide_pass(&mut index, &path);
    assert_eq!(fold(&second).prefix.held_requests, 2);
    let diag = take_diag();
    assert_eq!(diag.get("copy_prefix_origin_unaccepted_copies"), None);
    assert_eq!(diag.get("copy_prefix_origin_unaccepted_passes"), Some(&1));
    let _ = fs::remove_dir_all(dir);
}

/// [regress] A protected origin holding an old receipt (the observed case):
/// the copy keeps the prefix, flagged, with no wait for an ACK that cannot come.
#[test]
fn protected_origin_keeps_the_prefix_without_a_wait() {
    let dir = scratch();
    let path = copy_at(&dir);
    let mut index = index_holding(&dir, &["copy-a", "copy-b"]);
    accepted_receipt(&mut index, &dir);
    let support = scratch();
    crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&support, &[HOLDER]);
    index.load_claude_reemission_exclusions(&support);
    let kept = decide_pass(&mut index, &path);
    assert_eq!(fold(&kept).entity.removed_requests, 0);
    assert_eq!(fold(&kept).prefix.held_requests, 0);
    assert_eq!(fold(&kept).prefix.unproven_requests, 2, "flagged");
    assert_eq!(fold(&kept).entity.totals().1, 3);
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(support);
}
