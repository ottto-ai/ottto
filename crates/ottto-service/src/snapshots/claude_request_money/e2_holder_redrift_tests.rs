//! The Holders copy decision rebuilds a file's accounts without its copied
//! markers. An own request whose account that flips moves with the rebuild,
//! whether or not it was staged; only placement changes, never its money.

use super::*;
use crate::claude_local_otel::ClaudeTraceOwnershipLoadReport;
use crate::snapshots::claude_request_census::{
    ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};
use crate::snapshots::tests::complete_api_row;
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
    let index = index_holding(&dir, copied);
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
