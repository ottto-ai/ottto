//! A request first seen as a local-telemetry side row, then on a transcript
//! line a few ms earlier, keeps the later activity time. Its usage, hours
//! and placement never change.

use super::*;
use crate::claude_local_otel::{ClaudeApiEvidenceRead, ClaudeTraceOwnershipLoadReport};
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, scan_money, RouteResult};
use crate::snapshots::tests::complete_api_row;
use crate::snapshots::{
    apply_claude_code_line, SnapshotAccumulator, SnapshotSource, SourceScanResult,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const ROOT: &str = "d0000000-0000-4000-8000-00000000000d";
const T0: &str = "2026-08-02T07:00:00Z";
/// `complete_api_row` observes sequence `n` at `07:00:0n`.
const A_CLOCK: &str = "2026-08-02T07:00:01Z";
const OBSERVED: &str = "2026-08-02T07:00:05Z";
const SIX_MS_EARLIER: &str = "2026-08-02T07:00:04.994Z";

fn nanos(clock: &str) -> i128 {
    rfc3339_unix_nanos(clock).unwrap()
}
fn line(id: &str, clock: &str) -> Value {
    json!({"type":"assistant","version":"2.1.309","sessionId":ROOT,"timestamp":clock,
        "requestId":id,"message":{"id":format!("msg-{id}"),"model":"claude-haiku-4-5",
        "usage":{"input_tokens":10,"output_tokens":1}}})
}
fn row(id: &str, sequence: u64) -> ClaudeLocalOtelEvidence {
    complete_api_row(ROOT, id, sequence, 10, 1, 0)
}
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ottto-e2-clock-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}
/// The live sidecar reader over exactly these rows for ROOT.
fn sidecar(name: &str, rows: &[ClaudeLocalOtelEvidence]) -> ClaudeApiEvidenceRead {
    let support = scratch(&format!("{name}-support"));
    let dir = support.join(crate::claude_local_otel::STORE_DIR);
    fs::create_dir_all(&dir).unwrap();
    let body = rows
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    let file = format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes()));
    fs::write(dir.join(file), body).unwrap();
    let read = ClaudeApiEvidenceRead::load(&support, [ROOT.to_owned()]).unwrap();
    fs::remove_dir_all(support).unwrap();
    read
}
/// One page as the scan runs it: parse, attach, side calls, finish.
fn body(name: &str, lines: &[Value], rows: &[ClaudeLocalOtelEvidence]) -> SnapshotItem {
    let dir = scratch(name);
    let path = dir.join(format!("{ROOT}.jsonl"));
    fs::write(&path, b"fixture\n").unwrap();
    let index = ScanIndex::default();
    let mut a = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    let opened = fs::File::open(&path).and_then(|file| file.metadata()).ok();
    a.claude_file_birth = ClaudeFileBirth::observe(&path, opened.as_ref());
    a.claude_file_birth.set_birth_for_test(nanos(T0));
    for value in lines {
        apply_claude_code_line(value, &mut a);
    }
    a.finalize_claude_responses_e2(Some(ReadContext {
        index: &index,
        path: &path,
        twins: &Default::default(),
    }));
    let mut items = a.into_items(&path, "2026-08-02T09:00:00Z", "fixture".into(), None);
    decide_page_copies(&mut items, &index, None);
    let read = sidecar(name, rows);
    attach_page(&mut items, &read);
    let api = ClaudeLocalOtelLoadReport {
        evidence: read.evidence.clone(),
        health: Default::default(),
    };
    let trace = ClaudeTraceOwnershipLoadReport::default();
    side_calls_page(&mut items, &api, &trace, &index);
    decide_page_copies(&mut items, &index, None);
    let (mut held, queued) = (Default::default(), Default::default());
    finish_page(
        &mut items,
        &index,
        TelemetryRead::Loaded,
        &mut held,
        &queued,
    );
    fs::remove_dir_all(dir).unwrap();
    assert_eq!(items.len(), 1);
    items.remove(0)
}
/// The server's data time of a body: its latest bucket or source clock.
fn data_time(item: &SnapshotItem) -> i128 {
    let source = [
        item.source_started_at.as_ref(),
        item.source_ended_at.as_ref(),
        item.source_last_activity_at.as_ref(),
    ];
    item.usage_buckets
        .iter()
        .flat_map(|b| {
            [
                Some(&b.bucket_start),
                b.first_activity_at.as_ref(),
                b.last_activity_at.as_ref(),
            ]
        })
        .chain(source)
        .flatten()
        .filter_map(|clock| rfc3339_unix_nanos(clock.as_str()))
        .max()
        .unwrap()
}
fn usage(item: &SnapshotItem) -> Value {
    let hours = item
        .usage_buckets
        .iter()
        .map(|b| &b.bucket_start)
        .collect::<Vec<_>>();
    json!([
        item.request_count,
        item.input_tokens,
        item.output_tokens,
        item.cache_read_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.cost,
        hours
    ])
}
fn route(item: SnapshotItem) -> RouteResult {
    let mut scan = SourceScanResult::empty(SnapshotSource::ClaudeCode);
    scan.snapshots = vec![item];
    scan_money(SnapshotSource::ClaudeCode, &ScanIndex::default(), &scan)
}

/// [regress] Observed: a request uploaded from its side row, then from its
/// transcript line 6 ms earlier, made the next body older with equal usage.
#[test]
fn otel_first_request_never_moves_the_next_body_back() {
    let rows = [row("a", 1), row("b", 5)];
    let first = body("first", &[line("a", A_CLOCK)], &rows);
    let lines = [line("a", A_CLOCK), line("b", SIX_MS_EARLIER)];
    let next = body("next", &lines, &rows);
    assert_eq!(first.request_count, 2, "b counts as a side call first");
    assert!(data_time(&next) >= data_time(&first));
    assert_eq!(usage(&next), usage(&first));
}

/// [regress] With one representation only, the clock is that one's.
#[test]
fn transcript_only_and_otel_only_requests_keep_their_clock() {
    let lines = [line("a", A_CLOCK), line("b", SIX_MS_EARLIER)];
    let transcript_only = body("transcript-only", &lines, &[row("a", 1)]);
    assert_eq!(data_time(&transcript_only), nanos(SIX_MS_EARLIER));
    let otel_only = body(
        "otel-only",
        &[line("a", A_CLOCK)],
        &[row("a", 1), row("b", 5)],
    );
    assert_eq!(data_time(&otel_only), nanos(OBSERVED));
}

/// [money] The later row clock moves no total, hour, row or placement:
/// equal to the body whose row clock equals its line's (today's behaviour),
/// and a cold rebuild of the same inputs is equivalent.
#[test]
fn later_row_clock_changes_no_money_or_placement() {
    let lines = [line("a", A_CLOCK), line("b", SIX_MS_EARLIER)];
    let mut same = row("b", 5);
    same.observed_at = SIX_MS_EARLIER.into();
    same.fingerprint.clear();
    same.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&same).unwrap())
    );
    let today = route(body("money", &lines, &[row("a", 1), same]));
    let later = route(body("money", &lines, &[row("a", 1), row("b", 5)]));
    money_oracle::assert_placement_equivalent(&today, &later);
    for field in money_oracle::FIELDS {
        assert_eq!(
            today.snapshots[ROOT][*field], later.snapshots[ROOT][*field],
            "{field}"
        );
    }
    let cold = route(body("money", &lines, &[row("a", 1), row("b", 5)]));
    money_oracle::assert_equivalent(&cold, &later);
}
