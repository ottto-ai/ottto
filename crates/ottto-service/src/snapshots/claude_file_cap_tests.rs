// Synthetic real-scan admission and native parse/finalize memory receipts.
// The memory case runs alone in a fresh process; fixture generation happens
// in the parent. Measurements report observations, never establish a budget.
use super::*;

const SESSION: &str = "019e2700-5555-7000-9000-555555555555";
const AT: &str = "2026-10-27T08:00:00Z";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(temp_dir("claude-file-cap"))
    }
    fn path(&self) -> PathBuf {
        self.0.join(format!("{SESSION}.jsonl"))
    }
    fn scan(&self, source: SnapshotSource, index: &mut ScanIndex, hour: u8) -> SourceScanResult {
        scan_source_roots_with_limit(
            source,
            std::slice::from_ref(&self.0),
            index,
            &format!("2026-10-27T{hour:02}:00:00Z"),
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            false,
        )
        .expect("native scan")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn usage(n: u64) -> Value {
    json!({"type":"assistant","sessionId":SESSION,"uuid":format!("assistant-{n}"),
        "timestamp":AT,"requestId":format!("req-{n}"),
        "message":{"id":format!("msg-{n}"),"role":"assistant",
        "model":if n % 2 == 0 {"claude-sonnet-4-6"} else {"claude-opus-4-6"},
        "content":[{"type":"text","text":"Synthetic analysis of a test fixture."},
        {"type":"tool_use","id":format!("tool-{n}"),"name":"Read","input":{"file_path":"fixture.txt"}}],
        "usage":{"input_tokens":100,"output_tokens":10,"cache_read_input_tokens":20,"cache_creation_input_tokens":0}}})
}
fn write_row(writer: &mut impl Write, value: &Value) -> u64 {
    let bytes = serde_json::to_vec(value).unwrap();
    writer.write_all(&bytes).unwrap();
    writer.write_all(b"\n").unwrap();
    bytes.len() as u64 + 1
}
fn assert_native(scan: &SourceScanResult, requests: u64) {
    assert_eq!(scan.oversized_file_count, 0);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(scan.malformed_json_line_count, 0);
    assert_eq!(scan.over_line_cap_count, 0);
    assert_eq!(scan.dropped_usage_record_count, 0);
    assert!(scan.census_complete);
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].request_count, requests);
    assert_eq!(scan.snapshots[0].input_tokens, requests * 100);
    assert_eq!(scan.snapshots[0].output_tokens, requests * 10);
    assert_eq!(scan.snapshots[0].cache_read_tokens, requests * 20);
}

#[test]
fn oversized_claude_shrink_then_grow_keeps_unread_content_unproven() {
    let fixture = Fixture::new();
    let path = fixture.path();
    let mut file = File::create(&path).unwrap();
    let valid_size = write_row(&mut file, &usage(0));
    file.set_len(MAX_CLAUDE_JSONL_FILE_BYTES + 1).unwrap();
    drop(file);
    let key = local_index_key(&path);
    let mut index = ScanIndex::default();
    let skipped = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 9);
    assert_eq!(skipped.oversized_file_count, 1);
    assert_eq!(skipped.scanned_file_count, 0);
    assert!(skipped.snapshots.is_empty());
    assert!(!skipped.census_complete);
    assert!(
        !index.files.contains_key(&key),
        "no proof before native read"
    );
    assert!(!index.file_snapshot_fingerprints.contains_key(&key));

    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(valid_size)
        .unwrap();
    let mut admitted = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 11);
    assert_native(&admitted, 1);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut admitted, &mut index);
    let prior = index.files[&key].source_file_fingerprint.clone();
    assert!(!prior.is_empty());

    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_CLAUDE_JSONL_FILE_BYTES + 1)
        .unwrap();
    let grown = fixture.scan(SnapshotSource::ClaudeCode, &mut index, 13);
    assert_eq!(grown.oversized_file_count, 1);
    assert_eq!(grown.scanned_file_count, 0);
    assert!(grown.snapshots.is_empty());
    assert!(!grown.census_complete);
    assert_eq!(
        index.files[&key].source_file_fingerprint, prior,
        "oversized content cannot replace prior read authority"
    );

    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(valid_size)
        .unwrap();
    assert_native(&fixture.scan(SnapshotSource::ClaudeCode, &mut index, 15), 1);
}
