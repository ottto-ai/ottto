//! Pi SOURCE canaries and codec restore controls, using synthetic sessions only.
use super::*;
use crate::durable_tail_codec::HDigest;
use crate::durable_tail_store::{
    self as store, Binding, DurableSource, PendingRecord, ReadOutcome,
};
use crate::snapshots::sampled_scan::durable_tail::Counters;
use crate::transcript_acquisition::{birth_unix_nanos, ReadMode, Scope};
use base64::Engine as _;
use serde_json::json;
use std::io::Write;

const NOW: u64 = 1_790_000_000;
const AT: &str = "2026-10-20T10:00:00Z";
const CANARY_RESPONSE: &str = "CANARY_RESPONSE_pi_private";
const CANARY_PROMPT: &str = "CANARY_PROMPT_pi_private";
const CANARY_SYSTEM: &str = "CANARY_SYSTEM_pi_private";
const CANARY_SUMMARY: &str = "CANARY_SUMMARY_pi_private";
const CANARY_CHECKPOINT: &str = "CANARY_CHECKPOINT_pi_private";
const CANARY_PARENT: &str = "/tmp/CANARY_PARENT_pi_private/session.jsonl";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(crate::test_scratch::private_dir("ottto-durable-pi"))
    }
    fn write(&self, lines: &[String]) -> PathBuf {
        let path = self.0.join("session.jsonl");
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scope() -> Scope {
    Scope("durable-pi-codec-test".into())
}

fn parser(path: &Path) -> OwnedJsonlParser {
    OwnedJsonlParser::new(
        File::open(path).unwrap(),
        path,
        SnapshotSource::Pi,
        apply_pi_line,
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap()
}

fn full_read(path: &Path) -> (CachedJsonlReduction, Checkpoint) {
    let mut parser = parser(path);
    assert!(matches!(
        parser
            .prepare_acquisition(None, &scope(), None, NOW)
            .unwrap(),
        ReadMode::Full(_)
    ));
    while !parser.step().unwrap() {}
    let reduction = parser.reduction_copy();
    let checkpoint = match parser.certify_without_retention(&scope(), NOW).unwrap() {
        SideCertificate::Certified { completed, .. } => completed.checkpoint,
        _ => panic!("clean Pi fixture must certify"),
    };
    (reduction, checkpoint)
}

fn body(reduction: &CachedJsonlReduction) -> Vec<u8> {
    encode(reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).expect("Pi record persists")
}

fn restore(path: &Path, body: &[u8]) -> (CachedJsonlReduction, RederiveReceipt) {
    let decoded = decode(body, SnapshotSource::Pi).expect("decode Pi");
    let parser = rederive_parser(File::open(path).unwrap(), path, &decoded).unwrap();
    decoded
        .rederive(
            parser,
            &mut File::open(path).unwrap(),
            jsonl_line_cap() as u64,
        )
        .unwrap()
}

/// Include every content field and all three ledger containers, without
/// asking the shared E-class field to become persistable for other sources.
fn full_digest(reduction: &CachedJsonlReduction) -> [u8; 32] {
    let mut copy = reduction.clone();
    let ledger = std::mem::take(&mut copy.accumulator.seen_pi_usage_keys);
    let mut e = Enc::hash("durable-pi-codec-test:full");
    copy.put(&mut e).unwrap();
    ledger.len().put(&mut e).unwrap();
    for (key, state) in ledger {
        key.put(&mut e).unwrap();
        state.message.put(&mut e).unwrap();
        state.message_end.put(&mut e).unwrap();
        state.paired_digests.put(&mut e).unwrap();
    }
    e.finish_hash()
}

fn items(parser: OwnedJsonlParser, path: &Path) -> Value {
    let identity =
        opened_object_identity(SnapshotSource::Pi, &mut File::open(path).unwrap()).unwrap();
    let parsed = parser
        .finish_with_repository_identity(
            &identity,
            path,
            "2026-10-20T12:00:00Z",
            "fp".into(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    assert_eq!(parsed.recognized_usage_drop_count, 0);
    assert_eq!(parsed.dropped_usage_record_count, 0);
    assert!(!parsed.zero_snapshot_usage_evidence);
    serde_json::to_value(parsed.snapshots).unwrap()
}

fn usage(shape: &str, response: Option<&str>) -> String {
    let mut line = json!({"type":shape,"timestamp":AT,"message":{
        "role":"assistant","timestamp":AT,"provider":"openai","model":"gpt-5.4",
        "content":[{"type":"text","text":"synthetic answer"}],"stopReason":"stop",
        "usage":{"input":10,"output":3,"cacheRead":0,"cacheWrite":0,
            "cost":{"total":0.001}}}});
    if let Some(response) = response {
        line["message"]["responseId"] = json!(response);
    }
    line.to_string()
}

fn header() -> String {
    json!({"type":"session","version":3,"id":"pi-codec-fixture","timestamp":AT,
        "cwd":"/tmp/pi-codec-fixture","parentSession":CANARY_PARENT})
    .to_string()
}

fn privacy_lines() -> Vec<String> {
    let system = format!("{CANARY_SYSTEM}{}", "s".repeat(7_168));
    vec![
        header(),
        json!({"type":"model_change","timestamp":AT,"provider":"openai","modelId":"gpt-5.4"}).to_string(),
        json!({"type":"message","timestamp":AT,"message":{"role":"system","content":system}}).to_string(),
        json!({"type":"message","timestamp":AT,"message":{"role":"user","content":[
            {"type":"text","text":CANARY_PROMPT}]}}).to_string(),
        usage("message", Some(CANARY_RESPONSE)),
        json!({"type":"compaction","id":"compact-fixture","timestamp":AT,
            "firstKeptEntryId":"entry-fixture","tokensBefore":100,
            "summary":CANARY_SUMMARY,"systemMessage":format!("{CANARY_CHECKPOINT}{}", "c".repeat(7_168)),
            "usage":{"input":20,"output":5,"cost":{"total":0.002}}}).to_string(),
    ]
}

fn assert_private(bytes: &[u8]) {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    for canary in [
        CANARY_RESPONSE,
        CANARY_PROMPT,
        CANARY_SYSTEM,
        CANARY_SUMMARY,
        CANARY_CHECKPOINT,
        CANARY_PARENT,
    ] {
        let hex = canary
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        for form in [
            canary.to_string(),
            hex.clone(),
            hex.to_uppercase(),
            STANDARD.encode(canary),
            STANDARD_NO_PAD.encode(canary),
            URL_SAFE.encode(canary),
            URL_SAFE_NO_PAD.encode(canary),
        ] {
            assert!(
                !bytes
                    .windows(form.len())
                    .any(|window| window == form.as_bytes()),
                "private Pi canary reached encoded bytes or diagnostics: {canary}"
            );
        }
    }
}

#[test]
fn pi_record_and_store_diagnostics_exclude_private_canaries() {
    let scratch = Scratch::new();
    let path = scratch.write(&privacy_lines());
    let (reduction, checkpoint) = full_read(&path);
    assert!(reduction
        .accumulator
        .first_prompt_title
        .as_deref()
        .unwrap()
        .contains(CANARY_PROMPT));
    assert_eq!(reduction.accumulator.seen_pi_usage_keys.len(), 1);
    let encoded = body(&reduction);
    assert_private(&encoded);
    verify(&encoded).expect("Pi structural verification");
    let (restored, receipt) = restore(&path, &encoded);
    assert_eq!(full_digest(&restored), full_digest(&reduction));
    assert!(receipt.head_bytes <= HEAD_BOUND);
    assert!(receipt.named_lines as usize <= NAMED_LINES);

    // Exercise the real store write/read and its public counter formatter.
    let lock = crate::locked_state_dir::LockedStateDir::acquire(&scratch.0).unwrap();
    let dir = store::store_dir_for_index(&scratch.0.join("index.json"));
    let mut disk = store::DurableTailStore::new(dir.clone(), DurableSource::Pi);
    let key = store::key_digest(DurableSource::Pi, "synthetic-pi-index-key");
    let allowlist = allowlist_digest(SnapshotSource::Pi);
    let pending = PendingRecord {
        binding: Binding {
            source: DurableSource::Pi,
            key,
            context: [1; 32],
            scope: [2; 32],
            entry: [3; 32],
        },
        certificate: checkpoint
            .durable_certificate(birth_unix_nanos(&fs::metadata(&path).unwrap()))
            .unwrap(),
        body: encoded.clone(),
        allowlist,
    };
    let written = disk.write_after_save(&lock, 1, vec![pending]).unwrap();
    assert_eq!(written.written, 1);
    assert_private(format!("{written:?}").as_bytes());
    drop(disk);
    let mut disk = store::DurableTailStore::new(dir.clone(), DurableSource::Pi);
    let found = match disk.read(&key, &allowlist) {
        ReadOutcome::Found(found) => found,
        outcome => panic!("Pi store did not restore: {outcome:?}"),
    };
    assert_eq!(found.record.body, encoded);
    let (from_disk, _) = restore(&path, &found.record.body);
    assert_eq!(full_digest(&from_disk), full_digest(&reduction));
    for entry in fs::read_dir(dir).unwrap() {
        assert_private(&fs::read(entry.unwrap().path()).unwrap());
    }
    let store_counts = disk.counters();
    assert_eq!(store_counts.records_read, 1);
    let counts = Counters {
        restore_attempts: 1,
        restored: 1,
        rederive_head_bytes: receipt.head_bytes,
        rederive_named_lines: receipt.named_lines,
        rederive_line_bytes: receipt.line_bytes,
        ..Counters::default()
    };
    assert_private(counts.summary(SnapshotSource::Pi, &store_counts).as_bytes());
    assert_private(format!("{counts:?} {store_counts:?}").as_bytes());
}

fn ledger_lines() -> (Vec<String>, Vec<String>) {
    let repeated = usage("message", Some("repeat-fixture"));
    let no_id = usage("message", None);
    (
        vec![
            header(),
            repeated.clone(),
            repeated.clone(),
            usage("message", Some("paired-fixture")),
            usage("message_end", Some("paired-fixture")),
            usage("message", Some("split-fixture")),
            usage("message_end", Some("end-first-fixture")),
            usage("message_end", Some("end-first-fixture")),
            no_id.clone(),
            no_id.clone(),
        ],
        vec![
            usage("message_end", Some("repeat-fixture")),
            repeated,
            usage("message_end", Some("split-fixture")),
            usage("message", Some("end-first-fixture")),
            no_id.clone(),
            no_id,
        ],
    )
}

fn assert_hex(value: &str) {
    assert_eq!(value.len(), 64, "Pi key/digest length");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Pi key/digest must be lower hex"
    );
}

#[test]
fn decoded_pi_keys_and_occurrence_digests_are_fixed_lower_hex() {
    let scratch = Scratch::new();
    let path = scratch.write(&ledger_lines().0);
    let (reduction, _) = full_read(&path);
    let encoded = body(&reduction);
    verify(&encoded).unwrap();
    let decoded = decode(&encoded, SnapshotSource::Pi).unwrap();
    let ledger = &decoded.reduction.accumulator.seen_pi_usage_keys;
    assert_eq!(ledger.len(), 4);
    let mut counts = [0; 3];
    for (key, state) in ledger {
        assert_hex(key);
        for (slot, digests) in [
            state.message.keys().collect::<Vec<_>>(),
            state.message_end.keys().collect(),
            state.paired_digests.iter().collect(),
        ]
        .into_iter()
        .enumerate()
        {
            counts[slot] += digests.len();
            for digest in digests {
                assert_hex(digest);
            }
        }
    }
    assert!(
        counts.into_iter().all(|count| count > 0),
        "exercise all three digest containers"
    );
    assert_eq!(
        full_digest(&restore(&path, &encoded).0),
        full_digest(&reduction)
    );
}

#[test]
fn invalid_pi_keys_and_digests_are_never_accepted() {
    let scratch = Scratch::new();
    let path = scratch.write(&ledger_lines().0);
    let (reduction, _) = full_read(&path);
    let encoded = body(&reduction);
    let key = reduction
        .accumulator
        .seen_pi_usage_keys
        .keys()
        .next()
        .unwrap();
    let mut h = Enc::bytes(32);
    key.put_h(&mut h, "PiSection.usage_keys").unwrap();
    let h = h.into_bytes();
    let positions = encoded
        .windows(h.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == h).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(
        positions.len(),
        1,
        "locate the fixed H key in the Pi record"
    );
    for invalid in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "g".repeat(64),
        "A".repeat(64),
    ] {
        // A legacy/free-form string is not a valid fixed-width H key on the
        // wire, even when its text has the old response-id shape.
        let mut text = Enc::bytes(128);
        invalid.put(&mut text).unwrap();
        let mut malformed = encoded.clone();
        malformed.splice(positions[0]..positions[0] + 32, text.into_bytes());
        assert!(
            verify(&malformed).is_err(),
            "verify accepted a string in place of an H key"
        );
        assert!(
            decode(&malformed, SnapshotSource::Pi).is_err(),
            "decode accepted a string in place of an H key"
        );
        for container in 0..4 {
            let mut changed = reduction.clone();
            let ledger = &mut changed.accumulator.seen_pi_usage_keys;
            let key = ledger.keys().next().unwrap().clone();
            let mut state = ledger.remove(&key).unwrap();
            match container {
                0 => {
                    ledger.insert(invalid.clone(), state);
                }
                1 => {
                    state.message.insert(invalid.clone(), 2);
                    ledger.insert(key, state);
                }
                2 => {
                    state.message_end.insert(invalid.clone(), 2);
                    ledger.insert(key, state);
                }
                3 => {
                    state.paired_digests.insert(invalid.clone());
                    ledger.insert(key, state);
                }
                _ => unreachable!(),
            }
            // Fixed H encoding may refuse before emitting any malformed wire
            // value. If bytes are emitted, verify or decode must reject them.
            if let Ok(encoded) = encode(&changed, store::RECORD_BYTES, jsonl_line_cap() as u64) {
                assert!(
                    verify(&encoded).is_err() || decode(&encoded, SnapshotSource::Pi).is_err(),
                    "accepted invalid Pi key/digest {invalid:?} in container {container}"
                );
            }
        }
    }
}

#[test]
fn pi_restore_then_tail_matches_cold_full_with_occurrence_counts() {
    let scratch = Scratch::new();
    let (lines, appended) = ledger_lines();
    let path = scratch.write(&lines);
    let (reduction, checkpoint) = full_read(&path);
    assert!(reduction
        .accumulator
        .seen_pi_usage_keys
        .values()
        .any(|state| state.message.values().any(|count| *count > 1)));
    assert!(reduction
        .accumulator
        .seen_pi_usage_keys
        .values()
        .any(|state| state.message_end.values().any(|count| *count > 1)));
    let encoded = body(&reduction);
    let certificate = checkpoint
        .durable_certificate(birth_unix_nanos(&fs::metadata(&path).unwrap()))
        .unwrap();
    let (restored, _) = restore(&path, &encoded);
    assert_eq!(full_digest(&restored), full_digest(&reduction));
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    for line in appended {
        writeln!(file, "{line}").unwrap();
    }
    drop(file);
    let (checkpoint, _) = certificate
        .restore(&mut File::open(&path).unwrap(), scope())
        .unwrap();
    let mut continued = parser(&path);
    assert_eq!(
        continued
            .prepare_acquisition(
                Some(Retained {
                    checkpoint,
                    state: restored
                }),
                &scope(),
                None,
                NOW
            )
            .unwrap(),
        ReadMode::Tail
    );
    while !continued.step().unwrap() {}
    let continued_reduction = continued.reduction_copy();
    let (cold_reduction, _) = full_read(&path);
    assert_eq!(
        full_digest(&continued_reduction),
        full_digest(&cold_reduction)
    );
    let actual = items(continued, &path);
    let mut cold = parser(&path);
    while !cold.step().unwrap() {}
    assert_eq!(actual, items(cold, &path));
    assert_eq!(actual.as_array().unwrap().len(), 1);
    assert_eq!(actual[0]["request_count"], 11);
    assert_eq!(actual[0]["input_tokens"], 110);
    assert_eq!(actual[0]["output_tokens"], 33);
}
