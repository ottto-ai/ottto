//! One source regression each: native Full, RAM and database continuation,
//! physical suffix custody, native conflict holds and exact-body acceptance.
use super::super::claude::{tests::lines as claude_lines, Claude};
use super::super::codex::{tests::candidate, tests::lines as codex_lines, Codex};
use super::super::load::{load, Load};
use super::super::pi::Pi;
use super::tests::{route_for, scope, Route, NOW};
use super::*;
use crate::snapshot_sync::tail_ack_ledger::AckLedger;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Accepted, Mode, RouteResult,
};
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::state_v2::TailHead;
use serde_json::json;
use std::io::Write;

trait SourceFixture: TailSource {
    const INDEX: Source;
    const APPLY: fn(&Value, &mut SnapshotAccumulator);
    const TOTAL: (u64, u64);
    fn lines() -> Vec<String>;
    fn name() -> String {
        "session.jsonl".into()
    }
    fn bad() -> Vec<String>;
}
impl SourceFixture for Claude {
    const INDEX: Source = Source::Claude;
    const APPLY: fn(&Value, &mut SnapshotAccumulator) = apply_claude_code_line;
    const TOTAL: (u64, u64) = (21, 10);
    fn lines() -> Vec<String> {
        claude_lines(2)
    }
    fn bad() -> Vec<String> {
        vec![
            json!({"type":"assistant","sessionId":"5f0c2a8e-1111-4222-8333-944445555777",
            "timestamp":"2026-10-20T10:00:30Z","requestId":"bad","message":{
                "id":"bad","model":"claude-opus-4-1","usage":{"input_tokens":"invalid"}}})
            .to_string(),
        ]
    }
}
impl SourceFixture for Codex {
    const INDEX: Source = Source::Codex;
    const APPLY: fn(&Value, &mut SnapshotAccumulator) = apply_codex_line;
    const TOTAL: (u64, u64) = (200, 20);
    fn lines() -> Vec<String> {
        codex_lines(2)
    }
    fn name() -> String {
        "rollout-019a0c2a-8e11-7222-8333-944445555777.jsonl".into()
    }
    fn bad() -> Vec<String> {
        vec![
            json!({"timestamp":"2026-10-18T10:00:30Z","type":"event_msg","payload":{
            "type":"token_count","info":{"total_token_usage":{"input_tokens":"invalid"}}}})
            .to_string(),
        ]
    }
}
impl SourceFixture for Pi {
    const INDEX: Source = Source::Pi;
    const APPLY: fn(&Value, &mut SnapshotAccumulator) = apply_pi_line;
    const TOTAL: (u64, u64) = (24, 8);
    fn lines() -> Vec<String> {
        let mut rows = vec![json!({"type":"session","id":"synthetic-pi-bad-record",
            "timestamp":"2026-10-20T10:00:00Z"})
        .to_string()];
        for i in 0..2 {
            rows.push(pi_usage(
                "message",
                &format!("good-{i}"),
                json!(format!("2026-10-20T10:0{i}:00Z")),
            ));
        }
        rows
    }
    fn bad() -> Vec<String> {
        // Provider clocks on both assistant shapes and an entry-level clock.
        let mut rows = vec![
            pi_usage("message", "bad-message", json!("invalid")),
            pi_usage("message_end", "bad-end", json!(i64::MAX)),
        ];
        rows.push(
            json!({"type":"usage","timestamp":"invalid","usage":{
            "input":300,"output":30},"model":"gpt-5"})
            .to_string(),
        );
        rows
    }
}
fn pi_usage(shape: &str, id: &str, at: Value) -> String {
    json!({"type":shape,"timestamp":"2026-10-20T10:00:00Z","message":{
        "role":"assistant","provider":"openai","model":"gpt-5","responseId":id,
        "timestamp":at,"usage":{"input":12,"output":4}}})
    .to_string()
}
fn write(path: &Path, rows: &[String]) {
    fs::write(path, rows.join("\n") + "\n").unwrap();
}
fn parser<S: SourceFixture>(path: &Path) -> OwnedJsonlParser {
    fixture::native_cold::parser(S::SOURCE, path, File::open(path).unwrap(), S::APPLY)
}
fn finish<S: SourceFixture>(
    route: &Route,
    path: &Path,
    mut p: OwnedJsonlParser,
    base: Option<TailBase>,
) -> (PendingTail, ParsedJsonlFile) {
    while !p.step().unwrap() {}
    let (tail, native) = route.finish_under::<S>(path, p, base, |_| {}, &scope());
    (tail, native.unwrap())
}
fn full<S: SourceFixture>(route: &Route, path: &Path) -> (PendingTail, ParsedJsonlFile) {
    let mut p = parser::<S>(path);
    assert!(matches!(
        p.prepare_acquisition(None, &scope(), None, NOW).unwrap(),
        ReadMode::Full(_)
    ));
    finish::<S>(route, path, p, None)
}
fn stored<S: SourceFixture>(route: &Route, path: &Path) -> (OwnedJsonlParser, TailBase, ReadMode) {
    let mut held = File::open(path).unwrap();
    let mut p = parser::<S>(path);
    let id = HeadIdentity::new(&route.path, S::SOURCE, &route.dir, path, false);
    let Load::Reused(taken, Some(base)) = load::<S>(
        &route.index,
        &route.path,
        &local_index_key(path),
        &id,
        &mut held,
        &scope(),
        &candidate(path),
        &p.accumulator,
    ) else {
        panic!("committed loss is progress, never reconstruction");
    };
    let mode = p
        .prepare_acquisition(Some(*taken), &scope(), None, NOW)
        .unwrap();
    (p, base, mode)
}
fn emitted<S: SourceFixture>(mode: Mode, route: &Route, items: &[SnapshotItem]) -> RouteResult {
    let batch = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: S::SOURCE.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("0.1.synthetic".into()),
        snapshots: items.to_vec(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let bytes = if items.is_empty() {
        vec![]
    } else {
        vec![serde_json::to_vec(&batch).unwrap()]
    };
    let mut result = RouteResult::emitted(mode, S::SOURCE, bytes, items);
    if S::SOURCE == SnapshotSource::Codex {
        result.codex_evidence = fixture::codex_evidence_of_items(&route.index, items);
    }
    result
}
fn head<S: SourceFixture>(route: &Route, path: &Path) -> TailHead {
    state_v2::load_head(&route.index, &local_index_key(path), S::REDUCTION_REVISION)
        .unwrap()
        .unwrap()
}
fn commit<S: SourceFixture>(
    route: &mut Route,
    path: &Path,
    tail: PendingTail,
    parsed: ParsedJsonlFile,
) {
    assert!(parsed.progress_complete());
    assert!(tail.publish(&Ok(parsed)));
    route.save(false);
    assert!(!head::<S>(route, path).metadata_only);
}
fn regression<S: SourceFixture>() {
    let mut route = route_for(S::INDEX);
    let path = route.dir.join(S::name());
    // O1/O3/O4: independently enumerate valid siblings, then add physical and
    // recognized usage losses between them. Their native reducers stay unchanged.
    write(&path, &S::lines());
    let (_, clean) = full::<S>(&route, &path);
    assert_eq!(
        (
            clean.snapshots[0].input_tokens,
            clean.snapshots[0].output_tokens
        ),
        S::TOTAL
    );
    let mut mixed = S::lines();
    mixed.splice(2..2, S::bad());
    let mut bytes = mixed[..2].join("\n").into_bytes();
    bytes.extend_from_slice(b"\n{broken\n\xff\n");
    bytes.extend_from_slice(mixed[2..].join("\n").as_bytes());
    bytes.push(b'\n');
    fs::write(&path, &bytes).unwrap();
    let (tail, parsed) = full::<S>(&route, &path);
    assert_eq!(
        (
            parsed.report.malformed_json_line_count,
            parsed.report.invalid_utf8_line_count
        ),
        (1, 1)
    );
    assert!(
        !parsed.report.complete(),
        "loss-free authority remains strict"
    );
    assert!(parsed.recognized_usage_drop_count > 0);
    let loss = parsed.terminal_loss().unwrap();
    assert_eq!(
        (
            parsed.snapshots[0].input_tokens,
            parsed.snapshots[0].output_tokens
        ),
        S::TOTAL
    );
    let cold = emitted::<S>(Mode::ColdFull, &route, &parsed.snapshots);
    // The RAM arm continues the real PRE accumulator and checkpoint.
    let mut p = parser::<S>(&path);
    p.prepare_acquisition(None, &scope(), None, NOW).unwrap();
    while !p.step().unwrap() {}
    let reduction = p.durable_test_reduction_copy();
    let cp = p
        .retain_reduction(
            &scope(),
            NOW,
            sampled_scan::RetainBudget::granted_unclassified(0).excluded(),
        )
        .unwrap()
        .unwrap()
        .checkpoint;
    let taken = crate::transcript_cache::Taken {
        modified_hint: cp.modified_hint(),
        retained: crate::transcript_cache::Retained {
            checkpoint: cp,
            state: reduction,
        },
        finalization_charge: 0,
        e2_held_new_file: false,
    };
    let mut ram = parser::<S>(&path);
    assert_eq!(
        ram.prepare_acquisition(Some(taken), &scope(), None, NOW)
            .unwrap(),
        ReadMode::Unchanged
    );
    let (_, ram) = finish::<S>(&route, &path, ram, None);
    money_oracle::assert_equivalent(&cold, &emitted::<S>(Mode::Ram, &route, &ram.snapshots));
    let mut census = ScanCensus::default();
    census.add_terminal_jsonl_loss(&loss);
    assert_eq!(
        (
            census.malformed_json_line_count,
            census.invalid_utf8_line_count
        ),
        (1, 1)
    );
    let items = parsed.snapshots.clone();
    commit::<S>(&mut route, &path, tail, parsed);
    // O7: stored-body acceptance is independent of source progress. Retry an
    // ACKed exact body once; the actual upload loop suppresses another POST.
    let mut ack = AckLedger::new(S::SOURCE);
    ack.deliver(&items);
    assert!(items.iter().all(|item| ack.settled(item)));
    let posts = ack.posts();
    ack.deliver(&items);
    assert_eq!(ack.posts(), posts);
    route.index = ScanIndex::load(&route.path).unwrap();
    let ((p, base, mode), consumed) = fixture::observe_consumed(|| stored::<S>(&route, &path));
    assert_eq!(mode, ReadMode::Unchanged);
    assert_eq!(consumed, 0);
    let (tail, restored) = finish::<S>(&route, &path, p, Some(base));
    money_oracle::assert_equivalent(
        &cold,
        &emitted::<S>(Mode::DiskRestore, &route, &restored.snapshots),
    );
    assert_eq!(restored.terminal_loss(), Some(loss.clone()));
    assert_eq!(tail.certificate.sealed_offset, bytes.len() as u64);
    commit::<S>(&mut route, &path, tail, restored);
    // The unchanged acquisition selected above takes the metadata-only path;
    // no parser, named-row or acquisition sample bytes are read there.
    let mut quiet = emitted::<S>(Mode::Restart, &route, &[]);
    quiet.io.consumed = consumed;
    quiet.io.cheap_checks = Some(0);
    quiet.io.anchor_reads = Some(0);
    quiet.io.other_reads = Some(0);
    money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    // O9: an old serde writer discards additive diagnostics, retaining all
    // old spellings. Missing diagnostics confer no new source/ACK authority.
    let old = json!({"source_file_fingerprint":"a".repeat(64),
        "parser_generation":JSONL_TERMINAL_DISPOSITION_GENERATION,
        "loss":{"over_line_cap_count":1,"recognized_usage_drop_count":loss.recognized_usage_drop_count,
        "dropped_usage_record_count":loss.dropped_usage_record_count}});
    let legacy: TerminalJsonlDisposition = serde_json::from_value(old).unwrap();
    assert_eq!(
        legacy.loss.recognized_usage_drop_count,
        loss.recognized_usage_drop_count
    );
    assert_eq!(legacy.loss.malformed_json_line_count, 0);
    let before = head::<S>(&route, &path).body;
    route
        .index
        .terminal_jsonl_dispositions
        .insert(local_index_key(&path), legacy);
    route.save(false);
    route.index = ScanIndex::load(&route.path).unwrap();
    assert_eq!(head::<S>(&route, &path).body, before);
    let (p, base, mode) = stored::<S>(&route, &path);
    assert_eq!(mode, ReadMode::Unchanged);
    let (_, native) = finish::<S>(&route, &path, p, Some(base));
    money_oracle::assert_equivalent(
        &cold,
        &emitted::<S>(Mode::Restart, &route, &native.snapshots),
    );
    suffix::<S>();
    loss_only::<S>(&cold, &items);
}
fn suffix<S: SourceFixture>() {
    for suffix in [b"{\"paused\":".as_slice(), b"\xff".as_slice()] {
        let mut route = route_for(S::INDEX);
        let path = route.dir.join(S::name());
        let mut bytes = (S::lines().join("\n") + "\n{bad\n").into_bytes();
        let seal = bytes.len();
        bytes.extend_from_slice(suffix);
        fs::write(&path, &bytes).unwrap();
        let mut p = parser::<S>(&path);
        p.prepare_acquisition(None, &scope(), None, NOW).unwrap();
        p.reader.set_extent_limit(bytes.len() as u64);
        while !p.step().unwrap() {}
        assert!(
            !p.apply_sealed_fragment(),
            "an unchanged stamp cannot complete invalid JSON"
        );
        assert!(p.reader.sealed_fragment());
        assert_eq!(p.reader.report.malformed_json_line_count, 1);
        assert_eq!(p.reader.report.invalid_utf8_line_count, 0);
        let (tail, parsed) = finish::<S>(&route, &path, p, None);
        assert_eq!(tail.certificate.sealed_offset, seal as u64);
        assert!(
            !tail.unsealed,
            "unapplied suffix has a matching prefix reduction"
        );
        let cold = emitted::<S>(Mode::ColdFull, &route, &parsed.snapshots);
        commit::<S>(&mut route, &path, tail, parsed);
        route.index = ScanIndex::load(&route.path).unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(if suffix[0] == b'{' { b"true}\n" } else { b"\n" })
            .unwrap();
        drop(file);
        let (p, base, mode) = stored::<S>(&route, &path);
        assert_eq!(mode, ReadMode::Tail);
        let (tail, parsed) = finish::<S>(&route, &path, p, Some(base));
        assert_eq!(parsed.report.malformed_json_line_count, 1);
        assert_eq!(
            parsed.report.invalid_utf8_line_count,
            usize::from(suffix[0] == 0xff)
        );
        money_oracle::assert_equivalent(
            &cold,
            &emitted::<S>(Mode::Restart, &route, &parsed.snapshots),
        );
        commit::<S>(&mut route, &path, tail, parsed);
    }
    // O2: valid final JSON remains admitted, but an applied-past-seal PRE
    // reduction must not replace its predecessor with the smaller certificate.
    let mut route = route_for(S::INDEX);
    let path = route.dir.join(S::name());
    let bytes = S::lines().join("\n");
    fs::write(&path, bytes).unwrap();
    let mut p = parser::<S>(&path);
    p.prepare_acquisition(None, &scope(), None, NOW).unwrap();
    p.reader
        .set_extent_limit(fs::metadata(&path).unwrap().len());
    while !p.step().unwrap() {}
    assert!(p.apply_sealed_fragment());
    let (tail, parsed) = finish::<S>(&route, &path, p, None);
    assert!(tail.unsealed);
    assert!(!tail.publish(&Ok(parsed)));
    route.save(false);
    assert!(
        state_v2::load_head(&route.index, &local_index_key(&path), S::REDUCTION_REVISION)
            .unwrap()
            .is_none()
    );
}
fn loss_only<S: SourceFixture>(cold: &RouteResult, previous: &[SnapshotItem]) {
    let mut route = route_for(S::INDEX);
    let path = route.dir.join(S::name());
    let mut rows = S::lines();
    rows.retain(|line| {
        let v: Value = serde_json::from_str(line).unwrap();
        matches!(
            v["type"].as_str(),
            Some("session" | "session_meta" | "user")
        )
    });
    rows.extend(S::bad());
    write(&path, &rows);
    let (tail, parsed) = full::<S>(&route, &path);
    assert!(parsed.snapshots.is_empty());
    assert!(parsed.progress_complete());
    assert!(parsed.terminal_loss().is_some());
    commit::<S>(&mut route, &path, tail, parsed);
    route.index = ScanIndex::load(&route.path).unwrap();
    let (p, base, mode) = stored::<S>(&route, &path);
    assert_eq!(mode, ReadMode::Unchanged);
    let (_, parsed) = finish::<S>(&route, &path, p, Some(base));
    assert!(parsed.snapshots.is_empty());
    let mut ack = AckLedger::new(S::SOURCE);
    ack.deliver(previous);
    let mut prior = cold.clone();
    for item in previous {
        assert!(ack.settled(item));
        prior.accepted.insert(
            item.source_session_id.clone(),
            Accepted {
                body: serde_json::to_value(item).unwrap(),
                witness: snapshot_upload_body_witness(item),
            },
        );
    }
    let mut held = emitted::<S>(Mode::Restart, &route, &[]);
    held.accepted = prior.accepted.clone();
    for item in previous {
        money_oracle::assert_held(&item.source_session_id, &prior, &held, cold);
        money_oracle::assert_no_smaller_reemit(&item.source_session_id, &prior, &held, cold, true);
    }
}
/// [regress] O1-O4/O6-O9: Claude responses survive discarded siblings.
#[test]
fn claude_bad_record_keeps_valid_responses() {
    regression::<Claude>();
}
/// [regress] O1-O3/O6-O9: Codex keeps native occurrence and cumulative rules.
#[test]
fn codex_bad_record_keeps_valid_occurrences() {
    regression::<Codex>();
}
/// [regress] O1/O2/O5-O9: Pi clocks skip records; opposite-shape conflicts hold.
#[test]
fn pi_bad_record_keeps_valid_occurrences() {
    regression::<Pi>();
    let route = route_for(Source::Pi);
    let path = route.dir.join("conflict.jsonl");
    let mut rows = Pi::lines();
    rows.push(pi_usage(
        "message_end",
        "good-0",
        json!("2026-10-20T10:00:00Z"),
    ));
    write(&path, &rows);
    let (_, paired) = full::<Pi>(&route, &path);
    assert_eq!(
        (
            paired.snapshots[0].input_tokens,
            paired.snapshots[0].request_count
        ),
        (24, 2)
    );
    rows.push(pi_usage("message", "good-0", json!("2026-10-20T10:00:00Z")));
    write(&path, &rows);
    let (_, repeated) = full::<Pi>(&route, &path);
    assert_eq!(
        (
            repeated.snapshots[0].input_tokens,
            repeated.snapshots[0].request_count
        ),
        (36, 3)
    );
    let mut conflict: Value = serde_json::from_str(&rows[3]).unwrap();
    conflict["message"]["usage"]["input"] = json!(99);
    rows[3] = conflict.to_string();
    write(&path, &rows);
    let (tail, conflict) = full::<Pi>(&route, &path);
    assert!(!conflict.progress_complete());
    assert!(conflict.non_progressing_residue());
    assert!(!tail.publish(&Ok(conflict)));
    // The ordinary clock drops in the separate fixture still publish.
}
