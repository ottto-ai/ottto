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
    assert_eq!(parsed.recognized_usage_drop_count, S::bad().len());
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
    let sample_bytes = p
        .reader
        .acquisition
        .as_ref()
        .unwrap()
        .metrics()
        .sample_bytes as u64;
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
    quiet.io.anchor_reads = Some(sample_bytes);
    quiet.io.other_reads = Some(0);
    money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    // O9: an old serde writer discards additive diagnostics, retaining all
    // old spellings. Missing diagnostics confer no new source/ACK authority.
    let old = json!({"source_file_fingerprint":"a".repeat(64),
        "parser_generation":JSONL_TERMINAL_DISPOSITION_GENERATION,
        "loss":{"over_line_cap_count":1,"recognized_usage_drop_count":loss.recognized_usage_drop_count,
        "dropped_usage_record_count":loss.dropped_usage_record_count}});
    let legacy = state_v2::terminal_loss_for_test(&serde_json::to_vec(&old).unwrap());
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
    admission::<S>();
    ack_transitions::<S>(&route, &items);
}
fn suffix<S: SourceFixture>() {
    for suffix in [b"{\"paused\":".as_slice(), b"\xff".as_slice()] {
        let mut route = route_for(S::INDEX);
        let path = route.dir.join(S::name());
        write(&path, &S::lines());
        let (tail, parsed) = full::<S>(&route, &path);
        let cold = emitted::<S>(Mode::ColdFull, &route, &parsed.snapshots);
        commit::<S>(&mut route, &path, tail, parsed);
        let predecessor = head::<S>(&route, &path).body;
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{bad\n").unwrap();
        file.write_all(suffix).unwrap();
        drop(file);
        let (mut p, base, mode) = stored::<S>(&route, &path);
        assert_eq!(mode, ReadMode::Tail);
        p.reader.set_extent_limit(
            fs::metadata(&path).unwrap().len()
                - p.reader.acquisition.as_ref().unwrap().start_offset(),
        );
        while !p.step().unwrap() {}
        assert!(!p.apply_sealed_fragment());
        assert!(p.reader.sealed_fragment());
        assert_eq!(
            (
                p.reader.report.malformed_json_line_count,
                p.reader.report.invalid_utf8_line_count
            ),
            (1, 0)
        );
        let (tail, parsed) = finish::<S>(&route, &path, p, Some(base));
        // Existing unsealed refusal retains the prior head on an ordinary reader.
        assert!(tail.unsealed);
        assert!(!tail.publish(&Ok(parsed)));
        route.save(false);
        route.index = ScanIndex::load(&route.path).unwrap();
        assert_eq!(head::<S>(&route, &path).body, predecessor);
        // Main's compatibility reader may disclose the unfinished row once;
        // no resulting reduction can overwrite that predecessor.
        let (tail, compatibility) = full::<S>(&route, &path);
        assert_eq!(
            compatibility.report.physical_line_count,
            S::lines().len() + 2
        );
        assert!(!tail.publish(&Ok(compatibility)));
        route.save(false);
        assert_eq!(head::<S>(&route, &path).body, predecessor);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(if suffix[0] == b'{' { b"true}\n" } else { b"\n" })
            .unwrap();
        drop(file);
        let (p, base, mode) = stored::<S>(&route, &path);
        assert_eq!(mode, ReadMode::Tail);
        let (tail, parsed) = finish::<S>(&route, &path, p, Some(base));
        assert_eq!(
            (
                parsed.snapshots[0].input_tokens,
                parsed.snapshots[0].output_tokens
            ),
            S::TOTAL
        );
        // Compare the same lossy source on a cold Full, including partial evidence.
        let (_, full) = full::<S>(&route, &path);
        money_oracle::assert_equivalent(
            &emitted::<S>(Mode::ColdFull, &route, &full.snapshots),
            &emitted::<S>(Mode::Restart, &route, &parsed.snapshots),
        );
        assert_eq!(parsed.report.malformed_json_line_count, 1);
        assert_eq!(
            parsed.report.invalid_utf8_line_count,
            usize::from(suffix[0] == 0xff)
        );
        assert_eq!(cold.snapshots.len(), parsed.snapshots.len());
        commit::<S>(&mut route, &path, tail, parsed);
    }
    for end in ["", "   "] {
        let mut route = route_for(S::INDEX);
        let path = route.dir.join(S::name());
        let mut rows = S::lines();
        if !end.is_empty() {
            rows.push(end.into());
        }
        fs::write(&path, rows.join("\n")).unwrap();
        let mut p = parser::<S>(&path);
        p.prepare_acquisition(None, &scope(), None, NOW).unwrap();
        p.reader
            .set_extent_limit(fs::metadata(&path).unwrap().len());
        while !p.step().unwrap() {}
        assert!(p.apply_sealed_fragment());
        let (tail, parsed) = finish::<S>(&route, &path, p, None);
        assert_eq!(
            (
                parsed.snapshots[0].input_tokens,
                parsed.snapshots[0].output_tokens
            ),
            S::TOTAL
        );
        assert!(tail.unsealed);
        assert!(!tail.publish(&Ok(parsed)));
        route.save(false);
        assert!(
            state_v2::load_head(&route.index, &local_index_key(&path), S::REDUCTION_REVISION)
                .unwrap()
                .is_none()
        );
    }
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
    assert!(!parsed.progress_complete());
    assert!(parsed.non_progressing_residue());
    assert!(parsed.terminal_loss().is_some());
    // The public ownership counter keeps its native meaning for no-entity loss.
    assert_eq!(parsed.ownership_incomplete_file_count, 0);
    assert!(!tail.publish(&Ok(parsed)));
    route.save(false);
    assert!(
        state_v2::load_head(&route.index, &local_index_key(&path), S::REDUCTION_REVISION)
            .unwrap()
            .is_none()
    );
    assert!(!route
        .index
        .confirmed_empty_files
        .contains(&local_index_key(&path)));
    // Ordinary scanning/finalization also leaves accepted witnesses and incidence.
    let mut index = ScanIndex::default();
    let key = local_index_key(&path);
    let witness = snapshot_upload_body_witness(&previous[0]);
    index.files.insert(key.clone(), serde_json::from_value(json!({
        "size_bytes":0,"modified_unix_seconds":0,"source_file_fingerprint":"prior",
        "last_snapshot_fingerprint":previous[0].snapshot_fingerprint,"last_upload_body_witness":witness})).unwrap());
    index.file_snapshot_fingerprints.insert(
        key.clone(),
        BTreeSet::from([previous[0].snapshot_fingerprint.clone()]),
    );
    index.accepted_rebuild_incidence.insert(
        key.clone(),
        BTreeSet::from([previous[0].snapshot_fingerprint.clone()]),
    );
    let before = (
        index.files[&key].last_snapshot_fingerprint.clone(),
        index.files[&key].last_upload_body_witness.clone(),
        index.accepted_rebuild_incidence.clone(),
    );
    let mut scan = scan_source_roots(
        S::SOURCE,
        std::slice::from_ref(&route.dir),
        &mut index,
        "2026-10-20T16:00:00Z",
        BACKFILL_WINDOW_DAYS,
    )
    .unwrap();
    assert!(scan.snapshots.is_empty());
    finalize_scan_after_policy(S::SOURCE, &mut scan, &mut index);
    assert_eq!(
        (
            index.files[&key].last_snapshot_fingerprint.clone(),
            index.files[&key].last_upload_body_witness.clone(),
            index.accepted_rebuild_incidence.clone()
        ),
        before
    );
    assert!(!index.confirmed_empty_files.contains(&key));
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
    claude_responses();
    placement();
}
/// [regress] O1-O3/O6-O9: Codex keeps native occurrence and cumulative rules.
#[test]
fn codex_bad_record_keeps_valid_occurrences() {
    regression::<Codex>();
    codex_occurrences();
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
    // A checked overflow is one discarded record beside healthy occurrences.
    let mut rows = Pi::lines();
    let mut overflow: Value = serde_json::from_str(&pi_usage(
        "message_end",
        "overflow",
        json!("2026-10-20T10:00:00Z"),
    ))
    .unwrap();
    overflow["message"]["usage"]["input"] = json!(u64::MAX);
    rows.push(overflow.to_string());
    write(&path, &rows);
    let (tail, parsed) = full::<Pi>(&route, &path);
    assert!(parsed.progress_complete());
    assert_eq!(
        (
            parsed.snapshots[0].input_tokens,
            parsed.snapshots[0].request_count
        ),
        (24, 2)
    );
    assert_eq!(parsed.dropped_usage_record_count, 1);
    assert!(tail.publish(&Ok(parsed)));
}

// O8 uses the real listing gate: an aged never-read file is skipped, an
// eligible first admission adds valid siblings, and its accepted body stays quiet.
fn admission<S: SourceFixture>() {
    let route = route_for(S::INDEX);
    let path = route.dir.join(S::name());
    let mut rows = S::lines();
    rows.extend(S::bad());
    write(&path, &rows);
    let at = "2026-12-20T00:00:00Z";
    let now = rfc3339_unix_seconds(at).unwrap();
    let set_age = |days| {
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(now - days * 86400))
            .unwrap()
    };
    let mut index = ScanIndex::default();
    set_age(61);
    let skipped = scan_source_roots(
        S::SOURCE,
        std::slice::from_ref(&route.dir),
        &mut index,
        at,
        BACKFILL_WINDOW_DAYS,
    )
    .unwrap();
    assert_eq!(
        (skipped.scanned_file_count, skipped.snapshots.len()),
        (0, 0)
    );
    set_age(59);
    index.traversal = None;
    let mut admitted = scan_source_roots(
        S::SOURCE,
        std::slice::from_ref(&route.dir),
        &mut index,
        at,
        BACKFILL_WINDOW_DAYS,
    )
    .unwrap();
    assert_eq!(
        (admitted.scanned_file_count, admitted.snapshots.len()),
        (1, 1)
    );
    assert_eq!(
        (
            admitted.snapshots[0].input_tokens,
            admitted.snapshots[0].output_tokens
        ),
        S::TOTAL
    );
    finalize_scan_after_policy(S::SOURCE, &mut admitted, &mut index);
    let accepted = index.files[&local_index_key(&path)]
        .last_snapshot_fingerprint
        .clone();
    assert!(accepted.is_some());
    index.traversal = None;
    let quiet = scan_source_roots(
        S::SOURCE,
        std::slice::from_ref(&route.dir),
        &mut index,
        at,
        BACKFILL_WINDOW_DAYS,
    )
    .unwrap();
    assert_eq!(quiet.scanned_file_count, 0);
    assert!(quiet.snapshots.is_empty());
    assert_eq!(
        index.files[&local_index_key(&path)].last_snapshot_fingerprint,
        accepted
    );
}

// O3: bad totals never reset a native baseline. Cumulative-only usage retains
// the native next-hour placement; per-turn usage and native occurrences retain
// their existing repeat/reset rules.
fn codex_occurrences() {
    let mut route = route_for(Source::Codex);
    let path = route.dir.join(Codex::name());
    let event = |minute, total: Value, last: Option<u64>| {
        let mut info = json!({"total_token_usage":{"input_tokens":total,"output_tokens":0}});
        if let Some(last) = last {
            info["last_token_usage"] = json!({"input_tokens":last,"output_tokens":0});
        }
        json!({"type":"event_msg","timestamp":format!("2026-10-18T{minute:02}:00:00Z"),
            "payload":{"type":"token_count","info":info}})
        .to_string()
    };
    for per_turn in [false, true] {
        let rows = vec![codex_lines(1)[0].clone(),
            json!({"type":"turn_context","timestamp":"2026-10-18T10:00:00Z","payload":{"model":"gpt-5"}}).to_string(),
            event(10, json!(100), per_turn.then_some(100)),
            event(11, json!("invalid"), None),
            event(12, json!(200), per_turn.then_some(100)),
            event(12, json!(200), per_turn.then_some(100)),
            event(13, json!(50), per_turn.then_some(50))];
        write(&path, &rows);
        let (tail, parsed) = full::<Codex>(&route, &path);
        assert!(parsed.progress_complete());
        assert_eq!(parsed.snapshots[0].input_tokens, 250);
        assert_eq!(parsed.recognized_usage_drop_count, 1);
        let bucket = parsed.snapshots[0]
            .usage_buckets
            .iter()
            .find(|b| b.bucket_start == "2026-10-18T12:00:00Z")
            .unwrap();
        assert_eq!(
            bucket
                .model_usage
                .iter()
                .map(|row| row.input_tokens)
                .sum::<u64>(),
            100,
            "the bad total is neither zero nor a reset"
        );
        let cold = emitted::<Codex>(Mode::ColdFull, &route, &parsed.snapshots);
        commit::<Codex>(&mut route, &path, tail, parsed);
        route.index = ScanIndex::load(&route.path).unwrap();
        let (p, base, mode) = stored::<Codex>(&route, &path);
        assert_eq!(mode, ReadMode::Unchanged);
        let (_, restored) = finish::<Codex>(&route, &path, p, Some(base));
        money_oracle::assert_equivalent(
            &cold,
            &emitted::<Codex>(Mode::Restart, &route, &restored.snapshots),
        );
    }
}

// O4: a progressive response is finalized once. A conflicting response stays
// excluded while a distinct healthy response retains exact native money.
fn claude_responses() {
    let mut route = route_for(Source::Claude);
    let path = route.dir.join(Claude::name());
    let response = |id, input, output, at| {
        json!({"type":"assistant",
        "sessionId":"5f0c2a8e-1111-4222-8333-944445555777","timestamp":at,
        "requestId":id,"message":{"id":id,"model":"claude-opus-4-1",
            "usage":{"input_tokens":input,"output_tokens":output}}})
        .to_string()
    };
    let rows = vec![
        response("progressive", 10, 1, "2026-10-20T10:00:00Z"),
        response("progressive", 10, 3, "2026-10-20T10:01:00Z"),
        response("conflict", 20, 5, "2026-10-20T10:02:00Z"),
        response("conflict", 21, 4, "2026-10-20T10:03:00Z"),
        response("healthy", 7, 2, "2026-10-20T10:04:00Z"),
    ];
    write(&path, &rows);
    let (tail, parsed) = full::<Claude>(&route, &path);
    assert!(parsed.progress_complete());
    assert_eq!(
        (
            parsed.snapshots[0].input_tokens,
            parsed.snapshots[0].output_tokens,
            parsed.snapshots[0].request_count
        ),
        (17, 5, 2)
    );
    assert!(parsed.recognized_usage_drop_count > 0);
    let cold = emitted::<Claude>(Mode::ColdFull, &route, &parsed.snapshots);
    commit::<Claude>(&mut route, &path, tail, parsed);
    route.index = ScanIndex::load(&route.path).unwrap();
    let (p, base, mode) = stored::<Claude>(&route, &path);
    assert_eq!(mode, ReadMode::Unchanged);
    let (_, parsed) = finish::<Claude>(&route, &path, p, Some(base));
    money_oracle::assert_equivalent(
        &cold,
        &emitted::<Claude>(Mode::Restart, &route, &parsed.snapshots),
    );
}

// O7: transport refusal and not-stored credit nothing; a partial ACK credits
// its exact entity; crash/reopen retains that credit without replaying it.
fn ack_transitions<S: SourceFixture>(route: &Route, items: &[SnapshotItem]) {
    let mut rows = S::lines();
    let original = &items[0].source_session_id;
    let sibling = "019a0c2a-8e11-7222-8333-944445555778";
    for row in &mut rows {
        *row = row.replace(original, sibling);
    }
    let path = route.dir.join(format!("rollout-{sibling}.jsonl"));
    write(&path, &rows);
    let (_, parsed) = full::<S>(route, &path);
    let mut offered = items.to_vec();
    offered.extend(parsed.snapshots);
    assert_eq!(offered.len(), 2);
    let response = |batch: &[SnapshotItem], partial: bool, not_stored: bool| {
        let refs: Vec<Value> = batch.iter().take(if partial {1} else {batch.len()}).map(|item| json!({
            "source_session_id":item.source_session_id,"snapshot_fingerprint":item.snapshot_fingerprint,
            "body_witness_digest":snapshot_upload_body_witness(item),"occurrence_count":1,
            "unchanged_basis":not_stored.then_some("usage_identical")
        })).collect();
        serde_json::from_value::<crate::snapshot_client::SnapshotBatchResponse>(json!({
            "accepted":refs.len(),"sessions_reconciled":refs.len(),"session_ids":[],"disabled":false,
            "disabled_reason":null,"entity_ack_contract":SNAPSHOT_ENTITY_ACK_CONTRACT,
            "accepted_entities":if not_stored {vec![]} else {refs.clone()},
            "unchanged_entities":if not_stored {refs} else {vec![]},
            "rejected_entities":if partial {batch.iter().skip(1).map(|item| json!({
                "source_session_id":item.source_session_id,"snapshot_fingerprint":item.snapshot_fingerprint,
                "occurrence_count":1,"reason":"invalid","detail":"synthetic refusal","permanent":true
            })).collect::<Vec<_>>()} else {vec![]}
        })).unwrap()
    };
    let mut ack = AckLedger::new(S::SOURCE);
    assert!(ack
        .attempt(&offered, |_| Err(anyhow::anyhow!(
            "synthetic transport failure"
        )))
        .is_err());
    assert!(!offered.iter().any(|item| ack.settled(item)));
    let mut unstored = AckLedger::new(S::SOURCE);
    let _ = unstored.attempt(&offered, |batch| Ok(response(&batch, false, true)));
    assert!(!offered.iter().any(|item| unstored.settled(item)));
    let _ = ack.attempt(&offered, |batch| Ok(response(&batch, true, false)));
    assert!(ack.settled(&offered[0]));
    assert!(!ack.settled(&offered[1]));
    let progress = route.dir.join("acks.json");
    ack.save(&progress);
    let mut restarted = AckLedger::new(S::SOURCE);
    restarted.reopen(S::SOURCE, &progress);
    assert!(restarted.settled(&offered[0]));
    assert!(!restarted.settled(&offered[1]));
    let retry = offered[1].clone();
    // Permanent refusal stores no body ACK; a fresh delivery context can retry it.
    let mut retrying = AckLedger::new(S::SOURCE);
    retrying.deliver(std::slice::from_ref(&retry));
    assert!(retrying.settled(&retry));
    restarted.deliver(std::slice::from_ref(&offered[0]));
    assert_eq!(restarted.posts(), 0);
    assert!(restarted.settled(&offered[0]));
    assert!(!restarted.settled(&offered[1]));
}

// The existing native account corpus supplies two accounts and the switch;
// add one genuine side call and an unobserved transcript request, then feed
// the production evidence/tag stage after both cold and continued native reads.
fn placement() {
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    crate::snapshots::with_max_gated_claude_revision(3, || {
        let (dir, specimen, mut api, mut traces) = claude_request_account_mixed_fixture(4, false);
        let session = specimen.source_session_id.clone();
        let path = dir.join(format!("{session}.jsonl"));
        let support = dir.with_extension("b2-evidence");
        let mut side = api.evidence[&session][3].clone();
        side.request_id = "side-call".into();
        side.client_request_id = "client-side-call".into();
        side.event_sequence = Some(5);
        side.input_tokens = 5;
        side.output_tokens = 2;
        side.fingerprint.clear();
        side.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&side).unwrap())
        );
        api.evidence.get_mut(&session).unwrap().push(side);
        let mut trace = traces.evidence[&session][3].clone();
        trace.request_id = "side-call".into();
        trace.client_request_id = "client-side-call".into();
        trace.fingerprint.clear();
        trace.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&trace).unwrap())
        );
        traces.evidence.get_mut(&session).unwrap().push(trace);
        for (kind, rows) in [
            (
                "claude-code-effort",
                serde_json::to_value(&api.evidence[&session]).unwrap(),
            ),
            (
                "claude-code-trace-ownership",
                serde_json::to_value(&traces.evidence[&session]).unwrap(),
            ),
        ] {
            let file = support
                .join("local-otel")
                .join(kind)
                .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())));
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(
                file,
                rows.as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        }
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(
            file,
            "{}",
            json!({"type":"assistant","sessionId":session,
            "timestamp":"2026-08-02T07:04:00Z","requestId":"gap","message":{"id":"gap",
                "model":"claude-opus-4-1","usage":{"input_tokens":7,"output_tokens":2}}})
        )
        .unwrap();
        writeln!(
            file,
            "{}",
            json!({"type":"assistant","sessionId":session,
            "timestamp":"2026-08-02T07:05:00Z","requestId":"bad","message":{"id":"bad",
                "usage":{"input_tokens":"invalid"}}})
        )
        .unwrap();
        drop(file);
        let births = BTreeMap::from([(
            path.clone(),
            time::OffsetDateTime::parse(
                "2026-08-02T07:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap()
            .unix_timestamp_nanos(),
        )]);
        let run = |scanner: &E2ScanFixture, index, sampled| {
            let index = if sampled {
                scanner.routed(index, &dir)
            } else {
                index
            };
            let (mut index, mut scan, _) = scanner.scan(
                std::slice::from_ref(&dir),
                &support,
                index,
                100,
                sampled,
                &births,
                &[],
            );
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(
                &support, &mut scan, &mut index,
            );
            for item in &mut scan.snapshots {
                item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            }
            (index, scan)
        };
        let (cold_index, cold_scan) = run(
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            false,
        );
        let cold = fixture::scan_money(SnapshotSource::ClaudeCode, &cold_index, &cold_scan);
        assert_eq!(cold_scan.snapshots[0].input_tokens, 52);
        assert_eq!(
            cold_scan.snapshots[0].request_count, 6,
            "four responses, gap and independent side call"
        );
        let mut accounts = BTreeSet::new();
        fn accounts_in(value: &Value, into: &mut BTreeSet<String>) {
            match value {
                Value::Object(map) => {
                    if let Some(a) = map.get("account_identifier_hash").and_then(Value::as_str) {
                        into.insert(a.to_owned());
                    }
                    for v in map.values() {
                        accounts_in(v, into);
                    }
                }
                Value::Array(a) => {
                    for v in a {
                        accounts_in(v, into);
                    }
                }
                _ => {}
            }
        }
        for item in &cold_scan.snapshots {
            accounts_in(&serde_json::to_value(item).unwrap(), &mut accounts);
        }
        assert!(
            accounts.len() >= 2,
            "native tags cover both sides of the account switch"
        );
        assert!(!api.evidence[&session]
            .iter()
            .any(|row| row.request_id == "gap"));
        let scanner = E2ScanFixture::capturing_identity();
        let (index, scan) = run(&scanner, ScanIndex::default(), true);
        money_oracle::assert_equivalent(
            &cold,
            &fixture::scan_money(SnapshotSource::ClaudeCode, &index, &scan),
        );
        let mut index = index;
        // The file has a committed reduction but its finalized body is still owed.
        index
            .files
            .get_mut(&local_index_key(&path))
            .unwrap()
            .last_snapshot_fingerprint = None;
        let route = crate::snapshots::e2_pipeline_scan_fixture::route_of(&index).unwrap();
        index.save(&route).unwrap();
        let loaded = ScanIndex::load(&route).unwrap();
        let restarted = E2ScanFixture::capturing_identity();
        restarted.on_committed_route(&route);
        let (restored, scan) = run(&restarted, loaded, true);
        money_oracle::assert_equivalent(
            &cold,
            &fixture::scan_money(SnapshotSource::ClaudeCode, &restored, &scan),
        );
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(support).unwrap();
    });
}
