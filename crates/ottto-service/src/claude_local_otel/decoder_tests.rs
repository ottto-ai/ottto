//! Frozen a0e3e222 whole-file decisions, deliberately independent of decoder methods.
use super::*;

fn baseline_api(bytes: &[u8]) -> ApiSidecarDecoder<'static> {
    let mut state = ApiSidecarDecoder::new("scope", Vec::new());
    let mut reader = BufReader::new(bytes);
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).unwrap() == 0 {
            break;
        }
        baseline_decode_api_line(
            &line,
            "scope",
            &mut state.health,
            &mut state.rows,
            &mut state.seen_fingerprints,
            &mut state.request_rows,
        );
    }
    state
}

fn baseline_trace(bytes: &[u8]) -> TraceSidecarDecoder<'static> {
    let mut state = TraceSidecarDecoder::new("scope", Vec::new());
    for line in BufReader::new(bytes).lines() {
        match line {
            Ok(line) => baseline_decode_trace_line(
                &line,
                "scope",
                &mut state.report,
                &mut state.rows,
                &mut state.seen_fingerprints,
                &mut state.request_fingerprints,
            ),
            Err(_) => state.report.unreadable_lines += 1,
        }
    }
    state
}

// Feed only physical LF-terminated lines; the adapter owns any unfinished bytes.
fn complete_lines(bytes: &[u8], mut push: impl FnMut(&[u8])) -> &[u8] {
    let sealed = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    for line in bytes[..sealed].split_inclusive(|b| *b == b'\n') {
        push(line);
    }
    &bytes[sealed..]
}

fn fragment(bytes: &[u8]) -> Option<&[u8]> {
    (!bytes.is_empty()).then_some(bytes)
}

// Sampled split points keep every boundary class of the old every-byte walk:
// byte 0, the last byte and the end; each LF -1..=+2 (CR/LF interior and both
// line edges); each UTF-8 continuation byte; and a 61-byte stride in between.
fn sampled_splits(bytes: &[u8]) -> Vec<usize> {
    let len = bytes.len();
    let mut splits = vec![0, len.saturating_sub(1), len];
    splits.extend((0..=len).step_by(61));
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            splits.extend(i.saturating_sub(1)..=(i + 2).min(len));
        }
        if matches!(*byte, 0x80..=0xBF) {
            splits.push(i);
        }
    }
    splits.sort_unstable();
    splits.dedup();
    splits
}

// EOF views are clones of sealed state: 19a does not introduce a durable overlay.
fn api_splits(bytes: &[u8]) {
    let expected = baseline_api(bytes);
    for split in sampled_splits(bytes) {
        let mut state = ApiSidecarDecoder::new("scope", Vec::new());
        let tail = complete_lines(&bytes[..split], |line| state.push_line(line));
        let sealed = split - tail.len();
        assert_eq!(state, baseline_api(&bytes[..sealed]), "sealed API {split}");
        let mut eof = state.clone();
        eof.finish_eof(fragment(tail));
        assert_eq!(eof, baseline_api(&bytes[..split]), "EOF API {split}");
        let tail = complete_lines(&bytes[sealed..], |line| state.push_line(line));
        state.finish_eof(fragment(tail));
        assert_eq!(state, expected, "continued API {split}");
    }
}

fn trace_splits(bytes: &[u8]) {
    let expected = baseline_trace(bytes);
    for split in sampled_splits(bytes) {
        let mut state = TraceSidecarDecoder::new("scope", Vec::new());
        let tail = complete_lines(&bytes[..split], |line| state.push_line(line));
        let sealed = split - tail.len();
        assert_eq!(
            state,
            baseline_trace(&bytes[..sealed]),
            "sealed trace {split}"
        );
        let mut eof = state.clone();
        eof.finish_eof(fragment(tail));
        assert_eq!(eof, baseline_trace(&bytes[..split]), "EOF trace {split}");
        let tail = complete_lines(&bytes[sealed..], |line| state.push_line(line));
        state.finish_eof(fragment(tail));
        assert_eq!(state, expected, "continued trace {split}");
    }
}

fn api_row(request: &str, fingerprint: &str) -> ClaudeLocalOtelEvidence {
    ClaudeLocalOtelEvidence {
        capture_revision: API_REQUEST_CAPTURE_REVISION.into(),
        session_id: "scope".into(),
        request_id: request.into(),
        fingerprint: fingerprint.into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        model: "synthetic-é\"\\\n".into(),
        cost_usd_micros: Some(123),
        input_tokens: 17,
        request_count: 1,
        ..Default::default()
    }
}

fn api_fixture(reverse: bool) -> Vec<u8> {
    let old = api_row("upgrade", "old");
    let mut richer = old.clone();
    richer.fingerprint = "richer".into();
    richer.request_identity = Some(ClaudeRequestIdentityEvidence {
        identity_hash_scheme: "synthetic".into(),
        account: ClaudeIdentityAttributeEvidence {
            origin: ClaudeIdentityAttributeOrigin::Missing,
            disposition: ClaudeIdentityDisposition::Missing,
            resource_hash: None,
            log_record_hash: None,
        },
        organization: ClaudeIdentityAttributeEvidence {
            origin: ClaudeIdentityAttributeOrigin::Missing,
            disposition: ClaudeIdentityDisposition::Missing,
            resource_hash: None,
            log_record_hash: None,
        },
        disposition: ClaudeIdentityDisposition::Missing,
    });
    let mut conflict = old.clone();
    conflict.fingerprint = "conflict".into();
    conflict.output_tokens = 9;
    let mut wrong_session = api_row("other", "wrong");
    wrong_session.session_id = "foreign".into();
    let (first, second) = if reverse {
        (&richer, &old)
    } else {
        (&old, &richer)
    };
    let mut bytes = Vec::new();
    for row in [
        first,
        &api_row("between", "between"),
        second,
        &old,
        &richer,
        &conflict,
        &old,
        &api_row("", "missing"),
        &api_row("", "missing"),
        &wrong_session,
    ] {
        bytes.extend(serde_json::to_vec(row).unwrap());
        bytes.extend(b"\r\n");
    }
    // Interior malformed and invalid UTF-8 lines, followed by a healthy row.
    bytes.extend(b"{broken\n\xff\n\n");
    bytes.extend(serde_json::to_vec(&api_row("last", "last")).unwrap());
    bytes
}

#[test]
fn api_continuation_and_eof_match_frozen_whole_file_at_sampled_boundaries() {
    let started = std::time::Instant::now();
    for reverse in [false, true] {
        let bytes = api_fixture(reverse);
        let state = baseline_api(&bytes);
        assert_eq!(
            state
                .rows
                .iter()
                .map(|r| r.fingerprint.as_str())
                .collect::<Vec<_>>(),
            ["richer", "between", "conflict", "missing", "last"]
        );
        assert_eq!(state.seen_fingerprints.len(), 6);
        assert!(
            state.seen_fingerprints.contains("old"),
            "suppressed fingerprint retained"
        );
        assert_eq!(state.request_rows["upgrade"], 0);
        assert_eq!(
            state.health.conflicting_request_ids,
            BTreeSet::from(["upgrade".into()])
        );
        assert_eq!(state.health.missing_request_ids, 2, "health precedes dedup");
        assert_eq!(state.health.invalid_session_rows, 1);
        assert_eq!(state.health.malformed_lines, 2);
        assert_eq!(state.health.unreadable_lines, 1);
        // Both orders keep the frozen golden above; the split walk runs for one.
        if reverse {
            continue;
        }
        for ending in [
            b"".as_slice(),
            b"\n",
            b"\n{",
            b"\n\xff",
            b"\n{\n",
            b"\n\xff\n",
        ] {
            let mut input = bytes.clone();
            input.extend(ending);
            api_splits(&input);
        }
    }
    eprintln!(
        "sidecar sampled-boundary oracle: kind=api wall_seconds={:.3}",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn trace_continuation_and_eof_match_frozen_whole_file_at_sampled_boundaries() {
    let started = std::time::Instant::now();
    let row = ClaudeTraceOwnershipEvidence {
        session_id: "scope".into(),
        request_id: "request".into(),
        fingerprint: "first".into(),
        agent_id: "synthetic-é\"\\\n".into(),
        observed_at: "clock".into(),
        ..Default::default()
    };
    let mut other = row.clone();
    other.fingerprint = "second".into();
    let mut missing = row.clone();
    missing.request_id.clear();
    missing.fingerprint = "missing".into();
    let mut foreign = row.clone();
    foreign.session_id = "foreign".into();
    let mut bytes = Vec::new();
    for item in [&row, &other, &row, &missing, &missing, &foreign] {
        bytes.extend(serde_json::to_vec(item).unwrap());
        bytes.extend(b"\r\n");
    }
    bytes.extend(b"{broken\n\xff\n\n");
    bytes.extend(serde_json::to_vec(&row).unwrap());
    let state = baseline_trace(&bytes);
    assert_eq!(
        state
            .rows
            .iter()
            .map(|r| r.fingerprint.as_str())
            .collect::<Vec<_>>(),
        ["first", "second", "missing"]
    );
    assert_eq!(state.seen_fingerprints.len(), 3);
    assert_eq!(
        state.request_fingerprints["request"], "first",
        "last export was deduplicated"
    );
    assert_eq!(
        state.report.conflicting_request_ids,
        BTreeSet::from(["request".into()])
    );
    assert_eq!(state.report.missing_request_ids, 2);
    assert_eq!(state.report.invalid_session_rows, 1);
    assert_eq!(state.report.malformed_lines, 2);
    assert_eq!(state.report.unreadable_lines, 1);
    for ending in [
        b"".as_slice(),
        b"\n",
        b"\n{",
        b"\n\xff",
        b"\n{\n",
        b"\n\xff\n",
    ] {
        let mut input = bytes.clone();
        input.extend(ending);
        trace_splits(&input);
    }
    eprintln!(
        "sidecar sampled-boundary oracle: kind=trace wall_seconds={:.3}",
        started.elapsed().as_secs_f64()
    );
}

// Only the additive identity field may differ across a v2 upgrade replay.
// Comparing the whole typed row protects every pre-existing usage/ownership field.
fn baseline_identity_upgrade_replay(
    previous: &ClaudeLocalOtelEvidence,
    incoming: &ClaudeLocalOtelEvidence,
) -> bool {
    if previous.capture_revision != API_REQUEST_CAPTURE_REVISION
        || incoming.capture_revision != API_REQUEST_CAPTURE_REVISION
        || previous.request_identity.is_none() == incoming.request_identity.is_none()
    {
        return false;
    }
    let mut previous = previous.clone();
    let mut incoming = incoming.clone();
    previous.fingerprint.clear();
    incoming.fingerprint.clear();
    previous.request_identity = None;
    incoming.request_identity = None;
    previous == incoming
}

/// Append one distinct request row; report a same-request fingerprint conflict.
/// A compatible upgrade replay keeps one usage row and the richer local witness.
fn baseline_append_request_evidence(
    rows: &mut Vec<ClaudeLocalOtelEvidence>,
    seen_fingerprints: &mut BTreeSet<String>,
    request_rows: &mut BTreeMap<String, usize>,
    item: ClaudeLocalOtelEvidence,
) -> bool {
    if !seen_fingerprints.insert(item.fingerprint.clone()) {
        return false;
    }
    let mut conflict = false;
    if !item.request_id.is_empty() {
        if let Some(index) = request_rows.get(&item.request_id).copied() {
            if baseline_identity_upgrade_replay(&rows[index], &item) {
                if item.request_identity.is_some() {
                    rows[index] = item;
                }
                return false;
            }
            conflict = true;
        } else {
            request_rows.insert(item.request_id.clone(), rows.len());
        }
    }
    rows.push(item);
    conflict
}

// Shared canonical row decoder: the optional paid-input path only controls
// storage/capacity; identity, validation and conflict decisions stay here.
fn baseline_decode_api_line(
    line: &[u8],
    session_id: &str,
    health: &mut ClaudeLocalOtelLoadHealth,
    rows: &mut Vec<ClaudeLocalOtelEvidence>,
    seen: &mut BTreeSet<String>,
    request_rows: &mut BTreeMap<String, usize>,
) {
    let Ok(line) = std::str::from_utf8(line) else {
        health.unreadable_lines += 1;
        return;
    };
    let item = match serde_json::from_str::<ClaudeLocalOtelEvidence>(line) {
        Ok(item) => item,
        Err(_) => {
            health.malformed_lines += 1;
            return;
        }
    };
    if item.session_id != session_id {
        health.invalid_session_rows += 1;
        return;
    }
    if item.request_id.is_empty() {
        health.missing_request_ids += 1;
    }
    let request_id = item.request_id.clone();
    if baseline_append_request_evidence(rows, seen, request_rows, item) {
        health.conflicting_request_ids.insert(request_id);
    }
}

fn baseline_decode_trace_line(
    line: &str,
    session_id: &str,
    report: &mut ClaudeTraceOwnershipLoadReport,
    rows: &mut Vec<ClaudeTraceOwnershipEvidence>,
    seen_fingerprints: &mut BTreeSet<String>,
    request_fingerprints: &mut BTreeMap<String, String>,
) {
    let item = match serde_json::from_str::<ClaudeTraceOwnershipEvidence>(line) {
        Ok(item) => item,
        Err(_) => {
            report.malformed_lines += 1;
            return;
        }
    };
    if item.session_id != session_id {
        report.invalid_session_rows += 1;
        return;
    }
    if item.request_id.is_empty() {
        report.missing_request_ids += 1;
    } else if let Some(previous) =
        request_fingerprints.insert(item.request_id.clone(), item.fingerprint.clone())
    {
        if previous != item.fingerprint {
            report
                .conflicting_request_ids
                .insert(item.request_id.clone());
        }
    }
    if seen_fingerprints.insert(item.fingerprint.clone()) {
        rows.push(item);
    }
}
