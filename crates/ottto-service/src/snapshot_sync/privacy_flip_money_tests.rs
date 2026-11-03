// A Tail under a flipped setting or capability after a parse under the old one
// equals a Full under the new one, on the real E2 pipeline with two accounts
// placed, a side call and an evidence gap. Every flip's wire fields are checked
// against what it demands before the POSTed bodies are compared.
use super::money_equivalence_tests::{claude_change, claude_corpus, input_clock};
use super::state_v2_money_tests::{otel_rows, routed, second_account, tagged_api};
use super::*;
use crate::session_attribution::{normalize_template_material, opaque_hmac_id};
use crate::snapshots::privacy_flip_modes::{all as policy_all, link, Mode, FLIPS};
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle::assert_equivalent, RouteResult,
};

/// A resumed session: its copied prefix is what the copy capability marks.
const RESUMED: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
/// A session whose cold requests are what the cache capability carries.
const COLD: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const PROMPT: &str = "Review the synthetic checkout flow and report only safe results.";
const SKILL: &str = "synthetic-review";

/// The state a flip starts from. A key only shows while attribution is on, so
/// its row starts there, from either key.
fn start_of(name: &str, start: bool) -> Mode {
    let key_row = name == "key";
    Mode {
        policy: policy_all(start || key_row),
        key: u8::from(key_row && start),
        cache: start,
        copy: start,
    }
}
fn key_bytes(key: u8) -> [u8; 32] {
    [13 + key; 32]
}
fn attribution_under(c: &Corpus, key: u8) -> crate::session_attribution::SessionAttributionContext {
    use base64::Engine;
    crate::session_attribution::SessionAttributionContext::from_activity_hint(
        SnapshotSource::ClaudeCode,
        &c.root,
        true,
        Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes(key))),
        Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .unwrap()
}

fn page_under(c: &Corpus, scanner: &E2ScanFixture, mut index: ScanIndex, mode: Mode) -> Page {
    let attribution = mode
        .policy
        .session_attribution_enabled
        .then(|| attribution_under(c, mode.key));
    let namespace = attribution
        .as_ref()
        .map(|context| context.checkpoint_namespace());
    scanner.set_attribution(attribution);
    let base = cycle_upload_context(mode.policy, namespace.as_deref(), mode.cache);
    index.activate_upload_context(copy_unproven_upload_context(
        resumed_prefix_upload_context(base.clone(), true),
        mode.copy,
    ));
    // As the prepare: finish writes copy rows under the active capability.
    index.copy_unproven_enabled = mode.copy;
    index.set_copy_prefix_base_upload_context(Some(base));
    index.activate_effective_upload_body_witness_revision(3);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    index.load_claude_reemission_exclusions(&c.support);
    let committed = index.clone();
    let (index, scan, modes) = scanner.scan(
        std::slice::from_ref(&c.root),
        &c.support,
        index,
        100,
        true,
        &c.births,
        &[],
    );
    Page {
        cache: scanner.cache.clone(),
        committed,
        index,
        scan,
        modes,
        disposition: Default::default(),
        released: Default::default(),
        unhealthy: Default::default(),
        stats: Default::default(),
        delivered: None,
        upload_policy: mode.policy,
    }
}
/// The root with everything a setting governs: a title, a repository, a link,
/// a first prompt (a keyed template and its label) and a skill (a keyed id, its
/// label and the activity summary).
fn write_root_material(c: &mut Corpus) -> PathBuf {
    let repository = c.base.join("synthetic-repo");
    std::fs::create_dir_all(&repository).unwrap();
    let status = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repository)
        .status()
        .unwrap();
    assert!(status.success());
    let cwd = repository.to_string_lossy().into_owned();
    let mut response: serde_json::Value = serde_json::from_str(&line(ROOT, "r1", AT, 10)).unwrap();
    response["message"]["role"] = json!("assistant");
    response["message"]["content"] = json!([
        {"type":"tool_use","id":"skill-1","name":"Skill","input":{"skill":SKILL}},
        {"type":"tool_use","id":"skill-2","name":"Read",
            "input":{"file_path":format!("/synthetic/skills/{SKILL}/SKILL.md")}}
    ]);
    let text = [
        json!({"type":"user","sessionId":ROOT,"timestamp":AT,"cwd":cwd,
            "message":{"role":"user","content":PROMPT}}),
        json!({"timestamp":AT,"sessionId":ROOT,"summary":"Synthetic title","cwd":cwd}),
        link(ROOT, AT, 0),
        response,
    ]
    .iter()
    .map(|row| format!("{row}\n"))
    .collect::<String>();
    let path = c.root(ROOT, &text);
    input_clock(&path);
    path
}
/// A sibling session whose telemetry names no account: an evidence gap,
/// grown with the root.
fn evidence_gap(c: &mut Corpus, grown: bool) {
    let mut text = line(COPY, "gap-1", AT, 6);
    let mut rows = vec![api_for(COPY, "gap-1", 6, 60)];
    if grown {
        text += &line(COPY, "gap-2", AT, 7);
        rows.push(api_for(COPY, "gap-2", 7, 70));
    }
    let path = c.root(COPY, &text);
    c.evidence_for(COPY, &rows, &[]);
    input_clock(&path);
}
/// A resumed session with an unproven copied prefix, grown with the root.
fn resumed_session(c: &mut Corpus, grown: bool) {
    let mut lines = vec![A, B, C];
    let mut rows = vec![
        api_for(RESUMED, "a", 10, 250),
        api_for(RESUMED, "c", 10, 400),
    ];
    if grown {
        lines.push(D);
        rows.push(api_for(RESUMED, "d", 10, 400));
    }
    let path = c.write_at(
        &file(RESUMED),
        &resumed(RESUMED, &lines),
        "2026-08-02T07:03:00Z",
    );
    c.evidence_for(RESUMED, &rows, &[]);
    input_clock(&path);
}
/// A forked session, whose own start is proven by its inherited line, of large
/// prompts barely read from cache, grown with the root.
fn cold_session(c: &mut Corpus, grown: bool) {
    let inherited = json!({"timestamp":AT,"sessionId":COLD,"type":"assistant",
        "forkedFrom":{"sessionId":ROOT,"messageUuid":"parent-message"},
        "requestId":"cold-parent","message":{"id":"msg-cold-parent",
            "model":"claude-haiku-4-5","usage":{"input_tokens":5,"output_tokens":5}}});
    let mut text = format!("{inherited}\n") + &line(COLD, "cold-1", AT, 30_000);
    let mut rows = vec![api_for(COLD, "cold-1", 30_000, 300)];
    if grown {
        text += &line(COLD, "cold-2", "2026-08-02T07:00:40Z", 40_000);
        rows.push(api_for(COLD, "cold-2", 40_000, 400));
    }
    let path = c.root(COLD, &text);
    c.evidence_for(COLD, &rows, &[]);
    input_clock(&path);
}
/// A telemetry-only request the root owns through its trace, on account b.
fn side_call(c: &Corpus) {
    let mut effort: Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence> =
        otel_rows(c, "claude-code-effort");
    let mut traces: Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence> =
        otel_rows(c, "claude-code-trace-ownership");
    effort.push(tagged_api("r-side", 5, Some(&"b".repeat(64))));
    traces.push(trace("r-side", ""));
    c.evidence(&effort, &traces);
}
/// The service's finish: enrichment and the upload filter, the effective body
/// witness, then the cache projection onto the bodies that go out.
fn settle(c: &Corpus, page: &mut Page, mode: Mode) {
    page.enrich(c);
    let progress = e2_progress();
    let disposition = page.disposition.clone();
    let legacy = BTreeSet::new();
    page.finish_with(|item| {
        effective_snapshot_upload_body_witness(
            item,
            &progress,
            mode.cache,
            false,
            &legacy,
            &disposition,
        )
    });
    for snapshot in &mut page.scan.snapshots {
        prepare_snapshot_cache_for_upload(snapshot, &progress, mode.cache, false, &legacy);
    }
}
fn carried(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Array(rows) => !rows.is_empty(),
        _ => true,
    }
}
/// The POSTed bodies carry each field exactly when `mode` lets them, and keyed
/// values are the ones computed here under the key at send.
fn assert_wire(route: &RouteResult, mode: Mode, label: &str) {
    let policy = mode.policy;
    let root = &route.snapshots[ROOT];
    assert_eq!(
        carried(&root["session_display_name"]),
        policy.session_titles_enabled,
        "{label}: title"
    );
    assert_eq!(
        carried(&root["repository_label"]),
        policy.workspace_labels_enabled,
        "{label}: repository label"
    );
    assert_eq!(
        carried(&root["session_artifacts"]),
        policy.session_artifacts_enabled,
        "{label}: links"
    );
    assert_eq!(
        carried(&root["activity_summary"]["skills"]),
        policy.private_labels(),
        "{label}: skill names"
    );
    let empty = Vec::new();
    let facts = root["attribution_facts"].as_array().unwrap_or(&empty);
    let keyed = |field: &str| {
        facts
            .iter()
            .filter(|fact| fact["field"] == field)
            .map(|fact| fact["value"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    if policy.session_attribution_enabled {
        let key = key_bytes(mode.key);
        let template = normalize_template_material(PROMPT).unwrap();
        assert_eq!(
            keyed("template_group_id"),
            vec![opaque_hmac_id(&key, "template_group", &template).unwrap()],
            "{label}: template under the key at send"
        );
        // One opaque id per skill is a name: it goes only with names on.
        let skill_ids = if policy.names() {
            vec![opaque_hmac_id(&key, "skill", SKILL).unwrap()]
        } else {
            Vec::new()
        };
        assert_eq!(
            keyed("skill_id"),
            skill_ids,
            "{label}: skill under the key at send"
        );
    } else {
        assert!(facts.is_empty(), "{label}: attribution off");
    }
    assert_eq!(
        facts.iter().any(|fact| carried(&fact["display_label"])),
        policy.session_attribution_enabled
            && policy.session_attribution_labels_enabled
            && policy.session_titles_enabled,
        "{label}: fact labels"
    );
    assert_eq!(
        carried(&route.snapshots[COLD]["cache_observations"]["operations"]),
        mode.cache,
        "{label}: cache observations"
    );
    assert_eq!(
        carried(&route.snapshots[RESUMED]["copy_unproven_counts"]),
        mode.copy,
        "{label}: copy disclosure"
    );
}

/// [money] T1 on the real pipeline, for every setting and capability bit in
/// both directions.
#[cfg(unix)]
#[test]
fn flipped_policy_tail_places_money_like_a_full() {
    if !crate::heap_layout_bound::layout_supported() {
        println!("PRIVACY_FLIP_MONEY UNEXECUTED: native retained layout unavailable");
        return;
    }
    with_e2(|| {
        for (name, field) in FLIPS {
            for start in [false, true] {
                let label = format!("{name}/{start}");
                let before = start_of(name, start);
                let mut after = before;
                field(&mut after);

                let (mut c, _) = claude_corpus("progressive_response");
                let path = write_root_material(&mut c);
                evidence_gap(&mut c, false);
                resumed_session(&mut c, false);
                cold_session(&mut c, false);
                let scanner = E2ScanFixture::with_identity_capture(true);
                let mut warm = page_under(&c, &scanner, ScanIndex::default(), before);
                settle(&c, &mut warm, before);
                claude_change(&c, &path, "progressive_response");
                append(&path, &format!("{}\n", link(ROOT, AT, 1)));
                second_account(&c, &path);
                side_call(&c);
                evidence_gap(&mut c, true);
                resumed_session(&mut c, true);
                cold_session(&mut c, true);
                input_clock(&path);

                let mut tail = page_under(&c, &scanner, warm.index.clone(), after);
                settle(&c, &mut tail, after);
                assert_eq!(tail.modes, (0, 4, 0), "{label}");

                let fresh = E2ScanFixture::with_identity_capture(true);
                let mut cold = page_under(&c, &fresh, ScanIndex::default(), after);
                settle(&c, &mut cold, after);
                assert_eq!(cold.modes.0, 4, "{label}: control is a Full");
                let root = cold
                    .scan
                    .snapshots
                    .iter()
                    .find(|item| item.source_session_id == ROOT)
                    .unwrap();
                assert_eq!(
                    root.request_count, 4,
                    "positive control: three transcript requests and the side call"
                );
                assert!(
                    cold.scan
                        .snapshots
                        .iter()
                        .flat_map(|item| &item.usage_buckets)
                        .flat_map(|bucket| &bucket.model_usage)
                        .any(|row| row.account_identifier_hash.is_none()
                            && row.evidence_ref.is_none()
                            && row.identity_parts.is_none()),
                    "positive control: an evidence gap"
                );

                let accounts = tail
                    .scan
                    .snapshots
                    .iter()
                    .flat_map(|item| {
                        item.model_usage
                            .iter()
                            .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
                    })
                    .flat_map(|row| {
                        row.account_identifier_hash.iter().chain(
                            row.identity_parts
                                .iter()
                                .flatten()
                                .filter_map(|part| part.account_identifier_hash.as_ref()),
                        )
                    })
                    .collect::<BTreeSet<_>>();
                assert!(accounts.len() >= 2, "positive control: two accounts placed");
                let mut tampered = routed(&tail, after.policy);
                let (cold, tail) = (routed(&cold, after.policy), routed(&tail, after.policy));
                assert_wire(&cold, after, &format!("{label}/cold"));
                assert_wire(&tail, after, &format!("{label}/tail"));
                assert_equivalent(&cold, &tail);
                let body = tampered.snapshots.values_mut().next().unwrap();
                body["input_tokens"] = json!(u32::MAX);
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        assert_equivalent(&cold, &tampered)
                    }))
                    .is_err(),
                    "positive control: the oracle sees a token difference"
                );
            }
        }
    });
}

/// [money] Forward-only on the real pipeline, Claude: the bodies were sent but
/// no proof reached the index (no receipt, no stamps). A setting or capability
/// flip reads none of those files. Their next growth is a Tail under the new
/// context whose wire follows the new setting and whose money and placement
/// equal a cold Full under it.
#[cfg(unix)]
#[test]
fn flip_reads_no_unproven_delivered_file_then_tail_places_money_like_a_full() {
    if !crate::heap_layout_bound::layout_supported() {
        println!("PRIVACY_FLIP_FORWARD_ONLY UNEXECUTED: native retained layout unavailable");
        return;
    }
    with_e2(|| {
        for (name, field) in FLIPS {
            let label = format!("{name}/forward-only");
            let before = start_of(name, false);
            let mut after = before;
            field(&mut after);

            let (mut c, _) = claude_corpus("progressive_response");
            let path = write_root_material(&mut c);
            evidence_gap(&mut c, false);
            resumed_session(&mut c, false);
            cold_session(&mut c, false);
            let scanner = E2ScanFixture::with_identity_capture(true);
            let mut warm = page_under(&c, &scanner, ScanIndex::default(), before);
            settle(&c, &mut warm, before);
            // Delivered: the server holds the bodies. The index keeps no proof.
            let delivered = routed(&warm, before.policy);
            assert!(!delivered.snapshots.is_empty(), "{label}: delivered");
            let owed = warm.index.upload_context_owed_file_count();
            assert!(owed > 0, "{label}: positive control, unproven files");

            for (key, entry) in &warm.index.files {
                eprintln!(
                    "PRIV1DIAG7 {label} warm file={:?} rearmed={} evidence_owed={}",
                    Path::new(key).file_name(),
                    entry.rearmed(),
                    entry.evidence_owed
                );
            }
            let mut quiet = page_under(&c, &scanner, warm.index.clone(), after);
            eprintln!("PRIV1DIAG7 {label} quiet modes={:?}", quiet.modes);
            for item in &quiet.scan.snapshots {
                eprintln!(
                    "PRIV1DIAG7 {label} quiet emitted session={} requests={} removed={:?} file={:?}",
                    item.source_session_id,
                    item.request_count,
                    item.removed_request_count,
                    item.source_file_fingerprint.is_some()
                );
            }
            assert_eq!(
                (quiet.modes.0, quiet.modes.1),
                (0, 0),
                "{label}: the flip reads nothing"
            );
            assert!(quiet.scan.snapshots.is_empty(), "{label}: nothing to send");
            settle(&c, &mut quiet, after);
            assert_eq!(
                quiet.index.upload_context_owed_file_count(),
                owed,
                "{label}: still owed, paid by the next read"
            );

            claude_change(&c, &path, "progressive_response");
            append(&path, &format!("{}\n", link(ROOT, AT, 1)));
            second_account(&c, &path);
            side_call(&c);
            evidence_gap(&mut c, true);
            resumed_session(&mut c, true);
            cold_session(&mut c, true);
            input_clock(&path);

            let mut tail = page_under(&c, &scanner, quiet.index.clone(), after);
            settle(&c, &mut tail, after);
            assert_eq!(tail.modes, (0, 4, 0), "{label}");

            let fresh = E2ScanFixture::with_identity_capture(true);
            let mut cold = page_under(&c, &fresh, ScanIndex::default(), after);
            settle(&c, &mut cold, after);
            assert_eq!(cold.modes.0, 4, "{label}: control is a Full");
            let (cold, tail) = (routed(&cold, after.policy), routed(&tail, after.policy));
            assert_wire(&cold, after, &format!("{label}/cold"));
            assert_wire(&tail, after, &format!("{label}/tail"));
            assert_equivalent(&cold, &tail);
        }
    });
}
