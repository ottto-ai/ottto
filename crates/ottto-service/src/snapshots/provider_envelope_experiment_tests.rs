// Nonshipping boundary experiment. This module is compiled only in tests.
// Uses the real native parser, usage/owner fold, candidate decision, selected
// checkpoint and locked save/load. It is NOT the complete two-phase scanner.
use super::*;

type Api = crate::claude_local_otel::ClaudeLocalOtelLoadReport;
type Trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport;

fn reports(root: &str, extra: bool) -> (Api, Trace) {
    let mut api = (1..=5)
        .map(|i| {
            complete_api_row(
                root,
                &format!("req_{i}"),
                i,
                10,
                if i == 5 { 1 } else { 10 },
                0,
            )
        })
        .collect::<Vec<_>>();
    let mut trace = (1..=5)
        .map(|i| {
            complete_trace_row(
                root,
                &format!("req_{i}"),
                if i == 5 { "a4d1585d310070d0f" } else { "" },
            )
        })
        .collect::<Vec<_>>();
    if extra {
        api.push(complete_api_row(root, "req_extra", 6, 10, 10, 0));
        trace.push(complete_trace_row(root, "req_extra", ""));
    }
    (
        Api {
            evidence: BTreeMap::from([(root.to_string(), api)]),
            health: Default::default(),
        },
        Trace {
            evidence: BTreeMap::from([(root.to_string(), trace)]),
            ..Default::default()
        },
    )
}

fn fixture_index(root: &Path, parent: &str, items: &[SnapshotItem]) -> ScanIndex {
    let mut index = ScanIndex {
        accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
        ..Default::default()
    };
    let keys = [
        local_index_key(&root.join(format!("{parent}.jsonl"))),
        local_index_key(
            &root
                .join(parent)
                .join("subagents/agent-a4d1585d310070d0f.jsonl"),
        ),
    ];
    for (key, item) in keys.iter().zip(items) {
        index_file(
            &mut index,
            key,
            item.source_file_fingerprint.as_ref().unwrap(),
            &item.snapshot_fingerprint,
            WINDOW,
        );
        index
            .accepted_snapshot_fingerprints
            .insert(item.snapshot_fingerprint.clone());
    }
    index
}

fn raw_hashes(item: &SnapshotItem) -> BTreeSet<String> {
    item.claude_usage_request_ids
        .iter()
        .map(|id| format!("{:x}", Sha256::digest(id.as_bytes())))
        .collect()
}

// A caller MUST freeze `retained` before the authoritative fold. Passing the
// just-inserted witness is deliberately demonstrated to be wrong below.
fn qualified_prior(
    retained: &ClaudeUsageFamilyWitness,
    raw: &SnapshotItem,
    api: &Api,
    trace: &Trace,
    reported: bool,
) -> Option<BTreeSet<String>> {
    if !reported
        || !api.health.is_complete()
        || !trace.is_complete()
        || retained
            .legacy_excluded_request_id_hashes
            .values()
            .any(|e| !e.is_empty())
    {
        return None;
    }
    let root = claude_snapshot_family_root(raw);
    let owners = claude_legacy_request_owners(api, trace);
    let family = reconstruct_claude_usage_family(&root, retained, api, trace, owners.as_ref())?;
    let hashes = raw_hashes(raw);
    let occurrences = raw
        .claude_usage_occurrences
        .iter()
        .map(|(id, value)| {
            (
                format!("{:x}", Sha256::digest(id.as_bytes())),
                ClaudeTranscriptUsageOccurrenceWitness::from(value),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if retained
        .member_request_id_fingerprints
        .get(&raw.source_session_id)
        != Some(&claude_request_id_set_fingerprint(&hashes))
        || retained
            .member_occurrence_fingerprints
            .get(&raw.source_session_id)
            != Some(&claude_occurrence_map_fingerprint(&occurrences))
    {
        return None;
    }
    Some(
        family
            .rows_by_member
            .get(&raw.source_session_id)?
            .iter()
            .map(|row| format!("{:x}", Sha256::digest(row.request_id.as_bytes())))
            .collect(),
    )
}

#[test]
fn envelope_experiment_frozen_old_proof_does_not_mask_new_native_request() {
    let (dir, parent, raw) = claude_account_family_fixture();
    let (api0, trace0) = reports(&parent, false);
    let mut index = fixture_index(&dir, &parent, &raw);
    let mut seed = raw.clone();
    apply_claude_reported_usage_with_index(&mut seed, &api0, &trace0, &mut index, true, WINDOW);
    let retained = index.claude_usage_family_witnesses[&parent].clone();
    assert!(qualified_prior(&retained, &raw[0], &api0, &trace0, true).is_some());

    let path = dir.join(format!("{parent}.jsonl"));
    let mut contents = fs::read_to_string(&path).unwrap();
    contents.push_str(&format!("{{\"timestamp\":\"2026-08-02T07:00:06Z\",\"type\":\"assistant\",\"sessionId\":\"{parent}\",\"requestId\":\"req_extra\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"));
    fs::write(&path, contents).unwrap();
    let grown = parse_claude_code_jsonl_file(&path, WINDOW, hex64('a'))
        .unwrap()
        .remove(0);
    let (api1, trace1) = reports(&parent, true);
    let mut current = vec![grown.clone(), raw[1].clone()];
    let outcome = apply_claude_reported_usage_with_index(
        &mut current,
        &api1,
        &trace1,
        &mut index,
        true,
        WINDOW,
    );
    assert!(!outcome.duplicate_census.census_invalid);
    assert!(current
        .iter()
        .all(|i| i.usage_accounting_contract.as_deref()
            == Some("session_exclusive_reported_usage:v1")));
    let new_proof = &index.claude_usage_family_witnesses[&parent];
    assert_ne!(new_proof, &retained);
    assert!(qualified_prior(&retained, &grown, &api1, &trace1, true).is_none());
    let unsafe_prior = qualified_prior(new_proof, &grown, &api1, &trace1, true).unwrap();
    let actual = raw_hashes(&grown);
    assert!(
        actual.difference(&unsafe_prior).next().is_none(),
        "fresh proof would hide the new request"
    );
    let extra = format!("{:x}", Sha256::digest(b"req_extra"));
    assert!(
        actual.contains(&extra),
        "old-proof miss falls back to ALL, preserving the native comparison trigger"
    );
    assert!(
        qualified_prior(new_proof, &grown, &api1, &trace1, false).is_none(),
        "demotion cannot certify prior"
    );
    writeln!(std::io::stderr().lock(), "envelope_experiment_old_p: frozen_rejected=true fresh_would_mask=true required_native_hit=1").unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[derive(Default)]
struct ProcessPermit {
    scope: Option<&'static str>,
}
impl ProcessPermit {
    fn native_save(
        &mut self,
        scope: &'static str,
        outcome: &ClaudeUsageAuthorityDisposition,
        index: &mut ScanIndex,
        path: &Path,
    ) -> Result<()> {
        self.scope = None;
        index.save(path)?;
        let c = outcome.duplicate_census;
        if c.census_complete
            && c.coverage_complete
            && !c.census_invalid
            && !c.fence_after
            && outcome.transcript_ownership_complete
        {
            self.scope = Some(scope);
        }
        Ok(())
    }
    fn allowed(&self, scope: &str) -> bool {
        self.scope == Some(scope)
    }
}

#[test]
fn envelope_experiment_native_save_bootstrap_restart_matches_base_owners() {
    let (dir, parent, raw) = claude_account_family_fixture();
    let scratch = crate::test_scratch::ScratchDir::new("envelope-bootstrap");
    let path = scratch.join("index.json");
    let (mut api, mut trace) = reports(&parent, false);
    let mut optimized = fixture_index(&dir, &parent, &raw);
    let mut items = raw.clone();
    let receipt = apply_claude_reported_usage_with_index(
        &mut items,
        &api,
        &trace,
        &mut optimized,
        true,
        WINDOW,
    );
    let mut permit = ProcessPermit::default();
    assert!(!permit.allowed("source/destination/context"));
    permit
        .native_save(
            "source/destination/context",
            &receipt,
            &mut optimized,
            &path,
        )
        .unwrap();
    assert!(permit.allowed("source/destination/context"));
    assert!(!permit.allowed("different-context"));
    let mut base = optimized.clone();
    let key = local_index_key(&dir.join(format!("{parent}.jsonl")));
    let candidate = matching_candidate(&optimized, &key);
    assert_eq!(decision(&optimized, &candidate).0, CandidateDecision::Skip);

    // Exercise the earlier-page rearm boundary with real partial + terminal
    // owner folds. Only the unchanged, normal-Skip, negatively refuted target
    // source fingerprint may be retained by this test candidate. The entire
    // authoritative owner fold still executes; no possible owner is inserted.
    let frozen = optimized.claude_usage_family_witnesses[&parent].clone();
    let old_source = optimized.files[&key].source_file_fingerprint.clone();
    for index in [&mut base, &mut optimized] {
        let mut earlier = vec![raw[0].clone()];
        apply_claude_reported_usage_with_index(
            &mut earlier,
            &api,
            &trace,
            index,
            false,
            "2026-08-02T07:11:00Z",
        );
        let mut terminal = vec![raw[1].clone()];
        apply_claude_reported_usage_with_index(
            &mut terminal,
            &api,
            &trace,
            index,
            true,
            "2026-08-02T07:11:00Z",
        );
    }
    assert!(base.files[&key].source_file_fingerprint.is_empty());
    let prior = qualified_prior(&frozen, &raw[1], &api, &trace, true).unwrap();
    assert!(raw_hashes(&raw[1]).difference(&prior).next().is_none());
    assert!(permit.allowed("source/destination/context"));
    assert!(!optimized
        .claude_usage_authority_quarantine
        .contains_key(&parent));
    optimized
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint = old_source;
    assert_eq!(decision(&base, &candidate).0, CandidateDecision::Parse);
    assert_eq!(decision(&optimized, &candidate).0, CandidateDecision::Skip);
    assert_eq!(
        base.claude_duplicate_request_owners,
        optimized.claude_duplicate_request_owners
    );

    // Three real unchanged terminal folds using the candidate's normal Skip
    // state. This is boundary parity, not a completed two-phase cost benchmark.
    for _ in 0..3 {
        for index in [&mut base, &mut optimized] {
            apply_claude_reported_usage_with_index(
                &mut [],
                &api,
                &trace,
                index,
                true,
                "2026-08-02T07:12:00Z",
            );
        }
    }
    optimized.save(&path).unwrap();
    optimized = ScanIndex::load(&path).unwrap();
    permit = ProcessPermit::default(); // real disk reload carries no permit
    assert!(!permit.allowed("source/destination/context"));
    // A new legacy root appears only after restart. Both histories must use
    // the base native comparison before its first body, including copied prefix.
    let c = "c3333333-3333-4333-8333-333333333333";
    let c_path = dir.join(format!("{c}.jsonl"));
    // The existing legacy proof requires divergent suffixes on BOTH roots.
    // Copying all four parent requests leaves no parent-side divergence and
    // correctly does not qualify for exclusion. Fork after the first two.
    let prefix = fs::read_to_string(dir.join(format!("{parent}.jsonl")))
        .unwrap()
        .lines()
        .take(2)
        .collect::<Vec<_>>()
        .join("\n")
        .replace(&parent, c)
        + "\n";
    fs::write(&c_path, format!("{prefix}{{\"timestamp\":\"2026-08-02T07:00:07Z\",\"type\":\"assistant\",\"sessionId\":\"{c}\",\"requestId\":\"req_c\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n")).unwrap();
    let c_native = parse_claude_code_jsonl_file(&c_path, WINDOW, hex64('c'))
        .unwrap()
        .remove(0);
    api.evidence.insert(
        c.to_string(),
        vec![complete_api_row(c, "req_c", 7, 10, 10, 0)],
    );
    trace
        .evidence
        .insert(c.to_string(), vec![complete_trace_row(c, "req_c", "")]);
    for index in [&mut base, &mut optimized] {
        index.files.insert(
            local_index_key(&c_path),
            committed_entry(&hex64('c'), &c_native.snapshot_fingerprint),
        );
    }
    let mut base_items = raw.clone();
    base_items.push(c_native.clone());
    let mut restarted_items = raw.clone();
    restarted_items.push(c_native);
    let base_receipt = apply_claude_reported_usage_with_index(
        &mut base_items,
        &api,
        &trace,
        &mut base,
        true,
        "2026-08-02T07:13:00Z",
    );
    let restarted_receipt = apply_claude_reported_usage_with_index(
        &mut restarted_items,
        &api,
        &trace,
        &mut optimized,
        true,
        "2026-08-02T07:13:00Z",
    );
    assert_eq!(base_receipt, restarted_receipt);
    assert_eq!(
        restarted_items[2].request_count, 1,
        "native prefix comparison excludes all copied requests before C body"
    );
    assert_eq!(
        restarted_items[2].usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    assert_eq!(
        serde_json::to_vec(&base_items).unwrap(),
        serde_json::to_vec(&restarted_items).unwrap()
    );
    assert_eq!(
        base.claude_duplicate_request_owners,
        optimized.claude_duplicate_request_owners
    );
    // CAS failure must revoke a previously minted permit.
    let mut stale = optimized.clone();
    optimized.save(&path).unwrap();
    permit.scope = Some("source/destination/context");
    assert!(permit
        .native_save("source/destination/context", &receipt, &mut stale, &path)
        .is_err());
    assert!(!permit.allowed("source/destination/context"));
    writeln!(std::io::stderr().lock(), "envelope_experiment_bootstrap: candidate_rearm_suppressed=1 restart_owner_body_parity=true cas_failure_revokes=true full_two_phase_coverage=unproved").unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn envelope_experiment_selected_restore_rearm_survives_reload_without_age_proof() {
    let scratch = crate::test_scratch::ScratchDir::new("envelope-deferral");
    let path = scratch.join("index.json");
    let native_dir = scratch.join("native");
    fs::create_dir_all(&native_dir).unwrap();
    let a = local_index_key(&native_dir.join("a1111111-1111-4111-8111-111111111111.jsonl"));
    let b = local_index_key(&native_dir.join("b2222222-2222-4222-8222-222222222222.jsonl"));
    let c = local_index_key(&native_dir.join("c3333333-3333-4333-8333-333333333333.jsonl"));
    for key in [&a, &b, &c] {
        fs::write(key, "{}\n").unwrap();
    }
    let mut previous = ScanIndex {
        accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
        ..Default::default()
    };
    for (key, revision, body) in [(&a, hex64('a'), hex64('1')), (&b, hex64('b'), hex64('2'))] {
        index_file(&mut previous, key, &revision, &body, WINDOW);
        previous.accepted_snapshot_fingerprints.insert(body);
    }
    previous.save(&path).unwrap();
    let previous_b = serde_json::to_vec(&previous.files[&b]).unwrap();
    let mut scanned = previous.clone();
    index_file(&mut scanned, &b, &hex64('d'), &hex64('3'), WINDOW);
    index_file(&mut scanned, &c, &hex64('e'), &hex64('4'), WINDOW);
    let mut selected = scanned.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert!(!selected.files.contains_key(&c));
    assert_eq!(serde_json::to_vec(&selected.files[&b]).unwrap(), previous_b);
    // Candidate fallback AFTER selected-state restoration, never a fake hold.
    selected
        .files
        .get_mut(&a)
        .unwrap()
        .source_file_fingerprint
        .clear();
    // Use the real scanner's frozen durable candidate queue, not a parallel
    // scheduler model. A cleared fp alone has no special selection priority.
    let roots = [native_dir];
    let prepared = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &roots,
        selected,
        WINDOW,
        30,
        0,
        false,
        None,
        &[],
        false,
        false,
        false,
    );
    let mut selected = prepared.index;
    let queue = &mut selected.traversal.as_mut().unwrap().pending_candidates;
    let a_position = queue
        .iter()
        .position(|p| local_index_key(&p.path) == a)
        .unwrap();
    let a_pending = queue.remove(a_position).unwrap();
    // Place C first to characterize that traversal order is independent of
    // the target's rearm fingerprint; then apply the candidate queue priority.
    let c_position = queue
        .iter()
        .position(|p| local_index_key(&p.path) == c)
        .unwrap();
    let c_pending = queue.remove(c_position).unwrap();
    queue.push_front(c_pending);
    queue.push_back(a_pending.clone());
    let unprioritized = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &roots,
        selected.clone(),
        WINDOW,
        30,
        1,
        false,
        None,
        &[],
        false,
        false,
        false,
    );
    assert_eq!(
        local_index_key(&unprioritized.identified_candidates[0].path),
        c
    );
    let queue = &mut selected.traversal.as_mut().unwrap().pending_candidates;
    queue.retain(|p| local_index_key(&p.path) != a);
    queue.push_front(a_pending); // existing durable carrier, no extra age field
    selected.mark_bounded_sweep_unsettled();
    selected.save(&path).unwrap();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert!(reloaded.files[&a].source_file_fingerprint.is_empty());
    assert!(reloaded.bounded_sweep_had_unsettled_upload());
    assert!(!reloaded.files.contains_key(&c));
    assert!(!reloaded.confirmed_empty_files.contains(&c));
    assert_eq!(serde_json::to_vec(&reloaded.files[&b]).unwrap(), previous_b);
    assert_eq!(
        reloaded.accepted_snapshot_fingerprints,
        previous.accepted_snapshot_fingerprints
    );
    assert!(reloaded.quarantined_snapshot_fingerprints.is_empty());
    assert!(reloaded.claude_usage_authority_quarantine.is_empty());
    assert!(reloaded.claude_account_deferred_holds.is_empty());
    assert!(reloaded.claude_duplicate_request_owners.is_empty());
    let prioritized = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &roots,
        reloaded.clone(),
        WINDOW,
        30,
        1,
        false,
        None,
        &[],
        false,
        false,
        false,
    );
    assert_eq!(
        local_index_key(&prioritized.identified_candidates[0].path),
        a
    );
    let mut target = matching_candidate(&previous, &a);
    target.source_file_fingerprint = hex64('a');
    assert_eq!(
        decision(&reloaded, &target),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::Rearmed)
        )
    );
    // Different deferral ages (or a process stopped >15 min) have identical
    // persisted state. The window timestamps date a census, not a deferral.
    // This receipt proves explicit queue priority and retry eligibility, not wall time.
    writeln!(std::io::stderr().lock(), "envelope_experiment_deferral: selected_old_b=true new_c_uncommitted=true durable_target_rearm=true explicit_durable_queue_priority=true deferral_age=unknown wall_completion=unknown").unwrap();
}

// Phase 2 uses actual constructor priority and the real locked partial-save
// seam. Controls remain scoped/cfg(test); no shipping eligibility is added.
struct SelectionFixture {
    _scratch: crate::test_scratch::ScratchDir,
    roots: [PathBuf; 1],
    paths: [PathBuf; 4], // A, audit B, uncommitted C, A's subagent
    index_path: PathBuf,
    progress_path: PathBuf,
    previous: ScanIndex,
}
impl SelectionFixture {
    fn new() -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("envelope-selection-matrix");
        let root = scratch.join("native");
        fs::create_dir_all(&root).unwrap();
        let a = "a1111111-1111-4111-8111-111111111111";
        let sessions = [
            a,
            "b2222222-2222-4222-8222-222222222222",
            "c3333333-3333-4333-8333-333333333333",
            a,
        ];
        let paths = [
            root.join(format!("{a}.jsonl")),
            root.join(format!("{}.jsonl", sessions[1])),
            root.join(format!("{}.jsonl", sessions[2])),
            root.join(a).join("subagents/agent-comparison.jsonl"),
        ];
        let mut previous = ScanIndex {
            accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
            ..Default::default()
        };
        for (slot, path) in paths.iter().enumerate() {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let agent = if slot == 3 {
                "\"agentId\":\"comparison\",\"isSidechain\":true,"
            } else {
                ""
            };
            fs::write(path, format!("{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{}\",{agent}\"requestId\":\"req_matrix_{slot}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n", sessions[slot])).unwrap();
            if slot != 2 {
                let body = format!("{slot:064x}");
                index_file(
                    &mut previous,
                    &local_index_key(path),
                    &hex64('a'),
                    &body,
                    WINDOW,
                );
                previous.accepted_snapshot_fingerprints.insert(body);
            }
        }
        previous
            .files
            .get_mut(&local_index_key(&paths[1]))
            .unwrap()
            .set_unverified_deadline(1);
        let index_path = scratch.join("index.json");
        let progress_path = scratch.join("progress.json");
        previous.save(&index_path).unwrap();
        Self {
            _scratch: scratch,
            roots: [root],
            paths,
            index_path,
            progress_path,
            previous,
        }
    }
    fn prepare(&self, index: ScanIndex, limit: usize) -> OwnedSourceScan {
        OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            &self.roots,
            index,
            WINDOW,
            30,
            limit,
            false,
            None,
            &[],
            false,
            false,
            false,
        )
    }
    fn run(mut native: OwnedSourceScan) -> (ScanIndex, SourceScanResult) {
        for _ in 0..1024 {
            match native.step(None) {
                OwnedSourceScanStep::Pending(next) => native = next,
                OwnedSourceScanStep::Complete { index, scan } => return (index, scan),
            }
        }
        panic!("bounded fixture native scan did not complete");
    }
    fn checkpoint(&self, index: &ScanIndex, scan: &SourceScanResult) -> ScanIndex {
        crate::snapshot_sync::comparison_partial_checkpoint_for_test(
            index,
            &self.previous,
            &scan.snapshots,
            &self.index_path,
            &self.progress_path,
        )
        .unwrap()
    }
}

#[test]
fn envelope_experiment_target_priority_precedes_actual_audit_selection() {
    let fixture = SelectionFixture::new();
    let base = fixture.prepare(fixture.previous.clone(), 1);
    assert_eq!(base.identified_candidates[0].path, fixture.paths[1]);
    let scope = envelope_selection_experiment::Scope::controlled();
    scope.register("family", BTreeSet::from([fixture.paths[0].clone()]));
    let candidate = fixture.prepare(fixture.previous.clone(), 1);
    assert_eq!(candidate.identified_candidates.len(), 1);
    assert_eq!(candidate.identified_candidates[0].path, fixture.paths[0]);
    let (index, scan) = SelectionFixture::run(candidate);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(scan.snapshots.len(), 1);
    assert!(
        index.files[&local_index_key(&fixture.paths[1])]
            .audit_requires_full(sampled_scan::now_seconds()),
        "priority does not clear unrelated audit debt"
    );
    writeln!(std::io::stderr().lock(), "envelope_experiment_audit: base_selects_audit=true candidate_selects_target=true page_limit=1 audit_debt_preserved=true").unwrap();
}

#[test]
fn envelope_experiment_oversized_family_exits_immediately_without_cap_increase() {
    let fixture = SelectionFixture::new();
    let scope = envelope_selection_experiment::Scope::controlled();
    let paths = BTreeSet::from([fixture.paths[0].clone(), fixture.paths[3].clone()]);
    scope.register("family", paths.clone());
    let first = fixture.prepare(fixture.previous.clone(), 1);
    assert!(!scope.allowed("family"));
    assert_eq!(scope.counts().base_exits, 1);
    assert_eq!(first.identified_candidates.len(), 1);
    let (index, first_scan) = SelectionFixture::run(first);
    let second = fixture.prepare(index, 1);
    assert_eq!(second.identified_candidates.len(), 1);
    let (_, second_scan) = SelectionFixture::run(second);
    let members = first_scan
        .snapshots
        .iter()
        .chain(&second_scan.snapshots)
        .map(|item| item.source_session_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        members.len(),
        2,
        "native base spans pages under the unchanged file limit"
    );
    scope.register("family", paths);
    assert!(
        !scope.allowed("family"),
        "new registration/proof cannot renew the disabled process family"
    );
    assert_eq!(scope.counts().base_exits, 1);
    assert_eq!(scope.counts().successful_deferrals, 0);
    writeln!(std::io::stderr().lock(), "envelope_experiment_oversized: family_members=2 page_limit=1 base_exits=1 native_pages=2 no_renewal=true").unwrap();
}

#[test]
fn envelope_experiment_two_successful_deferrals_use_locked_shed_restore_then_disable() {
    let fixture = SelectionFixture::new();
    let scope = envelope_selection_experiment::Scope::controlled();
    let target = BTreeSet::from([fixture.paths[0].clone()]);
    scope.register("family", target.clone());
    scope.withhold(BTreeSet::from([
        local_index_key(&fixture.paths[1]),
        local_index_key(&fixture.paths[2]),
    ]));
    let mut previous = fixture.previous.clone();
    for attempt in 1..=2 {
        let native = fixture.prepare(previous.clone(), 1);
        assert_eq!(native.identified_candidates[0].path, fixture.paths[0]);
        let (mut index, scan) = SelectionFixture::run(native);
        assert_eq!(scan.scanned_file_count, 1);
        scope.defer_after_native("family", &scan);
        // Unaccepted current B/C replacements: no fake ACK/refusal/hold.
        index_file(
            &mut index,
            &local_index_key(&fixture.paths[1]),
            &hex64('d'),
            &hex64('3'),
            WINDOW,
        );
        index_file(
            &mut index,
            &local_index_key(&fixture.paths[2]),
            &hex64('e'),
            &hex64('4'),
            WINDOW,
        );
        let saved = crate::snapshot_sync::comparison_partial_checkpoint_for_test(
            &index,
            &previous,
            &scan.snapshots,
            &fixture.index_path,
            &fixture.progress_path,
        )
        .unwrap();
        let loaded = ScanIndex::load(&fixture.index_path).unwrap();
        let a = local_index_key(&fixture.paths[0]);
        let b = local_index_key(&fixture.paths[1]);
        let c = local_index_key(&fixture.paths[2]);
        assert!(saved.files[&a].source_file_fingerprint.is_empty());
        assert_eq!(
            serde_json::to_vec(&loaded.files[&b]).unwrap(),
            serde_json::to_vec(&previous.files[&b]).unwrap()
        );
        assert!(!loaded.files.contains_key(&c));
        assert!(!loaded.confirmed_empty_files.contains(&c));
        assert_eq!(
            loaded.accepted_snapshot_fingerprints,
            fixture.previous.accepted_snapshot_fingerprints
        );
        assert_eq!(scope.counts().successful_deferrals, attempt);
        previous = loaded;
    }
    assert!(!scope.allowed("family"));
    scope.register("family", target);
    assert!(
        !scope.allowed("family"),
        "cannot reset the attempt bound with new proof/census registration"
    );
    assert_eq!(scope.counts().base_exits, 1);
    drop(scope);
    let restarted = envelope_selection_experiment::Scope::restart();
    assert!(!restarted.allowed("family"));
    let first_after_restart = fixture.prepare(previous, 1);
    assert_eq!(
        first_after_restart.identified_candidates[0].path,
        fixture.paths[0]
    );
    let (_, scan) = SelectionFixture::run(first_after_restart);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(restarted.counts().unknown_age, 1);
    writeln!(std::io::stderr().lock(), "envelope_experiment_attempts: successful_deferrals=2 base_exits=1 no_renewal=true locked_shed_restore=true restart_native_priority=true age_unknown_count=1").unwrap();
}

#[test]
fn envelope_experiment_failed_open_is_unavailable_not_success_and_keeps_durable_rearm() {
    let fixture = SelectionFixture::new();
    let scope = envelope_selection_experiment::Scope::controlled();
    scope.register("family", BTreeSet::from([fixture.paths[0].clone()]));
    let native = fixture.prepare(fixture.previous.clone(), 1);
    assert_eq!(native.identified_candidates[0].path, fixture.paths[0]);
    let bytes = fs::read(&fixture.paths[0]).unwrap();
    fs::remove_file(&fixture.paths[0]).unwrap(); // after frozen selection, before safe open
    let (index, scan) = SelectionFixture::run(native);
    assert!(scan.disappeared_file_count + scan.unreadable_path_count > 0);
    scope.defer_after_native("family", &scan);
    assert_eq!(scope.counts().unavailable, 1);
    assert_eq!(scope.counts().successful_deferrals, 0);
    assert!(
        !scope.allowed("family"),
        "fallback revokes reuse, never converts failed read to success"
    );
    let saved = fixture.checkpoint(&index, &scan);
    assert!(saved.files[&local_index_key(&fixture.paths[0])]
        .source_file_fingerprint
        .is_empty());
    assert_eq!(
        saved.accepted_snapshot_fingerprints,
        fixture.previous.accepted_snapshot_fingerprints
    );
    fs::write(&fixture.paths[0], bytes).unwrap();
    drop(scope);
    let restarted = envelope_selection_experiment::Scope::restart();
    let reloaded = ScanIndex::load(&fixture.index_path).unwrap();
    let retry = fixture.prepare(reloaded, 1);
    assert_eq!(retry.identified_candidates[0].path, fixture.paths[0]);
    let (_, scan) = SelectionFixture::run(retry);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(restarted.counts().unknown_age, 1);
    writeln!(std::io::stderr().lock(), "envelope_experiment_unavailable: reason=comparison_deferred_unavailable failed_open=1 successful_deferrals=0 durable_rearm=true restart_retry=true age_unknown_count=1").unwrap();
}

fn comparison_owner_epoch(
    index: &mut ScanIndex,
    root: &SnapshotItem,
    child: &SnapshotItem,
    api: &Api,
    trace: &Trace,
) {
    apply_claude_reported_usage_with_index(
        &mut [root.clone()],
        api,
        trace,
        index,
        false,
        "2026-08-02T07:11:00Z",
    );
    apply_claude_reported_usage_with_index(
        &mut [child.clone()],
        api,
        trace,
        index,
        true,
        "2026-08-02T07:11:00Z",
    );
}

#[test]
fn envelope_experiment_disabled_family_bypasses_actual_rearm_suppression_gate() {
    let (dir, parent, _) = claude_account_family_fixture();
    let roots = [dir.clone()];
    let initial = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &roots,
        ScanIndex::default(),
        WINDOW,
        30,
        8,
        false,
        None,
        &[],
        false,
        false,
        false,
    );
    let (mut baseline, mut scan) = SelectionFixture::run(initial);
    assert!(scan.census_complete);
    let raw_root = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == parent)
        .unwrap()
        .clone();
    let raw_child = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id != parent)
        .unwrap()
        .clone();
    let (api, trace) = reports(&parent, false);
    apply_claude_reported_usage_with_index(
        &mut scan.snapshots,
        &api,
        &trace,
        &mut baseline,
        true,
        WINDOW,
    );
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut baseline);
    let key = local_index_key(&dir.join(format!("{parent}.jsonl")));
    let candidate = matching_candidate(&baseline, &key);
    assert_eq!(decision(&baseline, &candidate).0, CandidateDecision::Skip);
    let frozen = baseline.claude_usage_family_witnesses[&parent].clone();
    let prior = qualified_prior(&frozen, &raw_child, &api, &trace, true).unwrap();
    assert!(raw_hashes(&raw_child).difference(&prior).next().is_none());
    assert!(!baseline
        .claude_usage_authority_quarantine
        .contains_key(&parent));
    let scope = envelope_selection_experiment::Scope::controlled();
    let targets = BTreeSet::from([PathBuf::from(&key)]);
    scope.register(&parent, targets.clone());
    scope.certify_negative(key.clone());
    let mut enabled = baseline.clone();
    comparison_owner_epoch(&mut enabled, &raw_root, &raw_child, &api, &trace);
    assert_eq!(decision(&enabled, &candidate).0, CandidateDecision::Skip);
    assert_eq!(scope.counts().rearm_suppressed, 1);

    // Real successful native target reads, not an invented scan result, earn
    // the two controlled eligible attempts. Other cases cover atomic partial
    // saves; this case specifically connects disable to the actual fold gate.
    let mut native_index = baseline.clone();
    native_index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    for _ in 0..2 {
        let native = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            &roots,
            native_index,
            WINDOW,
            30,
            1,
            false,
            None,
            &[],
            false,
            false,
            false,
        );
        let (mut index, scan) = SelectionFixture::run(native);
        assert_eq!(scan.scanned_file_count, 1);
        scope.defer_after_native(&parent, &scan);
        envelope_selection_experiment::after_selected_restore(&mut index, &baseline);
        native_index = index;
    }
    assert_eq!(scope.counts().successful_deferrals, 2);
    assert!(!scope.allowed(&parent));
    scope.register(&parent, targets);
    scope.certify_negative(key.clone()); // even a renewed negative cannot reset disable
    let mut disabled = baseline.clone();
    comparison_owner_epoch(&mut disabled, &raw_root, &raw_child, &api, &trace);
    assert_eq!(
        decision(&disabled, &candidate),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::Rearmed)
        )
    );
    assert_eq!(scope.counts().rearm_base_bypasses, 1);
    assert_eq!(scope.counts().rearm_suppressed, 1);
    assert_eq!(
        enabled.claude_duplicate_request_owners,
        disabled.claude_duplicate_request_owners
    );
    writeln!(std::io::stderr().lock(), "envelope_experiment_gate: actual_rearm_suppressed=1 successful_deferrals=2 actual_base_bypasses=1 register_and_negative_cannot_renew=true").unwrap();
    fs::remove_dir_all(dir).unwrap();
}

// Carried from #587; the tests below exercise the new moving preparation seam,
// not the synthetic permit/rearm controls above. No reuse is activated.
struct NativePreparationFixture {
    native_conjunction: bool,
    dir: PathBuf,
    parent: String,
    index: ScanIndex,
    api: Api,
    trace: Trace,
}
impl NativePreparationFixture {
    fn new() -> Self {
        let (dir, parent, _) = claude_account_family_fixture();
        let native = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&dir),
            ScanIndex::default(),
            WINDOW,
            30,
            8,
            false,
            None,
            &[],
            false,
            false,
            false,
        );
        let (mut index, mut scan) = SelectionFixture::run(native);
        assert!(scan.census_complete);
        let (api, trace) = reports(&parent, false);
        let disposition = apply_claude_reported_usage_with_index(
            &mut scan.snapshots,
            &api,
            &trace,
            &mut index,
            true,
            WINDOW,
        );
        let native_conjunction = claude_native_comparison::actual_native_conjunction(&disposition);
        assert!(native_conjunction);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
        index.upload_context_fingerprint = Some("native-preparation-test".into());
        index.active_upload_context_fingerprint = index.upload_context_fingerprint.clone();
        assert!(index.claude_usage_family_witnesses.contains_key(&parent));
        Self {
            native_conjunction,
            dir,
            parent,
            index,
            api,
            trace,
        }
    }
    fn paused(&self) -> OwnedSourceScan {
        let mut state = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.dir),
            self.index.clone(),
            WINDOW,
            30,
            8,
            false,
            None,
            &[],
            false,
            false,
            false,
        );
        state.enable_native_comparison();
        for _ in 0..1024 {
            if state.native_comparison_ready() {
                return state;
            }
            match state.step(None) {
                OwnedSourceScanStep::Pending(next) => state = next,
                OwnedSourceScanStep::Complete { .. } => {
                    panic!("finalized before native preparation")
                }
            }
        }
        panic!("native preparation did not reach bounded pause");
    }
}
impl Drop for NativePreparationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn native_comparison_actual_skip_freezes_retained_proof_before_body_fold() {
    let fixture = NativePreparationFixture::new();
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 0);
    let before = serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap();
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 2);
    assert_eq!(
        serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap(),
        before
    );
    assert!(state.snapshots.is_empty());
    let (_, scan) = SelectionFixture::run(state);
    assert_eq!(scan.scanned_file_count, 0);
    writeln!(std::io::stderr().lock(), "native_comparison_checkpoint: actual_skip_certificates=2 retained_proof_unchanged=true body_mutations=0 reuse_activated=false").unwrap();
}

#[test]
fn native_comparison_seeded_index_is_not_an_actual_skip_certificate() {
    let fixture = NativePreparationFixture::new();
    let mut phase = claude_native_comparison::NativePhase::default();
    assert!(phase.pause_before_finalization());
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = phase.qualify(
        &fixture.index,
        &[],
        WINDOW,
        claude_native_comparison::PairedRows {
            api: &fixture.api.evidence,
            trace: &fixture.trace.evidence,
            healthy_roots: &healthy,
        },
    );
    assert_eq!(qualification.certified_member_count(), 0);
}

#[test]
fn native_comparison_current_nonreported_member_withdraws_whole_family() {
    let fixture = NativePreparationFixture::new();
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    writeln!(file, "{{\"timestamp\":\"2026-08-02T07:00:08Z\",\"type\":\"assistant\",\"sessionId\":\"{}\",\"requestId\":\"new_native_request\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}", fixture.parent).unwrap();
    drop(file);
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 1);
    assert!(!state.snapshots.is_empty());
    let native_before = serde_json::to_vec(&state.snapshots).unwrap();
    let proof_before = serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap();
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 0);
    assert_eq!(serde_json::to_vec(&state.snapshots).unwrap(), native_before);
    assert_eq!(
        serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap(),
        proof_before
    );
    let (mut index, mut scan) = SelectionFixture::run(state);
    let disposition = apply_claude_reported_usage_with_index(
        &mut scan.snapshots,
        &fixture.api,
        &fixture.trace,
        &mut index,
        true,
        WINDOW,
    );
    assert!(disposition
        .quarantined_source_session_ids
        .contains(&fixture.parent));
    writeln!(std::io::stderr().lock(), "native_comparison_checkpoint: nonreported_native_member=true qualified_family_members=0 authoritative_demotion_agrees=true preflight_body_mutations=0").unwrap();
}

fn write_native_preparation_pair(support: &Path, root: &str, api: &Api, trace: &Trace) {
    let name = format!("{:x}.jsonl", Sha256::digest(root.as_bytes()));
    for (folder, rows) in [
        (
            "claude-code-effort",
            api.evidence[root]
                .iter()
                .map(|row| serde_json::to_string(row).unwrap())
                .collect::<Vec<_>>(),
        ),
        (
            "claude-code-trace-ownership",
            trace.evidence[root]
                .iter()
                .map(|row| serde_json::to_string(row).unwrap())
                .collect::<Vec<_>>(),
        ),
    ] {
        let path = support.join("local-otel").join(folder).join(&name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, rows.join("\n") + "\n").unwrap();
        fs::rename(replacement, path).unwrap();
    }
}

fn native_preparation_pair_roundtrip(replace: bool) {
    let fixture = NativePreparationFixture::new();
    let support = crate::test_scratch::ScratchDir::new("native-preparation-pairs");
    write_native_preparation_pair(&support, &fixture.parent, &fixture.api, &fixture.trace);
    crate::claude_local_otel::reset_evidence_read_counts_for_test();
    let (api, trace, healthy, permissive_rows) =
        crate::snapshot_sync::prepared_claude_pair_for_test(
            &support,
            &[],
            &fixture.index,
            &fixture.parent,
            || {
                assert_eq!(
                    crate::claude_local_otel::evidence_read_counts_for_test(),
                    (1, 1)
                );
                if replace {
                    let (api, trace) = reports(&fixture.parent, true);
                    write_native_preparation_pair(&support, &fixture.parent, &api, &trace);
                }
            },
        );
    assert!(healthy);
    assert!(api.health.is_complete() && trace.is_complete());
    let rows = if replace { 6 } else { 5 };
    assert_eq!(
        permissive_rows, rows,
        "effort fold must also receive current rows after the pause"
    );
    assert_eq!(api.evidence[&fixture.parent].len(), rows);
    assert_eq!(trace.evidence[&fixture.parent].len(), rows);
    let reads = if replace { 2 } else { 1 };
    assert_eq!(
        crate::claude_local_otel::evidence_read_counts_for_test(),
        (reads, reads)
    );
    writeln!(std::io::stderr().lock(), "native_comparison_checkpoint: paired_rows_replace={replace} api_opens={reads} trace_opens={reads} final_rows={rows} stale_rows_consumed=false").unwrap();
}

#[test]
fn native_comparison_paired_rows_move_once_without_reloading_unchanged_files() {
    native_preparation_pair_roundtrip(false);
}

#[test]
fn native_comparison_paired_rows_replaced_after_preflight_use_fresh_strict_load() {
    native_preparation_pair_roundtrip(true);
}

#[test]
fn native_comparison_lifecycle_requires_native_save_and_revokes_after_drop_context_or_restart() {
    let mut fixture = NativePreparationFixture::new();
    let scratch = crate::test_scratch::ScratchDir::new("native-comparison-lifecycle");
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut first = owner.begin();
    first.bind("synthetic-source-destination-context".into());
    assert!(!first.allowed());
    fixture.index.save(&scratch.join("index.json")).unwrap();
    first.note_native_save(fixture.native_conjunction);
    first.finish(true);
    let mut next = owner.begin();
    next.bind("synthetic-source-destination-context".into());
    assert!(next.allowed());
    next.finish(true);
    let restarted = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let reloaded = ScanIndex::load(&scratch.join("index.json")).unwrap();
    assert_eq!(reloaded.generation, fixture.index.generation);
    let mut restart_lease = restarted.begin();
    restart_lease.bind("synthetic-source-destination-context".into());
    assert!(
        !restart_lease.allowed(),
        "retained index is not process bootstrap"
    );
    drop(restart_lease);
    let mut changed = owner.begin();
    changed.bind("different-source-destination-context".into());
    assert!(!changed.allowed());
    drop(changed);
    let mut original = owner.begin();
    original.bind("synthetic-source-destination-context".into());
    assert!(
        !original.allowed(),
        "context rollback cannot revive a process grant"
    );
    writeln!(std::io::stderr().lock(), "native_comparison_lifecycle: actual_native_conjunction=true actual_index_save=true next_cycle_allowed=true retained_index_restart_base=true context_change_and_drop_revoke=true").unwrap();
}

#[test]
fn native_comparison_lifecycle_failed_cas_never_mints_a_grant() {
    let mut fixture = NativePreparationFixture::new();
    let scratch = crate::test_scratch::ScratchDir::new("native-comparison-cas");
    let path = scratch.join("index.json");
    let mut stale = fixture.index.clone();
    fixture.index.save(&path).unwrap();
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut failed = owner.begin();
    failed.bind("synthetic-source-destination-context".into());
    assert!(!failed.allowed());
    let result = stale.save(&path);
    assert!(result.is_err());
    // Same ordering as finish: save failure exits before note_native_save.
    drop(failed);
    let mut next = owner.begin();
    next.bind("synthetic-source-destination-context".into());
    assert!(!next.allowed());
    writeln!(
        std::io::stderr().lock(),
        "native_comparison_lifecycle: actual_failed_index_cas=true process_grant=false"
    )
    .unwrap();
}

fn pause_native_comparison(mut state: OwnedSourceScan) -> OwnedSourceScan {
    for _ in 0..1024 {
        if state.native_comparison_ready() {
            return state;
        }
        match state.step(None) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete { .. } => {
                panic!("target phase finalized before comparison")
            }
        }
    }
    panic!("target phase did not reach bounded pause");
}

#[test]
fn native_comparison_q5_keeps_old_proof_and_checks_revision_and_occurrences() {
    let mut fixture = NativePreparationFixture::new();
    let key = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
    fixture
        .index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 1);
    let native = state
        .snapshots
        .iter()
        .find(|item| item.source_session_id == fixture.parent)
        .unwrap()
        .clone();
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 1);
    assert!(qualification.new_native_hashes(&native).unwrap().is_empty());
    // Changing the live index proof after qualification cannot turn P_new into
    // the old prior. This immutable plan never consults the live proof map.
    state.index.claude_usage_family_witnesses.clear();
    assert!(qualification.new_native_hashes(&native).unwrap().is_empty());
    let mut changed = native.clone();
    changed.source_file_fingerprint = Some(hex64('d'));
    assert_eq!(
        qualification.new_native_hashes(&changed).unwrap(),
        raw_hashes(&changed)
    );
    changed = native.clone();
    changed
        .claude_usage_occurrences
        .values_mut()
        .next()
        .unwrap()
        .usage
        .input_tokens += 1;
    assert_eq!(
        qualification.new_native_hashes(&changed).unwrap(),
        raw_hashes(&changed)
    );
    changed = native;
    changed
        .claude_usage_request_ids
        .insert("novel-after-freeze".into());
    changed.request_count += 1;
    assert_eq!(
        qualification.new_native_hashes(&changed).unwrap(),
        raw_hashes(&changed)
    );
    writeln!(std::io::stderr().lock(), "native_comparison_q5: frozen_old_p=true live_proof_replacement_ignored=true changed_revision_or_occurrence_or_request_set_uses_all=true").unwrap();
}

fn native_comparison_positive_hit_fixture() -> (
    NativePreparationFixture,
    OwnedSourceScan,
    claude_native_comparison::Qualification,
) {
    let fixture = NativePreparationFixture::new();
    let c = "c3333333-3333-4333-8333-333333333333";
    fs::write(fixture.dir.join(format!("{c}.jsonl")), format!("{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{c}\",\"requestId\":\"req_1\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n")).unwrap();
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 1);
    assert_eq!(state.snapshots.len(), 1);
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 2);
    assert_eq!(
        qualification.possible_targets(&state.snapshots[0]).unwrap(),
        BTreeSet::from([fixture.parent.clone()])
    );
    (fixture, state, qualification)
}

#[test]
fn native_comparison_positive_hit_reads_targets_in_same_owner_before_body_fold() {
    let (_fixture, mut state, mut qualification) = native_comparison_positive_hit_fixture();
    let scope_before = state.native_comparison_context().unwrap().to_owned();
    let requested_layout_bytes =
        crate::heap_layout_bound::completed_bound(&qualification, usize::MAX)
            .expect("frozen plan has an exhaustively accounted owned graph");
    assert!(requested_layout_bytes > 0);
    let limit = state.file_limit;
    let selection = state.acquire_native_comparison_targets(&mut qualification);
    assert_eq!(selection.matched_roots, 1);
    assert_eq!(selection.queued, 2);
    assert!(selection.unresolved_sources.is_empty());
    assert_eq!(
        qualification.certified_member_count(),
        0,
        "positive hit withdraws S"
    );
    assert_eq!(
        state.scanned_file_count, 1,
        "enqueue is not a successful read"
    );
    let mut state = pause_native_comparison(state);
    assert_eq!(state.scanned_file_count, 3);
    assert_eq!(state.snapshots.len(), 3);
    assert_eq!(state.pending_finalization.len(), 3);
    assert!(state
        .pending_finalization
        .iter()
        .all(|entry| entry.parse_complete));
    assert_eq!(
        state.native_comparison_context(),
        Some(scope_before.as_str())
    );
    assert_eq!(state.file_limit, limit);
    assert!(state.scanned_file_count <= limit);
    assert!(state
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    let again = state.acquire_native_comparison_targets(&mut qualification);
    assert_eq!(
        again.queued, 0,
        "withdrawn family cannot target twice in a pass"
    );
    state.resume_native_comparison_base();
    let (_, scan) = SelectionFixture::run(state);
    assert_eq!(scan.scanned_file_count, 3);
    writeln!(std::io::stderr().lock(), "native_comparison_target: initial_native=1 matched_roots=1 queued=2 actual_target_reads=2 same_scanner_context=true existing_file_budget=true before_body_fold=true repeated_targets=0 requested_layout_bytes={requested_layout_bytes} rss_measured=false").unwrap();
}

#[test]
fn native_comparison_insufficient_remaining_budget_withdraws_and_reports_unresolved() {
    let (_fixture, state, mut qualification) = native_comparison_positive_hit_fixture();
    let before = state.scanned_file_count;
    let (candidates, selection) = qualification.take_target_candidates(&state.snapshots, 1);
    assert!(candidates.is_empty());
    assert_eq!(selection.matched_roots, 1);
    assert_eq!(selection.queued, 0);
    assert_eq!(
        selection.unresolved_sources,
        BTreeSet::from(["c3333333-3333-4333-8333-333333333333".to_owned()])
    );
    assert_eq!(qualification.certified_member_count(), 0);
    assert_eq!(state.scanned_file_count, before);
}

#[test]
fn native_comparison_replaced_target_keeps_safe_open_failure_visible() {
    let (fixture, mut state, mut qualification) = native_comparison_positive_hit_fixture();
    let selection = state.acquire_native_comparison_targets(&mut qualification);
    assert_eq!(selection.queued, 2);
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    let replacement = fixture.dir.join("replacement.tmp");
    fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
    fs::rename(&replacement, &path).unwrap();
    let mut state = pause_native_comparison(state);
    assert!(
        state.census.disappeared_file_count + state.census.unreadable_path_count > 0,
        "the existing safe open must reject a replaced frozen object"
    );
    assert!(
        state.scanned_file_count < 3,
        "failed target is not a successful native read"
    );
    assert_eq!(qualification.certified_member_count(), 0);
    state.resume_native_comparison_base();
    let (_, scan) = SelectionFixture::run(state);
    assert!(!scan.census_complete);
}
