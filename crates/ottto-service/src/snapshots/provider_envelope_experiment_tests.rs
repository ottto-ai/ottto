// Nonshipping boundary experiment. This module is compiled only in tests.
// Uses the real native parser, usage/owner fold, candidate decision, selected
// checkpoint and locked save/load. It is NOT the complete two-phase scanner.
use super::*;

/// Physical positive preparation needs the validated container layout.
/// Unsupported runs retain the separate BASE/refusal checks, never pretend
/// that zero certificates exercised a positive path.
fn native_positive_layout_for_test(name: &str) -> bool {
    let supported = crate::heap_layout_bound::layout_supported();
    if !supported {
        writeln!(std::io::stderr().lock(), "native_comparison_layout: test={name} supported_positive=UNEXECUTED layout_supported=false no_guard_override=true").unwrap();
    }
    supported
}

type Api = crate::claude_local_otel::ClaudeLocalOtelLoadReport;
type Trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport;

#[test]
fn native_comparison_target_body_retention_pays_exact_peak_before_buffer_growth() {
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("UNEXECUTED target body retention: unsupported layout");
        return;
    }
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    for (short, unknown) in [(false, false), (true, false), (false, true)] {
        let mut fixture = NativePreparationFixture::new();
        // An actual controlled re-arm; the fixture's initial state would
        // otherwise produce only ordinary unchanged Skips and no body.
        let key = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
        fixture
            .index
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let state = fixture.paused_with_limit(1);
        assert_eq!(state.scanned_file_count, 1);
        assert_eq!(state.snapshots.len(), 1);
        let parsed = ParsedJsonlFile {
            snapshots: state.snapshots,
            report: JsonlReadReport::default(),
            recognized_usage_drop_count: 0,
            cause: ownership::PARSER,
            ownership_incomplete_file_count: 0,
            zero_snapshot_usage_evidence: false,
            dropped_usage_record_count: 0,
            claude_compaction_unlinked_parent_count: 0,
            terminal_line_loss_count: 0,
            state_only_blocked_session_ids: BTreeSet::new(),
            codex_parent_session_ref: None,
            codex_parent_ledger_identity_used: None,
            codex_parent_resolution_pending: false,
            codex_parent_ownership_ledger: None,
            codex_parent_unresolvable: None,
            codex_parent_ledger_unusable: None,
            codex_parent_ledger_consulted: false,
            codex_parent_prefix_decided: None,
            codex_parent_proof_used: None,
            codex_parent_proof_refusal: None,
        };
        let mut payload = Counter::new(usize::MAX);
        for snapshot in &parsed.snapshots {
            snapshot.completed_heap_bound(&mut payload).unwrap();
        }
        let expected_extra = payload.bytes + std::mem::size_of::<SnapshotItem>();
        let mut phase = claude_native_comparison::NativePhase::default();
        let old = phase.owned_capture_bytes().unwrap();
        let recovery = 256;
        let mut paid = Some(
            crate::source_rotation::PaidReservation::from_remainder(
                Some(old + expected_extra + recovery - usize::from(short)),
                old,
                old,
            )
            .unwrap(),
        );
        assert!(paid.as_mut().unwrap().reserve_recovery(recovery));
        if unknown {
            paid.as_mut().unwrap().at_turn(None);
        }
        let expected_admission = !short && !unknown;
        let mut retained = Vec::new();
        // Synchronous on this thread (no spawn, channel or pool in the call
        // chain): thread-local accounting counts the same allocation events
        // and excludes unrelated tests' allocations in parallel hosted runs.
        let (admitted, allocations) = crate::retry_allocation_probe::measure(|| {
            phase.retain_target_output(&parsed, &mut retained, &mut paid)
        });
        assert_eq!(admitted.is_ok(), expected_admission);
        assert!(paid.as_ref().unwrap().permits_recovery_peak(old + recovery));
        if !expected_admission {
            assert_eq!(retained.capacity(), 0);
            assert_eq!(
                allocations.allocations, 0,
                "refusal before optional destination growth"
            );
            assert_eq!(paid.as_ref().unwrap().allocated(), old);
        } else {
            assert_eq!(retained.capacity(), 1);
            assert_eq!(paid.as_ref().unwrap().allocated(), old + expected_extra);
            assert_eq!(phase.owned_capture_bytes().unwrap(), old + expected_extra);
            phase.disable();
            assert_eq!(
                phase.owned_capture_bytes().unwrap(),
                old + expected_extra,
                "revocation cannot forget retained target storage"
            );
            assert_eq!(
                allocations.requested_peak_with_overlap,
                std::mem::size_of::<SnapshotItem>()
            );
        }
        eprintln!("native target retention: one_byte_short={short} unknown_remainder={unknown} admitted={} planned_extra={expected_extra} destination_allocation={} protected_recovery=true component_only=true full_finish_metadata_unqualified=true", admitted.is_ok(), allocations.requested_peak_with_overlap);
    }
}

#[test]
fn native_comparison_borrowed_membership_matches_complete_physical_universe() {
    let mut index = ScanIndex::default();
    for ordinal in 0..2043 {
        let root = format!("root-{ordinal:04}");
        for path in [
            format!("/project/{root}.jsonl"),
            format!("/project/{root}/subagents/agent-a.jsonl"),
        ] {
            index.files.insert(path, manifest_index_entry(Some("body")));
        }
    }
    for path in [
        "/other/root-0001/subagents/agent-a.jsonl", // duplicate physical member
        "/other/root-0002/subagents/agent-unexpected.jsonl",
        "/other/missing-root/subagents/agent-a.jsonl",
        "/other/root-0003/subagents/workflows/run/journal.jsonl", // excluded
    ] {
        index
            .files
            .insert(path.into(), manifest_index_entry(Some("body")));
    }
    let canonical = complete_claude_usage_family_members(&index);
    // This synchronous operation spawns no work. Count this thread's actual
    // allocation, not unrelated tests running concurrently on the hosted job.
    let ((view, selected), allocations) = crate::retry_allocation_probe::measure(|| {
        (
            claude_native_comparison::MembershipView::capture(&index, |_| true).unwrap(),
            claude_native_comparison::MembershipView::selected_count(&index, |_| true).unwrap(),
        )
    });
    assert_eq!(allocations.allocations, 1);
    assert_eq!(
        allocations.requested_peak_with_overlap,
        selected * std::mem::size_of::<ClaudeIndexPathMemberRef<'_>>()
    );
    for root in (0..2043)
        .map(|n| format!("root-{n:04}"))
        .chain(std::iter::once("missing-root".into()))
    {
        let expected = canonical.get(&root);
        let members = expected
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([root.clone()]));
        let mut witness = ClaudeUsageFamilyWitness {
            evidence_fingerprint: String::new(),
            member_request_id_fingerprints: members
                .into_iter()
                .map(|m| (m, String::new()))
                .collect(),
            member_occurrence_fingerprints: BTreeMap::new(),
            assigned_request_id_fingerprints: BTreeMap::new(),
            legacy_excluded_request_id_hashes: BTreeMap::new(),
            legacy_exclusion_evidence_fingerprint: None,
            legacy_owner_roots: BTreeSet::new(),
        };
        assert_eq!(view.matches(&root, &witness), expected.is_some(), "{root}");
        if expected.is_some() {
            witness
                .member_request_id_fingerprints
                .insert(format!("{root}_absent"), String::new());
            assert!(
                !view.matches(&root, &witness),
                "missing indexed member: {root}"
            );
        }
    }
    eprintln!("native membership borrowed view: roots=2043 selected_paths={selected} requested_peak={} full_canonical_parity=true duplicate_missing_extra_paths_checked=true not_RSS=true", allocations.requested_peak_with_overlap);
}

#[test]
fn native_comparison_borrowed_index_identity_matches_owned_path_oracle_without_allocating() {
    fn reference(path: &Path) -> Option<(String, String)> {
        if path.extension().and_then(|v| v.to_str()) != Some("jsonl")
            || claude_transcript_excluded_from_snapshots(path)
        {
            return None;
        }
        if let Some(identity) = claude_subagent_identity(path) {
            return Some((
                identity.root_session_id.clone(),
                identity.source_session_id(),
            ));
        }
        let stem = path.file_stem()?.to_str().filter(|v| !v.is_empty())?;
        Some((stem.to_owned(), stem.to_owned()))
    }
    let paths = [
        "ordinary.jsonl",
        "/project/root.jsonl",
        "/project/root/subagents/agent-a.jsonl",
        "/project/root/subagents/workflows/wf-a/agent-a.jsonl",
        "/project/root/subagents/workflows/wf-a/nested/agent-b.jsonl",
        "/project/root/subagents/workflows/wf-a/journal.jsonl",
        "/project/root/subagents/nested/subagents/agent-c.jsonl",
        "subagents/agent-a.jsonl",
        "/subagents/agent-a.jsonl",
        "/project/journal.jsonl",
        "/project/root/subagents/../agent-a.jsonl",
        "/project/root/subagents/agent-a.meta.json",
        "/unicode-Ω/根/subagents/agent-一.jsonl",
    ];
    for path in paths {
        assert_eq!(
            claude_index_path_member_ref(Path::new(path)).map(|id| id.into_owned()),
            reference(Path::new(path)),
            "{path}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/project/root/subagents/\xff/agent-a.jsonl".to_vec(),
        ));
        assert_eq!(
            claude_index_path_member_ref(&path).map(|id| id.into_owned()),
            reference(&path)
        );
    }
    let (_, allocation) = crate::retry_allocation_probe::measure(|| {
        for path in paths {
            std::hint::black_box(claude_index_path_member_ref(Path::new(path)));
        }
    });
    assert_eq!(
        allocation.allocations, 0,
        "planning must not allocate a component vector or identity"
    );
}

#[test]
fn native_comparison_paid_import_reserves_before_membership_and_moves_only_once() {
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("UNEXECUTED paid native window import: unsupported layout");
        return;
    }
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    for one_byte_short in [false, true] {
        let fixture = NativePreparationFixture::new();
        let NativeWindowPage {
            index,
            scan,
            window,
            ..
        } = native_window_page(&fixture);
        let mut phase = claude_native_comparison::NativePhase::default();
        let extra = phase.window_import_extra_for_test(&window, &index).unwrap();
        let mut old = Counter::new(usize::MAX);
        window.heap_bound(&mut old).unwrap();
        let external = 137;
        let recovery = 256;
        let occupied = phase.owned_capture_bytes().unwrap() + old.bytes + external;
        let limit = occupied + extra + recovery - usize::from(one_byte_short);
        let mut paid = Some(
            crate::source_rotation::PaidReservation::from_remainder(
                Some(limit),
                occupied,
                occupied,
            )
            .unwrap(),
        );
        assert!(paid.as_mut().unwrap().reserve_recovery(recovery));
        let unchanged = serde_json::to_vec(&index).unwrap();
        // Synchronous on this thread (no spawn, channel or pool in the call
        // chain). The import drops the pre-existing window, so keep
        // born-in-scope accounting (that free cannot hide a later peak) but
        // charge only this thread, excluding parallel tests' allocations.
        let (imported, allocations) = crate::retry_allocation_probe::measure_caller_thread(|| {
            phase.import_window_paid(Some(window), &index, &scan.census_window_end, &mut paid)
        });
        assert_eq!(imported, !one_byte_short);
        assert_eq!(serde_json::to_vec(&index).unwrap(), unchanged);
        assert!(allocations.requested_peak_with_overlap <= extra);
        assert!(paid
            .as_ref()
            .unwrap()
            .permits_recovery_peak(external + recovery));
        if one_byte_short {
            assert!(phase.disabled_for_test());
            assert_eq!(allocations.allocations, 0);
            assert_eq!(paid.as_ref().unwrap().allocated(), external);
        } else {
            assert_eq!(phase.capture_count_for_test(), 1);
            assert_eq!(
                paid.as_ref().unwrap().allocated(),
                external + phase.owned_capture_bytes().unwrap()
            );
        }
        eprintln!("native paid import: one_byte_short={one_byte_short} imported={imported} planned_extra={extra} measured_incremental_peak={} index_unchanged=true recovery_preserved=true", allocations.requested_peak_with_overlap);
    }
}

#[test]
fn native_comparison_paid_capture_population_reports_guard_viability_without_bypass() {
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("UNEXECUTED native descriptor population: unsupported layout");
        return;
    }
    let mut index = ScanIndex {
        upload_context_fingerprint: Some("synthetic-context".into()),
        active_upload_context_fingerprint: Some("synthetic-context".into()),
        ..Default::default()
    };
    let candidates = (0..2043)
        .map(|ordinal| {
            let path = PathBuf::from(format!("/synthetic/project/session-{ordinal}.jsonl"));
            let mut entry = manifest_index_entry(Some("accepted-body"));
            entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
            index.files.insert(local_index_key(&path), entry);
            CandidateFile {
                physical_identity: None,
                scan_root: PathBuf::from("/synthetic/project"),
                path,
                size_bytes: 1,
                modified_unix_seconds: 2,
                modified_unix_nanos: 3,
                source_file_fingerprint: "source".into(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: "synthetic-descriptor-not-opened-evidence".into(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
            }
        })
        .collect::<Vec<_>>();
    let mut phase = claude_native_comparison::NativePhase::default();
    let initial = phase.owned_capture_bytes().unwrap();
    let budget = crate::source_rotation::PARKED_BUDGET;
    // A descriptor/accounting component experiment, not a fabricated runtime
    // lease or actual opened-Skip certificate. Pipeline proof uses rotation.
    let mut credit = Some(
        crate::source_rotation::PaidReservation::from_remainder(Some(budget), initial, initial)
            .unwrap(),
    );
    assert!(credit.as_mut().unwrap().reserve_recovery(1024));
    let started = std::time::Instant::now();
    let mut attempted = 0;
    let mut maximum_retained = 0;
    let mut maximum_owned = initial;
    let (_, allocation) = crate::retry_allocation_probe::measure(|| {
        for candidate in &candidates {
            attempted += 1;
            phase.record_actual_skip_paid(&index, candidate, WINDOW, &mut credit);
            maximum_retained = maximum_retained.max(phase.capture_count_for_test());
            maximum_owned = maximum_owned.max(credit.as_ref().unwrap().allocated());
            if !phase.capture_active() {
                break;
            }
        }
    });
    let elapsed_us = started.elapsed().as_micros();
    let refused = !phase.capture_active();
    let mut unused = crate::heap_layout_bound::Counter::new(usize::MAX);
    crate::heap_layout_bound::HeapLayoutBound::heap_bound(credit.as_ref().unwrap(), &mut unused)
        .unwrap();
    let prepaid_peak = credit
        .as_ref()
        .unwrap()
        .allocated()
        .checked_add(unused.bytes)
        .unwrap();
    assert!(
        allocation.requested_peak_with_overlap <= prepaid_peak,
        "capture transient allocation exceeds paid credit"
    );
    eprintln!("native capture allocation: requested_peak_with_overlap={} prepaid_peak={prepaid_peak} not_RSS=true", allocation.requested_peak_with_overlap);

    if refused {
        assert!(
            phase.disabled_for_test(),
            "unknown accounting cannot retain partial eligibility"
        );
    }
    assert_eq!(index.files.len(), 2043);
    assert_eq!(
        maximum_retained, 2043,
        "all descriptors must fit without bypassing the visit guard"
    );
    assert!(!refused);
    assert!(maximum_owned <= budget);
    assert!(credit
        .as_ref()
        .unwrap()
        .permits_recovery_peak(initial + 1024));
    eprintln!("native capture population viability: requested_population=2043 attempted={attempted} maximum_retained={maximum_retained} maximum_owned_charge={maximum_owned} budget={budget} refused={refused} elapsed_us={elapsed_us} native_skip_evidence=false component_only=true representative_runtime_coverage_unproved=true guard_unchanged=true");
    // Actual new-descriptor pressure preserves earlier paid eligibility. A
    // parse that cannot record its mandatory revocation instead fails closed.
    credit.as_mut().unwrap().at_turn(Some(maximum_owned));
    let mut extra = candidates[0].clone();
    extra.path = PathBuf::from("/synthetic/project/extra.jsonl");
    let mut entry = manifest_index_entry(Some("accepted-body"));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
    index.files.insert(local_index_key(&extra.path), entry);
    phase.record_actual_skip_paid(&index, &extra, WINDOW, &mut credit);
    assert!(phase.capture_active());
    assert_eq!(phase.capture_count_for_test(), 2043);
    assert!(!phase.record_parse_attempt_paid(&candidates[0], &mut credit));
    assert!(phase.disabled_for_test());
}

#[test]
fn native_comparison_selected_membership_sees_all_paths_without_unrelated_owned_graph() {
    let mut index = ScanIndex::default();
    for ordinal in 0..2048 {
        let mut entry = manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = "s".repeat(4096);
        index
            .files
            .insert(format!("/unrelated/u-{ordinal}.jsonl"), entry);
    }
    for path in [
        "/project/healthy.jsonl",
        "/project/healthy/subagents/agent-a.jsonl",
        // Not in the initial target list, but still a required family member.
        "/different-project/healthy/subagents/agent-unexpected.jsonl",
        "/project/duplicated.jsonl",
        "/project/duplicated/subagents/agent-a.jsonl",
        "/different-project/duplicated/subagents/agent-a.jsonl",
        "/project/missing-root/subagents/agent-a.jsonl",
    ] {
        index
            .files
            .insert(path.into(), manifest_index_entry(Some("body")));
    }
    let selected = BTreeSet::from(["healthy".into(), "duplicated".into(), "missing-root".into()]);
    let (all, baseline) =
        crate::retry_allocation_probe::measure(|| complete_claude_usage_family_members(&index));
    let (scoped, allocated) = crate::retry_allocation_probe::measure(|| {
        complete_claude_usage_family_members_matching(&index, Some(&selected))
    });
    for root in &selected {
        assert_eq!(scoped.get(root), all.get(root));
    }
    assert!(scoped["healthy"].contains("healthy_agent-unexpected"));
    assert!(
        !scoped.contains_key("duplicated"),
        "another project's duplicate must invalidate the family"
    );
    assert!(!scoped.contains_key("missing-root"));
    assert_eq!(scoped.len(), 1);
    assert!(allocated.requested_peak_with_overlap < baseline.requested_peak_with_overlap);
    let base_source_bytes = index
        .files
        .values()
        .map(|entry| entry.source_file_fingerprint.capacity())
        .sum::<usize>();
    assert!(base_source_bytes >= crate::source_rotation::PARKED_BUDGET);
    eprintln!("native comparison membership scratch: unrelated_files=2048 borrowed_base_source_bytes={base_source_bytes} baseline_global_peak={} selected_peak={} selected_duplicate_outside_targets_rejected=true missing_root_rejected=true extra_member_visible=true final_global_fold_unchanged=true admission_unproved=true not_RSS=true", baseline.requested_peak_with_overlap, allocated.requested_peak_with_overlap);
}

#[test]
fn native_comparison_selected_restore_membership_matches_canonical_without_global_set() {
    let mut index = ScanIndex::default();
    for ordinal in 0..2048 {
        let key = format!("file-{ordinal}");
        index.files.insert(
            key.clone(),
            manifest_index_entry(Some(&format!("legacy-{ordinal}"))),
        );
        if ordinal % 3 == 0 {
            index.file_snapshot_fingerprints.insert(
                key,
                BTreeSet::from([format!("exact-{ordinal}"), "shared".into()]),
            );
        }
    }
    index
        .files
        .insert("empty".into(), manifest_index_entry(Some("shadowed-empty")));
    index
        .file_snapshot_fingerprints
        .insert("empty".into(), BTreeSet::new());
    index
        .codex_state_only_snapshot_fingerprints
        .insert("state".into(), "codex-state".into());
    let queries = [
        "exact-0",
        "legacy-0",
        "legacy-1",
        "exact-2046",
        "legacy-2047",
        "shared",
        "shadowed-empty",
        "codex-state",
        "absent",
    ];
    let (canonical, old) =
        crate::retry_allocation_probe::measure(|| index.current_snapshot_fingerprints());
    let expected = queries
        .iter()
        .filter(|fp| !canonical.contains(**fp))
        .map(|fp| (*fp).to_owned())
        .collect::<BTreeSet<_>>();
    let ((unreferenced, visits), borrowed) = crate::retry_allocation_probe::measure(|| {
        let mut affected = queries
            .iter()
            .map(|fp| (*fp).to_owned())
            .collect::<BTreeSet<_>>();
        let mut visits = 0usize;
        for current in index.current_snapshot_fingerprint_refs() {
            visits += 1;
            affected.remove(current);
        }
        (affected, visits)
    });
    assert_eq!(unreferenced, expected);
    let expected_visits = index
        .file_snapshot_fingerprints
        .values()
        .map(BTreeSet::len)
        .sum::<usize>()
        + index
            .files
            .keys()
            .filter(|key| !index.file_snapshot_fingerprints.contains_key(*key))
            .count()
        + index.codex_state_only_snapshot_fingerprints.len();
    assert_eq!(
        visits, expected_visits,
        "one universe pass, not affected bodies times the full index"
    );
    assert!(borrowed.requested_peak_with_overlap < old.requested_peak_with_overlap);
    eprintln!("native comparison selected restore: unrelated_files=2048 affected_queries={} universe_visits={visits} old_global_requested_peak={} selected_set_requested_peak={} one_universe_pass=true exact_empty_overrides_legacy=true codex_state_preserved=true not_RSS=true", queries.len(), old.requested_peak_with_overlap, borrowed.requested_peak_with_overlap);
}

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

// Nonshipping frozen-proof experiment retired.

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
    // Legacy reported-usage rebuild and selectors; E2 attaches telemetry to native grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
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

// Nonshipping target-priority experiment retired.

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

/// Restores a file's original mode at teardown, also when an assertion panics.
#[cfg(unix)]
struct RestoreFileMode<'a>(&'a Path, fs::Permissions);
#[cfg(unix)]
impl Drop for RestoreFileMode<'_> {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.0, self.1.clone());
    }
}

/// A failed read, not a deletion: a Claude file deleted beneath its present
/// parent is a removal (N), so the failure is injected as a permission error.
#[cfg(unix)]
#[test]
fn envelope_experiment_failed_open_is_unavailable_not_success_and_keeps_durable_rearm() {
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(
        // SAFETY: geteuid() is always-successful and has no preconditions.
        unsafe { libc::geteuid() },
        0,
        "this test injects a failed open with chmod 000, which root reads through; run it as a non-root user"
    );
    let fixture = SelectionFixture::new();
    let scope = envelope_selection_experiment::Scope::controlled();
    scope.register("family", BTreeSet::from([fixture.paths[0].clone()]));
    let native = fixture.prepare(fixture.previous.clone(), 1);
    assert_eq!(native.identified_candidates[0].path, fixture.paths[0]);
    let bytes = fs::read(&fixture.paths[0]).unwrap();
    // After frozen selection, before safe open.
    let unreadable = RestoreFileMode(
        &fixture.paths[0],
        fs::metadata(&fixture.paths[0]).unwrap().permissions(),
    );
    fs::set_permissions(&fixture.paths[0], fs::Permissions::from_mode(0o000)).unwrap();
    let ((index, scan), producer_events) =
        disappearance_diagnostics::observe(|| SelectionFixture::run(native));
    assert_eq!(
        producer_events, [[0; 4]; 3],
        "a failed read is not a NotFound producer"
    );
    assert_eq!(scan.disappeared_file_count, 0);
    assert_eq!(scan.unreadable_path_count, 1);
    assert!(scan.disappeared_file_count + scan.unreadable_path_count > 0);
    scope.defer_after_native("family", &scan);
    assert_eq!(scope.counts().unavailable, 1);
    assert_eq!(scope.counts().successful_deferrals, 0);
    assert!(
        !scope.allowed("family"),
        "fallback revokes reuse, never converts failed read to success"
    );
    let body_before = serde_json::to_vec(&scan.snapshots).unwrap();
    let (saved, copy_events) =
        disappearance_diagnostics::observe(|| fixture.checkpoint(&index, &scan));
    assert_eq!(
        copy_events, [[0; 4]; 3],
        "partial checkpoint must not record producers again"
    );
    assert_eq!(serde_json::to_vec(&scan.snapshots).unwrap(), body_before);
    let saved_bytes = fs::read(&fixture.index_path).unwrap();
    assert_eq!(saved_bytes, serde_json::to_vec(&saved).unwrap());
    assert!(!String::from_utf8(saved_bytes.clone())
        .unwrap()
        .contains("disappearance_process_totals_v1"));
    assert!(saved.files[&local_index_key(&fixture.paths[0])]
        .source_file_fingerprint
        .is_empty());
    assert_eq!(
        saved.accepted_snapshot_fingerprints,
        fixture.previous.accepted_snapshot_fingerprints
    );
    drop(unreadable);
    fs::write(&fixture.paths[0], bytes).unwrap();
    drop(scope);
    let restarted = envelope_selection_experiment::Scope::restart();
    let (reloaded, reload_events) = disappearance_diagnostics::observe(|| {
        let loaded = ScanIndex::load(&fixture.index_path).unwrap();
        let _ = disappearance_diagnostics::snapshot(SnapshotSource::ClaudeCode);
        loaded
    });
    assert_eq!(reload_events, [[0; 4]; 3]);
    assert_eq!(serde_json::to_vec(&reloaded).unwrap(), saved_bytes);
    assert_eq!(fs::read(&fixture.index_path).unwrap(), saved_bytes);
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
        self.paused_with_limit(8)
    }
    fn paused_with_limit(&self, limit: usize) -> OwnedSourceScan {
        let mut state = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.dir),
            self.index.clone(),
            WINDOW,
            30,
            limit,
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
    if !native_positive_layout_for_test(
        "native_comparison_actual_skip_freezes_retained_proof_before_body_fold",
    ) {
        return;
    }
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
    // Legacy reported-usage rebuild and selectors; E2 attaches telemetry to native grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
fn native_comparison_negative_rows_recheck_each_opened_pair_without_decoding() {
    let fixture = NativePreparationFixture::new();
    let required = BTreeSet::from([fixture.parent.clone()]);
    // Same-byte object replacement must still withdraw a frozen negative;
    // neither API nor trace generation can be inferred from the other.
    for changed in [
        None,
        Some("claude-code-effort"),
        Some("claude-code-trace-ownership"),
    ] {
        let support = crate::test_scratch::ScratchDir::new("native-negative-generation");
        write_native_preparation_pair(&support, &fixture.parent, &fixture.api, &fixture.trace);
        crate::claude_local_otel::reset_evidence_read_counts_for_test();
        let (before, after) = crate::snapshot_sync::prepared_claude_negative_rows_for_test(
            &support,
            &fixture.index,
            &required,
            || {
                if let Some(folder) = changed {
                    let path = support.join("local-otel").join(folder).join(format!(
                        "{:x}.jsonl",
                        Sha256::digest(fixture.parent.as_bytes())
                    ));
                    let replacement = path.with_extension("replacement");
                    fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
                    fs::rename(replacement, path).unwrap();
                }
            },
        );
        assert!(before);
        assert_eq!(after, changed.is_none());
        assert_eq!(
            crate::claude_local_otel::evidence_read_counts_for_test(),
            (1, 1),
            "negative validation must not silently reload P or decode another graph"
        );
    }
    writeln!(std::io::stderr().lock(), "native_comparison_generation: unchanged_pair_reusable=true same_bytes_api_or_trace_replacement_withdraws=true validation_decodes=0 controller_unproved=true").unwrap();
}

#[test]
fn native_comparison_negative_rows_cannot_qualify_an_unloaded_predecessor() {
    let fixture = NativePreparationFixture::new();
    let support = crate::test_scratch::ScratchDir::new("native-negative-missing-root");
    write_native_preparation_pair(&support, &fixture.parent, &fixture.api, &fixture.trace);
    let required = BTreeSet::from([fixture.parent.clone(), "unknown-predecessor".to_owned()]);
    let (before, after) = crate::snapshot_sync::prepared_claude_negative_rows_for_test(
        &support,
        &fixture.index,
        &required,
        || {},
    );
    assert!(
        !before && !after,
        "one healthy root cannot certify missing predecessor rows"
    );
}

fn native_recovery_priority_scan(
    fixture: &SelectionFixture,
    index: ScanIndex,
    limit: usize,
    paths: &[PathBuf],
) -> OwnedSourceScan {
    OwnedSourceScan::new_with_identity_capture_and_recovery_priority(
        SnapshotSource::ClaudeCode,
        &fixture.roots,
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
        paths,
    )
}

#[test]
fn native_comparison_recovery_selection_precedes_real_audit_without_expanding_page() {
    let fixture = SelectionFixture::new();
    let mut rearmed = fixture.previous.clone();
    rearmed
        .files
        .get_mut(&local_index_key(&fixture.paths[0]))
        .unwrap()
        .source_file_fingerprint
        .clear();
    rearmed.save(&fixture.index_path).unwrap();
    let rearmed = ScanIndex::load(&fixture.index_path).unwrap();
    assert!(rearmed.files[&local_index_key(&fixture.paths[0])]
        .source_file_fingerprint
        .is_empty());
    let base = fixture.prepare(rearmed.clone(), 1);
    assert_eq!(base.identified_candidates.len(), 1);
    assert_eq!(base.identified_candidates[0].path, fixture.paths[1]);
    let _scope = claude_native_comparison::enable_for_test();
    let native = native_recovery_priority_scan(&fixture, rearmed, 1, &fixture.paths[..1]);
    assert_eq!(native.identified_candidates.len(), 1);
    assert_eq!(native.identified_candidates[0].path, fixture.paths[0]);
    let (index, scan) = SelectionFixture::run(native);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(scan.snapshots.len(), 1);
    assert!(index.files[&local_index_key(&fixture.paths[1])]
        .audit_requires_full(sampled_scan::now_seconds()));
    assert!(
        index
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .any(|entry| entry.path == fixture.paths[1]),
        "unselected audit remains queued"
    );
    writeln!(std::io::stderr().lock(), "native_comparison_recovery_priority: real_constructor=true actual_index_save_reload=true base_selects_audit=true recovery_selected_first=true native_reads=1 page_limit=1 audit_debt_and_queue_preserved=true selected_save_and_lifecycle_unproved=true").unwrap();
}

#[test]
fn native_comparison_recovery_priority_requires_scope_queued_debt_and_remaining_budget() {
    let fixture = SelectionFixture::new();
    let mut rearmed = fixture.previous.clone();
    rearmed
        .files
        .get_mut(&local_index_key(&fixture.paths[0]))
        .unwrap()
        .source_file_fingerprint
        .clear();
    let inactive = native_recovery_priority_scan(&fixture, rearmed.clone(), 1, &fixture.paths[..1]);
    assert_eq!(
        inactive.identified_candidates[0].path, fixture.paths[1],
        "ordinary construction stays on base with no process test opt-in"
    );
    let _scope = claude_native_comparison::enable_for_test();
    let no_debt =
        native_recovery_priority_scan(&fixture, fixture.previous.clone(), 1, &fixture.paths[..1]);
    assert_eq!(no_debt.identified_candidates[0].path, fixture.paths[1]);
    let unknown = fixture.roots[0].join("unknown-recovery.jsonl");
    let missing = native_recovery_priority_scan(&fixture, rearmed.clone(), 1, &[unknown]);
    assert_eq!(
        missing.identified_candidates[0].path, fixture.paths[1],
        "missing path cannot become a synthetic queued candidate"
    );
    let zero = native_recovery_priority_scan(&fixture, rearmed, 0, &fixture.paths[..1]);
    assert!(zero.identified_candidates.is_empty());
}

fn complete_native_with_terminal_owner(
    mut state: OwnedSourceScan,
) -> (
    ScanIndex,
    SourceScanResult,
    Option<Box<claude_native_comparison::TerminalTraversal>>,
) {
    for _ in 0..1024 {
        if state.native_comparison_ready() {
            state.resume_native_comparison_base();
        }
        match state.step(None) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete {
                index,
                scan,
                terminal_native_traversal,
            } => {
                return (index, scan, terminal_native_traversal);
            }
        }
    }
    panic!("bounded native scan did not complete");
}

#[test]
fn native_comparison_terminal_checkpoint_moves_outside_cloneable_scan_result() {
    let fixture = NativePreparationFixture::new();
    let base = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.dir),
        fixture.index.clone(),
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
    let (base_index, base_scan, base_terminal) = complete_native_with_terminal_owner(base);
    assert!(base_terminal.is_none());
    let state = fixture.paused();
    let original_context = state
        .index
        .traversal
        .as_ref()
        .unwrap()
        .context_fingerprint
        .as_ptr() as usize;
    let (index, scan, terminal) = complete_native_with_terminal_owner(state);
    let terminal = terminal.expect("complete opted-in native traversal moves separately");
    assert!(scan.census_complete && base_scan.census_complete);
    assert!(index.traversal.is_none() && base_index.traversal.is_none());
    assert_eq!(
        terminal.context_pointer_for_test(),
        original_context,
        "move the original allocation, never the diagnostic traversal clone"
    );
    assert!(terminal.contains_observed_for_test(&local_index_key(
        &fixture.dir.join(format!("{}.jsonl", fixture.parent))
    )));
    assert_eq!(
        serde_json::to_value(&index).unwrap(),
        serde_json::to_value(&base_index).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&scan.snapshots).unwrap(),
        serde_json::to_value(&base_scan.snapshots).unwrap()
    );
    let result_clone = scan.clone();
    drop(scan);
    assert!(result_clone.census_complete);
    assert_eq!(terminal.context_pointer_for_test(), original_context);
    writeln!(std::io::stderr().lock(), "native_comparison_terminal_owner: original_context_allocation_moved=true result_clone_separate=true base_index_body_parity=true actual_census_complete=true selected_restore_unproved=true").unwrap();
}

#[test]
fn native_comparison_terminal_owner_requires_complete_current_claude_census() {
    let fixture = SelectionFixture::new();
    let mut incomplete = fixture.prepare(fixture.previous.clone(), 1);
    incomplete.enable_native_comparison();
    let (index, scan, terminal) = complete_native_with_terminal_owner(incomplete);
    assert!(!scan.census_complete);
    assert!(index.traversal.is_some());
    assert!(
        terminal.is_none(),
        "incomplete traversal stays under its existing index owner"
    );
    let fixture = NativePreparationFixture::new();
    let state = fixture.paused();
    for (source, active, complete, window) in [
        (SnapshotSource::Codex, true, true, WINDOW),
        (SnapshotSource::ClaudeCode, false, true, WINDOW),
        (SnapshotSource::ClaudeCode, true, false, WINDOW),
        (SnapshotSource::ClaudeCode, true, true, "different-census"),
    ] {
        let mut index = state.index.clone();
        let before = serde_json::to_value(&index).unwrap();
        assert!(claude_native_comparison::TerminalTraversal::take(
            &mut index, source, active, complete, window
        )
        .is_none());
        assert_eq!(
            serde_json::to_value(&index).unwrap(),
            before,
            "failed capture guard must not consume or alter the existing traversal"
        );
    }
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
    first.note_selected_save(fixture.native_conjunction);
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
    // Same ordering as finish: save failure exits before note_selected_save.
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

fn native_comparison_quiet_bounded_page(
    fixture: &NativePreparationFixture,
) -> (ScanIndex, SourceScanResult, ClaudeUsageAuthorityDisposition) {
    let native = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.dir),
        fixture.index.clone(),
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
    let (mut index, mut scan) = SelectionFixture::run(native);
    assert!(!scan.census_complete);
    assert_eq!(scan.scanned_file_count, 0);
    assert!(scan.snapshots.is_empty(), "no new body needs an ACK");
    let disposition = apply_claude_reported_usage_with_index(
        &mut scan.snapshots,
        &fixture.api,
        &fixture.trace,
        &mut index,
        scan.census_complete,
        &scan.census_window_end,
    );
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    (index, scan, disposition)
}

#[test]
fn native_comparison_lifecycle_saved_bounded_page_retains_only_existing_grant() {
    let mut fixture = NativePreparationFixture::new();
    let scratch = crate::test_scratch::ScratchDir::new("native-comparison-page-save");
    let path = scratch.join("index.json");
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut bootstrap = owner.begin();
    bootstrap.bind("page-source-destination-context".into());
    fixture.index.save(&path).unwrap();
    bootstrap.note_selected_save(fixture.native_conjunction);
    bootstrap.finish(true);

    let mut page = owner.begin();
    page.bind("page-source-destination-context".into());
    assert!(page.allowed());
    let (mut index, scan, disposition) = native_comparison_quiet_bounded_page(&fixture);
    assert!(claude_native_comparison::selected_page_is_clean(
        &scan,
        &index,
        &disposition
    ));
    index.save(&path).unwrap();
    page.note_selected_save(false); // A partial census cannot bootstrap.
    page.finish(claude_native_comparison::selected_page_is_clean(
        &scan,
        &index,
        &disposition,
    ));
    let mut next = owner.begin();
    next.bind("page-source-destination-context".into());
    assert!(next.allowed());
    drop(next);

    let restarted = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut fresh = restarted.begin();
    fresh.bind("page-source-destination-context".into());
    assert!(!fresh.allowed());
    index.save(&path).unwrap();
    fresh.note_selected_save(false);
    fresh.finish(true);
    let mut after_restart = restarted.begin();
    after_restart.bind("page-source-destination-context".into());
    assert!(
        !after_restart.allowed(),
        "saved partial page is not bootstrap"
    );
    writeln!(std::io::stderr().lock(), "native_comparison_page_lease: actual_native_bootstrap_save=true actual_quiet_bounded_page_save=true prior_grant_retained=true partial_page_cannot_mint=true certificate_carry_unwired=true").unwrap();
}

#[test]
fn native_comparison_lifecycle_page_loss_or_missing_selected_save_revokes() {
    let mut fixture = NativePreparationFixture::new();
    let scratch = crate::test_scratch::ScratchDir::new("native-comparison-page-loss");
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut bootstrap = owner.begin();
    bootstrap.bind("page-source-destination-context".into());
    fixture.index.save(&scratch.join("index.json")).unwrap();
    bootstrap.note_selected_save(fixture.native_conjunction);
    bootstrap.finish(true);
    let mut no_save = owner.begin();
    no_save.bind("page-source-destination-context".into());
    assert!(no_save.allowed());
    no_save.finish(true);
    let mut next = owner.begin();
    next.bind("page-source-destination-context".into());
    assert!(
        !next.allowed(),
        "clean boolean cannot replace selected save"
    );

    let (index, scan, disposition) = native_comparison_quiet_bounded_page(&fixture);
    assert!(claude_native_comparison::selected_page_is_clean(
        &scan,
        &index,
        &disposition
    ));
    let mut loss = scan.clone();
    loss.unreadable_path_count = 1;
    assert!(!claude_native_comparison::selected_page_is_clean(
        &loss,
        &index,
        &disposition
    ));
    let mut sidecar = scan.clone();
    sidecar.sidecar_census_complete = false;
    assert!(!claude_native_comparison::selected_page_is_clean(
        &sidecar,
        &index,
        &disposition
    ));
    let mut unknown = index.clone();
    unknown.traversal = None;
    assert!(!claude_native_comparison::selected_page_is_clean(
        &scan,
        &unknown,
        &disposition
    ));
    let mut unsettled = index.clone();
    unsettled.mark_bounded_sweep_unsettled();
    assert!(!claude_native_comparison::selected_page_is_clean(
        &scan,
        &unsettled,
        &disposition
    ));
    let mut invalid = ClaudeUsageAuthorityDisposition::default();
    invalid.duplicate_census.census_invalid = true;
    assert!(!claude_native_comparison::selected_page_is_clean(
        &scan, &index, &invalid
    ));
    let mut closed = index.clone();
    closed.claude_duplicate_request_witness_overflowed = true;
    assert!(!claude_native_comparison::selected_page_is_clean(
        &scan,
        &closed,
        &disposition
    ));
    writeln!(std::io::stderr().lock(), "native_comparison_page_lease: no_selected_save_revokes=true unreadable_sidecar_unknown_unsettled_invalid_closed_rejected=true certificate_carry_unwired=true").unwrap();
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
    if !native_positive_layout_for_test(
        "native_comparison_q5_keeps_old_proof_and_checks_revision_and_occurrences",
    ) {
        return;
    }
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
    assert_eq!(
        qualification.certified_member_count(),
        0,
        "an actual family parse withdraws sibling negatives, not the exact Q5 native prior"
    );
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
    if !native_positive_layout_for_test(
        "native_comparison_positive_hit_reads_targets_in_same_owner_before_body_fold",
    ) {
        return;
    }
    let (_fixture, mut state, mut qualification) = native_comparison_positive_hit_fixture();
    let scope_before = state.native_comparison_context().unwrap().to_owned();
    let requested_layout_bytes =
        crate::heap_layout_bound::completed_bound(&qualification, usize::MAX);
    if crate::heap_layout_bound::layout_supported() {
        assert!(requested_layout_bytes.is_some_and(|bytes| bytes > 0));
    } else {
        assert!(
            requested_layout_bytes.is_none(),
            "unvalidated compiler layouts must remain unavailable"
        );
    }
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
    writeln!(std::io::stderr().lock(), "native_comparison_target: initial_native=1 matched_roots=1 queued=2 actual_target_reads=2 same_scanner_context=true existing_file_budget=true before_body_fold=true repeated_targets=0 requested_layout_bytes={requested_layout_bytes:?} rss_measured=false").unwrap();
}

#[test]
fn native_comparison_insufficient_remaining_budget_withdraws_and_reports_unresolved() {
    if !native_positive_layout_for_test(
        "native_comparison_insufficient_remaining_budget_withdraws_and_reports_unresolved",
    ) {
        return;
    }
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
    if !native_positive_layout_for_test(
        "native_comparison_replaced_target_keeps_safe_open_failure_visible",
    ) {
        return;
    }
    let (fixture, mut state, mut qualification) = native_comparison_positive_hit_fixture();
    let selection = state.acquire_native_comparison_targets(&mut qualification);
    assert_eq!(selection.queued, 2);
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    let replacement = fixture.dir.join("replacement.tmp");
    fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
    fs::rename(&replacement, &path).unwrap();
    let base_bodies = state
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                serde_json::to_vec(item).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let target_key = local_index_key(&path);
    let target_entry = serde_json::to_vec(&state.index.files[&target_key]).unwrap();
    let file_limit = state.file_limit;
    let sidecar_complete = state.sidecar_census_complete;
    let (mut state, disappearance_events) =
        disappearance_diagnostics::observe(|| pause_native_comparison(state));
    assert_eq!(
        disappearance_events,
        [[0; 4], [0, 0, 0, 1], [0; 4]],
        "a real reopened replacement reaches the frozen revision comparison"
    );
    assert_eq!(
        serde_json::to_vec(&state.index.files[&target_key]).unwrap(),
        target_entry,
        "a mismatched target cannot refresh the frozen index entry"
    );
    assert_eq!(state.file_limit, file_limit);
    assert_eq!(state.sidecar_census_complete, sidecar_complete);
    for (session, bytes) in base_bodies {
        let retained = state
            .snapshots
            .iter()
            .find(|item| item.source_session_id == session)
            .unwrap();
        assert_eq!(
            serde_json::to_vec(retained).unwrap(),
            bytes,
            "target failure preserves already parsed native bodies"
        );
    }

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

fn native_observation_duplicate_fixture() -> (
    crate::test_scratch::ScratchDir,
    ScanIndex,
    SourceScanResult,
    String,
    String,
) {
    let dir = crate::test_scratch::ScratchDir::new("native-observation-emission-split");
    let b = "b2222222-2222-4222-8222-222222222222".to_owned();
    let d = "d4444444-4444-4444-8444-444444444444".to_owned();
    for (session, own) in [(&b, "b_unique"), (&d, "d_unique")] {
        let rows = [own, "shared_second"].into_iter().enumerate().map(|(i, request)| {
            format!("{{\"timestamp\":\"2026-08-02T07:00:0{i}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n")
        }).collect::<String>();
        fs::write(dir.join(format!("{session}.jsonl")), rows).unwrap();
    }
    let native = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &[dir.to_path_buf()],
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
    let (index, scan) = SelectionFixture::run(native);
    assert!(scan.census_complete);
    assert_eq!(scan.scanned_file_count, 2);
    assert_eq!(scan.snapshots.len(), 2);
    (dir, index, scan, b, d)
}

#[test]
fn native_comparison_withheld_body_keeps_actual_duplicate_against_unaffected_body() {
    let (_dir, mut index, mut scan, b, d) = native_observation_duplicate_fixture();
    let mut base_index = index.clone();
    let mut base_scan = scan.clone();
    let api = Api::default();
    let trace = Trace::default();
    let base = apply_claude_reported_usage_to_scan_with_identity(
        &mut base_scan,
        &api,
        &trace,
        &mut base_index,
        None,
    );
    let shared = format!("{:x}", Sha256::digest(b"shared_second"));
    let expected = BTreeSet::from([
        claude_duplicate_request_owner(&b, &b),
        claude_duplicate_request_owner(&d, &d),
    ]);
    assert_eq!(
        base_index.claude_duplicate_request_owners.get(&shared),
        Some(&expected)
    );
    let mut bad_index = index.clone();
    let mut bad_scan = scan.clone();
    bad_scan
        .snapshots
        .retain(|item| item.source_session_id != b);
    apply_claude_reported_usage_to_scan_with_identity(
        &mut bad_scan,
        &api,
        &trace,
        &mut bad_index,
        None,
    );
    assert!(
        !bad_index
            .claude_duplicate_request_owners
            .contains_key(&shared),
        "control demonstrates why filtering before native accumulation is wrong"
    );
    let observed = record_claude_native_observations(&scan, &mut index);
    scan.snapshots.retain(|item| item.source_session_id != b);
    scan.pending_finalization.retain(|pending| {
        claude_index_path_family_member(Path::new(&pending.index_key))
            .is_some_and(|(_, member)| member != b)
    });
    let split = apply_claude_reported_usage_to_scan_with_observations(
        &mut scan,
        &api,
        &trace,
        &mut index,
        None,
        Some(observed),
    );
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].source_session_id, d);
    assert_eq!(
        index.claude_duplicate_request_owners.get(&shared),
        Some(&expected)
    );
    assert_eq!(
        index.claude_duplicate_request_owners,
        base_index.claude_duplicate_request_owners
    );
    assert_eq!(split.duplicate_census, base.duplicate_census);
    assert_eq!(
        split.transcript_ownership_complete,
        base.transcript_ownership_complete
    );
    // Effective terminality changes only AFTER the authoritative actual-native
    // census, never before duplicate detection. Final selected restore/rearm is
    // still a separate required integration gate.
    scan.census_complete = false;
    index.mark_bounded_sweep_unsettled();
    writeln!(std::io::stderr().lock(), "native_comparison_observations: actual_native_files=2 actual_native_occurrences=4 withheld_bodies=1 emitted_bodies=1 b_d_duplicate_retained=true filter_first_control_misses_duplicate=true actual_fold_once=true selected_settlement_unproved=true").unwrap();
}

#[test]
fn native_comparison_consumed_observations_preserve_unfiltered_base_fold() {
    let (_dir, mut index, mut scan, _, _) = native_observation_duplicate_fixture();
    let mut base_index = index.clone();
    let mut base_scan = scan.clone();
    let api = Api::default();
    let trace = Trace::default();
    let base = apply_claude_reported_usage_to_scan_with_identity(
        &mut base_scan,
        &api,
        &trace,
        &mut base_index,
        None,
    );
    let observed = record_claude_native_observations(&scan, &mut index);
    let split = apply_claude_reported_usage_to_scan_with_observations(
        &mut scan,
        &api,
        &trace,
        &mut index,
        None,
        Some(observed),
    );
    assert_eq!(
        serde_json::to_value(&index).unwrap(),
        serde_json::to_value(&base_index).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&scan.snapshots).unwrap(),
        serde_json::to_value(&base_scan.snapshots).unwrap()
    );
    assert_eq!(split.duplicate_census, base.duplicate_census);
    assert_eq!(
        split.transcript_ownership_complete,
        base.transcript_ownership_complete
    );
}

#[test]
fn native_comparison_legacy_exclusion_is_target_evidence_never_a_q5_prior() {
    if !native_positive_layout_for_test(
        "native_comparison_legacy_exclusion_is_target_evidence_never_a_q5_prior",
    ) {
        return;
    }
    let mut fixture = NativePreparationFixture::new();
    let c = "c3333333-3333-4333-8333-333333333333";
    let path = fixture.dir.join(format!("{c}.jsonl"));
    let parent_rows =
        fs::read_to_string(fixture.dir.join(format!("{}.jsonl", fixture.parent))).unwrap();
    let mut child_rows = parent_rows
        .lines()
        .take(2)
        .map(|line| line.replace(&fixture.parent, c) + "\n")
        .collect::<String>();
    child_rows.push_str(&format!("{{\"timestamp\":\"2026-08-02T07:00:06Z\",\"type\":\"assistant\",\"sessionId\":\"{c}\",\"requestId\":\"req_extra\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"));
    fs::write(&path, child_rows).unwrap();
    fixture.api.evidence.insert(
        c.to_owned(),
        vec![complete_api_row(c, "req_extra", 6, 10, 10, 0)],
    );
    fixture
        .trace
        .evidence
        .insert(c.to_owned(), vec![complete_trace_row(c, "req_extra", "")]);
    // Introducing C changes the duplicate-owner witness and legitimately
    // rearms existing members. This is a qualification fixture, not a quiet
    // convergence oracle: establish a second complete native conjunction before
    // asking which unchanged members the ordinary scanner can actually skip.
    // Never restore fingerprints by hand or suppress that production rearm.
    for establishing_pass in 0..2 {
        for entry in fixture.index.files.values_mut() {
            entry.source_file_fingerprint.clear();
        }
        let native = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.dir),
            fixture.index.clone(),
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
        assert_eq!(scan.scanned_file_count, 3);
        assert!(scan.census_complete);
        apply_claude_reported_usage_with_index(
            &mut scan.snapshots,
            &fixture.api,
            &fixture.trace,
            &mut index,
            true,
            WINDOW,
        );
        let excluded =
            index.claude_usage_family_witnesses[c].legacy_excluded_request_id_hashes[c].clone();
        assert_eq!(
            excluded,
            ["req_1", "req_2"]
                .into_iter()
                .map(|id| format!("{:x}", Sha256::digest(id.as_bytes())))
                .collect::<BTreeSet<_>>()
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
        if establishing_pass == 0 {
            assert!(index
                .files
                .values()
                .any(|entry| entry.source_file_fingerprint.is_empty()));
        } else {
            assert!(index
                .files
                .values()
                .all(|entry| !entry.source_file_fingerprint.is_empty()));
        }
        fixture.index = index;
    }
    let stable_index = fixture.index.clone();
    fixture
        .index
        .files
        .get_mut(&local_index_key(&path))
        .unwrap()
        .source_file_fingerprint
        .clear();
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 1);
    let native = state
        .snapshots
        .iter()
        .find(|item| item.source_session_id == c)
        .unwrap()
        .clone();
    let healthy = BTreeSet::from([fixture.parent.clone(), c.to_owned()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 2);
    assert_eq!(
        qualification.new_native_hashes(&native).unwrap(),
        raw_hashes(&native),
        "E nonempty cannot subtract a prior S even under the exact retained P"
    );
    assert_eq!(
        qualification.possible_targets(&native).unwrap(),
        BTreeSet::from([fixture.parent.clone()])
    );
    fixture.index = stable_index;
    let d = "d4444444-4444-4444-8444-444444444444";
    fs::write(
        fixture.dir.join(format!("{d}.jsonl")),
        parent_rows
            .lines()
            .next()
            .unwrap()
            .replace(&fixture.parent, d)
            + "\n",
    )
    .unwrap();
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 1);
    let native_d = state.snapshots[0].clone();
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 3);
    assert_eq!(
        qualification.possible_targets(&native_d).unwrap(),
        BTreeSet::from([fixture.parent.clone(), c.to_owned()]),
        "C is a target only because its certified S also contains E, not just assigned req_extra"
    );
    writeln!(std::io::stderr().lock(), "native_comparison_legacy: actual_prefix_exclusion=2 e_nonempty_q5_prior=false copied_native_requests_hit_predecessor=true certified_exclusion_is_target=true body_offer_unproved=true").unwrap();
}

#[test]
fn native_comparison_acquisition_requires_actual_completed_target_reads() {
    if !native_positive_layout_for_test(
        "native_comparison_acquisition_requires_actual_completed_target_reads",
    ) {
        return;
    }
    let (fixture, mut state, mut qualification) = native_comparison_positive_hit_fixture();
    let selection = state.acquire_native_comparison_targets(&mut qualification);
    assert_eq!(selection.queued, 2);
    let mut state = pause_native_comparison(state);
    let acquired = state.take_native_comparison_acquisition(&mut qualification);
    assert_eq!(acquired.completed_target_files, 2);
    assert_eq!(
        acquired.acquired_roots,
        BTreeSet::from([fixture.parent.clone()])
    );
    assert_eq!(
        acquired.ready_for_fold_sources,
        BTreeSet::from(["c3333333-3333-4333-8333-333333333333".to_owned()])
    );
    assert!(acquired.unresolved_sources.is_empty());
    assert!(acquired.rearm_roots.is_empty());
    assert!(acquired.known_rearm_candidates.is_empty());
    assert!(state
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    let consumed = state.take_native_comparison_acquisition(&mut qualification);
    assert_eq!(
        consumed.completed_target_files, 0,
        "actual acquisition receipt is consumed once"
    );
    assert!(consumed.ready_for_fold_sources.is_empty());
    state.resume_native_comparison_base();
    SelectionFixture::run(state);
    writeln!(std::io::stderr().lock(), "native_comparison_acquisition: queued=2 actual_full_reads=2 ready_for_exact_fold=1 body_authority_granted=false receipt_consumed_once=true").unwrap();
}

#[test]
fn native_comparison_controller_moves_frozen_plan_across_native_target_yields() {
    if !native_positive_layout_for_test(
        "native_comparison_controller_moves_frozen_plan_across_native_target_yields",
    ) {
        return;
    }
    let (fixture, mut state, qualification) = native_comparison_positive_hit_fixture();
    let mut controller = claude_native_comparison::Controller::new(qualification);
    assert_eq!(
        controller.required_roots(),
        &BTreeSet::from([fixture.parent.clone()])
    );
    let context = state.native_comparison_context().unwrap().to_owned();
    assert!(controller.advance(&mut state, true));
    assert_eq!(state.scanned_file_count, 1, "queueing is not acquisition");
    let mut state = pause_native_comparison(state);
    assert_eq!(state.scanned_file_count, 3);
    assert_eq!(state.native_comparison_context(), Some(context.as_str()));
    assert!(controller.advance(&mut state, true));
    let (receipt, frontier) = controller.receipt_for_test();
    assert_eq!(frontier, 3, "only the two newly acquired bodies extend H");
    assert_eq!(receipt.completed_target_files, 2);
    assert_eq!(
        receipt.acquired_roots,
        BTreeSet::from([fixture.parent.clone()])
    );
    assert_eq!(receipt.ready_for_fold_sources.len(), 1);
    assert!(receipt.unresolved_sources.is_empty());
    assert!(state.identified_candidates.is_empty());
    assert!(!state.native_comparison_ready());
    assert!(state
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    let (_, scan) = SelectionFixture::run(state);
    assert_eq!(scan.scanned_file_count, 3);
    assert_eq!(
        scan.snapshots.len(),
        3,
        "no emission filtering is activated"
    );
    writeln!(std::io::stderr().lock(), "native_comparison_controller: initial_native=1 completed_targets=2 frontier=3 same_owner_context=true repeated_targets=0 pre_fold_bodies=3 selected_deferral_and_rearm_suppression=false").unwrap();
}

#[test]
fn native_comparison_controller_generation_loss_or_insufficient_budget_uses_base() {
    if !native_positive_layout_for_test(
        "native_comparison_controller_generation_loss_or_insufficient_budget_uses_base",
    ) {
        return;
    }
    for changed_pair in [true, false] {
        let (_fixture, mut state, qualification) = native_comparison_positive_hit_fixture();
        if !changed_pair {
            state.file_limit = state.scanned_file_count + 1;
        }
        let mut controller = claude_native_comparison::Controller::new(qualification);
        assert!(!controller.advance(&mut state, !changed_pair));
        assert!(
            state
                .native_comparison
                .as_ref()
                .is_some_and(|phase| phase.disabled_for_test()),
            "no eligibility remains; only terminal-traversal custody survives"
        );
        assert!(
            !controller.advance(&mut state, true),
            "generation rollback or a later positive boolean cannot revive the controller"
        );
        assert!(state.identified_candidates.is_empty());
        let (_, scan) = SelectionFixture::run(state);
        assert_eq!(scan.scanned_file_count, 1);
        assert_eq!(
            scan.snapshots.len(),
            1,
            "base native body remains available"
        );
        assert!(scan.snapshots[0].usage_accounting_contract.is_none());
    }
    writeln!(std::io::stderr().lock(), "native_comparison_controller: changed_generation_base=true insufficient_remaining_budget_base=true no_extra_target_reads=true no_body_suppression=true actual_process_bootstrap_unproved=true").unwrap();
}

#[test]
fn native_comparison_controller_replaced_target_cannot_complete_comparison() {
    if !native_positive_layout_for_test(
        "native_comparison_controller_replaced_target_cannot_complete_comparison",
    ) {
        return;
    }
    let (fixture, mut state, qualification) = native_comparison_positive_hit_fixture();
    let mut controller = claude_native_comparison::Controller::new(qualification);
    assert!(controller.advance(&mut state, true));
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    let replacement = fixture.dir.join("controller-replacement.tmp");
    fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
    fs::rename(replacement, &path).unwrap();
    let base_bodies = state
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                serde_json::to_vec(item).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let target_key = local_index_key(&path);
    let target_entry = serde_json::to_vec(&state.index.files[&target_key]).unwrap();
    let file_limit = state.file_limit;
    let sidecar_complete = state.sidecar_census_complete;
    let (mut state, disappearance_events) =
        disappearance_diagnostics::observe(|| pause_native_comparison(state));
    assert_eq!(
        disappearance_events,
        [[0; 4], [0, 0, 0, 1], [0; 4]],
        "a real reopened replacement reaches the frozen revision comparison"
    );
    assert_eq!(
        serde_json::to_vec(&state.index.files[&target_key]).unwrap(),
        target_entry,
        "a mismatched target cannot refresh the frozen index entry"
    );
    assert_eq!(state.file_limit, file_limit);
    assert_eq!(state.sidecar_census_complete, sidecar_complete);
    for (session, bytes) in base_bodies {
        let retained = state
            .snapshots
            .iter()
            .find(|item| item.source_session_id == session)
            .unwrap();
        assert_eq!(
            serde_json::to_vec(retained).unwrap(),
            bytes,
            "target failure preserves already parsed native bodies"
        );
    }

    assert!(!controller.advance(&mut state, true));
    assert!(
        state
            .native_comparison
            .as_ref()
            .is_some_and(|phase| phase.disabled_for_test()),
        "no eligibility remains; only terminal-traversal custody survives"
    );
    assert!(controller.receipt_for_test().0.acquired_roots.is_empty());
    let (_, scan) = SelectionFixture::run(state);
    assert!(!scan.census_complete);
    assert!(scan
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    writeln!(std::io::stderr().lock(), "native_comparison_controller: actual_target_replacement_base=true current_native_census_incomplete=true no_acquired_owner_posture=true").unwrap();
}

#[test]
fn native_comparison_failed_target_keeps_dependent_source_unresolved() {
    if !native_positive_layout_for_test(
        "native_comparison_failed_target_keeps_dependent_source_unresolved",
    ) {
        return;
    }
    let (fixture, mut state, mut qualification) = native_comparison_positive_hit_fixture();
    assert_eq!(
        state
            .acquire_native_comparison_targets(&mut qualification)
            .queued,
        2
    );
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    let replacement = fixture.dir.join("acquisition-replacement.tmp");
    fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
    fs::rename(replacement, path).unwrap();
    let mut state = pause_native_comparison(state);
    let acquired = state.take_native_comparison_acquisition(&mut qualification);
    assert_eq!(
        acquired.completed_target_files, 1,
        "only the unchanged child completed"
    );
    assert!(acquired.acquired_roots.is_empty());
    assert!(acquired.ready_for_fold_sources.is_empty());
    assert_eq!(
        acquired.unresolved_sources,
        BTreeSet::from(["c3333333-3333-4333-8333-333333333333".to_owned()])
    );
    assert_eq!(
        acquired.rearm_roots,
        BTreeSet::from([fixture.parent.clone()])
    );
    assert_eq!(acquired.known_rearm_candidates.len(), 2);
    assert!(state
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    state.resume_native_comparison_base();
    let (_, scan) = SelectionFixture::run(state);
    assert!(!scan.census_complete);
    writeln!(std::io::stderr().lock(), "native_comparison_acquisition: queued=2 actual_full_reads=1 unresolved_sources=1 fallback_roots=1 queue_is_not_success=true body_authority_granted=false").unwrap();
}

#[test]
fn native_comparison_ambiguous_index_member_withdraws_frozen_family() {
    let fixture = NativePreparationFixture::new();
    let mut state = fixture.paused();
    let original = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
    let duplicate = fixture
        .dir
        .join("other-project")
        .join(format!("{}.jsonl", fixture.parent));
    fs::create_dir_all(duplicate.parent().unwrap()).unwrap();
    fs::write(&duplicate, fs::read(&original).unwrap()).unwrap();
    // Model an indexed duplicate from an earlier bounded page. The genuine
    // normal-Skip certificates above cannot make ambiguous member paths unique.
    state.index.files.insert(
        local_index_key(&duplicate),
        state.index.files[&original].clone(),
    );
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualified = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualified.certified_member_count(), 0);
    assert!(state.snapshots.is_empty());
}

#[test]
fn native_comparison_family_parse_withdraws_skips_before_and_after_attempt() {
    if !native_positive_layout_for_test(
        "native_comparison_family_parse_withdraws_skips_before_and_after_attempt",
    ) {
        return;
    }
    for parse_child in [false, true] {
        let mut fixture = NativePreparationFixture::new();
        let path = if parse_child {
            fixture
                .dir
                .join(&fixture.parent)
                .join("subagents/agent-a4d1585d310070d0f.jsonl")
        } else {
            fixture.dir.join(format!("{}.jsonl", fixture.parent))
        };
        // Existing durable rearm debt forces a real unchanged native parse.
        // No revision, request, occurrence or retained proof is fabricated.
        fixture
            .index
            .files
            .get_mut(&local_index_key(&path))
            .unwrap()
            .source_file_fingerprint
            .clear();
        let mut state = fixture.paused();
        assert_eq!(state.scanned_file_count, 1);
        assert_eq!(state.snapshots.len(), 1);
        let native_before = serde_json::to_vec(&state.snapshots).unwrap();
        let proof_before = serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap();
        let healthy = BTreeSet::from([fixture.parent.clone()]);
        let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
            api: &fixture.api.evidence,
            trace: &fixture.trace.evidence,
            healthy_roots: &healthy,
        });
        assert_eq!(qualification.certified_member_count(), 0);
        assert!(
            qualification
                .new_native_hashes(&state.snapshots[0])
                .unwrap()
                .is_empty(),
            "revoking negatives must preserve the independently verified pre-mutation Q5 prior"
        );
        assert_eq!(serde_json::to_vec(&state.snapshots).unwrap(), native_before);
        assert_eq!(
            serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap(),
            proof_before
        );
        writeln!(std::io::stderr().lock(), "native_comparison_parse_revocation: actual_unchanged_parse=1 parse_child={parse_child} sibling_negative_members=0 exact_q5_prior_retained=true native_and_proof_unchanged=true crosspage_carry_unwired=true").unwrap();
    }
}

#[test]
fn native_comparison_empty_parse_withdraws_sibling_without_native_body() {
    let fixture = NativePreparationFixture::new();
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    fs::write(&path, "").unwrap();
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 1);
    assert!(
        state.snapshots.is_empty(),
        "the actual parse emitted no body"
    );
    assert_eq!(state.pending_finalization.len(), 1);
    assert!(state.pending_finalization[0].parse_complete);
    let proof_before = serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap();
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(
        qualification.certified_member_count(),
        0,
        "absence of a native body cannot hide the family's actual parse"
    );
    assert_eq!(
        serde_json::to_vec(&state.index.claude_usage_family_witnesses).unwrap(),
        proof_before
    );
    writeln!(std::io::stderr().lock(), "native_comparison_parse_revocation: actual_empty_parse=1 native_bodies=0 sibling_negative_members=0 retained_proof_unchanged=true crosspage_carry_unwired=true").unwrap();
}

struct NativeWindowPage {
    index: ScanIndex,
    scan: SourceScanResult,
    window: Box<claude_native_comparison::WindowEligibility>,
    clean: bool,
}

fn native_window_page(fixture: &NativePreparationFixture) -> NativeWindowPage {
    let mut state = fixture.paused_with_limit(1);
    assert_eq!(state.scanned_file_count, 0);
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 1);
    let mut controller = claude_native_comparison::Controller::new(qualification);
    assert!(controller.advance(&mut state, true));
    let mut window = controller.into_window(&state.census_window_end).unwrap();
    let (mut index, mut scan) = SelectionFixture::run(state);
    assert!(!scan.census_complete);
    assert!(scan.snapshots.is_empty());
    let disposition = apply_claude_reported_usage_with_index(
        &mut scan.snapshots,
        &fixture.api,
        &fixture.trace,
        &mut index,
        scan.census_complete,
        &scan.census_window_end,
    );
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    window.retain_current(&index);
    assert_eq!(window.certified_member_count(), 1);
    let clean = claude_native_comparison::selected_page_is_clean(&scan, &index, &disposition);
    assert!(clean);
    NativeWindowPage {
        index,
        scan,
        window,
        clean,
    }
}

#[test]
fn native_comparison_window_saved_graph_obeys_real_layout_gate() {
    if !native_positive_layout_for_test(
        "native_comparison_window_saved_graph_obeys_real_layout_gate",
    ) {
        // Exercise the actual closed qualifier on this layout, rather than
        // fabricating a positive window merely to price it afterwards.
        let fixture = NativePreparationFixture::new();
        let mut state = fixture.paused_with_limit(1);
        let before = serde_json::to_vec(&state.index).unwrap();
        let healthy = BTreeSet::from([fixture.parent.clone()]);
        let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
            api: &fixture.api.evidence,
            trace: &fixture.trace.evidence,
            healthy_roots: &healthy,
        });
        assert_eq!(
            qualification.certified_member_count(),
            0,
            "unsupported layout mints no certificate"
        );
        assert_eq!(
            serde_json::to_vec(&state.index).unwrap(),
            before,
            "closed qualification adds no persistent debt or selected mutation"
        );
        let owner = claude_native_comparison::lifecycle::Lifecycle::default();
        assert!(!owner.retained_valid_for_test());
        assert_eq!(owner.retained_bound(usize::MAX), Some(0));
        writeln!(std::io::stderr().lock(), "native_comparison_unsupported_BASE: actual_qualification=true certificates=0 selected_index_unchanged=true grant=false empty_retained_bytes=0 positive_window=UNEXECUTED").unwrap();
        return;
    }
    let mut fixture = NativePreparationFixture::new();
    let scratch = crate::test_scratch::ScratchDir::new("native-window-layout");
    let path = scratch.join("index.json");
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut bootstrap = owner.begin();
    bootstrap.bind("window-source-destination-context".into());
    fixture.index.save(&path).unwrap();
    bootstrap.note_selected_save(fixture.native_conjunction);
    bootstrap.finish(true);
    let mut lease = owner.begin();
    lease.bind("window-source-destination-context".into());
    assert!(lease.allowed());
    let mut page = native_window_page(&fixture);
    let pointer = page.window.as_ref() as *const _ as usize;
    page.index.save(&path).unwrap();
    lease.note_selected_save(false);
    lease.stage_window_after_save(Some(page.window), &page.index, page.scan.census_complete);
    lease.finish(page.clean);
    let bound = owner.retained_bound(crate::source_rotation::PARKED_BUDGET);
    if crate::heap_layout_bound::layout_supported() {
        assert!(bound.is_some_and(|bytes| bytes > 0));
        let mut next = owner.begin();
        next.bind("window-source-destination-context".into());
        assert!(next.allowed());
        assert_eq!(
            owner.retained_bound(crate::source_rotation::PARKED_BUDGET),
            Some(0),
            "the moved graph is now frame-owned, not external retention"
        );
        let graph = next.take_window().unwrap();
        assert_eq!(graph.as_ref() as *const _ as usize, pointer);
        assert_eq!(graph.certified_member_count(), 1);
        drop(next);
    } else {
        assert_eq!(
            bound,
            Some(0),
            "unsupported window was dropped before retention; no alternate layout admitted"
        );
        assert!(!owner.retained_valid_for_test());
        owner.discard_retained();
        let mut next = owner.begin();
        next.bind("window-source-destination-context".into());
        assert!(!next.allowed());
        assert!(next.take_window().is_none());
    }
    writeln!(std::io::stderr().lock(), "native_comparison_window: actual_partial_skip=1 actual_selected_save=true requested_layout={bound:?} supported_move_exercised={} full_driver_proved=false", crate::heap_layout_bound::layout_supported()).unwrap();
}

#[test]
fn native_comparison_window_component_reconstructs_same_census_current_rows() {
    if !native_positive_layout_for_test(
        "native_comparison_window_component_reconstructs_same_census_current_rows",
    ) {
        return;
    }
    let mut fixture = NativePreparationFixture::new();
    let page = native_window_page(&fixture);
    fixture.index = page.index;
    let mut next = fixture.paused_with_limit(1);
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = next
        .prepare_native_comparison_with_window(
            claude_native_comparison::PairedRows {
                api: &fixture.api.evidence,
                trace: &fixture.trace.evidence,
                healthy_roots: &healthy,
            },
            Some(page.window),
        )
        .unwrap();
    assert_eq!(qualification.certified_member_count(), 2);
    assert!(next.snapshots.is_empty());
    // A source-component check before lifecycle/budget admission. This cannot
    // establish that the original optimized pipeline or a layout gate passes.
    writeln!(std::io::stderr().lock(), "native_comparison_window: actual_skip_pages=2 current_rows_reconstructed=true component_members=2 lifecycle_budget_admission_proved=false original_oracle_passed=false").unwrap();
}

#[test]
fn native_comparison_window_later_parse_withdraws_carried_sibling() {
    if !native_positive_layout_for_test(
        "native_comparison_window_later_parse_withdraws_carried_sibling",
    ) {
        return;
    }
    let mut fixture = NativePreparationFixture::new();
    let page = native_window_page(&fixture);
    let old_key = page.window.first_key_for_test().unwrap().to_owned();
    fixture.index = page.index;
    let next_key = fixture
        .index
        .files
        .keys()
        .find(|key| **key != old_key)
        .unwrap()
        .clone();
    fixture
        .index
        .files
        .get_mut(&next_key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let mut next = fixture.paused_with_limit(1);
    assert_eq!(next.scanned_file_count, 1);
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = next
        .prepare_native_comparison_with_window(
            claude_native_comparison::PairedRows {
                api: &fixture.api.evidence,
                trace: &fixture.trace.evidence,
                healthy_roots: &healthy,
            },
            Some(page.window),
        )
        .unwrap();
    assert_eq!(qualification.certified_member_count(), 0);
    let window = claude_native_comparison::Controller::new(qualification)
        .into_window(&next.census_window_end)
        .unwrap();
    assert!(window.root_revoked_for_test(&fixture.parent));
    writeln!(std::io::stderr().lock(), "native_comparison_window: actual_later_member_parse=1 carried_sibling_members=0 sticky_tombstone=true full_driver_proved=false").unwrap();
}

#[test]
fn native_comparison_window_proof_membership_empty_or_context_change_withdraws() {
    if !native_positive_layout_for_test(
        "native_comparison_window_proof_membership_empty_or_context_change_withdraws",
    ) {
        return;
    }
    for control in 0..4 {
        let fixture = NativePreparationFixture::new();
        let mut page = native_window_page(&fixture);
        let key = page.window.first_key_for_test().unwrap().to_owned();
        match control {
            0 => {
                page.index
                    .claude_usage_family_witnesses
                    .get_mut(&fixture.parent)
                    .unwrap()
                    .evidence_fingerprint = hex64('f')
            }
            1 => {
                let other = fixture
                    .dir
                    .join(&fixture.parent)
                    .join("subagents/agent-3333333333333333.jsonl");
                page.index
                    .files
                    .insert(local_index_key(&other), page.index.files[&key].clone());
            }
            2 => {
                page.index.confirmed_empty_files.insert(key);
            }
            _ => page.index.active_upload_context_fingerprint = Some("changed-context".into()),
        }
        page.window.retain_current(&page.index);
        assert_eq!(page.window.certified_member_count(), 0);
        assert!(page.window.root_revoked_for_test(&fixture.parent));
    }
}

#[test]
fn native_comparison_window_wrong_window_scope_restart_or_missing_save_is_base() {
    if !native_positive_layout_for_test(
        "native_comparison_window_wrong_window_scope_restart_or_missing_save_is_base",
    ) {
        return;
    }
    let mut fixture = NativePreparationFixture::new();
    let page = native_window_page(&fixture);
    let mut phase = claude_native_comparison::NativePhase::default();
    assert!(!phase.import_window(Some(page.window), &page.index, "different-window"));
    let scratch = crate::test_scratch::ScratchDir::new("native-window-scope");
    let path = scratch.join("index.json");
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut bootstrap = owner.begin();
    bootstrap.bind("original-scope".into());
    fixture.index.save(&path).unwrap();
    bootstrap.note_selected_save(fixture.native_conjunction);
    bootstrap.finish(true);
    let page = native_window_page(&fixture);
    let mut no_save = owner.begin();
    no_save.bind("original-scope".into());
    no_save.stage_window_after_save(Some(page.window), &page.index, false);
    no_save.finish(true);
    assert_eq!(
        owner.retained_bound(crate::source_rotation::PARKED_BUDGET),
        Some(0)
    );
    let mut changed = owner.begin();
    changed.bind("other-scope".into());
    assert!(!changed.allowed());
    assert!(changed.take_window().is_none());
    let restarted = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut fresh = restarted.begin();
    fresh.bind("original-scope".into());
    assert!(!fresh.allowed());
    assert!(fresh.take_window().is_none());
}

#[test]
fn native_comparison_window_scope_change_revokes_a_valid_saved_grant() {
    let mut fixture = NativePreparationFixture::new();
    let scratch = crate::test_scratch::ScratchDir::new("native-window-valid-scope");
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut bootstrap = owner.begin();
    bootstrap.bind("original-scope".into());
    fixture.index.save(&scratch.join("index.json")).unwrap();
    bootstrap.note_selected_save(fixture.native_conjunction);
    bootstrap.finish(true);
    let mut valid = owner.begin();
    valid.bind("original-scope".into());
    assert!(valid.allowed(), "control starts with a valid saved grant");
    valid.note_selected_save(false);
    valid.finish(true);
    let mut changed = owner.begin();
    changed.bind("other-scope".into());
    assert!(!changed.allowed());
    assert!(changed.take_window().is_none());
    changed.note_selected_save(false);
    changed.finish(true);
    let mut rolled_back = owner.begin();
    rolled_back.bind("original-scope".into());
    assert!(
        !rolled_back.allowed(),
        "scope rollback cannot revive permission"
    );
    writeln!(std::io::stderr().lock(), "native_comparison_window_revocation: independently_valid_scope_control=true changed_scope_base=true rolled_back_scope_base=true").unwrap();
}

#[test]
fn native_comparison_window_unknown_lock_and_stale_generation_revoke() {
    if !native_positive_layout_for_test(
        "native_comparison_window_unknown_lock_and_stale_generation_revoke",
    ) {
        return;
    }
    let mut fixture = NativePreparationFixture::new();
    let scratch = crate::test_scratch::ScratchDir::new("native-window-lock-generation");
    let owner = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut bootstrap = owner.begin();
    bootstrap.bind("scope".into());
    fixture.index.save(&scratch.join("index.json")).unwrap();
    bootstrap.note_selected_save(fixture.native_conjunction);
    bootstrap.finish(true);
    let mut outstanding = owner.begin();
    outstanding.bind("scope".into());
    assert!(outstanding.allowed());
    let page = native_window_page(&fixture);
    outstanding.note_selected_save(false);
    outstanding.stage_window_after_save(Some(page.window), &page.index, false);
    owner.with_state_locked_for_test(|| {
        assert_eq!(
            owner.retained_bound(crate::source_rotation::PARKED_BUDGET),
            None
        );
    });
    // Exactly the rotation refusal action, after the failed nonblocking query
    // releases its lock. This also invalidates a graph already moved to a frame.
    owner.discard_retained();
    assert!(!outstanding.allowed());
    assert!(outstanding.take_window().is_none());
    outstanding.note_selected_save(fixture.native_conjunction);
    outstanding.finish(true);
    let mut next = owner.begin();
    next.bind("scope".into());
    assert!(!next.allowed(), "stale finish must not republish a grant");
    assert!(next.take_window().is_none());
    writeln!(std::io::stderr().lock(), "native_comparison_window_revocation: held_lock_bound=None whole_window_discard=true stale_generation_cannot_republish=true").unwrap();
}

#[test]
fn native_comparison_window_missing_current_rows_withdraws_until_window_end() {
    if !native_positive_layout_for_test(
        "native_comparison_window_missing_current_rows_withdraws_until_window_end",
    ) {
        return;
    }
    for control in 0..3 {
        let mut fixture = NativePreparationFixture::new();
        let page = native_window_page(&fixture);
        fixture.index = page.index;
        let mut next = fixture.paused_with_limit(1);
        let healthy = if control == 2 {
            BTreeSet::new()
        } else {
            BTreeSet::from([fixture.parent.clone()])
        };
        let mut api = fixture.api.evidence.clone();
        let mut trace = fixture.trace.evidence.clone();
        if control == 0 {
            api.remove(&fixture.parent);
        }
        if control == 1 {
            trace.remove(&fixture.parent);
        }
        let qualification = next
            .prepare_native_comparison_with_window(
                claude_native_comparison::PairedRows {
                    api: &api,
                    trace: &trace,
                    healthy_roots: &healthy,
                },
                Some(page.window),
            )
            .unwrap();
        assert_eq!(qualification.certified_member_count(), 0);
        let window = claude_native_comparison::Controller::new(qualification)
            .into_window(&next.census_window_end)
            .unwrap();
        assert!(window.root_revoked_for_test(&fixture.parent));
        let mut retry = fixture.paused_with_limit(1);
        let healthy = BTreeSet::from([fixture.parent.clone()]);
        let recovered_rows = retry
            .prepare_native_comparison_with_window(
                claude_native_comparison::PairedRows {
                    api: &fixture.api.evidence,
                    trace: &fixture.trace.evidence,
                    healthy_roots: &healthy,
                },
                Some(window),
            )
            .unwrap();
        assert_eq!(
            recovered_rows.certified_member_count(),
            0,
            "a later healthy reconstruction cannot undo a same-window withdrawal"
        );
    }
    writeln!(std::io::stderr().lock(), "native_comparison_window_revocation: current_api_missing_base=true current_trace_missing_base=true unhealthy_pair_base=true later_rows_cannot_revive=true").unwrap();
}

#[test]
fn native_comparison_window_any_authority_quarantine_withdraws() {
    if !native_positive_layout_for_test(
        "native_comparison_window_any_authority_quarantine_withdraws",
    ) {
        return;
    }
    for corrected in [false, true] {
        let fixture = NativePreparationFixture::new();
        let mut page = native_window_page(&fixture);
        let witness = &page.index.claude_usage_family_witnesses[&fixture.parent];
        let digest = claude_usage_family_witness_fingerprint(witness);
        let members = witness
            .member_request_id_fingerprints
            .keys()
            .map(|member| {
                let key = page
                    .index
                    .files
                    .keys()
                    .find(|key| {
                        claude_index_path_family_member(Path::new(key))
                            .is_some_and(|(_, current)| current == *member)
                    })
                    .unwrap();
                (
                    member.clone(),
                    page.index.files[key].source_file_fingerprint.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        page.index.claude_usage_authority_quarantine.insert(
            fixture.parent.clone(),
            ClaudeUsageAuthorityQuarantineRecord {
                contract: if corrected {
                    CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION
                } else {
                    CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION
                }
                .into(),
                proven_witness_fingerprint: digest.clone(),
                member_source_file_fingerprints: members.clone(),
                failed_reconstruction_count: MAX_CLAUDE_USAGE_AUTHORITY_FAILURES,
                disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
                retry_after_unix_seconds: claude_usage_authority_retry_deadline(
                    &fixture.parent,
                    &digest,
                ),
                proof_correction: corrected.then(|| ClaudeAuthorityProofCorrection {
                    proof_witness_fingerprint: digest,
                    owed_member_ids: members.into_keys().collect(),
                }),
            },
        );
        page.window.retain_current(&page.index);
        assert_eq!(page.window.certified_member_count(), 0);
        assert!(page.window.root_revoked_for_test(&fixture.parent));
    }
    writeln!(std::io::stderr().lock(), "native_comparison_window_revocation: terminal_quarantine_base=true proof_correction_quarantine_base=true accepted_body_or_debt_unchanged=true").unwrap();
}

// The same actual scanner/controller and selected-save seams used by finish.
// A/D share an exact native ID; the healthy C body has independent requests.
const FALLBACK_COPY: &str = "c3333333-3333-4333-8333-333333333333";
const FALLBACK_PEER: &str = "d4444444-4444-4444-8444-444444444444";
const FALLBACK_HEALTHY: &str = "e5555555-5555-4555-8555-555555555555";
fn native_comparison_selected_fallback_fixture() -> (
    NativePreparationFixture,
    ScanIndex,
    SourceScanResult,
    claude_native_comparison::SelectedFallback,
    ScanIndex,
    PathBuf,
) {
    let mut fixture = NativePreparationFixture::new();
    for (session, request) in [
        (FALLBACK_COPY, "req_1"),
        (FALLBACK_PEER, "req_1"),
        (FALLBACK_HEALTHY, "req_healthy"),
    ] {
        fs::write(fixture.dir.join(format!("{session}.jsonl")), format!("{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n")).unwrap();
    }
    let copy_key = local_index_key(&fixture.dir.join(format!("{FALLBACK_COPY}.jsonl")));
    let mut old = fixture.index.files.values().next().unwrap().clone();
    let old_head = format!("{:064x}", 58801);
    old.source_file_fingerprint = format!("{:064x}", 58802);
    old.last_snapshot_fingerprint = Some(old_head.clone());
    old.last_upload_body_witness = Some(format!("{:064x}", 58803));
    fixture.index.files.insert(copy_key.clone(), old);
    fixture
        .index
        .file_snapshot_fingerprints
        .insert(copy_key, BTreeSet::from([old_head.clone()]));
    fixture
        .index
        .accepted_snapshot_fingerprints
        .insert(old_head.clone());
    fixture
        .index
        .snapshot_activity_at
        .insert(old_head, Some(WINDOW.to_owned()));
    let path = fixture.dir.join("selected-index.json");
    fixture.index.save(&path).unwrap();
    fixture.index = ScanIndex::load(&path).unwrap();
    // The selected upload context is runtime-only. Real preparation activates
    // it after load; a missing context correctly reparses both proven members.
    fixture
        .index
        .activate_upload_context("native-preparation-test".to_owned());
    let previous = fixture.index.clone();
    let mut state = fixture.paused();
    assert_eq!(state.scanned_file_count, 3);
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 2);
    // Exhaust the existing page budget, without changing any scope or cap.
    state.file_limit = state.scanned_file_count;
    let mut controller = claude_native_comparison::Controller::new(qualification);
    assert!(!controller.advance(&mut state, true));
    let (mut index, mut scan, terminal) = loop {
        match state.step(None) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete {
                index,
                scan,
                terminal_native_traversal,
            } => break (index, scan, terminal_native_traversal),
        }
    };
    assert!(scan.census_complete);
    assert!(
        terminal.is_some(),
        "failed comparison still MOVES the actual terminal traversal"
    );
    let completion = controller.complete(&scan, terminal, false).unwrap();
    assert!(completion.window.is_none());
    let fallback = completion.fallback.unwrap();
    let observed = record_claude_native_observations(&scan, &mut index);
    fallback.withhold(&mut scan);
    assert!(scan
        .snapshots
        .iter()
        .all(|item| item.source_session_id == FALLBACK_HEALTHY));
    let disposition = apply_claude_reported_usage_to_scan_with_observations(
        &mut scan,
        &fixture.api,
        &fixture.trace,
        &mut index,
        None,
        Some(observed),
    );
    let shared = format!("{:x}", Sha256::digest(b"req_1"));
    let owners = index.claude_duplicate_request_owners.get(&shared).unwrap();
    assert!(owners.contains(&claude_duplicate_request_owner(
        FALLBACK_COPY,
        FALLBACK_COPY
    )));
    assert!(owners.contains(&claude_duplicate_request_owner(
        FALLBACK_PEER,
        FALLBACK_PEER
    )));
    assert!(
        disposition.duplicate_census.census_complete,
        "raw-native terminal decision reaches the ONE fold"
    );
    fallback.after_native_fold(&mut scan, &mut index);
    assert!(!scan.census_complete);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    (fixture, index, scan, fallback, previous, path)
}

#[test]
fn native_comparison_selected_fallback_preserves_prior_body_and_queues_native_before_copies() {
    if !native_positive_layout_for_test(
        "native_comparison_selected_fallback_preserves_prior_body_and_queues_native_before_copies",
    ) {
        return;
    }
    let (fixture, mut index, scan, mut fallback, previous, path) =
        native_comparison_selected_fallback_fixture();
    let key = local_index_key(&fixture.dir.join(format!("{FALLBACK_COPY}.jsonl")));
    let old = serde_json::to_vec(&previous.files[&key]).unwrap();
    fallback.restore_selected(&mut index, &previous).unwrap();
    assert_eq!(serde_json::to_vec(&index.files[&key]).unwrap(), old);
    assert_eq!(
        index.file_snapshot_fingerprints[&key],
        previous.file_snapshot_fingerprints[&key]
    );
    let traversal = index.traversal.as_ref().unwrap();
    let queued = traversal
        .pending_candidates
        .iter()
        .map(|p| local_index_key(&p.path))
        .collect::<Vec<_>>();
    assert_eq!(queued.len(), 4);
    assert!(queued[..2]
        .iter()
        .all(|key| claude_index_path_family_member(Path::new(key)).unwrap().0 == fixture.parent));
    assert!(queued[2..].iter().any(|k| k == &key));
    assert!(index.bounded_sweep_had_unsettled_upload());
    index.save(&path).unwrap();
    let restored = ScanIndex::load(&path).unwrap();
    assert_eq!(serde_json::to_vec(&restored.files[&key]).unwrap(), old);
    assert!(scan
        .snapshots
        .iter()
        .all(|item| item.source_session_id == FALLBACK_HEALTHY));
    writeln!(std::io::stderr().lock(), "native_comparison_selected_fallback: actual_native_copy_peer_observed=true healthy_body_retained=true old_body_accepted_ledger_unchanged=true terminal_graph_moved=true native_targets_before_BC=true normal_save_reload=true parked_schema=false").unwrap();
}

/// Diagnostics only: the comparison fallback's fold and its selected restore
/// each mark the sweep without naming a path, so both name `unattributed`,
/// also beside a named page cause and across a reload.
#[test]
fn native_comparison_fallback_marks_name_unattributed() {
    if !native_positive_layout_for_test("native_comparison_fallback_marks_name_unattributed") {
        return;
    }
    let (_fixture, mut index, _scan, mut fallback, previous, path) =
        native_comparison_selected_fallback_fixture();
    assert!(index.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        index.bounded_sweep_unsettled_cause_names(),
        ["unattributed"]
    );
    // Isolate the restore's own mark.
    index.bounded_sweep_had_unsettled_upload = false;
    index.bounded_sweep_unsettled_causes = 0;
    fallback.restore_selected(&mut index, &previous).unwrap();
    assert!(index.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        index.bounded_sweep_unsettled_cause_names(),
        ["unattributed"]
    );
    index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::Shed);
    index.save(&path).unwrap();
    let restored = ScanIndex::load(&path).unwrap();
    assert_eq!(
        restored.bounded_sweep_unsettled_cause_names(),
        ["shed", "unattributed"]
    );
}

/// Slice D1 (TD1b, SOURCE #588): a selected restore reverts the withheld key
/// to `previous` and REMOVES its request-census record. No record of the
/// withheld revision, and none restored from `previous`, survives.
#[test]
fn native_comparison_selected_restore_removes_the_withheld_census_record() {
    if !native_positive_layout_for_test(
        "native_comparison_selected_restore_removes_the_withheld_census_record",
    ) {
        return;
    }
    let (fixture, mut index, _scan, mut fallback, mut previous, _path) =
        native_comparison_selected_fallback_fixture();
    let key = local_index_key(&fixture.dir.join(format!("{FALLBACK_COPY}.jsonl")));
    let record = |seed: char| {
        claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
            &seed.to_string().repeat(64),
            1,
            claude_request_census::ClaudeRequestCensusShape::Exact,
            vec![1],
        )
    };
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, record('a'));
    previous
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, record('b'));
    fallback.restore_selected(&mut index, &previous).unwrap();
    assert_eq!(
        serde_json::to_vec(&index.files[&key]).unwrap(),
        serde_json::to_vec(&previous.files[&key]).unwrap()
    );
    assert!(index.claude_request_census_for_test().get(&key).is_none());
}

#[test]
fn native_comparison_selected_fallback_partial_locked_save_and_restart_keep_exact_debt() {
    if !native_positive_layout_for_test(
        "native_comparison_selected_fallback_partial_locked_save_and_restart_keep_exact_debt",
    ) {
        return;
    }
    let (fixture, index, scan, mut fallback, previous, path) =
        native_comparison_selected_fallback_fixture();
    let progress = fixture.dir.join("partial-progress.json");
    let selected = crate::snapshot_sync::comparison_partial_fallback_for_test(
        &index,
        &previous,
        &scan,
        &mut fallback,
        &path,
        &progress,
    )
    .unwrap();
    let key = local_index_key(&fixture.dir.join(format!("{FALLBACK_COPY}.jsonl")));
    assert_eq!(
        serde_json::to_vec(&selected.files[&key]).unwrap(),
        serde_json::to_vec(&previous.files[&key]).unwrap()
    );
    let new_key = local_index_key(&fixture.dir.join(format!("{FALLBACK_PEER}.jsonl")));
    assert!(
        !selected.files.contains_key(&new_key),
        "never-accepted copy has no committed entry or empty marker"
    );
    assert!(!selected.confirmed_empty_files.contains(&new_key));
    assert!(selected.bounded_sweep_had_unsettled_upload());
    let restarted = ScanIndex::load(&path).unwrap();
    assert_eq!(
        restarted
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .len(),
        4
    );
    assert!(!claude_native_comparison::lifecycle::Lifecycle::default().retained_valid_for_test());
    writeln!(std::io::stderr().lock(), "native_comparison_partial_fallback: actual_progress_lock_selected_restore_CAS_save=true old_accepted_body_preserved=true new_copy_uncommitted=true no_empty_or_fake_hold=true native_priority_survives_reload=true restart_base=true").unwrap();
}

#[test]
fn native_comparison_selected_fallback_cas_loss_and_wrong_window_never_commit() {
    if !native_positive_layout_for_test(
        "native_comparison_selected_fallback_cas_loss_and_wrong_window_never_commit",
    ) {
        return;
    }
    let (_fixture, mut index, _scan, mut fallback, previous, path) =
        native_comparison_selected_fallback_fixture();
    let mut winner = previous.clone();
    winner.save(&path).unwrap();
    let durable = fs::read(&path).unwrap();
    fallback.restore_selected(&mut index, &previous).unwrap();
    assert!(index.save(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), durable);
    index.traversal.as_mut().unwrap().census_window_end = "different-window".into();
    assert!(fallback.restore_selected(&mut index, &previous).is_err());
    assert_eq!(fs::read(&path).unwrap(), durable);
    writeln!(std::io::stderr().lock(), "native_comparison_fallback_failure: actual_index_CAS_loser_preserves_winner=true wrong_window_refused=true no_checkpoint_or_offer_success=true").unwrap();
}

/// Complete only the remaining physical cursor before a SECOND component
/// parse. The first corrective page selected the parent with limit1; the child
/// is still queued. Clearing the parent's debt does not inject it into that
/// older queue. Use the real unchanged child traversal, never reset its fields
/// or assert a second parent read before it can actually be selected. This
/// data-level helper mints no proof, native receipt, ACK or lifecycle grant.
fn finish_native_receipt_component_cursor(fixture: &mut NativePreparationFixture) {
    for _ in 0..8 {
        if fixture.index.traversal.is_none() {
            return;
        }
        let native = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.dir),
            fixture.index.clone(),
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
        let (index, scan) = SelectionFixture::run(native);
        assert_eq!(
            scan.scanned_file_count, 0,
            "only the existing unchanged cursor tail is consumed"
        );
        assert!(scan.snapshots.is_empty() && scan.pending_finalization.is_empty());
        assert_eq!(
            index.claude_usage_family_witnesses,
            fixture.index.claude_usage_family_witnesses
        );
        assert_eq!(
            index.accepted_snapshot_fingerprints,
            fixture.index.accepted_snapshot_fingerprints
        );
        fixture.index = index;
    }
    panic!("native receipt component cursor did not terminate");
}

fn native_comparison_corrected_native_receipt_fixture(
    mode: &str,
) -> (
    NativePreparationFixture,
    ScanIndex,
    Option<Box<claude_native_comparison::WindowEligibility>>,
) {
    let mut fixture = if mode == "noop" {
        let (mut fixture, accepted, _) =
            native_comparison_corrected_native_receipt_fixture("exact_ack");
        fixture.index = accepted; // Actual prior validated ACK and durable save.
        finish_native_receipt_component_cursor(&mut fixture);
        fixture
    } else {
        NativePreparationFixture::new()
    };
    let key = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
    fixture
        .index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let previous = fixture.index.clone();
    let mut state = fixture.paused_with_limit(1);
    assert_eq!(
        state.scanned_file_count, 1,
        "actual native correction read, not a seeded Skip"
    );
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    let mut controller = claude_native_comparison::Controller::new(qualification);
    assert!(controller.advance(&mut state, true));
    let (mut index, mut scan) = SelectionFixture::run(state);
    assert!(
        !scan.census_complete,
        "an earlier bounded page, before terminal rearm"
    );
    let mut completion = controller.complete(&scan, None, true).unwrap();
    let disposition = apply_claude_reported_usage_to_scan_with_identity(
        &mut scan,
        &fixture.api,
        &fixture.trace,
        &mut index,
        None,
    );
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(
        scan.snapshots[0].usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    if mode == "credit_refused" {
        completion.attach_reservation(crate::source_rotation::PaidReservation::from_remainder(
            Some(0),
            0,
            0,
        ));
        // Synchronous on this thread (no spawn, channel or pool in the call
        // chain): thread-local accounting counts the same allocation events
        // and excludes unrelated tests' allocations in parallel hosted runs.
        let (_, allocation) = crate::retry_allocation_probe::measure(|| {
            completion.prepare_native_corrections(&scan, &previous, &disposition)
        });
        assert_eq!(
            allocation.allocations, 0,
            "declined optional correction metadata allocates nothing"
        );
        assert_eq!(completion.pending_native_correction_count_for_test(), 0);
    } else {
        completion.prepare_native_corrections(&scan, &previous, &disposition);
    }
    for item in &mut scan.snapshots {
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    }
    assert_eq!(
        completion.native_correction_count_for_test(),
        0,
        "parse/capture never mints a receipt"
    );
    let offered = scan.snapshots.clone();
    let witnesses = offered
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut baseline_scan = scan.clone();
    let mut baseline_index = index.clone();
    let mut baseline_projections = 0;
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut baseline_scan,
        &mut baseline_index,
        |snapshot| {
            baseline_projections += 1;
            snapshot_upload_body_witness(snapshot)
        },
    );
    let mut observed_projections = 0;
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut scan,
        &mut index,
        |snapshot| {
            observed_projections += 1;
            let witness = snapshot_upload_body_witness(snapshot);
            completion.observe_native_correction(snapshot, &witness);
            witness
        },
    );
    assert_eq!(
        observed_projections, baseline_projections,
        "native receipts add no upload-body serialization"
    );
    assert_eq!(
        serde_json::to_vec(&scan.snapshots).unwrap(),
        serde_json::to_vec(&baseline_scan.snapshots).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&index).unwrap(),
        serde_json::to_vec(&baseline_index).unwrap()
    );

    if mode == "capture_only" {
        return (fixture, index, completion.window);
    }
    if matches!(mode, "exact_ack" | "wrong_witness" | "credit_refused") {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "claude_code".to_owned(),
            machine_id: "otm_native_receipt".to_owned(),
            collector_version: None,
            snapshots: offered,
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let refs=request.snapshots.iter().map(|item| {
            let version=crate::snapshot_client::snapshot_ack_body_witness_version(item).expect("production public ACK mapping");
            serde_json::json!({"source_session_id":item.source_session_id,
                "snapshot_fingerprint":item.snapshot_fingerprint,"occurrence_count":1,
                "body_witness_version":version,
                "body_witness_digest":version.map(|_|if mode=="wrong_witness" {"f".repeat(64)}else{snapshot_upload_body_witness(item)}),
            })
        }).collect::<Vec<_>>();
        let response:crate::snapshot_client::SnapshotBatchResponse=serde_json::from_value(serde_json::json!({
            "accepted":request.snapshots.len(),"sessions_reconciled":request.snapshots.len(),
            "session_ids":[],"disabled":false,"disabled_reason":null,"entity_ack_contract":"snapshot_entity_ack:v1",
            "accepted_entities":refs,"unchanged_entities":[],"rejected_entities":[],"conflict_entities":[],
        })).unwrap();
        let validation = response.validate_entity_ack(&request);
        if mode == "wrong_witness" {
            assert!(
                validation.is_err(),
                "same fp with a different body witness is not an ACK"
            );
        } else {
            validation.unwrap();
            let accepted = witnesses.keys().cloned().collect();
            index.record_accepted_snapshot_fingerprints(&accepted);
        }
    }
    if mode == "noop" {
        assert_eq!(
            previous.files[&key].last_upload_body_witness,
            index.files[&key].last_upload_body_witness,
            "no-op must be the exact previously ACKed grouped body"
        );
    }
    let path = fixture.dir.join("native-correction-selected.json");
    index.save(&path).unwrap();
    completion.note_native_corrections_after_save(&index, &previous, |fp, witness| match mode {
        "refused" => None,
        "exact_ack" | "credit_refused" => {
            Some(witnesses.get(fp).is_some_and(|actual| actual == witness))
        }
        _ => Some(false),
    });
    let expected = usize::from(matches!(mode, "exact_ack" | "noop"));
    assert_eq!(completion.native_correction_count_for_test(), expected);
    assert!(serde_json::to_value(&index)
        .unwrap()
        .get("native_corrections")
        .is_none());
    writeln!(std::io::stderr().lock(),"native_comparison_native_receipt: mode={mode} actual_native_read=true frozen_proof=true body_ACK_validator_executed={} prior_exact_ACK={} selected_save=true minted={expected} Skip_or_envelope=false layout_admission=false", matches!(mode,"exact_ack"|"wrong_witness"),mode=="noop").unwrap();
    (fixture, index, completion.window)
}

#[test]
fn native_comparison_native_receipt_requires_exact_ack_or_accepted_noop_after_selected_save() {
    // Legacy reported-body proof/delivery; E2 publishes a request-owned literal instead.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !native_positive_layout_for_test(
        "native_comparison_native_receipt_requires_exact_ack_or_accepted_noop_after_selected_save",
    ) {
        return;
    }
    for mode in [
        "capture_only",
        "credit_refused",
        "pending",
        "wrong_witness",
        "refused",
        "exact_ack",
        "noop",
    ] {
        native_comparison_corrected_native_receipt_fixture(mode);
    }
}

#[test]
fn native_comparison_native_receipt_proof_revision_reparse_and_restart_are_base() {
    // Legacy reported-body proof/delivery; E2 publishes a request-owned literal instead.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !native_positive_layout_for_test(
        "native_comparison_native_receipt_proof_revision_reparse_and_restart_are_base",
    ) {
        return;
    }
    for change in ["proof", "revision"] {
        let (fixture, mut index, window) =
            native_comparison_corrected_native_receipt_fixture("exact_ack");
        let mut window = window.unwrap();
        assert_eq!(window.native_correction_count_for_test(), 1);
        if change == "proof" {
            index
                .claude_usage_family_witnesses
                .get_mut(&fixture.parent)
                .unwrap()
                .evidence_fingerprint = "a different proof".to_owned();
        } else {
            let key = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
            index.files.get_mut(&key).unwrap().source_file_fingerprint = "f".repeat(64);
        }
        window.retain_current(&index);
        assert_eq!(window.native_correction_count_for_test(), 0);
    }
    let (mut fixture, index, window) =
        native_comparison_corrected_native_receipt_fixture("exact_ack");
    fixture.index = index;
    finish_native_receipt_component_cursor(&mut fixture);
    let key = local_index_key(&fixture.dir.join(format!("{}.jsonl", fixture.parent)));
    fixture
        .index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let mut state = fixture.paused_with_limit(1);
    assert_eq!(state.scanned_file_count, 1);
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let qualification = state
        .prepare_native_comparison_with_window(
            claude_native_comparison::PairedRows {
                api: &fixture.api.evidence,
                trace: &fixture.trace.evidence,
                healthy_roots: &healthy,
            },
            window,
        )
        .unwrap();
    let controller = claude_native_comparison::Controller::new(qualification);
    let window = controller.into_window(&state.census_window_end).unwrap();
    assert_eq!(
        window.native_correction_count_for_test(),
        0,
        "even same-revision native reparse revokes the old receipt"
    );
    let restarted = Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut lease = restarted.begin();
    lease.bind("same-source-destination-context".to_owned());
    assert!(!lease.allowed());
    assert!(lease.take_window().is_none());
    writeln!(std::io::stderr().lock(),"native_comparison_native_receipt_revocation: changed_P_base=true changed_R_base=true same_R_reparse_drops=true restart_no_disk_receipt=true no_Skip_or_coverage_claim=true").unwrap();
}

#[test]
fn native_comparison_default_constructor_honors_durable_queue_debt_prefix_before_audits() {
    let fixture = SelectionFixture::new();
    let mut index = fixture.previous.clone();
    index
        .files
        .get_mut(&local_index_key(&fixture.paths[0]))
        .unwrap()
        .source_file_fingerprint
        .clear();
    index.save(&fixture.index_path).unwrap();
    let index = ScanIndex::load(&fixture.index_path).unwrap();
    let base = fixture.prepare(index.clone(), 1);
    assert_eq!(base.identified_candidates[0].path, fixture.paths[1]);
    let _scope = claude_native_comparison::enable_for_test();
    let native = fixture.prepare(index, 1); // ordinary constructor, NO supplied recovery list
    assert_eq!(native.identified_candidates.len(), 1);
    assert_eq!(native.identified_candidates[0].path, fixture.paths[0]);
    let (index, scan) = SelectionFixture::run(native);
    assert_eq!(scan.scanned_file_count, 1);
    assert!(index.files[&local_index_key(&fixture.paths[1])]
        .audit_requires_full(sampled_scan::now_seconds()));
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|p| p.path == fixture.paths[1]));
    writeln!(std::io::stderr().lock(),"native_comparison_default_recovery_priority: actual_save_reload=true ordinary_constructor=true no_process_recovery_list=true known_empty_fp_queue_prefix_before_audits=true same_page_cap=true audit_debt_preserved=true no_new_native_eligibility=true").unwrap();
}

#[test]
fn native_comparison_deferred_policy_unknown_native_is_base_without_new_debt() {
    if !native_positive_layout_for_test(
        "native_comparison_deferred_policy_unknown_native_is_base_without_new_debt",
    ) {
        return;
    }
    let fixture = NativePreparationFixture::new();
    let mut state = fixture.paused();
    let healthy = BTreeSet::from([fixture.parent.clone()]);
    let mut qualification = state.prepare_native_comparison(claude_native_comparison::PairedRows {
        api: &fixture.api.evidence,
        trace: &fixture.trace.evidence,
        healthy_roots: &healthy,
    });
    assert_eq!(qualification.certified_member_count(), 2);
    let path = fixture.dir.join(format!("{}.jsonl", fixture.parent));
    let mut generic = parse_claude_code_jsonl_file(&path, WINDOW, hex64('e'))
        .unwrap()
        .remove(0);
    generic.source_session_id = "generic-unproven-input".into();
    generic.claude_usage_request_ids.clear();
    assert!(generic.request_count > 0);
    let before_body = serde_json::to_vec(&generic).unwrap();
    let before_index = serde_json::to_value(&fixture.index).unwrap();
    let owner = std::sync::Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
    let mut lease = owner.begin();
    lease.bind("logical-policy-decision-only".into());
    assert!(
        !lease.allowed(),
        "this regression never fabricates a bootstrap grant"
    );
    let mut credit = crate::source_rotation::PaidReservation::from_remainder(
        Some(crate::source_rotation::PARKED_BUDGET),
        crate::heap_layout_bound::completed_bound(&qualification, usize::MAX).unwrap()
            - std::mem::size_of_val(&qualification),
        crate::heap_layout_bound::completed_bound(&qualification, usize::MAX).unwrap()
            - std::mem::size_of_val(&qualification),
    );
    let (targets, selection) = qualification
        .take_target_candidates_after(
            std::slice::from_ref(&generic),
            0,
            0,
            &[],
            8,
            Some(&mut claude_native_comparison::RecoveryBudget {
                previous: &fixture.index,
                credit: &mut credit,
                lease: &mut lease,
            }),
        )
        .unwrap();
    assert!(selection.requires_base);
    assert!(targets.is_empty() && selection.unresolved_sources.is_empty());
    assert_eq!(owner.status().deferred_family_count, Some(0));
    assert_eq!(serde_json::to_vec(&generic).unwrap(), before_body);
    assert_eq!(serde_json::to_value(&fixture.index).unwrap(), before_index);
    eprintln!("native_comparison_deferred_unknown: decision_only=true unknown_ids_not_positive=true BASE_required=true new_debt=0 body_index_unchanged=true bootstrap_grant=false physical_liveness_claim=false");
}

#[test]
fn native_comparison_matching_prepays_hit_and_no_hit_before_scratch_allocation() {
    if !native_positive_layout_for_test(
        "native_comparison_matching_prepays_hit_and_no_hit_before_scratch_allocation",
    ) {
        return;
    }
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    for (hit, pressure, unknown) in [
        (false, true, false),
        (true, true, false),
        (true, false, true),
        (false, false, false),
        (true, false, false),
    ] {
        let fixture = NativePreparationFixture::new();
        let mut state = fixture.paused();
        let healthy = BTreeSet::from([fixture.parent.clone()]);
        let mut qualification =
            state.prepare_native_comparison(claude_native_comparison::PairedRows {
                api: &fixture.api.evidence,
                trace: &fixture.trace.evidence,
                healthy_roots: &healthy,
            });
        assert_eq!(qualification.certified_member_count(), 2);
        let mut item = parse_claude_code_jsonl_file(
            &fixture.dir.join(format!("{}.jsonl", fixture.parent)),
            WINDOW,
            hex64('e'),
        )
        .unwrap()
        .remove(0);
        item.source_session_id = "new-copy".into();
        if !hit {
            item.claude_usage_request_ids.clear();
            item.claude_usage_request_ids
                .insert("unique-request".into());
            item.request_count = 1;
        }
        let body_before = serde_json::to_vec(&item).unwrap();
        let mut before = Counter::new(usize::MAX);
        qualification.completed_heap_bound(&mut before).unwrap();
        let recovery_bytes = 512;
        let limit = if pressure {
            before.bytes + recovery_bytes
        } else {
            crate::source_rotation::PARKED_BUDGET
        };
        let mut paid = crate::source_rotation::PaidReservation::from_remainder(
            Some(limit),
            before.bytes,
            before.bytes,
        );
        assert!(paid.as_mut().unwrap().reserve_recovery(recovery_bytes));
        if unknown {
            paid.as_mut().unwrap().at_turn(None);
        }
        let owner = std::sync::Arc::new(claude_native_comparison::lifecycle::Lifecycle::default());
        let mut lease = owner.begin();
        lease.bind("logical-matching-budget".into());
        let (outcome, allocations) = crate::retry_allocation_probe::measure(|| {
            qualification.take_target_candidates_after(
                std::slice::from_ref(&item),
                0,
                0,
                &[],
                8,
                Some(&mut claude_native_comparison::RecoveryBudget {
                    previous: &fixture.index,
                    credit: &mut paid,
                    lease: &mut lease,
                }),
            )
        });
        if pressure || unknown {
            assert!(outcome.is_err());
            assert_eq!(
                allocations.allocations, 0,
                "refuse before hash/Q5/group allocation, even without a hit"
            );
            assert_eq!(qualification.certified_member_count(), 2);
            assert_eq!(paid.as_ref().unwrap().allocated(), before.bytes);
        } else {
            let (targets, selection) = outcome.unwrap();
            assert!(targets.is_empty());
            assert_eq!(selection.matched_roots > 0, hit);
            assert_eq!(!selection.unresolved_sources.is_empty(), hit);
            if !hit {
                let mut after = Counter::new(usize::MAX);
                qualification.completed_heap_bound(&mut after).unwrap();
                targets.completed_heap_bound(&mut after).unwrap();
                selection.completed_heap_bound(&mut after).unwrap();
                assert_eq!(
                    paid.as_ref().unwrap().allocated(),
                    after.bytes,
                    "scratch is released; only the conservative returned graph remains charged"
                );
            }
        }
        assert_eq!(
            paid.as_ref().unwrap().recovery_bytes_for_test(),
            recovery_bytes
        );
        assert_eq!(serde_json::to_vec(&item).unwrap(), body_before);
        eprintln!("native_comparison_matching_budget: hit={hit} pressure={pressure} unknown={unknown} refused_before_alloc={} protected_recovery={recovery_bytes} input_unchanged=true", pressure || unknown);
    }
}

#[test]
fn account_audit_release_waits_for_cache_heads_and_native_selected_restore() {
    if !native_positive_layout_for_test(
        "account_audit_release_waits_for_cache_heads_and_native_selected_restore",
    ) {
        return;
    }
    for partial in [false, true] {
        let (fixture, mut index, mut scan, mut fallback, mut previous, path) =
            native_comparison_selected_fallback_fixture();
        assert!(
            index.traversal.is_none(),
            "terminal is held by SelectedFallback"
        );
        let key = local_index_key(&fixture.dir.join(format!("{FALLBACK_HEALTHY}.jsonl")));
        assert!(index.files.contains_key(&key));
        let entry = index.files[&key].clone();
        previous.files.insert(key.clone(), entry.clone());
        previous
            .file_snapshot_fingerprints
            .insert(key.clone(), index.file_snapshot_fingerprints[&key].clone());
        previous
            .claude_account_deferred_holds
            .insert(key.clone(), entry.source_file_fingerprint.clone());
        index
            .claude_account_deferred_holds
            .insert(key.clone(), entry.source_file_fingerprint.clone());
        for n in 0..crate::transcript_cache::CACHE_ENTRIES {
            let audit_key = format!("/synthetic-unavailable-release/{n}.jsonl");
            let mut audit_entry = entry.clone();
            audit_entry.set_unverified_deadline(1);
            index.files.insert(audit_key.clone(), audit_entry.clone());
            previous.files.insert(audit_key, audit_entry);
        }
        // No optional copy remains: the same release path must preserve
        // unknown acquisition custody without touching the retained terminal.
        let cache = sampled_scan::SharedCache::default();
        let selected = if partial {
            let progress = fixture.dir.join("released-fallback-progress.json");
            crate::snapshot_sync::checkpoint_account_release_for_test(
                index,
                &previous,
                &mut scan,
                &cache,
                std::slice::from_ref(&fixture.dir),
                &mut fallback,
                (&path, &progress),
            )
            .unwrap()
        } else {
            let mut selected = crate::snapshot_sync::accept_account_release_for_test(
                index,
                &previous,
                &mut scan,
                &cache,
                std::slice::from_ref(&fixture.dir),
                Some(&mut fallback),
            );
            selected.save(&path).unwrap();
            selected
        };
        assert!(!selected.claude_account_deferred_holds.contains_key(&key));
        assert!(selected.files[&key].source_file_fingerprint.is_empty());
        assert_eq!(
            selected
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            crate::transcript_cache::CACHE_ENTRIES
        );
        let copy = local_index_key(&fixture.dir.join(format!("{FALLBACK_COPY}.jsonl")));
        assert_eq!(
            serde_json::to_value(&selected.files[&copy]).unwrap(),
            serde_json::to_value(&previous.files[&copy]).unwrap(),
            "fallback retains prior copy"
        );
        let restarted = ScanIndex::load(&path).unwrap();
        assert!(restarted.files[&key].source_file_fingerprint.is_empty());
        assert!(restarted
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .any(|candidate| local_index_key(&candidate.path) == key));
        if partial {
            assert!(restarted.bounded_sweep_had_unsettled_upload());
        }
    }
}

#[test]
fn ownership_diagnostics_preserve_real_claude_terminal_completed_heap_and_paid_completion() {
    let fixture = NativePreparationFixture::new();
    let (_, scan, terminal) = complete_native_with_terminal_owner(fixture.paused());
    assert!(scan.census_complete);
    assert!(scan.causes.is_empty(), "exercise the empty diagnostic case");
    let terminal = terminal.expect("actual clean Claude terminal traversal");
    use crate::heap_layout_bound::HeapLayoutBound;
    let mut bound = crate::heap_layout_bound::Counter::new(usize::MAX);
    assert!(terminal.completed_heap_bound(&mut bound).is_some());
    if !crate::heap_layout_bound::layout_supported() {
        return; // full paid-completion layout qualification remains a native CI check
    }
    assert!(crate::heap_layout_bound::completed_bound(&terminal, usize::MAX).is_some());
    let mut credit = crate::source_rotation::PaidReservation::from_remainder(
        Some(crate::source_rotation::PARKED_BUDGET),
        0,
        0,
    );
    let controller = claude_native_comparison::Controller::new_paid(
        claude_native_comparison::Qualification::default(),
        scan.snapshots.len(),
        &mut credit,
    )
    .unwrap();
    let completion = controller
        .complete_paid(&scan, Some(terminal), true, &mut credit)
        .expect("empty diagnostic metadata cannot refuse real Claude terminal completion");
    assert!(completion.fallback.is_none());
    assert!(crate::heap_layout_bound::completed_bound(&completion, usize::MAX).is_some());
}
