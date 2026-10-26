// Small scheduling fixtures use real selection, parse, persistence and the real
// structural price. Only the multi-root scheduling refusal is injectable.
struct RetryMultiRefusal(bool);
impl RetryMultiRefusal {
    fn new() -> Self {
        Self(RETRY_ADMISSION_REFUSE_MULTI.with(|v| v.replace(true)))
    }
}
impl Drop for RetryMultiRefusal {
    fn drop(&mut self) {
        RETRY_ADMISSION_REFUSE_MULTI.with(|v| v.set(self.0));
    }
}

fn retry_test_context(index: &mut ScanIndex, root: &Path) {
    let context = scan_traversal_context_fingerprint(
        SnapshotSource::ClaudeCode,
        &[root.to_owned()],
        index,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    traversal.context_fingerprint = context;
    traversal.scan_roots = vec![root.to_owned()];
}

fn retry_test_page(
    index: ScanIndex,
    root: &Path,
    at: &str,
    limit: usize,
) -> (ScanIndex, SourceScanResult, Vec<String>) {
    let mut scan = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        &[root.to_owned()],
        index,
        at,
        BACKFILL_WINDOW_DAYS,
        limit,
        false,
        Some(&root.join("support")),
        &[],
        false,
        true,
        true,
    );
    let selected = scan
        .identified_candidates
        .iter()
        .map(|c| local_index_key(&c.path))
        .collect::<Vec<_>>();
    assert!(
        selected.len() <= limit,
        "same production selection allowance"
    );
    for _ in 0..256 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, selected),
        }
    }
    panic!("small ordinary page must complete");
}

#[test]
fn oversized_singleton_keeps_runnable_debt_and_later_siblings_after_reload() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let started = std::time::Instant::now();
    let mut fixture = scoped_retry_fixture(0, 3, false);
    let root = fixture
        ._scratch
        .join("p".repeat(200))
        .join("q".repeat(200))
        .join("r".repeat(200));
    std::fs::create_dir_all(&root).unwrap();
    // One real root file plus stale synthetic missing members. The missing
    // members are ordinary runnable open opportunities, never fake ACKs.
    let old_files = std::mem::take(&mut fixture.index.files);
    let old_heads = std::mem::take(&mut fixture.index.file_snapshot_fingerprints);
    for (old, entry) in old_files {
        let path = root.join(Path::new(&old).file_name().unwrap());
        std::fs::write(&path, b"{}\n").unwrap();
        let key = local_index_key(&path);
        fixture.index.files.insert(key.clone(), entry);
        fixture
            .index
            .file_snapshot_fingerprints
            .insert(key, old_heads[&old].clone());
    }
    let owed = fixture.roots[0].clone();
    let real = local_index_key(&root.join(format!("{owed}.jsonl")));
    let template = fixture.index.files[&real].clone();
    for number in 0..6000 {
        let path = root
            .join(&owed)
            .join("subagents")
            .join(format!("agent-{number:016x}.jsonl"));
        assert!(path.to_string_lossy().len() >= 700);
        fixture
            .index
            .files
            .insert(local_index_key(&path), template.clone());
    }
    fixture
        .index
        .claude_usage_family_pending
        .get_mut(&owed)
        .unwrap()
        .invalid = true;
    retry_test_context(&mut fixture.index, &root);
    let singleton = BTreeSet::from([owed.clone()]);
    assert!(
        matches!(
            claude_stream_accepted_retry_carry(&fixture.index, &singleton),
            Err(ClaudeRetryAdmissionRefusal::Structure)
        ),
        "REAL singleton price exceeds the unchanged 8MiB gate"
    );
    let before = fixture.index.files[&real].source_file_fingerprint.clone();
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        &mut fixture.index,
        CARRY_RETRY,
        BACKFILL_WINDOW_DAYS,
    );
    let state = fixture
        .index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .unwrap()
        .admission
        .as_ref()
        .unwrap();
    assert_eq!(state.oversized_root.as_deref(), Some(owed.as_str()));
    assert!(!state.complete);
    assert!(!fixture.index.claude_stale_family_carry.contains(&owed));
    assert_eq!(
        fixture.index.files[&real].source_file_fingerprint, before,
        "debt recording does not clear unoffered work"
    );
    // No hint or ordinary queue can mask a missing fallback after reload.
    fixture
        .index
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .clear();
    fixture
        .index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .clear();
    let path = fixture._scratch.join("oversized-index.json");
    fixture.index.save(&path).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    let (mut index, scan, selected) = retry_test_page(loaded, &root, CARRY_RETRY, 1);
    assert_eq!(selected, vec![real.clone()]);
    assert_eq!(
        scan.scanned_file_count, 1,
        "the owed real file actually parses"
    );
    assert!(!scan.census_complete);
    assert_ne!(index.files[&real].source_file_fingerprint, before);
    let state = index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .unwrap()
        .admission
        .as_ref()
        .unwrap();
    assert_eq!(state.oversized_after_path.as_deref(), Some(real.as_str()));
    assert!(
        !state.complete,
        "unoffered missing members still owe service"
    );
    index.save(&path).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    // An exhausted/red ordinary checkpoint may leave unoffered fallback
    // members. The actual next start must advance siblings without dropping it.
    carry_red(&mut loaded, CARRY_RETRY, 7);
    loaded.claude_reemission_exclusions =
        ReemissionExclusions::load(&fixture._scratch.join("support"));
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[root],
        &mut loaded,
        CARRY_SECOND_RETRY,
        BACKFILL_WINDOW_DAYS,
    );
    let next = loaded
        .claude_stale_family_carry
        .origin
        .as_ref()
        .unwrap()
        .admission
        .as_ref()
        .unwrap();
    assert_eq!(
        next.after_root.as_deref(),
        Some(fixture.roots[2].as_str()),
        "the real next start covers both later siblings"
    );
    assert_eq!(next.oversized_root.as_deref(), Some(owed.as_str()));
    assert!(
        !next.complete,
        "root iteration is not full coverage while fallback is owed"
    );
    eprintln!("retry_scheduling_runtime: test=oversized_singleton_keeps_runnable_debt_and_later_siblings_after_reload elapsed_ms={}", started.elapsed().as_millis());
}

#[test]
fn rotating_due_seed_services_over_64_paths_before_audits_across_reload() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let started = std::time::Instant::now();
    let _refusal = RetryMultiRefusal::new();
    let _native = claude_native_comparison::enable_for_test();
    let mut fixture = scoped_retry_fixture(70, 2, false);
    let root = fixture._scratch.to_path_buf();
    retry_test_context(&mut fixture.index, &root);
    let deadline = rfc3339_unix_seconds(CARRY_FAILED).unwrap() + 1;
    for (number, family) in fixture.roots.iter().take(70).enumerate() {
        let record = fixture
            .index
            .claude_usage_authority_quarantine
            .get_mut(family)
            .unwrap();
        record.retry_after_unix_seconds = deadline;
        if number < 65 {
            record.proof_correction = Some(ClaudeAuthorityProofCorrection {
                proof_witness_fingerprint: record.proven_witness_fingerprint.clone(),
                owed_member_ids: BTreeSet::from([family.clone()]),
            });
        }
    }
    // A competing due audit remains available on every page, but cannot
    // consume the existing two slots ahead of runnable authority work.
    let audit = root.join(format!("{CARRY_OTHER}.jsonl"));
    std::fs::write(&audit, b"{}\n").unwrap();
    let audit_key = local_index_key(&audit);
    let mut audit_entry = manifest_index_entry(Some("audit-body"));
    audit_entry.scan_identity_version = Some(sampled_audit::marker(0));
    fixture.index.files.insert(audit_key.clone(), audit_entry);
    let due_keys = fixture
        .roots
        .iter()
        .take(70)
        .map(|r| local_index_key(&root.join(format!("{r}.jsonl"))))
        .collect::<BTreeSet<_>>();
    // Resume a real priced admission result. The injected multi-root refusal
    // is AFTER the unchanged real structural math, not a fake carry decision.
    let stale = fixture.roots.iter().skip(70).cloned().collect();
    let (mut carry, _, state) = claude_retry_admit_batch(&fixture.index, &stale, None, CARRY_RETRY);
    carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
        context_fingerprint: fixture
            .index
            .traversal
            .as_ref()
            .unwrap()
            .context_fingerprint
            .clone(),
        process: claude_full_rearm_process(),
        full_rearm_window: false,
        admission: Some(state),
    });
    fixture.index.claude_stale_family_carry = carry;
    let path = root.join("retry-state.json");
    let mut seen = BTreeSet::new();
    let mut index = fixture.index;
    for tick in 0..35 {
        // Retained recovery debt stays empty while held/deferred. Production's
        // earlier native recovery selector must count as actual service too.
        for family in fixture.roots.iter().take(65) {
            index
                .files
                .get_mut(&local_index_key(&root.join(format!("{family}.jsonl"))))
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
        index
            .files
            .get_mut(&audit_key)
            .unwrap()
            .scan_identity_version = Some(sampled_audit::marker(0));
        let at = if tick < 5 {
            CARRY_RETRY
        } else {
            CARRY_SECOND_RETRY
        };
        let (next, scan, selected) = retry_test_page(index, &root, at, 2);
        assert_eq!(selected.len(), 2);
        assert!(
            selected.iter().all(|key| due_keys.contains(key)),
            "due work wins before audits, tick {tick}"
        );
        assert_eq!(
            scan.scanned_file_count, 2,
            "actual ordinary parses, not just seed insertion"
        );
        let last_offered = selected.last().cloned();
        seen.extend(selected);
        index = next;
        let state = index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .admission
            .as_ref()
            .unwrap();
        assert_eq!(
            state.served_before,
            rfc3339_unix_seconds(CARRY_FAILED).unwrap(),
            "a new start must not consume unoffered deadlines"
        );
        assert_eq!(
            state.due_after_path, last_offered,
            "only actually offered selection slots advance the cursor"
        );
        if tick == 31 {
            assert_eq!(seen.len(), 64);
            assert!(
                !state.due_complete,
                "overflow deadlines remain runnable after the first 64"
            );
        }
        if tick == 4 {
            // A later red terminal/start must retain overflow deadlines, not
            // consume them en masse by advancing the traversal clock.
            carry_red(&mut index, CARRY_RETRY, 7);
        }
        index.save(&path).unwrap();
        index = ScanIndex::load(&path).unwrap();
    }
    assert_eq!(seen, due_keys, "all70due paths reach actual selection within35two-file pages despite persistent prefix and audits");
    assert!(
        index.claude_usage_authority_quarantine.values().any(|r| r
            .proof_correction
            .as_ref()
            .is_some_and(|c| !c.owed_member_ids.is_empty())),
        "persistent prefix was not settled to fake fairness"
    );
    eprintln!("retry_scheduling_runtime: test=rotating_due_seed_services_over_64_paths_before_audits_across_reload elapsed_ms={}", started.elapsed().as_millis());
}

#[test]
fn completed_retry_admission_releases_to_whole_carry_when_history_fits() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let started = std::time::Instant::now();
    let mut fixture = scoped_retry_fixture(0, 2, false);
    let stale = fixture.roots.iter().cloned().collect();
    let (mut carry, _, state) = claude_retry_admit_batch(&fixture.index, &stale, None, CARRY_RETRY);
    carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
        context_fingerprint: fixture
            .index
            .traversal
            .as_ref()
            .unwrap()
            .context_fingerprint
            .clone(),
        process: claude_full_rearm_process(),
        full_rearm_window: false,
        admission: Some(state),
    });
    fixture.index.claude_stale_family_carry = carry;
    claude_retry_queue_due_families(&mut fixture.index, CARRY_RETRY);
    assert!(
        fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .admission
            .as_ref()
            .unwrap()
            .complete,
        "the real empty due/fallback pass finishes"
    );
    carry_red(&mut fixture.index, CARRY_FAILED, 7);
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    assert_eq!(row["carried_pending_families"], 2);
    assert_eq!(row["rearmed_index_files"], 0);
    assert!(
        fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .admission
            .is_none(),
        "completed scheduling must not keep clean traversal/reconciliation permanently disabled"
    );
    eprintln!("retry_scheduling_runtime: test=completed_retry_admission_releases_to_whole_carry_when_history_fits elapsed_ms={}", started.elapsed().as_millis());
}
