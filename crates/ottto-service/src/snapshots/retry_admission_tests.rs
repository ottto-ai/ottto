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

// Unlike the older in-memory carry fixtures, scheduling fixtures cross the
// real strict save/load boundary. ACKs must therefore be canonical identities.
fn retry_durable_fixture(held: usize, healthy: usize) -> ScopedRetryFixture {
    let mut fixture = scoped_retry_fixture(0, held + healthy, false);
    // The initial empty start has no carry or scheduling obligation. Its
    // origin is intentionally omitted by the normal writer; seed the same
    // canonical empty shape before asserting exact durable custody below.
    assert!(fixture.index.claude_stale_family_carry.is_empty());
    fixture.index.claude_stale_family_carry = ClaudeStaleFamilyCarry::default();
    fixture.index.accepted_snapshot_fingerprints.clear();
    fixture.index.snapshot_activity_at.clear();
    let keys = fixture.index.files.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let entities = fixture
            .index
            .file_snapshot_fingerprints
            .get_mut(&key)
            .unwrap();
        *entities = entities
            .iter()
            .map(|body| format!("{:x}", Sha256::digest(body.as_bytes())))
            .collect();
        fixture
            .index
            .accepted_snapshot_fingerprints
            .extend(entities.iter().cloned());
        scoped_retry_accept_member(&mut fixture.index, &key);
    }
    for family in fixture.roots.iter().take(held) {
        let key = local_index_key(&fixture._scratch.join(format!("{family}.jsonl")));
        fixture.index.bind_retry_pending_claude_authority_for_test(
            family,
            BTreeMap::from([(
                family.clone(),
                fixture.index.files[&key].source_file_fingerprint.clone(),
            )]),
        );
    }
    fixture
}

fn retry_test_reload(index: &mut ScanIndex, path: &Path) -> ScanIndex {
    let accepted = index.accepted_snapshot_fingerprints.clone();
    let authority = serde_json::to_value(&index.claude_usage_authority_quarantine).unwrap();
    let admission = serde_json::to_value(&index.claude_stale_family_carry.origin).unwrap();
    let drops = claude_authority_drops_for_test();
    index.save(path).unwrap();
    let loaded = ScanIndex::load(path).unwrap();
    assert_eq!(
        loaded.accepted_snapshot_fingerprints, accepted,
        "strict persistence retains every ACK"
    );
    assert_eq!(
        serde_json::to_value(&loaded.claude_usage_authority_quarantine).unwrap(),
        authority,
        "strict persistence retains every bound authority record"
    );
    assert_eq!(
        serde_json::to_value(&loaded.claude_stale_family_carry.origin).unwrap(),
        admission,
        "strict persistence retains runnable admission debt"
    );
    assert_eq!(
        claude_authority_drops_for_test(),
        drops,
        "no malformed fixture authority was discarded"
    );
    loaded
}

fn retry_test_corrections(fixture: &mut ScopedRetryFixture) {
    let deadline = rfc3339_unix_seconds(CARRY_FAILED).unwrap() + 1;
    for (number, family) in fixture.roots.iter().take(70).enumerate() {
        let record = fixture
            .index
            .claude_usage_authority_quarantine
            .get_mut(family)
            .unwrap();
        record.retry_after_unix_seconds = deadline;
        if number < 65 {
            // A correction is a terminal re-offer, never a RetryPending grant.
            record.contract = CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION.to_string();
            record.disposition = ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal;
            record.failed_reconstruction_count = MAX_CLAUDE_USAGE_AUTHORITY_FAILURES;
            record.retry_after_unix_seconds = 0;
            record.proof_correction = Some(ClaudeAuthorityProofCorrection {
                proof_witness_fingerprint: record.proven_witness_fingerprint.clone(),
                owed_member_ids: BTreeSet::from([family.clone()]),
            });
        }
        assert!(claude_usage_authority_preserves_pending(
            record,
            &fixture.index.claude_usage_family_witnesses[family]
        ));
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
    mut index: ScanIndex,
    root: &Path,
    at: &str,
    limit: usize,
) -> (ScanIndex, SourceScanResult, Vec<String>) {
    // OwnedSourceScan is below pipeline configuration, which reloads policy
    // before scanning a durable index. Mirror that boundary, including on restart.
    index.claude_reemission_exclusions = ReemissionExclusions::load(&root.join("support"));
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
    let mut fixture = retry_durable_fixture(0, 3);
    let root = fixture
        ._scratch
        .join("p".repeat(200))
        .join("q".repeat(200))
        .join("r".repeat(200));
    std::fs::create_dir_all(&root).unwrap();
    let list = ReemissionExclusions::path(&root.join("support"));
    std::fs::create_dir_all(list.parent().unwrap()).unwrap();
    std::fs::write(list, b"").unwrap();
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
    let loaded = retry_test_reload(&mut fixture.index, &path);
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
    let mut loaded = retry_test_reload(&mut index, &path);
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
    let mut fixture = retry_durable_fixture(70, 2);
    let root = fixture._scratch.to_path_buf();
    retry_test_context(&mut fixture.index, &root);
    retry_test_corrections(&mut fixture);
    fixture.index = retry_test_reload(&mut fixture.index, &root.join("retry-state.json"));
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
        index = retry_test_reload(&mut index, &path);
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
    let mut fixture = retry_durable_fixture(0, 2);
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

// Runs on Linux too: the strict persistence checks reproduce both original
// fixture defects without asking an unsupported platform to mint native carry.
#[test]
fn retry_scheduling_fixtures_keep_ack_and_correction_custody_on_reload() {
    let mut fixture = retry_durable_fixture(70, 3);
    retry_test_corrections(&mut fixture);
    fixture.index = retry_test_reload(&mut fixture.index, &fixture._scratch.join("custody.json"));
    assert_eq!(fixture.index.accepted_snapshot_fingerprints.len(), 73);
    assert_eq!(fixture.index.claude_usage_authority_quarantine.len(), 70);
    assert_eq!(
        fixture
            .index
            .claude_usage_authority_quarantine
            .values()
            .filter(|r| r.proof_correction.is_some())
            .count(),
        65
    );
    assert_eq!(
        fixture
            .index
            .claude_usage_authority_quarantine
            .values()
            .filter(|r| r.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending)
            .count(),
        5
    );
}

#[test]
fn retry_due_cursor_rotates_portably_across_reload_without_consuming_gaps() {
    let mut fixture = retry_durable_fixture(70, 0);
    retry_test_corrections(&mut fixture);
    let root = fixture._scratch.to_path_buf();
    retry_test_context(&mut fixture.index, &root);
    // An empty root pass takes the real batch helper without any native carry
    // allocation. All 70 authority opportunities still use the real seed,
    // pre-audit selection and actual-offer cursor functions below.
    let (mut carry, _, state) =
        claude_retry_admit_batch(&fixture.index, &BTreeSet::new(), None, CARRY_RETRY);
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
    let due = fixture.index.files.keys().cloned().collect::<BTreeSet<_>>();
    let audit = root.join(format!("{CARRY_OTHER}.jsonl"));
    let mut seen = BTreeSet::new();
    let path = root.join("portable-state.json");
    for tick in 0..35 {
        fixture.index = retry_test_reload(&mut fixture.index, &path);
        let traversal = fixture.index.traversal.as_mut().unwrap();
        traversal.pending_candidates.push_front(ScanTraversalPath {
            scan_root: root.clone(),
            path: audit.clone(),
            census_member: true,
            watcher_hint: false,
        });
        claude_retry_queue_due_families(&mut fixture.index, CARRY_RETRY);
        let mut selected = Vec::new();
        let state = fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .admission
            .as_ref()
            .unwrap();
        let traversal = fixture.index.traversal.as_mut().unwrap();
        claude_retry_select_due_paths(
            state,
            &fixture.index.claude_usage_authority_quarantine,
            &mut traversal.pending_candidates,
            &mut selected,
            rfc3339_unix_seconds(CARRY_RETRY).unwrap(),
            2,
        );
        assert_eq!(
            selected.len(),
            2,
            "two due slots ahead of audit, tick {tick}"
        );
        let keys = selected
            .iter()
            .map(|p| local_index_key(&p.path))
            .collect::<Vec<_>>();
        assert!(keys.iter().all(|key| due.contains(key)));
        assert!(
            keys.iter().all(|key| !seen.contains(key)),
            "persistent correction prefix must not repeat"
        );
        claude_retry_note_offered(&mut fixture.index, &selected, CARRY_RETRY);
        let state = fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .admission
            .as_ref()
            .unwrap();
        assert_eq!(state.due_after_path.as_ref(), keys.last());
        assert_eq!(
            state.served_before,
            rfc3339_unix_seconds(CARRY_FAILED).unwrap()
        );
        seen.extend(keys);
        if tick == 31 {
            assert_eq!(seen.len(), 64);
            assert!(!state.due_complete);
        }
    }
    assert_eq!(seen, due, "all70 offered within35 pages on every platform");
    fixture.index = retry_test_reload(&mut fixture.index, &path);
    assert_eq!(fixture.index.claude_usage_authority_quarantine.len(), 70);
}

// The classifier runs on Linux too; native carry allocation is intentionally
// separate. Duplicate identities and absent pending members must stay OWED.
#[test]
fn storage_only_refusal_requires_complete_accepted_unique_evidence() {
    let mut fixture = retry_durable_fixture(0, 1);
    let root = fixture.roots[0].clone();
    assert!(claude_retry_singleton_storage_only(&fixture.index, &root));
    let key = fixture.index.files.keys().next().unwrap().clone();
    let accepted = fixture.index.clone();
    fixture
        .index
        .claude_usage_family_pending
        .get_mut(&root)
        .unwrap()
        .invalid = true;
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture
        .index
        .claude_usage_family_pending
        .get_mut(&root)
        .unwrap()
        .member_request_id_hashes
        .insert(format!("{root}_agent-missing"), BTreeSet::new());
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture.index.files.insert(
        format!("/duplicate/{root}.jsonl"),
        fixture.index.files[&key].clone(),
    );
    fixture.index.file_snapshot_fingerprints.insert(
        format!("/duplicate/{root}.jsonl"),
        fixture.index.file_snapshot_fingerprints[&key].clone(),
    );
    let duplicate = format!("/duplicate/{root}.jsonl");
    scoped_retry_accept_member(&mut fixture.index, &duplicate);
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture.index.bind_retry_pending_claude_authority_for_test(
        &root,
        BTreeMap::from([(
            root.clone(),
            fixture.index.files[&key].source_file_fingerprint.clone(),
        )]),
    );
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted.clone();
    fixture
        .index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
    fixture.index = accepted;
    fixture.index.accepted_snapshot_fingerprints.clear();
    assert!(!claude_retry_singleton_storage_only(&fixture.index, &root));
}

#[test]
fn oversized_complete_accepted_singleton_defers_without_healthy_full_reads() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let started = std::time::Instant::now();
    let mut fixture = retry_durable_fixture(0, 2);
    let root = fixture
        ._scratch
        .join("p".repeat(200))
        .join("q".repeat(200))
        .join("r".repeat(200));
    std::fs::create_dir_all(&root).unwrap();
    let list = ReemissionExclusions::path(&root.join("support"));
    std::fs::create_dir_all(list.parent().unwrap()).unwrap();
    std::fs::write(list, b"").unwrap();
    let family = fixture.roots[0].clone();
    let old = std::mem::take(&mut fixture.index.files);
    let heads = std::mem::take(&mut fixture.index.file_snapshot_fingerprints);
    for (key, entry) in old {
        let path = root.join(Path::new(&key).file_name().unwrap());
        std::fs::write(&path, b"{}\n").unwrap();
        let new_key = local_index_key(&path);
        fixture.index.files.insert(new_key.clone(), entry);
        fixture
            .index
            .file_snapshot_fingerprints
            .insert(new_key, heads[&key].clone());
    }
    let real = local_index_key(&root.join(format!("{family}.jsonl")));
    let template = fixture.index.files[&real].clone();
    let members = root.join(&family).join("subagents");
    std::fs::create_dir_all(&members).unwrap();
    for number in 0..6000 {
        let stem = format!("agent-{number:016x}");
        let path = members.join(format!("{stem}.jsonl"));
        std::fs::write(&path, b"{}\n").unwrap();
        let key = local_index_key(&path);
        assert!(key.len() >= 700);
        let entity = format!("{:x}", Sha256::digest(key.as_bytes()));
        fixture.index.files.insert(key.clone(), template.clone());
        fixture
            .index
            .file_snapshot_fingerprints
            .insert(key, BTreeSet::from([entity.clone()]));
        fixture.index.accepted_snapshot_fingerprints.insert(entity);
        fixture
            .index
            .claude_usage_family_pending
            .get_mut(&family)
            .unwrap()
            .member_request_id_hashes
            .insert(format!("{family}_{stem}"), BTreeSet::new());
    }
    let healthy = fixture.index.files.keys().cloned().collect::<Vec<_>>();
    let mut candidates = Vec::new();
    // Bind the synthetic accepted heads to the ACTUAL opened scan identity,
    // not a path hash. All 6000 physical member files remain unchanged below.
    for key in &healthy {
        scoped_retry_accept_member(&mut fixture.index, key);
        let mut census = ScanCensus::default();
        let mut candidate = candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            ScanTraversalPath {
                scan_root: root.clone(),
                path: PathBuf::from(key),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            rfc3339_unix_seconds(CARRY_RETRY),
            BACKFILL_WINDOW_DAYS,
            discovery_retention!(fixture.index),
        )
        .unwrap();
        prepare_owned_scan_candidate(
            SnapshotSource::ClaudeCode,
            &mut candidate,
            &CodexTitleMetadata::default(),
            &ClaudeTitleMetadata::default(),
            Some(&root.join("support")),
        );
        let (candidate, _) = open_and_identify_scan_candidate(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut census,
            rfc3339_unix_seconds(CARRY_RETRY),
            BACKFILL_WINDOW_DAYS,
            discovery_retention!(fixture.index),
        )
        .unwrap();
        let entry = fixture.index.files.get_mut(key).unwrap();
        entry.source_file_fingerprint = candidate.source_file_fingerprint.clone();
        entry.size_bytes = candidate.size_bytes;
        entry.modified_unix_seconds = candidate.modified_unix_seconds;
        entry.modified_unix_nanos = Some(candidate.modified_unix_nanos);
        let record = scoped_retry_record(
            key,
            serde_json::json!({
                "v": claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,
                "fp": candidate.source_file_fingerprint,
                "w": rfc3339_unix_seconds(CARRY_FAILED).unwrap(), "s":"exact", "h":"0000000000000001",
                "bi":rfc3339_unix_seconds(CARRY_FAILED).unwrap(), "bd":1,"bn":1,
            }),
        );
        fixture
            .index
            .claude_request_census
            .insert(key.clone(), record);
        candidates.push(candidate);
    }
    fixture
        .index
        .load_claude_reemission_exclusions(&root.join("support"));
    retry_test_context(&mut fixture.index, &root);
    assert!(claude_retry_singleton_storage_only(&fixture.index, &family));
    assert!(
        matches!(
            claude_stream_accepted_retry_carry(&fixture.index, &BTreeSet::from([family.clone()])),
            Err(ClaudeRetryAdmissionRefusal::Structure)
        ),
        "real accepted singleton exceeds the unchanged8MiB gate"
    );
    let baseline = fixture
        .index
        .healthy_custody_digest_for_test(healthy.iter().map(String::as_str));
    let path = fixture._scratch.join("accepted-singleton-index.json");
    let mut index = fixture.index;
    for tick in 0..3 {
        let seconds = rfc3339_unix_seconds(CARRY_RETRY).unwrap() + tick * 3601;
        let at = OffsetDateTime::from_unix_timestamp(seconds as i64)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        carry_red(&mut index, CARRY_FAILED, 7);
        index.load_claude_reemission_exclusions(&root.join("support"));
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            &at,
            BACKFILL_WINDOW_DAYS,
        );
        let state = index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .unwrap()
            .admission
            .as_ref()
            .unwrap();
        assert!(state.storage_deferred && !state.complete);
        assert!(
            state.oversized_root.is_none(),
            "storage refusal creates no runnable re-arm"
        );
        assert!(
            !index.claude_stale_family_carry.contains(&family),
            "no carry or proof granted"
        );
        assert_eq!(
            scoped_retry_full_reads(&index, &candidates),
            0,
            "zero cold healthy Full reads, tick{tick}"
        );
        let traversal = index.traversal.as_mut().unwrap();
        traversal.pending_directories.clear();
        traversal.pending_candidates.clear();
        // Even explicitly offering a healthy root follows the real unchanged
        // path. Without the fix the fallback seeds/clears healthy members here.
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root: root.clone(),
            path: PathBuf::from(&real),
            census_member: true,
            watcher_hint: false,
        });
        let (next, scan, _) = retry_test_page(index, &root, &at, 1);
        assert_eq!(
            scan.scanned_file_count, 0,
            "no actual healthy parse/Full read at tick{tick}"
        );
        assert!(!scan.census_complete);
        index = next;
        assert_eq!(
            index.healthy_custody_digest_for_test(healthy.iter().map(String::as_str)),
            baseline
        );
        assert!(index.claude_duplicate_request_witness_overflowed);
        index = retry_test_reload(&mut index, &path);
    }
    eprintln!("retry_scheduling_runtime: test=oversized_complete_accepted_singleton_defers_without_healthy_full_reads elapsed_ms={} members={}", started.elapsed().as_millis(), healthy.len());
}

#[test]
fn stale_carry_batch_diagnostics_discard_failed_larger_attempts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = retry_durable_fixture(0, 4);
    let stale = fixture.roots.iter().cloned().collect();
    let _refuse = RetryMultiRefusal::new();
    let mut diagnostics = StaleCarryRejectionCounts::default();
    let (carry, covered, _) = claude_retry_admit_batch_observed(
        &fixture.index,
        &stale,
        None,
        CARRY_RETRY,
        &mut diagnostics,
        claude_contract_debt_scope(&fixture.index),
    );
    assert_eq!(carry.roots.len(), 1);
    assert_eq!(covered.len(), 1);
    assert_eq!(
        diagnostics.rejected(),
        0,
        "larger failed probes are not root rejections"
    );
    assert_eq!(diagnostics.eligible_before_funding, 1);
}
