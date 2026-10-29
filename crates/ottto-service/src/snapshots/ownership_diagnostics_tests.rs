use super::*;

fn conserved(counts: &Counts, total: usize) {
    let (c, [unknown, _, _]) = counts.summary(total);
    assert_eq!(
        c[..N]
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(*v))
            .unwrap()
            .checked_add(unknown),
        Some(total)
    );
}

#[test]
fn cause_cardinality_and_each_contribution_slot_are_pinned_and_sum_to_s() {
    let all = [INVENTORY, CREATED, PARENT, ABSENT, GROUP, PARSER];
    assert_eq!(all.len(), N);
    assert_eq!(all.into_iter().collect::<BTreeSet<_>>(), (0..N).collect());
    assert_eq!(NAMES.split(' ').count(), N);
    let mut traversal = Counts::default();
    let mut page = traversal.page(Some(77));
    for cause in all {
        page.add(cause, 1);
    }
    traversal.merge(&page);
    assert_eq!(traversal.summary(N).0[..N], [1; N]);
    assert_eq!(traversal.summary(N).1[0], 0);
    conserved(&traversal, N);
}

#[test]
fn repeated_work_counts_every_contribution_and_marker_stays_in_generation() {
    let mut traversal = Counts::default();
    let mut first = traversal.page(Some(77));
    let marker = first.summary(0).1[1];
    assert!(marker > 0);
    first.add(INVENTORY, 2);
    traversal.merge(&first);
    let mut second = traversal.page(Some(77));
    assert_eq!(second.summary(0).1[1], marker);
    second.add(CREATED, 1);
    traversal.merge(&second);
    assert_eq!(traversal.summary(3).0[INVENTORY], 2);
    assert_eq!(traversal.summary(3).0[CREATED], 1);
    conserved(&traversal, 3);
    assert_eq!(Counts::default().page(Some(78)).summary(0).1[1], 78);
}

#[test]
fn index_save_load_resume_retains_contributions_and_start_marker_and_fresh_generation_resets_them()
{
    let dir = crate::test_scratch::ScratchDir::new("ownership-causes-restart");
    let path = dir.join("index.json");
    let mut index = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &[],
        &mut index,
        "2026-10-12T00:00:00Z",
        30,
    );
    let traversal = index.traversal.as_mut().unwrap();
    let started = rfc3339_unix_seconds(&traversal.census_window_end).unwrap();
    let counts = &mut traversal.counts;
    counts.causes = counts.causes.page(Some(started));
    counts.causes.add(PARENT, 2);
    counts.ownership_incomplete_file_count = 2;
    let marker = counts.causes.summary(2).1[1];
    index.save(&path).unwrap();
    let mut restored = ScanIndex::load(&path).unwrap();
    let traversal = restored.traversal.as_mut().unwrap();
    let restored_start = rfc3339_unix_seconds(&traversal.census_window_end).unwrap();
    assert_eq!(restored_start as usize, marker);
    let counts = &mut traversal.counts;
    assert_eq!(counts.causes.summary(2).0[PARENT], 2);
    assert_eq!(counts.causes.summary(2).1, [0; 3]);
    let mut page = counts.causes.page(Some(restored_start));
    assert_eq!(
        page.summary(0).1[1],
        marker,
        "routine reload retains the traversal start marker"
    );
    page.add(PARENT, 1);
    counts.causes.merge(&page);
    counts.ownership_incomplete_file_count += 1;
    assert_eq!(counts.causes.summary(3).0[PARENT], 3);
    conserved(&counts.causes, 3);
    restored.traversal = None;
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &[],
        &mut restored,
        "2026-10-13T00:00:00Z",
        30,
    );
    let fresh = restored.traversal.as_mut().unwrap();
    assert_eq!(fresh.counts.causes.summary(0), ([0; N + 2], [0; 3]));
    let fresh_start = rfc3339_unix_seconds(&fresh.census_window_end).unwrap();
    assert!(fresh_start as usize > marker);
    assert_eq!(
        fresh.counts.causes.page(Some(fresh_start)).summary(0).1[1],
        fresh_start as usize
    );
}

#[test]
fn sparse_closed_wire_and_json_omit_empty_causes_and_keep_unattributed_last() {
    assert!(line(Counts::default().summary(0)).is_empty());
    assert!(serde_json::to_value(ScanTraversalCounts::default())
        .unwrap()
        .get("causes")
        .is_none());
    let mut counts = Counts::default().page(Some(77));
    counts.add(PARENT, 1);
    let emitted = line(counts.summary(4));
    assert!(emitted.contains("ownership_incomplete_generation_start="));
    assert!(
        emitted.contains("ownership_incomplete_contributions{bucket=\"parent_unresolvable\"}=1")
    );
    assert!(emitted.contains("ownership_incomplete_contributions{bucket=\"unattributed\"}=3"));
    assert!(!emitted.contains("created_thread_proof"));
    assert!(!emitted.contains("distinct"));
    assert!(!emitted.contains("invalid_resets"));
    assert!(emitted.find("parent_unresolvable").unwrap() < emitted.find("unattributed").unwrap());
    let saved = serde_json::to_value(&counts).unwrap();
    assert_eq!(saved.as_object().unwrap().len(), 1);
    assert_eq!(saved["contributions"].as_array().unwrap().len(), 8);
    conserved(&counts, 4);
}

#[test]
fn overclassified_restored_state_is_disclosed_and_projected_to_all_unattributed() {
    let c: Counts = serde_json::from_value(json!({"contributions":[1,0,0,0,0,0,0,0]})).unwrap();
    assert_eq!(c.summary(0), ([0; N + 2], [0, 0, 1]));
    assert!(line(c.summary(0)).contains("ownership_incomplete_invalid_resets=1"));
    conserved(&c, 0);
}

#[test]
fn aggregate_overflow_and_slot_add_merge_overflow_are_counted_without_wrapping() {
    let mut c = Counts::default();
    c.add(INVENTORY, usize::MAX);
    c.add(PARENT, 1);
    assert_eq!(c.summary(usize::MAX), ([0; N + 2], [usize::MAX, 0, 1]));
    conserved(&c, usize::MAX);
    let mut slot = Counts::default();
    slot.add(INVENTORY, usize::MAX);
    slot.add(INVENTORY, 1);
    assert_eq!(slot.summary(10), ([0; N + 2], [10, 0, 1]));
    let mut page = Counts::default();
    page.add(PARENT, usize::MAX);
    slot.add(PARENT, 1);
    slot.merge(&page);
    assert_eq!(slot.summary(10), ([0; N + 2], [10, 0, 2]));
}

#[test]
fn legacy_remainder_overflow_is_disclosed_even_when_legacy_scalar_wraps_to_zero() {
    let mut legacy = Counts::default();
    let scalar = usize::MAX;
    assert_eq!(legacy.summary(scalar).1[0], scalar);
    legacy.add(PARENT, 1);
    // Diagnostic-only seam: do not execute or change the pre-existing unchecked scalar addition.
    assert_eq!(scalar.checked_add(1), None);
    let wrapped_scalar = scalar.wrapping_add(1);
    assert_eq!(legacy.summary(wrapped_scalar), ([0; N + 2], [0, 0, 1]));
    conserved(&legacy, wrapped_scalar);
    legacy.observation[1] = usize::MAX;
    assert_eq!(
        legacy.summary(wrapped_scalar).1[2],
        usize::MAX,
        "reset counter saturates explicitly"
    );
}

#[test]
fn prior_map_and_positional_counts_default_the_appended_split_without_shifting_neighbors() {
    let old = ScanTraversalCounts {
        ownership_incomplete_file_count: 17,
        dropped_usage_record_count: 23,
        terminal_zero_snapshot_usage_evidence_count: 29,
        ..ScanTraversalCounts::default()
    };
    let mut object = serde_json::to_value(old).unwrap();
    object.as_object_mut().unwrap().remove("causes");
    let fields = [
        "discovered_file_count",
        "directory_entry_cap_exceeded_count",
        "symlink_rejected_count",
        "unreadable_path_count",
        "unreadable_causes",
        "parent_unresolvable",
        "oversized_file_count",
        "disappeared_file_count",
        "malformed_json_line_count",
        "invalid_utf8_line_count",
        "over_line_cap_count",
        "recognized_usage_drop_count",
        "ownership_incomplete_file_count",
        "zero_snapshot_usage_evidence_count",
        "dropped_usage_record_count",
        "terminal_over_line_cap_count",
        "terminal_recognized_usage_drop_count",
        "terminal_dropped_usage_record_count",
        "terminal_ownership_incomplete_file_count",
        "terminal_zero_snapshot_usage_evidence_count",
    ];
    let mut positional = fields.map(|name| object[name].clone()).to_vec();
    positional.extend([json!(31), json!({"retired_nonzero": 37})]);
    for bytes in [
        serde_json::to_vec(&object).unwrap(),
        serde_json::to_vec(&positional).unwrap(),
    ] {
        let restored: ScanTraversalCounts = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.ownership_incomplete_file_count, 17);
        assert_eq!(restored.dropped_usage_record_count, 23);
        assert_eq!(restored.terminal_zero_snapshot_usage_evidence_count, 29);
        assert_eq!(restored.causes.summary(17).1[0], 17);
        conserved(&restored.causes, 17);
    }
    let mut added = Counts::default().page(Some(77));
    added.add(GROUP, 1);
    positional.push(serde_json::to_value(added).unwrap());
    let restored: ScanTraversalCounts = serde_json::from_value(json!(positional)).unwrap();
    assert_eq!(restored.causes.summary(17).0[GROUP], 1);
    assert_eq!(restored.causes.summary(17).1[0], 16);
    conserved(&restored.causes, 17);
}

// Exact merge-base ScanTraversalCounts serde shape, including retired positional slots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct MergeBaseScanTraversalCounts {
    discovered_file_count: usize,
    directory_entry_cap_exceeded_count: usize,
    symlink_rejected_count: usize,
    unreadable_path_count: usize,
    unreadable_causes: UnreadableCauses,
    /// PR-P: held fork children per parent cause, traversal-cumulative.
    /// Additive: old checkpoints load as zero (struct-level `serde(default)`).
    parent_unresolvable: ParentUnresolvableCauses,
    oversized_file_count: usize,
    disappeared_file_count: usize,
    malformed_json_line_count: usize,
    invalid_utf8_line_count: usize,
    over_line_cap_count: usize,
    recognized_usage_drop_count: usize,
    ownership_incomplete_file_count: usize,
    zero_snapshot_usage_evidence_count: usize,
    dropped_usage_record_count: u64,
    /// Subset of the public loss counters above that has a durable terminal
    /// disposition. These remain disclosed but do not make an exhausted
    /// traversal retryable.
    #[serde(default)]
    terminal_over_line_cap_count: usize,
    #[serde(default)]
    terminal_recognized_usage_drop_count: usize,
    #[serde(default)]
    terminal_dropped_usage_record_count: u64,
    /// Non-progressing residue promoted to terminal by the generation that
    /// re-derived it. Ownership-incomplete Codex rollouts whose parent
    /// resolution is not pending, files with usage evidence but no entity, and
    /// the usage records those files drop are deterministic functions of their
    /// unchanged bytes, sidecar and parent evidence. Their files are never
    /// checkpointed, so every generation parses them again and reaches the
    /// same counts; retrying the traversal cannot change them. Once discovery
    /// finishes without any retryable problem they are settled here so the
    /// census can complete with the loss named, instead of holding every
    /// downstream completeness gate red for as long as those files exist.
    /// See `settle_non_progressing_residue`.
    #[serde(default)]
    terminal_ownership_incomplete_file_count: usize,
    #[serde(default)]
    terminal_zero_snapshot_usage_evidence_count: usize,
    // Persisted positional slots: diagnostic additions must remain last.
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "unchanged_reread_admitted", default, skip_serializing)]
    _retired_unchanged_reread_admitted: serde::de::IgnoredAny,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "reread_budget_refused", default, skip_serializing)]
    _retired_reread_budget_refused: serde::de::IgnoredAny,
}

#[test]
fn current_object_old_reader_current_roundtrip_retains_s_but_explicitly_loses_split() {
    let mut current = ScanTraversalCounts {
        ownership_incomplete_file_count: 17,
        dropped_usage_record_count: 23,
        terminal_zero_snapshot_usage_evidence_count: 29,
        ..ScanTraversalCounts::default()
    };
    current.causes.add(PARENT, 5);
    let object = serde_json::to_value(&current).unwrap();
    assert!(object.is_object());
    assert_eq!(object["causes"]["contributions"][PARENT], 5);
    let old: MergeBaseScanTraversalCounts = serde_json::from_value(object).unwrap();
    assert_eq!(old.ownership_incomplete_file_count, 17);
    assert_eq!(old.dropped_usage_record_count, 23);
    assert_eq!(old.terminal_zero_snapshot_usage_evidence_count, 29);
    let saved = serde_json::to_value(old).unwrap();
    assert!(saved.is_object());
    assert!(saved.get("causes").is_none());
    let upgraded: ScanTraversalCounts = serde_json::from_value(saved).unwrap();
    assert_eq!(upgraded.ownership_incomplete_file_count, 17);
    assert_eq!(upgraded.dropped_usage_record_count, 23);
    assert_eq!(upgraded.terminal_zero_snapshot_usage_evidence_count, 29);
    assert_eq!(upgraded.causes.summary(17), ([0; N + 2], [17, 0, 0]));
    conserved(&upgraded.causes, 17);
}
