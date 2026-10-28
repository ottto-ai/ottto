use super::*;

fn conserved(counts: &Counts, total: usize) {
    let (c, _, unknown) = counts.summary(total);
    assert_eq!(c[..N].iter().sum::<usize>() + unknown, total);
    assert_eq!(c[..N].iter().sum::<usize>(), c[N] + c[N + 1]);
}

#[test]
fn cause_cardinality_and_all_contribution_slots_are_pinned() {
    let all = [INVENTORY, CREATED, PARENT, ABSENT, GROUP, PARSER];
    assert_eq!(all.len(), N);
    assert_eq!(all.into_iter().collect::<BTreeSet<_>>(), (0..N).collect());
    assert_eq!(NAMES.split(' ').count(), N);
    let mut traversal = Counts::default();
    let mut page = traversal.page(100);
    for (i, cause) in all.into_iter().enumerate() {
        page.add(cause, [format!("private-{i}.jsonl")]);
    }
    traversal.merge(&page);
    conserved(&traversal, N);
    assert_eq!(traversal.summary(N).0[..N], [1; N]);
    assert_eq!(traversal.summary(N).1[..N], [1; N]);
    let encoded = serde_json::to_string(&traversal).unwrap();
    assert!(!encoded.contains("private"));
    assert!(!encoded.contains("distinct"));
}

#[test]
fn repeated_key_adds_two_contributions_and_one_distinct_first_cause_wins() {
    let mut generation = Counts::default();
    let mut first = generation.page(2);
    first.add(INVENTORY, ["same.jsonl", "same.jsonl"]);
    generation.merge(&first);
    let (c, d, _) = generation.summary(2);
    assert_eq!(c[INVENTORY], 2);
    assert_eq!(d[INVENTORY], 1);
    let mut next = generation.page(2);
    next.add(CREATED, ["same.jsonl"]);
    generation.merge(&next);
    let (c, d, _) = generation.summary(3);
    assert_eq!(c[CREATED], 1);
    assert_eq!(d[CREATED], 0);
    assert_eq!(d[INVENTORY], 1);
    conserved(&generation, 3);
}

#[test]
fn distinct_cap_is_bounded_sticky_and_never_caps_contributions() {
    let mut counts = Counts::default().page(1);
    counts.add(PARSER, ["a.jsonl", "b.jsonl", "b.jsonl", "a.jsonl"]);
    assert_eq!(counts.state().0.len(), 1);
    assert_eq!(counts.summary(4).1[PARSER], 1);
    assert_eq!(counts.summary(4).1[N], 1);
    assert_eq!(counts.summary(4).0[PARSER], 4);
    // Increasing the index later cannot renew this generation's insertion allowance.
    let mut next = counts.page(100);
    next.add(PARSER, ["c.jsonl"]);
    assert_eq!(counts.state().0.len(), 1);
    assert_eq!(Counts::default().page(100_000).state().2, Some(65_536));
    let mut empty = Counts::default().page(0);
    empty.add(PARSER, ["a.jsonl"]);
    assert_eq!(empty.summary(1).1[N], 1);
    assert_eq!(empty.state().0.len(), 0);
    conserved(&counts, 4);
}

#[test]
fn known_compression_is_input_only_and_absent_parent_does_not_imply_compressed() {
    let mut counts = Counts::default().page(10);
    counts.add(PARENT, ["plain-child.jsonl"]);
    counts.add(GROUP, ["known-input.jsonl.zst"]);
    let (c, _, unknown) = counts.summary(2);
    assert_eq!(c[PARENT], 1);
    assert_eq!(c[N], 1);
    assert_eq!(c[N + 1], 1);
    assert_eq!(unknown, 0);
    let emitted = line(counts.summary(2));
    assert!(emitted.contains("ownership_input_compressed=1"));
    assert!(emitted.contains("ownership_parent_unresolvable=1"));
    assert!(!emitted.contains("plain-child"));
    conserved(&counts, 2);
}

#[test]
fn index_restart_retains_contributions_but_resets_distinct_and_fresh_generation_resets_both() {
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
    let counts = &mut index.traversal.as_mut().unwrap().counts;
    counts.causes = counts.causes.page(10);
    counts.causes.add(PARENT, ["same.jsonl", "same.jsonl"]);
    counts.ownership_incomplete_file_count = 2;
    assert_eq!(counts.causes.summary(2).1[PARENT], 1);
    index.save(&path).unwrap();
    let mut restored = ScanIndex::load(&path).unwrap();
    let counts = &mut restored.traversal.as_mut().unwrap().counts;
    assert_eq!(counts.causes.summary(2).0[PARENT], 2);
    assert_eq!(counts.causes.summary(2).1, [0; N + 1]);
    let mut page = counts.causes.page(10);
    page.add(PARENT, ["same.jsonl"]);
    counts.causes.merge(&page);
    counts.ownership_incomplete_file_count += 1;
    assert_eq!(counts.causes.summary(3).0[PARENT], 3);
    assert_eq!(counts.causes.summary(3).1[PARENT], 1);
    conserved(&counts.causes, counts.ownership_incomplete_file_count);
    restored.traversal = None;
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &[],
        &mut restored,
        "2026-10-13T00:00:00Z",
        30,
    );
    let fresh = &restored.traversal.as_ref().unwrap().counts;
    assert_eq!(fresh.causes.summary(0), ([0; N + 2], [0; N + 1], 0));
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
        assert_eq!(restored.causes.summary(17).2, 17);
        conserved(&restored.causes, 17);
    }
    let mut added = Counts::default().page(2);
    added.add(GROUP, ["a.jsonl"]);
    positional.push(serde_json::to_value(added).unwrap());
    let restored: ScanTraversalCounts = serde_json::from_value(json!(positional)).unwrap();
    assert_eq!(restored.causes.summary(17).0[GROUP], 1);
    assert_eq!(restored.causes.summary(17).2, 16);
    assert_eq!(restored.causes.summary(17).1, [0; N + 1]);
    conserved(&restored.causes, 17);
}
