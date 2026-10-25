// Fix 1: a closed duplicate fence held only by an unchanged set of
// structurally invalid Claude families skips its due full re-arm. Each test
// folds the shared account family fixture (a root and one subagent) whose
// subagent names a request but carries no usage occurrence, so the family is
// invalid from its own bytes alone. A terminal makes the closed-fence re-arm
// due, folds the family, and then re-reads every file the fold re-armed, as
// the next window's walk would. A BASE arm forgets the persisted progress
// before every terminal, which is the behavior before Fix 1. Fixtures are
// synthetic and content-free.
use super::*;

const WINDOW: &str = "2026-08-02T07:10:00Z";
const CENSUS_CLOCK: u64 = 1_785_654_600;
const OTHER_ROOT: &str = "e5555555-5555-4555-8555-555555555555";

/// One due terminal's counters and the re-read it leaves for the next walk.
#[derive(Debug)]
struct Terminal {
    counts: ClaudeDuplicateCensusCounts,
    suppression: ClaudeFullRearmSuppressionCounts,
    rearmed_files: usize,
    rearmed_bytes: u64,
}

struct Rearm {
    root: PathBuf,
    parent: String,
    /// The fixture's valid parent body, the source of a second family.
    valid_parent: SnapshotItem,
    /// The structurally invalid family the walk parses.
    items: Vec<SnapshotItem>,
    /// Index key to the source revision a re-read records.
    sources: BTreeMap<String, String>,
}

impl Rearm {
    fn new() -> Self {
        let (root, parent, mut items) = claude_account_family_fixture();
        let valid_parent = items[0].clone();
        items[1].claude_usage_occurrences.clear();
        assert!(claude_member_invalidity_is_structural(&items[1]));
        assert!(!claude_member_invalidity_is_structural(&items[0]));
        let sources = BTreeMap::from([
            (
                local_index_key(&root.join(format!("{parent}.jsonl"))),
                "rev-parent".to_string(),
            ),
            (
                local_index_key(
                    &root
                        .join(&parent)
                        .join("subagents")
                        .join("agent-a4d1585d310070d0f.jsonl"),
                ),
                "rev-child".to_string(),
            ),
        ]);
        Self {
            root,
            parent,
            valid_parent,
            items,
            sources,
        }
    }

    fn other_key(&self) -> String {
        local_index_key(&self.root.join(format!("{OTHER_ROOT}.jsonl")))
    }

    /// A second, single-member family with its own request ids.
    fn other_family(&self, structural: bool) -> SnapshotItem {
        let mut other = self.valid_parent.clone();
        let from = other.source_session_id.clone();
        other.source_session_id = OTHER_ROOT.to_string();
        for fact in &mut other.attribution_facts {
            if fact.value == from {
                fact.value = OTHER_ROOT.to_string();
            }
        }
        let rekey = |request: &str| format!("f{}", &request[1..]);
        other.claude_usage_request_ids = other
            .claude_usage_request_ids
            .iter()
            .map(|request| rekey(request))
            .collect();
        other.claude_usage_occurrences = std::mem::take(&mut other.claude_usage_occurrences)
            .into_iter()
            .map(|(request, occurrence)| (rekey(&request), occurrence))
            .collect();
        other.snapshot_fingerprint = format!("{}-other", other.snapshot_fingerprint);
        other.source_file_fingerprint = other
            .source_file_fingerprint
            .map(|fingerprint| format!("{fingerprint}-other"));
        if structural {
            other.claude_usage_occurrences.clear();
        }
        assert_eq!(claude_snapshot_family_root(&other), OTHER_ROOT);
        assert_eq!(claude_member_invalidity_is_structural(&other), structural);
        other
    }

    fn add_other_family(&mut self, index: &mut ScanIndex) {
        let key = self.other_key();
        self.sources.insert(key.clone(), "rev-other".to_string());
        insert_file(index, &key, "rev-other", 512);
    }

    /// A closed fence under a recorded, settled contract, every member
    /// committed.
    fn index(&self) -> ScanIndex {
        let mut index = ScanIndex {
            claude_duplicate_request_witness_overflowed: true,
            claude_request_identity_contract: Some(
                claude_request_identity::cycle_contract(false).to_string(),
            ),
            ..ScanIndex::default()
        };
        for (key, source) in &self.sources {
            let size = fs::metadata(key).map_or(512, |metadata| metadata.len());
            insert_file(&mut index, key, source, size);
        }
        index
    }

    fn fold(
        &self,
        index: &mut ScanIndex,
        items: &[SnapshotItem],
        census_complete: bool,
        max_pending_occurrences: usize,
    ) -> ClaudeUsageAuthorityDisposition {
        let mut items = items.to_vec();
        apply_claude_reported_usage_with_index_and_limits(
            &mut items,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport {
                evidence: BTreeMap::new(),
                health: Default::default(),
            },
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            index,
            census_complete,
            WINDOW,
            max_pending_occurrences,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
        )
    }

    /// A due terminal over `items`, then the next walk's re-read.
    fn terminal(&self, index: &mut ScanIndex, items: &[SnapshotItem]) -> Terminal {
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
        let disposition = self.fold(index, items, true, MAX_CLAUDE_PENDING_USAGE_OCCURRENCES);
        self.reread(index, &disposition)
    }

    fn base_terminal(&self, index: &mut ScanIndex, items: &[SnapshotItem]) -> Terminal {
        index.claude_full_rearm_progress = ClaudeFullRearmProgress::default();
        self.terminal(index, items)
    }

    /// Re-read every re-armed file, recording its current revision.
    fn reread(
        &self,
        index: &mut ScanIndex,
        disposition: &ClaudeUsageAuthorityDisposition,
    ) -> Terminal {
        let mut rearmed_files = 0;
        let mut rearmed_bytes = 0;
        for (key, source) in &self.sources {
            let entry = index.files.get_mut(key).expect("an indexed member");
            if entry.source_file_fingerprint.is_empty() {
                rearmed_files += 1;
                rearmed_bytes += entry.size_bytes;
                entry.source_file_fingerprint = source.clone();
            }
        }
        Terminal {
            counts: disposition.duplicate_census,
            suppression: disposition.full_rearm_suppression,
            rearmed_files,
            rearmed_bytes,
        }
    }

    /// The first closed terminal re-arms and records the set; the next one
    /// skips. Returns that skipping terminal.
    fn establish(&self, index: &mut ScanIndex, items: &[SnapshotItem]) -> Terminal {
        let first = self.terminal(index, items);
        assert!(first.counts.full_rearm, "no record yet: {first:?}");
        assert!(index.claude_full_rearm_progress.structural_record.is_some());
        let skipped = self.terminal(index, items);
        assert!(skipped.suppression.full_rearm_suppressed, "{skipped:?}");
        assert!(!skipped.counts.full_rearm);
        skipped
    }
}

impl Drop for Rearm {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn insert_file(index: &mut ScanIndex, key: &str, source: &str, size_bytes: u64) {
    let mut entry = manifest_index_entry(Some(&format!("body-{source}")));
    entry.source_file_fingerprint = source.to_string();
    entry.size_bytes = size_bytes;
    index.files.insert(key.to_string(), entry);
}

/// Positive: across N due terminals an unchanged structural set re-arms
/// once, where BASE re-reads the whole family at every one. The fence stays
/// closed, the census stays invalid, the attempt is not bumped, and the
/// skips are disclosed on the evidence line.
#[test]
fn unchanged_structural_set_skips_repeated_full_rearms() {
    const TERMINALS: usize = 5;
    let rearm = Rearm::new();
    let mut fix = rearm.index();
    let mut base = rearm.index();
    let fix_runs = (0..TERMINALS)
        .map(|_| rearm.terminal(&mut fix, &rearm.items))
        .collect::<Vec<_>>();
    let base_runs = (0..TERMINALS)
        .map(|_| rearm.base_terminal(&mut base, &rearm.items))
        .collect::<Vec<_>>();
    let family_bytes = rearm
        .sources
        .keys()
        .map(|key| fix.files[key].size_bytes)
        .sum::<u64>();
    // Preconditions on BASE: every due terminal re-arms the whole family.
    for run in &base_runs {
        assert!(run.counts.full_rearm && run.counts.fence_after, "{run:?}");
        assert!(run.counts.census_invalid);
        assert_eq!(run.counts.page_invalidated_identity_count, 1);
        assert_eq!(run.rearmed_files, 2);
        assert_eq!(run.suppression, ClaudeFullRearmSuppressionCounts::default());
    }
    // The first fix terminal has no record yet and re-arms like BASE.
    assert!(fix_runs[0].counts.full_rearm);
    assert_eq!(fix_runs[0].rearmed_files, 2);
    assert!(!fix_runs[0].suppression.full_rearm_suppressed);
    // FLIPS: every later due terminal skips.
    for (skipped, run) in fix_runs.iter().enumerate().skip(1) {
        assert!(!run.counts.full_rearm, "{run:?}");
        assert!(run.counts.fence_before && run.counts.fence_after);
        assert!(run.counts.census_invalid, "the census stays invalid");
        assert_eq!(run.rearmed_files, 0);
        assert_eq!(
            run.suppression,
            ClaudeFullRearmSuppressionCounts {
                full_rearm_suppressed: true,
                full_rearm_skipped_invalid_unchanged: skipped as u64,
                full_rearm_post_rebuild_skipped: 0,
                structural_invalid_family_count: 1,
                suppressed_since_unix_seconds: Some(CENSUS_CLOCK),
            }
        );
    }
    let parses = |runs: &[Terminal]| runs.iter().map(|run| run.rearmed_files).sum::<usize>();
    let bytes = |runs: &[Terminal]| runs.iter().map(|run| run.rearmed_bytes).sum::<u64>();
    assert_eq!(parses(&base_runs), 2 * TERMINALS);
    assert_eq!(parses(&fix_runs), 2);
    assert_eq!(bytes(&base_runs), family_bytes * TERMINALS as u64);
    assert_eq!(bytes(&fix_runs), family_bytes);
    assert_eq!(base.claude_duplicate_fence_rearm_attempt, TERMINALS as u8);
    assert_eq!(
        fix.claude_duplicate_fence_rearm_attempt, 1,
        "no attempt bump"
    );
    assert!(fix.claude_duplicate_request_witness_overflowed);
    assert!(!fix.claude_request_identity_contract_changed);

    // Disclosed beside the duplicate census, and absent while empty.
    let line = |suppression| {
        serde_json::to_value(crate::snapshot_sync::ClaudeLocalEvidenceStats {
            full_rearm_suppression: suppression,
            ..Default::default()
        })
        .unwrap()
    };
    let disclosed = line(fix_runs[TERMINALS - 1].suppression);
    assert_eq!(
        disclosed["full_rearm_suppression"]["full_rearm_skipped_invalid_unchanged"],
        (TERMINALS - 1) as u64
    );
    assert_eq!(
        disclosed["full_rearm_suppression"]["structural_invalid_family_count"],
        1
    );
    assert_eq!(
        disclosed["full_rearm_suppression"]["suppressed_since_unix_seconds"],
        CENSUS_CLOCK
    );
    assert!(line(Default::default())
        .get("full_rearm_suppression")
        .is_none());
    let encoded = serde_json::to_string(&ClaudeFullRearmSuppressionCounts {
        full_rearm_suppressed: true,
        full_rearm_skipped_invalid_unchanged: u64::MAX,
        full_rearm_post_rebuild_skipped: 0,
        structural_invalid_family_count: usize::MAX,
        suppressed_since_unix_seconds: Some(u64::MAX),
    })
    .unwrap();
    assert!(encoded.len() <= 192, "{} bytes", encoded.len());

    // The persisted record is content-free: digests and counts only.
    let progress = serde_json::to_string(&fix.claude_full_rearm_progress).unwrap();
    let root = rearm.root.to_string_lossy().to_string();
    for forbidden in [
        rearm.parent.as_str(),
        "a4d1585d",
        "rev-",
        "req_",
        root.as_str(),
    ] {
        assert!(!progress.contains(forbidden), "{forbidden}");
    }
}

/// An incremental terminal that reads nothing is closed only by coverage, by
/// the same unchanged structural family; it skips too. BASE re-arms.
#[test]
fn coverage_only_terminal_skips_while_the_set_is_unchanged() {
    let rearm = Rearm::new();
    let mut fix = rearm.index();
    rearm.establish(&mut fix, &rearm.items);
    let mut base = fix.clone();
    let quiet = rearm.terminal(&mut fix, &[]);
    let base_quiet = rearm.base_terminal(&mut base, &[]);
    assert!(base_quiet.counts.full_rearm && !base_quiet.counts.coverage_complete);
    assert_eq!(base_quiet.rearmed_files, 2);
    assert!(!quiet.counts.full_rearm && quiet.counts.fence_after);
    assert!(!quiet.counts.coverage_complete);
    assert!(quiet.suppression.full_rearm_suppressed);
    assert_eq!(quiet.suppression.full_rearm_skipped_invalid_unchanged, 2);
    assert_eq!(quiet.rearmed_files, 0);
}

/// COST: any change to a recorded member's revision re-arms exactly once;
/// that window records the new set and the skip resumes, counted afresh.
#[test]
fn changed_member_revision_rearms_once_then_skips_again() {
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    let recorded = index.claude_full_rearm_progress.structural_record.clone();
    let child = rearm.sources.keys().nth(1).unwrap().clone();
    rearm
        .sources
        .insert(child.clone(), "rev-child-2".to_string());
    index.files.get_mut(&child).unwrap().source_file_fingerprint = "rev-child-2".to_string();
    let changed = rearm.terminal(&mut index, &rearm.items);
    assert!(changed.counts.full_rearm, "{changed:?}");
    assert!(!changed.suppression.full_rearm_suppressed);
    assert_eq!(changed.rearmed_files, 2);
    assert_ne!(
        index.claude_full_rearm_progress.structural_record, recorded,
        "the new set is recorded"
    );
    let skipped = rearm.terminal(&mut index, &rearm.items);
    assert!(skipped.suppression.full_rearm_suppressed);
    assert_eq!(skipped.suppression.full_rearm_skipped_invalid_unchanged, 1);
    assert_eq!(skipped.rearmed_files, 0);

    // A recorded member that lost its committed revision re-arms too.
    index
        .files
        .get_mut(&child)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let uncommitted = rearm.terminal(&mut index, &rearm.items);
    assert!(uncommitted.counts.full_rearm, "{uncommitted:?}");
}

/// A changed set: a second structurally invalid family re-arms once, then
/// the two-family set skips.
#[test]
fn new_structural_family_rearms_once() {
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    rearm.add_other_family(&mut index);
    let mut items = rearm.items.clone();
    items.push(rearm.other_family(true));
    let grown = rearm.terminal(&mut index, &items);
    assert!(grown.counts.full_rearm, "{grown:?}");
    assert_eq!(grown.rearmed_files, 3);
    let skipped = rearm.terminal(&mut index, &items);
    assert!(skipped.suppression.full_rearm_suppressed, "{skipped:?}");
    assert_eq!(skipped.suppression.structural_invalid_family_count, 2);
}

/// Non-structural invalidation: a member changed within the window, or the
/// pending-occurrence cap, re-arms even while the structural set is
/// unchanged.
#[test]
fn non_structural_invalidation_rearms() {
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.add_other_family(&mut index);
    let other = rearm.other_family(false);
    let mut items = rearm.items.clone();
    items.push(other.clone());
    rearm.establish(&mut index, &items);

    // Member changed: a later page of the same window holds a shorter body.
    let mut prefix = other.clone();
    let last = prefix.claude_usage_request_ids.pop_last().unwrap();
    prefix.claude_usage_occurrences.remove(&last);
    prefix.request_count -= 1;
    let mut changed = index.clone();
    changed.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
    rearm.fold(
        &mut changed,
        &items,
        false,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    let disposition = rearm.fold(
        &mut changed,
        std::slice::from_ref(&prefix),
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    let changed = rearm.reread(&mut changed, &disposition);
    assert_eq!(changed.counts.page_invalidated_member_changed_count, 1);
    assert!(changed.counts.full_rearm, "{changed:?}");
    assert!(!changed.suppression.full_rearm_suppressed);

    // Cap: the second family's occurrences exceed the pending bound.
    let mut capped = index.clone();
    capped.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
    let disposition = rearm.fold(&mut capped, &items, true, 1);
    let capped = rearm.reread(&mut capped, &disposition);
    assert!(capped.counts.page_invalidated_cap_count > 0, "{capped:?}");
    assert!(capped.counts.full_rearm);
    assert!(!capped.suppression.full_rearm_suppressed);

    // The unchanged window still skips.
    assert!(
        rearm
            .terminal(&mut index, &items)
            .suppression
            .full_rearm_suppressed
    );
}

/// F1a: a set contract-5 latch, or an unrecorded contract, never skips; the
/// full re-arm runs and clears the latch as before, and the skip resumes.
#[test]
fn identity_contract_latch_or_unrecorded_contract_rearms() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);

    let mut unrecorded = index.clone();
    unrecorded.claude_request_identity_contract = None;
    let run = rearm.terminal(&mut unrecorded, &rearm.items);
    assert!(run.counts.full_rearm, "{run:?}");
    assert!(!run.suppression.full_rearm_suppressed);

    index.claude_request_identity_contract_changed = true;
    let latched = rearm.terminal(&mut index, &rearm.items);
    assert!(latched.counts.full_rearm, "{latched:?}");
    assert_eq!(latched.rearmed_files, 2);
    assert!(!index.claude_request_identity_contract_changed);
    let skipped = rearm.terminal(&mut index, &rearm.items);
    assert!(skipped.suppression.full_rearm_suppressed, "{skipped:?}");
}

/// A record written under another basis (a D1 derivation, scan identity or
/// record version bump) re-arms once, then the current basis is recorded.
#[test]
fn record_basis_change_rearms_once() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    index
        .claude_full_rearm_progress
        .structural_record
        .as_mut()
        .unwrap()
        .basis = "older-derivation".to_string();
    let bumped = rearm.terminal(&mut index, &rearm.items);
    assert!(bumped.counts.full_rearm, "{bumped:?}");
    assert_eq!(
        index
            .claude_full_rearm_progress
            .structural_record
            .as_ref()
            .unwrap()
            .basis,
        claude_full_rearm_record_basis(claude_request_identity::cycle_contract(false))
    );
    assert!(
        rearm
            .terminal(&mut index, &rearm.items)
            .suppression
            .full_rearm_suppressed
    );
}

/// A first-proof hold on a dormant owner (C1a) waits on the full re-arm, so
/// it vetoes the skip until one runs.
#[test]
fn first_proof_hold_vetoes_the_skip_until_a_full_rearm() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    index
        .claude_full_rearm_progress
        .first_proof_hold_since_full_rearm = true;
    let held = rearm.terminal(&mut index, &rearm.items);
    assert!(held.counts.full_rearm, "{held:?}");
    assert!(
        !index
            .claude_full_rearm_progress
            .first_proof_hold_since_full_rearm
    );
    assert!(
        rearm
            .terminal(&mut index, &rearm.items)
            .suppression
            .full_rearm_suppressed
    );
}

/// A malformed persisted progress value decodes as no progress: the index
/// still loads (nothing is quarantined) and the next due terminal re-arms.
#[test]
fn malformed_persisted_progress_loads_and_rearms() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.terminal(&mut index, &rearm.items);
    let dir = temp_dir("claude-full-rearm-progress-malformed");
    let path = dir.join("claude-scan-index.json");
    fs::write(&path, serde_json::to_vec(&index).unwrap()).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(
        loaded.claude_full_rearm_progress,
        index.claude_full_rearm_progress
    );
    assert!(
        rearm
            .terminal(&mut loaded, &rearm.items)
            .suppression
            .full_rearm_suppressed
    );
    for malformed in [
        serde_json::json!(42),
        serde_json::json!("x"),
        serde_json::json!([1, 2]),
        serde_json::json!({"structural_record": 7}),
        serde_json::json!({"structural_record": {"basis": 1}}),
        serde_json::json!({"stale_rearms_at_deadline": -1}),
    ] {
        let mut saved = serde_json::to_value(&index).unwrap();
        saved["claude_full_rearm_progress"] = malformed.clone();
        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut loaded = ScanIndex::load(&path).expect("the index still loads");
        assert!(path.exists(), "{malformed}: not quarantined");
        assert!(
            loaded.files.keys().eq(index.files.keys()),
            "{malformed}: the files survive"
        );
        assert_eq!(
            loaded.claude_full_rearm_progress,
            ClaudeFullRearmProgress::default(),
            "{malformed}"
        );
        let run = rearm.terminal(&mut loaded, &rearm.items);
        assert!(
            run.counts.full_rearm && run.counts.fence_after,
            "{malformed}"
        );
        assert_eq!(run.rearmed_files, 2);
    }
    let _ = fs::remove_dir_all(dir);
}

/// COST ruling #3: a rebuilt index (the #700 seen marker beside a fresh
/// index) starts no backoff ramp. Its first close still re-arms once, but the
/// next due re-arm waits the capped delay; without the marker a fresh index
/// ramps from the base delay as before.
#[test]
fn rebuilt_index_first_close_waits_the_capped_delay() {
    let rearm = Rearm::new();
    let support = temp_dir("claude-full-rearm-rebuild");
    let path = support.join("claude-scan-index.json");
    let fresh =
        ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &support).unwrap();
    assert_eq!(fresh.claude_duplicate_fence_rearm_attempt, 0);
    let marker = ReemissionExclusions::seen_marker_path(&support);
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    fs::write(&marker, "").unwrap();
    let rebuilt =
        ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &support).unwrap();
    restart_claude_reemission_stop_for_test();
    assert_eq!(
        rebuilt.claude_duplicate_fence_rearm_attempt,
        CLAUDE_DUPLICATE_FENCE_REARM_MAX_ATTEMPT
    );
    // Other sources never seed it.
    let codex = ScanIndex::load_for_snapshot_source(
        &support.join("codex-scan-index.json"),
        SnapshotSource::Codex,
        &support,
    )
    .unwrap();
    assert_eq!(codex.claude_duplicate_fence_rearm_attempt, 0);
    for (mut index, delay) in [
        (fresh, CLAUDE_DUPLICATE_FENCE_REARM_BASE_SECONDS),
        (rebuilt, CLAUDE_DUPLICATE_FENCE_REARM_MAX_SECONDS),
    ] {
        let counts = rearm
            .fold(
                &mut index,
                &rearm.items,
                true,
                MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            )
            .duplicate_census;
        assert!(!counts.fence_before && counts.fence_after, "{counts:?}");
        assert!(counts.full_rearm, "a close still re-arms once");
        assert_eq!(counts.full_rearm_deferred_until, Some(CENSUS_CLOCK + delay));
    }
    let _ = fs::remove_dir_all(support);
}

#[test]
fn structural_classification_accepts_only_own_byte_count_failures() {
    let rearm = Rearm::new();
    let valid = &rearm.valid_parent;
    assert!(!claude_member_invalidity_is_structural(valid));
    let mut missing_id = valid.clone();
    missing_id.claude_usage_request_ids.pop_last();
    assert!(claude_member_invalidity_is_structural(&missing_id));
    let mut duplicate_response = valid.clone();
    duplicate_response.request_count += 1;
    assert!(claude_member_invalidity_is_structural(&duplicate_response));
    let mut missing_occurrence = valid.clone();
    missing_occurrence.claude_usage_occurrences.pop_last();
    assert!(claude_member_invalidity_is_structural(&missing_occurrence));
    let mut unknown = valid.clone();
    unknown.request_count = 0;
    assert!(!claude_member_invalidity_is_structural(&unknown));
}

#[test]
fn unknown_identity_failure_in_a_structural_family_keeps_the_rearm() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    let mut items = rearm.items.clone();
    items[0].request_count = 0;
    let unknown = rearm.terminal(&mut index, &items);
    assert!(unknown.counts.full_rearm);
    assert!(!unknown.suppression.full_rearm_suppressed);
    assert_eq!(unknown.rearmed_files, 2);
}

#[test]
fn contract_rearm_remains_independent_of_the_full_rearm_deadline() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(CENSUS_CLOCK + 100);
    index.claude_request_identity_contract_changed = true;
    index.bounded_sweep_had_unsettled_upload = true;
    let disposition = rearm.fold(
        &mut index,
        &rearm.items,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    let run = rearm.reread(&mut index, &disposition);
    assert!(!run.counts.full_rearm, "liveness re-arm is not due");
    assert!(!run.suppression.full_rearm_suppressed);
    assert_eq!(run.rearmed_files, 2, "the contract re-arm still runs");
    assert!(
        index.claude_request_identity_contract_changed,
        "the unsettled latch survives"
    );
}

/// The production scanner retires a clean traversal before the fold. Its
/// origin must survive so the re-arm can bind the next window, even then.
#[test]
fn full_rearm_window_keeps_the_origin_after_scanner_checkpoint_retirement() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        WINDOW,
        BACKFILL_WINDOW_DAYS,
    );
    let origin = index
        .traversal
        .as_ref()
        .unwrap()
        .context_fingerprint
        .clone();
    index.traversal = None;
    let closed = rearm.terminal(&mut index, &rearm.items);
    assert!(closed.counts.full_rearm);
    let window = index
        .claude_full_rearm_progress
        .full_rearm_window
        .as_ref()
        .unwrap();
    assert_eq!(window.context_fingerprint, origin);
    assert_eq!(window.process, claude_full_rearm_process());
    assert!(index.claude_full_rearm_progress.full_rearm_window_next);
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        "2026-08-02T07:20:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    assert_eq!(
        index
            .claude_full_rearm_progress
            .full_rearm_window
            .as_ref()
            .unwrap()
            .window_ends,
        BTreeSet::from(["2026-08-02T07:20:00Z".to_string()])
    );
}

/// An observation before the deadline cannot pay for the required full re-arm.
#[test]
fn non_due_changes_remain_owed_until_one_real_full_rearm() {
    for cause in ["member", "set", "basis", "missing", "malformed", "reverted"] {
        let mut rearm = Rearm::new();
        let mut index = rearm.index();
        rearm.establish(&mut index, &rearm.items);
        let mut items = rearm.items.clone();
        match cause {
            "member" | "reverted" => {
                let key = rearm.sources.keys().next().unwrap().clone();
                index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .source_file_fingerprint
                    .push_str("-changed");
                if cause == "member" {
                    rearm.sources.get_mut(&key).unwrap().push_str("-changed");
                }
            }
            "set" => {
                rearm.add_other_family(&mut index);
                items.push(rearm.other_family(true));
            }
            "basis" => {
                index
                    .claude_full_rearm_progress
                    .structural_record
                    .as_mut()
                    .unwrap()
                    .basis = "previous-basis".to_string()
            }
            "missing" | "malformed" => {
                let mut saved = serde_json::to_value(&index).unwrap();
                if cause == "missing" {
                    saved
                        .as_object_mut()
                        .unwrap()
                        .remove("claude_full_rearm_progress");
                } else {
                    saved["claude_full_rearm_progress"] =
                        serde_json::json!({"structural_record": 7});
                }
                index = serde_json::from_value(saved).unwrap();
            }
            _ => unreachable!(),
        }
        let before = index.claude_full_rearm_progress.structural_record.clone();
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(CENSUS_CLOCK + 100);
        let early = rearm.fold(
            &mut index,
            &items,
            true,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        );
        let early = rearm.reread(&mut index, &early);
        assert!(!early.counts.full_rearm, "{cause}: {early:?}");
        assert!(!early.suppression.full_rearm_suppressed, "{cause}");
        assert_eq!(early.rearmed_files, 0, "{cause}");
        assert_eq!(
            index.claude_full_rearm_progress.structural_record, before,
            "{cause}"
        );
        assert!(
            index.claude_full_rearm_progress.structural_rearm_owed,
            "{cause}"
        );
        // The obligation survives persistence, including a change that reverts.
        index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        if cause == "reverted" {
            for (key, revision) in &rearm.sources {
                index.files.get_mut(key).unwrap().source_file_fingerprint = revision.clone();
            }
        }
        let due = rearm.terminal(&mut index, &items);
        assert!(due.counts.full_rearm, "{cause}: {due:?}");
        assert_eq!(due.rearmed_files, rearm.sources.len(), "{cause}");
        assert!(!due.suppression.full_rearm_suppressed, "{cause}");
        assert!(
            !index.claude_full_rearm_progress.structural_rearm_owed,
            "{cause}"
        );
        let next = rearm.terminal(&mut index, &items);
        assert!(!next.counts.full_rearm, "{cause}: {next:?}");
        assert!(next.suppression.full_rearm_suppressed, "{cause}");
        assert_eq!(next.rearmed_files, 0, "{cause}");
    }
}

/// Every disallowed cause is exercised through the real terminal fold with
/// an otherwise unchanged, established structural baseline.
#[test]
fn non_own_byte_causes_veto_structural_suppression_at_the_terminal() {
    for cause in [
        "account",
        "owned-start",
        "api",
        "trace",
        "bad-clock",
        "census-clock",
        "filtered-health",
        "identity-refused",
        "coverage",
    ] {
        let mut rearm = Rearm::new();
        let mut index = rearm.index();
        rearm.establish(&mut index, &rearm.items);
        let mut items = rearm.items.clone();
        let mut api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
        let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
        let mut window = WINDOW;
        match cause {
            "account" => {
                let key = rearm.sources.keys().next().unwrap().clone();
                index
                    .claude_account_deferred_holds
                    .insert(key, "held-revision".to_string());
            }
            "owned-start" => {
                index.claude_owned_start_census.insert(
                    items[0].source_session_id.clone(),
                    ClaudeOwnedStartCensusWitness {
                        marker_source_file_fingerprint: "marker-revision".to_string(),
                        verified_source_file_fingerprint: None,
                        emitted_source_file_fingerprint: None,
                    },
                );
            }
            "api" => api.health.missing_files = 1,
            "trace" => trace.missing_files = 1,
            "bad-clock" => {
                items[0]
                    .claude_usage_occurrences
                    .values_mut()
                    .next()
                    .unwrap()
                    .event_clock_complete = false
            }
            "census-clock" => window = "bad-clock",
            "filtered-health" => index.note_claude_full_rearm_evidence_gap(window),
            "identity-refused" => items[0].request_identity_refusals = 1,
            "coverage" => rearm.add_other_family(&mut index),
            _ => unreachable!(),
        }
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
        let disposition = apply_claude_reported_usage_with_index_and_limits(
            &mut items,
            &api,
            &trace,
            &mut index,
            true,
            window,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
        );
        let run = rearm.reread(&mut index, &disposition);
        assert!(
            run.counts.fence_before && run.counts.fence_after,
            "{cause}: {run:?}"
        );
        assert!(run.counts.full_rearm, "{cause}: {run:?}");
        assert!(!run.suppression.full_rearm_suppressed, "{cause}");
        assert_eq!(run.rearmed_files, rearm.sources.len(), "{cause}");
    }
}

#[test]
fn unhealthy_earlier_page_keeps_a_healthy_terminal_rearm_enabled() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    let mut api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    api.health.unreadable_lines = 1;
    apply_claude_reported_usage_with_index_and_limits(
        &mut [],
        &api,
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        &mut index,
        false,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    );
    let run = rearm.terminal(&mut index, &rearm.items);
    assert!(run.counts.full_rearm);
    assert!(!run.suppression.full_rearm_suppressed);
    assert_eq!(run.rearmed_files, 2);
}

#[test]
fn occurrence_key_mismatch_in_an_already_invalid_family_still_vetoes() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    let mut items = rearm.items.clone();
    let (key, occurrence) = items[0].claude_usage_occurrences.pop_first().unwrap();
    items[0]
        .claude_usage_occurrences
        .insert(format!("unknown-{key}"), occurrence);
    assert!(!claude_member_invalidity_is_structural(&items[0]));
    rearm.fold(
        &mut index,
        &rearm.items,
        false,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    let run = rearm.terminal(&mut index, &items);
    assert!(run.counts.full_rearm);
    assert!(!run.suppression.full_rearm_suppressed);
    assert_eq!(run.rearmed_files, 2);
}

/// Production removes unpaired/unhealthy sidecars from the aggregate reports.
/// Those reports must not erase the suppression veto, even without a permit.
#[test]
fn pipeline_filtered_sidecar_failures_keep_the_due_rearm_enabled() {
    let rearm = Rearm::new();
    let mut baseline = rearm.index();
    rearm.establish(&mut baseline, &rearm.items);
    for cause in [
        "absent",
        "matched",
        "unpaired",
        "malformed-pair",
        "request-gap",
        "client-mismatch",
        "invalid-api",
    ] {
        let support = temp_dir("full-rearm-filtered-sidecars");
        if cause != "absent" {
            let digest = format!("{:x}", Sha256::digest(rearm.parent.as_bytes()));
            let mut kinds = vec!["claude-code-effort"];
            if cause != "unpaired" {
                kinds.push("claude-code-trace-ownership");
            }
            for kind in kinds {
                let path = support
                    .join("local-otel")
                    .join(kind)
                    .join(format!("{digest}.jsonl"));
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                let row = if !matches!(cause, "unpaired" | "malformed-pair") {
                    if kind == "claude-code-effort" {
                        let mut row = complete_api_row(&rearm.parent, "req_1", 0, 10, 10, 0);
                        // This dark-path control claims no account identity.
                        // Partial checked coverage would independently veto the
                        // skip and mask semantic client/row failures below.
                        row.account_identity_checked = false;
                        row.account_identifier_hash = None;
                        if cause == "invalid-api" {
                            row.request_count = 2;
                        }
                        row.fingerprint.clear();
                        row.fingerprint = format!(
                            "sha256:{:x}",
                            Sha256::digest(serde_json::to_vec(&row).unwrap())
                        );
                        assert_eq!(
                            validate_claude_api_row(&row, &rearm.parent),
                            cause != "invalid-api"
                        );
                        serde_json::to_string(&row).unwrap()
                    } else {
                        let request = if cause == "request-gap" {
                            "req_gap"
                        } else {
                            "req_1"
                        };
                        let mut row = complete_trace_row(&rearm.parent, request, "");
                        if cause == "client-mismatch" {
                            row.client_request_id = "different-nonempty-client".to_string();
                            row.fingerprint.clear();
                            row.fingerprint = format!(
                                "sha256:{:x}",
                                Sha256::digest(serde_json::to_vec(&row).unwrap())
                            );
                            assert!(claude_trace_evidence_fingerprint_is_valid(&row));
                        }
                        serde_json::to_string(&row).unwrap()
                    }
                } else {
                    "not json".to_string()
                };
                fs::write(path, format!("{row}\n")).unwrap();
            }
        }
        let mut index = baseline.clone();
        // A second terminal uses the exact same source revisions and sidecar
        // bytes, so a change-triggered reread cannot mask semantic qualification.
        for _ in 0..2 {
            // Obtain a real empty scan envelope, independently of the index whose
            // baseline is under test, then supply this window's parsed fixture.
            let mut scan = scan_source_roots_with_test_limit(
                SnapshotSource::ClaudeCode,
                &[],
                &mut ScanIndex::default(),
                WINDOW,
                7,
                100,
                false,
            )
            .unwrap();
            scan.snapshots = rearm.items.clone();
            scan.census_complete = true;
            index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
            let record = index
                .claude_full_rearm_progress
                .structural_record
                .clone()
                .map(|mut record| {
                    // A paid rearm preserves the baseline, resetting its skip history.
                    record.suppressed_since_unix_seconds = None;
                    record.skipped_full_rearms = 0;
                    record
                });
            let (disposition, _, stats) = crate::snapshot_sync::apply_claude_local_evidence_to_scan(
                &support, &mut scan, &mut index,
            );
            assert!(
                scan.snapshots
                    .iter()
                    .all(|item| item.claude_account_withheld_reason.is_none()),
                "{cause}: account withholding cannot mask semantic qualification"
            );
            assert!(index.claude_account_deferred_holds.is_empty(), "{cause}");
            assert!(index.claude_owned_start_census.is_empty(), "{cause}");
            assert!(!index.claude_request_identity_contract_changed, "{cause}");
            if cause == "request-gap" {
                assert_eq!(stats.api_incomplete_root_count, 0);
                assert_eq!(stats.trace_incomplete_root_count, 0);
                assert_eq!(stats.request_set_mismatch_root_count, 1);
            }
            if matches!(cause, "matched" | "client-mismatch" | "invalid-api") {
                assert_eq!(stats.api_incomplete_root_count, 0, "{cause}");
                assert_eq!(stats.trace_incomplete_root_count, 0, "{cause}");
                assert_eq!(stats.exact_request_set_root_count, 1, "{cause}");
                assert_eq!(stats.request_set_mismatch_root_count, 0, "{cause}");
            }
            let run = rearm.reread(&mut index, &disposition);
            assert!(
                run.counts.fence_before && run.counts.fence_after,
                "{cause}: {run:?}"
            );
            if matches!(cause, "absent" | "matched") {
                assert!(
                    run.suppression.full_rearm_suppressed,
                    "{cause} healthy control: {run:?}"
                );
                assert!(!run.counts.full_rearm);
                assert_eq!(run.rearmed_files, 0);
            } else {
                assert!(run.counts.full_rearm, "{cause}: {run:?}");
                assert!(!run.suppression.full_rearm_suppressed, "{cause}");
                assert_eq!(run.rearmed_files, 2, "{cause}");
                assert_eq!(
                    index.claude_full_rearm_progress.structural_record, record,
                    "semantic refusals do not replace the structural baseline"
                );
            }
        }
        let _ = fs::remove_dir_all(support);
    }
}

/// The real rebuild produces BadClock for an auxiliary row in this pass,
/// before final identity application installs its refusal counter on the item.
#[test]
fn pipeline_new_auxiliary_bad_clock_keeps_the_due_rearm_enabled() {
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.add_other_family(&mut index);
    index.claude_request_identity_contract =
        Some(claude_request_identity::cycle_contract(true).to_string());
    let other = rearm.other_family(false);
    assert_eq!(other.request_identity_refusals, 0);
    assert!(other
        .claude_usage_occurrences
        .values()
        .all(|occurrence| occurrence.event_clock_complete));
    let mut items = rearm.items.clone();
    items.push(other.clone());
    let support = temp_dir("full-rearm-auxiliary-bad-clock");
    let digest = format!("{:x}", Sha256::digest(OTHER_ROOT.as_bytes()));
    let mut api = other
        .claude_usage_request_ids
        .iter()
        .enumerate()
        .map(|(sequence, request)| {
            complete_api_row(OTHER_ROOT, request, sequence as u64, 10, 10, 0)
        })
        .collect::<Vec<_>>();
    let mut trace = other
        .claude_usage_request_ids
        .iter()
        .map(|request| complete_trace_row(OTHER_ROOT, request, ""))
        .collect::<Vec<_>>();
    let write_rows =
        |api: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
         trace: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence]| {
            for (kind, rows) in [
                (
                    "claude-code-effort",
                    api.iter()
                        .map(|row| serde_json::to_string(row).unwrap())
                        .collect::<Vec<_>>(),
                ),
                (
                    "claude-code-trace-ownership",
                    trace
                        .iter()
                        .map(|row| serde_json::to_string(row).unwrap())
                        .collect::<Vec<_>>(),
                ),
            ] {
                let path = support
                    .join("local-otel")
                    .join(kind)
                    .join(format!("{digest}.jsonl"));
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, rows.join("\n") + "\n").unwrap();
            }
        };
    write_rows(&api, &trace);
    let terminal = |index: &mut ScanIndex| {
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            &[],
            &mut ScanIndex::default(),
            WINDOW,
            7,
            100,
            false,
        )
        .unwrap();
        scan.snapshots = items.clone();
        scan.census_complete = true;
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
        let permit = claude_request_identity::emission_permit(
            SnapshotSource::ClaudeCode,
            Some(claude_request_identity::COHORT_HINT_TOKEN),
        )
        .unwrap();
        let (disposition, _, stats) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan_with_permit(
                &support,
                &mut scan,
                index,
                Some(permit),
            );
        assert_eq!(stats.api_incomplete_root_count, 0);
        assert_eq!(stats.trace_incomplete_root_count, 0);
        assert_eq!(stats.exact_request_set_root_count, 1);
        assert_eq!(stats.request_set_mismatch_root_count, 0);
        let reported = scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == OTHER_ROOT)
            .unwrap();
        assert_eq!(
            reported.usage_accounting_contract.as_deref(),
            Some("session_exclusive_reported_usage:v1")
        );
        assert_eq!(
            reported.provenance.collector,
            claude_request_identity::COLLECTOR
        );
        assert!(!index.claude_request_identity_contract_changed);
        assert!(index.claude_account_deferred_holds.is_empty());
        assert!(index.claude_owned_start_census.is_empty());
        let run = rearm.reread(index, &disposition);
        (run, reported.clone())
    };
    // Establish the structural baseline and healthy matched-pair control
    // under this same permit contract, with every source revision unchanged.
    let (first, reported) = terminal(&mut index);
    assert!(first.counts.full_rearm);
    assert_eq!(reported.request_identity_refusals, 0);
    let (healthy, _) = terminal(&mut index);
    assert!(healthy.suppression.full_rearm_suppressed, "{healthy:?}");
    assert!(!healthy.counts.full_rearm);
    let record = index
        .claude_full_rearm_progress
        .structural_record
        .clone()
        .map(|mut record| {
            record.suppressed_since_unix_seconds = None;
            record.skipped_full_rearms = 0;
            record
        });
    assert!(record.is_some());

    let auxiliary = "auxiliary-no-transcript-clock";
    assert!(!other.claude_usage_request_ids.contains(auxiliary));
    api.push(complete_api_row(OTHER_ROOT, auxiliary, 10, 17, 3, 0));
    trace.push(complete_trace_row(OTHER_ROOT, auxiliary, ""));
    // Validate the exact canonical refusal independently of the scheduling
    // assertion; every paired row is otherwise valid and fully decodable.
    let api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([(OTHER_ROOT.to_string(), api.clone())]),
        ..Default::default()
    };
    let trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(OTHER_ROOT.to_string(), trace.clone())]),
        ..Default::default()
    };
    assert!(claude_legacy_request_owners(&api_report, &trace_report).is_some());
    let evidence = claude_request_identity::ScanEvidence::new(
        &api_report,
        &trace_report,
        BTreeSet::new(),
        None,
    );
    assert_eq!(
        claude_request_identity::classify(
            &evidence,
            &claude_request_identity::RequestFacts {
                root: OTHER_ROOT,
                source_session_id: OTHER_ROOT,
                request_id: auxiliary,
                terminal_unix_seconds: None,
                event_clock_complete: false,
                marker: claude_request_identity::MarkerVerdict::None,
                desktop: false,
                scan_unix_seconds: Some(CENSUS_CLOCK),
                email_home: None,
                session_start_unix_seconds: None,
                duplicated_elsewhere: false,
            }
        ),
        claude_request_identity::RequestIdentity::Refused(
            claude_request_identity::Refusal::BadClock
        )
    );
    write_rows(&api, &trace);
    // Repeat the same evidence to exercise the steady state too; no contract
    // change, prior item counter, sidecar change or structural change pays it.
    for _ in 0..2 {
        let (run, reported) = terminal(&mut index);
        assert_eq!(reported.request_count, 5);
        assert!(reported.request_identity_refusals > 0);
        assert!(run.counts.full_rearm, "{run:?}");
        assert!(!run.suppression.full_rearm_suppressed, "{run:?}");
        assert_eq!(run.rearmed_files, 3);
        assert_eq!(index.claude_full_rearm_progress.structural_record, record);
    }
    let _ = fs::remove_dir_all(support);
}

/// A previously loaded rebuild checkpoint can prove a new complete read; a
/// fresh load itself cannot. This is the same non-fresh rule used by #712.
fn rebuild_candidate(rearm: &Rearm, origin: ScanIndexLoadOrigin) -> ScanIndex {
    let mut index = rearm.index();
    index.generation = 1;
    index.claude_duplicate_request_witness_overflowed = false;
    index.claude_duplicate_fence_rearm_attempt = CLAUDE_DUPLICATE_FENCE_REARM_MAX_ATTEMPT;
    index.settle_claude_index_load(&rearm.root.join("index.json"), origin);
    index.claude_full_rearm_progress.rebuild_read_full = index.claude_rebuild_read_load_eligible;
    index.claude_full_rearm_progress.traversal_origin = Some(ClaudeFullRearmWindow {
        context_fingerprint: "rebuild-context".to_string(),
        process: claude_full_rearm_process(),
        window_ends: BTreeSet::from([WINDOW.to_string()]),
        member_digests: BTreeMap::new(),
    });
    index
}

fn rebuild_reads(index: &ScanIndex) -> Vec<PendingIndexFinalization> {
    index
        .files
        .iter()
        .map(|(key, entry)| PendingIndexFinalization {
            sampled_audit_verified: false,
            codex_pending_recovery: false,
            index_key: key.clone(),
            source_file_fingerprint: entry.source_file_fingerprint.clone(),
            previous_snapshot_fingerprint: None,
            previous_upload_body_witness: None,
            parse_complete: true,
            diagnostic_reason: FileReason::Complete,
            parsed_snapshot_count: 1,
            effective_upload_body_witness_revision: 0,
        })
        .collect()
}

#[test]
fn complete_rebuild_read_skips_only_the_first_close_and_discloses_it() {
    let rearm = Rearm::new();
    let mut index = rebuild_candidate(&rearm, ScanIndexLoadOrigin::Loaded);
    seal_claude_complete_rebuild_read(&mut index, &rebuild_reads(&rearm.index()), true);
    assert!(index
        .claude_full_rearm_progress
        .complete_rebuild_read
        .is_some());
    let run = rearm.terminal(&mut index, &rearm.items);
    assert!(!run.counts.fence_before && run.counts.fence_after);
    assert!(!run.counts.full_rearm, "{run:?}");
    assert_eq!(run.rearmed_files, 0);
    assert_eq!(run.suppression.full_rearm_post_rebuild_skipped, 1);
    assert_eq!(
        run.counts.full_rearm_deferred_until,
        Some(CENSUS_CLOCK + CLAUDE_DUPLICATE_FENCE_REARM_MAX_SECONDS)
    );
    let disclosed = serde_json::to_value(crate::snapshot_sync::ClaudeLocalEvidenceStats {
        full_rearm_suppression: run.suppression,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        disclosed["full_rearm_suppression"]["full_rearm_post_rebuild_skipped"],
        1
    );
    assert!(index
        .claude_full_rearm_progress
        .complete_rebuild_read
        .is_none());
    let due = rearm.terminal(&mut index, &rearm.items);
    assert!(due.counts.full_rearm, "proof is single-use: {due:?}");
}

#[test]
fn incomplete_rebuild_read_keeps_rearm_for_every_refusal() {
    let rearm = Rearm::new();
    for cause in [
        "partial",
        "failed",
        "cap",
        "tail",
        "withheld",
        "excluded-source",
        "revision",
        "membership",
        "origin",
        "restart",
        "identity-contract",
        "occurrence-cap",
    ] {
        let mut index = rebuild_candidate(&rearm, ScanIndexLoadOrigin::Loaded);
        let mut reads = rebuild_reads(&index);
        match cause {
            "partial" => {
                reads.pop();
            }
            "failed" => reads[0].parse_complete = false,
            "cap" => index.claude_full_rearm_progress.rebuild_read_full = false,
            "tail" => index.claude_full_rearm_progress.rebuild_read_full = false,
            _ => {}
        }
        seal_claude_complete_rebuild_read(&mut index, &reads, true);
        match cause {
            "withheld" => index.mark_bounded_sweep_unsettled(),
            "excluded-source" => {
                index
                    .effective_upload_body_witness_revision_excluded_source_files
                    .insert("held-source".to_string());
            }
            "revision" => index
                .files
                .values_mut()
                .next()
                .unwrap()
                .source_file_fingerprint
                .push('x'),
            "membership" => {
                index.files.pop_first();
            }
            "origin" => index
                .claude_full_rearm_progress
                .traversal_origin
                .as_mut()
                .unwrap()
                .context_fingerprint
                .push('x'),
            "restart" => {
                let value = serde_json::to_vec(&index).unwrap();
                let path = rearm.root.join("restart-index.json");
                fs::write(&path, value).unwrap();
                index = ScanIndex::load(&path).unwrap();
                assert!(index
                    .claude_full_rearm_progress
                    .complete_rebuild_read
                    .is_none());
            }
            "identity-contract" => index.claude_request_identity_contract_changed = true,
            _ => {}
        }
        let disposition = rearm.fold(
            &mut index,
            &rearm.items,
            true,
            if cause == "occurrence-cap" {
                0
            } else {
                MAX_CLAUDE_PENDING_USAGE_OCCURRENCES
            },
        );
        assert!(
            disposition.duplicate_census.full_rearm,
            "{cause}: {disposition:?}"
        );
        assert_eq!(
            disposition
                .full_rearm_suppression
                .full_rearm_post_rebuild_skipped,
            0,
            "{cause}"
        );
    }
}

#[test]
fn fresh_load_origins_never_prove_a_complete_rebuild_even_after_replay_fills_files() {
    let rearm = Rearm::new();
    for origin in [
        ScanIndexLoadOrigin::Missing,
        ScanIndexLoadOrigin::Quarantined,
    ] {
        let mut index = rebuild_candidate(&rearm, origin);
        assert!(!index.claude_rebuild_read_load_eligible);
        seal_claude_complete_rebuild_read(&mut index, &rebuild_reads(&rearm.index()), true);
        assert!(index
            .claude_full_rearm_progress
            .complete_rebuild_read
            .is_none());
        let run = rearm.terminal(&mut index, &rearm.items);
        assert!(run.counts.full_rearm, "{origin:?}: {run:?}");
        assert_eq!(run.suppression.full_rearm_post_rebuild_skipped, 0);
    }
    let mut empty = ScanIndex::default();
    empty.settle_claude_index_load(&rearm.root.join("empty.json"), ScanIndexLoadOrigin::Loaded);
    assert!(!empty.claude_rebuild_read_load_eligible);
}

/// Real discovery/parser wiring, plus fail-closed reuse of unchanged files.
#[test]
fn scanner_seals_only_actual_complete_rebuild_reads() {
    let rearm = Rearm::new();
    let mut index = rebuild_candidate(&rearm, ScanIndexLoadOrigin::Loaded);
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    let mut scan = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&rearm.root),
        &mut index,
        WINDOW,
        0,
        100,
        false,
    )
    .unwrap();
    assert!(scan.census_complete, "{scan:?}");
    assert_eq!(scan.scanned_file_count, rearm.sources.len());
    assert!(index
        .claude_full_rearm_progress
        .complete_rebuild_read
        .is_some());
    assert!(take_claude_complete_rebuild_read(&mut index, WINDOW));
    // This raw scan entry leaves policy finalization to its caller. Without
    // it, missing activity/incidence metadata legitimately selects unchanged
    // files for LegacyActivity reparsing and seals another complete read.
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    assert_eq!(index.file_snapshot_fingerprints.len(), rearm.sources.len());
    assert!(index
        .file_snapshot_fingerprints
        .values()
        .all(|fingerprints| {
            !fingerprints.is_empty()
                && fingerprints.iter().all(|fingerprint| {
                    index
                        .snapshot_activity_at
                        .get(fingerprint)
                        .is_some_and(valid_snapshot_activity)
                })
        }));
    let scan = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&rearm.root),
        &mut index,
        "2026-08-02T08:10:00Z",
        0,
        100,
        false,
    )
    .unwrap();
    assert!(scan.census_complete);
    assert_eq!(
        scan.scanned_file_count, 0,
        "unchanged files must be skipped"
    );
    assert!(scan.pending_finalization.is_empty());
    assert!(
        index
            .claude_full_rearm_progress
            .complete_rebuild_read
            .is_none(),
        "unchanged files were not read again"
    );
}

#[test]
fn structural_family_masks_valid_cross_file_duplicate_with_or_without_full_rearm() {
    const THIRD_ROOT: &str = "d6666666-6666-4666-8666-666666666666";
    let mut rearm = Rearm::new();
    let mut fix = rearm.index();
    rearm.add_other_family(&mut fix);
    let first = rearm.other_family(false);
    let mut second = first.clone();
    second.source_session_id = THIRD_ROOT.to_string();
    for fact in &mut second.attribution_facts {
        if fact.value == OTHER_ROOT {
            fact.value = THIRD_ROOT.to_string();
        }
    }
    second.snapshot_fingerprint.push_str("-third");
    assert_eq!(claude_snapshot_family_root(&second), THIRD_ROOT);
    assert_eq!(
        first.claude_usage_request_ids,
        second.claude_usage_request_ids
    );
    let third_key = local_index_key(&rearm.root.join(format!("{THIRD_ROOT}.jsonl")));
    rearm
        .sources
        .insert(third_key.clone(), "rev-third".to_string());
    insert_file(&mut fix, &third_key, "rev-third", 512);
    let mut items = rearm.items.clone();
    items.extend([first.clone(), second.clone()]);
    rearm.establish(&mut fix, &items);
    let mut base = fix.clone();
    let skipped = rearm.terminal(&mut fix, &items);
    let paid = rearm.base_terminal(&mut base, &items);
    assert!(!skipped.counts.full_rearm);
    assert!(paid.counts.full_rearm);
    for index in [&fix, &base] {
        assert!(index.claude_duplicate_request_witness_overflowed);
        assert!(
            index.claude_duplicate_request_owners.is_empty(),
            "the structural family masks even valid cross-file duplicates"
        );
    }
    assert!(skipped.counts.census_invalid && paid.counts.census_invalid);
    // The traversal retires the structural family, leaving both valid owners.
    rearm.sources.retain(|key, _| {
        claude_index_path_member_ref(Path::new(key)).is_some_and(|m| m.root != rearm.parent)
    });
    for index in [&mut fix, &mut base] {
        index.files.retain(|key, _| rearm.sources.contains_key(key));
        index.claude_usage_family_pending.remove(&rearm.parent);
        let run = rearm.terminal(index, &[first.clone(), second.clone()]);
        assert!(!run.counts.census_invalid);
        assert!(!run.counts.fence_after);
        assert!(!index.claude_duplicate_request_owners.is_empty());
        assert!(index
            .claude_duplicate_request_owners
            .values()
            .all(|owners| owners.len() == 2));
    }
    assert_eq!(
        fix.claude_duplicate_request_owners,
        base.claude_duplicate_request_owners
    );
}

#[test]
fn scanner_does_not_seal_capped_or_failed_rebuild_reads() {
    for failed in [false, true] {
        let rearm = Rearm::new();
        let mut index = rebuild_candidate(&rearm, ScanIndexLoadOrigin::Loaded);
        for entry in index.files.values_mut() {
            entry.source_file_fingerprint.clear();
        }
        if failed {
            let path = rearm.sources.keys().next().unwrap();
            let mut contents = fs::read(path).unwrap();
            contents.extend_from_slice(b"\nnot json\n");
            fs::write(path, contents).unwrap();
        }
        let scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&rearm.root),
            &mut index,
            WINDOW,
            0,
            if failed { 100 } else { 1 },
            false,
        )
        .unwrap();
        assert!(!scan.census_complete, "{failed}: {scan:?}");
        assert!(index
            .claude_full_rearm_progress
            .complete_rebuild_read
            .is_none());
        assert!(!take_claude_complete_rebuild_read(&mut index, WINDOW));
    }
}
