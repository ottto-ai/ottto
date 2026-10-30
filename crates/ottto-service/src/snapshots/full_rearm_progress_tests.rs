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

/// F1a: an unrecorded contract never skips. A set contract-5 latch still
/// re-reads every family file once through its identity contract re-arm,
/// which clears the latch; since the contract-5 cutover (Lead B) the latch
/// alone no longer also takes the due liveness re-arm, so the same terminal
/// counts as a skip.
#[test]
fn identity_contract_latch_or_unrecorded_contract_rearms() {
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
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
    // Was `latched.counts.full_rearm`: the record names this contract, so
    // only the latch's own re-arm re-reads the family.
    assert!(!latched.counts.full_rearm, "{latched:?}");
    assert!(latched.suppression.full_rearm_suppressed, "{latched:?}");
    assert_eq!(latched.rearmed_files, 2, "the identity contract re-arm");
    assert!(!index.claude_request_identity_contract_changed);
    let skipped = rearm.terminal(&mut index, &rearm.items);
    assert!(skipped.suppression.full_rearm_suppressed, "{skipped:?}");
    assert_eq!(scope.finish().contract.identity_contract_latch.cleared, 1);
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
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
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

/// These explanations never contribute request ids to the duplicate census.
/// Exercise each alone, including both withheld-account reasons.
#[test]
fn attribution_explanations_do_not_rearm_an_unchanged_structural_baseline() {
    for (reason, refusals) in [
        (Some(CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE), 0),
        (Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS), 0),
        (None, 1),
    ] {
        let rearm = Rearm::new();
        let mut index = rearm.index();
        rearm.establish(&mut index, &rearm.items);
        let mut items = rearm.items.clone();
        items[0].claude_account_withheld_reason = reason;
        items[0].request_identity_refusals = refusals;
        let run = rearm.terminal(&mut index, &items);
        assert!(run.counts.fence_before && run.counts.fence_after);
        assert!(
            run.suppression.full_rearm_suppressed,
            "{reason:?}/{refusals}: {run:?}"
        );
        assert!(!run.counts.full_rearm);
        assert_eq!(run.rearmed_files, 0);
        assert_eq!(items[0].claude_account_withheld_reason, reason);
        assert_eq!(items[0].request_identity_refusals, refusals);

        // The same removed inputs also must not veto a certified first close.
        let mut rebuilt = rebuild_candidate(&rearm, ScanIndexLoadOrigin::Loaded);
        seal_claude_complete_rebuild_read(&mut rebuilt, &rebuild_reads(&rearm.index()), true);
        let first_close = rearm.terminal(&mut rebuilt, &items);
        assert!(!first_close.counts.full_rearm, "{first_close:?}");
        assert_eq!(first_close.suppression.full_rearm_post_rebuild_skipped, 1);
        assert_eq!(first_close.rearmed_files, 0);
    }
}

/// A transient read failure stays retryable, then a healthy read of the same
/// evidence can suppress again without replacing the structural baseline.
#[test]
fn evidence_read_failure_rearms_but_a_healthy_retry_suppresses() {
    let rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.establish(&mut index, &rearm.items);
    let mut api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    api.health.unreadable_lines = 1;
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
    let failed = apply_claude_reported_usage_with_index_and_limits(
        &mut rearm.items.clone(),
        &api,
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        &mut index,
        true,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    );
    let failed = rearm.reread(&mut index, &failed);
    assert!(failed.counts.full_rearm, "{failed:?}");
    assert_eq!(failed.rearmed_files, 2);
    let recovered = rearm.terminal(&mut index, &rearm.items);
    assert!(recovered.suppression.full_rearm_suppressed, "{recovered:?}");
    assert!(!recovered.counts.full_rearm);
    assert_eq!(recovered.rearmed_files, 0);
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

/// Failed reads retain their retry veto; deterministic sidecar-content
/// refusals cannot justify a whole-index transcript re-read.
#[test]
fn pipeline_sidecar_health_vetoes_but_fixed_evidence_refusals_do_not() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    let rearm = Rearm::new();
    let mut baseline = rearm.index();
    rearm.establish(&mut baseline, &rearm.items);
    for cause in [
        "absent",
        "matched",
        "unpaired",
        "malformed-pair",
        "request-gap",
        "api-only-gap",
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
                        let mut row = complete_trace_row(&rearm.parent, "req_1", "");
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
                let mut rows = vec![row];
                if cause == "request-gap" && kind == "claude-code-trace-ownership" {
                    rows.push(
                        serde_json::to_string(&complete_trace_row(&rearm.parent, "req_gap", ""))
                            .unwrap(),
                    );
                }
                if cause == "api-only-gap" && kind == "claude-code-effort" {
                    let mut extra = complete_api_row(&rearm.parent, "req_gap", 1, 10, 10, 0);
                    extra.account_identity_checked = false;
                    extra.account_identifier_hash = None;
                    extra.fingerprint.clear();
                    extra.fingerprint = format!(
                        "sha256:{:x}",
                        Sha256::digest(serde_json::to_vec(&extra).unwrap())
                    );
                    rows.push(serde_json::to_string(&extra).unwrap());
                }
                fs::write(path, rows.join("\n") + "\n").unwrap();
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
            let mut record = index.claude_full_rearm_progress.structural_record.clone();
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
            if matches!(cause, "request-gap" | "api-only-gap") {
                assert_eq!(stats.api_incomplete_root_count, 0);
                assert_eq!(stats.trace_incomplete_root_count, 0);
                assert_eq!(stats.request_set_mismatch_root_count, 1);
                assert_eq!(
                    stats.api_only_request_count,
                    usize::from(cause == "api-only-gap")
                );
                assert_eq!(
                    stats.trace_only_request_count,
                    usize::from(cause == "request-gap")
                );
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
            if !matches!(cause, "unpaired" | "malformed-pair") {
                assert!(
                    run.suppression.full_rearm_suppressed,
                    "{cause} cannot be fixed by a transcript re-read: {run:?}"
                );
                assert!(!run.counts.full_rearm);
                assert_eq!(run.rearmed_files, 0);
                if let Some(record) = &mut record {
                    record.suppressed_since_unix_seconds = Some(CENSUS_CLOCK);
                    record.skipped_full_rearms += 1;
                }
            } else {
                if let Some(record) = &mut record {
                    record.suppressed_since_unix_seconds = None;
                    record.skipped_full_rearms = 0;
                }
                assert!(run.counts.full_rearm, "{cause}: {run:?}");
                assert!(!run.suppression.full_rearm_suppressed, "{cause}");
                assert_eq!(run.rearmed_files, 2, "{cause}");
            }
            assert_eq!(
                index.claude_full_rearm_progress.structural_record, record,
                "{cause}: evidence never replaces the structural baseline"
            );
        }
        if cause == "malformed-pair" {
            // The real strict-loader seam removed both failed roots before
            // passing default-healthy aggregate reports to the fold. Repair
            // the pair to healthy absence: unchanged native bytes now suppress.
            fs::remove_dir_all(support.join("local-otel")).unwrap();
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
            let (disposition, _, stats) = crate::snapshot_sync::apply_claude_local_evidence_to_scan(
                &support, &mut scan, &mut index,
            );
            assert_eq!(stats.api_incomplete_root_count, 0);
            assert_eq!(stats.trace_incomplete_root_count, 0);
            let recovered = rearm.reread(&mut index, &disposition);
            assert!(recovered.suppression.full_rearm_suppressed, "{recovered:?}");
            assert_eq!(recovered.rearmed_files, 0);
        }
        let _ = fs::remove_dir_all(support);
    }
}

/// One always-on terminal: the real sync evidence stage over the fixture
/// family with `support`'s sidecars, then the next walk's re-read. Returns
/// the parent body as it would upload and the terminal's veto state.
fn always_on_terminal(
    rearm: &Rearm,
    support: &Path,
    index: &mut ScanIndex,
) -> (Terminal, SnapshotItem, String) {
    always_on_terminal_at(rearm, support, index, 1, true)
}

/// `always_on_terminal` with the full re-arm deadline at `due_at` (due when
/// not after the census clock) and the given census completeness.
fn always_on_terminal_at(
    rearm: &Rearm,
    support: &Path,
    index: &mut ScanIndex,
    due_at: u64,
    census_complete: bool,
) -> (Terminal, SnapshotItem, String) {
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
    scan.census_complete = census_complete;
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(due_at);
    let (disposition, _, _) =
        crate::snapshot_sync::apply_claude_local_evidence_to_scan(support, &mut scan, index);
    let parent = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == rearm.parent)
        .unwrap()
        .clone();
    let state = always_on_veto_state(rearm, index, &scan.snapshots);
    (rearm.reread(index, &disposition), parent, state)
}

/// The family root's paired sidecars for `req_1`: a dark row, or one with
/// complete request identity (login and organization). `account_checked`
/// keeps the legacy account check on the row; covering one of the parent's
/// four requests, it withholds the session account for incomplete request
/// evidence. Unchecked, the account stays unknown and contract 5 does not
/// tag the body (`valid_login`).
fn write_parent_sidecars(rearm: &Rearm, support: &Path, identity: bool, account_checked: bool) {
    write_sidecar_rows(
        rearm,
        support,
        identity,
        &[("req_1", "", 10, account_checked)],
    );
}

/// Paired rows for each `(request, agent, output tokens, account checked)`,
/// with the fixture's own token counts; otherwise as `write_parent_sidecars`.
fn write_sidecar_rows(
    rearm: &Rearm,
    support: &Path,
    identity: bool,
    requests: &[(&str, &str, u64, bool)],
) {
    let (mut api_rows, mut trace_rows) = (String::new(), String::new());
    for (sequence, &(request, agent, output_tokens, account_checked)) in requests.iter().enumerate()
    {
        let mut api = complete_api_row(
            &rearm.parent,
            request,
            sequence as u64,
            10,
            output_tokens,
            0,
        );
        if identity {
            api.request_identity = Some(
                serde_json::from_value(serde_json::json!({
                    "identity_hash_scheme":"provider-sha256:v1", "disposition":"complete",
                    "account":{"disposition":"complete", "origin":"log_record", "log_record_hash":"a".repeat(64)},
                    "organization":{"disposition":"complete", "origin":"log_record", "log_record_hash":"d".repeat(64)},
                }))
                .unwrap(),
            );
        }
        if !account_checked {
            api.account_identity_checked = false;
            api.account_identifier_hash = None;
        }
        api.fingerprint.clear();
        api.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&api).unwrap())
        );
        let trace = complete_trace_row(&rearm.parent, request, agent);
        api_rows.push_str(&format!("{}\n", serde_json::to_string(&api).unwrap()));
        trace_rows.push_str(&format!("{}\n", serde_json::to_string(&trace).unwrap()));
    }
    let digest = format!("{:x}", Sha256::digest(rearm.parent.as_bytes()));
    for (kind, rows) in [
        ("claude-code-effort", api_rows),
        ("claude-code-trace-ownership", trace_rows),
    ] {
        let path = support
            .join("local-otel")
            .join(kind)
            .join(format!("{digest}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, rows).unwrap();
    }
}

/// Why a terminal could not skip: the window's non-structural observation
/// and each folded item's own vetoes.
fn always_on_veto_state(rearm: &Rearm, index: &ScanIndex, items: &[SnapshotItem]) -> String {
    let progress = &index.claude_full_rearm_progress;
    let items = items
        .iter()
        .map(|item| {
            format!(
                "{}: structural={} refusals={} withheld={:?} clocks_complete={}",
                item.source_session_id,
                claude_member_invalidity_is_structural(item),
                item.request_identity_refusals,
                item.claude_account_withheld_reason,
                item.claude_usage_occurrences
                    .values()
                    .all(|occurrence| occurrence.event_clock_complete),
            )
        })
        .collect::<Vec<_>>();
    format!(
        "parent={} observed_window={:?} other={} structural_roots={} owed={} record={} items={items:?}",
        rearm.parent,
        progress.observed_window,
        progress.other_invalidation_observed,
        progress.structural_roots.len(),
        progress.structural_rearm_owed,
        progress.structural_record.is_some(),
    )
}

/// Contract-5 cutover (E1 seam, Lead B condition D): on a permitted Mac
/// (contract recorded, latch clear) every terminal builds contract-5
/// evidence and emits contract-5 bodies. With the family's sidecars absent,
/// matched, or matched with request identity but no account check, the
/// first due terminal records the structural baseline and every later due
/// terminal with no contract change skips: no fingerprint is cleared, so
/// nothing reads Full. Under the released E2 contract (gate on); the
/// gate-off (pre-flip) collector only with absent sidecars, since there a
/// dark row is refused as invalid evidence, a non-structural veto.
#[test]
fn always_on_terminals_keep_the_structural_suppression() {
    for (contract, gate, causes) in [
        (
            claude_request_identity::E2_GROUPING,
            true,
            &["absent", "matched", "matched-identity"][..],
        ),
        (claude_request_identity::COLLECTOR, false, &["absent"][..]),
    ] {
        let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(gate);
        claude_request_identity::with_cycle_contract_for_test(contract, || {
            for &cause in causes {
                let arm = format!("{contract} {cause}");
                let rearm = Rearm::new();
                let support = temp_dir("full-rearm-always-on");
                if cause != "absent" {
                    write_parent_sidecars(&rearm, &support, cause == "matched-identity", false);
                }
                let mut index = rearm.index();
                index.claude_request_identity_contract = Some(contract.to_string());
                let mut runs = Vec::new();
                for _ in 0..3 {
                    let (run, parent, state) = always_on_terminal(&rearm, &support, &mut index);
                    let tagged_rows = parent
                        .model_usage
                        .iter()
                        .chain(
                            parent
                                .usage_buckets
                                .iter()
                                .flat_map(|bucket| &bucket.model_usage),
                        )
                        .filter(|row| row.evidence_ref.is_some() || row.identity_parts.is_some())
                        .count();
                    let body = format!(
                        "collector={} evidence={} tagged_rows={tagged_rows} refusals={} {state}",
                        parent.provenance.collector,
                        parent.request_evidence.len(),
                        parent.request_identity_refusals
                    );
                    assert_eq!(parent.provenance.collector, contract, "{arm}: {body}");
                    assert_eq!(parent.request_identity_refusals, 0, "{arm}: {body}");
                    // Request identity without D1's account-checked login never
                    // tags (`valid_login`); a tagged body is the control below.
                    assert_eq!(tagged_rows, 0, "{arm}: {body}");
                    assert_eq!(
                        index.claude_request_identity_contract.as_deref(),
                        Some(contract),
                        "{arm}"
                    );
                    assert!(!index.claude_request_identity_contract_changed, "{arm}");
                    runs.push((run, body));
                }
                let (first, body) = &runs[0];
                assert!(first.counts.full_rearm, "{arm}: {first:?} {body}");
                assert_eq!(first.rearmed_files, 2, "{arm}");
                assert!(
                    index.claude_full_rearm_progress.structural_record.is_some(),
                    "{arm}: the baseline is recorded: {body}"
                );
                for (run, body) in &runs[1..] {
                    assert!(
                        run.counts.fence_before && run.counts.fence_after,
                        "{arm}: {run:?} {body}"
                    );
                    assert!(
                        run.suppression.full_rearm_suppressed,
                        "{arm}: no contract change keeps the skip: {run:?} {body}"
                    );
                    assert!(!run.counts.full_rearm, "{arm}");
                    assert_eq!(
                        run.rearmed_files, 0,
                        "{arm}: no fingerprint cleared, no Full"
                    );
                }
                let _ = fs::remove_dir_all(support);
            }
        });
    }
}

/// SOURCE condition (2026-10-28 review of #840): the permitted shape with
/// real tagged bodies. The index records E2 and the structural baseline is
/// built with evidence. Every request of the family has a paired row with
/// complete request identity; `req_1`'s also carries D1's account-checked
/// login, so contract 5 tags the parent's body, and the other rows are
/// unchecked, so the legacy account path neither binds nor withholds the
/// session account (full checked coverage binds it and keeps the legacy
/// body; partial checked coverage alone withholds it, the control below).
/// The census identity is kept (request-id hashes only: the one structural
/// child invalidation, nothing more), and every due terminal after the
/// first skips: no fingerprint is cleared, nothing reads Full.
#[test]
fn a_tagged_permitted_body_keeps_census_identity_and_the_suppression() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let contract = claude_request_identity::E2_GROUPING;
    claude_request_identity::with_cycle_contract_for_test(contract, || {
        let rearm = Rearm::new();
        let support = temp_dir("full-rearm-tagged-permitted");
        write_sidecar_rows(
            &rearm,
            &support,
            true,
            &[
                ("req_1", "", 10, true),
                ("req_2", "", 10, false),
                ("req_3", "", 10, false),
                ("req_4", "", 10, false),
                ("req_5", "a4d1585d310070d0f", 1, false),
            ],
        );
        let mut index = rearm.index();
        index.claude_request_identity_contract = Some(contract.to_string());
        let mut runs = Vec::new();
        for _ in 0..3 {
            let (run, parent, state) = always_on_terminal(&rearm, &support, &mut index);
            let tagged = parent
                .model_usage
                .iter()
                .chain(
                    parent
                        .usage_buckets
                        .iter()
                        .flat_map(|bucket| &bucket.model_usage),
                )
                .any(|row| row.evidence_ref.is_some() || row.identity_parts.is_some());
            assert!(tagged, "a real tagged contract-5 body: {state}");
            assert_eq!(parent.provenance.collector, contract, "{state}");
            assert_eq!(parent.claude_account_withheld_reason, None, "{state}");
            assert_eq!(parent.request_identity_refusals, 0, "{state}");
            assert_eq!(
                run.counts.page_invalidated_identity_count, 1,
                "census identity kept: only the structural child: {run:?} {state}"
            );
            assert_eq!(
                index.claude_request_identity_contract.as_deref(),
                Some(contract)
            );
            assert!(!index.claude_request_identity_contract_changed);
            runs.push((run, state));
        }
        let (first, state) = &runs[0];
        assert!(first.counts.full_rearm, "the baseline: {first:?} {state}");
        assert!(index.claude_full_rearm_progress.structural_record.is_some());
        for (run, state) in &runs[1..] {
            assert!(
                run.counts.fence_before && run.counts.fence_after,
                "{run:?} {state}"
            );
            assert!(
                run.suppression.full_rearm_suppressed,
                "the re-arm stays suppressed: {run:?} {state}"
            );
            assert!(!run.counts.full_rearm);
            assert_eq!(run.rearmed_files, 0, "no fingerprint cleared: {state}");
        }
        let _ = fs::remove_dir_all(support);
    });
}

/// Control for the structural suppression (Lead B condition D): contract 5
/// tags only from D1's account-checked login, and a family whose one
/// checked row covers one of the parent's four requests also withholds the
/// session account for incomplete request evidence (legacy account path,
/// `apply_claude_account_evidence`). That explanation is not duplicate-census
/// input: the first terminal pays for the structural baseline, then both later
/// due terminals suppress with zero clears. The always-on build still tags the
/// contract-5 body, and the pre-cutover arm has identical re-arm behavior.
#[test]
fn a_withheld_account_rearms_the_same_before_and_after_the_cutover() {
    claude_request_identity::with_cycle_contract_for_test(
        claude_request_identity::E2_GROUPING,
        || {
            let runs = [false, true].map(|always_on| {
                let rearm = Rearm::new();
                let support = temp_dir("full-rearm-withheld-account");
                write_parent_sidecars(&rearm, &support, true, true);
                let mut index = rearm.index();
                let _pre_cutover =
                    (!always_on).then(claude_request_identity::PreCutoverEvidenceForTest::enter);
                index.claude_request_identity_contract =
                    Some(claude_request_identity::cycle_contract(always_on).to_string());
                let runs = (0..3)
                    .map(|_| {
                        let (run, parent, state) = always_on_terminal(&rearm, &support, &mut index);
                        assert!(
                            parent.claude_account_withheld_reason.is_some(),
                            "always_on={always_on}: {state}"
                        );
                        assert_eq!(parent.request_identity_refusals, 0, "{state}");
                        if always_on {
                            let tagged = parent
                                .model_usage
                                .iter()
                                .chain(
                                    parent
                                        .usage_buckets
                                        .iter()
                                        .flat_map(|bucket| &bucket.model_usage),
                                )
                                .any(|row| {
                                    row.evidence_ref.is_some() || row.identity_parts.is_some()
                                });
                            assert!(tagged, "a tagged contract-5 body: {state}");
                            assert_eq!(
                                parent.provenance.collector,
                                claude_request_identity::E2_GROUPING
                            );
                        }
                        (
                            run.counts.full_rearm,
                            run.suppression.full_rearm_suppressed,
                            run.rearmed_files,
                        )
                    })
                    .collect::<Vec<_>>();
                let _ = fs::remove_dir_all(support);
                runs
            });
            assert_eq!(runs[0], runs[1], "the cutover adds no re-arm");
            assert_eq!(
                runs[1],
                vec![(true, false, 2), (false, true, 0), (false, true, 0)],
                "pay once for the baseline; attribution explanations never re-arm it"
            );
        },
    );
}

/// Lead B condition D with Lead A ruling (a). A never-permitted install
/// recorded `""` and its structural baseline under it (no evidence); the
/// always-on build observes its contract. That cutover's latch re-arms at
/// the first complete terminal only (`contract_cutover_rearm`), and its
/// baseline carries over to the new contract, so no terminal re-arms the
/// whole index for it. A real contract-to-contract change (a recorded
/// collector baseline) still re-arms every family file once and records the
/// new contract. Every later due terminal skips, also while an unsettled
/// sweep holds the latch. The index is a released E2 Mac's (active revision
/// 3, every file stamped 3), where the latch's own re-read is E2's paced
/// debt; below revision 3 see `a_never_permitted_cutover_rearms_once_and_is_counted`.
#[test]
fn a_contract_change_rearms_at_most_once_then_skips() {
    for (from, held) in [
        ("", false),
        ("", true),
        (claude_request_identity::COLLECTOR, false),
        (claude_request_identity::COLLECTOR, true),
    ] {
        claude_request_identity::with_cycle_contract_for_test(
            claude_request_identity::E2_GROUPING,
            || {
                let arm = format!("from {from:?}, latch held {held}");
                let rearm = Rearm::new();
                let support = temp_dir("full-rearm-contract-change");
                let mut index = rearm.index();
                index.active_effective_upload_body_witness_revision = 3;
                for entry in index.files.values_mut() {
                    entry.effective_upload_body_witness_revision = 3;
                }
                assert_eq!(index.claude_request_identity_contract.as_deref(), Some(""));
                {
                    let _pre_cutover = claude_request_identity::PreCutoverEvidenceForTest::enter();
                    let (first, _, state) = always_on_terminal(&rearm, &support, &mut index);
                    assert!(first.counts.full_rearm, "{arm}: {first:?} {state}");
                    let (skipped, _, state) = always_on_terminal(&rearm, &support, &mut index);
                    assert!(
                        skipped.suppression.full_rearm_suppressed,
                        "{arm}: {skipped:?} {state}"
                    );
                }
                if !from.is_empty() {
                    // A permitted gate-off install's baseline.
                    index.claude_request_identity_contract = Some(from.to_string());
                    index
                        .claude_full_rearm_progress
                        .structural_record
                        .as_mut()
                        .unwrap()
                        .basis = claude_full_rearm_record_basis(from);
                }
                let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
                index.observe_claude_request_identity_contract(true);
                assert_eq!(
                    index.claude_request_identity_contract.as_deref(),
                    Some(claude_request_identity::E2_GROUPING)
                );
                assert!(index.claude_request_identity_contract_changed);
                let mut runs = Vec::new();
                for _ in 0..3 {
                    if held {
                        index.bounded_sweep_had_unsettled_upload = true;
                    }
                    let (run, _, state) = always_on_terminal(&rearm, &support, &mut index);
                    runs.push((run, state));
                }
                let cutover = scope.finish().contract.contract_cutover_rearm;
                let (first, state) = &runs[0];
                if from.is_empty() {
                    assert!(
                        !first.counts.full_rearm && first.suppression.full_rearm_suppressed,
                        "{arm}: the cutover keeps the baseline: {first:?} {state}"
                    );
                    assert_eq!(first.rearmed_files, 0, "{arm}: {state}");
                    assert_eq!(
                        (cutover.runs, cutover.files, cutover.bytes),
                        (1, 0, 0),
                        "{arm}"
                    );
                } else {
                    assert!(
                        first.counts.full_rearm,
                        "{arm}: the change re-arms once: {first:?} {state}"
                    );
                    assert_eq!(first.rearmed_files, 2, "{arm}");
                    assert_eq!(cutover.runs, 0, "{arm}: not a cutover");
                }
                assert_eq!(
                    index
                        .claude_full_rearm_progress
                        .structural_record
                        .as_ref()
                        .map(|record| record.basis.clone()),
                    Some(claude_full_rearm_record_basis(
                        claude_request_identity::E2_GROUPING
                    )),
                    "{arm}: the baseline names the new contract"
                );
                for (run, state) in &runs[1..] {
                    assert!(
                        run.suppression.full_rearm_suppressed,
                        "{arm}: never again: {run:?} {state}"
                    );
                    assert!(!run.counts.full_rearm, "{arm}");
                    assert_eq!(
                        run.rearmed_files, 0,
                        "{arm}: no fingerprint cleared: {state}"
                    );
                }
                if held {
                    assert!(
                        index.claude_request_identity_contract_changed,
                        "{arm}: the unsettled sweep keeps the latch"
                    );
                }
                let _ = fs::remove_dir_all(support);
            },
        );
    }
}

/// Lead A ruling (a), gate off (collector contract, revision below 3), where
/// the latch's own re-arm clears every family file. A never-permitted index
/// (recorded `""`, structural baseline built without evidence) observes the
/// always-on contract: an opening fence leaves the cutover owed, and the
/// first complete terminal behind a closed fence re-arms the family once,
/// counted with its files and bytes as `contract_cutover_rearm`, and keeps
/// the structural baseline (no whole-index re-arm). While an unsettled sweep
/// holds the latch, later terminals, a restart, an incomplete census and an
/// evidence-gap veto re-arm nothing more; the next settled terminal clears
/// the latch.
#[test]
fn a_never_permitted_cutover_rearms_once_and_is_counted() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    claude_request_identity::with_cycle_contract_for_test(
        claude_request_identity::COLLECTOR,
        || {
            let rearm = Rearm::new();
            let support = temp_dir("full-rearm-cutover");
            let path = support.join("index.json");
            let mut index = rearm.index();
            assert_eq!(index.claude_request_identity_contract.as_deref(), Some(""));
            {
                let _pre_cutover = claude_request_identity::PreCutoverEvidenceForTest::enter();
                let (first, _, state) = always_on_terminal(&rearm, &support, &mut index);
                assert!(first.counts.full_rearm, "{first:?} {state}");
                let (skipped, _, state) = always_on_terminal(&rearm, &support, &mut index);
                assert!(
                    skipped.suppression.full_rearm_suppressed,
                    "{skipped:?} {state}"
                );
            }
            index.observe_claude_request_identity_contract(true);
            assert!(index.claude_request_identity_contract_changed);
            // An opening fence runs none of the latch's re-arm causes, so the
            // cutover stays owed (Claude review, round 3).
            let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            index.bounded_sweep_had_unsettled_upload = true;
            index.claude_duplicate_request_witness_overflowed = false;
            let (opening, _, state) = always_on_terminal(&rearm, &support, &mut index);
            assert_eq!(
                index.claude_full_rearm_progress.contract_cutover, CLAUDE_CONTRACT_CUTOVER_OWED,
                "{opening:?} {state}"
            );
            assert_eq!(scope.finish().contract.contract_cutover_rearm.runs, 0);
            index.claude_duplicate_request_witness_overflowed = true;
            let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            index.bounded_sweep_had_unsettled_upload = true;
            let (first, _, state) = always_on_terminal(&rearm, &support, &mut index);
            assert!(
                !first.counts.full_rearm,
                "no whole-index re-arm: {first:?} {state}"
            );
            assert!(first.suppression.full_rearm_suppressed, "{first:?} {state}");
            assert_eq!(
                first.rearmed_files, 2,
                "the latch re-arms the family once: {state}"
            );
            let cutover = scope.finish().contract.contract_cutover_rearm;
            assert_eq!(
                (cutover.runs, cutover.files, cutover.bytes),
                (1, 2, first.rearmed_bytes),
                "counted with its files and bytes"
            );
            assert!(first.rearmed_bytes > 0);
            assert!(index.claude_request_identity_contract_changed, "held latch");

            let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            for step in [
                "later",
                "later again",
                "restart",
                "incomplete census",
                "complete again",
                "evidence gap",
            ] {
                if step == "restart" {
                    index.save(&path).unwrap();
                    index = ScanIndex::load(&path).unwrap();
                    assert!(index.claude_request_identity_contract_changed, "{step}");
                }
                index.bounded_sweep_had_unsettled_upload = true;
                if step == "evidence gap" {
                    index.note_claude_full_rearm_evidence_gap(WINDOW);
                }
                // The evidence gap vetoes the structural skip, so its terminal is
                // not due: only the latch could re-arm there.
                let due_at = if step == "evidence gap" {
                    CENSUS_CLOCK + 3_600
                } else {
                    1
                };
                let (run, _, state) = always_on_terminal_at(
                    &rearm,
                    &support,
                    &mut index,
                    due_at,
                    step != "incomplete census",
                );
                assert!(!run.counts.full_rearm, "{step}: {run:?} {state}");
                assert_eq!(run.rearmed_files, 0, "{step}: never again: {state}");
            }
            assert!(index.claude_request_identity_contract_changed, "still held");
            index.bounded_sweep_had_unsettled_upload = false;
            let (settled, _, state) =
                always_on_terminal_at(&rearm, &support, &mut index, CENSUS_CLOCK + 3_600, true);
            assert_eq!(settled.rearmed_files, 0, "{state}");
            assert!(
                !index.claude_request_identity_contract_changed,
                "a settled terminal clears the spent latch: {state}"
            );
            assert_eq!(
                scope.finish().contract.contract_cutover_rearm.runs,
                0,
                "the cutover is spent for good"
            );
            let _ = fs::remove_dir_all(support);
        },
    );
}

/// A pre-cutover writer drops the spent field and records `""` again.
/// Re-upgrading owes exactly one additional counted cutover, then keeps SPENT
/// through another terminal and restart. An unknown contract is not this case.
#[test]
fn a_dropped_cutover_field_with_recorded_empty_spends_one_more_run() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    claude_request_identity::with_cycle_contract_for_test(
        claude_request_identity::COLLECTOR,
        || {
            let rearm = Rearm::new();
            let support = temp_dir("full-rearm-cutover-reupgrade");
            let path = support.join("index.json");
            let mut index = rearm.index();
            assert_eq!(index.claude_request_identity_contract.as_deref(), Some(""));
            {
                let _pre_cutover = claude_request_identity::PreCutoverEvidenceForTest::enter();
                let (first, _, state) = always_on_terminal(&rearm, &support, &mut index);
                assert!(first.counts.full_rearm, "{first:?} {state}");
                let (quiet, _, state) = always_on_terminal(&rearm, &support, &mut index);
                assert!(quiet.suppression.full_rearm_suppressed, "{quiet:?} {state}");
            }
            let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            index.observe_claude_request_identity_contract(true);
            let (first, _, state) = always_on_terminal(&rearm, &support, &mut index);
            assert_eq!(first.rearmed_files, 2, "{first:?} {state}");
            assert_eq!(
                index.claude_full_rearm_progress.contract_cutover,
                CLAUDE_CONTRACT_CUTOVER_SPENT
            );
            let before = scope.finish().contract.contract_cutover_rearm.runs;
            assert_eq!(before, 1, "the original cutover was actually spent");
            index.save(&path).unwrap();

            // Model the older writer's rewrite: drop only the unknown field,
            // and record its never-permitted contract explicitly (not None).
            let mut saved: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                saved["claude_full_rearm_progress"]
                    .as_object_mut()
                    .unwrap()
                    .remove("contract_cutover"),
                Some(serde_json::json!(CLAUDE_CONTRACT_CUTOVER_SPENT))
            );
            saved["claude_request_identity_contract"] = serde_json::json!("");
            fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
            index = ScanIndex::load(&path).unwrap();
            assert_eq!(index.claude_full_rearm_progress.contract_cutover, 0);
            assert_eq!(index.claude_request_identity_contract.as_deref(), Some(""));
            {
                let _pre_cutover = claude_request_identity::PreCutoverEvidenceForTest::enter();
                always_on_terminal(&rearm, &support, &mut index);
                let (quiet, _, state) = always_on_terminal(&rearm, &support, &mut index);
                assert!(quiet.suppression.full_rearm_suppressed, "{quiet:?} {state}");
            }
            index.save(&path).unwrap();
            index = ScanIndex::load(&path).unwrap();
            assert_eq!(index.claude_full_rearm_progress.contract_cutover, 0);
            assert_eq!(index.claude_request_identity_contract.as_deref(), Some(""));

            let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            index.observe_claude_request_identity_contract(true);
            assert_eq!(
                index.claude_full_rearm_progress.contract_cutover,
                CLAUDE_CONTRACT_CUTOVER_OWED
            );
            let (reupgrade, _, state) = always_on_terminal(&rearm, &support, &mut index);
            assert_eq!(reupgrade.rearmed_files, 2, "{reupgrade:?} {state}");
            assert_eq!(
                index.claude_full_rearm_progress.contract_cutover,
                CLAUDE_CONTRACT_CUTOVER_SPENT
            );
            let after = before + scope.finish().contract.contract_cutover_rearm.runs;
            assert_eq!(after, before + 1, "exactly one more cutover run");

            let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            for restart in [false, true] {
                if restart {
                    index.save(&path).unwrap();
                    index = ScanIndex::load(&path).unwrap();
                }
                index.observe_claude_request_identity_contract(true);
                let (quiet, _, state) = always_on_terminal(&rearm, &support, &mut index);
                assert_eq!(
                    quiet.rearmed_files, 0,
                    "restart={restart}: {quiet:?} {state}"
                );
                assert_eq!(
                    index.claude_full_rearm_progress.contract_cutover,
                    CLAUDE_CONTRACT_CUTOVER_SPENT
                );
            }
            assert_eq!(
                after + scope.finish().contract.contract_cutover_rearm.runs,
                after,
                "SPENT stays sticky on the next pass and after restart"
            );
            fs::remove_dir_all(support).unwrap();
        },
    );
}

/// A telemetry-only row never has a transcript clock to regenerate. Its
/// canonical BadClock refusal stays visible without forcing whole-index Full.
#[test]
fn pipeline_auxiliary_bad_clock_preserves_refusal_without_whole_index_rearm() {
    // Terminal-authority hold/rearm policy; E2 literal bodies bypass legacy demotion.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
        let (disposition, _, stats) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(&support, &mut scan, index);
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
    let mut record = index.claude_full_rearm_progress.structural_record.clone();
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
        assert!(!run.counts.full_rearm, "{run:?}");
        assert!(run.suppression.full_rearm_suppressed, "{run:?}");
        assert_eq!(run.rearmed_files, 0);
        record.as_mut().unwrap().skipped_full_rearms += 1;
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
            lineage_edge_reoffer_bytes: None,
            desktop_identity_reoffer: None,
            desktop_identity_resolved: false,
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
fn structural_family_masks_duplicate_ownership_but_native_copy_still_rearms() {
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
    let mut baseline = rearm.items.clone();
    baseline.push(first.clone());
    rearm.establish(&mut fix, &baseline);
    let third_key = local_index_key(&rearm.root.join(format!("{THIRD_ROOT}.jsonl")));
    rearm
        .sources
        .insert(third_key.clone(), "rev-third".to_string());
    insert_file(&mut fix, &third_key, "rev-third", 512);
    let mut items = rearm.items.clone();
    items.extend([first.clone(), second.clone()]);
    let mut base = fix.clone();
    let kept = rearm.terminal(&mut fix, &items);
    let paid = rearm.base_terminal(&mut base, &items);
    assert!(kept.counts.full_rearm && paid.counts.full_rearm);
    assert!(!kept.suppression.full_rearm_suppressed);
    assert_eq!(kept.rearmed_files, 4);
    assert_eq!(paid.rearmed_files, 4);
    for index in [&fix, &base] {
        assert!(index.claude_duplicate_request_witness_overflowed);
        assert!(
            index.claude_duplicate_request_owners.is_empty(),
            "the structural family masks even valid cross-file duplicates"
        );
    }
    assert!(kept.counts.census_invalid && paid.counts.census_invalid);
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

/// Appending the missing telemetry selects both members through their root's
/// sidecar fingerprint. An unrelated, structurally invalid family stays quiet.
#[test]
fn late_account_telemetry_reselects_the_family_without_whole_index_rearm() {
    let _gate = claude_request_money::e2::GateForTest::off();
    claude_request_identity::with_cycle_contract_for_test("", || {
        let mut rearm = Rearm::new();
        let support = temp_dir("full-rearm-late-account");
        let child = rearm
            .root
            .join(&rearm.parent)
            .join("subagents/agent-a4d1585d310070d0f.jsonl");
        let parent = rearm.root.join(format!("{}.jsonl", rearm.parent));
        let other_parent = rearm.root.join(format!("{OTHER_ROOT}.jsonl"));
        let other_child = rearm
            .root
            .join(OTHER_ROOT)
            .join("subagents/agent-a4d1585d310070d0f.jsonl");
        fs::create_dir_all(other_child.parent().unwrap()).unwrap();
        for (from, to) in [(&parent, &other_parent), (&child, &other_child)] {
            fs::write(
                to,
                fs::read_to_string(from)
                    .unwrap()
                    .replace(&rearm.parent, OTHER_ROOT)
                    .replace("req_", "other_req_"),
            )
            .unwrap();
        }
        // The original family's own bytes, not a test-injected counter, are invalid.
        let mut invalid: Value =
            serde_json::from_str(&fs::read_to_string(&child).unwrap()).unwrap();
        invalid.as_object_mut().unwrap().remove("requestId");
        fs::write(&child, format!("{invalid}\n")).unwrap();
        let sidecar = support
            .join("local-otel/claude-code-effort")
            .join(format!("{:x}.jsonl", Sha256::digest(OTHER_ROOT.as_bytes())));
        fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        let row = |n| {
            complete_api_row(
                OTHER_ROOT,
                &format!("other_req_{n}"),
                n,
                10,
                if n == 5 { 1 } else { 10 },
                0,
            )
        };
        fs::write(
            &sidecar,
            format!("{}\n", serde_json::to_string(&row(1)).unwrap()),
        )
        .unwrap();
        let roots = [rearm.root.clone()];
        let scan = |index: &mut ScanIndex, window: &str| {
            scan_source_roots_with_test_limit_and_claude_support(
                &roots,
                index,
                window,
                BACKFILL_WINDOW_DAYS,
                100,
                &support,
            )
            .unwrap()
        };
        let enrich = |scan: &mut SourceScanResult, index: &mut ScanIndex| {
            let evidence = crate::claude_local_otel::load_claude_effort_evidence(
                &support,
                [OTHER_ROOT.to_string()],
            )
            .unwrap();
            apply_claude_effort_evidence_with_index(
                &mut scan.snapshots,
                &evidence,
                index,
                scan.census_complete,
                &scan.census_window_end,
            );
        };
        let mut index = rearm.index();
        let mut initial = scan(&mut index, WINDOW);
        assert_eq!(initial.scanned_file_count, 4);
        assert!(initial.census_complete);
        enrich(&mut initial, &mut index);
        let family = |items: &[SnapshotItem]| {
            items
                .iter()
                .filter(|item| claude_snapshot_family_root(item) == OTHER_ROOT)
                .map(|item| item.source_session_id.clone())
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(family(&initial.snapshots).len(), 2);
        let initial_parent = initial
            .snapshots
            .iter()
            .find(|item| item.source_session_id == OTHER_ROOT)
            .unwrap();
        assert_eq!(
            initial_parent.claude_account_withheld_reason,
            Some(CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE)
        );
        assert!(
            initial
                .snapshots
                .iter()
                .filter(|item| claude_snapshot_family_root(item) == OTHER_ROOT)
                .all(|item| exact_session_account_hash(item).is_none()),
            "neither member is bound by partial coverage"
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut initial, &mut index);
        // Normalize the helper's simulated reread revisions to the actual scanner's.
        rearm.sources = index
            .files
            .iter()
            .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
            .collect();
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
        let first = rearm.fold(
            &mut index,
            &initial.snapshots,
            true,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        );
        assert!(first.duplicate_census.full_rearm);
        assert!(index
            .files
            .values()
            .all(|entry| entry.source_file_fingerprint.is_empty()));

        // Consume the first paid re-arm's real scanner window, then verify
        // that the unchanged, withheld family no longer requests a re-arm.
        let mut paid = scan(&mut index, WINDOW);
        enrich(&mut paid, &mut index);
        let quiet = rearm.terminal(&mut index, &paid.snapshots);
        assert!(quiet.suppression.full_rearm_suppressed, "{quiet:?}");
        assert_eq!(quiet.rearmed_files, 0);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut paid, &mut index);
        let unchanged = scan(&mut index, WINDOW);
        assert_eq!(
            unchanged.scanned_file_count, 0,
            "no unchanged transcript re-read"
        );
        let before = index
            .files
            .iter()
            .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
            .collect::<BTreeMap<_, _>>();

        let mut file = fs::OpenOptions::new().append(true).open(&sidecar).unwrap();
        for n in 2..=5 {
            writeln!(file, "{}", serde_json::to_string(&row(n)).unwrap()).unwrap();
        }
        drop(file);
        let mut completed = scan(&mut index, "2026-08-02T08:10:00Z");
        assert_eq!(
            completed.scanned_file_count, 2,
            "only the complete family reselects"
        );
        assert_eq!(
            family(&completed.snapshots),
            BTreeSet::from([
                OTHER_ROOT.to_string(),
                format!("{OTHER_ROOT}_agent-a4d1585d310070d0f"),
            ])
        );
        enrich(&mut completed, &mut index);
        let account = "a".repeat(64);
        assert!(completed
            .snapshots
            .iter()
            .all(|item| item.claude_account_withheld_reason.is_none()
                && exact_session_account_hash(item).as_deref() == Some(account.as_str())));
        assert!(index
            .bind_session_accounts(
                SnapshotSource::ClaudeCode,
                "synthetic-machine",
                &mut completed.snapshots,
                &[]
            )
            .is_empty());
        let run = rearm.terminal(&mut index, &completed.snapshots);
        assert!(
            run.suppression.full_rearm_suppressed && !run.counts.full_rearm,
            "{run:?}"
        );
        assert_eq!(
            run.rearmed_files, 0,
            "zero fingerprint clears, including outside the family"
        );
        for (key, entry) in &index.files {
            assert!(!entry.source_file_fingerprint.is_empty());
            if claude_index_path_member_ref(Path::new(key)).unwrap().root != OTHER_ROOT {
                assert_eq!(
                    entry.source_file_fingerprint, before[key],
                    "unrelated family: {key}"
                );
            }
        }
        assert_eq!(
            index.session_account_bindings.len(),
            2,
            "both accounts bound"
        );
        assert!(index
            .session_account_bindings
            .values()
            .all(|binding| binding.account_identifier_hash == account));
        fs::remove_dir_all(support).unwrap();
    });
}

/// A fixed gap cannot be cured by the first-proof re-arm either. Once the
/// gap is fixed, the existing dormant-owner hold must veto suppression again.
#[test]
fn dormant_owner_hold_returns_when_unrelated_sidecar_gap_is_fixed() {
    const DORMANT: &str = "d6666666-6666-4666-8666-666666666666";
    const GAP: &str = "b7777777-7777-4777-8777-777777777777";
    let _gate = claude_request_money::e2::GateForTest::off();
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.add_other_family(&mut index);
    let mut successor = rearm.other_family(false);
    let copied = successor.claude_usage_request_ids.pop_first().unwrap();
    successor
        .claude_usage_request_ids
        .insert("req_1".to_string());
    let occurrence = successor.claude_usage_occurrences.remove(&copied).unwrap();
    successor
        .claude_usage_occurrences
        .insert("req_1".to_string(), occurrence);
    let mut items = rearm.items.clone();
    items.push(successor);
    rearm.establish(&mut index, &items);

    // Mint the dormant owner's witness through the real canonical proof.
    let mut owner = rearm.valid_parent.clone();
    owner.source_session_id = DORMANT.to_string();
    let mut owner_index = ScanIndex::default();
    insert_file(
        &mut owner_index,
        &local_index_key(&rearm.root.join(format!("{DORMANT}.jsonl"))),
        "rev-dormant",
        512,
    );
    let mut api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    api.evidence.insert(
        DORMANT.to_string(),
        (1..=4)
            .map(|n| complete_api_row(DORMANT, &format!("req_{n}"), n, 10, 10, 0))
            .collect(),
    );
    trace.evidence.insert(
        DORMANT.to_string(),
        (1..=4)
            .map(|n| complete_trace_row(DORMANT, &format!("req_{n}"), ""))
            .collect(),
    );
    apply_claude_reported_usage_with_index(
        &mut [owner],
        &api,
        &trace,
        &mut owner_index,
        true,
        WINDOW,
    );
    let witness = owner_index
        .claude_usage_family_witnesses
        .remove(DORMANT)
        .unwrap();
    // A retired owner's witness persists, while its transcript is absent.
    index
        .claude_usage_family_witnesses
        .insert(DORMANT.to_string(), witness);
    assert!(tombstone_retired_claude_family(
        &mut index.claude_retired_family_tombstones,
        DORMANT,
        CENSUS_CLOCK
    ));
    api.evidence.insert(
        OTHER_ROOT.to_string(),
        (2..=4)
            .map(|n| complete_api_row(OTHER_ROOT, &format!("feq_{n}"), n, 10, 10, 0))
            .collect(),
    );
    trace.evidence.insert(
        OTHER_ROOT.to_string(),
        (2..=4)
            .map(|n| complete_trace_row(OTHER_ROOT, &format!("feq_{n}"), ""))
            .collect(),
    );
    api.evidence.insert(
        GAP.to_string(),
        vec![complete_api_row(GAP, "gap_api", 1, 10, 10, 0)],
    );
    trace.evidence.insert(
        GAP.to_string(),
        vec![complete_trace_row(GAP, "gap_trace", "")],
    );
    assert!(claude_legacy_request_owners(&api, &trace).is_none());
    for gap in [true, false] {
        if !gap {
            api.evidence.remove(GAP);
            trace.evidence.remove(GAP);
            assert!(claude_legacy_request_owners(&api, &trace).is_some());
        }
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
        let disposition = apply_claude_reported_usage_with_index_and_limits(
            &mut items.clone(),
            &api,
            &trace,
            &mut index,
            true,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
        );
        assert_eq!(
            disposition
                .first_proof_hold
                .dormant_owner_successor_family_count,
            usize::from(!gap)
        );
        let run = rearm.reread(&mut index, &disposition);
        assert!(run.counts.fence_before && run.counts.fence_after);
        assert_eq!(run.suppression.full_rearm_suppressed, gap, "{run:?}");
        assert_eq!(run.counts.full_rearm, !gap, "{run:?}");
        assert_eq!(run.rearmed_files, if gap { 0 } else { 3 });
    }
}

fn diagnostics(counts: crate::local_resource_diagnostics::claude_reread::Counts) -> Value {
    serde_json::to_value(counts).unwrap()
}

fn assert_ignored(value: &Value, key: &str, preserved: u64) {
    assert_eq!(value["rearm_veto_ignored"][key], 1, "{value}");
    assert_eq!(value["rearm_fingerprints_preserved"], preserved, "{value}");
}

fn reports_for(
    item: &SnapshotItem,
) -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    let root = claude_snapshot_family_root(item);
    let rows = item
        .claude_usage_occurrences
        .iter()
        .enumerate()
        .map(|(n, (id, occurrence))| {
            let mut row = complete_api_row(
                &root,
                id,
                n as u64,
                occurrence.usage.input_tokens,
                occurrence.usage.output_tokens,
                occurrence.usage.cache_creation_5m_tokens
                    + occurrence.usage.cache_creation_1h_tokens,
            );
            row.model = occurrence.model.clone().unwrap_or(row.model);
            row.cache_read_tokens = occurrence.usage.cache_read_tokens;
            row.effort = occurrence.reasoning_effort.clone().unwrap_or_default();
            row.speed = occurrence
                .selector
                .context
                .get("speed_mode")
                .cloned()
                .unwrap_or_default();
            row.account_identity_checked = false;
            row.account_identifier_hash = None;
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            assert!(validate_claude_api_row(&row, &root));
            row
        })
        .collect();
    (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(root.clone(), rows)]),
            ..Default::default()
        },
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(
                root.clone(),
                item.claude_usage_request_ids
                    .iter()
                    .map(|id| complete_trace_row(&root, id, ""))
                    .collect(),
            )]),
            ..Default::default()
        },
    )
}

fn fold_reports(
    rearm: &Rearm,
    index: &mut ScanIndex,
    items: &mut [SnapshotItem],
    api: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    complete: bool,
) -> ClaudeUsageAuthorityDisposition {
    let _ = rearm;
    apply_claude_reported_usage_with_index_and_limits(
        items,
        api,
        trace,
        index,
        complete,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    )
}

/// Synthetic *healthy reports* isolate canonical reducer failures. A strict
/// loader may reject conflicting duplicate rows earlier through read-health;
/// this test does not certify those files healthy or weaken that boundary.
#[test]
fn each_canonical_telemetry_refusal_is_counted_without_whole_index_rearm() {
    for cause in [
        "invalid-api",
        "invalid-trace",
        "duplicate-api",
        "duplicate-trace",
        "client-mismatch",
        "multi-root",
        "evidence-gap",
    ] {
        let rearm = Rearm::new();
        let mut index = rearm.index();
        rearm.establish(&mut index, &rearm.items);
        let mut api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
        let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
        api.evidence.insert(
            OTHER_ROOT.to_string(),
            vec![complete_api_row(OTHER_ROOT, "shared", 1, 10, 10, 0)],
        );
        trace.evidence.insert(
            OTHER_ROOT.to_string(),
            vec![complete_trace_row(OTHER_ROOT, "shared", "")],
        );
        let expected = match cause {
            "invalid-api" => {
                api.evidence.get_mut(OTHER_ROOT).unwrap()[0]
                    .capture_revision
                    .clear();
                IgnoredVeto::InvalidRows
            }
            "invalid-trace" => {
                trace.evidence.get_mut(OTHER_ROOT).unwrap()[0]
                    .capture_revision
                    .clear();
                IgnoredVeto::InvalidRows
            }
            "duplicate-api" => {
                let rows = api.evidence.get_mut(OTHER_ROOT).unwrap();
                rows.push(rows[0].clone());
                IgnoredVeto::DuplicateRows
            }
            "duplicate-trace" => {
                let rows = trace.evidence.get_mut(OTHER_ROOT).unwrap();
                rows.push(rows[0].clone());
                IgnoredVeto::DuplicateRows
            }
            "client-mismatch" => {
                let row = &mut trace.evidence.get_mut(OTHER_ROOT).unwrap()[0];
                row.client_request_id = "different".to_string();
                row.fingerprint.clear();
                row.fingerprint = format!(
                    "sha256:{:x}",
                    Sha256::digest(serde_json::to_vec(&row).unwrap())
                );
                IgnoredVeto::ClientMismatch
            }
            "multi-root" => {
                api.evidence.insert(
                    rearm.parent.clone(),
                    vec![complete_api_row(&rearm.parent, "shared", 1, 10, 10, 0)],
                );
                trace.evidence.insert(
                    rearm.parent.clone(),
                    vec![complete_trace_row(&rearm.parent, "shared", "")],
                );
                IgnoredVeto::MultiRootClaims
            }
            "evidence-gap" => {
                trace.evidence.get_mut(OTHER_ROOT).unwrap().clear();
                IgnoredVeto::EvidenceGap
            }
            _ => unreachable!(),
        };
        assert_eq!(
            classify_claude_legacy_request_owners(api.evidence.iter(), &trace.evidence)
                .unwrap_err(),
            expected
        );
        assert!(
            claude_legacy_request_owners(&api, &trace).is_none(),
            "Option facade unchanged"
        );
        for _ in 0..2 {
            let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
            index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
            let disposition = fold_reports(
                &rearm,
                &mut index,
                &mut rearm.items.clone(),
                &api,
                &trace,
                true,
            );
            let run = rearm.reread(&mut index, &disposition);
            assert!(run.suppression.full_rearm_suppressed, "{cause}: {run:?}");
            assert_eq!(run.rearmed_files, 0, "{cause}");
            let key = IgnoredVeto::ALL
                .iter()
                .find(|(kind, _)| *kind == expected)
                .unwrap()
                .1;
            assert_ignored(&diagnostics(scope.finish()), key, 2);
        }
    }
}

#[test]
fn semantic_refusal_keys_follow_real_proof_reconstruction_inputs_and_rebuild_branches() {
    let _gate = claude_request_money::e2::GateForTest::off();
    for cause in [
        "proof_failure",
        "reconstruction_failure",
        "missing_inputs",
        "rebuild_failure",
    ] {
        let mut rearm = Rearm::new();
        let mut index = rearm.index();
        rearm.add_other_family(&mut index);
        let other = rearm.other_family(false);
        let mut all = rearm.items.clone();
        all.push(other.clone());
        rearm.establish(&mut index, &all);
        let (mut api, trace) = reports_for(&other);
        // Obtain an actual canonical retained witness before testing refusals.
        fold_reports(&rearm, &mut index, &mut all.clone(), &api, &trace, true);
        assert!(index.claude_usage_family_witnesses.contains_key(OTHER_ROOT));
        let mut changed = other.clone();
        match cause {
            "proof_failure" => {
                index.claude_usage_family_witnesses.remove(OTHER_ROOT);
                api.evidence.get_mut(OTHER_ROOT).unwrap().pop();
            }
            "reconstruction_failure" => {
                api.evidence.get_mut(OTHER_ROOT).unwrap().pop();
            }
            "missing_inputs" => {
                changed
                    .claude_usage_occurrences
                    .values_mut()
                    .next()
                    .unwrap()
                    .usage
                    .input_tokens += 1;
            }
            "rebuild_failure" => {
                // Timestamp is not in the retained occurrence witness. This is
                // deterministic preparation validation, with complete read-health.
                changed
                    .claude_usage_occurrences
                    .values_mut()
                    .next()
                    .unwrap()
                    .timestamp = Some("invalid".to_string());
            }
            _ => unreachable!(),
        }
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        if cause == "proof_failure" {
            // Canonical pairing succeeds, but native request coverage fails.
            let id = trace.evidence[OTHER_ROOT]
                .last()
                .unwrap()
                .request_id
                .clone();
            let mut paired_trace = trace.clone();
            paired_trace
                .evidence
                .get_mut(OTHER_ROOT)
                .unwrap()
                .retain(|row| row.request_id != id);
            index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
            let disposition = fold_reports(&rearm, &mut index, &mut all, &api, &paired_trace, true);
            let run = rearm.reread(&mut index, &disposition);
            assert!(run.suppression.full_rearm_suppressed, "{cause}: {run:?}");
            assert_eq!(run.rearmed_files, 0);
        } else {
            // Incremental reconstruction reads the retained witness; it does
            // not overwrite it with a new proof from the changed page input.
            fold_reports(
                &rearm,
                &mut index,
                &mut [changed.clone()],
                &api,
                &trace,
                false,
            );
            // Terminal reasons accumulated on the earlier page remain visible.
            index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
            // Keep the refused family on the terminal page: an earlier-page
            // successful proof has its own independent fingerprint clear.
            let mut terminal_items = rearm.items.clone();
            terminal_items.push(changed);
            let disposition =
                fold_reports(&rearm, &mut index, &mut terminal_items, &api, &trace, true);
            let run = rearm.reread(&mut index, &disposition);
            assert!(run.suppression.full_rearm_suppressed, "{cause}: {run:?}");
            assert_eq!(run.rearmed_files, 0);
        }
        assert_ignored(&diagnostics(scope.finish()), cause, 3);
    }
}

#[test]
fn attribution_keys_and_request_sink_refusal_are_diagnostic_only() {
    for kind in [
        IgnoredVeto::WithheldAccount,
        IgnoredVeto::IdentityRefusals,
        IgnoredVeto::RequestsRefused,
    ] {
        let rearm = Rearm::new();
        let mut index = rearm.index();
        rearm.establish(&mut index, &rearm.items);
        let mut items = rearm.items.clone();
        let mut api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
        let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
        if kind == IgnoredVeto::RequestsRefused {
            let (matching, _) = reports_for(&items[0]);
            assert!(rebuild_claude_reported_usage(
                &mut items[0],
                &matching.evidence[&rearm.parent],
                &BTreeSet::new(),
                None
            ));
            assert!(!items[0].usage_buckets.is_empty());
            // Missing evidence alone is Missing, not Refused. A checked row
            // without a login exercises a genuine InvalidEvidence refusal.
            let request = items[0].claude_usage_request_ids.first().unwrap();
            let mut row = complete_api_row(&rearm.parent, request, 1, 10, 10, 0);
            row.account_identifier_hash = None;
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            api.evidence.insert(rearm.parent.clone(), vec![row]);
            trace.evidence.insert(
                rearm.parent.clone(),
                vec![complete_trace_row(&rearm.parent, request, "")],
            );
        }
        let evidence =
            claude_request_identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
        match kind {
            IgnoredVeto::WithheldAccount => {
                items[0].claude_account_withheld_reason =
                    Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS)
            }
            IgnoredVeto::IdentityRefusals => items[0].request_identity_refusals = 1,
            IgnoredVeto::RequestsRefused => {
                assert!(claude_request_identity::full_rearm_requests_refused(
                    &items[0],
                    &evidence,
                    None,
                    &index.claude_duplicate_request_owners
                ))
            }
            _ => unreachable!(),
        }
        // Keep the settled contract fixed when entering the contract-5 fold.
        let identity = (kind == IgnoredVeto::RequestsRefused).then_some(&evidence);
        if identity.is_some() {
            index.claude_request_identity_contract =
                Some(claude_request_identity::cycle_contract(true).to_string());
            index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
            let paid = apply_claude_reported_usage_with_index_and_limits(
                &mut rearm.items.clone(),
                &api,
                &trace,
                &mut index,
                true,
                WINDOW,
                MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
                MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
                identity,
            );
            rearm.reread(&mut index, &paid);
        }
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
        let disposition = apply_claude_reported_usage_with_index_and_limits(
            &mut items,
            &api,
            &trace,
            &mut index,
            true,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            identity,
        );
        let run = rearm.reread(&mut index, &disposition);
        assert!(run.suppression.full_rearm_suppressed, "{kind:?}: {run:?}");
        assert_eq!(run.rearmed_files, 0);
        let key = IgnoredVeto::ALL
            .iter()
            .find(|(candidate, _)| *candidate == kind)
            .unwrap()
            .1;
        assert_ignored(&diagnostics(scope.finish()), key, 2);
    }
}

#[test]
fn ignored_reasons_follow_window_scope_and_exclude_independent_or_empty_clears() {
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.add_other_family(&mut index);
    let mut items = rearm.items.clone();
    items.push(rearm.other_family(false));
    rearm.establish(&mut index, &items);
    items[0].claude_account_withheld_reason = Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS);
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    // A nonterminal page captures the reason without reporting savings.
    rearm.fold(
        &mut index,
        &items,
        false,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    assert_eq!(diagnostics(Default::default()), serde_json::json!({}));
    let mut persisted = serde_json::to_value(&index).unwrap();
    assert!(!persisted.to_string().contains("ignored_vetoes"));
    // The already-empty entry is outside the recorded invalid family, so
    // it does not change that family's structural fingerprint basis.
    index
        .files
        .get_mut(&rearm.other_key())
        .unwrap()
        .source_file_fingerprint
        .clear();
    let run = rearm.terminal(&mut index, &rearm.items);
    assert!(!run.counts.full_rearm);
    assert!(run.suppression.full_rearm_suppressed);
    assert_eq!(
        run.rearmed_files, 1,
        "only the entry already empty before terminal"
    );
    assert_ignored(&diagnostics(scope.finish()), "withheld_account", 2);
    // Process-local masks are intentionally not restored from serialized state.
    persisted["claude_full_rearm_progress"]["ignored_vetoes"] = serde_json::json!(65535);
    let restored: ScanIndex = serde_json::from_value(persisted).unwrap();
    assert_eq!(restored.claude_full_rearm_progress.ignored_vetoes, 0);
    let mut progress = ClaudeFullRearmProgress::default();
    progress.observe_ignored("old", IgnoredVeto::WithheldAccount.bit());
    progress.observe_ignored("new", IgnoredVeto::EvidenceGap.bit());
    assert_eq!(progress.ignored_vetoes, IgnoredVeto::EvidenceGap.bit());
}

#[test]
fn bound_retry_pending_authority_survives_unrelated_suppression_and_offers_its_own_due_retry() {
    let _gate = claude_request_money::e2::GateForTest::off();
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.add_other_family(&mut index);
    let mut items = rearm.items.clone();
    let revision = "1".repeat(64);
    let mut other = rearm.other_family(false);
    other.source_file_fingerprint = Some(revision.clone());
    index
        .files
        .get_mut(&rearm.other_key())
        .unwrap()
        .source_file_fingerprint = revision.clone();
    rearm.sources.insert(rearm.other_key(), revision.clone());
    items.push(other.clone());
    rearm.establish(&mut index, &items);
    index.insert_retry_pending_claude_authority_at_revision_for_test(OTHER_ROOT, &revision);
    let before = index.claude_usage_authority_quarantine[OTHER_ROOT].clone();
    let (api, trace) = reports_for(&other);
    let mut malformed = api.clone();
    malformed.evidence.get_mut(OTHER_ROOT).unwrap()[0]
        .capture_revision
        .clear();
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    let disposition = fold_reports(&rearm, &mut index, &mut items, &malformed, &trace, true);
    assert!(disposition
        .quarantined_source_session_ids
        .contains(OTHER_ROOT));
    let run = rearm.reread(&mut index, &disposition);
    assert!(run.suppression.full_rearm_suppressed, "{run:?}");
    assert_eq!(run.rearmed_files, 0);
    let held = &index.claude_usage_authority_quarantine[OTHER_ROOT];
    assert_eq!(
        held.disposition,
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending
    );
    assert_eq!(
        held.proven_witness_fingerprint,
        before.proven_witness_fingerprint
    );
    assert!(claude_usage_authority_preserves_pending(
        held,
        &index.claude_usage_family_witnesses[OTHER_ROOT]
    ));
    assert_ignored(&diagnostics(scope.finish()), "invalid_rows", 3);
    let mut candidate = test_candidate(rearm.root.join(format!("{OTHER_ROOT}.jsonl")));
    candidate.source_file_fingerprint = held.member_source_file_fingerprints[OTHER_ROOT].clone();
    assert!(index
        .claude_usage_authority_candidate_requires_family_reparse(&candidate)
        .is_none());
    index
        .claude_usage_authority_quarantine
        .get_mut(OTHER_ROOT)
        .unwrap()
        .retry_after_unix_seconds = 0;
    assert_eq!(
        index
            .claude_usage_authority_candidate_requires_family_reparse(&candidate)
            .as_deref(),
        Some(OTHER_ROOT)
    );
    assert!(
        index
            .claude_usage_authority_quarantine
            .contains_key(OTHER_ROOT),
        "selection never settles the held authority"
    );
}

#[test]
fn ignored_savings_exclude_independent_proof_clears_and_non_due_passes() {
    let _gate = claude_request_money::e2::GateForTest::off();
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.add_other_family(&mut index);
    let other = rearm.other_family(false);
    let mut all = rearm.items.clone();
    all.push(other.clone());
    rearm.establish(&mut index, &all);
    let (api, trace) = reports_for(&other);
    let mut page = rearm.items.clone();
    page[0].claude_account_withheld_reason = Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS);
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(CENSUS_CLOCK + 1000);
    let not_due = fold_reports(&rearm, &mut index, &mut all.clone(), &api, &trace, true);
    assert!(!not_due.duplicate_census.full_rearm);
    assert!(diagnostics(scope.finish())
        .get("rearm_veto_ignored")
        .is_none());
    fold_reports(&rearm, &mut index, &mut [other], &api, &trace, false);
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
    let disposition = fold_reports(&rearm, &mut index, &mut page, &api, &trace, true);
    assert!(disposition.full_rearm_suppression.full_rearm_suppressed);
    assert!(!disposition.duplicate_census.full_rearm);
    assert!(
        index.files[&rearm.other_key()]
            .source_file_fingerprint
            .is_empty(),
        "earlier-page proof correction still clears independently"
    );
    assert_ignored(&diagnostics(scope.finish()), "withheld_account", 2);
}

fn reidentify_native(item: &mut SnapshotItem, session: &str, prefix: Option<&str>) {
    let old_root = claude_snapshot_family_root(item);
    item.source_session_id = session.to_string();
    let root = session
        .split_once("_agent-")
        .map_or(session, |(root, _)| root);
    for fact in &mut item.attribution_facts {
        if fact.value == old_root {
            fact.value = root.to_string();
        }
    }
    if let Some(prefix) = prefix {
        let rekey = |id: &str| format!("{prefix}-{id}");
        item.claude_usage_request_ids = item
            .claude_usage_request_ids
            .iter()
            .map(|id| rekey(id))
            .collect();
        item.claude_usage_occurrences = std::mem::take(&mut item.claude_usage_occurrences)
            .into_iter()
            .map(|(id, occurrence)| (rekey(&id), occurrence))
            .collect();
    }
}

#[test]
fn native_cross_family_copy_keeps_vetoing_every_due_terminal_and_is_counted() {
    const COPY: &str = "c8888888-8888-4888-8888-888888888888";
    let mut rearm = Rearm::new();
    let mut index = rearm.index();
    rearm.add_other_family(&mut index);
    let other = rearm.other_family(false);
    let mut items = rearm.items.clone();
    items.push(other.clone());
    rearm.establish(&mut index, &items);
    let copy_key = local_index_key(&rearm.root.join(format!("{COPY}.jsonl")));
    insert_file(&mut index, &copy_key, "copy-revision", 512);
    rearm.sources.insert(copy_key, "copy-revision".to_string());
    let mut copy = other;
    reidentify_native(&mut copy, COPY, None);
    items.push(copy);
    items[0].request_identity_refusals = 1;
    items[0].claude_account_withheld_reason =
        Some(CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE);
    for _ in 0..3 {
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let run = rearm.terminal(&mut index, &items);
        assert!(run.counts.full_rearm, "{run:?}");
        assert!(run.counts.fence_after && run.counts.census_invalid);
        assert!(!run.suppression.full_rearm_suppressed);
        assert_eq!(run.rearmed_files, 4);
        assert!(
            index.claude_duplicate_request_owners.is_empty(),
            "no positive ownership from the negative query"
        );
        let counts = diagnostics(scope.finish());
        assert_eq!(counts["rearm_structural_native_duplicate"], 1);
        assert!(
            counts.get("rearm_veto_ignored").is_none(),
            "a rearming terminal reports no ignored veto: {counts}"
        );
    }
    // Presence is measured only at due closed-fence terminals.
    let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(CENSUS_CLOCK + 1000);
    rearm.fold(
        &mut index,
        &items,
        true,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
    );
    assert!(diagnostics(scope.finish())
        .get("rearm_structural_native_duplicate")
        .is_none());
}

#[test]
fn unique_native_growth_and_retirement_do_not_rearm_through_removed_vetoes() {
    use claude_request_census::{ClaudeRequestCensusRecord, ClaudeRequestCensusShape};
    const NEXT: &str = "2026-08-03T07:10:00Z";
    const NEW: &str = "c8888888-8888-4888-8888-888888888888";
    for cause in [
        "unique-append",
        "unique-session",
        "unique-member",
        "retirement",
    ] {
        let mut rearm = Rearm::new();
        let mut index = rearm.index();
        rearm.add_other_family(&mut index);
        let mut items = rearm.items.clone();
        items.push(rearm.other_family(false));
        let key = rearm.other_key();
        let record = ClaudeRequestCensusRecord::synthetic_for_test(
            &"1".repeat(64),
            CENSUS_CLOCK,
            ClaudeRequestCensusShape::Exact,
            vec![1, 2],
        );
        index
            .claude_request_census
            .insert_for_test(&key, record.clone());
        rearm.establish(&mut index, &items);
        let basis = index
            .claude_full_rearm_progress
            .structural_record
            .as_ref()
            .unwrap()
            .basis
            .clone();
        match cause {
            "unique-append" => {
                let other = items.last_mut().unwrap();
                let mut occurrence = other
                    .claude_usage_occurrences
                    .values()
                    .next()
                    .unwrap()
                    .clone();
                occurrence.sequence += 100;
                other
                    .claude_usage_request_ids
                    .insert("unique-appended-request".to_string());
                other
                    .claude_usage_occurrences
                    .insert("unique-appended-request".to_string(), occurrence);
                other.request_count += 1;
                index.claude_request_census.insert_for_test(
                    &key,
                    ClaudeRequestCensusRecord::synthetic_for_test(
                        &"2".repeat(64),
                        CENSUS_CLOCK + 86400,
                        ClaudeRequestCensusShape::Exact,
                        vec![1, 2, 3],
                    ),
                );
            }
            "unique-session" | "unique-member" => {
                let mut unique = rearm.other_family(false);
                let session = if cause == "unique-member" {
                    format!("{OTHER_ROOT}_agent-unique")
                } else {
                    NEW.to_string()
                };
                reidentify_native(&mut unique, &session, Some("unique"));
                let path = if cause == "unique-member" {
                    rearm
                        .root
                        .join(OTHER_ROOT)
                        .join("subagents/agent-unique.jsonl")
                } else {
                    rearm.root.join(format!("{NEW}.jsonl"))
                };
                let key = local_index_key(&path);
                insert_file(&mut index, &key, "unique-revision", 512);
                rearm
                    .sources
                    .insert(key.clone(), "unique-revision".to_string());
                index.claude_request_census.insert_for_test(
                    &key,
                    ClaudeRequestCensusRecord::synthetic_for_test(
                        &"3".repeat(64),
                        CENSUS_CLOCK + 86400,
                        ClaudeRequestCensusShape::Exact,
                        vec![3, 4],
                    ),
                );
                items.push(unique);
            }
            "retirement" => {
                let mut retired = record;
                retired.retire();
                assert!(retired.request_hashes().is_empty());
                index.claude_request_census.insert_for_test(&key, retired);
            }
            _ => unreachable!(),
        }
        items[0].claude_account_withheld_reason = Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS);
        items[0].request_identity_refusals = 1;
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        index.claude_duplicate_fence_next_full_rearm_unix_seconds = Some(1);
        let disposition = apply_claude_reported_usage_with_index_and_limits(
            &mut items,
            &Default::default(),
            &Default::default(),
            &mut index,
            true,
            NEXT,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
        );
        let run = rearm.reread(&mut index, &disposition);
        assert!(run.suppression.full_rearm_suppressed, "{cause}: {run:?}");
        assert_eq!(run.rearmed_files, 0, "{cause}");
        assert_eq!(
            index
                .claude_full_rearm_progress
                .structural_record
                .as_ref()
                .unwrap()
                .basis,
            basis
        );
        let counts = diagnostics(scope.finish());
        assert_ignored(&counts, "withheld_account", index.files.len() as u64);
        assert_ignored(&counts, "identity_refusals", index.files.len() as u64);
        assert!(
            counts.get("rearm_structural_native_duplicate").is_none(),
            "{cause}: {counts}"
        );
    }
}
