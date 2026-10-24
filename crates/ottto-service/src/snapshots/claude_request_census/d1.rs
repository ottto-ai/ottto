//! Main 8b1c7309 D1 diagnostic join, preserved for activation OFF.
//! Coverage, duplicate merging and counts retain main semantics. D2 owns no
//! consumer here; optional safety must not change the pre-existing D1 line.
use super::*;

pub(super) fn measure(
    index: &mut ScanIndex,
    window: u64,
    residue_index_keys: &BTreeSet<String>,
) -> ClaudeRequestCensusShadowCounts {
    let join = D1Join::new(index, window, residue_index_keys);
    let mut counts = join.counts(true);
    let state = &mut index.claude_request_census_shadow;
    if state
        .would_open
        .is_some_and(|before| before != counts.would_open)
    {
        state.would_open_flips = state.would_open_flips.saturating_add(1);
    }
    state.would_open = Some(counts.would_open);
    counts.would_open_flips = state.would_open_flips;
    counts.derivation_drift = state.derivation_drift;
    counts.decode_duplicate_keys_dropped = state.decode_duplicate_keys_dropped;
    (
        counts.census_duplicate_rebuild_exhausted,
        counts.census_duplicate_rebuild_orphaned,
        counts.census_rebuild_priors_decode_refused,
        counts.census_duplicate_rebuild_identity_revoked,
    ) = rebuild_bound::terminal(index);
    // Main's census contains only these core records. Keep its byte and heap
    // meaning even when OFF encounters safety left by a previous ON run.
    counts.json_bytes = serialized_len(&index.claude_request_census.records);
    counts.heap_bytes =
        crate::heap_layout_bound::completed_bound(&index.claude_request_census.records, usize::MAX)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .unwrap_or_default();
    counts
}

pub(crate) struct D1Join {
    counts: ClaudeRequestCensusShadowCounts,
    coverage: BTreeMap<String, ClaudeRequestCensusCoverage>,
    shared_keys: BTreeSet<String>,
    unknown_roots: BTreeSet<String>,
}

impl D1Join {
    pub(crate) fn new(
        index: &ScanIndex,
        window: u64,
        residue_index_keys: &BTreeSet<String>,
    ) -> Self {
        let census = &index.claude_request_census;
        let mut join = Self {
            counts: ClaudeRequestCensusShadowCounts {
                // Birth stubs are no record.
                records: census.records().count(),
                hashes: census.active_hash_total,
                hash_budget_usage_percent: census.active_hash_total.saturating_mul(100)
                    / MAX_CLAUDE_REQUEST_CENSUS_HASHES,
                hash_budget_warning: census.active_hash_total.saturating_mul(100)
                    >= MAX_CLAUDE_REQUEST_CENSUS_HASHES * 80,
                ..ClaudeRequestCensusShadowCounts::default()
            },
            coverage: BTreeMap::new(),
            shared_keys: BTreeSet::new(),
            unknown_roots: BTreeSet::new(),
        };
        // Shadow-only workspace bound. Oversized inventories remain closed;
        // ordinary scan decisions and existing resource caps are unchanged.
        if index.files.len() > MAX_DECODE_ENTRIES
            || census.records.len() > MAX_DECODE_ENTRIES
            || Self::workspace_bound(index).map_or(true, |bytes| bytes > MAX_SHADOW_WORKSPACE_BYTES)
            || index
                .files
                .keys()
                .chain(census.records.keys())
                .any(|key| key.len() > MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES)
        {
            join.counts.transient_limited = true;
            return join;
        }
        let mut path_owners = BTreeMap::<(String, String), usize>::new();
        for (key, entry) in &index.files {
            let Some(path_owner) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            if index.confirmed_empty_files.contains(key) {
                continue;
            }
            join.counts.family_keys += 1;
            let record = census
                .get(key)
                .filter(|record| record.derivation == CLAUDE_REQUEST_CENSUS_DERIVATION);
            let coverage = Self::coverage(index, key, entry, record, window, residue_index_keys);
            let counts = &mut join.counts;
            match coverage {
                ClaudeRequestCensusCoverage::Fingerprint => counts.covered_by_fingerprint += 1,
                ClaudeRequestCensusCoverage::Window => counts.covered_by_window += 1,
                ClaudeRequestCensusCoverage::OverBudget => counts.missing_over_budget += 1,
                ClaudeRequestCensusCoverage::AccountHold => counts.missing_account_hold += 1,
                ClaudeRequestCensusCoverage::Residue => counts.missing_residue += 1,
                ClaudeRequestCensusCoverage::Placeholder => counts.missing_placeholder += 1,
                ClaudeRequestCensusCoverage::EmptyFingerprint => {
                    counts.missing_empty_fingerprint += 1
                }
                ClaudeRequestCensusCoverage::FingerprintMismatch => {
                    counts.missing_fingerprint_mismatch += 1
                }
                ClaudeRequestCensusCoverage::Migrate => counts.missing_migrate += 1,
            }
            let covered = matches!(
                coverage,
                ClaudeRequestCensusCoverage::Fingerprint | ClaudeRequestCensusCoverage::Window
            );
            if !covered
                && index
                    .claude_usage_authority_quarantine
                    .contains_key(&path_owner.0)
            {
                counts.quarantine_without_record += 1;
            }
            if let Some(record) = record.filter(|_| covered) {
                match record.shape {
                    ClaudeRequestCensusShape::Exact => counts.shape_exact += 1,
                    ClaudeRequestCensusShape::Empty => counts.shape_empty += 1,
                    ClaudeRequestCensusShape::IdentityIncomplete => {
                        counts.shape_identity_incomplete += 1
                    }
                    ClaudeRequestCensusShape::Lossy => counts.shape_lossy += 1,
                    ClaudeRequestCensusShape::OverBudget => {}
                }
                counts.unverified += usize::from(record.unverified);
                counts.twin += usize::from(record.twin);
                if record.shape.unknown() || record.twin {
                    join.unknown_roots.insert(path_owner.0.clone());
                }
            }
            join.coverage.insert(key.clone(), coverage);
            *path_owners.entry(path_owner).or_default() += 1;
        }
        join.observe_workspace(
            crate::heap_layout_bound::completed_bound(&path_owners, usize::MAX)
                .unwrap_or(usize::MAX),
        );
        // A path twin: one (root, member) on two or more keys.
        join.unknown_roots.extend(
            path_owners
                .into_iter()
                .filter(|(_, keys)| *keys > 1)
                .map(|((root, _), _)| root),
        );
        // A member that is not a counted key (residue never indexed, or a
        // confirmed-empty file) still leaves its family census-unknown.
        for (key, record) in &census.records {
            if join.coverage.contains_key(key)
                || record.derivation != CLAUDE_REQUEST_CENSUS_DERIVATION
                || !(record.shape.unknown() || record.twin)
            {
                continue;
            }
            if let Some((root, _)) = claude_index_path_family_member(Path::new(key)) {
                join.unknown_roots.insert(root);
            }
        }
        join.counts.family_unknown_roots = join.unknown_roots.len();
        join.merge_hashes(census);
        join.observe_workspace(0);
        join
    }

    /// Bound the peak requested layout before constructing a key copy.
    /// One full B-tree node per entry (the repository's layout bound), full
    /// path bytes for every root/member substring (two for the owner pair),
    /// and double vector capacities
    /// cover coverage/path owners/shared/unknown plus all merge buffers.
    fn workspace_bound(index: &ScanIndex) -> Option<usize> {
        use crate::heap_layout_bound::tree_node_bytes;
        let files = index.files.len();
        let records = index.claude_request_census.records.len();
        let file_keys = index
            .files
            .keys()
            .try_fold(0_usize, |bytes, key| bytes.checked_add(key.len()))?;
        let record_keys = index
            .claude_request_census
            .records
            .keys()
            .try_fold(0_usize, |bytes, key| bytes.checked_add(key.len()))?;
        let mut bytes = files
            .checked_add(1)?
            .checked_mul(tree_node_bytes::<String, ClaudeRequestCensusCoverage>()?)?;
        bytes = bytes.checked_add(
            files
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<(String, String), usize>()?)?,
        )?;
        bytes = bytes.checked_add(
            records
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, ()>()?)?,
        )?;
        bytes = bytes.checked_add(
            files
                .checked_add(records)?
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, ()>()?)?,
        )?;
        bytes = bytes.checked_add(file_keys.checked_mul(4)?)?;
        bytes = bytes.checked_add(record_keys.checked_mul(2)?)?;
        let merge_slot = std::mem::size_of::<(&String, &[u64])>()
            + std::mem::size_of::<Reverse<(u64, usize, usize)>>()
            + std::mem::size_of::<usize>();
        bytes.checked_add(records.checked_mul(2 * merge_slot)?)
    }

    fn observe_workspace(&mut self, extra: usize) {
        let owned = crate::heap_layout_bound::completed_bound(&self.coverage, usize::MAX)
            .and_then(|coverage| {
                crate::heap_layout_bound::completed_bound(&self.shared_keys, usize::MAX)
                    .and_then(|shared| coverage.checked_add(shared))
            })
            .and_then(|bytes| {
                crate::heap_layout_bound::completed_bound(&self.unknown_roots, usize::MAX)
                    .and_then(|roots| bytes.checked_add(roots))
            })
            .unwrap_or(usize::MAX);
        self.counts.transient_peak_bytes = self
            .counts
            .transient_peak_bytes
            .max(owned.saturating_add(extra));
    }

    fn coverage(
        index: &ScanIndex,
        key: &str,
        entry: &ScanIndexEntry,
        record: Option<&ClaudeRequestCensusRecord>,
        window: u64,
        residue_index_keys: &BTreeSet<String>,
    ) -> ClaudeRequestCensusCoverage {
        if let Some(record) =
            record.filter(|record| record.shape != ClaudeRequestCensusShape::OverBudget)
        {
            if decode_fingerprint(&entry.source_file_fingerprint)
                .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
            {
                return ClaudeRequestCensusCoverage::Fingerprint;
            }
            if window != 0 && record.window == window {
                return ClaudeRequestCensusCoverage::Window;
            }
        }
        if record.is_some_and(|record| record.shape == ClaudeRequestCensusShape::OverBudget) {
            ClaudeRequestCensusCoverage::OverBudget
        } else if index.claude_account_deferred_holds.contains_key(key) {
            ClaudeRequestCensusCoverage::AccountHold
        } else if residue_index_keys.contains(key) {
            ClaudeRequestCensusCoverage::Residue
        } else if entry.last_snapshot_fingerprint.is_none()
            && !index.file_snapshot_fingerprints.contains_key(key)
        {
            ClaudeRequestCensusCoverage::Placeholder
        } else if entry.source_file_fingerprint.is_empty() {
            ClaudeRequestCensusCoverage::EmptyFingerprint
        } else if record.is_some() {
            ClaudeRequestCensusCoverage::FingerprintMismatch
        } else {
            ClaudeRequestCensusCoverage::Migrate
        }
    }

    /// k-way merge of the sorted per-record hash lists. Hashes are unique per
    /// record, so a run of equal hashes is one hash under that many keys.
    fn merge_hashes(&mut self, census: &ClaudeRequestCensus) {
        let lists = census
            .records
            .iter()
            .filter(|(_, record)| !record.request_hashes().is_empty())
            .map(|(key, record)| (key, record.request_hashes()))
            .collect::<Vec<_>>();
        let mut heap = lists
            .iter()
            .enumerate()
            .map(|(list, (_, hashes))| Reverse((hashes[0], list, 0_usize)))
            .collect::<BinaryHeap<_>>();
        let mut run: Option<u64> = None;
        let mut run_lists = Vec::new();
        while let Some(Reverse((hash, list, position))) = heap.pop() {
            if run != Some(hash) {
                self.close_run(&lists, &run_lists);
                run = Some(hash);
                run_lists.clear();
            }
            run_lists.push(list);
            if let Some(next) = lists[list].1.get(position + 1) {
                heap.push(Reverse((*next, list, position + 1)));
            }
        }
        self.close_run(&lists, &run_lists);
        self.observe_workspace(
            lists
                .capacity()
                .saturating_mul(std::mem::size_of::<(&String, &[u64])>())
                .saturating_add(
                    heap.capacity()
                        .saturating_mul(std::mem::size_of::<Reverse<(u64, usize, usize)>>()),
                )
                .saturating_add(
                    run_lists
                        .capacity()
                        .saturating_mul(std::mem::size_of::<usize>()),
                ),
        );
    }

    fn close_run(&mut self, lists: &[(&String, &[u64])], run_lists: &[usize]) {
        if run_lists.len() < 2 {
            return;
        }
        self.counts.duplicate_hashes += 1;
        self.counts.duplicate_owner_entries = self
            .counts
            .duplicate_owner_entries
            .saturating_add(run_lists.len());
        self.shared_keys
            .extend(run_lists.iter().map(|list| lists[*list].0.clone()));
    }

    /// `claude_census_disjointness_complete`: on a terminal page with
    /// `census_complete`, (1) every indexed Claude family-member key that is
    /// not confirmed empty has a covering record (by fingerprint or this
    /// window; never excused by a quarantine), (2) the hash total fits the
    /// budget and (3) the duplicate owners fit the owner bound. It states only
    /// that every visible request id was compared with every other key's ids,
    /// never that any member is unique or owned.
    pub(crate) fn disjointness_complete(&self, census_complete: bool) -> bool {
        let counts = &self.counts;
        census_complete
            && !counts.transient_limited
            && counts.covered_by_fingerprint + counts.covered_by_window == counts.family_keys
            && counts.hashes <= MAX_CLAUDE_REQUEST_CENSUS_HASHES
            && counts.duplicate_owner_entries <= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
    }

    fn counts(&self, census_complete: bool) -> ClaudeRequestCensusShadowCounts {
        ClaudeRequestCensusShadowCounts {
            would_open: self.disjointness_complete(census_complete),
            shared_keys: self.shared_keys.len(),
            ..self.counts
        }
    }
}

/// Main's existing D1 line shape. OFF adds no default-valued D2 counters.
pub(super) struct CountsLine<'a>(pub(super) &'a ClaudeRequestCensusShadowCounts);
impl Serialize for CountsLine<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(32))?;
        map.serialize_entry("would_open", &self.0.would_open)?;
        map.serialize_entry("would_open_flips", &self.0.would_open_flips)?;
        map.serialize_entry("family_keys", &self.0.family_keys)?;
        map.serialize_entry("covered_by_fingerprint", &self.0.covered_by_fingerprint)?;
        map.serialize_entry("covered_by_window", &self.0.covered_by_window)?;
        map.serialize_entry("missing_residue", &self.0.missing_residue)?;
        map.serialize_entry("missing_account_hold", &self.0.missing_account_hold)?;
        map.serialize_entry("missing_placeholder", &self.0.missing_placeholder)?;
        map.serialize_entry(
            "missing_empty_fingerprint",
            &self.0.missing_empty_fingerprint,
        )?;
        map.serialize_entry(
            "missing_fingerprint_mismatch",
            &self.0.missing_fingerprint_mismatch,
        )?;
        map.serialize_entry("missing_migrate", &self.0.missing_migrate)?;
        map.serialize_entry("missing_over_budget", &self.0.missing_over_budget)?;
        map.serialize_entry(
            "quarantine_without_record",
            &self.0.quarantine_without_record,
        )?;
        map.serialize_entry("shape_exact", &self.0.shape_exact)?;
        map.serialize_entry("shape_empty", &self.0.shape_empty)?;
        map.serialize_entry(
            "shape_identity_incomplete",
            &self.0.shape_identity_incomplete,
        )?;
        map.serialize_entry("shape_lossy", &self.0.shape_lossy)?;
        map.serialize_entry("unverified", &self.0.unverified)?;
        map.serialize_entry("twin", &self.0.twin)?;
        map.serialize_entry("family_unknown_roots", &self.0.family_unknown_roots)?;
        map.serialize_entry("records", &self.0.records)?;
        map.serialize_entry("hashes", &self.0.hashes)?;
        map.serialize_entry(
            "hash_budget_usage_percent",
            &self.0.hash_budget_usage_percent,
        )?;
        map.serialize_entry("hash_budget_warning", &self.0.hash_budget_warning)?;
        map.serialize_entry("transient_limited", &self.0.transient_limited)?;
        map.serialize_entry("transient_peak_bytes", &self.0.transient_peak_bytes)?;
        map.serialize_entry("duplicate_hashes", &self.0.duplicate_hashes)?;
        map.serialize_entry("duplicate_owner_entries", &self.0.duplicate_owner_entries)?;
        map.serialize_entry("shared_keys", &self.0.shared_keys)?;
        map.serialize_entry("derivation_drift", &self.0.derivation_drift)?;
        map.serialize_entry("json_bytes", &self.0.json_bytes)?;
        map.serialize_entry("heap_bytes", &self.0.heap_bytes)?;
        map.end()
    }
}
