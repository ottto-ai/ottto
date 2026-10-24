//! Frozen admission/record-wire algorithm from main4d09e46aae9ffb2ed3774139bedd5f9d606fa805.
//! Test-only independence: never calls HEAD insert, charge, admission_bytes or
//! its record serializer. Types/getters are shared; MONEY getters are unchanged.
//! Byte counting runs through main's own `serialized_len` (unchanged by phase
//! B), so the OFF CPU receipt compares one counting-writer instantiation.
use super::*;
// Freeze main's limits too: changing HEAD limits must not move this reference.
const MAX_CLAUDE_REQUEST_CENSUS_HASHES: usize = 2_097_152;
const MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES: usize = 48 * 1024 * 1024;
const TOMBSTONE_RESERVE_BYTES: usize = 1024 * 1024;
#[derive(Clone, Default)]
pub(crate) struct MainAdmission {
    records: BTreeMap<String, ClaudeRequestCensusRecord>,
    hash_total: usize,
    serialized_total: usize,
}
struct MainRecord<'a>(&'a ClaudeRequestCensusRecord);
impl Serialize for MainRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let record = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("v", &record.derivation)?;
        map.serialize_entry("fp", &LowerHex(&record.source_file_fingerprint))?;
        map.serialize_entry("w", &record.window)?;
        map.serialize_entry("s", record.shape.wire())?;
        if record.twin {
            map.serialize_entry("tw", &true)?;
        }
        if record.unverified {
            map.serialize_entry("u", &true)?;
        }
        if !record.request_hashes().is_empty() {
            map.serialize_entry("b", &HashBase64(record.request_hashes()))?;
        }
        if let Some(birth) = &record.birth {
            map.serialize_entry("bi", &birth.unix_seconds)?;
            map.serialize_entry("bd", &birth.device)?;
            map.serialize_entry("bn", &birth.inode)?;
        }
        if let Some(retired) = record.retired {
            map.serialize_entry("r", &retired)?;
        }
        if let Some((requests, tokens)) = record.old_path_usage {
            map.serialize_entry("ur", &requests)?;
            map.serialize_entry("ut", &tokens)?;
        }
        if let Some(modified) = record.modified {
            map.serialize_entry("m", &modified)?;
        }
        let Some(ledger) = record.ledger.as_deref() else {
            return map.end();
        };
        if let Some(sweep) = &ledger.sweep {
            map.serialize_entry("sk", &sweep.complete_through)?;
            map.serialize_entry("sd", &sweep.debt)?;
        }
        if let Some(memo) = &ledger.family {
            map.serialize_entry("fr", &memo.removed_requests)?;
            map.serialize_entry("ft", &memo.removed_tokens)?;
            map.serialize_entry("fs", &memo.snapshot)?;
        }
        if let Some(facts) = &ledger.facts {
            map.serialize_entry("f", &BytesBase64(facts))?;
        }
        if let Some(tail) = &ledger.tail {
            map.serialize_entry("to", &tail.offset)?;
            map.serialize_entry("td", &tail.device)?;
            map.serialize_entry("tn", &tail.inode)?;
            map.serialize_entry("ta", &tail.anchor)?;
            map.serialize_entry("tc", &tail.line_sum)?;
            map.serialize_entry("tl", &tail.last_append_unix)?;
            map.serialize_entry("tv", &tail.audited_offset)?;
            map.serialize_entry("tw2", &tail.audited_unix)?;
            map.serialize_entry("tm", &tail.missing_sweeps)?;
            map.serialize_entry("te", &tail.first_event_unix)?;
            map.serialize_entry("tk", &tail.skip_bytes)?;
            if let Some(audit) = &tail.audit {
                map.serialize_entry("xa", &audit.target_offset)?;
                map.serialize_entry("xs", &audit.target_sum)?;
                map.serialize_entry("xp", &audit.position)?;
                map.serialize_entry("xq", &audit.partial_sum)?;
                map.serialize_entry("xk", &audit.skip_bytes)?;
            }
        }
        map.end()
    }
}

impl MainAdmission {
    pub(crate) fn from_census(census: &ClaudeRequestCensus) -> Self {
        let mut reference = Self::default();
        for (key, record) in &census.records {
            let record = record.clone();
            reference.charge(key, &record, true);
            reference.records.insert(key.clone(), record);
        }
        reference
    }
    pub(crate) fn into_census(self) -> ClaudeRequestCensus {
        let mut census = ClaudeRequestCensus {
            records: self.records,
            ..ClaudeRequestCensus::default()
        };
        census.recount();
        census
    }
    pub(crate) fn take(&mut self, key: &str) -> Option<ClaudeRequestCensusRecord> {
        let record = self.records.remove(key)?;
        self.charge(key, &record, false);
        Some(record)
    }
    pub(crate) fn hash_total(&self) -> usize {
        self.hash_total
    }
    pub(crate) fn serialized_total(&self) -> usize {
        self.serialized_total
    }
    /// Exchange record maps (O(1)) so a CPU arm walks the very same nodes,
    /// keys and hash buffers as the OFF arm: only the code differs.
    pub(crate) fn swap_records(&mut self, census: &mut ClaudeRequestCensus) {
        std::mem::swap(&mut self.records, &mut census.records);
    }
    pub(crate) fn get(&self, key: &str) -> Option<&ClaudeRequestCensusRecord> {
        self.records
            .get(key)
            .filter(|record| !record.is_birth_stub())
    }
    pub(crate) fn insert_for_test(
        &mut self,
        key: &str,
        record: impl Into<SafetyRecord>,
    ) -> ClaudeRequestCensusInsert {
        self.insert(key.to_owned(), record.into().core)
    }
    fn charge(&mut self, key: &str, record: &ClaudeRequestCensusRecord, add: bool) {
        let hashes = record.request_hashes().len();
        let bytes = entry_bytes(key, record);
        if add {
            self.hash_total += hashes;
            self.serialized_total = self.serialized_total.saturating_add(bytes);
        } else {
            self.hash_total -= hashes;
            self.serialized_total = self.serialized_total.saturating_sub(bytes);
        }
    }
    pub(crate) fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
    /// Main's MONEY maintenance at a healthy complete terminal: main's
    /// `retain_keys` (with its dropped count), recount and
    /// `retire_claude_transcript_records` (with its aged count), returned as
    /// (aged, dropped). Call `measure_d1` too for the complete main terminal.
    pub(crate) fn terminal(
        &mut self,
        index: &ScanIndex,
        observed: &BTreeSet<String>,
        window: u64,
    ) -> (u64, u64) {
        let mut dropped = 0_u64;
        self.records.retain(|key, record| {
            let kept =
                !is_ledger_key(key) && (index.files.contains_key(key) || observed.contains(key));
            dropped += u64::from(!kept && !record.is_birth_stub());
            kept
        });
        self.hash_total = 0;
        self.serialized_total = 0;
        for (key, record) in &self.records {
            self.hash_total += record.request_hashes().len();
            self.serialized_total += entry_bytes(key, record);
        }
        if window == 0 {
            return (0, dropped);
        }
        let cutoff = window.saturating_sub(CLAUDE_TRANSCRIPT_RETIREMENT_SECONDS);
        let files = &index.files;
        let census = self;
        let mut aged = 0_u64;
        let mut freed = (0_usize, 0_usize);
        for (key, record) in census.records.iter_mut() {
            if record.is_birth_stub()
                || record.retired.is_some()
                || record.request_hashes().is_empty()
            {
                continue;
            }
            // Not dirty: the indexed revision is still the one the record (and
            // its mtime) describes.
            let Some(entry) = files.get(key.as_str()).filter(|entry| {
                decode_fingerprint(&entry.source_file_fingerprint)
                    .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
            }) else {
                continue;
            };
            // A record written before `m` (#664) takes the entry's mtime: the
            // equal fingerprint hashes that same mtime.
            let modified = record
                .modified
                .or((entry.modified_unix_seconds > 0).then_some(entry.modified_unix_seconds));
            if !modified.is_some_and(|modified| modified < cutoff) {
                continue;
            }
            let before = (record.request_hashes().len(), entry_bytes(key, record));
            record.retire();
            let after = entry_bytes(key, record);
            freed.0 += before.0;
            freed.1 += before.1.saturating_sub(after);
            aged += 1;
        }
        census.hash_total -= freed.0;
        census.serialized_total = census.serialized_total.saturating_sub(freed.1);
        (aged, dropped)
    }
}
impl Serialize for MainAdmission {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.records.len()))?;
        for (key, record) in &self.records {
            map.serialize_entry(key, &MainRecord(record))?;
        }
        map.end()
    }
}
fn entry_bytes(key: &str, record: &ClaudeRequestCensusRecord) -> usize {
    // Main's `entry_serialized_bytes` with main's own counting writer
    // (`serialized_len`, byte-identical to main): no allocation and no HEAD
    // record serializer. One writer instantiation also keeps the per-byte
    // escape loop the same machine code in both CPU arms.
    serialized_len(&key)
        .saturating_add(serialized_len(&MainRecord(record)))
        .saturating_add(2)
}

impl MainAdmission {
    pub(crate) fn insert(
        &mut self,
        key: String,
        mut record: ClaudeRequestCensusRecord,
    ) -> ClaudeRequestCensusInsert {
        if let Some(old) = self.records.remove(&key) {
            self.charge(&key, &old, false);
        }
        let fits = |census: &Self, record: &ClaudeRequestCensusRecord, limit: usize| {
            census
                .hash_total
                .checked_add(record.request_hashes().len())
                .is_some_and(|total| total <= MAX_CLAUDE_REQUEST_CENSUS_HASHES)
                && census
                    .serialized_total
                    .checked_add(entry_bytes(&key, record))
                    .is_some_and(|total| total <= limit)
        };
        let mut outcome = ClaudeRequestCensusInsert::Stored;
        if !fits(
            self,
            &record,
            MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES - TOMBSTONE_RESERVE_BYTES,
        ) {
            record.shape = ClaudeRequestCensusShape::OverBudget;
            record.request_hashes = None;
            record.retired = None;
            if let Some(fields) = record.ledger.as_mut() {
                fields.facts = None;
            }
            outcome = ClaudeRequestCensusInsert::Tombstone;
            if !fits(self, &record, MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES) {
                return ClaudeRequestCensusInsert::Refused;
            }
        }
        self.charge(&key, &record, true);
        self.records.insert(key, record);
        outcome
    }
}

/// Frozen inline layout, only for the OFF receipt (no values constructed).
#[allow(dead_code)]
pub(crate) struct MainRecordLayout {
    /// The parse's candidate fingerprint (sidecar-inclusive), whether or not
    /// the entry was recorded with it.
    source_file_fingerprint: [u8; 32],
    /// `CLAUDE_REQUEST_CENSUS_DERIVATION` at production.
    derivation: u16,
    /// The census window end (unix seconds) of the traversal that parsed it.
    window: u64,
    shape: ClaudeRequestCensusShape,
    /// The parsed content (root, member) differs from the path-derived pair.
    twin: bool,
    /// Pending ruling S2: not source-verified (a tail parse that still owes
    /// its sampled audit, or a read that cannot certify its source). D1
    /// produces it as for a verified parse and only notes it here.
    unverified: bool,
    /// Sorted, strictly ascending `claude_request_hash` of every request id
    /// (None: none). Shared, never copied, by every clone of the index (the
    /// working, committed and selected-subset copies hold one buffer).
    request_hashes: Option<Arc<[u64]>>,
    /// First-seen birth of the physical object at this key, set once and
    /// bound to its (device, inode).
    birth: Option<ClaudeRequestBirth>,
    /// Retired: the hashes were dropped (old, settled file); this is how many
    /// there were. A retired record still counts as recorded.
    retired: Option<u64>,
    /// Old-path requests and conserved tokens last built from this file.
    old_path_usage: Option<(u64, u64)>,
    /// Transcript records: the file's modification time (unix seconds) at the
    /// parse that wrote the record. Retirement reads it, never the index.
    modified: Option<u64>,
    /// P1 money ledger records only (they live in the ledger's own store,
    /// never in the scan index): boxed so transcript records stay small.
    ledger: Option<Box<ClaudeLedgerFields>>,
}

// Frozen main resident/admission formula; the layout fields above are frozen.
pub(crate) const MAIN_RECORD_RESIDENT_OVERHEAD_BYTES: usize =
    (std::mem::size_of::<String>() + std::mem::size_of::<MainRecordLayout>()) * 3 / 2
        + std::mem::size_of::<ClaudeLedgerFields>()
        + 2 * std::mem::size_of::<usize>();

// Frozen main D1 join from 8b1c7309. Independent of HEAD d1::measure and D2.
crate::heap_layout_bound::fields!(MainAdmission; records, hash_total, serialized_total);
impl MainAdmission {
    fn records(&self) -> impl Iterator<Item = (&String, &ClaudeRequestCensusRecord)> {
        self.records
            .iter()
            .filter(|(_, record)| !record.is_birth_stub())
    }
    pub(crate) fn measure_d1(
        &self,
        index: &mut ScanIndex,
        window: u64,
        residue: &BTreeSet<String>,
    ) -> ClaudeRequestCensusShadowCounts {
        let join = D1Join::new(index, self, window, residue);
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
        counts.json_bytes = serialized_len(self);
        counts.heap_bytes =
            crate::heap_layout_bound::completed_bound(self, usize::MAX).unwrap_or_default();
        counts
    }
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
        census: &MainAdmission,
        window: u64,
        residue_index_keys: &BTreeSet<String>,
    ) -> Self {
        let mut join = Self {
            counts: ClaudeRequestCensusShadowCounts {
                // Birth stubs are no record.
                records: census.records().count(),
                hashes: census.hash_total,
                hash_budget_usage_percent: census.hash_total.saturating_mul(100)
                    / MAX_CLAUDE_REQUEST_CENSUS_HASHES,
                hash_budget_warning: census.hash_total.saturating_mul(100)
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
            || Self::workspace_bound(index, census)
                .map_or(true, |bytes| bytes > MAX_SHADOW_WORKSPACE_BYTES)
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
    fn workspace_bound(index: &ScanIndex, census: &MainAdmission) -> Option<usize> {
        use crate::heap_layout_bound::tree_node_bytes;
        let files = index.files.len();
        let records = census.records.len();
        let file_keys = index
            .files
            .keys()
            .try_fold(0_usize, |bytes, key| bytes.checked_add(key.len()))?;
        let record_keys = census
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
    fn merge_hashes(&mut self, census: &MainAdmission) {
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

// Freeze main's wire shape independently of HEAD's optional D2 fields.
#[derive(Default, Serialize)]
struct MainD1Counts {
    pub would_open: bool,
    pub would_open_flips: u64,
    pub family_keys: usize,
    pub covered_by_fingerprint: usize,
    pub covered_by_window: usize,
    pub missing_residue: usize,
    pub missing_account_hold: usize,
    pub missing_placeholder: usize,
    pub missing_empty_fingerprint: usize,
    pub missing_fingerprint_mismatch: usize,
    pub missing_migrate: usize,
    pub missing_over_budget: usize,
    pub quarantine_without_record: usize,
    pub shape_exact: usize,
    pub shape_empty: usize,
    pub shape_identity_incomplete: usize,
    pub shape_lossy: usize,
    pub unverified: usize,
    pub twin: usize,
    pub family_unknown_roots: usize,
    pub records: usize,
    pub hashes: usize,
    pub hash_budget_usage_percent: usize,
    pub hash_budget_warning: bool,
    pub transient_limited: bool,
    pub transient_peak_bytes: usize,
    pub duplicate_hashes: usize,
    pub duplicate_owner_entries: usize,
    pub shared_keys: usize,
    pub derivation_drift: u64,
    pub json_bytes: usize,
    pub heap_bytes: usize,
}
#[derive(Default, Serialize)]
struct MainDuplicateCounts {
    pub census_complete: bool,
    pub fence_before: bool,
    pub fence_after: bool,
    pub census_invalid: bool,
    pub invalid_current_window_family_count: usize,
    pub pending_occurrence_count: usize,
    pub page_invalidated_identity_count: usize,
    pub page_invalidated_occurrence_mismatch_count: usize,
    pub page_invalidated_cap_count: usize,
    pub page_invalidated_member_changed_count: usize,
    pub coverage_complete: bool,
    pub coverage_missing_member_count: usize,
    pub full_rearm: bool,
    pub rearm_attempt: u8,
    pub full_rearm_deferred_until: Option<u64>,
    /// Slice D1 shadow, present only on a complete Claude terminal scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_census: Option<MainD1Counts>,
}
pub(crate) fn counts_line(counts: ClaudeRequestCensusShadowCounts) -> Vec<u8> {
    serde_json::to_vec(&MainDuplicateCounts {
        request_census: Some(MainD1Counts {
            would_open: counts.would_open,
            would_open_flips: counts.would_open_flips,
            family_keys: counts.family_keys,
            covered_by_fingerprint: counts.covered_by_fingerprint,
            covered_by_window: counts.covered_by_window,
            missing_residue: counts.missing_residue,
            missing_account_hold: counts.missing_account_hold,
            missing_placeholder: counts.missing_placeholder,
            missing_empty_fingerprint: counts.missing_empty_fingerprint,
            missing_fingerprint_mismatch: counts.missing_fingerprint_mismatch,
            missing_migrate: counts.missing_migrate,
            missing_over_budget: counts.missing_over_budget,
            quarantine_without_record: counts.quarantine_without_record,
            shape_exact: counts.shape_exact,
            shape_empty: counts.shape_empty,
            shape_identity_incomplete: counts.shape_identity_incomplete,
            shape_lossy: counts.shape_lossy,
            unverified: counts.unverified,
            twin: counts.twin,
            family_unknown_roots: counts.family_unknown_roots,
            records: counts.records,
            hashes: counts.hashes,
            hash_budget_usage_percent: counts.hash_budget_usage_percent,
            hash_budget_warning: counts.hash_budget_warning,
            transient_limited: counts.transient_limited,
            transient_peak_bytes: counts.transient_peak_bytes,
            duplicate_hashes: counts.duplicate_hashes,
            duplicate_owner_entries: counts.duplicate_owner_entries,
            shared_keys: counts.shared_keys,
            derivation_drift: counts.derivation_drift,
            json_bytes: counts.json_bytes,
            heap_bytes: counts.heap_bytes,
        }),
        ..Default::default()
    })
    .unwrap()
}
