//! Runtime census-prefix veto (Lead B round 8). Once a family's usage pending
//! is retired, its request ids survive only as the request census's 8-byte
//! prefixes. This runtime index of those prefixes, for Claude roots with NO
//! usage pending, lets a later untagged copy of such a family still meet a
//! negative scheduling veto. Nothing is persisted: retention is the census
//! rule (35 idle days, pruned when the file vanishes), inherited by deriving
//! from it. A prefix collision only over-vetoes. An index past its byte
//! budget, or a pending-free record whose hashes the census dropped (over
//! budget), is Unknown: a B3 hold, never a dropped hash or a "Clear".
use super::*;

/// Byte budget of one build: the prefix and root-id arrays at their actual
/// capacities, root and pending-root metadata, the merge scratch, and any
/// cached index still alive beside it. An M4-sized census (about 884k
/// entries) needs 10.6 MB of arrays (12 bytes per entry) plus metadata.
pub(crate) const CENSUS_PREFIX_MAX_BYTES: usize = 12 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static CAP_FOR_TEST: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Run with this byte budget instead of [`CENSUS_PREFIX_MAX_BYTES`].
#[cfg(test)]
pub(crate) fn with_cap_for_test<T>(bytes: usize, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CAP_FOR_TEST.with(|cell| cell.set(None));
        }
    }
    CAP_FOR_TEST.with(|cell| cell.set(Some(bytes)));
    let _reset = Reset;
    run()
}

fn budget() -> usize {
    #[cfg(test)]
    if let Some(bytes) = CAP_FOR_TEST.with(std::cell::Cell::get) {
        return bytes;
    }
    CENSUS_PREFIX_MAX_BYTES
}

/// What the census says about some request prefixes of one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CensusPrefixVerdict {
    /// No other pending-free root's live census record holds any of them.
    Clear,
    /// Another root holds one: veto (a collision only over-vetoes).
    Held,
    /// No negative answer (B3 hold): the index would pass its byte budget,
    /// or a pending-free record's hashes were dropped (over budget).
    Unknown,
}

/// Every live, hash-bearing census transcript record whose root has no usage
/// pending, as two parallel arrays sorted by prefix: `prefixes[i]` is a
/// `claude_request_hash` and `ids[i]` the index of its root in `roots`.
#[derive(Debug, Default)]
pub(crate) struct CensusPrefixIndex {
    prefixes: Vec<u64>,
    ids: Vec<u32>,
    roots: Vec<String>,
    // Roots excluded for their usage pending, sorted. Once one of them has
    // none (retired, invalidated or vanished), its census belongs here and
    // the index is stale.
    pending: Vec<String>,
    unknown: bool,
    // Retained bytes: array capacities and root metadata.
    bytes: usize,
}
crate::heap_layout_bound::fields!(CensusPrefixIndex; prefixes, ids, roots, pending, unknown, bytes);

// Track allocations, not Arc reference counts: cloned committed baselines and
// older generations can retain an index after the working cache drops it.
// Fixed storage, and one lock across admission/build/registration; no I/O.
const LIVE_INDEX_SLOTS: usize = 64;
type LiveIndexes = [Option<std::sync::Weak<CensusPrefixIndex>>; LIVE_INDEX_SLOTS];
#[cfg(not(test))]
static LIVE_INDEXES: Mutex<LiveIndexes> = Mutex::new([const { None }; LIVE_INDEX_SLOTS]);
#[cfg(test)]
thread_local! {
    static LIVE_INDEXES: std::cell::RefCell<LiveIndexes> =
        const { std::cell::RefCell::new([const { None }; LIVE_INDEX_SLOTS]) };
}

fn with_live_indexes<T>(run: impl FnOnce(&mut LiveIndexes) -> T) -> T {
    #[cfg(test)]
    return LIVE_INDEXES.with(|live| run(&mut live.borrow_mut()));
    #[cfg(not(test))]
    run(&mut LIVE_INDEXES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}

fn build_shared(index: &ScanIndex) -> Arc<CensusPrefixIndex> {
    with_live_indexes(|live| {
        let mut retained = std::mem::size_of::<LiveIndexes>();
        for slot in live.iter_mut() {
            if let Some(built) = slot.as_ref().and_then(std::sync::Weak::upgrade) {
                retained = retained.saturating_add(built.bytes());
            } else {
                *slot = None;
            }
        }
        let free = live.iter().position(Option::is_none);
        let allowance = if free.is_some() {
            budget().saturating_sub(retained)
        } else {
            0
        };
        let built = Arc::new(CensusPrefixIndex::build_within(index, allowance));
        if !built.unknown() {
            live[free.expect("successful build has an admitted registry slot")] =
                Some(Arc::downgrade(&built));
        }
        built
    })
}

impl CensusPrefixIndex {
    #[cfg(test)]
    pub(crate) fn build(index: &ScanIndex) -> Self {
        Self::build_within(index, budget())
    }

    /// First count using borrowed census rows and no scratch allocation.
    /// Admit all vector capacities, owned strings, merge scratch and Arc
    /// metadata BEFORE reserving any of them. The merge uses sorted slices;
    /// no map nodes or sorting scratch are allocated.
    pub(crate) fn build_within(index: &ScanIndex, budget: usize) -> Self {
        let mut out = Self::default();
        let (mut over_budget, mut overflow) = (0_u64, 0_u64);
        let (mut records, mut total, mut root_chars) = (0_usize, 0_usize, 0_usize);
        for (key, record) in index.claude_request_census.records() {
            let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
                continue;
            };
            if index.claude_usage_family_pending.contains_key(member.root)
                || record.retired().is_some()
            {
                continue;
            }
            let root = member.root;
            if record.over_budget() {
                over_budget += 1;
            } else if !record.request_hashes().is_empty() {
                records = records.saturating_add(1);
                total = total.saturating_add(record.request_hashes().len());
                root_chars = root_chars.saturating_add(root.len());
            }
        }
        let pending_chars = index
            .claude_usage_family_pending
            .keys()
            .fold(0_usize, |n, root| n.saturating_add(root.len()));
        let per_record = std::mem::size_of::<&str>()
            + std::mem::size_of::<(&[u64], u32)>()
            + std::mem::size_of::<std::cmp::Reverse<(u64, usize, usize)>>()
            + std::mem::size_of::<String>();
        // Count duplicate root strings too: conservative before dedup.
        let peak = total
            .checked_mul(12)
            .and_then(|n| n.checked_add(records.checked_mul(per_record)?))
            .and_then(|n| n.checked_add(root_chars))
            .and_then(|n| {
                n.checked_add(
                    index
                        .claude_usage_family_pending
                        .len()
                        .checked_mul(std::mem::size_of::<String>())?,
                )
            })
            .and_then(|n| n.checked_add(pending_chars))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())
            });
        if over_budget == 0 && peak.is_some_and(|n| n <= budget) {
            overflow = u64::from(out.fill(index, records, total, budget).is_none());
        } else if over_budget == 0 {
            overflow = 1;
        }
        if over_budget != 0 || overflow != 0 {
            out = Self {
                unknown: true,
                ..Self::default()
            };
        }
        crate::local_resource_diagnostics::traversal_point(
            "claude_census_prefix_veto",
            SnapshotSource::ClaudeCode.api_slug(),
            &json!({"census_prefix_records":records,"census_prefix_entries":out.prefixes.len(),
                "census_prefix_bytes":out.bytes,"census_prefix_build_peak_bytes":peak,
                "census_prefix_over_budget_records":over_budget,"census_prefix_overflow":overflow,
                "census_prefix_unknown":u64::from(out.unknown)}),
        );
        out
    }

    fn fill(
        &mut self,
        index: &ScanIndex,
        records: usize,
        total: usize,
        budget: usize,
    ) -> Option<()> {
        let mut roots = Vec::<&str>::new();
        roots.try_reserve_exact(records).ok()?;
        let mut sources = Vec::<(&[u64], u32)>::new();
        sources.try_reserve_exact(records).ok()?;
        let mut heap = std::collections::BinaryHeap::new();
        heap.try_reserve_exact(records).ok()?;
        self.prefixes.try_reserve_exact(total).ok()?;
        self.ids.try_reserve_exact(total).ok()?;
        self.roots.try_reserve_exact(records).ok()?;
        self.pending
            .try_reserve_exact(index.claude_usage_family_pending.len())
            .ok()?;
        for (key, record) in index.claude_request_census.records() {
            let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
                continue;
            };
            if !index.claude_usage_family_pending.contains_key(member.root)
                && record.retired().is_none()
                && !record.request_hashes().is_empty()
            {
                roots.push(member.root);
            }
        }
        roots.sort_unstable();
        roots.dedup();
        self.roots
            .extend(roots.iter().map(|root| (*root).to_owned()));
        self.pending
            .extend(index.claude_usage_family_pending.keys().cloned());
        for (key, record) in index.claude_request_census.records() {
            let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
                continue;
            };
            if index.claude_usage_family_pending.contains_key(member.root)
                || record.retired().is_some()
                || record.request_hashes().is_empty()
            {
                continue;
            }
            let id = u32::try_from(roots.binary_search(&member.root).ok()?).ok()?;
            sources.push((record.request_hashes(), id));
        }
        for (at, (hashes, _)) in sources.iter().enumerate() {
            heap.push(std::cmp::Reverse((hashes[0], at, 0_usize)));
        }
        while let Some(std::cmp::Reverse((prefix, at, position))) = heap.pop() {
            let (hashes, id) = sources[at];
            if self.prefixes.last() != Some(&prefix) || self.ids.last() != Some(&id) {
                self.prefixes.push(prefix);
                self.ids.push(id);
            }
            if let Some(next) = hashes.get(position + 1) {
                heap.push(std::cmp::Reverse((*next, at, position + 1)));
            }
        }
        self.bytes = self
            .prefixes
            .capacity()
            .checked_mul(8)?
            .checked_add(self.ids.capacity().checked_mul(4)?)?
            .checked_add(
                self.roots
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())?,
            )?
            .checked_add(
                self.pending
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())?,
            )?
            .checked_add(
                self.roots
                    .iter()
                    .chain(&self.pending)
                    .try_fold(0_usize, |n, root| n.checked_add(root.capacity()))?,
            )?
            .checked_add(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())?;
        (self.bytes <= budget).then_some(())
    }

    /// Retained bytes, for the overlap budget of a build beside this one.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn unknown(&self) -> bool {
        self.unknown
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.prefixes.len()
    }

    /// A root excluded at build time has since lost its usage pending.
    pub(crate) fn stale(&self, index: &ScanIndex) -> bool {
        self.pending
            .iter()
            .any(|root| !index.claude_usage_family_pending.contains_key(root))
    }

    /// Whether a pending-free root other than `family_root` holds any of
    /// `prefixes` (`claude_request_hash` values).
    pub(crate) fn verdict(
        &self,
        family_root: &str,
        prefixes: impl IntoIterator<Item = u64>,
    ) -> CensusPrefixVerdict {
        if self.unknown {
            return CensusPrefixVerdict::Unknown;
        }
        for prefix in prefixes {
            let from = self.prefixes.partition_point(|hash| *hash < prefix);
            if self.prefixes[from..]
                .iter()
                .zip(&self.ids[from..])
                .take_while(|(hash, _)| **hash == prefix)
                .any(|(_, id)| self.roots[*id as usize] != family_root)
            {
                return CensusPrefixVerdict::Held;
            }
        }
        CensusPrefixVerdict::Clear
    }

    /// As [`Self::verdict`] for 64-hex pending request hashes.
    pub(crate) fn verdict_hex<'a>(
        &self,
        family_root: &str,
        hashes: impl IntoIterator<Item = &'a String>,
    ) -> CensusPrefixVerdict {
        self.verdict(
            family_root,
            hashes
                .into_iter()
                .filter_map(|hash| pending_hash_prefix(hash)),
        )
    }
}

/// A pending request hash (`format!("{:x}", Sha256::digest(id))`) as the
/// census's `claude_request_hash`: its first 16 hex digits.
pub(crate) fn pending_hash_prefix(hash: &str) -> Option<u64> {
    u64::from_str_radix(hash.get(..16)?, 16).ok()
}

/// The index for this pass: the cached one while still current, or a fresh
/// build (not cached).
pub(crate) fn current(index: &ScanIndex) -> Arc<CensusPrefixIndex> {
    match index.usage_guard_census_prefix() {
        Some(built) if !built.stale(index) => built,
        _ => build_shared(index),
    }
}

/// E7-3 copy-dependency API (account retirement, on its own branch): may
/// `family_root`'s requests (`claude_request_hash` prefixes, as account
/// pending keeps them) be copies of a pending-free family the census still
/// remembers? `Held` is a veto: keep the family's evidence. `Unknown` is a
/// hold: decide nothing. Only `Clear` answers no. Never a reason to count,
/// carry or re-arm; a prefix collision only over-vetoes.
// E7-3 calls this from its own branch; nothing here does yet.
#[allow(dead_code)]
pub(crate) fn census_prefix_verdict(
    index: &ScanIndex,
    family_root: &str,
    prefixes: impl IntoIterator<Item = u64>,
) -> CensusPrefixVerdict {
    current(index).verdict(family_root, prefixes)
}

impl ScanIndex {
    /// The index for this fold, kept in runtime custody: rebuilt once per
    /// complete pass, and otherwise only when none was built for this census
    /// window or a root it excluded has lost its usage pending. An
    /// overflowed index makes the hold projection global (B3 Unknown).
    pub(super) fn refresh_claude_census_prefix(
        &mut self,
        census_window_end: &str,
        census_complete: bool,
    ) -> Arc<CensusPrefixIndex> {
        if let Some(built) = self.usage_guard_census_prefix_for(census_window_end, census_complete)
        {
            if !built.stale(self) {
                return built;
            }
        }
        // Drop the working/custody owners. The allocation registry still charges
        // every surviving baseline or caller, including older generations.
        self.usage_guard_drop_census_prefix();
        let built = build_shared(self);
        self.usage_guard_set_census_prefix(census_window_end, census_complete, built.clone());
        built
    }
}

/// Request hashes of this page and of current-window pending that a
/// pending-free root's census record also holds: duplicated, veto only.
pub(super) fn duplicated_pending_hashes(
    index: &ScanIndex,
    prefixes: &CensusPrefixIndex,
    census_window_end: &str,
    items: &[SnapshotItem],
) -> Vec<String> {
    let mut hits = Vec::new();
    if prefixes.unknown() {
        return hits;
    }
    for (root, pending) in &index.claude_usage_family_pending {
        if pending.census_window_end != census_window_end {
            continue;
        }
        for hash in pending
            .membership()
            .values()
            .flat_map(|hashes| hashes.iter())
        {
            if prefixes.verdict_hex(root, std::iter::once(hash)) == CensusPrefixVerdict::Held {
                hits.push(hash.clone());
            }
        }
    }
    for item in items {
        let root = claude_snapshot_family_root(item);
        for request_id in &item.claude_usage_request_ids {
            let hash = format!("{:x}", Sha256::digest(request_id.as_bytes()));
            if prefixes.verdict_hex(&root, std::iter::once(&hash)) == CensusPrefixVerdict::Held {
                hits.push(hash);
            }
        }
    }
    hits.sort_unstable();
    hits.dedup();
    if !hits.is_empty() {
        crate::local_resource_diagnostics::traversal_point(
            "claude_census_prefix_veto",
            SnapshotSource::ClaudeCode.api_slug(),
            &json!({"census_prefix_vetoed_hashes":hits.len()}),
        );
    }
    hits
}

/// Carried stale roots the census-prefix veto keeps from every carry route
/// (ordinary, streaming, batched): a root whose pending requests a
/// pending-free root's live census record also holds, or any root while the
/// index is Unknown. Veto only.
pub(super) fn vetoed_carries<'a>(
    index: &ScanIndex,
    roots: impl IntoIterator<Item = &'a String>,
) -> BTreeSet<String> {
    let prefixes = current(index);
    roots
        .into_iter()
        .filter(|root| {
            let hashes = index
                .claude_usage_family_pending
                .get(root.as_str())
                .into_iter()
                .flat_map(|pending| pending.membership().values())
                .flat_map(|hashes| hashes.iter());
            prefixes.verdict_hex(root, hashes) != CensusPrefixVerdict::Clear
        })
        .cloned()
        .collect()
}
