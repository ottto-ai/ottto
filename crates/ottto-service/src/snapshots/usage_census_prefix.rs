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

fn string_bytes<'a>(strings: impl IntoIterator<Item = &'a str>) -> Option<usize> {
    strings.into_iter().try_fold(0_usize, |n, s| {
        n.checked_add(std::mem::size_of::<String>())?
            .checked_add(s.len())
    })
}

impl CensusPrefixIndex {
    /// One build within the full byte budget (no other index alive).
    pub(crate) fn build(index: &ScanIndex) -> Self {
        Self::build_within(index, budget())
    }

    /// One walk of the census, then a k-way merge of the records' already
    /// sorted hash slices straight into the two arrays (no sort scratch).
    /// Retired records (past the census horizon) contribute nothing, by the
    /// census rule. Unknown, holding nothing, when a pending-free record is
    /// over budget or the build would pass `budget` bytes.
    pub(crate) fn build_within(index: &ScanIndex, budget: usize) -> Self {
        let mut out = Self::default();
        let (mut over_budget, mut overflow) = (0_u64, 0_u64);
        let mut roots = BTreeMap::<&str, u32>::new();
        let mut sources = Vec::<(&[u64], u32)>::new();
        let mut total = 0_usize;
        for (key, record) in index.claude_request_census.records() {
            let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
                continue;
            };
            if index.claude_usage_family_pending.contains_key(member.root)
                || record.retired().is_some()
            {
                continue;
            }
            if record.over_budget() {
                // Its hashes were dropped: absence here proves nothing.
                over_budget += 1;
                continue;
            }
            let hashes = record.request_hashes();
            if hashes.is_empty() {
                continue;
            }
            let next = u32::try_from(roots.len()).unwrap_or(u32::MAX);
            let id = *roots.entry(member.root).or_insert(next);
            if sources.try_reserve(1).is_err() {
                overflow = 1;
                break;
            }
            sources.push((hashes, id));
            total = total.saturating_add(hashes.len());
        }
        // Peak bytes: both arrays, root and pending metadata, the id map and
        // the merge scratch (sources and heap).
        let entry = std::mem::size_of::<u64>() + std::mem::size_of::<u32>();
        let scratch = sources.capacity().saturating_mul(
            std::mem::size_of::<(&[u64], u32)>() + std::mem::size_of::<(u64, usize, usize)>(),
        );
        let peak = total
            .checked_mul(entry)
            .zip(string_bytes(roots.keys().copied()))
            .zip(string_bytes(
                index.claude_usage_family_pending.keys().map(String::as_str),
            ))
            .and_then(|((arrays, roots_bytes), pending_bytes)| {
                arrays
                    .checked_add(roots_bytes.checked_mul(3)?)?
                    .checked_add(pending_bytes)?
                    .checked_add(scratch)
            });
        if over_budget == 0 && overflow == 0 && peak.is_some_and(|peak| peak <= budget) {
            overflow = u64::from(out.fill(index, &roots, &sources, total).is_none());
        } else if over_budget == 0 {
            overflow = 1;
        }
        if over_budget != 0 || overflow != 0 {
            // Never a partial answer: an Unknown index holds nothing.
            out = Self {
                unknown: true,
                ..Self::default()
            };
        }
        crate::local_resource_diagnostics::traversal_point(
            "claude_census_prefix_veto",
            SnapshotSource::ClaudeCode.api_slug(),
            &json!({"census_prefix_records":sources.len(),"census_prefix_entries":out.prefixes.len(),
                "census_prefix_bytes":out.bytes,
                "census_prefix_over_budget_records":over_budget,"census_prefix_overflow":overflow,
                "census_prefix_unknown":u64::from(out.unknown)}),
        );
        out
    }

    fn fill(
        &mut self,
        index: &ScanIndex,
        roots: &BTreeMap<&str, u32>,
        sources: &[(&[u64], u32)],
        total: usize,
    ) -> Option<()> {
        self.prefixes.try_reserve_exact(total).ok()?;
        self.ids.try_reserve_exact(total).ok()?;
        self.roots.try_reserve_exact(roots.len()).ok()?;
        self.roots.resize(roots.len(), String::new());
        for (root, id) in roots {
            self.roots[*id as usize] = (*root).to_owned();
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(index.claude_usage_family_pending.len())
            .ok()?;
        pending.extend(index.claude_usage_family_pending.keys().cloned());
        self.pending = pending;
        let mut heap = std::collections::BinaryHeap::new();
        heap.try_reserve_exact(sources.len()).ok()?;
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
            .checked_mul(std::mem::size_of::<u64>())?
            .checked_add(
                self.ids
                    .capacity()
                    .checked_mul(std::mem::size_of::<u32>())?,
            )?
            .checked_add(string_bytes(self.roots.iter().map(String::as_str))?)?
            .checked_add(string_bytes(self.pending.iter().map(String::as_str))?)?;
        Some(())
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
    let cached = index.usage_guard_census_prefix();
    match cached {
        Some(built) if !built.stale(index) => built,
        // A stale cached index stays alive beside this build: budget both.
        cached => Arc::new(CensusPrefixIndex::build_within(
            index,
            budget().saturating_sub(cached.map_or(0, |built| built.bytes())),
        )),
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
        // Release the old index (and its process-custody copy) first, so a
        // rebuild never holds two within the byte budget.
        self.usage_guard_drop_census_prefix();
        let built = Arc::new(CensusPrefixIndex::build(self));
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
