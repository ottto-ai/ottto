//! Runtime census-prefix veto (Lead B round 8). Once a family's usage pending
//! is retired, its request ids survive only as the request census's 8-byte
//! prefixes. This runtime index of those prefixes, for Claude roots with NO
//! usage pending, lets a later untagged copy of such a family still meet a
//! negative scheduling veto. Nothing is persisted: retention is the census
//! rule (35 idle days, pruned when the file vanishes), inherited by deriving
//! from it. A prefix collision only over-vetoes. An index past its cap is
//! Unknown: it is a B3 hold, never a dropped hash.
use super::*;

/// Entries the index may hold: 12 bytes each, about 12.6 MB. The M4 worst
/// case is about 884k distinct requests (about 10.6 MB).
pub(crate) const CENSUS_PREFIX_MAX_ENTRIES: usize = 1_048_576;

#[cfg(test)]
thread_local! {
    static CAP_FOR_TEST: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_cap_for_test<T>(cap: usize, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CAP_FOR_TEST.with(|cell| cell.set(None));
        }
    }
    CAP_FOR_TEST.with(|cell| cell.set(Some(cap)));
    let _reset = Reset;
    run()
}

fn cap() -> usize {
    #[cfg(test)]
    if let Some(cap) = CAP_FOR_TEST.with(std::cell::Cell::get) {
        return cap;
    }
    CENSUS_PREFIX_MAX_ENTRIES
}

/// What the census says about some request prefixes of one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CensusPrefixVerdict {
    /// No other pending-free root's live census record holds any of them.
    Clear,
    /// Another root holds one: veto (a collision only over-vetoes).
    Held,
    /// The index overflowed its cap: no negative answer (B3 hold).
    Unknown,
}

/// Sorted `(claude_request_hash, root id)` of every live, hash-bearing census
/// transcript record whose root has no usage pending.
#[derive(Debug, Default)]
pub(crate) struct CensusPrefixIndex {
    entries: Vec<(u64, u32)>,
    roots: Vec<String>,
    // Roots excluded for their usage pending, sorted. Once one of them has
    // none (retired, invalidated or vanished), its census belongs here and
    // the index is stale.
    pending: Vec<String>,
    unknown: bool,
}
crate::heap_layout_bound::fields!(CensusPrefixIndex; entries, roots, pending, unknown);

impl CensusPrefixIndex {
    /// One walk of the census. Retired records (past the census horizon)
    /// contribute nothing, by the census rule. Over-budget records hold no
    /// hashes and are counted; the money path discloses the same residual.
    pub(crate) fn build(index: &ScanIndex) -> Self {
        let cap = cap();
        let mut out = Self {
            pending: index.claude_usage_family_pending.keys().cloned().collect(),
            ..Self::default()
        };
        let mut ids = BTreeMap::<&str, u32>::new();
        let (mut records, mut over_budget, mut overflow) = (0_u64, 0_u64, 0_u64);
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
                over_budget += 1;
                continue;
            }
            let hashes = record.request_hashes();
            if hashes.is_empty() {
                continue;
            }
            if out.entries.len().saturating_add(hashes.len()) > cap
                || out.entries.try_reserve(hashes.len()).is_err()
            {
                overflow = 1;
                out.unknown = true;
                break;
            }
            let next = u32::try_from(out.roots.len()).unwrap_or(u32::MAX);
            let id = *ids.entry(member.root).or_insert_with(|| {
                out.roots.push(member.root.to_owned());
                next
            });
            out.entries.extend(hashes.iter().map(|hash| (*hash, id)));
            records += 1;
        }
        if out.unknown {
            // Never a partial answer: an overflowed index holds nothing.
            out.entries = Vec::new();
            out.roots = Vec::new();
        }
        out.entries.sort_unstable();
        out.entries.dedup();
        crate::local_resource_diagnostics::traversal_point(
            "claude_census_prefix_veto",
            SnapshotSource::ClaudeCode.api_slug(),
            &json!({"census_prefix_records":records,"census_prefix_entries":out.entries.len(),
                "census_prefix_over_budget_records":over_budget,"census_prefix_overflow":overflow}),
        );
        out
    }

    pub(crate) fn unknown(&self) -> bool {
        self.unknown
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
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
            let from = self.entries.partition_point(|(hash, _)| *hash < prefix);
            if self.entries[from..]
                .iter()
                .take_while(|(hash, _)| *hash == prefix)
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
    index
        .usage_guard_census_prefix()
        .filter(|built| !built.stale(index))
        .unwrap_or_else(|| Arc::new(CensusPrefixIndex::build(index)))
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
