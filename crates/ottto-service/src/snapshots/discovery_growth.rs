//! Diagnostic observations of the existing bounded discovery page, not an
//! owed-key ledger. Dropping this scratch never changes retention or retry.
//! The saved index is the only authority for whether observed growth committed.
use super::*;

// Diagnostic admission is smaller than the ordinary discovery tick. A diagnostic overflow does
// not cap retention: disclose incomplete coverage rather than add a census.
const MAX_OBSERVATIONS: usize = 4_096;

#[derive(Clone, Copy, Debug)]
struct Observation {
    len: u64,
    modified: u64,
    stamp: Option<codex_fragment::Stamp>,
}
crate::heap_layout_bound::fields!(Observation; len, modified, stamp);

#[derive(Clone, Debug, Default)]
struct State {
    observations: BTreeMap<String, Observation>,
    key_bytes: usize,
    overflow: u64,
}
#[derive(Debug, Default)]
pub(crate) struct Page(Mutex<State>);
impl Clone for Page {
    fn clone(&self) -> Self {
        Self(Mutex::new(self.state().clone()))
    }
}
impl Page {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // Diagnostic scratch has no selection authority. Recover its counts;
        // never do filesystem I/O or emission while holding this lock.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for Page {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let state = self.state();
        // Inline values own no heap; key capacities are recorded at admission.
        // Constant-time accounting keeps this scratch out of per-line walks.
        crate::heap_layout_bound::tree_nodes::<String, Observation>(state.observations.len(), c)?;
        c.add(state.key_bytes)
    }
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Fate {
    pub(crate) committed: u64,
    pub(crate) still_retained: u64,
    /// No saved entry remains: do not invent either a commit or live growth.
    pub(crate) unindexed: u64,
}
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Age {
    pub(crate) le_30d: u64,
    pub(crate) d31_90: u64,
    pub(crate) gt_90d: u64,
    pub(crate) unknown: u64,
}
#[derive(Debug, Default, Serialize)]
pub(crate) struct Counts {
    pub(crate) discovery_retained_grown_fate: Fate,
    /// Current age estimate of still-retained observations, not elapsed time
    /// in retention. Uses last available file mtime and the save's wall clock.
    pub(crate) discovery_retained_grown_age: Age,
    /// Repeated gate observations refused diagnostic scratch admission;
    /// not unique keys. Nonzero means this page's population is incomplete.
    pub(crate) observation_overflow: u64,
}
impl Page {
    #[cfg(test)]
    pub(super) fn observe(&self, key: String, len: u64, modified: u64) {
        self.observe_stamped(key, len, modified, None);
    }
    pub(super) fn observe_stamped(
        &self,
        key: String,
        len: u64,
        modified: u64,
        stamp: Option<codex_fragment::Stamp>,
    ) {
        let mut state = self.state();
        if !state.observations.contains_key(&key) {
            if state.observations.len() == MAX_OBSERVATIONS {
                state.overflow = state.overflow.saturating_add(1);
                return;
            }
            let Some(key_bytes) = state.key_bytes.checked_add(key.capacity()) else {
                state.overflow = state.overflow.saturating_add(1);
                return;
            };
            state.key_bytes = key_bytes;
        }
        // BTreeMap keeps the original stored key on replacement, so its
        // charged capacity stays valid. Repeated gates get one fate per page.
        state.observations.insert(
            key,
            Observation {
                len,
                modified,
                stamp,
            },
        );
    }

    pub(super) fn counts(&self, index: &ScanIndex, now: u64) -> Counts {
        let state = self.state();
        let mut counts = Counts {
            observation_overflow: state.overflow,
            ..Counts::default()
        };
        for (key, observed) in &state.observations {
            let Some(entry) = index.files.get(key) else {
                counts.discovery_retained_grown_fate.unindexed += 1;
                continue;
            };
            // A newly sealed prefix can leave only the already-observed
            // fragment. It is neither outstanding grown usage nor age credit.
            if entry.codex_fragment.as_ref().is_some_and(|fragment| {
                fragment.matches(entry.size_bytes, observed.len, observed.stamp)
            }) {
                continue;
            }
            if entry.size_bytes >= observed.len {
                counts.discovery_retained_grown_fate.committed += 1;
                continue;
            }
            counts.discovery_retained_grown_fate.still_retained += 1;
            let age = &mut counts.discovery_retained_grown_age;
            match now
                .checked_sub(observed.modified)
                .filter(|_| observed.modified != 0)
            {
                None => age.unknown += 1,
                Some(seconds) if seconds <= 30 * 86_400 => age.le_30d += 1,
                Some(seconds) if seconds <= 90 * 86_400 => age.d31_90 += 1,
                Some(_) => age.gt_90d += 1,
            }
        }
        counts
    }

    pub(super) fn report(&self, source: SnapshotSource, index: &ScanIndex) {
        let observed = {
            let state = self.state();
            !state.observations.is_empty() || state.overflow != 0
        };
        if observed {
            crate::local_resource_diagnostics::discovery_growth_fate(
                source.api_slug(),
                &self.counts(index, sampled_scan::now_seconds()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_age_is_recomputed_at_save_and_fates_follow_selected_extent() {
        let now = 200 * 86_400;
        let page = Page::default();
        let mut index = ScanIndex::default();
        for (key, age) in [("a", 30), ("b", 31), ("c", 90), ("d", 91)] {
            let mut entry = super::super::tests::manifest_index_entry(None);
            entry.size_bytes = 1;
            index.files.insert(key.into(), entry);
            page.observe(key.into(), 2, now - age * 86_400);
            page.observe(key.into(), 2, now - age * 86_400); // gate dedup
        }
        let count = page.counts(&index, now);
        assert_eq!(count.discovery_retained_grown_fate.still_retained, 4);
        assert_eq!(
            count.discovery_retained_grown_age,
            Age {
                le_30d: 1,
                d31_90: 2,
                gt_90d: 1,
                unknown: 0
            }
        );
        let count = page.counts(&index, now + 86_400);
        assert_eq!(
            count.discovery_retained_grown_age,
            Age {
                le_30d: 0,
                d31_90: 2,
                gt_90d: 2,
                unknown: 0
            }
        );
        index.files.get_mut("a").unwrap().size_bytes = 2;
        index.files.remove("b");
        let count = page.counts(&index, now);
        assert_eq!(
            count.discovery_retained_grown_fate,
            Fate {
                committed: 1,
                still_retained: 2,
                unindexed: 1
            }
        );
        assert_eq!(count.discovery_retained_grown_age.d31_90, 1);
        assert_eq!(count.discovery_retained_grown_age.gt_90d, 1);
        // Missing/future metadata is explicitly unknown, never old or zero-age.
        page.observe("c".into(), 2, 0);
        page.observe("d".into(), 2, now + 1);
        assert_eq!(
            page.counts(&index, now)
                .discovery_retained_grown_age
                .unknown,
            2
        );
    }

    #[test]
    fn scratch_admission_is_bounded_and_never_changes_discovery_retention() {
        let page = Page::default();
        for n in 0..MAX_OBSERVATIONS {
            page.observe(n.to_string(), 2, 1);
        }
        page.observe("overflow".into(), 2, 1);
        assert_eq!(page.state().observations.len(), MAX_OBSERVATIONS);
        assert_eq!(page.state().overflow, 1);
        let mut index = ScanIndex::default();
        let mut entry = super::super::tests::manifest_index_entry(None);
        entry.size_bytes = 1;
        index.files.insert("overflow".into(), entry);
        assert!(discovery_retention!(index, &page).owes_with_len(
            SnapshotSource::Pi,
            Path::new("overflow"),
            2
        ));
        // An admitted key remains updateable even at the scratch cap.
        page.observe("0".into(), 3, 2);
        assert_eq!(page.state().observations["0"].len, 3);
        // Admit the whole diagnostic cap without exhausting the owner's
        // 4096-visit counter or walking keys in a per-line measurement.
        use crate::heap_layout_bound::HeapLayoutBound;
        let mut counter = crate::heap_layout_bound::Counter::new(usize::MAX);
        page.heap_bound(&mut counter).unwrap();
        assert!(counter.visits_for_test() <= 2);
        assert!(counter.bytes >= page.state().key_bytes);
        assert!(
            counter.bytes < 8 * 1024 * 1024,
            "scratch fits below frame parking budget"
        );
        let state = page.state();
        assert_eq!(
            state.key_bytes,
            state
                .observations
                .keys()
                .map(String::capacity)
                .sum::<usize>()
        );
    }
}
