// Nonshipping, thread-scoped candidate controls for actual scanner/checkpoint
// boundary tests. Absent from production binaries; inactive for other tests.
use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Family {
    paths: BTreeSet<PathBuf>,
    successful_deferrals: usize,
    disabled: bool,
}
#[derive(Default, Clone, Copy, Debug)]
pub(crate) struct Counts {
    pub successful_deferrals: usize,
    pub unavailable: usize,
    pub base_exits: usize,
    pub unknown_age: usize,
    pub rearm_suppressed: usize,
    pub rearm_base_bypasses: usize,
}
#[derive(Default)]
struct State {
    permit: bool,
    unknown_age_seen: bool,
    families: BTreeMap<String, Family>,
    withheld: BTreeSet<String>,
    certified_negative_keys: BTreeSet<String>,
    counts: Counts,
}
thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

pub(crate) struct Scope(Option<State>);
impl Scope {
    pub(crate) fn controlled() -> Self {
        Self(STATE.with(|state| {
            state.replace(Some(State {
                permit: true,
                ..Default::default()
            }))
        }))
    }
    pub(crate) fn restart() -> Self {
        Self(STATE.with(|state| state.replace(Some(State::default()))))
    }
    pub(crate) fn register(&self, family: &str, paths: BTreeSet<PathBuf>) {
        STATE.with(|state| {
            // Re-registering a newer proof/census cannot renew this process's
            // disabled family or reset its successful-attempt count.
            state
                .borrow_mut()
                .as_mut()
                .unwrap()
                .families
                .entry(family.to_string())
                .or_default()
                .paths
                .extend(paths);
        });
    }
    // Tests mint this only from frozen retained-P reconstruction, exact native
    // digests, normal Skip and a negative comparison. No production caller.
    pub(crate) fn certify_negative(&self, key: String) {
        STATE.with(|state| {
            state
                .borrow_mut()
                .as_mut()
                .unwrap()
                .certified_negative_keys
                .insert(key);
        });
    }
    pub(crate) fn withhold(&self, paths: BTreeSet<String>) {
        STATE.with(|state| state.borrow_mut().as_mut().unwrap().withheld = paths);
    }
    pub(crate) fn allowed(&self, family: &str) -> bool {
        STATE.with(|state| {
            let state = state.borrow();
            let state = state.as_ref().unwrap();
            state.permit
                && state
                    .families
                    .get(family)
                    .is_some_and(|family| !family.disabled)
        })
    }
    pub(crate) fn counts(&self) -> Counts {
        STATE.with(|state| state.borrow().as_ref().unwrap().counts)
    }
    pub(crate) fn defer_after_native(&self, family: &str, scan: &SourceScanResult) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let state = state.as_mut().unwrap();
            let target = state.families.get_mut(family).unwrap();
            let fully_read = target.paths.iter().all(|path| {
                scan.pending_finalization.iter().any(|pending| {
                    pending.index_key == local_index_key(path) && pending.parse_complete
                })
            });
            if !fully_read
                || scan.unreadable_path_count > 0
                || scan.disappeared_file_count > 0
                || scan.invalid_utf8_line_count > 0
                || scan.malformed_json_line_count > 0
            {
                state.counts.unavailable += 1;
                state.permit = false;
                // Failed reads never earn a successful eligible attempt.
                return;
            }
            if target.disabled {
                return;
            }
            target.successful_deferrals += 1;
            state.counts.successful_deferrals += 1;
            if target.successful_deferrals >= 2 {
                target.disabled = true;
                state.permit = false;
                state.counts.base_exits += 1;
            }
        });
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        STATE.with(|state| {
            state.replace(self.0.take());
        });
    }
}

// Used at the real proof-rearm branch, not just a policy assertion. Other
// rearm reasons (changed owner, invalid witness, global fence) remain intact.
pub(super) fn suppress_certified_negative_rearm(root: &str, key: &str) -> bool {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return false;
        };
        if !state.certified_negative_keys.contains(key) {
            return false;
        }
        let Some(family) = state.families.get(root) else {
            return false;
        };
        if !family.paths.contains(Path::new(key)) {
            return false;
        }
        if state.permit && !family.disabled {
            state.counts.rearm_suppressed += 1;
            true
        } else {
            state.counts.rearm_base_bypasses += 1;
            false
        }
    })
}

pub(super) fn before_audit_selection(
    source: SnapshotSource,
    queue: &mut VecDeque<ScanTraversalPath>,
    selected: &mut Vec<ScanTraversalPath>,
    files: &mut BTreeMap<String, ScanIndexEntry>,
    limit: usize,
) {
    if source != SnapshotSource::ClaudeCode || limit == 0 {
        return;
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return;
        };
        let mut targets = BTreeSet::new();
        for family in state.families.values_mut() {
            if family.paths.len() > limit && !family.disabled {
                family.disabled = true;
                state.permit = false;
                state.counts.base_exits += 1;
                for path in &family.paths {
                    if let Some(entry) = files.get_mut(&local_index_key(path)) {
                        entry.source_file_fingerprint.clear();
                    }
                }
            }
            targets.extend(family.paths.iter().cloned());
        }
        // A restarted test process has no eligible envelope family, but the
        // existing durable rearm still selects native work before audit work.
        while selected.len() < limit {
            let Some(position) = queue.iter().position(|candidate| {
                targets.contains(&candidate.path)
                    || files
                        .get(&local_index_key(&candidate.path))
                        .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            }) else {
                break;
            };
            if state.families.is_empty() && !state.unknown_age_seen {
                state.counts.unknown_age += 1;
                state.unknown_age_seen = true;
            }
            selected.push(queue.remove(position).unwrap());
        }
    });
}

pub(crate) fn after_selected_restore(index: &mut ScanIndex, previous: &ScanIndex) {
    STATE.with(|state| {
        let state = state.borrow();
        let Some(state) = state.as_ref() else {
            return;
        };
        for key in &state.withheld {
            match previous.files.get(key) {
                Some(entry) => {
                    index.files.insert(key.clone(), entry.clone());
                }
                None => {
                    index.files.remove(key);
                }
            }
            match previous.file_snapshot_fingerprints.get(key) {
                Some(values) => {
                    index
                        .file_snapshot_fingerprints
                        .insert(key.clone(), values.clone());
                }
                None => {
                    index.file_snapshot_fingerprints.remove(key);
                }
            }
            if previous.confirmed_empty_files.contains(key) {
                index.confirmed_empty_files.insert(key.clone());
            } else {
                index.confirmed_empty_files.remove(key);
            }
        }
        let targets = state
            .families
            .values()
            .flat_map(|family| family.paths.iter().cloned())
            .collect::<BTreeSet<_>>();
        for path in &targets {
            if let Some(entry) = index.files.get_mut(&local_index_key(path)) {
                entry.source_file_fingerprint.clear();
            }
        }
        if let Some(traversal) = index.traversal.as_mut() {
            let mut first = VecDeque::new();
            let mut rest = VecDeque::new();
            for pending in traversal.pending_candidates.drain(..) {
                if targets.contains(&pending.path) {
                    first.push_back(pending);
                } else {
                    rest.push_back(pending);
                }
            }
            // A target already consumed by this page must be queued again;
            // merely clearing its fp would wait for the rest of the sweep.
            // Only already-observed paths inside the frozen roots qualify.
            for path in &targets {
                if !first.iter().any(|pending| pending.path == *path)
                    && traversal
                        .observed_index_keys
                        .contains(&local_index_key(path))
                {
                    if let Some(scan_root) = traversal
                        .scan_roots
                        .iter()
                        .filter(|root| path.starts_with(root))
                        .max_by_key(|root| root.components().count())
                        .cloned()
                    {
                        first.push_back(ScanTraversalPath {
                            order_modified: None,
                            scan_root,
                            path: path.clone(),
                            census_member: true,
                            watcher_hint: false,
                        });
                    }
                }
            }
            first.append(&mut rest);
            traversal.pending_candidates = first;
        }
        if !state.families.is_empty() {
            index.mark_bounded_sweep_unsettled();
        }
    });
}
