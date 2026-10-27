//! Scheduling only: one Claude Full above the former 256 MiB cap per pass.
//! Pending paths remain census debt; this module never installs proof.
use super::*;

const LARGE_FULL_BYTES: u64 = 256 * 1024 * 1024;

pub(super) fn is_large(candidate: &CandidateFile) -> bool {
    candidate.size_bytes > LARGE_FULL_BYTES
}

pub(super) fn select_deferred(
    debt: &mut VecDeque<String>,
    pending: &mut VecDeque<ScanTraversalPath>,
    selected: &mut Vec<ScanTraversalPath>,
    limit: usize,
    discovery_done: bool,
) {
    // Inspect the prior FIFO once. Missing paths lose scheduling priority,
    // never an index entry, audit obligation or absence/completeness fence.
    for _ in 0..debt.len() {
        let key = debt.pop_front().expect("FIFO length");
        if let Some(position) = pending.iter().position(|path| path.path == Path::new(&key)) {
            if selected.len() < limit {
                selected.push(pending.remove(position).expect("pending position"));
            }
            debt.push_back(key);
        } else if !discovery_done {
            // Not discovered yet in this walk. Preserve its older turn without
            // injecting a path or authorizing a read before native discovery.
            debt.push_back(key);
        }
    }
}

pub(super) fn admit(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    full: bool,
    started: &mut bool,
) -> bool {
    let key = local_index_key(&candidate.path);
    if full && is_large(candidate) {
        if *started {
            let traversal = index.traversal.as_mut().expect("active Claude traversal");
            if let Some(pending) = traversal
                .pending_candidates
                .iter_mut()
                .find(|pending| pending.path == candidate.path)
            {
                pending.census_member = true;
            } else {
                traversal.pending_candidates.push_back(ScanTraversalPath {
                    scan_root: candidate.scan_root.clone(),
                    path: candidate.path.clone(),
                    // Even a previously processed hinted/audited path holds
                    // this generation open until its scheduled read happens.
                    census_member: true,
                    watcher_hint: false,
                });
            }
            if !index.claude_large_full_deferred.contains(&key) {
                index.claude_large_full_deferred.push_back(key);
            }
            return false;
        }
        *started = true;
    }
    index
        .claude_large_full_deferred
        .retain(|deferred| deferred != &key);
    true
}
