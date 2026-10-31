//! Q-D3: stat-gated digests in the existing daemon-owned sampled cache.
use super::*;
use crate::heap_layout_bound::{bound, HeapLayoutBound};

const MEMO_BYTES: usize = 2 * 1024 * 1024;
type FamilyDigest = claude_family_evidence::Dependencies;
#[derive(Default)]
pub(super) struct Memo {
    families: BTreeMap<String, (String, Option<FamilyDigest>)>,
}
crate::heap_layout_bound::fields!(Memo; families);

#[derive(Clone, Copy)]
pub(crate) struct Policy<'a> {
    pub(crate) cache: &'a Arc<sampled_scan::SharedCache>,
    pub(crate) enabled: bool,
}
impl<'a> Policy<'a> {
    pub(crate) fn machine(cache: &'a Arc<sampled_scan::SharedCache>) -> Self {
        Self {
            cache,
            enabled: terminal_off_policy::child_evidence_digest(),
        }
    }
}
pub(super) struct Page {
    cache: Arc<sampled_scan::SharedCache>,
    legacy_roots: BTreeSet<String>,
}
impl Page {
    pub(super) fn new(cache: Arc<sampled_scan::SharedCache>, index: &ScanIndex) -> Self {
        Self {
            cache,
            legacy_roots: index
                .claude_account_family_witnesses
                .keys()
                .cloned()
                .collect(),
        }
    }
    pub(super) fn cache(&self) -> std::sync::Weak<sampled_scan::SharedCache> {
        Arc::downgrade(&self.cache)
    }
    pub(super) fn prune(&self, index: &ScanIndex) {
        // Wait until discovery has enumerated the walk; pruning on an early
        // page would evict unchanged families that later pages will revisit.
        let Some(walk) = index
            .traversal
            .as_ref()
            .filter(|walk| walk.pending_directories.is_empty())
        else {
            return;
        };
        let roots = walk
            .observed_index_keys
            .iter()
            .filter_map(|key| claude_index_path_family_member(Path::new(key)).map(|(root, _)| root))
            .collect::<BTreeSet<_>>();
        if let Ok(mut memo) = self.cache.child_evidence.lock() {
            if let Some(memo) = memo.as_mut() {
                memo.families.retain(|root, _| roots.contains(root));
            }
        }
    }
    pub(super) fn digest(
        &mut self,
        support: Option<&Path>,
        child: &ClaudeSubagentIdentity,
    ) -> Option<String> {
        let support = support?;
        let root = &child.root_session_id;
        let stat = claude_usage_sidecars_fingerprint(support, root);
        let member = format!("{root}_{}", child.file_stem);
        {
            let memo = self.cache.child_evidence.lock().ok()?;
            if let Some((previous, digest)) = memo.as_ref().and_then(|m| m.families.get(root)) {
                if previous == &stat {
                    return digest.as_ref().map(|digest| {
                        digest.child_digest(&member, self.legacy_roots.contains(root))
                    });
                }
            }
        }
        let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
            support,
            [root.clone()],
        );
        let trace =
            crate::claude_local_otel::load_claude_trace_ownership_evidence(support, [root.clone()]);
        let unhealthy = if api.health.is_complete() && trace.is_complete() {
            BTreeSet::new()
        } else {
            BTreeSet::from([root.clone()])
        };
        let identity = claude_request_identity::ScanEvidence::new(&api, &trace, unhealthy, None);
        let rows = api.evidence.get(root).map(Vec::as_slice).unwrap_or(&[]);
        let digest =
            claude_family_evidence::Projection::new(rows).child_dependencies(root, &identity);
        let result = Some(digest.child_digest(&member, self.legacy_roots.contains(root)));
        let mut guard = self.cache.child_evidence.lock().ok()?;
        let memo = guard.get_or_insert_with(Default::default);
        memo.families.insert(root.clone(), (stat, Some(digest)));
        while bound(&memo.families, MEMO_BYTES).is_none() {
            if let Some(victim) = memo.families.keys().find(|key| *key != root).cloned() {
                memo.families.remove(&victim);
            } else {
                // An overlarge family keeps a small stat refusal instead of
                // decoding its oversized digest for every child. Read as main.
                memo.families.get_mut(root)?.1 = None;
                return None;
            }
        }
        result
    }
}
impl HeapLayoutBound for Page {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // The daemon owner charges the shared memo; charge this page's root view.
        self.legacy_roots.heap_bound(counter)
    }
}

#[cfg(test)]
mod tests;
