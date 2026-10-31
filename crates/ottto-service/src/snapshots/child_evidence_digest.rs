//! Q-D3: stat-gated digests in the existing daemon-owned sampled cache.
use super::*;
use crate::heap_layout_bound::{bound, HeapLayoutBound};

const MEMO_BYTES: usize = 2 * 1024 * 1024;
type FamilyDigest = (String, BTreeMap<String, String>);
#[derive(Default)]
pub(super) struct Memo {
    families: BTreeMap<String, (String, Option<FamilyDigest>)>,
    reproof_window: Option<String>,
    reproof_roots: BTreeSet<String>,
}
crate::heap_layout_bound::fields!(Memo; families, reproof_window, reproof_roots);

pub(super) struct Page {
    cache: Arc<sampled_scan::SharedCache>,
    bytes_read: u64,
}
impl Page {
    pub(super) fn new(cache: Arc<sampled_scan::SharedCache>) -> Self {
        Self {
            cache,
            bytes_read: 0,
        }
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
                memo.reproof_roots.retain(|root| roots.contains(root));
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
                    return member_digest(digest.as_ref(), &member);
                }
            }
        }
        // Observe existing loader accounting; do not install a nested allowance.
        let before = crate::claude_local_otel::strict_budget::bytes_read();
        let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
            support,
            [root.clone()],
        );
        let trace =
            crate::claude_local_otel::load_claude_trace_ownership_evidence(support, [root.clone()]);
        self.bytes_read +=
            crate::claude_local_otel::strict_budget::bytes_read().saturating_sub(before);
        let unhealthy = if api.health.is_complete() && trace.is_complete() {
            BTreeSet::new()
        } else {
            BTreeSet::from([root.clone()])
        };
        let digest = claude_request_identity::ScanEvidence::new(&api, &trace, unhealthy, None)
            .child_sidecar_fingerprints(root);
        let result = member_digest(Some(&digest), &member);
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
fn member_digest(digest: Option<&FamilyDigest>, member: &str) -> Option<String> {
    let (common, members) = digest?;
    Some(sha256_hex(&[
        "claude_child_consumed_sidecars:v1",
        common,
        members.get(member).map(String::as_str).unwrap_or(""),
    ]))
}
impl HeapLayoutBound for Page {
    fn heap_bound(&self, _: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // The daemon owner charges the shared memo; this page owns no rows.
        Some(())
    }
}

/// One fail-toward-reading reproof per family in a census window. No money or
/// accepted body is removed; only the existing selection fingerprint is cleared.
pub(super) fn reproof_missing_families(
    index: &mut ScanIndex,
    window: &str,
    mut roots: BTreeSet<String>,
    cache: &sampled_scan::SharedCache,
) {
    if let Ok(mut guard) = cache.child_evidence.lock() {
        let memo = guard.get_or_insert_with(Default::default);
        if memo.reproof_window.as_deref() != Some(window) {
            memo.reproof_window = Some(window.to_owned());
            memo.reproof_roots.clear();
        }
        roots.retain(|root| memo.reproof_roots.insert(root.clone()));
    } // A poisoned memo cannot suppress the fail-toward-reading fallback.
    for (key, entry) in &mut index.files {
        if claude_index_path_family_member(Path::new(key))
            .is_some_and(|(root, _)| roots.contains(&root))
        {
            crate::local_resource_diagnostics::claude_reread::clear(
                crate::local_resource_diagnostics::claude_reread::ClearSite::AccountReproof,
                !entry.source_file_fingerprint.is_empty(),
            );
            entry.source_file_fingerprint.clear();
        }
    }
}
#[cfg(test)]
mod tests;
