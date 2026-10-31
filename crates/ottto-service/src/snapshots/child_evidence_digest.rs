//! Q-D3 page-local fingerprint view. Parsing and extraction belong to the same
//! loaders and ScanEvidence::new used by try_apply_claude_local_evidence.
use super::*;

#[derive(Default)]
pub(super) struct Page {
    enabled: bool,
    bytes_read: u64,
    lookups: u64,
    families: BTreeMap<String, (String, BTreeMap<String, String>)>,
}
impl Page {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            bytes_read: 0,
            lookups: 0,
            families: BTreeMap::new(),
        }
    }

    pub(super) fn digest(
        &mut self,
        support: Option<&Path>,
        child: &ClaudeSubagentIdentity,
    ) -> Option<String> {
        // OFF performs no sidecar I/O, allocation or extraction.
        let support = support.filter(|_| self.enabled)?;
        self.lookups += 1;
        let root = &child.root_session_id;
        let (common, members) = self.families.entry(root.clone()).or_insert_with(|| {
            // Reuse the loaders' actual-byte allowance receipts, with their
            // ordinary per-file cap, rather than estimating stat lengths.
            let budget =
                crate::claude_local_otel::strict_budget::StrictReadBudget::new(64 * 1024 * 1024);
            let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
                support,
                [root.clone()],
            );
            self.bytes_read += budget.consumed();
            drop(budget);
            let budget =
                crate::claude_local_otel::strict_budget::StrictReadBudget::new(64 * 1024 * 1024);
            let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
                support,
                [root.clone()],
            );
            self.bytes_read += budget.consumed();
            drop(budget);
            let unhealthy = if api.health.is_complete() && trace.is_complete() {
                BTreeSet::new()
            } else {
                BTreeSet::from([root.clone()])
            };
            // This is the authoritative request/identity extraction, not a
            // second interpretation of sidecar JSON or trace ownership.
            claude_request_identity::ScanEvidence::new(&api, &trace, unhealthy, None)
                .child_sidecar_fingerprints(root)
        });
        let member = format!("{root}_{}", child.file_stem);
        Some(sha256_hex(&[
            "claude_child_consumed_sidecars:v1",
            common,
            members.get(&member).map(String::as_str).unwrap_or(""),
        ]))
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        if self.enabled && self.lookups > 0 {
            eprintln!(
                "claude_child_evidence_digest families={} lookups={} bytes_read={}",
                self.families.len(),
                self.lookups,
                self.bytes_read
            );
        }
    }
}
crate::heap_layout_bound::fields!(Page; enabled, bytes_read, lookups, families);

#[cfg(test)]
mod tests;
