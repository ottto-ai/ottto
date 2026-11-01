//! The cross-root answers of one Claude local-evidence pass, gathered root by
//! root while the strict read streams the corpus. Only the page's own roots
//! keep their rows; every other root's rows are dropped right after they are
//! added here. Each answer equals the one a pass holding every root's rows
//! gives: the same rows, the same sorted root order, the same first refusal.

use super::claude_context_file_birth::{ClaudeTelemetryTripwire, TelemetryRow};
use super::claude_request_identity::{prove_membership, unique_by_request, RequestRootIndex};
use super::{claude_earliest_request, ClaudeLegacyRequestOwners, SnapshotItem};
use crate::claude_local_otel::{
    claude_pair_generation, ClaudeLocalOtelEvidence, ClaudePairGeneration,
    ClaudeTraceOwnershipEvidence,
};
use crate::local_resource_diagnostics::claude_reread::IgnoredVeto;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type RereadPair = (
    Option<Vec<ClaudeLocalOtelEvidence>>,
    Option<Vec<ClaudeTraceOwnershipEvidence>>,
);

/// A tripwire row whose session is not its sidecar root: no single owner.
const NO_SINGLE_OWNER: u32 = u32::MAX;

/// Root ids and request digests stay in memory only: no `Debug`, never logged.
pub(crate) struct CrossRootEvidence {
    support_dir: PathBuf,
    /// Every root added, by ordinal; tripwire rows name their root this way.
    roots: Vec<String>,
    /// (a) Each healthy root's API and trace request ids, for fork and resume
    /// copies under another root.
    pub(crate) request_roots: RequestRootIndex,
    /// (b) Login to orgs, from every healthy root's intact unique rows.
    pub(crate) memberships: BTreeMap<String, BTreeSet<String>>,
    /// (c) Legacy request owners, added in sorted root order.
    pub(crate) legacy_request_owners: ClaudeLegacyRequestOwners,
    /// (d) Every loaded API (healthy or vetoing) and healthy trace row: its
    /// request hash and owner ordinal.
    tripwire_rows: Vec<(u64, u32)>,
    /// (e) Each healthy root's earliest API row time.
    earliest_requests: BTreeMap<String, u64>,
    /// Healthy roots with rows that the pass did not keep, with the pair's
    /// generation from before its read, for the terminal proof's reread.
    unkept: BTreeMap<String, Option<ClaudePairGeneration>>,
}

impl CrossRootEvidence {
    pub(crate) fn new(support_dir: &Path) -> Self {
        Self {
            support_dir: support_dir.to_path_buf(),
            roots: Vec::new(),
            request_roots: RequestRootIndex::default(),
            memberships: BTreeMap::new(),
            legacy_request_owners: ClaudeLegacyRequestOwners::default(),
            tripwire_rows: Vec::new(),
            earliest_requests: BTreeMap::new(),
            unkept: BTreeMap::new(),
        }
    }

    fn ordinal(&mut self, root: &str) -> u32 {
        let ordinal = self.roots.len() as u32;
        self.roots.push(root.to_owned());
        ordinal
    }

    /// API rows of a root whose pair is missing or unhealthy. They only veto
    /// the file birth rule (d); no other answer sees them.
    pub(crate) fn add_vetoing_api(&mut self, root: &str, api: &[ClaudeLocalOtelEvidence]) {
        let ordinal = self.ordinal(root);
        self.add_tripwire_rows(ordinal, root, api.iter().map(api_row_ids));
    }

    /// A healthy root's strict rows, where the pass would keep them. Call in
    /// sorted root order, once per root, before the root's rows are dropped.
    pub(crate) fn add_root(
        &mut self,
        root: &str,
        api: Option<&Vec<ClaudeLocalOtelEvidence>>,
        trace: Option<&Vec<ClaudeTraceOwnershipEvidence>>,
    ) {
        let ordinal = self.ordinal(root);
        let api_rows = api.map_or(&[][..], Vec::as_slice);
        let trace_rows = trace.map_or(&[][..], Vec::as_slice);
        self.request_roots.add_root(
            ordinal,
            api_rows
                .iter()
                .map(|row| row.request_id.as_str())
                .chain(trace_rows.iter().map(|row| row.request_id.as_str())),
        );
        for row in unique_by_request(api_rows).into_values().flatten() {
            prove_membership(row, root, &mut self.memberships);
        }
        if let Some(api) = api {
            self.legacy_request_owners.add_root(root, api, trace);
        }
        self.add_tripwire_rows(
            ordinal,
            root,
            api_rows
                .iter()
                .map(api_row_ids)
                .chain(trace_rows.iter().map(trace_row_ids)),
        );
        if let Some(earliest) = claude_earliest_request(api_rows) {
            self.earliest_requests.insert(root.to_owned(), earliest);
        }
    }

    /// A healthy root with rows that the pass drops: a terminal proof rereads
    /// it and requires the generation taken before this pass read it.
    pub(crate) fn note_unkept(&mut self, root: &str, generation: Option<ClaudePairGeneration>) {
        self.unkept.insert(root.to_owned(), generation);
    }

    /// Once every root is in.
    pub(crate) fn finish(&mut self) {
        self.request_roots.finish();
        self.tripwire_rows.shrink_to_fit();
    }

    fn add_tripwire_rows<'r>(
        &mut self,
        ordinal: u32,
        root: &str,
        rows: impl Iterator<Item = (&'r str, &'r str)>,
    ) {
        self.tripwire_rows
            .extend(rows.filter_map(|(session_id, request_id)| {
                let row = TelemetryRow::of(root, session_id, request_id)?;
                Some((
                    row.request_hash,
                    if row.owner.is_some() {
                        ordinal
                    } else {
                        NO_SINGLE_OWNER
                    },
                ))
            }));
    }

    pub(super) fn tripwire(
        &self,
        items: &[SnapshotItem],
        max_requests: usize,
    ) -> ClaudeTelemetryTripwire {
        ClaudeTelemetryTripwire::build_from(items, max_requests, || {
            self.tripwire_rows
                .iter()
                .map(|&(request_hash, owner)| TelemetryRow {
                    request_hash,
                    owner: (owner != NO_SINGLE_OWNER).then(|| self.roots[owner as usize].as_str()),
                })
        })
    }

    pub(super) fn earliest_request(&self, root: &str) -> Option<u64> {
        self.earliest_requests.get(root).copied()
    }

    /// The rows of a pair this pass read healthy but did not keep, read
    /// again. `Err` when the pair changed since that read: the family stays
    /// unproven this pass and is counted as a proof failure.
    pub(super) fn reread(&self, root: &str) -> Result<RereadPair, IgnoredVeto> {
        let Some(before) = self.unkept.get(root) else {
            return Ok((None, None));
        };
        let mut api = crate::claude_local_otel::load_claude_api_request_evidence_report(
            &self.support_dir,
            [root.to_owned()],
        );
        let mut trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
            &self.support_dir,
            [root.to_owned()],
        );
        let unchanged =
            before.is_some() && claude_pair_generation(&self.support_dir, root) == *before;
        if !unchanged || !api.health.is_complete() || !trace.is_complete() {
            return Err(IgnoredVeto::ProofFailure);
        }
        Ok((api.evidence.remove(root), trace.evidence.remove(root)))
    }
}

fn api_row_ids(row: &ClaudeLocalOtelEvidence) -> (&str, &str) {
    (row.session_id.as_str(), row.request_id.as_str())
}

fn trace_row_ids(row: &ClaudeTraceOwnershipEvidence) -> (&str, &str) {
    (row.session_id.as_str(), row.request_id.as_str())
}
