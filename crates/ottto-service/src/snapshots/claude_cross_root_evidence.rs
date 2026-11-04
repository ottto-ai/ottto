//! The cross-root answers of one Claude local-evidence pass, gathered root by
//! root while the strict read streams the pass's scope. Only the page's own
//! roots keep their rows; every other root's rows are dropped right after they
//! are added here. Each answer equals the one a pass holding every scope
//! root's rows gives: the same rows, the same sorted root order, the same
//! first refusal.

use super::claude_context_file_birth::{ClaudeTelemetryTripwire, TelemetryRow};
use super::claude_request_census::claude_request_hash;
use super::{ClaudeLegacyRequestOwners, ScanIndex, SnapshotItem};
use crate::claude_local_otel::{ClaudeLocalOtelEvidence, ClaudeTraceOwnershipEvidence};
use std::collections::{BTreeMap, BTreeSet};

/// A tripwire row whose session is not its sidecar root: no single owner.
const NO_SINGLE_OWNER: u32 = u32::MAX;

/// Exact ownership answers for this page's demand, rebuilt every evidence pass.
/// `None`: absent; `Some(Some(root))`: one root; `Some(None)`: several roots.
/// Request strings stay local and ephemeral: no `Debug` or serialization.
pub(crate) struct RequestRootJoins(BTreeMap<String, Option<Option<u32>>>);

impl RequestRootJoins {
    pub(crate) fn new<'r>(requests: impl Iterator<Item = &'r String>) -> Self {
        Self(requests.map(|id| (id.clone(), None)).collect())
    }

    /// Probe the diagnostic sets already built by the strict reader. API and
    /// trace hits are one claim per root, regardless of duplicate rows. Walks
    /// the smaller side, so a pass costs at most its rows, not roots × demand.
    pub(crate) fn add_root(&mut self, root: u32, api: &BTreeSet<&str>, trace: &BTreeSet<&str>) {
        let claim = |answer: &mut Option<Option<u32>>| {
            *answer = Some(match answer {
                None => Some(root),
                Some(_) => None,
            });
        };
        if api.len() + trace.len() < self.0.len() {
            // `union` yields each id once: one claim per root.
            for id in api.union(trace) {
                if let Some(answer) = self.0.get_mut(*id) {
                    claim(answer);
                }
            }
        } else {
            for (id, answer) in &mut self.0 {
                if api.contains(id.as_str()) || trace.contains(id.as_str()) {
                    claim(answer);
                }
            }
        }
    }

    /// Demanded request ids, for the cross-root stage record.
    pub(crate) fn demand_count(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn get(&self, request: &str) -> Option<Option<u32>> {
        // Whole-vs-streamed fixtures exercise every missing-local-row caller.
        #[cfg(test)]
        assert!(self.0.contains_key(request), "request outside page demand");
        self.0.get(request).copied().unwrap_or(Some(None))
    }
}

/// The roots one pass reads side files for, and which other sessions own a
/// page request. Root ids stay in memory only: no `Debug`, never logged.
#[derive(Default)]
pub(crate) struct EvidenceScope {
    roots: BTreeSet<String>,
    /// Census hash of a page request without an own API row: the sessions
    /// whose MAIN transcript holds it.
    holders: BTreeMap<u64, BTreeSet<String>>,
    /// Page root: the sessions its files' `fork-context-ref` lines name.
    parents: BTreeMap<String, BTreeSet<String>>,
}

impl EvidenceScope {
    /// Each page file's named fork parent, by the file's family root.
    pub(crate) fn fork_parents(items: &[SnapshotItem]) -> Vec<(String, String)> {
        items
            .iter()
            .filter_map(|item| {
                let parent = item.claude_money.as_deref()?.fork_parent()?;
                Some((
                    super::claude_snapshot_family_root_ref(item).to_owned(),
                    parent.to_owned(),
                ))
            })
            .collect()
    }

    /// `kept`: the page's own roots, read with their witnesses' legacy owners
    /// and named fork parents. `api`: the page's API read, by root. One census
    /// walk over every folder, with no deadline (in memory, no I/O), adds the
    /// holders of the page requests that have no API row of their own.
    pub(crate) fn of_page(
        items: &[SnapshotItem],
        index: &ScanIndex,
        kept: &BTreeSet<String>,
        fork_parents: Vec<(String, String)>,
        api: &BTreeMap<String, Vec<ClaudeLocalOtelEvidence>>,
    ) -> Self {
        let mut scope = Self {
            roots: kept.clone(),
            ..Self::default()
        };
        scope.roots.extend(
            kept.iter()
                .filter_map(|root| index.claude_usage_family_witnesses.get(root))
                .flat_map(|witness| witness.legacy_owner_roots.iter().cloned()),
        );
        for (root, parent) in fork_parents {
            scope.roots.insert(parent.clone());
            scope.parents.entry(root).or_default().insert(parent);
        }
        let own = api
            .iter()
            .flat_map(|(root, rows)| {
                rows.iter()
                    .map(move |row| (root.as_str(), row.request_id.as_str()))
            })
            .collect::<BTreeSet<_>>();
        let own = &own;
        let mut wanted = items
            .iter()
            .flat_map(|item| {
                let root = super::claude_snapshot_family_root_ref(item);
                super::claude_request_money::e2::item_request_ids(item)
                    .filter(move |id| !own.contains(&(root, id.as_str())))
                    .map(|id| claude_request_hash(id))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        wanted.sort_unstable();
        wanted.dedup();
        let holders = &mut scope.holders;
        let complete = index.claude_request_census.main_transcript_holders(
            None,
            &wanted,
            None,
            |_, holder, _, hits| {
                for &hash in hits {
                    holders.entry(hash).or_default().insert(holder.to_owned());
                }
            },
        );
        debug_assert!(complete.is_some(), "a walk without a deadline completes");
        scope
            .roots
            .extend(scope.holders.values().flatten().cloned());
        scope
    }

    /// The test reference: the given roots, as a pass over every side-file
    /// root would read them.
    #[cfg(test)]
    pub(crate) fn every(roots: impl IntoIterator<Item = String>) -> Self {
        Self {
            roots: roots.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Every root to read, in sorted order.
    pub(crate) fn roots(&self) -> impl Iterator<Item = &String> {
        self.roots.iter()
    }
}

/// Root ids and request strings stay in memory only: no `Debug`, never logged.
pub(crate) struct CrossRootEvidence {
    /// The roots this pass reads and the owners it names.
    scope: EvidenceScope,
    /// Every root added, by ordinal; tripwire rows name their root this way.
    roots: Vec<String>,
    /// (a) Exact cross-root answers for the page's possible request lookups.
    pub(crate) request_roots: RequestRootJoins,
    /// (c) Legacy request owners, added in sorted root order.
    pub(crate) legacy_request_owners: ClaudeLegacyRequestOwners,
    /// (d) Every loaded API (healthy or vetoing) and healthy trace row: its
    /// request hash and owner ordinal.
    tripwire_rows: Vec<(u64, u32)>,
}

impl CrossRootEvidence {
    pub(crate) fn new(items: &[SnapshotItem], scope: EvidenceScope) -> Self {
        Self {
            scope,
            roots: Vec::new(),
            // Includes copied/excluded ids and occurrence-only keys. These
            // cover transcript grouping, reconciliation and activity inputs.
            // Reported rebuild and later side-call additions come from API
            // rows: their local row bypasses the cross-root lookup entirely.
            request_roots: RequestRootJoins::new(
                items
                    .iter()
                    .flat_map(super::claude_request_money::e2::item_request_ids),
            ),
            legacy_request_owners: ClaudeLegacyRequestOwners::default(),
            tripwire_rows: Vec::new(),
        }
    }

    /// Every census holder the scope recorded for `request_id`.
    #[cfg(test)]
    pub(crate) fn holders_for_test(&self, request_id: &str) -> Vec<String> {
        self.scope
            .holders
            .get(&claude_request_hash(request_id))
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    /// The other sessions the scope names as owners of `request_id` in a file
    /// under `root`: the census holders and the file's named fork parents.
    pub(crate) fn named_owners<'s>(
        &'s self,
        root: &'s str,
        request_id: &str,
    ) -> impl Iterator<Item = &'s String> + 's {
        self.scope
            .holders
            .get(&claude_request_hash(request_id))
            .into_iter()
            .chain(self.scope.parents.get(root))
            .flatten()
            .filter(move |owner| owner.as_str() != root)
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
        api_ids: &BTreeSet<&str>,
        trace_ids: &BTreeSet<&str>,
    ) {
        let ordinal = self.ordinal(root);
        let api_rows = api.map_or(&[][..], Vec::as_slice);
        let trace_rows = trace.map_or(&[][..], Vec::as_slice);
        self.request_roots.add_root(ordinal, api_ids, trace_ids);
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
    }

    /// Once every root is in.
    pub(crate) fn finish(&mut self) {
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
}

fn api_row_ids(row: &ClaudeLocalOtelEvidence) -> (&str, &str) {
    (row.session_id.as_str(), row.request_id.as_str())
}

fn trace_row_ids(row: &ClaudeTraceOwnershipEvidence) -> (&str, &str) {
    (row.session_id.as_str(), row.request_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::claude_context_file_birth::{
        admit_claude_file_birth_posture, ClaudeContextFileBirthCounts, ClaudeFileBirthVerdict,
        ClaudeRememberedTripwire,
    };
    use crate::snapshots::claude_request_identity::RequestRootIndex;

    /// [behaviour] Exact page joins equal the old index across API/trace
    /// overlap and shared roots, whichever side `add_root` walks; an
    /// unhealthy API row still vetoes birth.
    #[test]
    fn demand_joins_equal_index_and_preserve_tripwire() {
        let demand = ["own", "shared", "trace-only", "absent"].map(String::from);
        let pad = |prefix: &'static str| (0..16).map(move |i| format!("{prefix}-{i}"));
        // Padding demand with absent ids makes every root walk its own ids;
        // padding roots with off-page ids makes every root walk the demand.
        let padded_demand = demand.iter().cloned().chain(pad("pad")).collect::<Vec<_>>();
        let off_page = pad("off-page").collect::<Vec<_>>();
        for roots in [
            // Mixed sizes against |demand| = 4: 5, 3 and 1 ids.
            vec![
                (0, vec!["own", "shared", "off-page"], vec!["own", "shared"]),
                (1, vec!["shared"], vec!["shared", "trace-only"]),
                (2, vec!["shared"], vec![]),
            ],
            // Root ⊃ demand.
            vec![(
                0,
                vec!["own", "shared", "trace-only", "absent", "x"],
                vec![],
            )],
            // Roots ⊂ demand, one with the same id on both sides.
            vec![
                (0, vec!["shared"], vec!["shared"]),
                (1, vec!["own"], vec![]),
            ],
            // Root size equal to |demand|.
            vec![
                (0, vec!["own", "x"], vec!["own", "shared"]),
                (1, vec!["shared", "trace-only"], vec!["absent", "own"]),
            ],
        ] {
            let mut old = RequestRootIndex::default();
            let mut joins = RequestRootJoins::new(demand.iter());
            let mut root_walk = RequestRootJoins::new(padded_demand.iter());
            let mut demand_walk = RequestRootJoins::new(demand.iter());
            for (root, api, trace) in roots {
                old.add_root(root, api.iter().chain(&trace).copied());
                let api = api.into_iter().collect::<BTreeSet<_>>();
                let trace = trace.into_iter().collect::<BTreeSet<_>>();
                joins.add_root(root, &api, &trace);
                root_walk.add_root(root, &api, &trace);
                let mut padded = api.clone();
                padded.extend(off_page.iter().map(String::as_str));
                demand_walk.add_root(root, &padded, &trace);
            }
            old.finish();
            for id in &demand {
                assert_eq!(joins.get(id), old.get(id));
                assert_eq!(root_walk.get(id), old.get(id));
                assert_eq!(demand_walk.get(id), old.get(id));
            }
            assert_eq!(joins.demand_count(), demand.len());
        }
        let root = "a0000000-0000-4000-8000-00000000000a";
        let dir = std::env::temp_dir().join(format!(
            "ottto-demand-join-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{root}.jsonl"));
        std::fs::write(
            &path,
            serde_json::json!({
                "timestamp": "2026-08-20T10:00:00Z", "type": "assistant",
                "sessionId": root, "requestId": "own",
                "message": {"id": "msg-own", "model": "claude-haiku-4-5",
                    "usage": {"input_tokens": 10, "output_tokens": 1}}
            })
            .to_string()
                + "\n",
        )
        .unwrap();
        let mut item = crate::snapshots::claude_history_upgrade::with_staged_births_for_test(
            BTreeMap::from([(
                crate::snapshots::local_index_key(&path),
                1_787_220_000_000_000_000,
            )]),
            || {
                crate::snapshots::parse_claude_code_jsonl_file(
                    &path,
                    "2026-08-20T10:02:00Z",
                    "fixture".into(),
                )
                .unwrap()
                .remove(0)
            },
        );
        let mut cross =
            CrossRootEvidence::new(std::slice::from_ref(&item), EvidenceScope::default());
        // No healthy root claims this request. The vetoing row is independent
        // of ownership demand and must not become a foreign-owner answer.
        cross.add_vetoing_api(
            "other",
            &[ClaudeLocalOtelEvidence {
                session_id: "other".into(),
                request_id: "own".into(),
                ..Default::default()
            }],
        );
        cross.finish();
        assert_eq!(cross.request_roots.get("own"), None);
        let tripwire = cross.tripwire(std::slice::from_ref(&item), 100);
        assert_eq!(
            admit_claude_file_birth_posture(
                &mut item,
                root,
                &tripwire,
                &mut ClaudeRememberedTripwire::new(100),
                false,
                &mut ClaudeContextFileBirthCounts::default(),
            ),
            ClaudeFileBirthVerdict::Tripwire
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
