//! Private, default-inactive native comparison preparation. Nothing here is
//! ownership, coverage, a settled body, or permission to suppress a rearm.
use super::*;

pub(crate) struct PairedRows<'a> {
    pub(crate) api: &'a BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
    pub(crate) trace:
        &'a BTreeMap<String, Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>>,
    /// Only complete, same-opened-generation pairs from this preparation.
    pub(crate) healthy_roots: &'a BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalSkip {
    root: String,
    member: String,
    revision: String,
    census_window_end: String,
    upload_context: Option<String>,
}

#[derive(Default)]
pub(crate) struct NativePhase {
    paused: bool,
    prepared: bool,
    // At most the candidates selected under the existing native page limit.
    skips: BTreeMap<String, NormalSkip>,
}

impl NativePhase {
    pub(super) fn record_actual_skip(
        &mut self,
        index: &ScanIndex,
        candidate: &CandidateFile,
        census_window_end: &str,
    ) {
        let Some((root, member)) = claude_index_path_family_member(&candidate.path) else {
            return;
        };
        let key = local_index_key(&candidate.path);
        let Some(entry) = index.files.get(&key) else {
            return;
        };
        // Called ONLY from the actual candidate Skip branch, after safe open,
        // canonical identity, sidecars and launcher context were prepared.
        // Held/empty/policy/legacy/terminal skips are not normal Skip evidence.
        if index.claude_usage_authority_quarantine.contains_key(&root)
            || index.claude_account_deferred_holds.contains_key(&key)
            || index.confirmed_empty_files.contains(&key)
            || index.terminal_jsonl_dispositions.contains_key(&key)
            || entry.scan_identity_version.as_deref() != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
            || entry.last_snapshot_fingerprint.is_none()
            || entry.source_file_fingerprint.is_empty()
            || entry.source_file_fingerprint != candidate.source_file_fingerprint
            || index.active_upload_context_fingerprint.is_none()
            || index.upload_context_fingerprint != index.active_upload_context_fingerprint
        {
            return;
        }
        self.skips.insert(
            key,
            NormalSkip {
                root,
                member,
                revision: candidate.source_file_fingerprint.clone(),
                census_window_end: census_window_end.to_owned(),
                upload_context: index.active_upload_context_fingerprint.clone(),
            },
        );
    }

    pub(super) fn pause_before_finalization(&mut self) -> bool {
        if self.prepared {
            return false;
        }
        self.paused = true;
        true
    }

    pub(super) fn ready(&self) -> bool {
        self.paused && !self.prepared
    }
    pub(super) fn resume(&mut self) {
        self.prepared = true;
        self.paused = false;
    }

    pub(super) fn qualify(
        &self,
        index: &ScanIndex,
        native: &[SnapshotItem],
        census_window_end: &str,
        rows: PairedRows<'_>,
    ) -> Qualification {
        assert!(self.ready(), "preflight must precede native finalization");
        let owners = claude_legacy_request_owners_from_rows(
            rows.api
                .iter()
                .filter(|(root, _)| rows.healthy_roots.contains(*root)),
            rows.trace,
        );
        let mut families = BTreeMap::new();
        for (root, retained) in &index.claude_usage_family_witnesses {
            // Freeze/reconstruct P from retained state. Never substitute a new
            // proof or mutate the index while deciding negative eligibility.
            if !rows.healthy_roots.contains(root)
                || index.claude_usage_authority_quarantine.contains_key(root)
            {
                continue;
            }
            let Some(api) = rows.api.get(root) else {
                continue;
            };
            let Some(trace) = rows.trace.get(root) else {
                continue;
            };
            let Some(family) = reconstruct_claude_usage_family_from_rows(
                root,
                retained,
                api,
                trace,
                owners.as_ref(),
            ) else {
                continue;
            };
            // Current members that would fail the exact authoritative rebuild
            // make this family ineligible. Shared checks include native set and
            // occurrence fingerprints, selectors, totals, clocks and overflow.
            if native
                .iter()
                .filter(|item| claude_snapshot_family_root(item) == *root)
                .any(|item| {
                    let Some((rows, excluded)) = claude_reported_usage_inputs(item, &family) else {
                        return true;
                    };
                    prepare_claude_reported_usage(item, rows, &excluded, None).is_none()
                })
            {
                continue;
            }
            let certified = self
                .skips
                .iter()
                .filter(|(key, skip)| {
                    skip.root == *root
                        && skip.census_window_end == census_window_end
                        && index.files.get(*key).is_some_and(|entry| {
                            entry.source_file_fingerprint == skip.revision
                                && skip.upload_context == index.active_upload_context_fingerprint
                        })
                        && retained
                            .member_request_id_fingerprints
                            .contains_key(&skip.member)
                })
                .map(|(key, skip)| (key.clone(), skip.clone()))
                .collect::<BTreeMap<_, _>>();
            if !certified.is_empty() {
                families.insert(root.clone(), FrozenFamily { family, certified });
            }
        }
        Qualification { families }
    }
}

struct FrozenFamily {
    family: ProvenClaudeUsageFamily,
    certified: BTreeMap<String, NormalSkip>,
}

#[derive(Default)]
pub(crate) struct Qualification {
    families: BTreeMap<String, FrozenFamily>,
}

impl Qualification {
    /// Count-only preparation receipt; not a bootstrap or reuse permit.
    pub(crate) fn certified_member_count(&self) -> usize {
        self.families
            .values()
            .map(|family| {
                // Keep the frozen proof together with its exact certified keys.
                // Later target selection must use this proof, never the live map.
                family
                    .certified
                    .values()
                    .filter(|skip| {
                        family
                            .family
                            .witness
                            .member_request_id_fingerprints
                            .contains_key(&skip.member)
                    })
                    .count()
            })
            .sum()
    }
}

// There is deliberately no runtime flag, API or environment opt-in.
pub(crate) fn enabled() -> bool {
    #[cfg(test)]
    {
        ENABLED.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
thread_local! { static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[cfg(test)]
pub(crate) struct TestScope(bool);
#[cfg(test)]
pub(crate) fn enable_for_test() -> TestScope {
    TestScope(ENABLED.with(|enabled| enabled.replace(true)))
}
#[cfg(test)]
impl Drop for TestScope {
    fn drop(&mut self) {
        ENABLED.with(|enabled| enabled.set(self.0));
    }
}
