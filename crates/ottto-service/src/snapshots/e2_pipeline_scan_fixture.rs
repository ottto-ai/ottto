//! Test-only observation of the real scanner; no alternate parser/finalizer.
use super::*;
use crate::transcript_acquisition::Scope;

#[derive(Default)]
pub(crate) struct E2ScanFixture {
    cache: Arc<sampled_scan::SharedCache>,
    observed: Mutex<Vec<PathBuf>>,
}
impl E2ScanFixture {
    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.observed.lock().unwrap().clone()
    }

    pub(crate) fn evict(&self) {
        self.cache.clear();
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan(
        &self,
        roots: &[PathBuf],
        support: &Path,
        index: ScanIndex,
        limit: usize,
        sampled: bool,
        births: &BTreeMap<PathBuf, i128>,
        hints: &[PathBuf],
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        self.observed.lock().unwrap().clear();
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            roots,
            index,
            "2026-08-02T08:00:00Z",
            183,
            limit,
            false,
            Some(support),
            hints,
            false,
            true,
            false,
        );
        if sampled {
            scan = scan.with_sampled_acquisition(self.cache.clone(), Scope("e2-pipeline".into()));
        }
        // The same synthetic root births reach the page's staged twin probes,
        // which read metadata before the file is opened for parse.
        let staged = births
            .iter()
            .filter(|(path, _)| {
                claude_index_path_member_ref(path)
                    .is_some_and(|member| member.subagent_stem.is_none())
            })
            .filter_map(|(path, birth)| Some((local_index_key(path), u64::try_from(*birth).ok()?)))
            .collect();
        claude_history_upgrade::with_staged_births_for_test(staged, || self.drive(scan, births))
    }

    fn drive(
        &self,
        mut scan: OwnedSourceScan,
        births: &BTreeMap<PathBuf, i128>,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        let mut seen = BTreeSet::new();
        for _ in 0..100_000 {
            // Existing fixture setter changes only physical birth. JSONL still
            // comes from the opened reader, including retained prefix/suffix.
            if let Some(active) = scan.active_file.as_deref_mut() {
                if seen.insert(active.candidate.path.clone()) {
                    self.observed
                        .lock()
                        .unwrap()
                        .push(active.candidate.path.clone());
                }
                if let Some(birth) = births.get(&active.candidate.path) {
                    if !active
                        .parser
                        .accumulator
                        .claude_file_birth
                        .is_subagent_for_test()
                    {
                        active
                            .parser
                            .accumulator
                            .claude_file_birth
                            .set_birth_for_test(*birth);
                    }
                }
            }
            let modes = scan.sampling.as_ref().map_or((0, 0, 0), |s| {
                (s.full_files, s.tail_files, s.unchanged_files)
            });
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("bounded synthetic E2 scan failed to finish");
    }
}

pub(crate) fn without_money_folds(scan: &mut SourceScanResult) {
    // Publication reference: the legacy caller has no E2 fold carrier.
    for item in &mut scan.snapshots {
        item.claude_money = None;
    }
}

pub(crate) fn birth_store_bytes(index: &ScanIndex) -> Vec<u8> {
    serde_json::to_vec(&index.claude_money_birth_store).unwrap()
}

pub(crate) fn with_history_byte_limit<T>(limit: u64, f: impl FnOnce() -> T) -> T {
    with_body_witness_adoption_byte_budget(limit, f)
}

pub(crate) fn explicitly_held(
    disposition: &ClaudeUsageAuthorityDisposition,
    session: &str,
) -> bool {
    disposition.quarantined_source_session_ids.contains(session)
}
