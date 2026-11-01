//! Test-only observation of the real scanner; no alternate parser/finalizer.
use super::*;
use crate::transcript_acquisition::Scope;

/// The sampled scope and identity-capture mode this fixture's scans bind; a
/// durable record (#806) restores only under the same pair.
fn durable_binding(source: SnapshotSource) -> (Scope, bool) {
    match source {
        SnapshotSource::ClaudeCode => (Scope("e2-pipeline".into()), CLAUDE_IDENTITY_CAPTURE),
        // Outside a sync cycle every scan captures (also in tests).
        _ => (Scope("money-equivalence".into()), true),
    }
}
const CLAUDE_IDENTITY_CAPTURE: bool = false;

#[derive(Default)]
pub(crate) struct E2ScanFixture {
    pub(crate) cache: Arc<sampled_scan::SharedCache>,
    observed: Mutex<Vec<PathBuf>>,
    pub(crate) versions: Option<Arc<codex_version::CodexVersionFeed>>,
    capture_claude_identity: bool,
}
impl E2ScanFixture {
    /// Opt in when the fixture asserts marker/identity behavior. Money-only
    /// fixtures retain their historical capture-off scope and bytes.
    pub(crate) fn capturing_identity() -> Self {
        Self::with_identity_capture(true)
    }

    pub(crate) fn with_identity_capture(capture_claude_identity: bool) -> Self {
        Self {
            capture_claude_identity,
            ..Self::default()
        }
    }

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.observed.lock().unwrap().clone()
    }

    /// Begins this owner's pass on the real durable store beside
    /// `index_path`, as the daemon does before a scan. `state_dir` holds the
    /// index and the single-writer lock.
    pub(crate) fn begin_durable(
        &self,
        source: SnapshotSource,
        state_dir: &Path,
        index_path: &Path,
    ) {
        let (scope, capture) = durable_binding(source);
        let capture = if source == SnapshotSource::ClaudeCode {
            self.capture_claude_identity
        } else {
            capture
        };
        begin_durable_pass(
            &self.cache,
            state_dir,
            source,
            index_path,
            false,
            &scope,
            capture,
        );
    }

    pub(crate) fn evict(&self) {
        self.cache.clear();
    }

    pub(crate) fn evict_for_pressure(&self) {
        let mut retained = self.cache.retained().unwrap();
        let empty = sampled_scan::RetainedCache::default();
        let limit = crate::heap_layout_bound::bound(&empty, usize::MAX).unwrap_or(0);
        assert!(retained.release_until(limit) || !crate::heap_layout_bound::layout_supported());
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
            self.capture_claude_identity,
        );
        if sampled {
            let (scope, _) = durable_binding(SnapshotSource::ClaudeCode);
            scan = scan.with_sampled_acquisition(self.cache.clone(), scope);
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

    /// Same retained reader seam for sources without Claude evidence.
    pub(crate) fn scan_other(
        &self,
        source: SnapshotSource,
        roots: &[PathBuf],
        support: &Path,
        index: ScanIndex,
        sampled: bool,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        let mut scan = OwnedSourceScan::new(
            source,
            roots,
            index,
            "2026-10-27T08:00:00Z",
            183,
            100,
            false,
            Some(support),
            &[],
            false,
        );
        if sampled {
            let (scope, _) = durable_binding(source);
            scan = scan.with_sampled_acquisition(self.cache.clone(), scope);
        }
        if let Some(versions) = self.versions.as_ref() {
            scan = scan.with_codex_versions(versions.clone());
        }
        self.drive(scan, &BTreeMap::new())
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

pub(crate) fn indexed_size(index: &ScanIndex, path: &Path) -> Option<u64> {
    index
        .files
        .get(&local_index_key(path))
        .map(|entry| entry.size_bytes)
}

/// Model already delivered history after the synthetic uploader has ACKed
/// every current entity: each file holds its receipt under `context` (an
/// empty file its local empty proof). Creates no ACK.
pub(crate) fn receipt_acked_files_for_test(index: &mut ScanIndex, context: &str) {
    let delivered = index.current_snapshot_fingerprints();
    assert!(!delivered.is_empty());
    assert!(delivered
        .iter()
        .all(|fp| index.accepted_snapshot_fingerprint_recorded(fp)));
    for entry in index.files.values_mut() {
        entry.upload_context_receipt = Some(super::upload_context_receipt::Receipt {
            context_fingerprint: context.into(),
            replay_generation: super::upload_context_receipt::RECEIPT_REPLAY_EPOCH,
            source_witness: entry.source_file_fingerprint.clone(),
            body_witness: entry.last_upload_body_witness.clone().unwrap_or_default(),
        });
    }
}

/// Each sent item's exact ACK (entity -> upload body witness), as the
/// synthetic responders answer a fully accepted page.
pub(crate) fn exact_acks_for_test(items: &[SnapshotItem]) -> BTreeMap<String, String> {
    items
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect()
}

/// The production finish of per-file upload-context proof for one page:
/// the page's final `items` become receipt candidates under the index's
/// active context, and only exact `acks` earn receipts (`snapshot_sync`
/// finish and partial checkpoint run the same calls), and the exact ACKs
/// stamp their entities' durable context proof under the active context in
/// one fixture destination. Call it after the page's settlement, where the
/// service does.
pub(crate) fn accept_upload_context_acks_for_test(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
    acks: &BTreeMap<String, String>,
) {
    let candidates = index.file_upload_context_ack_candidates(items);
    index.accept_file_upload_context_acks(&candidates, acks);
    let contexts = index
        .active_upload_context_fingerprint
        .as_ref()
        .map(|context| {
            acks.keys()
                .map(|entity| (entity.clone(), context.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    index.stamp_entity_upload_context_acks("e2-fixture-destination", acks, &contexts);
}

/// Install the real exclusion input used by ordinary-money fixture families.
/// An empty slice adopts request-owned money on the next normal source pass.
pub(crate) fn write_exclusions(support: &Path, sessions: &[&str]) {
    use sha2::Digest;
    let path = claude_reemission_exclusions::ReemissionExclusions::path(support);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let lines = sessions
        .iter()
        .map(|session| format!("{:x}\n", sha2::Sha256::digest(session.as_bytes())))
        .collect::<String>();
    fs::write(path, lines).unwrap();
}

/// A real fail-closed exclusion-list result, scoped to this fixture index.
pub(crate) fn ordinary_index(mut index: ScanIndex) -> ScanIndex {
    index.claude_reemission_exclusions = claude_reemission_exclusions::ReemissionExclusions::parse(
        b"malformed synthetic exclusion input",
    );
    index
}

/// Ordinary-money parser fixture through the existing native parser and real
/// paused-adoption input. No alternate resolver or money builder.
pub(crate) fn parse_ordinary(
    path: &Path,
    at: &str,
    fingerprint: String,
) -> Result<Vec<SnapshotItem>> {
    parse_ordinary_with_metadata(path, at, fingerprint, &ClaudeTitleMetadata::default(), true)
}

pub(super) fn parse_ordinary_with_metadata(
    path: &Path,
    at: &str,
    fingerprint: String,
    metadata: &ClaudeTitleMetadata,
    artifacts: bool,
) -> Result<Vec<SnapshotItem>> {
    let mut file = File::open(path)?;
    let opened = opened_object_identity(SnapshotSource::ClaudeCode, &mut file)?;
    let mut parser = OwnedJsonlParser::new(
        file,
        path,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
        None,
        None,
        artifacts,
    )?;
    while !parser.step()? {}
    let index = ordinary_index(ScanIndex::default());
    parser
        .finish_with_repository_identity(
            &opened,
            path,
            at,
            fingerprint,
            None,
            Some(metadata),
            None,
            None,
            Some(claude_request_money::e2::ReadContext {
                index: &index,
                path,
                twins: &std::cell::OnceCell::new(),
            }),
        )
        .map(|parsed| parsed.snapshots)
}

/// Persist a real malformed-list input to exercise fail-closed ordinary money.
pub(crate) fn pause_adoption(support: &Path) {
    let path = claude_reemission_exclusions::ReemissionExclusions::path(support);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"malformed synthetic exclusion input").unwrap();
}
