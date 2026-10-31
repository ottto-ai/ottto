use super::*;
use codex_compressed_input::{HeaderRead, HeaderWork};

/// A classification is never an ACK, ownership proof or permission to retire
/// another carrier. `Deferred` keeps selection debt in the existing queue.
pub(super) enum Admission {
    Read,
    Held(CodexZstCause),
    Deferred(CodexZstCause),
}

pub(super) enum ArchiveReplacement {
    Replace(Vec<codex_file_join::LegacyBaseline>),
    Dominated,
}

/// Borrowed scan inputs; the existing acquisition still owns the opened file
/// and the saved reservation. This operation builds neither a parser nor an ACK.
pub(super) struct Preparation<'a> {
    pub(super) source: SnapshotSource,
    pub(super) inventory: Option<&'a codex_file_join::HeaderInventory>,
    pub(super) sampling: Option<&'a sampled_scan::Context>,
    pub(super) codex_metadata: &'a CodexTitleMetadata,
    pub(super) claude_metadata: &'a ClaudeTitleMetadata,
    pub(super) effort_dir: Option<&'a Path>,
    pub(super) census_complete: bool,
    pub(super) curve: bool,
}

impl ScanIndex {
    #[inline(never)] // Keep archive preparation scratch out of the native scan frame.
    pub(super) fn prepare_archive(
        &mut self,
        candidate: &CandidateFile,
        file: &File,
        budget: &mut sampled_scan::codex_cursor::PageBudget,
        options: Preparation<'_>,
    ) -> Result<(Admission, Option<crate::transcript_acquisition::Scope>)> {
        if options.source != SnapshotSource::Codex || !codex_archive_path(&candidate.path) {
            return Ok((Admission::Read, None));
        }
        if self
            .files
            .get(&local_index_key(&candidate.path))
            .and_then(|e| e.archive.as_ref())
            .is_some_and(|a| a.user_change && a.matches(file))
            && !budget.archive_ready(&self.archive_pass)
        {
            return Ok((Admission::Held(CodexZstCause::CorrectionUnapplied), None));
        }
        let admission = self.classify_archive(
            candidate,
            file,
            options.inventory,
            options.sampling.map(|c| &c.cache),
            budget,
        )?;
        if !matches!(admission, Admission::Read) {
            return Ok((admission, None));
        }
        crate::context_composition::set_utility_qos();
        self.archive_pass.started = true;
        let scope = options
            .sampling
            .filter(|_| options.census_complete)
            .and_then(|context| {
                sampled_scan::reduction_dependencies(
                    options.source,
                    candidate,
                    options.codex_metadata,
                    options.claude_metadata,
                    options.effort_dir,
                    self.archive_header(&candidate.path),
                )
                .map(|dependency| {
                    context.file_scope(
                        options.source,
                        candidate,
                        &dependency,
                        true,
                        options.curve,
                        self,
                    )
                })
            });
        // Header work cannot carry AC permission into a later body claim.
        if !budget.archive_ready(&self.archive_pass) {
            return Ok((Admission::Deferred(CodexZstCause::AdmissionRefused), None));
        }
        Ok((Admission::Read, scope))
    }
}

/// One cause per newly retained residue key. This is disclosure only: deferred
/// work remains queued and gains no terminal, ownership or acceptance credit.
pub(super) fn retain_residue(keys: &mut BTreeSet<String>, path: &Path, cause: CodexZstCause) {
    if keys.insert(local_index_key(path)) {
        crate::local_resource_diagnostics::traversal_point(
            "codex_archive_residue",
            "codex",
            &BTreeMap::from([("codex_archive_residue", BTreeMap::from([(cause, 1_u64)]))]),
        );
    }
}

impl ScanIndex {
    /// The one completed-output gate for a paced custody attempt. The old
    /// carrier stays accepted until the ordinary exact-body ACK settles the
    /// replacement; the existing legacy-baseline reconciliation verifies the
    /// retained plain reduction against its accepted entity-set fingerprint.
    pub(super) fn archive_replacement_baselines(
        &self,
        path: &Path,
        parsed: &ParsedJsonlFile,
        usage: &UsageTotals,
        inputs: (
            &codex_file_join::HeaderInventory,
            &sampled_scan::SharedCache,
            &CodexTitleMetadata,
        ),
        mut budget: usize,
    ) -> Option<ArchiveReplacement> {
        let (inventory, cache, metadata) = inputs;
        let key = local_index_key(path);
        if !inventory.old_carrier(&key) {
            return (!inventory.archive_class(&key).sibling)
                .then(|| ArchiveReplacement::Replace(Vec::new()));
        }
        let (owner, ledger) = parsed
            .codex_parent_ownership_ledger
            .as_ref()
            .filter(|(_, l)| l.scan_complete)?;
        if self
            .files
            .get(&key)?
            .archive
            .as_ref()?
            .header_validated
            .as_ref()?
            .owner
            != *owner
        {
            return None;
        }
        if parsed
            .snapshots
            .iter()
            .any(|s| s.source_session_id != *owner)
        {
            return None;
        }
        let carriers = inventory.carrier_paths(owner).filter(|p| *p != key).count();
        budget = budget.checked_sub(
            carriers.checked_mul(std::mem::size_of::<codex_file_join::LegacyBaseline>())?,
        )?;
        let mut baselines = Vec::with_capacity(carriers);
        let mut replacement = true;
        let mut dominated = true;
        for carrier in inventory.carrier_paths(owner).filter(|p| *p != key) {
            if codex_archive_path(Path::new(carrier)) {
                return None;
            }
            let entry = self.files.get(carrier)?;
            entry.last_snapshot_fingerprint.as_ref()?;
            entry.last_upload_body_witness.as_ref()?;
            if !self
                .file_snapshot_fingerprints
                .get(carrier)
                .is_some_and(|fps| {
                    !fps.is_empty()
                        && fps
                            .iter()
                            .all(|fp| self.accepted_snapshot_fingerprints.contains(fp))
                })
            {
                return None;
            }
            let retained = cache.retained().ok()?;
            let prior = retained.peek(carrier)?;
            let relation = prior
                .state
                .compare_archive(owner, &ledger.signatures, usage, budget)?;
            replacement &= relation != std::cmp::Ordering::Less;
            dominated &= relation != std::cmp::Ordering::Greater;
            // Keep the accepted plain proof available for an unACKed archive's
            // next retry. Fund both the copy and its existing output charge
            // before cloning; no baseline file read is introduced.
            budget = budget.checked_sub(
                crate::heap_layout_bound::completed_bound(&prior.state, budget)?
                    .checked_add(retained.finalization_charge(carrier)?)?
                    .checked_add(carrier.len())?
                    .checked_add(owner.len())?
                    .checked_add(entry.last_snapshot_fingerprint.as_ref()?.len())?,
            )?;
            let state = prior.state.clone();
            drop(retained);
            baselines.push(state.into_archive_baseline(carrier, entry, owner, metadata));
        }
        if baselines.is_empty() {
            return None;
        }
        if replacement {
            return Some(ArchiveReplacement::Replace(baselines));
        }
        // A subset may settle without uploading only when this exact native
        // baseline already reproduces accepted output. A projection mismatch
        // remains unknown; it must never authorize discarding new usage.
        if dominated
            && baselines.iter().all(|baseline| {
                snapshot_file_entity_set_hex(
                    baseline
                        .snapshots
                        .iter()
                        .map(|s| s.snapshot_fingerprint.clone()),
                ) == baseline.expected
            })
        {
            return Some(ArchiveReplacement::Dominated);
        }
        None
    }

    /// Custody is negative scope only; acquisition and ACK remain independent.
    pub(super) fn classify_archive(
        &mut self,
        candidate: &CandidateFile,
        file: &File,
        inventory: Option<&codex_file_join::HeaderInventory>,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
        budget: &mut sampled_scan::codex_cursor::PageBudget,
    ) -> Result<Admission> {
        let key = local_index_key(&candidate.path);
        let ids = codex_session_id_candidates_from_path(&candidate.path);
        let custody_retry = cache.is_some()
            && self
                .files
                .get(&key)
                .is_some_and(|e| e.custody_retry_due(&candidate.path));
        if let Some(cause) = self
            .files
            .get(&key)
            .and_then(|e| e.codex_compressed_hold)
            .filter(|_| !custody_retry)
        {
            return Ok(Admission::Held(cause));
        }
        let prior = self
            .files
            .get(&key)
            .and_then(|e| e.archive.as_deref())
            .filter(|a| a.matches(file));
        if !custody_retry && prior.is_some_and(|a| a.quiet(file)) {
            return Ok(Admission::Held(
                prior
                    .and_then(|a| a.terminal_cause())
                    .unwrap_or(CodexZstCause::OutputHeld),
            ));
        }
        let retry =
            prior.is_some_and(|a| matches!(a.disposition, ArchiveDisposition::Pending { .. }));
        if retry && cache.is_none() {
            return Ok(Admission::Held(CodexZstCause::OutputHeld));
        }
        // One funded inventory result; no candidate-level roster/index walks.
        let Some(inventory) = inventory.filter(|i| i.classified_archive(&key)) else {
            if let Some(cache) = cache {
                cache.archive_yield(&key);
            }
            return Ok(Admission::Deferred(CodexZstCause::AdmissionRefused));
        };
        let family = inventory.archive_class(&key).sibling;
        let old_carrier = inventory.old_carrier(&key);
        if !custody_retry && (family || (!retry && old_carrier)) {
            let cause = if family {
                CodexZstCause::FamilyUnproven
            } else {
                CodexZstCause::ArchiveEquivalenceUnproven
            };
            self.hold_compressed(&candidate.path, ids.iter().cloned().collect(), cause);
            return Ok(Admission::Held(cause));
        }
        // A partial/old intake census is negative scope only. New archive
        // acquisition waits until every configured root has been inventoried.
        if !inventory.complete {
            return Ok(Admission::Deferred(CodexZstCause::AdmissionRefused));
        }
        if !budget.archive_ready(&self.archive_pass) {
            return Ok(Admission::Deferred(CodexZstCause::AdmissionRefused));
        }
        // Existing reservation/deadline bounds retries; identity and superset
        // proof remain mandatory at completed output, including retained resends.
        if retry || custody_retry {
            return Ok(Admission::Read);
        }
        if budget.singleton_remaining(sampled_scan::codex_cursor::Limits::current())
            < 2 * codex_file_join::MAX_HEADER_BYTES as u64
        {
            return Ok(Admission::Deferred(CodexZstCause::AdmissionRefused));
        }
        if !budget.archive_ready(&self.archive_pass) {
            return Ok(Admission::Deferred(CodexZstCause::AdmissionRefused));
        }
        crate::context_composition::set_utility_qos();
        let mut work = HeaderWork {
            allowed: true,
            ..HeaderWork::default()
        };
        let header = self.inventory_archive_header(candidate, cache, &mut work);
        self.archive_pass.started |= work.decoded_bytes > 0;
        budget.charge(false, work.decoded_bytes);
        match header? {
            HeaderRead::Deferred => Ok(Admission::Deferred(CodexZstCause::HeaderUnfunded)),
            HeaderRead::Validated(_) | HeaderRead::BoundReached => Ok(Admission::Read),
        }
    }
}

/// Order the supported header population globally before selecting a page.
/// Each archive stat is cached on its queued path; comparisons do no I/O and
/// unstable sorting needs no roster-sized sort scratch. Larger populations
/// retain the existing bounded inventory/custody behavior, never an unbounded
/// prep walk. Plain work always sorts ahead of archive backlog.
pub(super) fn order_pending(pending: &mut VecDeque<ScanTraversalPath>) {
    let quantum = codex_file_join::MAX_HEADER_FILES;
    let mut checks = 0_u64;
    for (position, member) in pending.iter_mut().take(quantum).enumerate() {
        let modified = if codex_archive_path(&member.path) {
            match member.order_modified {
                Some((modified, _)) => modified,
                None => {
                    checks += 1;
                    fs::symlink_metadata(&member.path)
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::UNIX_EPOCH)
                }
            }
        } else {
            std::time::UNIX_EPOCH
        };
        member.order_modified = Some((modified, position));
    }
    if pending.len() <= quantum {
        let compare = |a: &ScanTraversalPath, b: &ScanTraversalPath| {
            let a_archive = codex_archive_path(&a.path);
            let b_archive = codex_archive_path(&b.path);
            a_archive.cmp(&b_archive).then_with(|| {
                if a_archive {
                    std::cmp::Reverse(a.order_modified.map(|(mtime, _)| mtime))
                        .cmp(&std::cmp::Reverse(b.order_modified.map(|(mtime, _)| mtime)))
                        .then_with(|| a.path.cmp(&b.path))
                } else {
                    a.order_modified
                        .map(|(_, position)| position)
                        .cmp(&b.order_modified.map(|(_, position)| position))
                }
            })
        };
        if !pending
            .iter()
            .zip(pending.iter().skip(1))
            .all(|(a, b)| compare(a, b) != std::cmp::Ordering::Greater)
        {
            pending.make_contiguous().sort_unstable_by(compare);
        }
    }
    crate::local_resource_diagnostics::traversal_point(
        "codex_zst_order_metadata",
        "codex",
        &BTreeMap::from([("codex_zst_order_metadata_checks", checks)]),
    );
}
