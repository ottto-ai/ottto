//! Conservative admission over the ordinary native header inventory.
use super::*;

pub(super) enum Admission {
    Read,
    Quiet,
    Held(CodexZstCause),
}
impl ScanIndex {
    pub(super) fn archive_hold(&mut self, path: &Path, mut cause: CodexZstCause) {
        if let Some(archive) = self
            .files
            .get_mut(&local_index_key(path))
            .and_then(|e| e.archive.as_mut())
        {
            // Preserve a more specific cause computed at the native boundary.
            cause = archive
                .hold
                .or_else(|| archive.terminal_cause())
                .unwrap_or(cause);
            archive.defer_custody(cause);
        }
        crate::local_resource_diagnostics::codex_zst_held(cause);
        crate::local_resource_diagnostics::durable_tail_alarm(
            "codex",
            &serde_json::json!({"archive_held": 1}),
        );
    }

    /// Keep correction debt under the existing context owner without regranting
    /// a decode. Retained-body correction is a later shared operation.
    pub(super) fn hold_archive_corrections(&mut self) {
        let mut owed = false;
        for entry in self.files.values_mut() {
            if let Some(a) = entry.archive.as_mut() {
                if matches!(
                    a.disposition,
                    ArchiveDisposition::Acquired | ArchiveDisposition::Empty
                ) {
                    a.hold = Some(CodexZstCause::CorrectionUnapplied);
                    owed = true;
                }
            }
        }
        if owed {
            crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::CorrectionUnapplied);
            crate::local_resource_diagnostics::durable_tail_alarm(
                "codex",
                &serde_json::json!({"archive_correction_owed":1}),
            );
        }
    }

    pub(super) fn archive_admit(
        &mut self,
        candidate: &CandidateFile,
        file: &File,
        inventory: Option<&codex_file_join::HeaderInventory>,
        budget: &sampled_scan::codex_cursor::PageBudget,
    ) -> Admission {
        let key = local_index_key(&candidate.path);
        let archive = self.files.get(&key).and_then(|e| e.archive.as_deref());
        if let Some(archive) = archive.filter(|a| a.matches(file)) {
            if archive.quiet(file) {
                if matches!(
                    archive.disposition,
                    ArchiveDisposition::Refused {
                        cause: CodexZstCause::ArchiveDominated
                    }
                ) {
                    return Admission::Quiet;
                }
                let cause = archive.hold.or_else(|| archive.terminal_cause());
                if let Some(cause) = cause {
                    crate::local_resource_diagnostics::codex_zst_held(cause);
                    crate::local_resource_diagnostics::durable_tail_alarm(
                        "codex",
                        &serde_json::json!({"archive_held":1}),
                    );
                    return Admission::Held(cause);
                }
                return Admission::Quiet;
            }
        }
        let cause = if self.decode_holds_file(&key) {
            Some(CodexZstCause::OwnerUnproven)
        } else if !budget.archive_ready(&self.archive_pass) {
            Some(CodexZstCause::AdmissionRefused)
        } else {
            inventory
                .and_then(|i| self.archive_fence(&key, i).err())
                .or_else(|| inventory.is_none().then_some(CodexZstCause::OwnerUnproven))
        };
        if let Some(cause) = cause {
            if !self.files.get(&key).is_some_and(|e| e.archive.is_some())
                && !self.decode_holds_file(&key)
            {
                if let Ok(mut evidence) =
                    codex_compressed_input::ArchiveEvidence::begin(file, &candidate.path, None)
                {
                    evidence.decode_attempts = 0;
                    evidence.disposition = ArchiveDisposition::HeaderValidated;
                    self.files.entry(key).or_default().archive = Some(Box::new(evidence));
                }
            }
            self.archive_hold(&candidate.path, cause);
            Admission::Held(cause)
        } else {
            Admission::Read
        }
    }

    /// No filename establishes ownership; all positive claims are own headers.
    /// Any unavailable header prevents an absence proof for this archive.
    fn archive_fence<'a>(
        &self,
        key: &str,
        inventory: &'a codex_file_join::HeaderInventory,
    ) -> Result<Vec<&'a codex_file_join::HeaderWitness>, CodexZstCause> {
        if !inventory.complete
            || !inventory.archive_complete
            || !inventory.content_unchanged()
            || inventory.headers.len() > codex_file_join::MAX_HEADER_FILES
        {
            return Err(CodexZstCause::OwnerUnproven);
        }
        let header = inventory
            .headers
            .iter()
            .find(|h| h.candidate.path == Path::new(key))
            .ok_or(CodexZstCause::HeaderInvalid)?;
        inventory
            .directories
            .validate(&header.home)
            .map_err(|_| CodexZstCause::OwnerUnproven)?;
        let mut plain = Vec::new();
        for other in inventory
            .headers
            .iter()
            .filter(|h| h.owner == header.owner && h.candidate.path != Path::new(key))
        {
            if codex_archive_path(&other.candidate.path) {
                return Err(CodexZstCause::FamilyUnproven);
            }
            if plain.len() == 1 {
                return Err(CodexZstCause::ArchiveEquivalenceUnproven);
            }
            plain.push(other);
        }
        Ok(plain)
    }

    pub(super) fn archive_finish(
        &mut self,
        path: &Path,
        parsed: &ParsedJsonlFile,
        owner: Option<String>,
        usage: &UsageTotals,
        inventory: Option<&codex_file_join::HeaderInventory>,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
    ) -> bool {
        let key = local_index_key(path);
        let valid = self
            .files
            .get_mut(&key)
            .and_then(|e| e.archive.as_mut())
            .is_some_and(|a| a.finish(owner, path, parsed));
        let cause = if parsed.codex_parent_resolution_pending
            || parsed.codex_parent_unresolvable.is_some()
        {
            Some(CodexZstCause::ParentLedgerUnbound)
        } else if !valid {
            Some(CodexZstCause::OutputHeld)
        } else {
            None
        };
        if let Some(cause) = cause {
            self.archive_hold(path, cause);
            return false;
        }
        let proof = inventory.and_then(|i| self.archive_fence(&key, i).ok());
        let Some(plain) = proof else {
            self.archive_hold(path, CodexZstCause::OwnerUnproven);
            return false;
        };
        if plain.is_empty() {
            return true;
        }
        let dominated = cache.is_some_and(|cache| {
            self.archive_dominated(&plain[0].candidate.path, parsed, usage, cache)
        });
        if dominated {
            let archive = self
                .files
                .get_mut(&key)
                .and_then(|e| e.archive.as_mut())
                .expect("completed archive");
            archive.disposition = ArchiveDisposition::Refused {
                cause: CodexZstCause::ArchiveDominated,
            };
            archive.hold = None;
            archive.body_witness = None;
            crate::local_resource_diagnostics::codex_zst_refused(CodexZstCause::ArchiveDominated);
        } else {
            self.archive_hold(path, CodexZstCause::ArchiveEquivalenceUnproven);
        }
        false
    }

    fn archive_dominated(
        &self,
        plain: &Path,
        parsed: &ParsedJsonlFile,
        usage: &UsageTotals,
        cache: &Arc<sampled_scan::SharedCache>,
    ) -> bool {
        let prove = || -> Option<bool> {
            let (owner, ledger) = parsed
                .codex_parent_ownership_ledger
                .as_ref()
                .filter(|(_, l)| l.scan_complete)?;
            if parsed
                .snapshots
                .iter()
                .any(|s| &s.source_session_id != owner)
            {
                return None;
            }
            let key = local_index_key(plain);
            let entry = self.files.get(&key)?;
            let expected = entry.last_snapshot_fingerprint.as_ref()?;
            entry.last_upload_body_witness.as_ref()?;
            let fingerprints = self.file_snapshot_fingerprints.get(&key)?;
            if fingerprints.is_empty()
                || !fingerprints
                    .iter()
                    .all(|fp| self.accepted_snapshot_fingerprints.contains(fp))
            {
                return None;
            }
            let retained = cache.retained().ok()?;
            let old = retained.peek(&key)?;
            let budget = crate::source_rotation::PARKED_BUDGET;
            if matches!(
                old.state
                    .compare_archive(owner, &ledger.signatures, usage, budget)?,
                std::cmp::Ordering::Greater
            ) {
                return None;
            }
            // Fund the same plain reduction/output projection used by native joins.
            let bytes =
                crate::heap_layout_bound::completed_bound(&old.state, budget)?.checked_mul(2)?;
            drop(retained);
            let credit = cache.cursor_claim(bytes, true)?;
            let exact = (|| -> Option<bool> {
                let retained = cache.retained().ok()?;
                let state = &retained.peek(&key)?.state;
                if matches!(
                    state.compare_archive(owner, &ledger.signatures, usage, budget)?,
                    std::cmp::Ordering::Greater
                ) {
                    return None;
                }
                let baseline = state.clone().into_archive_baseline(
                    &key,
                    entry,
                    owner,
                    &CodexTitleMetadata::default(),
                );
                Some(
                    snapshot_file_entity_set_hex(
                        baseline
                            .snapshots
                            .iter()
                            .map(|s| s.snapshot_fingerprint.clone()),
                    ) == *expected
                        && Some(snapshot_file_upload_body_set_hex(
                            baseline.snapshots.iter().map(snapshot_upload_body_witness),
                        ))
                        .as_ref()
                            == entry.last_upload_body_witness.as_ref(),
                )
            })();
            credit.refund();
            exact
        };
        prove().unwrap_or(false)
    }
}
