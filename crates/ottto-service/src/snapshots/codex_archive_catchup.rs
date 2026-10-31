//! Standalone archive admission over the ordinary complete-scope inventory.
use super::*;
use codex_compressed_input::{archive_owed, ArchiveEvidence};

pub(super) enum Admission {
    Read,
    Quiet,
    Held,
}
impl ScanIndex {
    pub(super) fn archive_hold(&mut self, path: &Path, cause: CodexZstCause) {
        if let Some(a) = self.archives.get_mut(&local_index_key(path)) {
            a.hold(cause);
        }
    }
    pub(super) fn archive_owed_count(&self) -> usize {
        self.archives
            .values()
            .filter(|a| a.owed_cause().is_some())
            .count()
            + self.decode_holds.archive_keys().count()
            + self.archive_pass.deferred
    }
    pub(super) fn disclose_archive_debt(&self) {
        for a in self.archives.values() {
            if let Some(cause) = a.owed_cause() {
                archive_owed(cause, cause != CodexZstCause::CorrectionUnapplied);
            }
        }
        for _ in self.decode_holds.archive_keys() {
            archive_owed(CodexZstCause::OwnerUnproven, true);
        }
        if self.archive_pass.deferred > 0 {
            archive_owed(CodexZstCause::AdmissionRefused, true);
        }
    }
    pub(super) fn hold_archive_corrections(&mut self) {
        for a in self.archives.values_mut() {
            if matches!(
                a.disposition,
                ArchiveDisposition::Acquired | ArchiveDisposition::Empty
            ) {
                a.hold(CodexZstCause::CorrectionUnapplied);
                archive_owed(CodexZstCause::CorrectionUnapplied, true);
            }
        }
    }
    /// Reuse the ordinary absence owner; uncertainty in any configured root
    /// or inventoried home prevents publishing a uniqueness-dependent body.
    fn archive_fence(
        &self,
        key: &str,
        i: &codex_file_join::HeaderInventory,
    ) -> Result<(), CodexZstCause> {
        if !i.archive_complete
            || !codex_counting_version::absence_coverage_complete(self, i)
            || !i.content_unchanged()
            || !i.archives_unchanged()
        {
            return Err(CodexZstCause::OwnerUnproven);
        }
        for h in i.headers.iter().chain(&i.archive_headers) {
            i.directories
                .validate(&h.home)
                .map_err(|_| CodexZstCause::OwnerUnproven)?;
        }
        let h = i
            .archive_headers
            .iter()
            .find(|h| h.candidate.path == Path::new(key))
            .ok_or(CodexZstCause::OwnerUnproven)?;
        if i.headers
            .iter()
            .chain(&i.archive_headers)
            .any(|other| other.owner == h.owner && other.candidate.path != h.candidate.path)
        {
            return Err(
                if i.archive_headers
                    .iter()
                    .any(|other| other.owner == h.owner && other.candidate.path != h.candidate.path)
                {
                    CodexZstCause::FamilyUnproven
                } else {
                    CodexZstCause::ArchiveEquivalenceUnproven
                },
            );
        }
        if self
            .archives
            .get(key)
            .and_then(ArchiveEvidence::header)
            .and_then(|h| h.parent.as_ref())
            .is_some_and(|parent| {
                !self
                    .codex_parent_ownership_ledgers
                    .get(parent)
                    .is_some_and(|ledger| ledger.scan_complete)
            })
        {
            return Err(CodexZstCause::ParentLedgerUnbound);
        }
        Ok(())
    }
    /// Save one reservation batch for the admitted page, before constructing
    /// any Full reader. Refused resource work remains eligible next pass.
    pub(super) fn prepare_archive_reservations(
        &mut self,
        candidates: &VecDeque<CandidateFile>,
        inventory: &codex_file_join::HeaderInventory,
        budget: &sampled_scan::codex_cursor::PageBudget,
    ) {
        if self.archive_pass.prepared {
            return;
        }
        self.archive_pass.prepared = true;
        for c in candidates.iter().filter(|c| codex_archive_path(&c.path)) {
            let key = local_index_key(&c.path);
            let Some(a) = self.archives.get(&key) else {
                continue;
            };
            if a.quiet_disposition() {
                continue;
            }
            if !budget.archive_ready(&self.archive_pass) || !inventory.archive_complete {
                continue;
            }
            match self.archive_fence(&key, inventory) {
                Err(cause) => self.archive_hold(&c.path, cause),
                Ok(()) => {
                    let a = self.archives.get_mut(&key).unwrap();
                    if matches!(
                        a.disposition,
                        ArchiveDisposition::Held {
                            cause: CodexZstCause::ParentLedgerUnbound
                        }
                    ) && a.work.as_ref().is_some_and(|w| w.attempts > 0)
                    {
                        continue;
                    }
                    // Same-stamp post-Full structural failures never re-decode.
                    if matches!(
                        a.disposition,
                        ArchiveDisposition::Held {
                            cause: CodexZstCause::OutputHeld
                                | CodexZstCause::DecodeFailed
                                | CodexZstCause::HeaderInvalid
                                | CodexZstCause::CorrectionUnapplied
                        }
                    ) {
                        continue;
                    }
                    a.reserve();
                    a.work.as_mut().unwrap().reserved = true;
                    self.archive_pass.dirty = true;
                }
            }
        }
    }
    pub(super) fn archive_admit(
        &mut self,
        c: &CandidateFile,
        file: &File,
        inventory: Option<&codex_file_join::HeaderInventory>,
        budget: &sampled_scan::codex_cursor::PageBudget,
    ) -> Admission {
        let key = local_index_key(&c.path);
        let Some(a) = self.archives.get(&key).filter(|a| a.matches(file)) else {
            return Admission::Held;
        };
        if !a.ready_full() {
            if a.owed_cause().is_some() {
                return Admission::Held;
            }
            return Admission::Quiet;
        }
        if !budget.archive_ready(&self.archive_pass) {
            // No Full bytes spent: cancel the unconsumed reservation.
            self.archives.get_mut(&key).unwrap().disposition = ArchiveDisposition::HeaderValidated;
            return Admission::Held;
        }
        if let Err(cause) = inventory
            .ok_or(CodexZstCause::OwnerUnproven)
            .and_then(|i| self.archive_fence(&key, i))
        {
            self.archive_hold(&c.path, cause);
            return Admission::Held;
        }
        Admission::Read
    }
    pub(super) fn archive_finish(
        &mut self,
        path: &Path,
        parsed: &ParsedJsonlFile,
        owner: Option<&str>,
        inventory: Option<&codex_file_join::HeaderInventory>,
    ) -> bool {
        let key = local_index_key(path);
        if !self
            .archives
            .get_mut(&key)
            .is_some_and(|a| a.finish(owner, parsed))
        {
            return false;
        }
        if let Err(cause) = inventory
            .ok_or(CodexZstCause::OwnerUnproven)
            .and_then(|i| self.archive_fence(&key, i))
        {
            self.archive_hold(path, cause);
            return false;
        }
        true
    }
}
