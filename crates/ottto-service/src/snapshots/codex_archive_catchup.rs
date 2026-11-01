//! Standalone archive admission over the ordinary complete-scope inventory.
use super::*;
use codex_compressed_input::{archive_alarm, ArchiveEvidence};

pub(super) enum Admission {
    Read,
    Quiet,
    Held,
}
impl ScanIndex {
    pub(super) fn archive_size_refused(&mut self, path: &Path, bytes: u64) -> bool {
        if bytes <= max_jsonl_file_bytes(SnapshotSource::Codex) {
            return false;
        }
        let key = local_index_key(path);
        if self
            .archives
            .get(&key)
            .is_some_and(|a| a.owed_cause().is_none())
        {
            self.archive_pass.deferred.insert(key);
        } else {
            self.archive_transition(
                path,
                ArchiveTransition::Transient(CodexZstCause::AdmissionRefused),
            );
        }
        true
    }
    pub(super) fn archive_transition(&mut self, path: &Path, change: ArchiveTransition) {
        let key = local_index_key(path);
        if matches!(change, ArchiveTransition::Gone) {
            self.archives.remove(&key);
        } else {
            if !self.archives.contains_key(&key) {
                self.archive_pass.deferred.insert(key.clone());
                if let Some(walk) = self.traversal.as_mut() {
                    walk.codex_rollout_paths.insert(key);
                }
                return;
            }
            if let Some(a) = self.archives.get_mut(&key) {
                a.transition(change);
            }
        }
    }
    pub(super) fn revert_archive_witness(&mut self, key: &str, previous: &ScanIndex) {
        if self
            .archives
            .get(key)
            .and_then(|a| a.work.as_ref())
            .is_some_and(|w| w.body_witness.is_some())
        {
            match previous.archives.get(key) {
                Some(a) => {
                    self.archives.insert(key.to_owned(), a.clone());
                }
                None => {
                    self.archives.remove(key);
                }
            }
        }
    }
    pub(super) fn archive_refusal(&mut self, path: &Path, error: &anyhow::Error) {
        self.archive_transition(
            path,
            if codex_compressed_input::structural_read_error(error) {
                ArchiveTransition::Structural(CodexZstCause::DecodeFailed)
            } else {
                ArchiveTransition::Transient(CodexZstCause::AdmissionRefused)
            },
        );
    }
    pub(super) fn archive_quiet(&self, key: &str) -> bool {
        self.archives.get(key).is_some_and(|a| {
            a.quiet_disposition()
                && a.work
                    .as_ref()
                    .and_then(|w| w.body_witness.as_ref())
                    .map_or(true, |body| {
                        self.files.get(key).is_some_and(|e| {
                            e.last_upload_body_witness.as_ref() == Some(body)
                                && self.file_snapshot_fingerprints.get(key).is_some_and(|fps| {
                                    !fps.is_empty()
                                        && e.last_snapshot_fingerprint.as_ref()
                                            == Some(&snapshot_file_entity_set_hex(fps))
                                })
                        })
                    })
        })
    }
    pub(super) fn archive_owed_count(&self) -> usize {
        self.archives
            .values()
            .filter(|a| a.owed_cause().is_some())
            .count()
            + self.archive_pass.deferred.len()
    }
    pub(super) fn disclose_archive_debt(&mut self) {
        let mut counts = BTreeMap::<CodexZstCause, usize>::new();
        let mut alarm = 0;
        for a in self.archives.values_mut() {
            if let Some(w) = a.work.as_mut() {
                w.cancel_unopened_header();
            }
            if let Some(cause) = a.owed_cause() {
                *counts.entry(cause).or_default() += 1;
                if let Some(w) = a.work.as_mut() {
                    if w.alarmed != Some(cause) {
                        w.alarmed = Some(cause);
                        alarm += 1;
                    }
                }
            }
        }
        if !self.archive_pass.deferred.is_empty() {
            *counts.entry(CodexZstCause::AdmissionRefused).or_default() +=
                self.archive_pass.deferred.len();
        }
        if self.archive_pass.deferred.len() as u64 != self.archive_deferred_alarm_count {
            alarm += self.archive_pass.deferred.len();
        }
        self.archive_deferred_alarm_count = self.archive_pass.deferred.len() as u64;
        for (cause, count) in counts {
            crate::local_resource_diagnostics::codex_zst_held(cause, count);
        }
        archive_alarm(alarm);
    }
    pub(super) fn hold_archive_corrections(&mut self, context: Option<&str>) {
        let mut count = 0;
        for a in self.archives.values_mut() {
            if matches!(
                a.disposition,
                ArchiveDisposition::Acquired | ArchiveDisposition::Empty
            ) && context.map_or(true, |context| a.context.as_deref() != Some(context))
            {
                a.transition(ArchiveTransition::Correctness(
                    CodexZstCause::CorrectionUnapplied,
                ));
                count += 1;
            }
        }
        archive_alarm(count);
    }
    /// Reuse the ordinary absence owner; uncertainty in any configured root
    /// or inventoried home prevents publishing a uniqueness-dependent body.
    fn archive_fence(
        &self,
        key: &str,
        i: &codex_file_join::HeaderInventory,
    ) -> Result<(), CodexZstCause> {
        i.archive_scope(self)?;
        let h = i
            .archive_headers
            .iter()
            .find(|h| h.candidate.path == Path::new(key))
            .ok_or(CodexZstCause::OwnerUnproven)?;
        if i.archive_headers
            .iter()
            .any(|other| other.owner == h.owner && other.candidate.path != h.candidate.path)
        {
            return Err(CodexZstCause::FamilyUnproven);
        }
        if i.headers
            .iter()
            .any(|other| codex_protected_owner(&other.owner) == h.owner)
        {
            return Err(CodexZstCause::ArchiveEquivalenceUnproven);
        }
        Ok(())
    }
    fn archive_parent_ready(
        &self,
        key: &str,
        validated: Option<&Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    ) -> bool {
        self.archives
            .get(key)
            .and_then(ArchiveEvidence::header)
            .and_then(|h| h.parent.as_ref())
            .map_or(true, |parent| {
                validated
                    .and_then(|map| map.lock().ok())
                    .is_some_and(|map| {
                        map.get(parent).is_some_and(|ledger| {
                            ledger.scan_complete && !ledger.signatures.is_empty()
                        })
                    })
            })
    }
    /// Save one reservation batch for the admitted page, before constructing
    /// any Full reader. Refused resource work remains eligible next pass.
    pub(super) fn prepare_archive_reservations(
        &mut self,
        candidates: &VecDeque<CandidateFile>,
        inventory: &codex_file_join::HeaderInventory,
        budget: &sampled_scan::codex_cursor::PageBudget,
        validated: Option<&Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    ) {
        if self.archive_pass.prepared {
            return;
        }
        self.archive_pass.prepared = true;
        self.archive_pass.started = true;
        for c in candidates.iter().filter(|c| codex_archive_path(&c.path)) {
            let key = local_index_key(&c.path);
            if !self.archives.contains_key(&key) {
                continue;
            }
            if self.archive_quiet(&key) {
                continue;
            }
            if !budget.archive_ready(&self.archive_pass) {
                continue;
            }
            if !self.archive_parent_ready(&key, validated) {
                self.archive_transition(
                    &c.path,
                    ArchiveTransition::Correctness(CodexZstCause::ParentLedgerUnbound),
                );
                continue;
            }
            match self.archive_fence(&key, inventory) {
                Err(cause) => {
                    self.archive_transition(&c.path, ArchiveTransition::Correctness(cause))
                }
                Ok(()) => {
                    let a = self.archives.get_mut(&key).unwrap();
                    if a.work
                        .as_ref()
                        .is_some_and(|w| sampled_scan::now_seconds() < w.retry_after)
                    {
                        continue;
                    }
                    a.transition(ArchiveTransition::Reserve);
                    a.context = self.active_upload_context_fingerprint.clone();
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
        validated: Option<&Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    ) -> Admission {
        let key = local_index_key(&c.path);
        let Some(a) = self.archives.get(&key).filter(|a| a.matches(file)) else {
            self.archive_transition(
                &c.path,
                ArchiveTransition::Correctness(CodexZstCause::OwnerUnproven),
            );
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
            self.archive_transition(
                &c.path,
                ArchiveTransition::Transient(CodexZstCause::AdmissionRefused),
            );
            return Admission::Held;
        }
        if !self.archive_parent_ready(&key, validated) {
            self.archive_transition(
                &c.path,
                ArchiveTransition::Correctness(CodexZstCause::ParentLedgerUnbound),
            );
            return Admission::Held;
        }
        if let Err(cause) = inventory
            .ok_or(CodexZstCause::OwnerUnproven)
            .and_then(|i| self.archive_fence(&key, i))
        {
            self.archive_transition(&c.path, ArchiveTransition::Correctness(cause));
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
        if let Err(cause) = inventory
            .ok_or(CodexZstCause::OwnerUnproven)
            .and_then(|i| self.archive_fence(&key, i))
        {
            self.archive_transition(path, ArchiveTransition::Correctness(cause));
            return false;
        }
        if !self
            .archives
            .get_mut(&key)
            .is_some_and(|a| a.finish(owner, parsed))
        {
            return false;
        }
        true
    }
}
