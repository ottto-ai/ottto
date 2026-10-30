//! Source-owner restart custody. R1 supplies immutable records; the mapper
//! validates publication under the same owner lock and never promotes files.
use super::super::ScanIndexEntry;
use super::*;
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
/// Exact immutable record reference. No reduction/body bytes enter SQLite.
/// `publication` commits the entire file.progress value, including raw presence;
/// the certificate, interpretation pin and scope remain R1's checked inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResumeCheckpoint {
    pub record_generation: u64,
    pub record_name: String,
    pub trailer_digest: [u8; 32],
    pub file_generation: u64,
    pub committed_bytes: u64,
    pub reduction_version: u16,
    pub reduction_allowlist: [u8; 32],
    pub reduction_pin: Vec<u8>,
    pub binding: super::super::scan_index_persistence::Binding,
    pub key_digest: [u8; 32],
    pub context: [u8; 32],
    pub scope: [u8; 32],
    pub entry: [u8; 32],
    pub publication: [u8; 16],
    pub certificate: Certificate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Certificate {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub modified: (i64, i64),
    pub birth_nanos: u64,
    pub sealed_offset: u64,
    pub sample_len: u32,
    pub head_sha256: [u8; 32],
    pub boundary_sha256: [u8; 32],
    pub verified_unix_seconds: u64,
    pub audit_debt_unix_seconds: Option<u64>,
}
pub(super) fn files_signature(index: &ScanIndex) -> Result<[u8; 32]> {
    use sha2::Digest;
    let hash = super::super::serialized_json_digest(
        &(
            &index.files,
            &index.file_snapshot_fingerprints,
            &index.snapshot_activity_at,
            &index.confirmed_empty_files,
            &index.terminal_jsonl_dispositions,
            &index.claude_desktop_title_files,
            &index.growth_retention,
        ),
        b"ottto.state-v2.files-preflight.v1\0",
    )
    .context("state_v2_resume_serialize")?;
    Ok(hash.finalize().into())
}
fn publication(entry: &ScanIndexEntry) -> Result<[u8; 16]> {
    use sha2::Digest;
    let mut hash = value_digest_start(1);
    hash.update(codec::json(entry, MUTABLE_VALUE_BYTES)?);
    Ok(integrity(hash))
}
impl ResumeCheckpoint {
    pub(super) fn validate(
        &self,
        path: &str,
        entry: &ScanIndexEntry,
        generation: u64,
        binding: &super::super::scan_index_persistence::Binding,
    ) -> Result<()> {
        ensure!(&self.binding == binding, "state_v2_resume_binding");
        ensure!(
            self.record_generation > 0
                && self.record_generation == self.file_generation
                && self.file_generation <= generation
                && self.reduction_version > 0
                && !self.reduction_pin.is_empty()
                && self.reduction_pin.len() <= KEY_BYTES,
            "state_v2_resume_generation_pin"
        );
        ensure!(
            self.committed_bytes <= entry.size_bytes
                && self.certificate.length == entry.size_bytes
                && self.certificate.sealed_offset == self.committed_bytes
                && self.certificate.birth_nanos == entry.opened_birth_nanos
                && self.publication == publication(entry)?,
            "state_v2_resume_extent_entry"
        );
        ensure!(
            u64::try_from(self.certificate.modified.0).ok() == Some(entry.modified_unix_seconds)
                && (0..1_000_000_000).contains(&self.certificate.modified.1)
                && entry.modified_unix_nanos.map_or(true, |ns| {
                    entry
                        .modified_unix_seconds
                        .checked_mul(1_000_000_000)
                        .and_then(|sec| sec.checked_add(self.certificate.modified.1 as u64))
                        == Some(ns)
                })
                && u64::from(self.certificate.sample_len) == self.committed_bytes.min(4096),
            "state_v2_resume_certificate"
        );
        #[cfg(unix)]
        {
            use crate::durable_tail_store::{key_digest, DurableSource};
            let source = match binding.source {
                super::super::scan_index_persistence::Source::Claude => DurableSource::ClaudeCode,
                super::super::scan_index_persistence::Source::Codex => DurableSource::Codex,
                super::super::scan_index_persistence::Source::Pi => {
                    anyhow::bail!("state_v2_resume_source")
                }
            };
            ensure!(
                self.entry
                    == crate::durable_tail_store::entry_digest(
                        &entry.source_file_fingerprint,
                        entry.last_upload_body_witness.as_deref()
                    ),
                "state_v2_resume_entry_binding"
            );
            ensure!(
                self.key_digest == key_digest(source, path),
                "state_v2_resume_key"
            );
        }
        let digest = self
            .key_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let prefix = format!("{digest}.{}.", self.record_generation);
        let attempt = self
            .record_name
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".rec"))
            .context("state_v2_resume_name")?;
        ensure!(
            !attempt.is_empty()
                && attempt.len() <= 128
                && attempt
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "state_v2_resume_name"
        );
        Ok(())
    }
}

/// The caller supplies a source-authoritative, dependency-settled finish proof;
/// age, ACK and ordinary pass completion have no representation in this API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FinishReason {
    IrreversibleTerminal,
    AuthoritativeRemoval,
}
#[derive(Clone, Debug)]
pub(crate) struct FinishProof {
    pub prior: ResumeCheckpoint,
    pub reason: FinishReason,
    pub source_proof: [u8; 32],
    pub settled_dependencies: [u8; 32],
}
#[derive(Default)]
pub(crate) struct StagedCheckpoints {
    /// Actual immutable record bytes fsynced by R1, including replaced records.
    /// The owner reserves these bytes during committable-unit admission.
    pub bytes: u64,
    /// Per-file staging failures keep their prior committed ref and progress.
    pub excluded: BTreeSet<String>,
    pub replacements: BTreeMap<String, ResumeCheckpoint>,
    pub finished: BTreeMap<String, FinishProof>,
}
/// Called BEFORE Store::begin under the source-owner lock. R1 must fsync each
/// immutable file and its directory before returning staging proof. The mapper
/// owns no filesystem handles and never implements a promote step.
pub(crate) trait ResumeHooks {
    fn on_open(
        &mut self,
        generation: u64,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<()> {
        let _ = (generation, current);
        Ok(())
    }
    /// Pure candidate planning: exact intended refs and a byte reservation.
    /// No files are written here; stage must return these exact refs after
    /// selection, or the transaction refuses before publication.
    fn plan(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<StagedCheckpoints> {
        let _ = (prev, next, current);
        Ok(StagedCheckpoints::default())
    }
    /// Admit the selected output before any staging side effect.
    fn preflight_selected(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<u64> {
        let _ = (prev, next, current);
        Ok(0)
    }
    fn stage(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<StagedCheckpoints> {
        let _ = (prev, next, current);
        Ok(StagedCheckpoints::default())
    }
    /// Same owner lock, only after an unambiguous durable commit. R1 protects
    /// current, staging, predecessor, backup and unresolved recovery roots.
    fn post_commit(
        &mut self,
        generation: u64,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<()> {
        let _ = (generation, current);
        Ok(())
    }
}
/// A buildable seam before R1 installs its adapter. Preflight still refuses
/// advancing an active file without a freshly staged reference.
pub(super) struct NoResumeHooks;
impl ResumeHooks for NoResumeHooks {}
pub(super) struct Prepared {
    pub(super) generation: u64,
    pub(super) signature: [u8; 32],
    pub(super) checkpoints: BTreeMap<String, ResumeCheckpoint>,
    excluded: BTreeSet<String>,
}

impl KindCx {
    pub(super) fn check_planned_checkpoints(
        &self,
        planned: Option<&BTreeMap<String, ResumeCheckpoint>>,
    ) -> Result<()> {
        let prepared = self
            .prepared
            .as_ref()
            .context("state_v2_resume_preflight_required")?;
        let planned = planned.context("state_v2_resume_plan_required")?;
        ensure!(
            prepared
                .checkpoints
                .iter()
                .filter(|(key, _)| !prepared.excluded.contains(*key))
                .eq(planned
                    .iter()
                    .filter(|(key, _)| !prepared.excluded.contains(*key))),
            "state_v2_resume_plan_changed"
        );
        Ok(())
    }
    pub(super) fn retain_excluded(&mut self, prev: &ScanIndex, next: &mut ScanIndex) -> Result<()> {
        let Some(prepared) = &mut self.prepared else {
            return Ok(());
        };
        for path in &prepared.excluded {
            macro_rules! restore_map {
                ($field:ident) => {
                    match prev.$field.get(path) {
                        Some(value) => {
                            next.$field.insert(path.clone(), value.clone());
                        }
                        None => {
                            next.$field.remove(path);
                        }
                    }
                };
            }
            next.claude_request_census.remove(path);
            if let Some(record) = prev.claude_request_census.storage_records().get(path) {
                ensure!(
                    next.claude_request_census
                        .storage_insert(path.clone(), record.clone()),
                    "state_v2_resume_excluded_census"
                );
            }
            restore_map!(files);
            restore_map!(file_snapshot_fingerprints);
            restore_map!(terminal_jsonl_dispositions);
            restore_map!(growth_retention);
            restore_map!(claude_desktop_title_files);
            if prev.confirmed_empty_files.contains(path) {
                next.confirmed_empty_files.insert(path.clone());
            } else {
                next.confirmed_empty_files.remove(path);
            }
        }
        if !prepared.excluded.is_empty() {
            telemetry::event(
                "v2_resume_stage_excluded",
                &(prepared.excluded.len() as u64),
            );
        }
        prepared.signature = files_signature(next)?;
        Ok(())
    }

    pub(super) fn prepared_checkpoints(&self) -> Option<&BTreeMap<String, ResumeCheckpoint>> {
        self.prepared.as_ref().map(|p| &p.checkpoints)
    }
    pub(super) fn checkpoints(&self) -> &BTreeMap<String, ResumeCheckpoint> {
        &self.committed
    }
    pub(super) fn preflight_selected(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        selection: &units::Selection,
        hooks: &mut dyn ResumeHooks,
    ) -> Result<()> {
        ensure!(
            self.binding.as_ref() == Some(&selection.identity.binding)
                && prev.generation == selection.generation
                && prev.generation.checked_add(1) == Some(next.generation),
            "state_v2_resume_selected_generation"
        );
        let selected: BTreeSet<_> = selection.keys().collect();
        for path in prev.files.keys().chain(next.files.keys()) {
            if prev.files.get(path).map(publication).transpose()?
                != next.files.get(path).map(publication).transpose()?
            {
                ensure!(
                    selected.contains(&mapper::key("file.progress", path, 1)?),
                    "state_v2_resume_unselected_file"
                );
            }
        }
        let bytes = hooks.preflight_selected(prev, next, &self.committed)?;
        ensure!(
            bytes <= selection.staging_bytes(),
            "state_v2_resume_staging_admission"
        );
        self.preflight_reserved(prev, next, hooks, bytes)
    }
    pub(super) fn preflight(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        hooks: &mut dyn ResumeHooks,
    ) -> Result<()> {
        self.preflight_reserved(prev, next, hooks, 0)
    }
    pub(super) fn preflight_reserved(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        hooks: &mut dyn ResumeHooks,
        reserved_staging_bytes: u64,
    ) -> Result<()> {
        ensure!(
            !self.ambiguous && self.prepared.is_none(),
            "state_v2_resume_reopen_required"
        );
        self.require_preflight = true;
        let staged = hooks.stage(prev, next, &self.committed)?;
        ensure!(
            staged.bytes <= reserved_staging_bytes
                && (staged.replacements.is_empty() || staged.bytes > 0),
            "state_v2_resume_staging_admission"
        );
        self.prepare_checkpoints(prev, next, staged)
    }
    pub(super) fn prepare_plan(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        hooks: &mut dyn ResumeHooks,
    ) -> Result<u64> {
        let staged = hooks.plan(prev, next, &self.committed)?;
        let bytes = staged.bytes;
        self.prepare_checkpoints(prev, next, staged)?;
        Ok(bytes)
    }
    fn prepare_checkpoints(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        staged: StagedCheckpoints,
    ) -> Result<()> {
        ensure!(
            staged
                .excluded
                .iter()
                .all(|p| !staged.replacements.contains_key(p) && !staged.finished.contains_key(p)),
            "state_v2_resume_excluded_proof"
        );
        let binding = self.binding.as_ref().context("state_v2_resume_binding")?;
        let mut checkpoints = self.committed.clone();
        let finished_paths: BTreeSet<_> = staged.finished.keys().cloned().collect();
        for (path, proof) in staged.finished {
            ensure!(
                checkpoints.get(&path) == Some(&proof.prior)
                    && !staged.replacements.contains_key(&path),
                "state_v2_resume_finish_proof"
            );
            ensure!(
                proof.source_proof != [0; 32] && proof.settled_dependencies != [0; 32],
                "state_v2_resume_finish_proof"
            );
            if proof.reason == FinishReason::AuthoritativeRemoval {
                ensure!(
                    !next.files.contains_key(&path),
                    "state_v2_resume_removal_present"
                );
            }
            // Proofs are exact-reference tokens from R1/source custody, not booleans.
            checkpoints.remove(&path);
        }
        for (path, checkpoint) in staged.replacements {
            let entry = next.files.get(&path).context("state_v2_resume_orphan")?;
            checkpoint.validate(&path, entry, next.generation, binding)?;
            ensure!(
                checkpoint.file_generation == next.generation,
                "state_v2_resume_staging_generation"
            );
            if let Some(old) = self.committed.get(&path) {
                ensure!(
                    old.record_name != checkpoint.record_name || old == &checkpoint,
                    "state_v2_resume_mutable_name"
                );
                if prev.files.get(&path).map(publication).transpose()? == Some(publication(entry)?)
                {
                    ensure!(old == &checkpoint, "state_v2_resume_unchanged_replaced");
                }
            }
            checkpoints.insert(path, checkpoint);
        }
        for (path, checkpoint) in &checkpoints {
            let source = if staged.excluded.contains(path) {
                prev
            } else {
                next
            };
            let entry = source
                .files
                .get(path)
                .context("state_v2_resume_finish_required")?;
            checkpoint.validate(path, entry, next.generation, binding)?;
        }
        // R1 must cover every changed, still-active file, including first admission.
        for (path, entry) in &next.files {
            if staged.excluded.contains(path) {
                continue;
            }
            if prev.files.get(path).map(publication).transpose()? != Some(publication(entry)?) {
                ensure!(
                    checkpoints.contains_key(path) || finished_paths.contains(path),
                    "state_v2_resume_stage_required"
                );
            }
        }
        self.prepared = Some(Prepared {
            generation: next.generation,
            signature: files_signature(next)?,
            checkpoints,
            excluded: staged.excluded,
        });
        Ok(())
    }
    pub(super) fn post_commit(
        &mut self,
        outcome: &DurableCommitOutcome,
        hooks: &mut dyn ResumeHooks,
    ) -> Result<()> {
        match outcome {
            DurableCommitOutcome::Committed(generation) => {
                if self.prepared.as_ref().map(|p| p.generation) != Some(*generation) {
                    self.ambiguous = true;
                    anyhow::bail!("state_v2_resume_commit_generation");
                }
                let prepared = self
                    .prepared
                    .take()
                    .context("state_v2_resume_preflight_required")?;
                self.committed = prepared.checkpoints;
                let result = hooks.post_commit(*generation, &self.committed);
                if result.is_err() {
                    self.ambiguous = true;
                }
                result
            }
            DurableCommitOutcome::Published(_) | DurableCommitOutcome::Ambiguous => {
                self.ambiguous = true;
                anyhow::bail!("state_v2_resume_reopen_required")
            }
            DurableCommitOutcome::NotPublished => {
                self.prepared = None;
                // Encoders update resident headers before COMMIT. Even a
                // definite rollback needs a fresh context before another save.
                self.ambiguous = true;
                Ok(())
            }
        }
    }
}
