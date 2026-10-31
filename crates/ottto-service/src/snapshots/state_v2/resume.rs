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
            &index.v2().growth_retention,
        ),
        b"ottto.state-v2.files-preflight.v1\0",
    )
    .context("state_v2_resume_serialize")?;
    Ok(hash.finalize().into())
}
pub(in crate::snapshots) fn publication(entry: &ScanIndexEntry) -> Result<[u8; 16]> {
    use sha2::Digest;
    let mut hash = value_digest_start(1);
    hash.update(codec::json(entry, MUTABLE_VALUE_BYTES)?);
    Ok(integrity(hash))
}
impl ResumeCheckpoint {
    pub(in crate::snapshots) fn validate(
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
    AuthoritativeRemoval,
}
#[derive(Clone, Debug)]
pub(crate) struct FinishProof {
    pub prior: ResumeCheckpoint,
    pub reason: FinishReason,
    pub source_proof: [u8; 32],
    pub settled_dependencies: [u8; 32],
}
impl FinishProof {
    /// Called only at the admitted, revalidated vanished-file removal site.
    /// Ordinary absence/age and unverified-audit retirement have no producer.
    pub(in crate::snapshots) fn authoritative_removal(
        index: &ScanIndex,
        key: &str,
    ) -> Option<Self> {
        use sha2::Digest;
        if !super::super::restart_restore::enabled()
            || !super::state_v2_growth_retention_active(index)
        {
            return None;
        }
        let entry = index.files.get(key)?;
        let prior = index.v2().resume_checkpoints.as_ref()?.get(key)?;
        if super::super::claude_index_path_family_member(std::path::Path::new(key)).is_some_and(
            |(root, _)| {
                index.claude_usage_authority_quarantine.contains_key(&root)
                    || index.claude_account_family_pending.contains_key(&root)
            },
        ) {
            return None;
        }
        if prior.binding.source == super::super::scan_index_persistence::Source::Claude
            && !entry.has_unverified_source()
            && !index.effective_upload_body_witness_revision_requires_adoption(key)
            && !index
                .claude_copy_removals
                .pending(super::super::claude_money_birth_store::location_key(key))
            && !index.decode_holds_file(key)
            && !index.claude_account_deferred_holds.contains_key(key)
            && (super::super::claude_index_file_body_accepted(index, key, entry)
                && super::super::claude_accepted_ledger_is_current(index)
                || index.confirmed_empty_files.contains(key)
                    && index
                        .file_snapshot_fingerprints
                        .get(key)
                        .map_or(true, BTreeSet::is_empty))
            && publication(entry).ok()? == prior.publication
        {
            let source_proof = super::super::serialized_json_digest(
                &(key, prior, index.generation),
                b"ottto.resume.vanished.v1\0",
            )?
            .finalize()
            .into();
            let settled_dependencies = super::super::serialized_json_digest(
                &(
                    prior,
                    index.file_snapshot_fingerprints.get(key),
                    index.confirmed_empty_files.contains(key),
                ),
                b"ottto.resume.settled.v1\0",
            )?
            .finalize()
            .into();
            Some(Self {
                prior: prior.clone(),
                reason: FinishReason::AuthoritativeRemoval,
                source_proof,
                settled_dependencies,
            })
        } else {
            None
        }
    }
}
#[derive(Clone, Default)]
pub(crate) struct StagedCheckpoints {
    /// Actual immutable record bytes fsynced by R1, including replaced records.
    /// The owner reserves these bytes during committable-unit admission.
    pub bytes: u64,
    /// Any excluded key aborts this save; the next selection holds that key.
    pub excluded: BTreeSet<String>,
    pub replacements: BTreeMap<String, ResumeCheckpoint>,
    pub finished: BTreeMap<String, FinishProof>,
}
/// Called BEFORE Store::begin under the source-owner lock. R1 must fsync each
/// immutable file and its directory before returning staging proof. The mapper
/// owns no filesystem handles and never implements a promote step.
pub(crate) trait ResumeHooks {
    fn preflight_import(&self) -> Result<()> {
        Ok(())
    }
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
impl ResumeHooks for NoResumeHooks {
    fn preflight_import(&self) -> Result<()> {
        anyhow::bail!(import::Pause::R1StagingNotInstalled)
    }
}
/// Carries only selection keys to the existing route owner, never to diagnostics.
#[derive(Debug)]
pub(super) struct StageExcluded(
    pub BTreeSet<String>,
    pub BTreeMap<String, u64>,
    pub BTreeSet<String>,
);
impl std::fmt::Display for StageExcluded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("state_v2_resume_stage_excluded")
    }
}
impl std::error::Error for StageExcluded {}

pub(super) struct Prepared {
    pub(super) generation: u64,
    pub(super) signature: [u8; 32],
    pub(super) checkpoints: BTreeMap<String, ResumeCheckpoint>,
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
            &prepared.checkpoints == planned,
            "state_v2_resume_plan_changed"
        );
        Ok(())
    }
    pub(super) fn prepared_checkpoints(&self) -> Option<&BTreeMap<String, ResumeCheckpoint>> {
        self.prepared.as_ref().map(|p| &p.checkpoints)
    }
    #[cfg(test)]
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
        if !staged.excluded.is_empty() {
            return self.prepare_checkpoints(prev, next, staged);
        }
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
        if !staged.excluded.is_empty() {
            telemetry::event("v2_resume_stage_excluded", &(staged.excluded.len() as u64));
            let extents = staged
                .excluded
                .iter()
                .filter_map(|key| {
                    next.files
                        .get(key)
                        .map(|entry| (key.clone(), entry.size_bytes))
                })
                .collect();
            let prior_refs = staged
                .excluded
                .iter()
                .filter(|key| self.committed.contains_key(*key))
                .cloned()
                .collect();
            return Err(StageExcluded(staged.excluded, extents, prior_refs).into());
        }
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
            let entry = next
                .files
                .get(path)
                .context("state_v2_resume_finish_required")?;
            checkpoint.validate(path, entry, next.generation, binding)?;
        }
        // R1 must cover every changed, still-active file, including first admission.
        for (path, entry) in &next.files {
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

crate::heap_layout_bound::fields!(ResumeCheckpoint; record_generation, record_name, trailer_digest, file_generation, committed_bytes, reduction_version, reduction_allowlist, reduction_pin, binding, key_digest, context, scope, entry, publication, certificate);
crate::heap_layout_bound::fields!(Certificate; device, inode, length, modified, birth_nanos, sealed_offset, sample_len, head_sha256, boundary_sha256, verified_unix_seconds, audit_debt_unix_seconds);

crate::heap_layout_bound::fields!(FinishProof; prior, reason, source_proof, settled_dependencies);
impl crate::heap_layout_bound::HeapLayoutBound for FinishReason {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::AuthoritativeRemoval => c.add(0),
        }
    }
}
