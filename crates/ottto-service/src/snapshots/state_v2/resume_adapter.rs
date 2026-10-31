//! Transaction adapter over the source's existing durable-tail store.
use super::super::sampled_scan::SharedCache;
use super::resume::{ResumeCheckpoint, ResumeHooks, StagedCheckpoints};
use super::*;
use crate::durable_tail_store::{self as tail, ImmutableRecord, MutationWitness, RetireOutcome};
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(in crate::snapshots) struct Adapter {
    cache: Arc<SharedCache>,
    path: PathBuf,
    binding: super::super::scan_index_persistence::Binding,
    attempt: String,
    planned: Option<StagedCheckpoints>,
    records: Vec<ImmutableRecord>,
    prior: BTreeMap<String, ResumeCheckpoint>,
    signature: Option<[u8; 32]>,
    admitted: bool,
    lease: Option<tail::ActiveLease>,
}
impl Adapter {
    pub(in crate::snapshots) fn new(
        cache: Arc<SharedCache>,
        path: &Path,
        binding: super::super::scan_index_persistence::Binding,
    ) -> Result<Self> {
        ensure!(
            super::super::restart_restore::enabled(),
            "state_v2_resume_disabled"
        );
        ensure!(
            binding.source == super::super::scan_index_persistence::Source::Claude,
            "state_v2_resume_source"
        );
        // One existing active lease funds the retained encoded batch plus its
        // encoding/verification overlap. No state survives on the retained cache.
        let tail::LeaseWait::Granted(lease) = cache.acquire_active(
            super::super::SnapshotSource::ClaudeCode,
            tail::WRITE_PASS_BYTES as u64 + tail::RESTORE_INPUT_BYTES,
        ) else {
            anyhow::bail!("state_v2_resume_active_budget");
        };
        let mut nonce = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        Ok(Self {
            cache,
            path: path.to_owned(),
            binding,
            attempt: nonce.iter().map(|b| format!("{b:02x}")).collect(),
            planned: None,
            records: Vec::new(),
            prior: BTreeMap::new(),
            signature: None,
            admitted: false,
            lease: Some(lease),
        })
    }
    fn with_store<T>(&self, f: impl FnOnce(&mut tail::DurableTailStore) -> Result<T>) -> Result<T> {
        self.cache.with_resume_store(&self.path, f)
    }
    fn verify(checkpoint: &ResumeCheckpoint, record: &tail::DurableRecord) -> Result<()> {
        let r = &record.record;
        let c = &checkpoint.certificate;
        ensure!(
            record.index_generation == checkpoint.record_generation
                && record.trailer_digest() == Some(checkpoint.trailer_digest)
                && record.format == checkpoint.reduction_version
                && r.allowlist == checkpoint.reduction_allowlist
                && r.acquisition
                    .is_some_and(|a| a.acquired_revision.to_le_bytes().as_slice()
                        == checkpoint.reduction_pin)
                && r.binding.key == checkpoint.key_digest
                && r.binding.context == checkpoint.context
                && r.binding.scope == checkpoint.scope
                && r.certificate.device == c.device
                && r.certificate.inode == c.inode
                && r.certificate.length == c.length
                && r.certificate.modified == c.modified
                && r.certificate.birth_nanos == c.birth_nanos
                && r.certificate.sealed_offset == c.sealed_offset
                && r.certificate.sample_len == c.sample_len
                && r.certificate.head_sha256 == c.head_sha256
                && r.certificate.boundary_sha256 == c.boundary_sha256
                && r.certificate.verified_unix_seconds == c.verified_unix_seconds
                && record.envelope_audit_debt == c.audit_debt_unix_seconds,
            "state_v2_resume_exact_record"
        );
        Ok(())
    }
    pub(in crate::snapshots) fn restore(
        store: &mut tail::DurableTailStore,
        checkpoint: &ResumeCheckpoint,
    ) -> Result<Box<tail::DurableRecord>> {
        let result = (|| {
            let (record, _) = store
                .read_immutable(&checkpoint.record_name, &checkpoint.key_digest)
                .map_err(|_| anyhow::anyhow!("state_v2_resume_reference_unresolved"))?;
            Self::verify(checkpoint, &record)?;
            Ok(record)
        })();
        result.inspect_err(|_| super::telemetry::event("v2_resume_reference_unresolved", &1))
    }
}
impl ResumeHooks for Adapter {
    fn on_open(
        &mut self,
        generation: u64,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<()> {
        self.with_store(|store| {
            let writer = crate::locked_state_dir::held_for(&tail::store_dir_for_index(&self.path))
                .context("state_v2_resume_writer")?;
            // Retry a prior unlink barrier even if the retired path is absent.
            store.flush_immutable(writer)?;
            for checkpoint in current.values() {
                ensure!(
                    checkpoint.binding == self.binding
                        && checkpoint.record_generation <= generation,
                    "state_v2_resume_reference_binding"
                );
                Self::restore(store, checkpoint)?;
            }
            Ok(())
        })?;
        self.prior = current.clone();
        Ok(())
    }
    fn plan(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<StagedCheckpoints> {
        ensure!(self.planned.is_none(), "state_v2_resume_plan_reused");
        let (planned, records) =
            self.cache
                .plan_resume(prev, next, &self.binding, &self.attempt)?;
        self.signature = Some(super::resume::files_signature(next)?);
        self.prior = current.clone();
        self.records = records;
        self.planned = Some(planned.clone());
        Ok(planned)
    }
    fn preflight_selected(
        &mut self,
        _: &ScanIndex,
        next: &ScanIndex,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<u64> {
        ensure!(
            self.signature == Some(super::resume::files_signature(next)?) && &self.prior == current,
            "state_v2_resume_plan_changed"
        );
        let planned = self
            .planned
            .as_ref()
            .context("state_v2_resume_plan_required")?;
        self.with_store(|store| {
            let writer = crate::locked_state_dir::held_for(&tail::store_dir_for_index(&self.path))
                .context("state_v2_resume_writer")?;
            store.admit_immutable(
                writer,
                planned.bytes,
                current.iter().map(|(key, r)| {
                    (
                        r.key_digest,
                        r.record_name.clone(),
                        planned.replacements.contains_key(key),
                    )
                }),
            )?;
            Ok(())
        })?;
        self.admitted = true;
        Ok(planned.bytes)
    }
    fn stage(
        &mut self,
        _: &ScanIndex,
        next: &ScanIndex,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<StagedCheckpoints> {
        ensure!(
            self.admitted
                && self.signature == Some(super::resume::files_signature(next)?)
                && &self.prior == current,
            "state_v2_resume_admission_required"
        );
        let mut staged = self
            .planned
            .take()
            .context("state_v2_resume_plan_required")?;
        // Metadata drift belongs to this file; filesystem/write/fsync failures
        // belong to the store and refuse the entire transaction.
        for (key, checkpoint) in &staged.replacements {
            let metadata = match std::fs::symlink_metadata(key) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            let matches = metadata.is_some_and(|m| {
                use std::os::unix::fs::MetadataExt;
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.dev() == checkpoint.certificate.device
                    && m.ino() == checkpoint.certificate.inode
                    && crate::transcript_acquisition::birth_unix_nanos(&m)
                        == checkpoint.certificate.birth_nanos
                    && m.len() == checkpoint.certificate.length
                    && (m.mtime(), m.mtime_nsec()) == checkpoint.certificate.modified
            });
            if !matches {
                staged.excluded.insert(key.clone());
            }
        }
        if !staged.excluded.is_empty() {
            return Ok(staged);
        }
        self.with_store(|store| {
            let writer = crate::locked_state_dir::held_for(&tail::store_dir_for_index(&self.path))
                .context("state_v2_resume_writer")?;
            for record in &self.records {
                store.stage_immutable(writer, record)?;
            }
            Ok(())
        })?;
        Ok(staged)
    }
    fn post_commit(
        &mut self,
        generation: u64,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<()> {
        ensure!(
            current.values().all(|r| r.record_generation <= generation),
            "state_v2_resume_commit_generation"
        );
        let keep: BTreeSet<_> = current.values().map(|r| r.record_name.as_str()).collect();
        self.with_store(|store| {
            let writer = crate::locked_state_dir::held_for(&tail::store_dir_for_index(&self.path))
                .context("state_v2_resume_writer")?;
            for checkpoint in self
                .prior
                .values()
                .filter(|r| !keep.contains(r.record_name.as_str()))
            {
                let (record, proof): (_, MutationWitness) = store
                    .read_immutable(&checkpoint.record_name, &checkpoint.key_digest)
                    .map_err(|_| anyhow::anyhow!("state_v2_resume_gc_reference"))?;
                Self::verify(checkpoint, &record)?;
                let mut sync_due = false;
                ensure!(
                    matches!(
                        store.retire_immutable(
                            writer,
                            &checkpoint.record_name,
                            &proof,
                            &mut sync_due
                        ),
                        RetireOutcome::Retired
                    ),
                    "state_v2_resume_gc_retry"
                );
            }
            store.gc_immutable(writer, generation, &keep)?;
            store.flush_immutable(writer)?;
            Ok(())
        })
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.records.clear();
        if let Some(lease) = self.lease.take() {
            lease.release();
        }
    }
}
