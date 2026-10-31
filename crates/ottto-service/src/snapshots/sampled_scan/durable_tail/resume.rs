//! Claude v2 borrows the existing cache/store owner; no parser or store is added.
use super::*;
use crate::snapshots::state_v2::resume::{publication, ResumeCheckpoint, StagedCheckpoints};

impl SharedCache {
    pub(in crate::snapshots) fn initialize_resume_owner(&self, path: &Path) {
        let ready = self.durable().is_some_and(|mut stores| {
            stores
                .slot(DurableSource::ClaudeCode)
                .as_ref()
                .is_some_and(|slot| slot.index_path == path)
        });
        if !ready {
            self.durable_begin_pass(
                SnapshotSource::ClaudeCode,
                path,
                &Scope(String::new()),
                false,
            );
        }
    }

    pub(in crate::snapshots) fn with_resume_store<T>(
        &self,
        path: &Path,
        f: impl FnOnce(&mut DurableTailStore) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut stores = self
            .durable()
            .ok_or_else(|| anyhow::anyhow!("state_v2_resume_owner"))?;
        let slot = stores
            .slot(DurableSource::ClaudeCode)
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("state_v2_resume_owner"))?;
        anyhow::ensure!(slot.index_path == path, "state_v2_resume_owner_path");
        f(&mut slot.store)
    }

    /// Pure planning from the retained native acquisition. Encode once under
    /// the existing codec and retain its bounded bytes until stage completes.
    pub(in crate::snapshots) fn plan_resume(
        &self,
        prev: &ScanIndex,
        next: &ScanIndex,
        binding: &scan_index_persistence::Binding,
        attempt: &str,
    ) -> anyhow::Result<(StagedCheckpoints, Vec<store::ImmutableRecord>)> {
        let source = SnapshotSource::ClaudeCode;
        let ds = DurableSource::ClaudeCode;
        let (namespace, identity_capture, skill_labels_enabled, selected) = {
            let mut stores = self
                .durable()
                .ok_or_else(|| anyhow::anyhow!("state_v2_resume_owner"))?;
            let slot = stores
                .slot(ds)
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("state_v2_resume_owner"))?;
            (
                slot.namespace.clone(),
                slot.identity_capture,
                slot.skill_labels_enabled,
                next.files
                    .keys()
                    .filter_map(|key| {
                        stores
                            .selected
                            .get(key)
                            .map(|fingerprint| (key.clone(), fingerprint.clone()))
                    })
                    .collect::<BTreeMap<_, _>>(),
            )
        };
        let mut staged = StagedCheckpoints::default();
        let mut records = Vec::new();
        let cache = self
            .retained()
            .map_err(|_| anyhow::anyhow!("state_v2_resume_cache"))?;
        for (key, entry) in &next.files {
            if prev.files.get(key).map(publication).transpose()? == Some(publication(entry)?) {
                continue;
            }
            anyhow::ensure!(
                records.len() < store::MAX_BATCH,
                "state_v2_resume_pass_capacity"
            );
            let planned = (|| {
                let retained = cache.peek(key)?;
                let chain = cache.custody(key)?.chain()?;
                if retained.state.source() != source
                    || chain.source() != source
                    || chain.key() != key
                    || selected.get(key).map(String::as_str)
                        != Some(entry.source_file_fingerprint.as_str())
                    || entry.source_file_fingerprint.is_empty()
                    || chain.acquired_revision() != effective_revision(source)
                    || chain.file_scope() != retained.checkpoint.scope()
                    || chain.object().2 != entry.opened_birth_nanos
                    || next.effective_upload_body_witness_revision_requires_adoption(key)
                {
                    return None;
                }
                let interpretation =
                    Interpretation::of(source, key, next, identity_capture, &namespace);
                let mut expected = expected(
                    ds,
                    source,
                    key,
                    retained.checkpoint.scope(),
                    next,
                    &interpretation,
                    None,
                )?;
                let counting = acquired::ImmutableCounting::from_reduction(&retained.state).ok()?;
                expected.binding.entry = [0; 32];
                expected.binding.scope = v3_replay_scope(
                    source,
                    retained.checkpoint.scope(),
                    next,
                    &interpretation,
                    chain.acquired_revision(),
                    &counting,
                );
                let mut certificate = retained.checkpoint.durable_certificate(chain.object().2)?;
                certificate.audit_debt_unix_seconds =
                    sampled_audit::debt_for_key(next, key, certificate.verified_unix_seconds)
                        .map(|d| d.due_unix_seconds);
                let body_limit = store::BODY_BYTES - (store::HEADER_V3_BYTES - store::HEADER_BYTES);
                let body = codec::encode_permitted(
                    &retained.state,
                    body_limit,
                    jsonl_line_cap() as u64,
                    skill_labels_enabled,
                )
                .ok()?;
                Some(store::ImmutableRecord::plan(
                    PendingRecord {
                        binding: expected.binding,
                        certificate,
                        body,
                        allowlist: ds.properties().allowlist(),
                        acquisition: Some(store::AcquisitionFields {
                            acquired_revision: chain.acquired_revision(),
                            protocol: chain.write_protocol(),
                        }),
                    },
                    next.generation,
                    attempt,
                ))
            })();
            let Some(record) = planned else {
                staged.excluded.insert(key.clone());
                continue;
            };
            let certificate = &record.record.certificate;
            let checkpoint = ResumeCheckpoint {
                record_generation: record.generation,
                record_name: record.name.clone(),
                trailer_digest: record.trailer(),
                file_generation: next.generation,
                committed_bytes: certificate.sealed_offset,
                reduction_version: store::FORMAT_V3,
                reduction_allowlist: record.record.allowlist,
                reduction_pin: record
                    .record
                    .acquisition
                    .expect("native acquisition")
                    .acquired_revision
                    .to_le_bytes()
                    .to_vec(),
                binding: binding.clone(),
                key_digest: record.record.binding.key,
                context: record.record.binding.context,
                scope: record.record.binding.scope,
                entry: store::entry_digest(
                    &entry.source_file_fingerprint,
                    entry.last_upload_body_witness.as_deref(),
                ),
                publication: publication(entry)?,
                certificate: super::super::super::state_v2::resume::Certificate {
                    device: certificate.device,
                    inode: certificate.inode,
                    length: certificate.length,
                    modified: certificate.modified,
                    birth_nanos: certificate.birth_nanos,
                    sealed_offset: certificate.sealed_offset,
                    sample_len: certificate.sample_len,
                    head_sha256: certificate.head_sha256,
                    boundary_sha256: certificate.boundary_sha256,
                    verified_unix_seconds: certificate.verified_unix_seconds,
                    audit_debt_unix_seconds: certificate.audit_debt_unix_seconds,
                },
            };
            if checkpoint
                .validate(key, entry, next.generation, binding)
                .is_err()
            {
                staged.excluded.insert(key.clone());
                continue;
            }
            anyhow::ensure!(
                staged.bytes + record.len() <= store::WRITE_PASS_BYTES as u64,
                "state_v2_resume_pass_capacity"
            );
            staged.bytes += record.len();
            staged.replacements.insert(key.clone(), checkpoint);
            records.push(record);
        }
        Ok((staged, records))
    }
}
