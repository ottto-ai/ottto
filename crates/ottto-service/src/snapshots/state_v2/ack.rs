//! Exact ACK receipts precede progress replacement and source-DB settlement.
//! Diagnostic upload_receipts are bounded/truncated and are never recovery proof.
use super::*;
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// Bound before reading/serializing a companion. Overflow holds this source;
// it never evicts accepted bodies to make room for another upload.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    identity: Identity,
    generation: u64,
}
impl Scope {
    fn check(&self, current: &Self) -> Result<()> {
        require(self.identity == current.identity, "identity")?;
        require(
            self.generation >= self.identity.fence_generation
                && self.generation <= current.generation,
            "generation",
        )
    }
}
fn require(ok: bool, reason: &'static str) -> Result<()> {
    if !ok {
        telemetry::event("ack_recovery_hold", &reason);
        anyhow::bail!("state_v2_ack_recovery_hold");
    }
    Ok(())
}

/// Runtime-only. Clones retain the authenticated source scope, not environment
/// switch state. A companion from another DB or a newer recovery set holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRecovery {
    scope: Scope,
    path: PathBuf,
    db_path: Option<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u16,
    scope: Scope,
    previous_generation: u64,
    previous_digest: Option<[u8; 32]>,
    generation: u64,
    digest: [u8; 32],
    // Exact unchanged progress bytes, including cache heads and refusals. Body
    // hashes alone cannot reconstruct those independent settlement outcomes.
    progress: String,
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ottto.state-v2.ack-progress.v1\0");
    hash.update(bytes);
    hash.finalize().into()
}
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(meta) => {
            require(meta.is_file() && !meta.file_type().is_symlink(), "file")?;
            require(meta.len() <= MAX_BYTES, "size")?;
        }
    }
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    require(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "permissions",
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= MAX_BYTES, "size")?;
    Ok(Some(bytes))
}
fn progress_generation(bytes: &[u8]) -> Result<u64> {
    #[derive(Deserialize)]
    struct Generation {
        #[serde(default)]
        generation: u64,
    }
    Ok(serde_json::from_slice::<Generation>(bytes)?.generation)
}
impl ProgressRecovery {
    /// Caller holds the source owner; called before progress decoding/containment.
    /// OFF/v1 and Codex/Pi perform no extra reads, writes or normalization.
    pub(crate) fn for_index(index: &ScanIndex, index_path: &Path) -> Result<Option<Self>> {
        if !state_v2_growth_retention_active(index) {
            return Ok(None);
        }
        guard_external(index_path, index.persistence_v2.as_ref(), index.generation)?;
        let binding = super::super::scan_index_integration::scan_index_storage_binding(index_path)
            .context("state_v2_ack_binding")?;
        let (identity, _) =
            fence::reconcile(index_path, &binding, true)?.context("state_v2_ack_identity")?;
        Ok(Some(Self {
            scope: Scope {
                identity,
                generation: index.generation,
            },
            path: fence::sibling(index_path, ".v2-ack-receipt"),
            db_path: Some(fence::sibling(index_path, ".v2.sqlite")),
        }))
    }

    /// Import must call this under the existing owner/checkpoint locks after
    /// proving the original progress belongs to the source, before publication.
    /// It seals existing bytes without changing the upload-progress store.
    #[allow(dead_code)] // The importer seals custody before publishing its fence.
    pub(super) fn adopt(&self, progress: Option<&[u8]>) -> Result<()> {
        let bytes = progress.unwrap_or(b"{\"generation\":0}");
        require(
            bytes.len() as u64 <= (MAX_BYTES - CONTROL_BYTES) / 6,
            "size",
        )?;
        let generation = progress_generation(bytes)?;
        if read(&self.path)?.is_some() {
            let receipt = self.receipt_at(&self.scope)?;
            require(
                receipt.scope == self.scope
                    && receipt.generation == generation
                    && receipt.digest == digest(bytes),
                "already_bound",
            )?;
            super::super::sync_checkpoint_parent(&self.path)?;
            return Ok(());
        }
        self.write(Receipt {
            version: 1,
            scope: self.scope.clone(),
            previous_generation: generation,
            previous_digest: progress.map(digest),
            generation,
            digest: digest(bytes),
            progress: String::from_utf8(bytes.to_vec())?,
        })
    }

    pub(crate) fn invalid_progress(&self) -> Result<()> {
        require(false, "invalid_progress")
    }

    fn current_scope(&self) -> Result<Scope> {
        let mut scope = self.scope.clone();
        if let Some(path) = &self.db_path {
            scope.generation = sqlite::Sqlite::ack_generation(path, &scope.identity)
                .inspect_err(|_| telemetry::event("ack_recovery_hold", &"source"))?;
            self.scope.check(&scope)?;
        }
        Ok(scope)
    }
    fn receipt(&self) -> Result<Receipt> {
        self.receipt_at(&self.current_scope()?)
    }
    fn receipt_at(&self, scope: &Scope) -> Result<Receipt> {
        let bytes = read(&self.path)?;
        require(bytes.is_some(), "unbound")?;
        let parsed = serde_json::from_slice::<Receipt>(bytes.as_ref().unwrap());
        require(parsed.is_ok(), "receipt")?;
        let receipt = parsed?;
        require(receipt.version == 1, "version")?;
        receipt.scope.check(scope)?;
        require(
            receipt.digest == digest(receipt.progress.as_bytes())
                && progress_generation(receipt.progress.as_bytes())? == receipt.generation
                && (receipt.previous_generation == receipt.generation
                    || receipt.previous_generation.checked_add(1) == Some(receipt.generation)),
            "receipt",
        )?;
        Ok(receipt)
    }
    fn write(&self, receipt: Receipt) -> Result<()> {
        // JSON escaping costs at most 6x its input, so admit before allocation.
        require(
            receipt.progress.len() as u64 <= (MAX_BYTES - CONTROL_BYTES) / 6,
            "size",
        )?;
        let bytes = serde_json::to_vec(&receipt)?;
        require(bytes.len() as u64 <= MAX_BYTES, "size")?;
        ottto_core::write_owner_only_file_atomic(&self.path, &bytes)?;
        super::super::sync_checkpoint_parent(&self.path)?;
        Ok(())
    }

    /// Newer exact receipts are reconciled BEFORE any source-DB handoff. Both
    /// old and new progress bytes may be visible around rename/fsync failure;
    /// no third value, missing historical ledger or same-generation fork is
    /// inferred to be safe. Failed recovery stops collection without quarantine.
    pub(crate) fn recover(&self, progress_path: &Path) -> Result<()> {
        let receipt = self.receipt()?;
        super::super::sync_checkpoint_parent(&self.path)?;
        let current = read(progress_path)?;
        if current.as_deref().map(digest) == Some(receipt.digest) {
            // Retry the durability barrier even after a visible failed rename.
            super::super::sync_checkpoint_parent(progress_path)?;
            return Ok(());
        }
        require(
            current.as_deref().map(digest) == receipt.previous_digest
                && current
                    .as_deref()
                    .map(progress_generation)
                    .transpose()?
                    .unwrap_or(0)
                    == receipt.previous_generation,
            "progress",
        )?;
        // An adopted missing ledger is only a binding marker, not progress.
        if receipt.generation == 0 && receipt.previous_digest.is_none() {
            return Ok(());
        }
        ottto_core::write_owner_only_file_atomic(progress_path, receipt.progress.as_bytes())?;
        super::super::sync_checkpoint_parent(progress_path)?;
        telemetry::event("ack_receipt_reconciled", &1);
        Ok(())
    }

    /// Called inside the existing progress CAS lock, after the exact response
    /// has been validated. Failure creates no index acceptance/retirement.
    pub(crate) fn before_progress_save(&self, previous: Option<&[u8]>, next: &[u8]) -> Result<()> {
        let scope = self.current_scope()?;
        let receipt = self.receipt_at(&scope)?;
        require(
            previous.map(digest) == Some(receipt.digest)
                || (receipt.generation == 0
                    && receipt.previous_digest.is_none()
                    && previous.is_none()),
            "progress",
        )?;
        let previous_generation = previous.map(progress_generation).transpose()?.unwrap_or(0);
        let generation = progress_generation(next)?;
        require(next.len() as u64 <= (MAX_BYTES - CONTROL_BYTES) / 6, "size")?;
        require(
            previous_generation.checked_add(1) == Some(generation),
            "progress_generation",
        )?;
        self.write(Receipt {
            version: 1,
            scope,
            previous_generation,
            previous_digest: previous.map(digest),
            generation,
            digest: digest(next),
            progress: String::from_utf8(next.to_vec())?,
        })
    }
}

crate::heap_layout_bound::fields!(ProgressRecovery; scope, path, db_path);
crate::heap_layout_bound::fields!(Scope; identity, generation);
impl crate::heap_layout_bound::HeapLayoutBound for Identity {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        self.db_id.heap_bound(c)?;
        self.binding.namespace_hash.heap_bound(c)
    }
}

/// Exact recovery-set descriptor for a consistent DB backup plus its external
/// progress receipt and immutable restart references. A restore must reconcile
/// newer receipts first, then verify this descriptor before collection/GC.
/// No age, filename prefix or body hash can stand in for a missing member.
#[allow(dead_code)] // Import/backup owner calls this before publication is enabled.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoverySet {
    scope: Scope,
    receipt_digest: [u8; 32],
    resume: Vec<ResumeReference>,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeReference {
    key: Vec<u8>,
    position: u64,
    digest: [u8; 32],
}
fn control<T: serde::de::DeserializeOwned>(tx: &mut dyn Transaction, name: &str) -> Result<T> {
    let header = tx
        .get(&RowKey::Meta(name.into()))?
        .context("state_v2_ack_control")?;
    require(header.len <= CONTROL_BYTES, "control")?;
    let mut bytes = Vec::new();
    tx.read_value(&header, &mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
#[allow(dead_code)]
impl RecoverySet {
    /// Caller holds source ownership and one read snapshot through backup.
    pub(super) fn capture(
        tx: &mut dyn Transaction,
        recovery: &ProgressRecovery,
        progress_path: &Path,
    ) -> Result<Self> {
        let scope = Scope {
            identity: control(tx, "identity")?,
            generation: control(tx, "generation")?,
        };
        recovery.scope.check(&scope)?;
        let receipt = recovery.receipt()?;
        receipt.scope.check(&scope)?;
        let progress = read(progress_path)?;
        require(
            progress.as_deref().map(digest) == Some(receipt.digest)
                || (receipt.generation == 0
                    && receipt.previous_digest.is_none()
                    && progress.is_none()),
            "backup_progress",
        )?;
        let mut resume = Vec::new();
        let mut after = None;
        let mut charged = 0_u64;
        loop {
            let page = tx.scan_kind(
                &RecordKind::parse("resume.checkpoint")?,
                after.as_ref(),
                128,
            )?;
            if page.is_empty() {
                break;
            }
            for header in &page {
                let RowKey::Record {
                    key_bytes,
                    position,
                    ..
                } = &header.key
                else {
                    anyhow::bail!("state_v2_ack_resume_key");
                };
                charged = charged.saturating_add(key_bytes.len() as u64 + 128);
                require(
                    charged <= 8 * 1024 * 1024 && resume.len() < 65_536,
                    "backup_size",
                )?;
                // Consume the exact reference to verify chunks as well as headers.
                struct Sink(sha2::Sha256);
                impl Write for Sink {
                    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                        self.0.update(bytes);
                        Ok(bytes.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                let mut sink = Sink(Sha256::new());
                tx.read_value(header, &mut sink)?;
                resume.push(ResumeReference {
                    key: key_bytes.clone(),
                    position: *position,
                    digest: sink.0.finalize().into(),
                });
            }
            after = page.last().map(|h| h.key.clone());
        }
        Ok(Self {
            scope,
            receipt_digest: digest(&serde_json::to_vec(&receipt)?),
            resume,
        })
    }

    pub(super) fn verify(
        &self,
        tx: &mut dyn Transaction,
        recovery: &ProgressRecovery,
        progress_path: &Path,
    ) -> Result<()> {
        let actual = Self::capture(tx, recovery, progress_path)?;
        require(*self == actual, "recovery_set")
    }
}

#[cfg(test)]
impl ProgressRecovery {
    pub(crate) fn synthetic(index_path: &Path, namespace: &str, generation: u64) -> Self {
        Self {
            scope: Scope {
                identity: Identity {
                    format: FORMAT,
                    db_id: "synthetic-ack-db".into(),
                    binding: super::super::scan_index_persistence::Binding {
                        source: super::super::scan_index_persistence::Source::Claude,
                        namespace_hash: namespace.into(),
                    },
                    fence_generation: 0,
                },
                generation,
            },
            path: fence::sibling(index_path, ".v2-ack-receipt"),
            db_path: None,
        }
    }
    pub(crate) fn adopt_synthetic(&self, progress: Option<&[u8]>) {
        self.adopt(progress).unwrap();
    }
}

#[cfg(test)]
#[path = "ack_tests.rs"]
mod tests;

#[allow(dead_code)] // Called by the import owner after proving original custody.
impl ProgressRecovery {
    pub(super) fn seal_import(
        identity: Identity,
        generation: u64,
        index_path: &Path,
        progress: Option<&[u8]>,
    ) -> Result<Self> {
        require(
            identity.format == FORMAT && generation >= identity.fence_generation,
            "generation",
        )?;
        require(
            identity.binding.source == super::super::scan_index_persistence::Source::Claude,
            "source",
        )?;
        let recovery = Self {
            scope: Scope {
                identity,
                generation,
            },
            path: fence::sibling(index_path, ".v2-ack-receipt"),
            db_path: Some(fence::sibling(index_path, ".v2.sqlite")),
        };
        recovery.adopt(progress)?;
        Ok(recovery)
    }
}
