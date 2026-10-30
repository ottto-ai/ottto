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
    read_limited(path, MAX_BYTES)
}
fn read_limited(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(meta) => {
            require(meta.is_file() && !meta.file_type().is_symlink(), "file")?;
            require(meta.len() <= limit, "size")?;
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
    file.take(limit + 1).read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= limit, "size")?;
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
/// Bounded temporary custody for an obsolete, provably unpublished seal. Keep
/// exact predecessor bytes until a new seal + RecoverySet have been verified.
/// A crash leaves both copies, never an overwritten companion. New successful
/// sealing removes these remnants under the same progress/checkpoint owners.
fn failed_imports(index_path: &Path) -> Result<Vec<PathBuf>> {
    let parent = index_path.parent().context("state_v2_ack_parent")?;
    let prefix = fence::sibling(index_path, ".v2-ack-receipt.failed-import-");
    let prefix = prefix
        .file_name()
        .and_then(|s| s.to_str())
        .context("state_v2_ack_name")?;
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .and_then(|s| s.strip_prefix(prefix))
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            require(paths.len() < 8, "failed_import_capacity")?;
            paths.push(entry.path());
        }
    }
    Ok(paths)
}
pub(super) fn failed_import_inventory(index_path: &Path) -> Result<(u64, u64)> {
    let mut count = 0;
    let mut bytes = 0_u64;
    for path in failed_imports(index_path)? {
        count += 1;
        bytes = bytes
            .checked_add(std::fs::symlink_metadata(path)?.len())
            .context("state_v2_ack_size")?;
    }
    Ok((count, bytes))
}
pub(super) fn erase_failed_imports(index_path: &Path) -> Result<()> {
    for path in failed_imports(index_path)? {
        std::fs::remove_file(path)?;
    }
    super::super::sync_checkpoint_parent(index_path)
}
fn preserve_failed_import(index_path: &Path, companion: &Path, bytes: &[u8]) -> Result<()> {
    let suffix: String = digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
    let target = fence::sibling(
        index_path,
        &format!(".v2-ack-receipt.failed-import-{suffix}"),
    );
    if let Some(existing) = read(&target)? {
        if existing != bytes {
            // An interrupted copy is redundant with the complete, still-owned
            // companion. Only its exact prefix may be replaced on retry.
            require(bytes.starts_with(&existing), "failed_import_custody")?;
            std::fs::remove_file(&target)?;
            fence::preserve_file(companion, &target)?;
        }
    } else {
        let (count, size) = failed_import_inventory(index_path)?;
        require(
            count < 8 && size.saturating_add(bytes.len() as u64) <= MAX_BYTES,
            "failed_import_capacity",
        )?;
        fence::preserve_file(companion, &target)?;
        require(
            read(&target)?.as_deref() == Some(bytes),
            "failed_import_custody",
        )?;
    }
    require(
        read(&target)?.as_deref() == Some(bytes),
        "failed_import_custody",
    )?;
    // Retry every durability barrier after an interrupted copy/rename sequence.
    std::fs::File::open(&target)?.sync_all()?;
    super::super::sync_checkpoint_parent(&target)?;
    std::fs::remove_file(companion)?;
    super::super::sync_checkpoint_parent(companion)
}

/// Original upload-progress ownership is independent of the import filename.
/// Retain only a commitment; reacquire the existing progress lock and compare
/// exact bytes before sealing. Missing is an exact, separately proved state.
#[derive(Debug)]
pub(super) struct OriginalProgress {
    index_path: PathBuf,
    namespace: String,
    commitment: Option<[u8; 32]>,
}
impl OriginalProgress {
    pub(super) fn capture(index_path: &Path) -> Result<Self> {
        let binding = super::super::scan_index_integration::scan_index_storage_binding(index_path)
            .context("state_v2_original_progress_binding")?;
        require(
            binding.source == super::super::scan_index_persistence::Source::Claude,
            "source",
        )?;
        let mut original = Self {
            index_path: index_path.to_owned(),
            namespace: binding.namespace_hash,
            commitment: None,
        };
        original.commitment =
            crate::snapshot_sync::with_state_v2_progress_lock(index_path, |path| {
                let bytes = original.read_owned(path)?;
                Ok(bytes.as_deref().map(digest))
            })?;
        Ok(original)
    }
    fn read_owned(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        let bytes = read_limited(path, (MAX_BYTES - CONTROL_BYTES) / 6)?;
        if let Some(bytes) = &bytes {
            crate::snapshot_sync::validate_state_v2_original_progress(bytes, &self.namespace)?;
        }
        Ok(bytes)
    }
    fn unchanged(&self, bytes: Option<&[u8]>) -> Result<()> {
        require(
            bytes.map(digest) == self.commitment,
            "import_progress_changed",
        )
    }
    pub(super) fn retry_identity(&self, proposed: Identity) -> Result<Identity> {
        require(
            proposed.binding.namespace_hash == self.namespace,
            "identity",
        )?;
        crate::snapshot_sync::with_state_v2_progress_lock(&self.index_path, |path| {
            let progress = self.read_owned(path)?;
            self.unchanged(progress.as_deref())?;
            let companion = fence::sibling(&self.index_path, ".v2-ack-receipt");
            let Some(bytes) = read(&companion)? else {
                return Ok(proposed);
            };
            let receipt: Receipt = serde_json::from_slice(&bytes)?;
            let recovery = ProgressRecovery {
                scope: Scope {
                    identity: receipt.scope.identity.clone(),
                    generation: proposed.fence_generation,
                },
                path: companion,
                db_path: None,
            };
            let checked = recovery.receipt_at(&recovery.scope)?;
            let progress = progress.as_deref().unwrap_or(b"{\"generation\":0}");
            require(
                checked.scope.identity.binding == proposed.binding
                    && checked.scope.identity.format == proposed.format
                    && checked.scope.generation == checked.scope.identity.fence_generation
                    && checked.previous_generation == checked.generation
                    && (checked.previous_digest == Some(checked.digest)
                        || (checked.generation == 0 && checked.previous_digest.is_none())),
                "failed_import_custody",
            )?;
            if checked.scope.identity.fence_generation == proposed.fence_generation
                && checked.digest == digest(progress)
                && checked.previous_digest == self.commitment
            {
                return Ok(checked.scope.identity);
            }
            // Under the checkpoint owner, BOTH publication artifacts must be
            // absent. Published/ambiguous routes never reach this rotation.
            // Future generations and ACK-updated receipts cannot be rotated.
            require(
                checked.scope.generation <= proposed.fence_generation
                    && !fence::evidence(&self.index_path)?,
                "failed_import_published",
            )?;
            preserve_failed_import(&self.index_path, &recovery.path, &bytes)?;
            Ok(proposed)
        })
    }
    fn seal_locked<S: Store>(
        &self,
        index_path: &Path,
        identity: &Identity,
        progress_path: &Path,
        store: &mut S,
    ) -> Result<RecoverySet> {
        require(
            index_path == self.index_path && identity.binding.namespace_hash == self.namespace,
            "identity",
        )?;
        let bytes = self.read_owned(progress_path)?;
        self.unchanged(bytes.as_deref())?;
        let recovery = ProgressRecovery::seal_import(
            identity.clone(),
            identity.fence_generation,
            index_path,
            bytes.as_deref(),
        )?;
        let mut tx = store.begin(TxnMode::Read)?;
        let set = RecoverySet::capture(&mut tx, &recovery, progress_path)?;
        set.verify(&mut tx, &recovery, progress_path)?;
        drop(tx);
        erase_failed_imports(index_path)?;
        Ok(set)
    }
    #[cfg(test)]
    pub(super) fn seal_and_capture<S: Store>(
        &self,
        index_path: &Path,
        identity: &Identity,
        store: &mut S,
    ) -> Result<RecoverySet> {
        crate::snapshot_sync::with_state_v2_progress_lock(index_path, |path| {
            self.seal_locked(index_path, identity, path, store)
        })
    }
    /// Retain the existing progress owner through import close/fsync and fence
    /// publication. A progress save cannot slip between sealing and the fence.
    pub(super) fn with_sealed_import<S: Store, T>(
        &self,
        index_path: &Path,
        identity: &Identity,
        mut store: S,
        publish: impl FnOnce(S, RecoverySet) -> Result<T>,
    ) -> Result<T> {
        crate::snapshot_sync::with_state_v2_progress_lock(index_path, |path| {
            let set = self.seal_locked(index_path, identity, path, &mut store)?;
            publish(store, set)
        })
    }
}

impl ProgressRecovery {
    pub(super) fn for_backup(identity: Identity, generation: u64, path: &Path) -> Self {
        Self {
            scope: Scope {
                identity,
                generation,
            },
            path: fence::sibling(path, ".v2-ack-receipt"),
            db_path: None,
        }
    }
    /// Runtime load already holds CheckpointLock and has authenticated the DB.
    /// Replay before returning either a hydrated or cached graph, without
    /// recursively acquiring the checkpoint/route/session locks.
    pub(super) fn recover_route(identity: &Identity, generation: u64, path: &Path) -> Result<()> {
        let recovery = Self {
            scope: Scope {
                identity: identity.clone(),
                generation,
            },
            path: fence::sibling(path, ".v2-ack-receipt"),
            db_path: Some(fence::sibling(path, ".v2.sqlite")),
        };
        crate::snapshot_sync::recover_state_v2_progress(path, &recovery)
    }

    pub(super) fn recover_route_locked(
        identity: &Identity,
        generation: u64,
        path: &Path,
        owner: &crate::snapshot_sync::SnapshotProgressLock,
    ) -> Result<()> {
        let recovery = Self {
            scope: Scope {
                identity: identity.clone(),
                generation,
            },
            path: fence::sibling(path, ".v2-ack-receipt"),
            db_path: Some(fence::sibling(path, ".v2.sqlite")),
        };
        crate::snapshot_sync::recover_state_v2_progress_locked(path, &recovery, owner)
    }

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
    // Exact independently decodable reference tuple, not a content hash alone.
    encoded: Vec<u8>,
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
        let receipt = recovery.receipt_at(&scope)?;
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
                require(header.len <= MUTABLE_VALUE_BYTES, "backup_size")?;
                charged = charged.saturating_add(header.len.saturating_mul(4));
                require(charged <= 8 * 1024 * 1024, "backup_size")?;
                let mut encoded = Vec::new();
                tx.read_value(header, &mut encoded)?;
                resume.push(ResumeReference {
                    key: key_bytes.clone(),
                    position: *position,
                    digest: Sha256::digest(&encoded).into(),
                    encoded,
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

    pub(super) fn identity(&self) -> &Identity {
        &self.scope.identity
    }
    pub(super) fn checkpoints(&self) -> Result<Vec<kinds_files::ResumeCheckpoint>> {
        let mut checkpoints = Vec::new();
        for reference in &self.resume {
            require(
                reference.position == 0
                    && <[u8; 32]>::from(Sha256::digest(&reference.encoded)) == reference.digest,
                "backup_resume",
            )?;
            let mut decoded = CheckpointBytes(Vec::new());
            packed::decode(reference.encoded.as_slice(), &mut decoded)?;
            let checkpoint: kinds_files::ResumeCheckpoint = serde_json::from_slice(&decoded.0)?;
            require(
                checkpoint.binding == self.scope.identity.binding,
                "backup_resume",
            )?;
            checkpoints.push(checkpoint);
        }
        Ok(checkpoints)
    }
    pub(super) fn reconcile_receipt_before_restore(
        &self,
        index_path: &Path,
        progress_path: &Path,
        backup_receipt: &Path,
    ) -> Result<()> {
        let companion = fence::sibling(index_path, ".v2-ack-receipt");
        if read(&companion)?.is_none() {
            let bytes = read(backup_receipt)?.context("state_v2_backup_receipt")?;
            require(digest(&bytes) == self.receipt_digest, "backup_receipt")?;
            ottto_core::write_owner_only_file_atomic(&companion, &bytes)?;
            super::super::sync_checkpoint_parent(&companion)?;
        }
        let bytes = read(&companion)?.context("state_v2_backup_receipt")?;
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        require(
            receipt.scope.identity == self.scope.identity,
            "backup_receipt",
        )?;
        let recovery = ProgressRecovery {
            scope: Scope {
                identity: self.scope.identity.clone(),
                generation: receipt.scope.generation.max(self.scope.generation),
            },
            path: companion,
            db_path: None,
        };
        // Replay independently retained newer receipts BEFORE rejecting an old
        // snapshot. Accepted external state is never rolled back to the backup.
        recovery.recover(progress_path)?;
        require(
            receipt.scope.generation <= self.scope.generation
                && digest(&bytes) == self.receipt_digest,
            "backup_newer_receipt",
        )?;
        Ok(())
    }
    pub(super) fn reconcile_before_restore(
        &self,
        index_path: &Path,
        progress_path: &Path,
        backup_receipt: &Path,
    ) -> Result<()> {
        self.reconcile_receipt_before_restore(index_path, progress_path, backup_receipt)?;
        let db_path = fence::sibling(index_path, ".v2.sqlite");
        if fence::exists(&db_path)? {
            require(
                sqlite::Sqlite::ack_generation(&db_path, &self.scope.identity)?
                    == self.scope.generation,
                "backup_newer_database",
            )?;
        }
        Ok(())
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

/// Decoded checkpoints are mutable values, capped before extending the buffer.
struct CheckpointBytes(Vec<u8>);
impl std::io::Write for CheckpointBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MUTABLE_VALUE_BYTES as usize {
            return Err(std::io::Error::other("state_v2_backup_resume_admission"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
