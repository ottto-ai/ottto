//! Quiet audit retirement retains scheduling until both index saves succeed.
use super::super::durable_sources::DurableSource;
use super::super::sampled_scan::SharedCache;
use super::super::*;
use crate::durable_tail_store::{self as store, SingleWriter};
use crate::transcript_acquisition::{birth_unix_nanos, Checkpoint, DurableCertificate};
use std::os::unix::fs::MetadataExt;

fn durable_source(source: SnapshotSource) -> Option<DurableSource> {
    DurableSource::from_snapshot(source)
}

#[derive(Clone, Copy)]
pub(in crate::snapshots) struct QuietRetirement {
    pub(in crate::snapshots) key: store::Digest32,
    pub(in crate::snapshots) source: SnapshotSource,
    pub(in crate::snapshots) fingerprint: store::Digest32,
    pub(in crate::snapshots) durable: bool,
}

/// The retained checkpoint's certificate with the birth of the object now
/// at `key`'s path, or `None` when that object is not the checkpoint's (it
/// was replaced since the read: nothing is persisted for it).
pub(in crate::snapshots) fn certificate_at(
    key: &str,
    checkpoint: &Checkpoint,
    index: &ScanIndex,
    now: u64,
) -> Option<DurableCertificate> {
    let mut certificate = checkpoint.durable_certificate(0)?;
    let metadata = std::fs::metadata(key).ok()?;
    if metadata.dev() != certificate.device || metadata.ino() != certificate.inode {
        return None;
    }
    certificate.birth_nanos = birth_unix_nanos(&metadata);
    // Downgrade readers still consume these bytes. A decoded checkpoint has
    // dropped them; only the current committed index supplies write truth.
    certificate.audit_debt_unix_seconds =
        sampled_audit::debt_for_key(index, key, now).map(|debt| debt.due_unix_seconds);
    Some(certificate)
}

impl SharedCache {
    /// No durable slot means no old certificate exists in this acquisition
    /// context. Otherwise keep the persisted marker until this exact body's
    /// debt-free replacement and a second index CAS both succeed.
    pub(crate) fn durable_stage_quiet_retirement(
        &self,
        source: SnapshotSource,
        key: &str,
        fingerprint: &str,
    ) -> bool {
        if !restart_restore::enabled() {
            let Some(ds) = durable_source(source) else {
                return false;
            };
            let Ok(mut root) = self.durable.lock() else {
                return true;
            };
            if root.passes[ds.slot()].is_none() {
                return false;
            }
            let key = store::key_digest(ds, key);
            let slot = root
                .retiring
                .iter()
                .position(|p| p.is_some_and(|p| p.key == key))
                .or_else(|| root.retiring.iter().position(Option::is_none))
                .unwrap_or(0);
            root.retiring[slot] = Some(QuietRetirement {
                key,
                source,
                fingerprint: Sha256::digest(fingerprint.as_bytes()).into(),
                durable: false,
            });
            return true;
        }
        let Some(mut stores) = self.durable() else {
            return true;
        };
        let Some(durable_source) = durable_source(source) else {
            return false;
        };
        if restart_restore::enabled() && stores.slot(durable_source).is_none() {
            return false;
        }
        let key = store::key_digest(durable_source, key);
        let slot = stores
            .retiring
            .iter()
            .position(|pending| pending.is_some_and(|p| p.key == key))
            .or_else(|| stores.retiring.iter().position(Option::is_none))
            .unwrap_or(0);
        // Replacing a RAM proof candidate never removes its persisted marker;
        // that key must revalidate on its next visit before it can retire.
        stores.retiring[slot] = Some(QuietRetirement {
            key,
            source,
            fingerprint: Sha256::digest(fingerprint.as_bytes()).into(),
            durable: false,
        });
        true
    }
    pub(crate) fn durable_reconcile_retirements<W: SingleWriter>(
        &self,
        writer: &W,
        source: SnapshotSource,
        index: &mut ScanIndex,
        index_path: &Path,
    ) -> usize {
        if !index_path.starts_with(writer.state_dir()) {
            return 0;
        }
        let Some(durable_source) = durable_source(source) else {
            return 0;
        };
        let retiring = if restart_restore::enabled() {
            self.durable().map(|stores| stores.retiring)
        } else {
            self.durable.lock().ok().map(|root| root.retiring)
        };
        let ready: Vec<_> = retiring
            .map(|retiring| {
                index
                    .files
                    .iter()
                    .filter(|(key, entry)| {
                        retiring
                            .iter()
                            .flatten()
                            .find(|pending| pending.key == store::key_digest(durable_source, key))
                            .is_some_and(|pending| {
                                pending.source == source
                                    && pending.durable
                                    && pending.fingerprint
                                        == <[u8; 32]>::from(Sha256::digest(
                                            entry.source_file_fingerprint.as_bytes(),
                                        ))
                            })
                    })
                    .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut undo = BTreeMap::new();
        for (key, fingerprint) in &ready {
            let previous = index
                .files
                .get(key)
                .and_then(|entry| entry.scan_identity_version.clone());
            if !index.claude_account_deferred_holds.contains_key(key)
                && index.retire_quiet_audit(key, fingerprint)
            {
                undo.insert(key.clone(), previous);
            }
        }
        if undo.is_empty() {
            return 0;
        }
        if index.save(index_path).is_err() {
            for (key, previous) in undo {
                if let Some(entry) = index.files.get_mut(&key) {
                    entry.scan_identity_version = previous;
                }
            }
            return 0;
        }
        let retired = undo.len();
        if !restart_restore::enabled() {
            if let Ok(mut root) = self.durable.lock() {
                for pending in &mut root.retiring {
                    if pending.is_some_and(|p| {
                        undo.keys()
                            .any(|key| store::key_digest(durable_source, key) == p.key)
                    }) {
                        *pending = None;
                    }
                }
            }
        }
        if let Some(mut stores) = self.durable() {
            for pending in &mut stores.retiring {
                if pending.is_some_and(|p| {
                    undo.keys()
                        .any(|key| store::key_digest(durable_source, key) == p.key)
                }) {
                    *pending = None;
                }
            }
        }
        crate::local_resource_diagnostics::traversal_point(
            "sampled_audit_retirement",
            source.api_slug(),
            &serde_json::json!({"audit_quiet_retired": retired,
                "pending_audits": index.files.values().filter(|entry| entry.has_unverified_source()).count()}),
        );
        retired
    }
    pub(in crate::snapshots) fn qualify_quiet_retirements(
        &self,
        snapshot_source: SnapshotSource,
        index: &ScanIndex,
    ) -> Option<()> {
        // The committed save, not the working index, owns quiet-marker
        // settlement even without a record. Keep the ordinary second CAS.
        let source = durable_source(snapshot_source)?;
        let retiring = self.durable.lock().ok()?.retiring;
        let mut ready = BTreeSet::new();
        if let Ok(cache) = self.retained() {
            for key in cache.keys() {
                let Some(entry) = index.files.get(key) else {
                    continue;
                };
                let digest = store::key_digest(source, key);
                if retiring.iter().flatten().any(|pending| {
                    pending.key == digest
                        && pending.source == snapshot_source
                        && pending.fingerprint
                            == <[u8; 32]>::from(Sha256::digest(
                                entry.source_file_fingerprint.as_bytes(),
                            ))
                }) && entry.has_unverified_source()
                    && !entry.has_prefix_provenance()
                    && !index.claude_account_deferred_holds.contains_key(key)
                    && cache.peek(key).is_some_and(|retained| {
                        retained.checkpoint.audit_debt().is_none()
                            && certificate_at(
                                key,
                                &retained.checkpoint,
                                index,
                                unix_seconds(SystemTime::now()).unwrap_or(0),
                            )
                            .is_some()
                    })
                {
                    ready.insert(digest);
                }
            }
        }
        if let Ok(mut root) = self.durable.lock() {
            for pending in root.retiring.iter_mut().flatten() {
                pending.durable |= ready.contains(&pending.key);
            }
        }
        Some(())
    }
}
