//! Quiet audit retirement retains scheduling until both index saves succeed.
//! A retirement is staged for one pass with its body's fingerprint and the
//! proof that the completion's own certificate is debt-free on the object now
//! at the path. The committed index decides the rest, after the pass's save.
use super::super::sampled_scan::SharedCache;
use super::super::*;
use crate::transcript_acquisition::{Checkpoint, Scope};
use std::os::unix::fs::MetadataExt;

struct Pending {
    source: SnapshotSource,
    fingerprint: [u8; 32],
    proven: bool,
}

struct Pass {
    source: SnapshotSource,
    index_path: PathBuf,
    namespace: Scope,
    identity_capture: bool,
}

#[derive(Default)]
pub(in crate::snapshots) struct QuietRetirements {
    passes: Vec<Pass>,
    pending: BTreeMap<String, Pending>,
    /// Each source's first failed removal of its retired record directory.
    pub(in crate::snapshots) retired_failed_since: Vec<(SnapshotSource, std::time::Instant)>,
}

fn digest(fingerprint: &str) -> [u8; 32] {
    Sha256::digest(fingerprint.as_bytes()).into()
}

fn counted(source: SnapshotSource, counts: &serde_json::Value) {
    crate::local_resource_diagnostics::traversal_point(
        "quiet_retirement",
        source.api_slug(),
        counts,
    );
}

impl SharedCache {
    fn quiet_state(&self) -> std::sync::MutexGuard<'_, QuietRetirements> {
        self.quiet.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Registers the pass. Another index, scope or capture mode drops this
    /// source's retirements: they were staged for that context.
    pub(in crate::snapshots) fn quiet_begin_pass(
        &self,
        source: SnapshotSource,
        index_path: &Path,
        namespace: &Scope,
        identity_capture: bool,
    ) {
        let mut state = self.quiet_state();
        let pass = Pass {
            source,
            index_path: index_path.to_owned(),
            namespace: namespace.clone(),
            identity_capture,
        };
        match state.passes.iter().position(|p| p.source == source) {
            Some(at) => {
                let same = {
                    let old = &state.passes[at];
                    old.index_path == pass.index_path
                        && old.namespace == pass.namespace
                        && old.identity_capture == pass.identity_capture
                };
                if !same {
                    state.pending.retain(|_, p| p.source != source);
                }
                state.passes[at] = pass;
            }
            None => state.passes.push(pass),
        }
    }

    /// Whether this source has begun a pass in this process.
    pub(in crate::snapshots) fn quiet_registered(&self, source: SnapshotSource) -> bool {
        self.quiet_state().passes.iter().any(|p| p.source == source)
    }

    /// After a source's local copy is erased.
    pub(crate) fn quiet_forget_source(&self, source: SnapshotSource) {
        let mut state = self.quiet_state();
        state.passes.retain(|p| p.source != source);
        state.pending.retain(|_, p| p.source != source);
    }

    /// The completion's own certificate is debt-free and names the object now
    /// at `key`'s path.
    pub(in crate::snapshots) fn quiet_certified(&self, key: &str, checkpoint: &Checkpoint) -> bool {
        checkpoint.audit_debt().is_none()
            && checkpoint
                .durable_certificate(0)
                .is_some_and(|certificate| {
                    std::fs::metadata(key).is_ok_and(|metadata| {
                        metadata.dev() == certificate.device && metadata.ino() == certificate.inode
                    })
                })
    }

    /// False without a registered pass: nothing would settle a second save,
    /// so the caller retires directly. A staged marker stays until this exact
    /// body's second index save succeeds.
    pub(crate) fn quiet_stage(
        &self,
        source: SnapshotSource,
        key: &str,
        fingerprint: &str,
        proven: bool,
    ) -> bool {
        let mut state = self.quiet_state();
        if !state.passes.iter().any(|p| p.source == source) {
            return false;
        }
        state.pending.insert(
            key.to_owned(),
            Pending {
                source,
                fingerprint: digest(fingerprint),
                proven,
            },
        );
        counted(source, &serde_json::json!({"staged": 1}));
        true
    }

    /// The second index save: retires each staged marker the committed index
    /// still shows for the same body. Without the writer lock nothing happens
    /// and the staged set is dropped; a failed save restores the markers and
    /// keeps them staged for the next pass's reconcile.
    pub(in crate::snapshots) fn quiet_reconcile(
        &self,
        support_dir: &Path,
        source: SnapshotSource,
        index: &mut ScanIndex,
        index_path: &Path,
    ) -> usize {
        let writer = crate::locked_state_dir::held_for(support_dir)
            .filter(|writer| index_path.starts_with(writer.dir()));
        let mut state = self.quiet_state();
        let staged: Vec<String> = state
            .pending
            .iter()
            .filter(|(_, p)| p.source == source)
            .map(|(key, _)| key.clone())
            .collect();
        if writer.is_none() {
            state.pending.retain(|_, p| p.source != source);
            return 0;
        }
        let mut undo = BTreeMap::new();
        for key in &staged {
            let pending = &state.pending[key];
            let Some(entry) = index.files.get(key) else {
                state.pending.remove(key);
                continue;
            };
            let fingerprint = entry.source_file_fingerprint.clone();
            let previous = entry.scan_identity_version.clone();
            let ready = pending.proven
                && pending.fingerprint == digest(&fingerprint)
                && entry.has_unverified_source()
                && !entry.has_prefix_provenance()
                && !index.claude_account_deferred_holds.contains_key(key);
            if ready && index.retire_quiet_audit(key, &fingerprint) {
                undo.insert(key.clone(), previous);
            } else {
                state.pending.remove(key);
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
            counted(source, &serde_json::json!({"save_failed": 1}));
            return 0;
        }
        let retired = undo.len();
        for key in undo.keys() {
            state.pending.remove(key);
        }
        counted(source, &serde_json::json!({"retired": retired}));
        crate::local_resource_diagnostics::traversal_point(
            "sampled_audit_retirement",
            source.api_slug(),
            &serde_json::json!({"audit_quiet_retired": retired,
                "pending_audits": index.files.values().filter(|entry| entry.has_unverified_source()).count()}),
        );
        retired
    }
}
