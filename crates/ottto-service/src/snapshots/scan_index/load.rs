//! Loading a persisted `ScanIndex`: the attributed and probed v1/v2 loads,
//! the missing-root and quarantine paths, and the shared decoder tail.

use crate::snapshots::*;

impl ScanIndex {
    /// `load_for_snapshot_source_with_origin` without the origin.
    #[cfg(test)]
    pub(crate) fn load_for_snapshot_source(
        path: &Path,
        source: SnapshotSource,
        support_dir: &Path,
    ) -> Result<Self> {
        Ok(Self::load_for_snapshot_source_with_origin(path, source, support_dir)?.0)
    }

    /// Source-aware daemon load, before replay preparation can save/advance
    /// the generation. The durable exclusion marker is the active signal:
    /// there is no separate durable adoption-complete marker. A quarantine
    /// rebuild returns the same empty generation-0 index as an absent file.
    /// It also returns what the load found: a missing or
    /// quarantined file is a fresh index whatever it holds.
    pub(crate) fn load_for_snapshot_source_with_origin(
        path: &Path,
        source: SnapshotSource,
        support_dir: &Path,
    ) -> Result<(Self, ScanIndexLoadOrigin)> {
        Self::load_source_with_probe(path, source, support_dir, None)
    }
    pub(crate) fn load_for_snapshot_source_with_custody(
        path: &Path,
        source: SnapshotSource,
        support_dir: &Path,
        custody: bool,
    ) -> Result<(Self, ScanIndexLoadOrigin)> {
        Self::load_source_with_probe(path, source, support_dir, Some(custody))
    }
    fn load_source_with_probe(
        path: &Path,
        source: SnapshotSource,
        support_dir: &Path,
        custody: Option<bool>,
    ) -> Result<(Self, ScanIndexLoadOrigin)> {
        let loaded = Self::load_inner_with_probe(
            path,
            Some(source),
            Some(support_dir),
            SystemTime::now(),
            custody,
        );
        scan_index_health::observe(source, &loaded);
        let (mut index, origin) = match loaded {
            Ok(loaded) => {
                note_scan_index_rebuild_paused(source, false);
                disarm_scan_index_rebuild_manual_override(source);
                loaded
            }
            Err(error) => {
                if error.downcast_ref::<ScanIndexRebuildLoop>().is_some() {
                    note_scan_index_rebuild_paused(source, true);
                }
                return Err(error);
            }
        };
        let load_origin = ScanIndexLoadOrigin::from(&origin);
        index.settle_loaded_index(path);
        let first_load_in_process = index.note_first_index_load(path);
        if first_load_in_process {
            if source == SnapshotSource::Codex {
                codex_file_join::rearm_unsettled(&mut index);
            }
            requeue_unindexed_observed(source, &mut index);
        }
        if source == SnapshotSource::ClaudeCode
            && load_origin.is_fresh(&index)
            && fs::symlink_metadata(ReemissionExclusions::seen_marker_path(support_dir)).is_ok()
        {
            note_claude_reemission_stop_with_cause_at(
                &ClaudeContextFileBirthCounts::default(),
                &BTreeSet::new(),
                Some(ClaudeReemissionStopCause::IndexRebuild),
                std::time::Instant::now(),
            );
        }
        Ok((index, load_origin))
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::load_attributed(path, None)
    }

    /// `source` only names the source kind in containment lines and alarms.
    pub(in crate::snapshots) fn load_attributed(
        path: &Path,
        source: Option<SnapshotSource>,
    ) -> Result<Self> {
        let (mut index, _) =
            Self::load_inner_with_probe(path, source, None, SystemTime::now(), None)?;
        index.settle_loaded_index(path);
        index.note_first_index_load(path);
        Ok(index)
    }

    pub(in crate::snapshots) fn clear_retired_file_size_debt(&mut self) {
        if let Some(traversal) = &mut self.traversal {
            traversal.oversized_discovery.clear();
            traversal.counts.oversized_file_count = 0;
        }
    }

    /// The one post-load step of both load entry points. Growth-claim lineage
    /// binds here for every v2-active source, so the two cannot drift apart.
    fn settle_loaded_index(&mut self, path: &Path) {
        if sampled_audit::growth_active(self) {
            sampled_audit::bind_growth_claims(self, path);
        }
    }

    /// A load with its original freshness classification.
    #[cfg(test)]
    pub(in crate::snapshots) fn load_inner(
        path: &Path,
        source: Option<SnapshotSource>,
    ) -> Result<(Self, LoadOrigin)> {
        Self::load_inner_at(path, source, SystemTime::now())
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn load_inner_at(
        path: &Path,
        source: Option<SnapshotSource>,
        now: SystemTime,
    ) -> Result<(Self, LoadOrigin)> {
        Self::load_inner_with_support(path, source, None, now)
    }

    /// Only a load that names its support directory can spend an armed user
    /// Repair override and see the source-wide override stamp.
    #[cfg(test)]
    pub(in crate::snapshots) fn load_inner_with_support(
        path: &Path,
        source: Option<SnapshotSource>,
        support_dir: Option<&Path>,
        now: SystemTime,
    ) -> Result<(Self, LoadOrigin)> {
        Self::load_inner_with_probe(path, source, support_dir, now, None)
    }
    fn load_inner_with_probe(
        path: &Path,
        source: Option<SnapshotSource>,
        support_dir: Option<&Path>,
        now: SystemTime,
        custody: Option<bool>,
    ) -> Result<(Self, LoadOrigin)> {
        let _lock = CheckpointLock::acquire_with_custody(path, false, custody)?;
        let (v2_index, try_import) =
            state_v2::load_locked(path, support_dir.is_some(), _lock.custody)?;
        if let Some(mut index) = v2_index {
            if !index.finish_decoded_load(source) {
                return Err(anyhow::anyhow!(
                    "scan_index_storage_generation_requires_repair"
                ));
            }
            return Ok((index, LoadOrigin::Loaded));
        }
        let (decoded, origin) = if !path.exists() {
            let persistence_root =
                scan_index_integration::check_missing(path, scan_index_source_label(source))?;
            (
                Ok(Self {
                    persistence_root,
                    ..Self::default()
                }),
                LoadOrigin::Missing,
            )
        } else {
            let decoded =
                read_scan_index_representation(path, "load", scan_index_source_label(source), None)
                    .map_err(|error| match error.downcast::<lenient_decode::Error>() {
                        Ok(error) => error,
                        Err(error)
                            if error.chain().any(|cause| {
                                cause.to_string() == "scan_index_representation_refused"
                            }) =>
                        {
                            lenient_decode::Error::Refused("schema_version")
                        }
                        Err(_) => {
                            lenient_decode::Error::Refused("storage generation requires repair")
                        }
                    });
            (decoded, LoadOrigin::Loaded)
        };
        match decoded {
            Ok(index) if index.schema_version != SCAN_INDEX_SCHEMA_VERSION => Err(anyhow::anyhow!(
                "unsupported local snapshot scan index schema"
            )),
            // Written by a newer build: future state, refused like a schema
            // mismatch and never rebuilt over.
            Ok(index)
                if index.accepted_snapshot_fingerprint_ledger_version
                    > SNAPSHOT_ACCEPTED_LEDGER_VERSION =>
            {
                alarm_future_scan_index_ledger(
                    scan_index_source_label(source),
                    index.accepted_snapshot_fingerprint_ledger_version,
                );
                Err(anyhow::anyhow!(
                    "unsupported local snapshot scan index accepted-ledger version {}",
                    index.accepted_snapshot_fingerprint_ledger_version
                ))
            }
            Ok(mut index) => {
                if !index.finish_decoded_load(source) {
                    if index
                        .persistence_root
                        .as_ref()
                        .is_some_and(|(_, root)| !root.is_legacy())
                    {
                        return Err(anyhow::anyhow!(
                            "scan_index_storage_generation_requires_repair"
                        ));
                    }
                    let discarded = index.files.len();
                    return quarantine_invalid_scan_index(
                        path,
                        "codex_identity_collision",
                        Some(discarded),
                        source,
                        support_dir,
                        now,
                    )
                    .map(|index| (index, LoadOrigin::Quarantined));
                }
                if try_import {
                    state_v2::after_v1_locked(path, &mut index)?;
                }
                index.clear_retired_file_size_debt();
                Ok((index, origin))
            }
            Err(error) if error.quarantines() => {
                let cause = if matches!(error, lenient_decode::Error::HoldBudget) {
                    "hold_budget"
                } else {
                    "decode"
                };
                quarantine_invalid_scan_index(path, cause, None, source, support_dir, now)
                    .map(|index| (index, LoadOrigin::Quarantined))
                    .map_err(|refusal| refusal.context(error))
            }
            Err(error) => {
                Err(error).with_context(|| format!("parse scan index {}", path.display()))
            }
        }
    }

    // Shared by v1 and v2 after the raw-dependent decoder tail. A collision is
    // handled by the caller: v1 may quarantine; published v2 custody must hold.
    fn finish_decoded_load(&mut self, source: Option<SnapshotSource>) -> bool {
        let active_witness = source.map(snapshot_quarantine_witness);
        if self.persistence_available() {
            terminal_contract_retry::rearm(
                &mut self.quarantined_snapshot_fingerprints,
                active_witness.as_ref(),
            );
        }
        true
    }
}
