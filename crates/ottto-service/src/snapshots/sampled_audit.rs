//! Audit status lives in the existing per-file index, never in a new ledger.
#[cfg(unix)]
pub(in crate::snapshots) mod quiet_retirement;

use super::*;
use crate::transcript_acquisition::{AuditDebt, AUDIT_INTERVAL_SECONDS};
use crate::transcript_cache::CACHE_ENTRIES;

// v1 did not distinguish an ordinary Tail from a published FE prefix.
#[cfg(test)]
pub(super) const UNVERIFIED_IDENTITY: &str = "semantic_sync:v2+sampled_unverified:v1";
const UNVERIFIED_STEM: &str = "semantic_sync:v2+sampled_unverified:";
const PROVENANCE_IDENTITY: &str = "semantic_sync:v2+sampled_unverified:v2";

// Deadline and provenance occupy the EXISTING version string. c = complete
// native recomposition; p = sealed prefix. No new inline or persisted field.
const MAX_MARKER_BYTES: usize = 64;
pub(super) fn marker(due: u64) -> String {
    provenance_marker(due, false)
}
fn provenance_marker(due: u64, prefix: bool) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(MAX_MARKER_BYTES);
    write!(
        &mut value,
        "{PROVENANCE_IDENTITY}:{due}:{}",
        if prefix { "p" } else { "c" }
    )
    .expect("bounded marker formats");
    value
}
fn decode_marker(version: &str) -> Option<(u64, bool)> {
    let (due, provenance) = version
        .strip_prefix(PROVENANCE_IDENTITY)?
        .strip_prefix(':')?
        .split_once(':')?;
    if due.is_empty() || !due.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let due = due.parse().ok()?;
    Some((
        due,
        match provenance {
            "c" => false,
            "p" => true,
            _ => return None,
        },
    ))
}
impl ScanIndexEntry {
    pub(super) fn has_unverified_source(&self) -> bool {
        self.scan_identity_version
            .as_deref()
            .is_some_and(|version| version.starts_with(UNVERIFIED_STEM))
    }
    /// FE writes every prefix tag under the sampled stem, and replay keeps stem
    /// entries, so only a stem can carry a prefix. A stem fails closed unless
    /// it decodes as a v2 c tag; None and legacy identities are not prefixes.
    pub(super) fn has_prefix_provenance(&self) -> bool {
        self.has_unverified_source()
            && self
                .scan_identity_version
                .as_deref()
                .is_some_and(|version| !matches!(decode_marker(version), Some((_, false))))
    }
    pub(super) fn unverified_deadline(&self) -> Option<u64> {
        if !self.has_unverified_source() {
            return None;
        }
        let version = self.scan_identity_version.as_deref()?;
        Some(
            decode_marker(version)
                .map(|(due, _)| due)
                .unwrap_or_else(|| {
                    // Preserve a v1 deadline, but never infer complete provenance.
                    version
                        .strip_prefix(UNVERIFIED_STEM)
                        .and_then(|tail| tail.strip_prefix("v1:"))
                        .filter(|due| {
                            !due.is_empty() && due.bytes().all(|byte| byte.is_ascii_digit())
                        })
                        .and_then(|due| due.parse().ok())
                        .unwrap_or(0)
                }),
        )
    }
    pub(super) fn set_unverified_deadline(&mut self, due: u64) {
        self.scan_identity_version = Some(provenance_marker(due, self.has_prefix_provenance()));
    }
    /// Only an existing sampled stem carries provenance. A missing or legacy
    /// identity still reads as prefix until re-recorded, but an ordinary
    /// record never mints `p`; FE marks its prefix after `record`.
    pub(super) fn carried_audit_version(&self) -> String {
        if self.has_unverified_source() {
            provenance_marker(
                self.unverified_deadline().unwrap_or(0),
                self.has_prefix_provenance(),
            )
        } else {
            LOCAL_SCAN_INDEX_IDENTITY_VERSION.into()
        }
    }
    pub(super) fn carry_sampled_audit(&mut self, working: &Self) {
        if let Some(version) = self.sampled_audit_carry(working) {
            self.scan_identity_version = Some(version);
        }
    }
    /// Whether `carry_sampled_audit(working)` would change this entry. By
    /// value: the carry rewrites even this entry's own v1 marker in v2 form.
    pub(super) fn carry_sampled_audit_changes(&self, working: &Self) -> bool {
        self.sampled_audit_carry(working)
            .is_some_and(|version| self.scan_identity_version.as_deref() != Some(&*version))
    }
    fn sampled_audit_carry(&self, working: &Self) -> Option<String> {
        let due = working.unverified_deadline()?;
        Some(provenance_marker(
            self.unverified_deadline().map_or(due, |old| old.min(due)),
            self.has_prefix_provenance() || working.has_prefix_provenance(),
        ))
    }
    pub(super) fn audit_obligation(&self, now: u64) -> Option<AuditDebt> {
        if !self.has_unverified_source() {
            return None;
        }
        let deadline = self
            .unverified_deadline()
            .filter(|deadline| {
                *deadline > 0
                    && now
                        .checked_add(AUDIT_INTERVAL_SECONDS)
                        .is_some_and(|latest| *deadline <= latest)
            })
            .unwrap_or(now);
        Some(AuditDebt {
            due_unix_seconds: deadline,
        })
    }
    pub(super) fn audit_requires_full(&self, now: u64) -> bool {
        self.audit_obligation(now)
            .is_some_and(|debt| now >= debt.due_unix_seconds)
    }
    pub(super) fn retain_history_evidence(&self) -> bool {
        self.codex_history_is_protected() || self.has_unverified_source()
    }
}
impl ScanIndex {
    /// Existing obligations are never evicted. Imported over-cap populations
    /// must drain before any new marker can be admitted.
    pub(super) fn can_stage_sampled_audit(&self, key: &str) -> bool {
        self.files
            .get(key)
            .is_some_and(ScanIndexEntry::has_unverified_source)
            || self
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .take(CACHE_ENTRIES)
                .count()
                < CACHE_ENTRIES
    }

    pub(super) fn retire_quiet_audit(&mut self, key: &str, fingerprint: &str) -> bool {
        let Some(entry) = self.files.get_mut(key).filter(|entry| {
            entry.source_file_fingerprint == fingerprint
                && entry.has_unverified_source()
                && !entry.has_prefix_provenance()
        }) else {
            return false;
        };
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        true
    }

    /// Called only by a current validated native source completion. Entry/source
    /// equality fences an older completion; the existing writer owns lock/CAS.
    /// A delivery ACK never calls this method as source-verification authority.
    pub(super) fn stage_sampled_audit(
        &mut self,
        key: &str,
        source_fingerprint: &str,
        debt: AuditDebt,
    ) -> bool {
        if !self.can_stage_sampled_audit(key) {
            return false;
        }
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.source_file_fingerprint == source_fingerprint)
        else {
            return false;
        };
        let due = entry
            .unverified_deadline()
            .map_or(debt.due_unix_seconds, |old| old.min(debt.due_unix_seconds));
        entry.set_unverified_deadline(due);
        true
    }
    /// This caller just finished a progress-complete, EOF-revalidated native Full or
    /// Tail recomposition. FE never retains a prefix reduction in the cache,
    /// so a Tail here replays a complete retained baseline, not an FE body.
    /// Keep the audit debt: complete provenance is not Full-audit credit.
    pub(super) fn complete_native_recomposition(
        &mut self,
        key: &str,
        source_fingerprint: &str,
    ) -> bool {
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.source_file_fingerprint == source_fingerprint)
        else {
            return false;
        };
        if entry.has_prefix_provenance() {
            crate::local_resource_diagnostics::cache_lifecycle::record(
                crate::local_resource_diagnostics::cache_lifecycle::Event::PrefixTagCleared,
            );
        }
        entry.scan_identity_version = Some(
            entry
                .unverified_deadline()
                .map(marker)
                .unwrap_or_else(|| LOCAL_SCAN_INDEX_IDENTITY_VERSION.into()),
        );
        true
    }
    pub(super) fn mark_sealed_prefix(&mut self, key: &str, source_fingerprint: &str) -> bool {
        if !self.can_stage_sampled_audit(key) {
            return false;
        }
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.source_file_fingerprint == source_fingerprint)
        else {
            return false;
        };
        entry.scan_identity_version = Some(provenance_marker(
            entry.unverified_deadline().unwrap_or(0),
            true,
        ));
        true
    }
    pub(super) fn complete_full_audit(&mut self, key: &str, source_fingerprint: &str) -> bool {
        if !self.complete_native_recomposition(key, source_fingerprint) {
            return false;
        }
        self.files
            .get_mut(key)
            .expect("validated entry")
            .scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        true
    }
}

/// An accepted sampled generation must be verified even after its activity
/// ages out. The existing bounded walk remains its sole scheduler. Other old
/// files keep the configured window, and secure opens/file caps still apply.
pub(super) fn path_requires_verification(
    files: &SharedMap<String, ScanIndexEntry>,
    path: &Path,
) -> bool {
    files.get(&local_index_key(path)).is_some_and(|entry| {
        entry.has_unverified_source() || entry.source_file_fingerprint.is_empty()
    })
}

/// Retain the existing partial growth safeguard and shorter/future floors
/// until bounded old-directory rescue keeps all held growth discoverable.
/// This predicate alone does NOT implement or qualify that dependency.
/// Discovery grants no ACK, census proof or independent read permission.
pub(super) fn path_requires_recovery(
    source: SnapshotSource,
    files: &SharedMap<String, ScanIndexEntry>,
    path: &Path,
    length: u64,
) -> bool {
    path_requires_verification(files, path)
        || (source == SnapshotSource::ClaudeCode
            && files.get(&local_index_key(path)).is_some_and(|entry| {
                length != entry.size_bytes
                    || entry.effective_upload_body_witness_revision
                        > crate::snapshot_sync::effective_upload_body_witness_revision(source)
            }))
}

fn marker_storage_oversized(entry: &ScanIndexEntry) -> bool {
    entry.has_unverified_source()
        && entry
            .scan_identity_version
            .as_ref()
            .is_some_and(|tag| tag.capacity() > MAX_MARKER_BYTES)
}

/// Runs every Claude and Codex scan, so an index with nothing to normalize
/// stays shared with the committed baseline.
pub(super) fn normalize_marker_storage(index: &mut ScanIndex) {
    if !index.files.values().any(marker_storage_oversized) {
        return;
    }
    for (_, entry) in index.files.slots_mut() {
        if marker_storage_oversized(entry) {
            entry.make_mut().set_unverified_deadline(0);
        }
    }
}

/// The durable audit debt the next read of `key` carries. A debt alone never
/// selects a Full (`ReadPlan::prepare`): a read with a stored or retained copy
/// continues from it, and the debt travels in that read's checkpoint.
pub(super) fn debt_for_key(index: &ScanIndex, key: &str, now: u64) -> Option<AuditDebt> {
    index
        .files
        .get(key)
        .and_then(|entry| entry.audit_obligation(now))
}

impl SourceScanResult {
    /// Transfer a released account hold's acquisition debt before upload/save.
    /// Working retirements never refund their committed marker reservation.
    pub(crate) fn preserve_released_account_audits(
        &self,
        index: &mut ScanIndex,
        previous: &ScanIndex,
        cache: &sampled_scan::SharedCache,
        roots: &[PathBuf],
        backfill_window_days: u64,
    ) {
        let mut reserved = previous
            .files
            .values()
            .filter(|entry| entry.has_unverified_source())
            .count()
            .saturating_add(
                index
                    .files
                    .iter()
                    .filter(|(key, entry)| {
                        entry.has_unverified_source()
                            && !previous
                                .files
                                .get(*key)
                                .is_some_and(ScanIndexEntry::has_unverified_source)
                    })
                    .count(),
            );
        let mut staged = 0_u64;
        let mut queued = 0_u64;
        for (key, fingerprint) in self.completed_parses() {
            if !previous.claude_account_deferred_holds.contains_key(key)
                || index.claude_account_deferred_holds.contains_key(key)
                || !index
                    .files
                    .get(key)
                    .is_some_and(|entry| !entry.has_unverified_source())
            {
                continue;
            }
            // None is unknown/missing retained custody; keep a discoverable
            // retry rather than assuming that a missing copy discharged debt.
            let debt = cache.retained().ok().and_then(|retained| {
                retained
                    .peek(key)
                    .map(|entry| entry.checkpoint.audit_debt())
            });
            if debt == Some(None) {
                continue;
            }
            if let Some(Some(debt)) = debt {
                if reserved < CACHE_ENTRIES
                    && index
                        .files
                        .get(key)
                        .is_some_and(|entry| entry.source_file_fingerprint == fingerprint)
                    && index.stage_sampled_audit(key, fingerprint, debt)
                {
                    reserved += 1;
                    staged += 1;
                    continue;
                }
            }
            // This existing explicit-reparse witness survives traversal resets
            // and ages. It never labels an audit/clock Full or grants credit.
            index
                .files
                .get_mut(key)
                .expect("current parsed entry")
                .source_file_fingerprint
                .clear();
            if index.traversal.is_none() {
                ensure_bounded_traversal(
                    SnapshotSource::ClaudeCode,
                    roots,
                    index,
                    &self.census_window_end,
                    backfill_window_days,
                );
            }
            if let Some(traversal) = index.traversal.as_mut() {
                enqueue_watcher_hints(
                    SnapshotSource::ClaudeCode,
                    traversal,
                    &[PathBuf::from(key)],
                    false,
                );
            }
            queued += 1;
        }
        if staged + queued > 0 {
            crate::local_resource_diagnostics::traversal_point(
                "sampled_audit_account_release",
                "claude_code",
                &serde_json::json!({"marker_staged": staged, "retry_queued": queued}),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> ScanIndexEntry {
        serde_json::from_value(json!({
            "size_bytes": 1, "modified_unix_seconds": 1,
            "modified_unix_nanos": 1, "source_file_fingerprint": "source",
            "last_snapshot_fingerprint": null,
            "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
        }))
        .unwrap()
    }
    fn candidate() -> CandidateFile {
        CandidateFile {
            physical_identity: None,
            scan_root: PathBuf::from("/synthetic"),
            path: PathBuf::from("/synthetic/session.jsonl"),
            size_bytes: 1,
            modified_unix_seconds: 1,
            modified_unix_nanos: 1,
            source_file_fingerprint: "source".into(),
            legacy_source_file_fingerprint: "legacy".into(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".into(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
            withheld_content_stamp: None,
        }
    }
    fn index() -> ScanIndex {
        let mut index = ScanIndex::default();
        let key = local_index_key(&candidate().path);
        index.files.insert(key.clone(), entry());
        index.confirmed_empty_files.insert(key);
        index
    }
    #[test]
    fn cap_retry_keeps_durable_custody_without_a_traversal_or_marker() {
        let mut index = index();
        let candidate = candidate();
        let key = local_index_key(&candidate.path);
        assert!(index.traversal.is_none());
        assert!(!path_requires_verification(&index.files, &candidate.path));
        queue_cap_retry(&mut index, &candidate);
        let mut loaded: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        assert!(loaded.traversal.is_none());
        assert!(path_requires_verification(&loaded.files, &candidate.path));
        assert!(!loaded.files[&key].has_unverified_source());
        assert_eq!(loaded.files[&key].size_bytes, 1);
        // Same-process provenance survives the index round-trip until an
        // actual Full completes; merely queuing the retry emits no Full.
        let probe = crate::local_resource_diagnostics::Probe::start();
        assert!(probe.rearm_fulls().is_empty());
        let full = crate::transcript_acquisition::ReadMode::Full(
            crate::transcript_acquisition::FullReason::StateMissing,
        );
        probe.rearm_full_selected(&key, full);
        probe.rearm_full_completed(&key, full, 3);
        assert_eq!(
            serde_json::to_value(probe.rearm_fulls()).unwrap(),
            json!({"rearm_cleared{audit_cap_delay}": {"count": 1, "completed_native_bytes": 3}})
        );
        loaded.files.remove(&key);
        queue_cap_retry(&mut loaded, &candidate);
        assert!(!loaded.files.contains_key(&key), "no invented membership");
    }

    #[test]
    fn marked_population_admission_and_quiet_retirement_share_the_cap() {
        let mut index = index();
        for n in 0..CACHE_ENTRIES {
            let key = format!("missing-{n}");
            index.files.insert(key.clone(), entry());
            assert!(index.stage_sampled_audit(
                &key,
                "source",
                AuditDebt {
                    due_unix_seconds: 200
                }
            ));
        }
        let key = local_index_key(&candidate().path);
        assert!(!index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert!(!index.mark_sealed_prefix(&key, "source"));
        assert!(index.stage_sampled_audit(
            "missing-0",
            "source",
            AuditDebt {
                due_unix_seconds: 100
            }
        ));
        assert!(index.mark_sealed_prefix("missing-0", "source"));
        assert!(
            !index.retire_quiet_audit("missing-0", "source"),
            "prefix cannot retire"
        );
        assert!(!index.retire_quiet_audit("missing-1", "stale"));
        assert!(index.retire_quiet_audit("missing-1", "source"));
        assert!(index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert_eq!(
            index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            CACHE_ENTRIES
        );
        assert!(index.files["missing-0"].has_unverified_source());
    }

    #[test]
    fn sampled_audit_oldest_deadline_not_ack_or_tail_controls_idle_selection() {
        let mut index = index();
        let candidate = candidate();
        let key = local_index_key(&candidate.path);
        assert!(!index.stage_sampled_audit(
            &key,
            "stale",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert!(index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert!(index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 300
            }
        ));
        assert_eq!(
            index.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            200
        );
        assert_eq!(
            index.candidate_decision_at(&candidate, 199),
            CandidateDecision::Skip
        );
        assert_eq!(
            index.candidate_decision_at(&candidate, 200),
            CandidateDecision::Parse
        );
        let subset = index.committable_subset(&index.clone(), &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            subset.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            200
        );
        assert!(!index.complete_full_audit(&key, "older-source"));
        assert!(index.files[&key].has_unverified_source());
        assert!(index.complete_full_audit(&key, "source"));
        assert!(!index.files[&key].has_unverified_source());
    }
    #[test]
    fn sampled_audit_malformed_and_replay_markers_remain_due_without_resetting_index() {
        for malformed in [
            json!(null),
            json!(0),
            json!(-1),
            json!("later"),
            json!({"due":200}),
            json!(u64::MAX),
        ] {
            let mut raw = serde_json::to_value(entry()).unwrap();
            raw["scan_identity_version"] = json!(format!("{UNVERIFIED_IDENTITY}:{}", malformed));
            let mut index = index();
            let key = local_index_key(&candidate().path);
            index
                .files
                .insert(key.clone(), serde_json::from_value(raw).unwrap());
            assert!(index.files[&key].audit_requires_full(100));
            index.prepare_historical_replay("new-generation".into());
            assert!(index.files[&key].audit_requires_full(100));
            assert_eq!(index.files.len(), 1);
        }
        let mut index = index();
        let key = local_index_key(&candidate().path);
        index.files.get_mut(&key).unwrap().scan_identity_version = Some(UNVERIFIED_IDENTITY.into());
        index.record(candidate(), None, ScanParseOutcome::ConfirmedEmpty);
        assert_eq!(index.files[&key].unverified_deadline(), Some(0));
        index.prepare_historical_replay("replay".into());
        assert!(index.files[&key].audit_requires_full(100));
    }
    #[test]
    fn sampled_audit_shed_body_retains_newer_debt_with_previous_delivery_authority() {
        let mut previous = index();
        let key = local_index_key(&candidate().path);
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        previous.confirmed_empty_files.remove(&key);
        previous
            .files
            .get_mut(&key)
            .unwrap()
            .last_snapshot_fingerprint = Some(old.clone());
        previous
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint = "old-source".into();
        previous
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from([old.clone()]));
        let mut working = previous.clone();
        working
            .files
            .get_mut(&key)
            .unwrap()
            .last_snapshot_fingerprint = Some(new.clone());
        working.files.get_mut(&key).unwrap().source_file_fingerprint = "new-source".into();
        working
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from([new.clone()]));
        assert!(working.stage_sampled_audit(
            &key,
            "new-source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        let shed = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            shed.files[&key].last_snapshot_fingerprint.as_deref(),
            Some(old.as_str())
        );
        assert_eq!(shed.files[&key].source_file_fingerprint, "old-source");
        assert_eq!(
            shed.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            200
        );
        let accepted =
            working.committable_subset(&previous, &BTreeSet::from([new]), &BTreeMap::new());
        assert_eq!(accepted.files[&key].source_file_fingerprint, "new-source");
        assert!(accepted.files[&key].has_unverified_source());
    }
    #[test]
    fn sampled_audit_missing_source_and_existing_cas_cannot_erase_obligation() {
        let root = std::env::temp_dir().join(format!(
            "ottto-audit-index-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("index.json");
        let mut index = index();
        let key = local_index_key(&candidate().path);
        index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200,
            },
        );
        index.remove_file_entry(&key);
        assert!(index.files.contains_key(&key));
        index.save(&path).unwrap();
        let mut older = ScanIndex::load(&path).unwrap();
        let mut current = ScanIndex::load(&path).unwrap();
        assert!(current.files[&key].has_unverified_source());
        current.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 150,
            },
        );
        current.save(&path).unwrap();
        older.complete_full_audit(&key, "source");
        assert!(older.save(&path).is_err());
        let loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            loaded.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            150
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    fn index() -> ScanIndex {
        let mut index = ScanIndex::default();
        let entry = serde_json::from_value(json!({
            "size_bytes": 1, "modified_unix_seconds": 1,
            "modified_unix_nanos": 1, "source_file_fingerprint": "source",
            "last_snapshot_fingerprint": null,
            "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
        }))
        .unwrap();
        index.files.insert("file".into(), entry);
        index
    }
    #[test]
    fn prefix_provenance_survives_record_replay_and_deadline_carry() {
        let mut index = index();
        index
            .files
            .get_mut("file")
            .unwrap()
            .set_unverified_deadline(200);
        assert!(index.mark_sealed_prefix("file", "source"));
        let mut ordinary = self::index();
        ordinary
            .files
            .get_mut("file")
            .unwrap()
            .set_unverified_deadline(300);
        ordinary
            .files
            .get_mut("file")
            .unwrap()
            .carry_sampled_audit(&index.files["file"]);
        assert!(ordinary.files["file"].has_prefix_provenance());
        assert_eq!(ordinary.files["file"].unverified_deadline(), Some(200));
        let mut carried: ScanIndexEntry =
            serde_json::from_value(serde_json::to_value(&index.files["file"]).unwrap()).unwrap();
        carried.scan_identity_version = Some(carried.carried_audit_version());
        carried.set_unverified_deadline(150);
        assert!(carried.has_prefix_provenance());
        assert_eq!(carried.unverified_deadline(), Some(150));
        index.prepare_historical_replay("replay".into());
        assert!(index.files["file"].has_prefix_provenance());
        assert_eq!(index.files["file"].unverified_deadline(), Some(200));
    }
    #[test]
    fn prefix_clear_requires_exact_fingerprint_and_keeps_tail_audit_debt() {
        let mut index = index();
        index
            .files
            .get_mut("file")
            .unwrap()
            .set_unverified_deadline(200);
        assert!(index.mark_sealed_prefix("file", "source"));
        assert!(!index.complete_native_recomposition("file", "stale"));
        assert!(!index.complete_full_audit("file", "stale"));
        assert!(index.files["file"].has_prefix_provenance());
        assert!(index.complete_native_recomposition("file", "source"));
        assert!(!index.files["file"].has_prefix_provenance());
        assert_eq!(index.files["file"].unverified_deadline(), Some(200));
        assert!(index.mark_sealed_prefix("file", "source"));
        assert!(index.complete_full_audit("file", "source"));
        assert!(!index.files["file"].has_prefix_provenance());
        assert!(!index.files["file"].has_unverified_source());
    }

    /// c22 G1: `record` carries only an existing sampled stem. A replay-reset
    /// or legacy entry (never a prefix) re-recorded without
    /// verification or obligation becomes the clean identity; the same
    /// completion's FE mark still tags `p`.
    #[test]
    fn ordinary_record_never_mints_prefix_but_fe_mark_after_record_does() {
        let candidate = CandidateFile {
            physical_identity: None,
            scan_root: PathBuf::from("/synthetic"),
            path: PathBuf::from("/synthetic/session.jsonl"),
            size_bytes: 1,
            modified_unix_seconds: 1,
            modified_unix_nanos: 1,
            source_file_fingerprint: "source".into(),
            legacy_source_file_fingerprint: "legacy".into(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".into(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
            withheld_content_stamp: None,
        };
        let key = local_index_key(&candidate.path);
        for reset in [None, Some("semantic_sync:v1"), Some("unknown-provenance")] {
            let mut entry = index().files.remove("file").unwrap().into_inner();
            entry.scan_identity_version = reset.map(Into::into);
            assert!(
                !entry.has_prefix_provenance(),
                "{reset:?}: SOURCE Option 1: a non-stem identity is not a prefix"
            );
            let mut ordinary = ScanIndex::default();
            ordinary.files.insert(key.clone(), entry);
            let mut marked = ordinary.clone();
            let ((), counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
                ordinary.record(candidate.clone(), None, ScanParseOutcome::ConfirmedEmpty)
            });
            let entry = &ordinary.files[&key];
            assert_eq!(
                entry.scan_identity_version.as_deref(),
                Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION),
                "{reset:?}"
            );
            assert!(!entry.has_prefix_provenance(), "{reset:?}");
            assert!(!entry.has_unverified_source(), "{reset:?}: no audit debt");
            assert!(entry.audit_obligation(100).is_none(), "{reset:?}");
            assert_eq!(counts.prefix_tag_clears, 0, "{reset:?}");
            marked.record(candidate.clone(), None, ScanParseOutcome::ConfirmedEmpty);
            assert!(marked.mark_sealed_prefix(&key, "source"));
            assert!(marked.files[&key].has_unverified_source(), "{reset:?}");
            assert!(marked.files[&key].has_prefix_provenance(), "{reset:?}");
        }
    }
}

/// Keep a provisionally retired path selectable if partial-save reconciliation
/// restores its marker. Preserve the actual read's root: guessing from nested
/// roots could change the acquisition scope. A committed retirement skips it.
pub(super) fn queue_quiet_retirement(index: &mut ScanIndex, key: &str, scan_root: PathBuf) {
    queue_pending(index, Path::new(key), || scan_root, false, false);
}

/// The one deduplicated pending-candidate insert. Callers keep their own side
/// effects (rearm cause, growth residue); an absent traversal queues nothing.
/// The root is produced only on insertion.
fn queue_pending(
    index: &mut ScanIndex,
    path: &Path,
    scan_root: impl FnOnce() -> PathBuf,
    census_member: bool,
    watcher_hint: bool,
) {
    if let Some(traversal) = index.traversal.as_mut() {
        if !traversal
            .pending_candidates
            .iter()
            .any(|queued| queued.path == path)
        {
            traversal.pending_candidates.push_back(ScanTraversalPath {
                scan_root: scan_root(),
                path: path.to_owned(),
                census_member,
                watcher_hint,
            });
        }
    }
}

/// A cap delay is still owed: persist an age-bypassing retry without advancing
/// the committed file size or claiming source/census completion.
pub(super) fn queue_cap_retry(index: &mut ScanIndex, candidate: &CandidateFile) {
    // The queue can disappear on a context-changing traversal replacement.
    // Reuse the existing durable reparse witness at every age/open gate and
    // in partial saves; keep the committed size and marker population intact.
    let key = local_index_key(&candidate.path);
    if let Some(entry) = index.files.get_mut(&key) {
        crate::local_resource_diagnostics::rearm_cause::clear(
            &key,
            entry,
            crate::local_resource_diagnostics::rearm_cause::Cause::AuditCapDelay,
        );
    }
    queue_pending(
        index,
        &candidate.path,
        || candidate.scan_root.clone(),
        true,
        true,
    );
}

/// Positive removal only: a file or intermediate directory is NotFound beneath
/// a readable ancestor securely reached from a configured, readable root.
/// Missing roots, symlinks and permission errors keep the audit and account debt.
/// This is absence authority, never source verification or census credit.
pub(super) fn proven_absent(path: &Path, roots: &[PathBuf]) -> bool {
    absence_parent(path, roots).is_some()
}

/// Pin the nearest existing parent so its inode cannot be reused between probes.
/// Depth binds the missing component when an intermediate directory is absent.
#[derive(Debug)]
pub(super) struct AbsenceParent {
    directory: File,
    depth: usize,
}
impl AbsenceParent {
    pub(super) fn same_parent(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.depth == other.depth
                && self
                    .directory
                    .metadata()
                    .ok()
                    .zip(other.directory.metadata().ok())
                    .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
        }
        #[cfg(not(unix))]
        {
            let _ = (self, other);
            false
        }
    }
}
/// The pinned parent of the first configured root it is proven under,
/// only when the root has no symlink in any component (its real path is
/// itself) and that parent is on the root's device. A redirected prefix or a
/// mounted-over or replaced volume is unmount-like and stays loss.
pub(super) fn absence_parent_on_root_device(
    path: &Path,
    roots: &[PathBuf],
) -> Option<AbsenceParent> {
    #[cfg(unix)]
    {
        roots.iter().find_map(|root| {
            let configured: PathBuf = root.components().collect();
            if fs::canonicalize(root).ok()? != configured {
                return None;
            }
            let parent = absence_parent(path, std::slice::from_ref(root))?;
            let device = fs::symlink_metadata(root).ok()?.dev();
            (parent.directory.metadata().ok()?.dev() == device).then_some(parent)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, roots);
        None
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for AbsenceParent {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            directory: _,
            depth: _,
        } = self;
        c.add(0)
    }
}

pub(super) fn absence_parent(path: &Path, roots: &[PathBuf]) -> Option<AbsenceParent> {
    #[cfg(unix)]
    {
        roots
            .iter()
            .find_map(|root| proven_absent_beneath_root(path, root).ok().flatten())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, roots);
        None
    }
}

#[cfg(unix)]
fn proven_absent_beneath_root(path: &Path, root: &Path) -> std::io::Result<Option<AbsenceParent>> {
    fn open_directory(parent: &File, name: &std::ffi::CStr) -> std::io::Result<File> {
        // Match open_candidate_beneath_root: every directory is readable and
        // no component below the configured root may redirect through a link.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn name_absent(parent: &File, name: &std::ffi::CStr) -> std::io::Result<bool> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // A dangling symlink is present, not positive absence. Stat relative
        // to the pinned parent without opening any transcript bytes.
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(true)
        } else {
            Err(error)
        }
    }
    fn same_directory(left: &File, right: &File) -> std::io::Result<bool> {
        let left = left.metadata()?;
        let right = right.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    if !root.is_absolute()
        || root
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Ok(None);
    }
    // Preserve the nofollow check on the root's final component even when its
    // configured spelling has a trailing separator or `/.`.
    let root: PathBuf = root.components().collect();
    let Ok(relative) = path.strip_prefix(&root) else {
        return Ok(None);
    };
    let mut names = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Ok(None);
        };
        let Ok(name) = std::ffi::CString::new(name.as_bytes()) else {
            return Ok(None);
        };
        names.push(name);
    }
    let Some((final_name, parents)) = names.split_last() else {
        return Ok(None);
    };
    let mut root_options = fs::OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directories = vec![root_options.open(&root)?];
    let mut missing_name = final_name;
    for name in parents {
        match open_directory(directories.last().expect("opened ancestor"), name) {
            Ok(next) => directories.push(next),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                // The last pinned directory is the nearest existing ancestor.
                // Do not traverse the missing suffix or accept any other error.
                missing_name = name;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    if !name_absent(directories.last().expect("opened ancestor"), missing_name)? {
        return Ok(None);
    }

    // A removed/replaced ancestor can leave a readable but detached descriptor.
    // Rewalk from the configured root and compare every pinned directory before
    // accepting ENOENT at the same missing component. Any observed substitution
    // or recreation (even an empty directory) keeps the debt.
    let mut directory = root_options.open(&root)?;
    if !same_directory(&directory, &directories[0])? {
        return Ok(None);
    }
    for (name, original) in parents.iter().zip(&directories[1..]) {
        directory = open_directory(&directory, name)?;
        if !same_directory(&directory, original)? {
            return Ok(None);
        }
    }
    if !name_absent(&directory, missing_name)? {
        return Ok(None);
    }
    Ok(Some(AbsenceParent {
        directory,
        depth: directories.len(),
    }))
}

#[cfg(all(test, unix))]
mod absence_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = crate::test_scratch::unique_path("ottto-audit-absence");
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn transcript(&self) -> PathBuf {
            let path = self.0.join("root/project/session/subagents/file.jsonl");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"owed transcript").unwrap();
            path
        }
        fn roots(&self) -> Vec<PathBuf> {
            vec![self.0.join("root")]
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn intermediate_symlink_cannot_prove_absence_in_another_tree() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        let saved = fixture.0.join("original-project");
        fs::rename(fixture.0.join("root/project"), &saved).unwrap();
        let replacement = fixture.0.join("replacement-project");
        fs::create_dir_all(replacement.join("session/subagents")).unwrap();
        symlink(&replacement, fixture.0.join("root/project")).unwrap();
        // Reproduce the old predicate's false proof: the final parent is a
        // readable directory, and only the transcript name is NotFound.
        assert_eq!(
            fs::symlink_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(fs::read_dir(path.parent().unwrap()).is_ok());
        assert!(!proven_absent(&path, &fixture.roots()));
        assert!(saved.join("session/subagents/file.jsonl").is_file());
    }

    #[test]
    fn real_deletion_beneath_readable_parent_proves_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        assert!(!proven_absent(&path, &fixture.roots()));
        fs::remove_file(&path).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn missing_intermediate_directory_beneath_readable_root_proves_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
        fs::remove_dir_all(fixture.0.join("root/project")).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"recreated transcript").unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn missing_configured_root_cannot_prove_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_dir_all(fixture.0.join("root")).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn dangling_symlink_or_non_directory_ancestor_cannot_prove_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        let project = fixture.0.join("root/project");
        fs::remove_dir_all(&project).unwrap();
        symlink("missing-project", &project).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
        fs::remove_file(&project).unwrap();
        fs::write(&project, b"not a directory").unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn unreadable_existing_ancestor_or_root_cannot_prove_absence() {
        use std::os::unix::fs::PermissionsExt;

        // Root can bypass directory permissions; this control needs an
        // unprivileged process to exercise the permission-error boundary.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let fixture = Fixture::new();
        let path = fixture.transcript();
        let root = fixture.0.join("root");
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
        for directory in [path.parent().unwrap().parent().unwrap(), root.as_path()] {
            let permissions = fs::metadata(directory).unwrap().permissions();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o0)).unwrap();
            let absent = proven_absent(&path, &fixture.roots());
            fs::set_permissions(directory, permissions).unwrap();
            assert!(!absent);
        }
    }

    #[test]
    fn recreated_transcript_is_present_even_after_positive_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_file(&path).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
        fs::write(&path, b"new transcript").unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
        fs::remove_file(&path).unwrap();
        symlink("missing-target", &path).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn uncertain_roots_and_non_normal_paths_cannot_prove_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_file(&path).unwrap();
        assert!(!proven_absent(&path, &[]));
        assert!(!proven_absent(&path, &[fixture.0.join("elsewhere")]));
        assert!(!proven_absent(&fixture.0.join("root"), &fixture.roots()));
        assert!(!proven_absent(
            &path.parent().unwrap().join("../subagents/file.jsonl"),
            &fixture.roots()
        ));
        let root_link = fixture.0.join("root-link");
        symlink(fixture.0.join("root"), &root_link).unwrap();
        for root in [root_link.clone(), root_link.join(""), root_link.join(".")] {
            assert!(!proven_absent(
                &root.join("project/session/subagents/file.jsonl"),
                &[root]
            ));
        }
        fs::remove_dir_all(fixture.0.join("root")).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }
}

#[cfg(all(test, not(unix)))]
mod absence_non_unix_tests {
    #[test]
    fn absence_never_grants_authority_without_secure_directory_descriptors() {
        assert!(!super::proven_absent(
            std::path::Path::new("missing/file.jsonl"),
            &[std::path::PathBuf::from("missing")]
        ));
    }
}

/// V2-only selection bookkeeping. The key keeps the index key's PL class;
/// sizes, generations and consecutive uncertainty are N. It conveys no proof.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct GrowthRetention {
    predecessor_size: Option<u64>,
    uncertain_passes: u32,
    pub(super) checked_generation: Option<u64>,
    last_growth_full_unix: Option<u64>,
}
crate::heap_layout_bound::fields!(GrowthRetention; predecessor_size, uncertain_passes, checked_generation, last_growth_full_unix);

pub(super) fn growth_active(index: &ScanIndex) -> bool {
    crate::snapshots::state_v2::state_v2_growth_retention_active(index)
}

/// Owed native growth debt. Fresh growth (`len > size_bytes`) is main's
/// owes_stamped/codex_fragment::grown, which every age gate checks first.
pub(super) fn growth_selectable(
    source: SnapshotSource,
    path: &Path,
    growth: Option<&BTreeMap<String, GrowthRetention>>,
) -> bool {
    source == SnapshotSource::ClaudeCode
        && growth.is_some_and(|growth| {
            growth
                .get(&local_index_key(path))
                .is_some_and(|state| state.predecessor_size.is_some())
        })
}

fn retain_growth(index: &mut ScanIndex, key: &str, len: Option<u64>) {
    let Some(entry) = index.files.get(key) else {
        return;
    };
    let size = entry.size_bytes;
    let state = index
        .v2_mut()
        .growth_retention
        .entry(key.to_owned())
        .or_default();
    if state.predecessor_size.is_none() {
        state.predecessor_size = Some(size);
        crate::local_resource_diagnostics::v2_growth_retained(
            len.unwrap_or(size).saturating_sub(size),
        );
    }
    if let Some(walk) = index.traversal.as_mut() {
        walk.residue.index_keys.insert(key.to_owned());
    }
}

pub(super) fn retain_candidate_growth(
    source: SnapshotSource,
    index: &mut ScanIndex,
    candidate: &CandidateFile,
) {
    if !growth_active(index) {
        return;
    }
    let key = local_index_key(&candidate.path);
    // Selection, not an age gate: fresh growth starts its debt here.
    let grown = source == SnapshotSource::ClaudeCode
        && index
            .files
            .get(&key)
            .is_some_and(|entry| candidate.size_bytes > entry.size_bytes);
    if grown || growth_selectable(source, &candidate.path, Some(&index.v2().growth_retention)) {
        retain_growth(index, &key, Some(candidate.size_bytes));
    }
}

/// Metadata only, through the acquisition path's configured-root/no-follow open.
/// A failed open is never negative growth evidence. Positive absence keeps the
/// existing independent absence rules (including unreadable/missing roots).
pub(super) fn revalidate_growth(index: &mut ScanIndex, key: &str, roots: &[PathBuf]) -> bool {
    if !growth_active(index) || !index.files.contains_key(key) {
        return false;
    }
    let path = Path::new(key);
    let root = roots
        .iter()
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.components().count());
    let len = root.and_then(|root| {
        let candidate = CandidateFile {
            physical_identity: None,
            scan_root: root.clone(),
            path: path.to_owned(),
            size_bytes: 0,
            modified_unix_seconds: 0,
            modified_unix_nanos: 0,
            source_file_fingerprint: String::new(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
            withheld_content_stamp: None,
        };
        open_candidate_beneath_root(&candidate)
            .ok()?
            .metadata()
            .ok()
            .filter(|stat| stat.is_file())
            .map(|stat| stat.len())
    });
    let uncertain = len.is_none() && !proven_absent(path, roots);
    crate::local_resource_diagnostics::v2_growth_revalidate(uncertain);
    let retained = uncertain
        || index
            .v2()
            .growth_retention
            .get(key)
            .is_some_and(|state| state.predecessor_size.is_some())
            && len.is_some()
        || len.is_some_and(|len| len > index.files[key].size_bytes);
    if retained {
        retain_growth(index, key, len);
    }
    let generation = index.generation;
    // Restored residue needs a known status, or every page would re-select it.
    let residue = index
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.residue.index_keys.contains(key));
    let v2 = index.v2_mut();
    if uncertain {
        let state = v2.growth_retention.entry(key.to_owned()).or_default();
        if state.checked_generation != Some(generation) {
            state.checked_generation = Some(generation);
            state.uncertain_passes = state.uncertain_passes.saturating_add(1);
            if state.uncertain_passes > 3 {
                crate::local_resource_diagnostics::v2_growth_uncertain_alarm(
                    state.uncertain_passes,
                );
            }
        }
    } else if let Some(state) = v2.growth_retention.get_mut(key) {
        // Persist only a status change: no per-generation rewrite.
        state.uncertain_passes = 0;
        state.checked_generation.get_or_insert(generation);
    } else if residue {
        // Other check-only results (aged or kept-overlap retirement
        // candidates) persist nothing; the runtime memo bounds the work.
        v2.growth_retention.insert(
            key.to_owned(),
            GrowthRetention {
                checked_generation: Some(generation),
                ..GrowthRetention::default()
            },
        );
    }
    if !retained {
        return false;
    }
    if let Some(root) = root {
        queue_growth_path(index, key, root.clone(), true);
    }
    true
}

fn queue_growth_path(index: &mut ScanIndex, key: &str, scan_root: PathBuf, census_member: bool) {
    queue_pending(index, Path::new(key), || scan_root, census_member, false);
    if let Some(walk) = index.traversal.as_mut() {
        walk.residue.index_keys.insert(key.to_owned());
    }
}

pub(super) fn queue_growth_retry(index: &mut ScanIndex, candidate: &CandidateFile) {
    queue_growth_path(
        index,
        &local_index_key(&candidate.path),
        candidate.scan_root.clone(),
        false,
    );
}

/// A paced growth read (recent claim) is a deferral, never an unreadable: it
/// keeps its debt and is not re-queued, since every page would refuse it
/// again. Any other refusal keeps the re-queue and its unreadable Reduction.
#[track_caller]
pub(super) fn defer_growth_read(
    index: &mut ScanIndex,
    census: &mut ScanCensus,
    candidate: &CandidateFile,
) {
    let key = local_index_key(&candidate.path);
    let now = sampled_scan::now_seconds();
    if !index
        .v2()
        .growth_retention
        .get(&key)
        .is_some_and(|state| growth_claim_recent(state, now))
    {
        queue_growth_retry(index, candidate);
        return census.record_unreadable(UnreadableCause::Reduction, 1);
    }
    census.growth_deferred = census.growth_deferred.saturating_add(1);
    if let Some(walk) = index.traversal.as_mut() {
        walk.residue.index_keys.insert(key);
    }
}

/// Only native completion calls this; opens, length equality, progress saves,
/// audit retirement and delivery ACKs do not settle source growth.
pub(super) fn settle_growth(index: &mut ScanIndex, key: &str) {
    if growth_active(index) {
        let generation = index.generation;
        let v2 = index.v2_mut();
        if let Some(state) = v2.growth_retention.get_mut(key) {
            state.predecessor_size = None;
            state.uncertain_passes = 0;
            state.checked_generation = Some(generation);
        }
    }
}

pub(super) fn growth_subset(
    index: &ScanIndex,
    previous: &ScanIndex,
    safe: &BTreeSet<String>,
) -> BTreeMap<String, GrowthRetention> {
    let mut debt = index.v2().growth_retention.clone();
    if !growth_active(index) {
        return debt;
    }
    for (key, state) in &previous.v2().growth_retention {
        if !safe.contains(key) {
            let current = debt.entry(key.clone()).or_insert_with(|| state.clone());
            if state.predecessor_size.is_some() {
                current.predecessor_size = state.predecessor_size;
            }
        }
    }
    merge_growth_claims(&mut debt, &previous.v2().growth_retention);
    debt
}

pub(super) const GROWTH_FULL_INTERVAL: u64 = 6 * 60 * 60;

pub(super) fn prune_growth_retention(index: &mut ScanIndex, now: u64) {
    let files = &index.files;
    let Some(v2) = index.v2.as_mut() else { return };
    let reclaimed = reclaim_growth(&mut v2.growth_retention, |key| files.contains_key(key), now);
    if growth_active(index) {
        note_growth_reclaimed(reclaimed);
    }
}
fn reclaim_growth(
    retention: &mut BTreeMap<String, GrowthRetention>,
    has_file: impl Fn(&str) -> bool,
    now: u64,
) -> usize {
    let before = retention.len();
    retention.retain(|key, state| {
        has_file(key)
            || state
                .last_growth_full_unix
                .is_some_and(|last| now < last.saturating_add(GROWTH_FULL_INTERVAL))
    });
    before - retention.len()
}
fn note_growth_reclaimed(reclaimed: usize) {
    if reclaimed > 0 {
        crate::local_resource_diagnostics::claude_state_v2(&serde_json::json!({
            "growth_claim_reclaimed": reclaimed
        }));
    }
}

/// A load lineage shares only the generation of its own claim-only commits.
/// Ordinary saves replace this context, so stale clones cannot skip their CAS.
/// No transcript, checkpoint payload or second pacing store lives here.
#[derive(Debug)]
pub(super) struct GrowthClaimContext {
    path: PathBuf,
    base_generation: u64,
    v2_owner: Option<std::sync::Weak<state_v2::Runtime>>,
    receipt: Mutex<Option<(u64, (u64, u64))>>,
}
impl crate::heap_layout_bound::HeapLayoutBound for GrowthClaimContext {
    // The only heap allocation is the immutable path; the mutable receipt
    // contains only inline integers, so its heap charge cannot change.
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.path, c)
    }
}
pub(super) fn bind_growth_claims(index: &mut ScanIndex, path: &Path) {
    index.v2_mut().growth_claim_context = Some(Arc::new(GrowthClaimContext {
        path: path.to_owned(),
        base_generation: index.generation,
        v2_owner: index.v2().persistence_v2.as_ref().map(Arc::downgrade),
        receipt: Mutex::new(None),
    }));
}
pub(super) fn renew_growth_claims(index: &mut ScanIndex, path: &Path) {
    if index.v2().growth_claim_context.is_some() {
        bind_growth_claims(index, path);
    }
}
pub(super) fn own_growth_claim_generation(index: &ScanIndex, path: &Path) -> Option<u64> {
    let context = index.v2().growth_claim_context.as_ref()?;
    let (generation, stamp) = (*context.receipt.lock().ok()?)?;
    let matches = growth_owner_matches(index, context)
        && state_v2::confirmed_growth_stamp(index, path).ok() == Some(stamp)
        && stamp.0 == generation;
    (context.path == path
        && index.generation == context.base_generation
        && generation > context.base_generation
        && matches)
        .then_some(generation)
}

fn growth_owner_matches(index: &ScanIndex, context: &GrowthClaimContext) -> bool {
    match (&index.v2().persistence_v2, &context.v2_owner) {
        (Some(runtime), Some(owner)) => owner
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(runtime, &owner)),
        _ => false,
    }
}

fn authenticate_growth_generation(index: &ScanIndex, path: &Path) -> Result<()> {
    let context = index
        .v2()
        .growth_claim_context
        .as_ref()
        .context("growth claim context missing")?;
    anyhow::ensure!(
        context.path == path && growth_owner_matches(index, context),
        "growth claim owner changed"
    );
    let expected = own_growth_claim_generation(index, path).unwrap_or(index.generation);
    anyhow::ensure!(
        state_v2::confirmed_growth_stamp(index, path)?.0 == expected,
        "growth claim needs index reload"
    );
    Ok(())
}

/// Called after the claim's commit at `generation`, still under the checkpoint
/// lock. A same-generation replacement must not become a claim-lineage CAS bypass.
pub(super) fn publish_growth_claim_receipt(
    index: &ScanIndex,
    path: &Path,
    generation: u64,
) -> Result<()> {
    let context = index
        .v2()
        .growth_claim_context
        .as_ref()
        .context("growth claim context missing")?;
    anyhow::ensure!(context.path == path, "growth claim path changed");
    anyhow::ensure!(
        growth_owner_matches(index, context),
        "growth claim owner changed"
    );
    let stamp = state_v2::confirmed_growth_stamp(index, path)?;
    anyhow::ensure!(stamp.0 == generation, "growth claim publication changed");
    *context
        .receipt
        .lock()
        .map_err(|_| anyhow::anyhow!("growth claim receipt unavailable"))? =
        Some((generation, stamp));
    Ok(())
}

/// Claims are monotonic even when a subset restores an older file entry or
/// native completion clears its selection debt. A failed read still spent it.
pub(super) fn merge_growth_claims(
    target: &mut BTreeMap<String, GrowthRetention>,
    committed: &BTreeMap<String, GrowthRetention>,
) {
    for (key, state) in committed {
        if let Some(claim) = state.last_growth_full_unix {
            let current = target.entry(key.clone()).or_default();
            current.last_growth_full_unix =
                Some(current.last_growth_full_unix.unwrap_or(0).max(claim));
        }
    }
}

fn growth_claim_recent(state: &GrowthRetention, now: u64) -> bool {
    state
        .last_growth_full_unix
        .is_some_and(|last| now < last.saturating_add(GROWTH_FULL_INTERVAL))
}

/// Owed growth whose Full `claim_growth_full` would refuse now: selecting it
/// only defers it again (`defer_growth_read`), so it must not pull a family.
pub(super) fn growth_full_paced(index: &ScanIndex, key: &str, now: u64) -> bool {
    growth_active(index)
        && index.v2().growth_retention.get(key).is_some_and(|state| {
            state.predecessor_size.is_some() && growth_claim_recent(state, now)
        })
}

/// Debt whose claim has expired. Its deferral did not re-queue it, so its
/// queued path would wait behind the census FIFO; selection wakes it instead.
pub(super) fn expired_growth_claims(
    source: SnapshotSource,
    index: &ScanIndex,
    now: u64,
) -> BTreeSet<PathBuf> {
    if !growth_active(index) {
        return BTreeSet::new();
    }
    let mut oldest = 0_u64;
    let due: BTreeSet<_> = index
        .v2()
        .growth_retention
        .iter()
        .filter_map(|(key, state)| {
            state.predecessor_size?;
            let claim = state.last_growth_full_unix?;
            let expired_secs = now.checked_sub(claim.saturating_add(GROWTH_FULL_INTERVAL))?;
            oldest = oldest.max(expired_secs);
            Some(PathBuf::from(key))
        })
        .collect();
    if !due.is_empty() {
        crate::local_resource_diagnostics::hold_wake(source.api_slug(), due.len() as u64, oldest);
    }
    due
}

/// The claim is one store transaction CAS'd on this lineage's G; no
/// committed graph is decoded. A graph without its v2 runtime is refused.
fn claim_growth_full(index: &mut ScanIndex, key: &str, now: u64) -> Result<bool> {
    if index
        .v2()
        .growth_retention
        .get(key)
        .is_some_and(|state| growth_claim_recent(state, now))
        || index.decode_holds.contains("growth_retention", key)
    {
        return Ok(false);
    }
    let context = index
        .v2()
        .growth_claim_context
        .clone()
        .context("growth Full needs a committed scan index")?;
    let _lock = CheckpointLock::acquire(&context.path)?;
    authenticate_growth_generation(index, &context.path)?;
    let expected = own_growth_claim_generation(index, &context.path).unwrap_or(index.generation);
    // The committed graph shares this lineage's normalization; only claim
    // rows differ, so its availability is this graph's.
    index.require_persistence_available()?;
    let mut claim = index
        .v2()
        .growth_retention
        .get(key)
        .cloned()
        .unwrap_or_default();
    claim.last_growth_full_unix = Some(now);
    let decide =
        |rows: &mut BTreeMap<String, GrowthRetention>, held: bool, files: &BTreeSet<String>| {
            if held
                || rows
                    .get(key)
                    .is_some_and(|state| growth_claim_recent(state, now))
            {
                return false;
            }
            // The save's merge keeps the larger claim; this one is not recent,
            // so the committed claim is older. The save's pruning then applies.
            rows.insert(key.to_owned(), claim);
            note_growth_reclaimed(reclaim_growth(
                rows,
                |name| files.contains(name),
                sampled_scan::now_seconds(),
            ));
            true
        };
    let (admitted, committed) =
        state_v2::claim_growth_locked(&context.path, index, expected, key, decide)?;
    if admitted {
        let generation = expected.checked_add(1).context("growth claim generation")?;
        publish_growth_claim_receipt(index, &context.path, generation)?;
    }
    merge_growth_claims(&mut index.v2_mut().growth_retention, &committed);
    Ok(admitted)
}

/// Identity has already been checked by open_and_identify and ReadPlan.
/// Rewrites/shrinks keep their own counted cause; a missing reusable checkpoint
/// takes the existing Full only after a durable six-hour claim.
pub(super) fn growth_read_admitted(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    mode: crate::transcript_acquisition::ReadMode,
) -> bool {
    if !growth_active(index) {
        return true;
    }
    growth_read_admitted_at(index, candidate, mode, sampled_scan::now_seconds())
}
pub(super) fn growth_read_admitted_at(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    mode: crate::transcript_acquisition::ReadMode,
    now: u64,
) -> bool {
    use crate::transcript_acquisition::{FullReason, ReadMode};
    if !growth_active(index) {
        return true;
    }
    let key = local_index_key(&candidate.path);
    // A stale graph must not erase committed growth debt and bypass pacing.
    // Authenticate even rewrite Fulls before consulting working-page debt.
    if index.v2().persistence_v2.is_some() && matches!(mode, ReadMode::Full(_)) {
        let valid = (|| -> Result<()> {
            let path = &index
                .v2()
                .growth_claim_context
                .as_ref()
                .context("growth claim context missing")?
                .path;
            let _lock = CheckpointLock::acquire(path)?;
            authenticate_growth_generation(index, path)
        })();
        if valid.is_err() {
            state_v2::growth_claim_refused("lineage");
            return false;
        }
    }
    let held = index.decode_holds.contains("growth_retention", &key);
    if !held
        && !index
            .v2()
            .growth_retention
            .get(&key)
            .is_some_and(|state| state.predecessor_size.is_some())
    {
        return true;
    }
    if matches!(
        mode,
        ReadMode::Full(
            FullReason::StateMissing
                | FullReason::InvalidCheckpoint
                | FullReason::UnsupportedIdentity
        )
    ) {
        return match claim_growth_full(index, &key, now) {
            Ok(admitted) => admitted,
            Err(_) => {
                if index.v2().persistence_v2.is_some() {
                    state_v2::growth_claim_refused("publication");
                }
                false
            }
        };
    }
    true
}

#[cfg(test)]
mod growth_tests {
    use super::super::claude_request_census::{
        ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    };
    use super::*;

    const ACCEPTED: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    struct Fixture {
        root: PathBuf,
        path: PathBuf,
        key: String,
    }
    impl Fixture {
        fn new() -> Self {
            let root = crate::test_scratch::canonical_private_dir("ottto-v2-growth");
            let path = root.join("session.jsonl");
            fs::write(&path, b"old\n").unwrap();
            let key = local_index_key(&path);
            Self { root, path, key }
        }
        fn index(&self) -> ScanIndex {
            let index = self.legacy_index();
            self.persist(&index);
            ScanIndex::load(&self.storage_path()).unwrap()
        }
        fn legacy_index(&self) -> ScanIndex {
            let mut index = ScanIndex::default();
            let entry = serde_json::from_value(serde_json::json!({
                "size_bytes": 4, "modified_unix_seconds": 1, "modified_unix_nanos": 1,
                "source_file_fingerprint": "a".repeat(64), "last_snapshot_fingerprint": ACCEPTED,
                "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
            }))
            .unwrap();
            index.files.insert(self.key.clone(), entry);
            index.accepted_snapshot_fingerprints.insert(ACCEPTED.into());
            let record = ClaudeRequestCensusRecord::synthetic_for_test(
                &"a".repeat(64),
                1,
                ClaudeRequestCensusShape::Exact,
                vec![7],
            )
            .with_modified_for_test(Some(1));
            index
                .claude_request_census
                .insert_for_test(&self.key, record);
            ensure_bounded_traversal(
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&self.root),
                &mut index,
                "2026-10-07T12:00:00Z",
                30,
            );
            let walk = index.traversal.as_mut().unwrap();
            // The old directory has already been visited and age-skipped.
            walk.pending_directories.clear();
            walk.pending_candidates.clear();
            walk.observed_index_keys.clear();
            walk.reconciliation_upper_bound = Some(self.key.clone());
            index
        }
        fn storage_path(&self) -> PathBuf {
            self.root
                .join("snapshots/destinations")
                .join("a".repeat(64))
                .join("claude_code-test-scan-index.json")
        }
        fn persist(&self, index: &ScanIndex) {
            let path = self.storage_path();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let progress = serde_json::to_vec(&serde_json::json!({
                "schema_version": 3,
                "destination_namespace_hash": "a".repeat(64),
            }))
            .unwrap();
            if index.v2().persistence_v2.is_some() {
                index.clone().save(&path).unwrap();
            } else {
                state_v2::money_test_support::publish(index, &path, &progress);
            }
        }
        fn grow(&self) {
            fs::write(&self.path, b"old\nappend\n").unwrap();
        }
        fn pending(&self) -> ScanTraversalPath {
            ScanTraversalPath {
                scan_root: self.root.clone(),
                path: self.path.clone(),
                census_member: true,
                watcher_hint: false,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let path = self.storage_path();
            if path.parent().is_some_and(Path::exists) {
                state_v2::money_test_support::erase_published(&path);
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn restart_lenient(index: &ScanIndex) -> ScanIndex {
        if index.v2.is_some() || index.decode_holds.contains_field("growth_retention") {
            let root = crate::test_scratch::canonical_private_dir("growth-row-restart");
            let mut restored = state_v2::money_test_support::roundtrip_rows(
                index,
                &root.join("state.v2.sqlite.import"),
            );
            super::super::lenient_decode::post_decode_hydrated(
                &mut restored,
                "fixture",
                "claude_code",
            )
            .unwrap();
            fs::remove_dir_all(root).unwrap();
            restored.v2_mut().persistence_v2 = index.v2().persistence_v2.clone();
            restored
        } else {
            let mut bytes = Vec::new();
            super::super::lenient_decode::write_index(&mut bytes, index).unwrap();
            super::super::lenient_decode::read(
                std::io::Cursor::new(bytes),
                "fixture",
                "claude_code",
            )
            .unwrap()
        }
    }
    fn restart(index: &ScanIndex) -> ScanIndex {
        // V1 deliberately drops this field. Its independent v2 rows retain it.
        let serde: ScanIndex = serde_json::from_slice(&serde_json::to_vec(index).unwrap()).unwrap();
        assert!(serde.v2.is_none());
        let stored = restart_lenient(index);
        assert_eq!(stored.v2().growth_retention, index.v2().growth_retention);
        stored
    }

    /// [money] f1 resumed reconciliation keeps growth after hold and restart.
    #[test]
    fn f1_resumed_reconciliation_keeps_growth_after_hold_and_restart() {
        for age_days in [31, 40] {
            let fixture = Fixture::new();
            let held = fixture.index();
            fixture.grow();
            let mut resumed = restart(&held);
            let ((done, ()), rows) = crate::local_resource_diagnostics::capture(|| {
                let done = reconcile_missing_index_entries_with_limit(&mut resumed, 1);
                (done, ())
            });
            assert!(!done, "new census work defers terminal");
            assert_eq!(resumed.files[&fixture.key].size_bytes, 4);
            assert!(resumed.accepted_snapshot_fingerprints.contains(ACCEPTED));
            assert_eq!(resumed.claude_request_census.hash_total_for_test(), 1);
            assert!(resumed
                .traversal
                .as_ref()
                .unwrap()
                .residue
                .index_keys
                .contains(&fixture.key));
            assert_eq!(
                resumed
                    .traversal
                    .as_ref()
                    .unwrap()
                    .reconciliation_after
                    .as_deref(),
                Some(fixture.key.as_str())
            );
            assert!(rows
                .iter()
                .any(|row| row["counts"]["v2_growth_revalidate"]["stats"] == 1));
            resumed = restart(&resumed);
            let bounded = restart_lenient(&resumed);
            assert_eq!(bounded.v2().growth_retention, resumed.v2().growth_retention);
            assert!(resumed.v2().growth_retention[&fixture.key]
                .predecessor_size
                .is_some());
            let mut census = ScanCensus::default();
            let now = unix_seconds(SystemTime::now()).unwrap() + age_days * 86400;
            let candidate = candidate_from_traversal_path(
                SnapshotSource::ClaudeCode,
                fixture.pending(),
                &mut census,
                Some(now),
                30,
                // v2 growth follows the index (production derivation).
                &mut crate::snapshots::CandidateDiscovery::new(&mut resumed.clone(), None),
            )
            .unwrap();
            assert!(open_and_identify_scan_candidate_at(
                SnapshotSource::ClaudeCode,
                candidate,
                &mut census,
                crate::snapshots::CandidateWindow {
                    census_unix_seconds: Some(now),
                    backfill_window_days: 30,
                    retention: crate::snapshots::DiscoveryRetention::unverified(&resumed.files),
                    growth: Some(&resumed.v2().growth_retention),
                },
            )
            .is_some());
        }
    }

    /// [money] Growth settlement keeps a progress restart's audit debt.
    #[test]
    fn f2_progress_restart_growth_settlement_keeps_audit_debt() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        fixture.grow();
        assert!(revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root)
        ));
        // A progress checkpoint can advance working bytes before settlement.
        index.files.get_mut(&fixture.key).unwrap().size_bytes = 11;
        let mut index = restart(&index);
        index.traversal.as_mut().unwrap().pending_candidates.clear();
        index
            .files
            .get_mut(&fixture.key)
            .unwrap()
            .set_unverified_deadline(40 * 86400 + 10);
        settle_growth(&mut index, &fixture.key);
        assert!(
            index.files[&fixture.key].has_unverified_source(),
            "growth settlement does not erase audit debt"
        );
    }

    /// [off=main] f3 off preserves v1 age and bytes.
    #[test]
    fn f3_off_preserves_v1_age_and_bytes() {
        let fixture = Fixture::new();
        let mut index = fixture.legacy_index();
        fixture.grow();
        let before = serde_json::to_vec(&index).unwrap();
        assert!(!growth_active(&index));
        let candidate = identified(&fixture, &index);
        assert!(growth_read_admitted_at(
            &mut index,
            &candidate,
            crate::transcript_acquisition::ReadMode::Full(
                crate::transcript_acquisition::FullReason::StateMissing
            ),
            100,
        ));
        assert!(!revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root)
        ));
        assert_eq!(serde_json::to_vec(&index).unwrap(), before);
        assert!(!serde_json::from_slice::<serde_json::Value>(&before)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("growth_retention"));
        assert_eq!(serde_json::to_vec(&restart(&index)).unwrap(), before);
        let mut census = ScanCensus::default();
        let now = unix_seconds(SystemTime::now()).unwrap() + 40 * 86400;
        // Main's #876 retains an indexed grown file across the window
        // (DiscoveryRetention::owes_stamped / codex_fragment::grown); OFF
        // selects it exactly as main does, without any v2 growth custody.
        assert!(candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            fixture.pending(),
            &mut census,
            Some(now),
            30,
            // v2 growth follows the index (production derivation).
            &mut crate::snapshots::CandidateDiscovery::new(&mut index.clone(), None),
        )
        .is_some());
        assert!(reconcile_missing_index_entries_with_limit(&mut index, 1));
        assert!(!index.files.contains_key(&fixture.key));
    }

    /// [money] f9 uncertainty alarms on fourth consecutive saved pass without dropping.
    #[test]
    fn f9_uncertainty_alarms_on_fourth_consecutive_saved_pass_without_dropping() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        let missing_root = fixture.root.join("not-configured");
        for pass in 1..=4 {
            index.generation = pass;
            let (_, rows) = crate::local_resource_diagnostics::capture(|| {
                assert!(revalidate_growth(
                    &mut index,
                    &fixture.key,
                    std::slice::from_ref(&missing_root)
                ));
                // Repeat in the same pass must not spend another uncertainty.
                assert!(revalidate_growth(
                    &mut index,
                    &fixture.key,
                    std::slice::from_ref(&missing_root)
                ));
            });
            assert_eq!(
                rows.iter()
                    .any(|row| row["stage"] == "v2_growth_uncertain_alarm"),
                pass == 4
            );
            assert!(index.files.contains_key(&fixture.key));
            index = restart(&index);
        }
        assert_eq!(
            index.v2().growth_retention[&fixture.key].uncertain_passes,
            4
        );
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        assert_eq!(
            index.v2().growth_retention[&fixture.key].uncertain_passes,
            0
        );
    }
    /// [regress] N5: revalidation rewrote debt rows every generation.
    #[test]
    fn growth_revalidation_records_checked_status_once() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        assert!(!index.v2().growth_retention.contains_key(&fixture.key));
        // A debt row records its checked status once, not every generation.
        fixture.grow();
        let roots = std::slice::from_ref(&fixture.root);
        assert!(revalidate_growth(&mut index, &fixture.key, roots));
        let checked = index.v2().growth_retention[&fixture.key].checked_generation;
        assert!(checked.is_some());
        index.generation += 1;
        assert!(revalidate_growth(&mut index, &fixture.key, roots));
        assert_eq!(
            index.v2().growth_retention[&fixture.key].checked_generation,
            checked
        );
    }

    /// [money] f3 identity causes are not reclassified as retained growth.
    #[test]
    fn f3_identity_causes_are_not_reclassified_as_retained_growth() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let mut index = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            fixture.pending(),
            &mut census,
            None,
            30,
            // v2 growth follows the index (production derivation).
            &mut crate::snapshots::CandidateDiscovery::new(&mut index.clone(), None),
        )
        .unwrap();
        let (candidate, _) = open_and_identify_scan_candidate_at(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut census,
            crate::snapshots::CandidateWindow {
                census_unix_seconds: None,
                backfill_window_days: 30,
                retention: crate::snapshots::DiscoveryRetention::unverified(&index.files),
                growth: Some(&index.v2().growth_retention),
            },
        )
        .unwrap();
        for cause in [
            FullReason::Replaced,
            FullReason::Shrunk,
            FullReason::HeadChanged,
            FullReason::BoundaryChanged,
            FullReason::SameSizeEdit,
        ] {
            assert!(growth_read_admitted(
                &mut index,
                &candidate,
                ReadMode::Full(cause)
            ));
        }
        assert!(growth_read_admitted(&mut index, &candidate, ReadMode::Tail));
        assert!(
            !growth_read_admitted(
                &mut restart(&index),
                &candidate,
                ReadMode::Full(FullReason::StateMissing)
            ),
            "no restart allowance without a durable Full claim"
        );
    }

    /// [money] f2 growth subset restores debt for unsettled file only.
    #[test]
    fn f2_growth_subset_restores_debt_for_unsettled_file_only() {
        let fixture = Fixture::new();
        let mut previous = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut previous,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        let mut working = previous.clone();
        settle_growth(&mut working, &fixture.key);
        let mut subset = restart(&working);
        subset.v2_mut().growth_retention = growth_subset(&working, &previous, &BTreeSet::new());
        assert!(restart(&subset).v2().growth_retention[&fixture.key]
            .predecessor_size
            .is_some());
        assert!(
            growth_subset(&working, &previous, &BTreeSet::from([fixture.key.clone()]))
                .values()
                .all(|state| state.predecessor_size.is_none())
        );
    }
    fn identified(fixture: &Fixture, index: &ScanIndex) -> CandidateFile {
        identified_for_source(fixture, index, SnapshotSource::ClaudeCode)
    }
    fn identified_for_source(
        fixture: &Fixture,
        index: &ScanIndex,
        source: SnapshotSource,
    ) -> CandidateFile {
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            source,
            fixture.pending(),
            &mut census,
            None,
            30,
            // v2 growth follows the index (production derivation).
            &mut crate::snapshots::CandidateDiscovery::new(&mut index.clone(), None),
        )
        .unwrap();
        open_and_identify_scan_candidate_at(
            source,
            candidate,
            &mut census,
            crate::snapshots::CandidateWindow {
                census_unix_seconds: None,
                backfill_window_days: 30,
                retention: crate::snapshots::DiscoveryRetention::unverified(&index.files),
                growth: Some(&index.v2().growth_retention),
            },
        )
        .unwrap()
        .0
    }

    /// [regress] the two v2 loaders bound claims differently: Codex daemon loads
    /// had no lineage, so every Full was refused. Both loaders, every active source.
    #[test]
    fn every_v2_loader_binds_growth_claims_for_every_active_source() {
        use super::super::scan_index_persistence::Source;
        use state_v2::money_test_support::ColdSession;

        for source in [Source::Claude, Source::Codex] {
            let fixture = Fixture::new();
            let (session, _) = ColdSession::publish(source, &ScanIndex::default(), &fixture.root);
            let path = session.path();
            for daemon in [false, true] {
                let index = if daemon {
                    ScanIndex::load_for_snapshot_source(path, source.snapshot(), &fixture.root)
                } else {
                    ScanIndex::load(path)
                }
                .unwrap();
                assert!(growth_active(&index));
                let _lock = CheckpointLock::acquire(path).unwrap();
                authenticate_growth_generation(&index, path).unwrap();
            }
        }
    }

    /// [regress] daemon v2 loads authenticate plain Full reads for every active source.
    #[test]
    fn daemon_v2_load_authenticates_plain_full_for_active_sources() {
        use super::super::scan_index_persistence::Source;
        use crate::transcript_acquisition::{FullReason, ReadMode, ReadPlan, Scope};
        use state_v2::money_test_support::ColdSession;

        for source in [Source::Claude, Source::Codex] {
            let fixture = Fixture::new();
            let (session, _) = ColdSession::publish(source, &ScanIndex::default(), &fixture.root);
            let mut index = ScanIndex::load_for_snapshot_source(
                session.path(),
                source.snapshot(),
                &fixture.root,
            )
            .unwrap();
            assert!(growth_active(&index));
            let candidate = identified_for_source(&fixture, &index, source.snapshot());
            let mut file = open_candidate_beneath_root(&candidate).unwrap();
            let plan = ReadPlan::prepare(
                &mut file,
                None,
                &Scope("daemon-growth-load".into()),
                None,
                100,
            )
            .unwrap();
            assert_eq!(plan.mode(), ReadMode::Full(FullReason::StateMissing));
            assert!(growth_read_admitted_at(
                &mut index,
                &candidate,
                plan.mode(),
                100,
            ));
        }
    }

    /// [money] f3 growth full claim survives restart failure and subset save.
    #[test]
    fn f3_growth_full_claim_survives_restart_failure_and_subset_save() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        for reason in [
            FullReason::StateMissing,
            FullReason::InvalidCheckpoint,
            FullReason::UnsupportedIdentity,
        ] {
            let fixture = Fixture::new();
            let path = fixture.storage_path();
            let mut initial = fixture.index();
            fixture.grow();
            revalidate_growth(
                &mut initial,
                &fixture.key,
                std::slice::from_ref(&fixture.root),
            );
            fixture.persist(&initial);
            let previous = ScanIndex::load(&path).unwrap();
            let mut unrelated = ScanIndex::load(&path).unwrap();
            let mut working = previous.clone();
            let candidate = identified(&fixture, &working);
            // The working page's progress/output is not committable yet.
            working.files.get_mut(&fixture.key).unwrap().size_bytes = 999;
            working
                .files
                .get_mut(&fixture.key)
                .unwrap()
                .last_snapshot_fingerprint = Some("d".repeat(64));
            let now = 100_000;
            assert!(growth_read_admitted_at(
                &mut working,
                &candidate,
                ReadMode::Full(reason),
                now
            ));
            // Simulate acquisition failure after admission. There is no refund:
            // a restart before any outcome save must still see the claim.
            fs::remove_file(&fixture.path).unwrap();
            assert!(open_candidate_beneath_root(&candidate).is_err());
            let mut resumed = ScanIndex::load(&path).unwrap();
            assert_eq!(resumed.files[&fixture.key].size_bytes, 4);
            assert_eq!(
                resumed.v2().growth_retention[&fixture.key].last_growth_full_unix,
                Some(now)
            );
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + GROWTH_FULL_INTERVAL - 1
            ));
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now - 1
            ));
            assert!(
                unrelated.save(&path).is_err(),
                "independent stale loads still fail CAS"
            );
            // Subset publication restores the old file, never the spent claim.
            let mut subset =
                working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
            assert_eq!(subset.files[&fixture.key].size_bytes, 4);
            subset.save(&path).unwrap();
            assert!(
                working.save(&path).is_err(),
                "ordinary publication ends the old claim-only lineage"
            );
            let mut resumed = ScanIndex::load(&path).unwrap();
            assert_eq!(
                resumed.v2().growth_retention[&fixture.key].last_growth_full_unix,
                Some(now)
            );
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + 1
            ));
            assert!(growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + GROWTH_FULL_INTERVAL
            ));
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + GROWTH_FULL_INTERVAL
            ));
            // Even a settled key keeps its clock if it grows again soon.
            settle_growth(&mut resumed, &fixture.key);
            assert_eq!(
                resumed.v2().growth_retention[&fixture.key].last_growth_full_unix,
                Some(now + GROWTH_FULL_INTERVAL)
            );
        }
    }

    /// [money] f3 growth full without durable index never reads.
    #[test]
    fn f3_growth_full_without_durable_index_never_reads() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let mut index = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        let candidate = identified(&fixture, &index);
        // A graph without a load-lineage receipt cannot authorize acquisition.
        index.v2_mut().growth_claim_context = None;
        assert!(!growth_read_admitted_at(
            &mut index,
            &candidate,
            ReadMode::Full(FullReason::StateMissing),
            100
        ));
        assert_eq!(
            index.v2().growth_retention[&fixture.key].last_growth_full_unix,
            None
        );
    }

    /// [money] f3 recent claim outlives removal until interval expires.
    #[test]
    fn f3_recent_claim_outlives_removal_until_interval_expires() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        index.v2_mut().growth_retention.insert(
            fixture.key.clone(),
            GrowthRetention {
                last_growth_full_unix: Some(100),
                ..Default::default()
            },
        );
        index.files.clear();
        prune_growth_retention(&mut index, 100 + GROWTH_FULL_INTERVAL - 1);
        assert_eq!(
            restart(&index).v2().growth_retention[&fixture.key].last_growth_full_unix,
            Some(100)
        );
        prune_growth_retention(&mut index, 100 + GROWTH_FULL_INTERVAL);
        assert!(index.v2().growth_retention.is_empty());
    }
    /// [money] f3 malformed growth claim stays held across codec round trips.
    #[test]
    fn f3_malformed_growth_claim_stays_held_across_codec_round_trips() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let initial = fixture.index();
        let candidate = identified(&fixture, &initial);
        for bad in [
            serde_json::json!({"last_growth_full_unix": "bad"}),
            serde_json::json!({"last_growth_full_unix": "x".repeat(4097)}),
        ] {
            let mut seeded = initial.clone();
            let bytes = serde_json::to_vec(&bad).unwrap();
            let charge = bytes.len() as u64 + 256;
            seeded
                .decode_holds
                .v2_insert("growth_retention", fixture.key.clone(), bytes, None, charge)
                .unwrap();
            let mut decoded = restart_lenient(&seeded);
            assert!(decoded
                .decode_holds
                .contains("growth_retention", &fixture.key));
            assert!(!growth_read_admitted_at(
                &mut decoded,
                &candidate,
                ReadMode::Full(FullReason::StateMissing),
                100
            ));
            let raw = decoded
                .decode_holds
                .v2_entries()
                .find(|(field, key, ..)| *field == "growth_retention" && *key == fixture.key)
                .unwrap()
                .2;
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(raw).unwrap(),
                bad
            );
            let decoded = restart_lenient(&decoded);
            assert!(decoded
                .decode_holds
                .contains("growth_retention", &fixture.key));
        }
    }

    /// [money] f3 failed claim save never authorizes full or spends memory only.
    #[test]
    fn f3_failed_claim_save_never_authorizes_full_or_spends_memory_only() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let path = fixture.storage_path();
        let mut index = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        fixture.persist(&index);
        let mut stale = ScanIndex::load(&path).unwrap();
        let candidate = identified(&fixture, &stale);
        let mut newer = ScanIndex::load(&path).unwrap();
        newer.save(&path).unwrap();
        assert!(!growth_read_admitted_at(
            &mut stale,
            &candidate,
            ReadMode::Full(FullReason::StateMissing),
            100
        ));
        assert_eq!(
            stale.v2().growth_retention[&fixture.key].last_growth_full_unix,
            None
        );
        assert_eq!(
            ScanIndex::load(&path).unwrap().v2().growth_retention[&fixture.key]
                .last_growth_full_unix,
            None
        );
    }
    /// [money] f3 claim receipt rejects same generation checkpoint replacement.
    #[test]
    fn f3_claim_receipt_rejects_same_generation_checkpoint_replacement() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let path = fixture.storage_path();
        let mut initial = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut initial,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        fixture.persist(&initial);
        let mut working = ScanIndex::load(&path).unwrap();
        let candidate = identified(&fixture, &working);
        assert!(growth_read_admitted_at(
            &mut working,
            &candidate,
            ReadMode::Full(FullReason::StateMissing),
            100
        ));
        let db_path = path.with_file_name(format!(
            "{}.v2.sqlite",
            path.file_name().unwrap().to_str().unwrap()
        ));
        let bytes = fs::read(&db_path).unwrap();
        let replacement = fixture.root.join("replacement.sqlite");
        fs::write(&replacement, &bytes).unwrap();
        fs::rename(&replacement, &db_path).unwrap();
        assert!(
            working.save(&path).is_err(),
            "same generation alone is not exact claim publication custody"
        );
        assert_eq!(fs::read(&db_path).unwrap(), bytes);
    }
}
