//! Audit status lives in the existing per-file index, never in a new ledger.
use super::*;
use crate::transcript_acquisition::{AuditDebt, AUDIT_INTERVAL_SECONDS};

pub(super) const UNVERIFIED_IDENTITY: &str = "semantic_sync:v2+sampled_unverified:v1";

// A deadline occupies the existing version string. This avoids adding an
// inline field to every ordinary index entry and every baseline index copy.
const MAX_MARKER_BYTES: usize = 64;
pub(super) fn marker(due: u64) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(MAX_MARKER_BYTES);
    write!(&mut value, "{UNVERIFIED_IDENTITY}:{due}").expect("bounded marker formats");
    value
}

impl ScanIndexEntry {
    pub(super) fn has_unverified_source(&self) -> bool {
        self.scan_identity_version
            .as_deref()
            .is_some_and(|version| version.starts_with(UNVERIFIED_IDENTITY))
    }
    pub(super) fn unverified_deadline(&self) -> Option<u64> {
        if !self.has_unverified_source() {
            return None;
        }
        Some(
            self.scan_identity_version
                .as_deref()
                .and_then(|version| version.strip_prefix(UNVERIFIED_IDENTITY)?.strip_prefix(':'))
                .filter(|due| !due.is_empty() && due.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|due| due.parse::<u64>().ok())
                .unwrap_or(0),
        )
    }
    pub(super) fn set_unverified_deadline(&mut self, due: u64) {
        self.scan_identity_version = Some(marker(due));
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
    /// Called only by a current validated native source completion. Entry/source
    /// equality fences an older completion; the existing writer owns lock/CAS.
    /// A delivery ACK never calls this method as source-verification authority.
    pub(super) fn stage_sampled_audit(
        &mut self,
        key: &str,
        source_fingerprint: &str,
        debt: AuditDebt,
    ) -> bool {
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
    pub(super) fn complete_full_audit(&mut self, key: &str, source_fingerprint: &str) -> bool {
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.source_file_fingerprint == source_fingerprint)
        else {
            return false;
        };
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        true
    }
}

/// An accepted sampled generation must be verified even after its activity
/// ages out. The existing bounded walk remains its sole scheduler. Other old
/// files keep the configured window, and secure opens/file caps still apply.
pub(super) fn path_requires_verification(
    files: &BTreeMap<String, ScanIndexEntry>,
    path: &Path,
) -> bool {
    files
        .get(&local_index_key(path))
        .is_some_and(ScanIndexEntry::has_unverified_source)
}

pub(super) fn normalize_marker_storage(index: &mut ScanIndex) {
    for entry in index
        .files
        .values_mut()
        .filter(|entry| entry.has_unverified_source())
    {
        if entry
            .scan_identity_version
            .as_ref()
            .is_some_and(|tag| tag.capacity() > MAX_MARKER_BYTES)
        {
            entry.set_unverified_deadline(0);
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
            scan_root: PathBuf::from("/synthetic"),
            path: PathBuf::from("/synthetic/session.jsonl"),
            size_bytes: 1,
            modified_unix_seconds: 1,
            modified_unix_nanos: 1,
            source_file_fingerprint: "source".into(),
            legacy_source_file_fingerprint: "legacy".into(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".into(),
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
