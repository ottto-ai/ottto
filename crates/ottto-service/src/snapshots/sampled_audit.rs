//! Audit status lives in the existing per-file index, never in a new ledger.
use super::*;
use crate::transcript_acquisition::{AuditDebt, AUDIT_INTERVAL_SECONDS};
use crate::transcript_cache::CACHE_ENTRIES;

// v1 did not distinguish an ordinary Tail from a published FE prefix.
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
        if let Some(due) = working.unverified_deadline() {
            self.scan_identity_version = Some(provenance_marker(
                self.unverified_deadline().map_or(due, |old| old.min(due)),
                self.has_prefix_provenance() || working.has_prefix_provenance(),
            ));
        }
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
    /// This caller just finished a loss-free, EOF-revalidated native Full or
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

/// Restorations per sampled scan: under a steady scan cadence, at most one
/// restored audit falls due per page.
const HOLD_DEADLINE_RESTORES_PER_SCAN: usize = 1;

/// A plain-v2 entry whose census record is an N1 hold owes its deadline back
/// (option B below). Until a scan restores it, reconciliation keeps it as it
/// keeps a marked entry: an unobserved aged file must not be pruned, with its
/// hold, while it waits for the per-scan or audit-slot budget.
pub(super) fn awaits_hold_deadline_restoration(index: &ScanIndex, key: &str) -> bool {
    index.files.get(key).is_some_and(|entry| {
        entry.scan_identity_version.as_deref() == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    }) && index
        .claude_request_census
        .get(key)
        .is_some_and(|record| record.identity_incomplete_hold())
}

/// Option B (SOURCE rule 3: a hold may delay a re-offer, never cancel it). A
/// marker-erasing daemon (0.1.189's parse-free migrate) rewrote held entries
/// to plain v2, dropping their audit deadline; an unchanged file then skips
/// forever and an aged one leaves discovery. Re-derive the marker from the
/// persisted census hold: one interval out, as a Tail stages it, and tagged
/// `p` because plain v2 cannot prove the lost tag was `c`. Each restored
/// entry owes one Full; the deadline only delays it. Restorations take free
/// audit slots and always leave one, so sampling stays supported.
pub(super) fn restore_held_audit_deadlines(index: &mut ScanIndex, now: u64) -> usize {
    let pending = index
        .files
        .values()
        .filter(|entry| entry.has_unverified_source())
        .take(CACHE_ENTRIES)
        .count();
    let budget = CACHE_ENTRIES
        .saturating_sub(pending.saturating_add(1))
        .min(HOLD_DEADLINE_RESTORES_PER_SCAN);
    let Some(due) = now.checked_add(AUDIT_INTERVAL_SECONDS) else {
        return 0;
    };
    let keys = index
        .claude_request_census
        .records()
        .map(|(key, _)| key)
        .filter(|key| awaits_hold_deadline_restoration(index, key))
        .take(budget)
        .cloned()
        .collect::<Vec<_>>();
    for key in &keys {
        // A large Full delayed by the per-pass scheduler still owes its
        // already-due rotating-slot audit. Moving it into a newly free sampled
        // slot must not replace that deadline with a fresh interval.
        let due = index
            .held_audit_progress
            .as_ref()
            .filter(|slot| {
                slot.key == *key
                    && (index.claude_large_full_deferred.contains(key) || slot.large_full_deferred)
            })
            .map_or(due, |slot| due.min(slot.due));
        if let Some(entry) = index.files.get_mut(key) {
            entry.scan_identity_version = Some(provenance_marker(due, true));
        }
    }
    if !keys.is_empty() {
        super::claude_request_census::note_identity_incomplete_hold_deadlines_restored(
            keys.len() as u64
        );
    }
    keys.len()
}

/// Saturated sampled slots must not make a plain-v2 hold wait for an
/// unrelated unavailable/oversized file forever. One durable rotating slot
/// schedules a native Full after a fresh interval, without allocating a
/// sampled marker or taking the last sampled slot. It grants no authority.
/// Failed attempts rotate too; their census holds stay eligible for the next
/// round. The fixed population therefore cannot starve a readable member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct HeldAuditProgress {
    pub(super) key: String,
    pub(super) due: u64,
    pub(super) attempted: bool,
    /// Negative scheduling evidence: this actual large Full was delayed.
    /// Independent of cached priority and the last committed file size.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) large_full_deferred: bool,
}
crate::heap_layout_bound::fields!(HeldAuditProgress; key, due, attempted, large_full_deferred);

pub(super) fn progress_debt(index: &ScanIndex, key: &str, now: u64) -> Option<AuditDebt> {
    let slot = index.held_audit_progress.as_ref()?;
    (slot.key == key && now >= slot.due && awaits_hold_deadline_restoration(index, key)).then_some(
        AuditDebt {
            due_unix_seconds: slot.due,
        },
    )
}

pub(super) fn debt_for_key(index: &ScanIndex, key: &str, now: u64) -> Option<AuditDebt> {
    index
        .files
        .get(key)
        .and_then(|entry| entry.audit_obligation(now))
        .or_else(|| progress_debt(index, key, now))
}

impl OwnedSourceScan {
    /// At most one additional Full attempt per page. The queue contains only
    /// a bounded path and deadline; entry/census identity is never rewritten.
    pub(super) fn prepare_held_audit_progress(&mut self, now: u64) {
        if self.file_limit == 0 {
            return;
        }
        let previous = self.index.held_audit_progress.as_ref();
        // A held key the slot may serve: bounded, still awaiting restoration,
        // and owned by a scan root, so the Full below can be queued.
        let eligible = |key: &str| {
            key.len() <= 4096
                && awaits_hold_deadline_restoration(&self.index, key)
                && self.index.traversal.as_ref().is_some_and(|traversal| {
                    traversal.first_matching_scan_root(Path::new(key)).is_some()
                })
        };
        let keep = previous.is_some_and(|slot| {
            !slot.attempted
                && slot.due > 0
                && now
                    .checked_add(AUDIT_INTERVAL_SECONDS)
                    .is_some_and(|latest| slot.due <= latest)
                && eligible(slot.key.as_str())
        });
        if !keep {
            let after = previous.map(|slot| slot.key.as_str());
            // BTreeMap order plus a persisted cursor gives every held path a
            // turn, including when a prior turn failed its secure open/cap.
            let key = self
                .index
                .claude_request_census
                .records()
                .map(|(key, _)| key)
                .filter(|key| eligible(key.as_str()))
                .find(|key| after.map_or(true, |after| key.as_str() > after))
                .or_else(|| {
                    self.index
                        .claude_request_census
                        .records()
                        .map(|(key, _)| key)
                        .find(|key| eligible(key.as_str()))
                })
                .cloned();
            self.index.held_audit_progress =
                key.zip(now.checked_add(AUDIT_INTERVAL_SECONDS))
                    .map(|(key, due)| HeldAuditProgress {
                        key,
                        due,
                        attempted: false,
                        large_full_deferred: false,
                    });
        }
        let Some(slot) = self.index.held_audit_progress.as_ref() else {
            return;
        };
        if now < slot.due {
            return;
        }
        let path = PathBuf::from(&slot.key);
        // First match, not deepest: the root enters the sampled scope hash.
        let Some(root) = self
            .index
            .traversal
            .as_ref()
            .and_then(|traversal| traversal.first_matching_scan_root(&path).cloned())
        else {
            return;
        };
        let key = slot.key.clone();
        let Some(entry) = self.index.files.get(&key) else {
            return;
        };
        let mut candidate = CandidateFile {
            physical_identity: None,
            scan_root: root,
            path,
            size_bytes: entry.size_bytes,
            modified_unix_seconds: entry.modified_unix_seconds,
            modified_unix_nanos: entry.modified_unix_nanos.unwrap_or_default(),
            source_file_fingerprint: String::new(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
        };
        // Mirror candidate conversion's census observation. An old queued
        // age rejection must not delete a successful recovery at settlement.
        if !self.census.claude_vanished_index_keys.contains(&key) {
            self.census.removed_index_keys.remove(&key);
        }
        self.census.observed_index_keys.insert(key.clone());
        let prior_position = self
            .identified_candidates
            .iter()
            .position(|candidate| local_index_key(&candidate.path) == key);
        // A held file may have grown since its committed entry. Use native
        // selection metadata (or one stat), so a newly large held audit cannot
        // jump ahead of older debt by masquerading as its old small size.
        candidate.size_bytes = prior_position
            .map(|at| self.identified_candidates[at].size_bytes)
            .or_else(|| {
                fs::symlink_metadata(&candidate.path)
                    .ok()
                    .filter(|meta| meta.is_file())
                    .map(|meta| meta.len())
            })
            .unwrap_or(candidate.size_bytes);
        self.identified_candidates
            .retain(|candidate| local_index_key(&candidate.path) != key);
        let large = claude_large_full::is_large(&candidate);
        let position = if large && self.index.claude_large_full_deferred.overflowing() {
            // Retain an already selected held key's rank. A newly injected
            // held audit cannot jump ahead of overflow's ordinary census FIFO.
            prior_position
                .unwrap_or(self.identified_candidates.len())
                .min(self.identified_candidates.len())
        } else if large {
            // A new rotating-slot audit cannot jump ahead of older deferred
            // large Fulls. Small held files keep their existing first position.
            self.identified_candidates
                .iter()
                .take_while(|candidate| {
                    let candidate_key = local_index_key(&candidate.path);
                    self.index
                        .claude_large_full_deferred
                        .iter()
                        // Preserve this key's rank when it is already debt;
                        // a newly scheduled key follows all existing debt.
                        .take_while(|deferred| deferred.as_str() != key.as_str())
                        .any(|deferred| deferred == &candidate_key)
                })
                .count()
        } else {
            0
        };
        self.identified_candidates.insert(position, candidate);
        // Preserve the ordinary page limit and every displaced candidate.
        while self.identified_candidates.len() > self.file_limit.max(1) {
            let candidate = self.identified_candidates.pop_back().unwrap();
            if let Some(traversal) = self.index.traversal.as_mut() {
                if let Some(pending) = traversal
                    .pending_candidates
                    .iter_mut()
                    .find(|pending| large && pending.path == candidate.path)
                {
                    pending.census_member = true;
                } else {
                    traversal.pending_candidates.push_front(ScanTraversalPath {
                        scan_root: candidate.scan_root,
                        path: candidate.path,
                        census_member: true,
                        watcher_hint: false,
                    });
                }
            }
        }
        if large
            && !self
                .identified_candidates
                .iter()
                .any(|candidate| local_index_key(&candidate.path) == key)
        {
            // Displaced by older debt at the existing page limit. No attempt,
            // no deadline reset: the same slot remains eligible next pass.
            self.index.held_audit_progress.as_mut().unwrap().attempted = false;
            return;
        }
        self.index.held_audit_progress.as_mut().unwrap().attempted = true;
        super::claude_request_census::note_identity_incomplete_hold_deadlines_restored(1);
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
        }
    }
    #[test]
    fn deferred_large_held_audit_keeps_original_deadline_and_older_turn() {
        use crate::snapshots::claude_request_census::{
            ClaudeRequestCensusRecord as Record, ClaudeRequestCensusShape as Shape,
        };
        let scratch = crate::test_scratch::ScratchDir::new("large-held-audit");
        let root = scratch.as_ref().to_path_buf();
        let older = root.join("a-older.jsonl");
        let held = root.join("b-held.jsonl");
        fs::write(&older, "{}\n").unwrap();
        fs::write(&held, "{}\n").unwrap();
        for path in [&older, &held] {
            File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(257 * 1024 * 1024)
                .unwrap();
        }
        let old_key = local_index_key(&older);
        let held_key = local_index_key(&held);
        let mut index = ScanIndex {
            claude_request_identity_contract: Some(claude_request_identity::COLLECTOR.into()),
            ..ScanIndex::default()
        };
        index.files.insert(old_key.clone(), entry());
        let mut held_entry = entry();
        // The rotating slot constructs its candidate from native index size.
        // This test exercises scheduling only; it never decodes sparse data.
        held_entry.size_bytes = 257 * 1024 * 1024;
        index.files.insert(held_key.clone(), held_entry);
        index.claude_request_census_mut_for_test().insert_for_test(
            &held_key,
            Record::synthetic_for_test(&"a".repeat(64), 1, Shape::IdentityIncomplete, vec![1])
                .with_unverified_for_test(true),
        );
        let context = scan_traversal_context_fingerprint(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &index,
            BACKFILL_WINDOW_DAYS,
        );
        index
            .claude_large_full_deferred
            .begin(&context, std::slice::from_ref(&root));
        index.claude_large_full_deferred.push_back(old_key.clone());
        index.held_audit_progress = Some(HeldAuditProgress {
            key: held_key.clone(),
            due: 50,
            attempted: false,
            large_full_deferred: false,
        });
        let mut seed = index.clone();
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            "2026-10-27T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            1,
            false,
            None,
            &[],
            false,
            true,
        );
        scan.prepare_held_audit_progress(100);
        assert_eq!(scan.identified_candidates.len(), 1, "existing page limit");
        assert_eq!(
            local_index_key(&scan.identified_candidates[0].path),
            old_key
        );
        assert!(!scan.index.held_audit_progress.as_ref().unwrap().attempted);
        assert_eq!(
            progress_debt(&scan.index, &held_key, 100)
                .unwrap()
                .due_unix_seconds,
            50
        );
        assert!(scan
            .index
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .any(|candidate| candidate.path == held && candidate.census_member));

        let mut candidate = candidate();
        candidate.path = held;
        candidate.scan_root = scratch.as_ref().to_path_buf();
        candidate.size_bytes = 257 * 1024 * 1024;
        scan.index.held_audit_progress.as_mut().unwrap().attempted = true;
        // The actual file grew, while committed metadata is still small.
        scan.index.files.get_mut(&held_key).unwrap().size_bytes = 1;
        let mut full_spent = true;
        assert!(!claude_large_full::admit(
            &mut scan.index,
            &candidate,
            true,
            &mut full_spent
        ));
        assert!(!scan.index.held_audit_progress.as_ref().unwrap().attempted);
        assert_eq!(
            scan.index
                .claude_large_full_deferred
                .iter()
                .cloned()
                .collect::<VecDeque<_>>(),
            VecDeque::from([old_key, held_key.clone()])
        );
        assert!(
            scan.index
                .held_audit_progress
                .as_ref()
                .unwrap()
                .large_full_deferred
        );
        let mut overflow_index = scan.index.clone();
        overflow_index.held_audit_progress = serde_json::from_slice(
            &serde_json::to_vec(&overflow_index.held_audit_progress).unwrap(),
        )
        .unwrap();
        overflow_index.claude_large_full_deferred = claude_large_full::Priority::fallback();
        assert_eq!(restore_held_audit_deadlines(&mut overflow_index, 100), 1);
        assert_eq!(
            overflow_index.files[&held_key].unverified_deadline(),
            Some(50),
            "uncached overflow keeps the same original held deadline"
        );
        assert_eq!(restore_held_audit_deadlines(&mut scan.index, 100), 1);
        assert_eq!(
            scan.index.files[&held_key].unverified_deadline(),
            Some(50),
            "moving into a free sampled slot cannot postpone overdue debt"
        );
        assert!(scan.index.files[&held_key].audit_requires_full(100));
        assert_eq!(
            scan.index.files[&held_key].source_file_fingerprint,
            "source"
        );

        let mut fresh_allowance = false;
        assert!(claude_large_full::admit(
            &mut scan.index,
            &candidate,
            true,
            &mut fresh_allowance
        ));
        assert!(
            !scan
                .index
                .held_audit_progress
                .as_ref()
                .unwrap()
                .large_full_deferred,
            "an admitted attempt resumes the original failure/rotation policy"
        );

        // Already-deferred held debt must keep its earlier rank. Saturate
        // the existing restoration slots so production with_sampled cannot
        // convert the plain-v2 hold before its rotating slot is scheduled.
        let newer_key = local_index_key(&older);
        seed.files.get_mut(&held_key).unwrap().size_bytes = 1;
        seed.claude_large_full_deferred.clear();
        seed.claude_large_full_deferred
            .begin(&context, std::slice::from_ref(&root));
        seed.claude_large_full_deferred.push_back(held_key.clone());
        seed.claude_large_full_deferred.push_back(newer_key.clone());
        for n in 0..CACHE_ENTRIES - 1 {
            let mut pending = entry();
            pending.set_unverified_deadline(50);
            seed.files
                .insert(format!("/unavailable-held-audit/{n}"), pending);
        }
        let mut overflow_value = serde_json::to_value(&seed).unwrap();
        overflow_value["claude_large_full_deferred"]["overflow"] = serde_json::json!(true);
        let overflow_seed: ScanIndex = serde_json::from_value(overflow_value).unwrap();
        let ordered = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            seed,
            "2026-10-27T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            2,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(
            Arc::new(sampled_scan::SharedCache::default()),
            crate::transcript_acquisition::Scope("held-audit-fifo".into()),
        );
        assert_eq!(
            ordered.sampling.as_ref().unwrap().audit_slots,
            1,
            "existing final sampled slot remains free"
        );
        assert!(ordered
            .identified_candidates
            .iter()
            .all(claude_large_full::is_large));
        assert_eq!(
            ordered
                .identified_candidates
                .iter()
                .map(|candidate| local_index_key(&candidate.path))
                .collect::<Vec<_>>(),
            vec![held_key.clone(), newer_key],
            "held debt keeps the oldest Full turn"
        );
        let slot = ordered.index.held_audit_progress.as_ref().unwrap();
        assert_eq!(slot.key, held_key);
        assert_eq!(slot.due, 50);
        assert!(
            slot.attempted,
            "oldest held candidate is selected, not displaced"
        );
        let overflow_ordered = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            overflow_seed,
            "2026-10-27T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            2,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(
            Arc::new(sampled_scan::SharedCache::default()),
            crate::transcript_acquisition::Scope("held-audit-overflow".into()),
        );
        assert_eq!(overflow_ordered.sampling.as_ref().unwrap().audit_slots, 1);
        assert_eq!(
            overflow_ordered
                .identified_candidates
                .iter()
                .map(|candidate| local_index_key(&candidate.path))
                .collect::<Vec<_>>(),
            vec![held_key.clone(), local_index_key(&older)],
            "overflow preserves existing held FIFO rank"
        );
        assert_eq!(
            overflow_ordered
                .index
                .held_audit_progress
                .as_ref()
                .unwrap()
                .due,
            50
        );
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

    /// Option B: only a plain-v2 entry whose census record is an N1 hold gets
    /// a deadline back; one per scan, one interval out, prefix-tagged, and
    /// never into the last free audit slot.
    #[test]
    fn option_b_restores_only_erased_hold_deadlines_paced_by_audit_slots() {
        use crate::snapshots::claude_request_census::{
            identity_incomplete_hold_deadlines_restored_total as restored_total,
            ClaudeRequestCensusRecord as Record, ClaudeRequestCensusShape as Shape,
            CLAUDE_REQUEST_CENSUS_DERIVATION,
        };
        let held = || {
            Record::synthetic_for_test(&"a".repeat(64), 1, Shape::IdentityIncomplete, vec![1])
                .with_unverified_for_test(true)
        };
        let mut retired = held();
        retired.retire();
        let mut index = ScanIndex::default();
        for (key, record) in [
            ("held-a", held()),
            ("held-b", held()),
            ("held-legacy-entry", held()),
            ("not-held-retired", retired),
            (
                "not-held-stale-derivation",
                held().with_derivation_for_test(CLAUDE_REQUEST_CENSUS_DERIVATION + 1),
            ),
            ("not-held-verified", held().with_unverified_for_test(false)),
            (
                "not-held-exact",
                Record::synthetic_for_test(&"a".repeat(64), 1, Shape::Exact, vec![1])
                    .with_unverified_for_test(true),
            ),
        ] {
            index.files.insert(key.into(), entry());
            index
                .claude_request_census_mut_for_test()
                .insert_for_test(key, record);
        }
        index
            .files
            .get_mut("held-legacy-entry")
            .unwrap()
            .scan_identity_version = Some("semantic_sync:v1".into());
        let plain = |index: &ScanIndex| {
            index
                .files
                .iter()
                .filter(|(_, entry)| !entry.has_unverified_source())
                .map(|(key, _)| key.clone())
                .collect::<BTreeSet<_>>()
        };
        let before = plain(&index);
        let total = restored_total();

        assert_eq!(restore_held_audit_deadlines(&mut index, 100), 1);
        assert_eq!(restored_total(), total + 1);
        let restored = &index.files["held-a"];
        assert_eq!(
            restored.unverified_deadline(),
            Some(100 + AUDIT_INTERVAL_SECONDS)
        );
        assert!(
            restored.has_prefix_provenance(),
            "plain v2 cannot prove `c`"
        );
        assert!(!restored.audit_requires_full(100), "no read at restoration");
        assert!(restored.audit_requires_full(100 + AUDIT_INTERVAL_SECONDS));
        assert!(
            !index.files["held-b"].has_unverified_source(),
            "one per scan"
        );

        // The next scan restores the next hold; a restored entry is not
        // restored again, and nothing else ever is.
        assert_eq!(restore_held_audit_deadlines(&mut index, 200), 1);
        assert_eq!(
            index.files["held-a"].unverified_deadline(),
            Some(100 + AUDIT_INTERVAL_SECONDS)
        );
        assert_eq!(
            index.files["held-b"].unverified_deadline(),
            Some(200 + AUDIT_INTERVAL_SECONDS)
        );
        assert_eq!(restore_held_audit_deadlines(&mut index, 300), 0);
        assert_eq!(restored_total(), total + 2);
        let mut unchanged = before;
        unchanged.remove("held-a");
        unchanged.remove("held-b");
        assert_eq!(plain(&index), unchanged);
        assert_eq!(
            index.files["held-legacy-entry"]
                .scan_identity_version
                .as_deref(),
            Some("semantic_sync:v1")
        );

        // Restoration leaves the last audit slot free, so a full pending
        // set keeps sampling supported and restores nothing.
        let mut full = ScanIndex::default();
        full.files.insert("held".into(), entry());
        full.claude_request_census_mut_for_test()
            .insert_for_test("held", held());
        for slot in 0..CACHE_ENTRIES - 1 {
            let mut pending = entry();
            pending.set_unverified_deadline(1);
            full.files.insert(format!("pending-{slot}"), pending);
        }
        assert_eq!(restore_held_audit_deadlines(&mut full, 100), 0);
        assert!(!full.files["held"].has_unverified_source());
        full.files.remove("pending-0");
        assert_eq!(restore_held_audit_deadlines(&mut full, 100), 1);
        assert_eq!(restored_total(), total + 3);
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
    #[test]
    fn provenance_marker_stays_inside_existing_marker_budget() {
        // Native comparison's unchanged charge rounds this legacy bound to 64.
        let budget = (UNVERIFIED_IDENTITY.len() + 1 + 20).next_power_of_two();
        for prefix in [false, true] {
            let tag = provenance_marker(u64::MAX, prefix);
            assert!(tag.capacity() <= MAX_MARKER_BYTES);
            assert!(tag.capacity() <= budget);
            assert_eq!(decode_marker(&tag), Some((u64::MAX, prefix)));
        }
    }
    /// c22 G1: `record` carries only an existing sampled stem. A replay-reset
    /// or legacy entry (never a prefix, SOURCE Option 1) re-recorded without
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
        };
        let key = local_index_key(&candidate.path);
        for reset in [None, Some("semantic_sync:v1"), Some("unknown-provenance")] {
            let mut entry = index().files.remove("file").unwrap();
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
