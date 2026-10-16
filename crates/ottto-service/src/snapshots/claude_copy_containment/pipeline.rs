//! Native scanner/checkpoint integration. The ordinary owner does not attach a
//! context yet: absence keeps BASE behavior, never an active-status claim.
use super::*;
use crate::snapshots::{local_index_key, CandidateFile, ScanIndex};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldFile {
    revision: HoldRevision,
    /// Full duplicate-census source handles, scoped by the enclosing context.
    peers: BTreeSet<String>,
}
crate::heap_layout_bound::fields!(HeldFile; revision, peers);

#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub(crate) struct Holds {
    entries: BTreeMap<String, HeldFile>,
}
crate::heap_layout_bound::fields!(Holds; entries);
impl<'de> Deserialize<'de> for Holds {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let result = Self {
            entries: BTreeMap::deserialize(deserializer)?,
        };
        if result.valid() {
            Ok(result)
        } else {
            Err(serde::de::Error::custom(
                "invalid copied-request hold ledger",
            ))
        }
    }
}

/// Owner-supplied exact wake witnesses. None for a key means a required input
/// is UNKNOWN: keep parked. This is not a per-cycle restart allowance. The
/// eventual daemon owner must freeze the process/source/destination lease and
/// all W1-W5 inputs before attaching it; tests exercise the actual scanner seam.
#[derive(Debug, Clone)]
pub(crate) struct ScanContext {
    scope: String,
    contexts: BTreeMap<String, Option<String>>,
    parked: usize,
}
crate::heap_layout_bound::fields!(ScanContext; scope, contexts, parked);

impl ScanContext {
    pub(crate) fn new(scope: String, contexts: BTreeMap<String, Option<String>>) -> Option<Self> {
        (digest_valid(&scope) && contexts.values().flatten().all(|value| digest_valid(value)))
            .then_some(Self {
                scope,
                contexts,
                parked: 0,
            })
    }
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl Holds {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
    pub(crate) fn valid(&self) -> bool {
        self.entries.len() <= crate::snapshots::MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
            && self.entries.iter().all(|(key, held)| {
                !key.is_empty()
                    && held.revision.is_valid()
                    && held.peers.iter().all(|peer| digest_valid(peer))
            })
            && self
                .entries
                .values()
                .try_fold(0usize, |count, held| count.checked_add(held.peers.len()))
                .is_some_and(|count| count <= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS)
    }
}
impl ScanIndex {
    /// Actual process/source/destination attachment with no invented positive
    /// wake witness. Until the owner has acquired all required W1-W5 inputs,
    /// every existing hold remains UNKNOWN/parked, even after a cache eviction
    /// or index reload. This does not mint membership, a permit or a read grant.
    pub(crate) fn attach_unknown_copy_owner(&mut self, scope: String) -> anyhow::Result<()> {
        let context = ScanContext::new(scope, BTreeMap::new())
            .ok_or_else(|| anyhow::anyhow!("invalid copied-request comparison scope"))?;
        self.attach_copy_scan_context(context);
        Ok(())
    }

    pub(crate) fn attach_copy_scan_context(&mut self, context: ScanContext) {
        self.active_copy_scan = Some(context);
    }
    pub(crate) fn copy_hold_count(&self) -> usize {
        self.claude_copy_holds.entries.len()
    }
    pub(crate) fn copy_parked_count(&self) -> usize {
        self.active_copy_scan
            .as_ref()
            .map_or(0, |context| context.parked)
    }
    pub(in crate::snapshots) fn copy_hold_should_park(
        &mut self,
        candidate: &CandidateFile,
    ) -> bool {
        let Some(context) = self.active_copy_scan.as_mut() else {
            return false;
        };
        let key = local_index_key(&candidate.path);
        let Some(held) = self.claude_copy_holds.entries.get(&key) else {
            return false;
        };
        let park = context
            .contexts
            .get(&key)
            .and_then(Option::as_deref)
            .map_or(true, |evidence| {
                held.revision
                    .read_disposition(&candidate.source_file_fingerprint, evidence)
                    == ReadDisposition::ParkUnchangedHeldRevision
            });
        if park {
            context.parked = context.parked.saturating_add(1);
        }
        park
    }

    /// Restore only the file/entity/empty/acceptance facts of withheld keys.
    /// The separate debt survives a window miss, pruning, partial selection and
    /// a new never-committed copy. No account/authority record is manufactured.
    pub(crate) fn restore_copy_held_checkpoint(&mut self, previous: &Self) {
        if self.claude_copy_holds.is_empty() {
            return;
        }
        for key in self.claude_copy_holds.entries.keys() {
            let rejected = self
                .file_snapshot_fingerprints
                .remove(key)
                .unwrap_or_default();
            for fingerprint in rejected {
                if !previous
                    .accepted_snapshot_fingerprints
                    .contains(&fingerprint)
                {
                    self.accepted_snapshot_fingerprints.remove(&fingerprint);
                    self.snapshot_activity_at.remove(&fingerprint);
                }
            }
            match previous.files.get(key) {
                Some(old) => {
                    self.files.insert(key.clone(), old.clone());
                }
                None => {
                    self.files.remove(key);
                }
            }
            match previous.file_snapshot_fingerprints.get(key) {
                Some(old) => {
                    self.file_snapshot_fingerprints
                        .insert(key.clone(), old.clone());
                }
                None => {
                    self.file_snapshot_fingerprints.remove(key);
                }
            }
            if previous.confirmed_empty_files.contains(key) {
                self.confirmed_empty_files.insert(key.clone());
            } else {
                self.confirmed_empty_files.remove(key);
            }
            if let Some(old) = previous.file_snapshot_fingerprints.get(key) {
                for fingerprint in old {
                    if previous
                        .accepted_snapshot_fingerprints
                        .contains(fingerprint)
                    {
                        self.accepted_snapshot_fingerprints
                            .insert(fingerprint.clone());
                    }
                    if let Some(activity) = previous.snapshot_activity_at.get(fingerprint) {
                        self.snapshot_activity_at
                            .insert(fingerprint.clone(), activity.clone());
                    }
                }
            }
        }
        self.mark_bounded_sweep_unsettled();
    }

    /// Called AFTER the one authoritative native fold, BEFORE C5/name binding
    /// and before any body builder. A miss preserves the accepted interim BASE
    /// behavior for NEW candidates; it can NEVER release an existing hold.
    pub(crate) fn record_known_copy_holds(
        &mut self,
        items: &[SnapshotItem],
        opened_files: &[(&str, &str)],
        excluded: impl Fn(&SnapshotItem, &str) -> bool,
    ) -> BTreeSet<String> {
        if self.active_copy_scan.is_none() && self.claude_copy_holds.is_empty() {
            return BTreeSet::new();
        }
        // The fold may have cleared committed fingerprints already. Use only
        // this page's actual opened native inputs, never a scratch/restored
        // entry or an inferred session-to-path mapping. A partial input can
        // withhold a body; it supplies no completeness or release permission.
        let mut file_keys = BTreeMap::<&str, Vec<&str>>::new();
        for &(key, revision) in opened_files {
            file_keys.entry(revision).or_default().push(key);
        }
        let context = self.active_copy_scan.as_ref();
        let mut retained_peer_count = self
            .claude_copy_holds
            .entries
            .values()
            .map(|held| held.peers.len())
            .fold(0usize, usize::saturating_add);
        let mut withheld = BTreeSet::new();
        for item in items {
            let Some(revision) = item.source_file_fingerprint.as_deref() else {
                continue;
            };
            let Some(keys) = file_keys.get(revision) else {
                continue;
            };
            // Losing an owner/context never releases already-recorded debt.
            if context.is_none() {
                if keys
                    .iter()
                    .any(|key| self.claude_copy_holds.entries.contains_key(*key))
                {
                    withheld.insert(item.source_session_id.clone());
                }
                continue;
            }
            let context = context.expect("checked owner context");
            let root = crate::snapshots::claude_snapshot_family_root(item);
            let own =
                crate::snapshots::claude_duplicate_request_owner(&root, &item.source_session_id);
            let mut peers = BTreeSet::new();
            for id in &item.claude_usage_request_ids {
                let hash = format!("{:x}", sha2::Sha256::digest(id.as_bytes()));
                if excluded(item, &hash) {
                    continue;
                }
                if let Some(owners) = self.claude_duplicate_request_owners.get(&hash) {
                    peers.extend(
                        owners
                            .iter()
                            .filter(|owner| {
                                owner.source_session_id_hash != own.source_session_id_hash
                            })
                            .map(|owner| owner.source_session_id_hash.clone()),
                    );
                }
            }
            let known = !peers.is_empty();
            let already_held = keys
                .iter()
                .any(|key| self.claude_copy_holds.entries.contains_key(*key));
            if !already_held && !known {
                continue;
            }
            withheld.insert(item.source_session_id.clone());
            for key in keys {
                if let Some(held) = self.claude_copy_holds.entries.get_mut(*key) {
                    let evidence = context
                        .contexts
                        .get(*key)
                        .and_then(Option::as_ref)
                        .unwrap_or(&context.scope);
                    // Debt is retained even if this read no longer sees a peer.
                    if let Some(next) = held.revision.revise(revision.to_string(), evidence.clone())
                    {
                        held.revision = next;
                    }
                    // Do not grow a durable peer set from a lookup miss.
                    continue;
                }
                // Existing shared hold bound. No overflow grants eligibility;
                // the body stays withheld even when disclosure cannot expand.
                if self
                    .claude_copy_holds
                    .entries
                    .len()
                    .saturating_add(self.claude_account_deferred_holds.len())
                    >= crate::snapshots::MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
                {
                    continue;
                }
                if retained_peer_count
                    .checked_add(peers.len())
                    .map_or(true, |count| count > MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS)
                {
                    continue;
                }
                let evidence = context
                    .contexts
                    .get(*key)
                    .and_then(Option::as_ref)
                    .unwrap_or(&context.scope);
                if let Some(revision) = HoldRevision::new(
                    HoldReason::CopiedOverlapUnproven,
                    revision.to_string(),
                    evidence.clone(),
                    None,
                ) {
                    retained_peer_count += peers.len();
                    self.claude_copy_holds.entries.insert(
                        (*key).to_string(),
                        HeldFile {
                            revision,
                            peers: peers.clone(),
                        },
                    );
                }
            }
        }
        withheld
    }
}

#[cfg(test)]
mod tests;
