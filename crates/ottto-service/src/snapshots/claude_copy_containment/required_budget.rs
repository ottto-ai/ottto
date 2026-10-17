//! Required index credit only. This does not admit native membership, pay the
//! producer by itself, or enable the containment policy. The producer must
//! separately prepay its temporary, growth and escaped-output owners.
use super::super::sampled_scan::{CopyReservation, SharedCache};
use super::super::ScanIndex;
use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
use std::alloc::Layout;
use std::mem::{align_of, size_of};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

pub(in crate::snapshots) const LIMIT: usize = 31 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Unavailable;
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("required copy-index ownership unavailable")
    }
}
impl std::error::Error for Unavailable {}

#[derive(Default)]
enum CreditKind {
    #[default]
    Ordinary,
    Paid(Arc<Credit>),
    // Infallible Clone cannot acquire memory permission. A required caller
    // prepays its complete operation before cloning and installs fresh credit.
    Unpaid(Arc<Credit>),
}

#[derive(Default)]
pub(in crate::snapshots) struct IndexCredit {
    kind: CreditKind,
}
struct Credit {
    parent: IndexCredit,
    ledger_bytes: usize,
    selective_bytes: usize,
    metadata_bytes: usize,
    // Last: all returned parent metadata is retired before its credit too.
    reservation: CopyReservation,
}

impl Clone for IndexCredit {
    fn clone(&self) -> Self {
        Self {
            kind: match &self.kind {
                CreditKind::Ordinary => CreditKind::Ordinary,
                CreditKind::Paid(credit) | CreditKind::Unpaid(credit) => {
                    CreditKind::Unpaid(Arc::clone(credit))
                }
            },
        }
    }
}
impl std::fmt::Debug for IndexCredit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self.kind {
            CreditKind::Ordinary => "OrdinaryIndexCredit",
            CreditKind::Paid(_) => "RequiredIndexCredit",
            CreditKind::Unpaid(_) => "UnpaidIndexCopy",
        })
    }
}
impl IndexCredit {
    fn take_arc(&mut self) -> Option<Arc<Credit>> {
        match std::mem::replace(&mut self.kind, CreditKind::Ordinary) {
            CreditKind::Ordinary => None,
            CreditKind::Paid(credit) | CreditKind::Unpaid(credit) => Some(credit),
        }
    }
    pub(in crate::snapshots) fn required(&self) -> bool {
        !matches!(self.kind, CreditKind::Ordinary)
    }
    fn paid(&self) -> Option<&Credit> {
        match &self.kind {
            CreditKind::Paid(credit) => Some(credit),
            _ => None,
        }
    }
    pub(in crate::snapshots) fn owner(&self) -> Option<&Arc<SharedCache>> {
        Some(self.paid()?.reservation.owner())
    }
    pub(in crate::snapshots) fn metadata_layout() -> Option<usize> {
        // Pinned ArcInner<Credit>: strong, weak, data; no weak handle is exposed.
        Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<Credit>())
            .ok()
            .map(|(layout, _)| layout.pad_to_align().size())
    }
    pub(in crate::snapshots) fn fresh(
        reservation: CopyReservation,
        ledger_bytes: usize,
        selective_bytes: usize,
        metadata_bytes: usize,
    ) -> Self {
        // All checked arithmetic/layout/admission happens before splitting the
        // decoder credit. No fallible branch may release a transferred credit
        // while the decoded index is still alive.
        Self {
            kind: CreditKind::Paid(Arc::new(Credit {
                parent: Self::default(),
                ledger_bytes,
                selective_bytes,
                metadata_bytes,
                reservation,
            })),
        }
    }
    pub(super) fn append(&mut self, ledger: usize, selective: usize) -> Result<(), Unavailable> {
        let current = self.paid().ok_or(Unavailable)?;
        let metadata = Self::metadata_layout().ok_or(Unavailable)?;
        let ledger_bytes = current
            .ledger_bytes
            .checked_add(ledger)
            .ok_or(Unavailable)?;
        let selective_bytes = current
            .selective_bytes
            .checked_add(selective)
            .ok_or(Unavailable)?;
        let metadata_bytes = current
            .metadata_bytes
            .checked_add(metadata)
            .ok_or(Unavailable)?;
        let bytes = ledger
            .checked_add(selective)
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or(Unavailable)?;
        let reservation = current
            .reservation
            .owner()
            .reserve_copy_bytes(bytes)
            .ok_or(Unavailable)?;
        let parent = std::mem::take(self);
        self.kind = CreditKind::Paid(Arc::new(Credit {
            parent,
            ledger_bytes,
            selective_bytes,
            metadata_bytes,
            reservation,
        }));
        Ok(())
    }
}
impl Drop for IndexCredit {
    fn drop(&mut self) {
        let mut next = self.take_arc();
        while let Some(arc) = next {
            // ALL strong owners use this private wrapper; no Weak is created.
            // into_inner frees the Arc allocation before returning Credit, so
            // returning its reservation cannot precede header deallocation.
            let Some(mut credit) = Arc::into_inner(arc) else {
                break;
            };
            next = credit.parent.take_arc();
            drop(credit);
        }
    }
}
impl HeapLayoutBound for IndexCredit {
    fn stable_heap(&self) -> bool {
        !matches!(self.kind, CreditKind::Unpaid(_))
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match &self.kind {
            CreditKind::Ordinary => c.add(0),
            CreditKind::Paid(credit) => c.add(credit.metadata_bytes),
            CreditKind::Unpaid(_) => None,
        }
        // The existing shared cache is a borrowed accounting link, not a new
        // recursively owned payload. Its pool counts every live reservation;
        // index fields themselves still count their actual graph separately.
    }
}

pub(in crate::snapshots) fn ledger_bound(index: &ScanIndex) -> Option<usize> {
    let mut c = Counter::new(LIMIT);
    index.claude_copy_holds.completed_heap_bound(&mut c)?;
    index.active_copy_scan.completed_heap_bound(&mut c)?;
    Some(c.bytes)
}

pub(super) fn prospective_nodes<K, V>(
    existing: usize,
    insertions: usize,
    c: &mut Counter,
) -> Option<()> {
    if insertions == 0 {
        return c.add(0);
    }
    let future = existing.checked_add(insertions)?.checked_add(1)?;
    // At least two children at each internal level. One split allocation per
    // level plus a new root; this is a conservative insertion peak, not a
    // complete-baseline-tree charge.
    let height = (usize::BITS - future.leading_zeros()) as usize;
    let count = insertions.checked_mul(height.checked_add(2)?)?;
    let mut node = Counter::new(LIMIT);
    heap_layout_bound::tree_nodes::<K, V>(0, &mut node)?;
    c.add(node.bytes.checked_mul(count)?)
}

fn restore_bound(index: &ScanIndex, previous: &ScanIndex, accepted_extra: usize) -> Option<usize> {
    use super::super::ScanIndexEntry;
    let mut c = Counter::new(LIMIT);
    let mut keys = 0usize;
    let mut fingerprints = 0usize;
    for key in index.claude_copy_holds.entries_for_budget() {
        keys = keys.checked_add(1)?;
        // files / file-fingerprint map / confirmed-empty key copies and an
        // overwritten argument key. Charge spare capacity conservatively.
        c.add(key.capacity().checked_mul(4)?)?;
        if let Some(entry) = previous.files.get(key) {
            // New selected copy plus pre-overwrite old+new transient payload.
            let bytes = heap_layout_bound::completed_bound(entry, LIMIT)?;
            c.add(bytes.checked_mul(2)?)?;
        }
        if let Some(values) = previous.file_snapshot_fingerprints.get(key) {
            let bytes = heap_layout_bound::completed_bound(values, LIMIT)?;
            c.add(bytes.checked_mul(2)?)?;
            fingerprints = fingerprints.checked_add(values.len())?;
            for fingerprint in values {
                // Accepted-set key and activity-map key; duplicate insertion
                // still temporarily owns its argument before it is discarded.
                c.add(fingerprint.capacity().checked_mul(2)?)?;
                if let Some(Some(activity)) = previous.snapshot_activity_at.get(fingerprint) {
                    c.add(activity.capacity().checked_mul(2)?)?;
                }
            }
        }
    }
    let files = index.files.len().checked_add(previous.files.len())?;
    let mappings = index
        .file_snapshot_fingerprints
        .len()
        .checked_add(previous.file_snapshot_fingerprints.len())?;
    let accepted = index
        .accepted_snapshot_fingerprints
        .len()
        .checked_add(previous.accepted_snapshot_fingerprints.len())?
        .checked_add(accepted_extra)?;
    let activities = index
        .snapshot_activity_at
        .len()
        .checked_add(previous.snapshot_activity_at.len())?;
    prospective_nodes::<String, ScanIndexEntry>(files, keys, &mut c)?;
    prospective_nodes::<String, std::collections::BTreeSet<String>>(mappings, keys, &mut c)?;
    prospective_nodes::<String, ()>(
        index
            .confirmed_empty_files
            .len()
            .checked_add(previous.confirmed_empty_files.len())?,
        keys,
        &mut c,
    )?;
    prospective_nodes::<String, ()>(accepted, fingerprints, &mut c)?;
    prospective_nodes::<String, Option<String>>(activities, fingerprints, &mut c)?;
    Some(c.bytes)
}

// Generic FromIterator stages a Vec, stable-sort scratch, and a new tree.
// A single held insertion can cross its capacity threshold. Pay that entire
// temporary collector conservatively; do not pretend only the new slot grew.
fn collector<K, V>(count: usize, c: &mut Counter) -> Option<()> {
    let slots = count.max(48).checked_mul(4)?;
    c.add(slots.checked_mul(size_of::<(K, V)>())?)?;
    let mut nodes = Counter::new(LIMIT);
    heap_layout_bound::tree_nodes::<K, V>(count, &mut nodes)?;
    c.add(nodes.bytes.checked_mul(2)?)
}

/// Frozen scalar cost only, not permission to run a consumer. The future
/// caller must reserve before constructing either set, keep that reservation
/// through the actual CAS/report lifetime, and separately own escaped output.
#[derive(Debug, Clone, Copy)]
struct ConsumerCosts {
    cardinality_upper: usize,
    full_collectors: usize,
    affected_string_copies: usize,
    total: usize,
}

fn consumer_costs(index: &ScanIndex, previous: &ScanIndex) -> Option<ConsumerCosts> {
    if !super::required_decode::profile_supported() {
        return None;
    }
    if index.claude_copy_holds.is_empty() {
        return Some(ConsumerCosts {
            cardinality_upper: 0,
            full_collectors: 0,
            affected_string_copies: 0,
            total: 0,
        });
    }
    let mut full = Counter::new(LIMIT);
    // ONE frozen borrowed pass. Files.len bounds legacy last-fingerprint
    // fallbacks without an extra file walk; exact-map files are overcounted.
    let mut count = index
        .files
        .len()
        .checked_add(previous.files.len())?
        .checked_add(index.codex_state_only_snapshot_fingerprints.len())?
        .checked_add(previous.codex_state_only_snapshot_fingerprints.len())?;
    for values in index
        .file_snapshot_fingerprints
        .values()
        .chain(previous.file_snapshot_fingerprints.values())
    {
        count = count.checked_add(values.len())?;
    }
    // The first owned set survives CAS. Another owned set and a FAT &str set
    // coexist during each manifest call. Separate physical owners, not aliases.
    collector::<String, ()>(count, &mut full)?;
    collector::<String, ()>(count, &mut full)?;
    collector::<&str, ()>(count, &mut full)?;
    let mut payload = 0usize;
    for key in index.claude_copy_holds.entries_for_budget() {
        for owner in [index, previous] {
            if let Some(values) = owner.file_snapshot_fingerprints.get(key) {
                for fp in values {
                    payload = payload.checked_add(fp.capacity())?;
                }
            } else if let Some(fp) = owner
                .files
                .get(key)
                .and_then(|entry| entry.last_snapshot_fingerprint.as_ref())
            {
                // Canonical field type imposes no64B length validation here.
                payload = payload.checked_add(fp.capacity())?;
            }
        }
    }
    let affected_string_copies = payload.checked_mul(2)?;
    let total = full.bytes.checked_add(affected_string_copies)?;
    if total > LIMIT {
        return None;
    }
    Some(ConsumerCosts {
        cardinality_upper: count,
        full_collectors: full.bytes,
        affected_string_copies,
        total,
    })
}

fn selection_bound(
    index: &ScanIndex,
    previous: &ScanIndex,
    quarantined: &std::collections::BTreeMap<String, super::super::SnapshotQuarantineRecord>,
    fingerprints: usize,
) -> Option<usize> {
    use super::super::{ClaudeOwnedStartCensusWitness, SnapshotQuarantineRecord};
    if index.claude_copy_holds.is_empty() {
        return Some(0);
    }
    let mut c = Counter::new(LIMIT);
    // Reuse the one frozen borrowed cardinality computed for this selection
    // and its induced current-entity/manifest consumers. No second map walk.
    collector::<&String, ()>(fingerprints, &mut c)?;
    let quarantine_count = quarantined
        .len()
        .checked_add(previous.quarantined_snapshot_fingerprints.len())?
        .checked_add(index.quarantined_snapshot_fingerprints.len())?;
    collector::<String, SnapshotQuarantineRecord>(quarantine_count, &mut c)?;

    // Excluding a held key from safe_keys keeps its old terminal/census
    // payload alive rather than replacing it. The source derives subagent
    // member IDs with owned temporary strings; do not recreate those during
    // preflight. One borrowed maximum over the previous census is a deliberate
    // conservative charge, not an inference about which member owns a key.
    let mut census_max = 0usize;
    for (key, witness) in &previous.claude_owned_start_census {
        let bytes = key
            .capacity()
            .checked_add(heap_layout_bound::completed_bound(witness, LIMIT)?)?;
        census_max = census_max.max(bytes);
    }
    let mut keys = 0usize;
    for key in index.claude_copy_holds.entries_for_budget() {
        keys = keys.checked_add(1)?;
        c.add(census_max.checked_mul(2)?)?;
        if let Some(value) = previous.terminal_jsonl_dispositions.get(key) {
            c.add(key.capacity().checked_mul(2)?)?;
            c.add(heap_layout_bound::completed_bound(value, LIMIT)?.checked_mul(2)?)?;
        }
        // Recovery reconciliation can replace a captured/applied receipt while
        // its prior allocation still exists. Formatting captured_join has a
        // fixed prefix AND an arbitrary witness length; never assume 64 bytes.
        if let Some(entry) = previous.files.get(key) {
            c.add(heap_layout_bound::completed_bound(entry, LIMIT)?.checked_mul(2)?)?;
        }
        if let Some(entry) = index.files.get(key) {
            c.add(heap_layout_bound::completed_bound(entry, LIMIT)?.checked_mul(2)?)?;
            if let Some(witness) = entry.codex_joined_member_set.as_ref() {
                c.add(
                    witness
                        .len()
                        .checked_add("codex_captured_join:v1:".len())?
                        .checked_mul(4)?,
                )?;
            }
        }
        // Both possible old/current membership sets can change which local
        // quarantine/activity payloads survive the existing collectors. Count
        // only those referenced payloads; all other referents remain baseline.
        for values in [
            index.file_snapshot_fingerprints.get(key),
            previous.file_snapshot_fingerprints.get(key),
        ]
        .into_iter()
        .flatten()
        {
            for fp in values {
                for map in [
                    &index.quarantined_snapshot_fingerprints,
                    &previous.quarantined_snapshot_fingerprints,
                    quarantined,
                ] {
                    if let Some(record) = map.get(fp) {
                        c.add(fp.capacity().checked_mul(4)?)?;
                        c.add(heap_layout_bound::completed_bound(record, LIMIT)?.checked_mul(4)?)?;
                    }
                }
                for map in [&index.snapshot_activity_at, &previous.snapshot_activity_at] {
                    if let Some(Some(activity)) = map.get(fp) {
                        c.add(
                            fp.capacity()
                                .checked_add(activity.capacity())?
                                .checked_mul(2)?,
                        )?;
                    }
                }
            }
        }
    }
    prospective_nodes::<String, ClaudeOwnedStartCensusWitness>(
        previous
            .claude_owned_start_census
            .len()
            .checked_add(index.claude_owned_start_census.len())?,
        keys,
        &mut c,
    )?;
    Some(c.bytes)
}

impl ScanIndex {
    fn checked_copy_credit(&self) -> Result<&Credit, Unavailable> {
        let credit = self.copy_debt_budget.paid().ok_or(Unavailable)?;
        // A later measurement cannot bless earlier unpaid producer growth.
        // This is only a required-operation precondition, not native admission.
        if ledger_bound(self).ok_or(Unavailable)? > credit.ledger_bytes {
            return Err(Unavailable);
        }
        Ok(credit)
    }
    /// Only a paid required owner may decode a competing CAS checkpoint.
    /// An infallible Clone is explicitly unpaid and must fail before IO/copy.
    pub(in crate::snapshots) fn required_copy_owner(
        &self,
    ) -> Result<Option<&Arc<SharedCache>>, Unavailable> {
        if !self.copy_debt_budget.required() {
            return Ok(None);
        }
        Ok(Some(self.checked_copy_credit()?.reservation.owner()))
    }
    pub(crate) fn try_clone_for_copy(&self) -> Result<Self, Unavailable> {
        if !self.copy_debt_budget.required() {
            return Ok(self.clone());
        }
        let credit = self.checked_copy_credit()?;
        let ledger = ledger_bound(self).ok_or(Unavailable)?;
        let selective = credit.selective_bytes;
        let metadata = IndexCredit::metadata_layout().ok_or(Unavailable)?;
        let bytes = ledger
            .checked_add(selective)
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or(Unavailable)?;
        let reservation = credit
            .reservation
            .owner()
            .reserve_copy_bytes(bytes)
            .ok_or(Unavailable)?;
        let mut result = self.clone();
        result.copy_debt_budget = IndexCredit::fresh(reservation, ledger, selective, metadata);
        Ok(result)
    }
    pub(crate) fn try_committable_subset(
        &self,
        previous: &Self,
        accepted: &std::collections::BTreeSet<String>,
        quarantined: &std::collections::BTreeMap<String, super::super::SnapshotQuarantineRecord>,
    ) -> Result<Self, Unavailable> {
        if !self.copy_debt_budget.required() && !previous.copy_debt_budget.required() {
            return Ok(self.committable_subset(previous, accepted, quarantined));
        }
        let credit = self.checked_copy_credit()?;
        let prior = if previous.copy_debt_budget.required() {
            previous.checked_copy_credit()?.selective_bytes
        } else if previous.claude_copy_holds.is_empty() && previous.active_copy_scan.is_none() {
            0
        } else {
            return Err(Unavailable);
        };
        let ledger = ledger_bound(self).ok_or(Unavailable)?;
        let consumers = consumer_costs(self, previous).ok_or(Unavailable)?;
        let selective = credit
            .selective_bytes
            .checked_add(prior)
            .and_then(|bytes| {
                bytes.checked_add(
                    restore_bound(self, previous, accepted.len())?
                        .checked_add(selection_bound(
                            self,
                            previous,
                            quarantined,
                            consumers.cardinality_upper,
                        )?)?
                        .checked_add(consumers.total)?,
                )
            })
            .ok_or(Unavailable)?;
        let metadata = IndexCredit::metadata_layout().ok_or(Unavailable)?;
        let bytes = ledger
            .checked_add(selective)
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or(Unavailable)?;
        let reservation = credit
            .reservation
            .owner()
            .reserve_copy_bytes(bytes)
            .ok_or(Unavailable)?;
        let mut result = self.committable_subset(previous, accepted, quarantined);
        result.copy_debt_budget = IndexCredit::fresh(reservation, ledger, selective, metadata);
        Ok(result)
    }
    pub(crate) fn try_restore_copy_held_checkpoint(
        &mut self,
        previous: &Self,
    ) -> Result<(), Unavailable> {
        if self.copy_debt_budget.required() {
            self.checked_copy_credit()?;
            if previous.copy_debt_budget.required() {
                previous.checked_copy_credit()?;
            }
            let bytes = restore_bound(self, previous, 0).ok_or(Unavailable)?;
            self.copy_debt_budget.append(0, bytes)?;
        } else if previous.copy_debt_budget.required() {
            return Err(Unavailable);
        }
        self.restore_copy_held_checkpoint(previous);
        Ok(())
    }
    pub(in crate::snapshots) fn prepay_copy_context<T: HeapLayoutBound>(
        &mut self,
        context: &T,
    ) -> Result<(), Unavailable> {
        if self.copy_debt_budget.required() {
            self.checked_copy_credit()?;
            let bytes = heap_layout_bound::completed_bound(context, LIMIT).ok_or(Unavailable)?;
            self.copy_debt_budget.append(bytes, 0)?;
        }
        Ok(())
    }
}

// Kept type-derived, not a fixed fudge factor, for decoder error-box layout.
pub(in crate::snapshots) fn error_box_layout() -> Option<usize> {
    let payload_size = size_of::<Box<str>>().max(size_of::<std::io::Error>());
    let payload_align = align_of::<Box<str>>().max(align_of::<std::io::Error>());
    Layout::new::<usize>()
        .extend(Layout::from_size_align(payload_size, payload_align).ok()?)
        .ok()?
        .0
        .extend(Layout::new::<[usize; 2]>())
        .ok()
        .map(|(layout, _)| layout.pad_to_align().size())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    #[test]
    fn copy_containment_required_collector_capacity_boundaries() {
        if !super::super::required_decode::profile_supported() {
            eprintln!("copy_containment_required_collector: unsupported profile; positive allocation branches UNEXECUTED");
            return;
        }
        for count in [31usize, 32, 33, 47, 48, 49, 63, 64, 65] {
            let inputs = (0..count)
                .map(|n| format!("key-{n:04}"))
                .collect::<Vec<_>>();
            let mut c = Counter::new(LIMIT);
            collector::<&String, ()>(count, &mut c).unwrap();
            // Referents pre-exist; measure only the actual generic collector.
            let (_, actual) = crate::retry_allocation_probe::measure(|| {
                let selected = inputs.iter().rev().collect::<BTreeSet<_>>();
                assert_eq!(selected.len(), count);
                drop(selected);
            });
            assert!(actual.requested_peak_with_overlap <= c.bytes);
            assert_eq!(actual.requested_live, 0);
            eprintln!("copy_containment_required_collector: n={count} conservative_full_collector={} actual_requested_peak={} incremental_payload_excluded=true", c.bytes, actual.requested_peak_with_overlap);
        }
    }

    #[test]
    fn copy_containment_consumer_legacy_owned_lifetime_across_actual_cas_and_manifest() {
        use std::io::Write;
        // Ordinary existing index/CAS is the lifetime oracle, not required
        // admission. This fixture can execute on an unsupported new-codec
        // layout without pretending that its resource bound is validated.
        let root = std::env::temp_dir().join(format!(
            "ottto-copy-consumer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Remove(std::path::PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Remove(root.clone());
        let path = root.join("index.json");
        let legacy = "legacy-".repeat(128);
        let mut index = ScanIndex::default();
        index.files.insert(
            "legacy.jsonl".to_string(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":1, "modified_unix_seconds":1, "source_file_fingerprint":"a".repeat(64),
                "last_snapshot_fingerprint":legacy
            }))
            .unwrap(),
        );
        index
            .snapshot_activity_at
            .insert(legacy.clone(), Some("2026-10-17T00:01:00Z".to_string()));
        // No exact-map entry: ordinary current_snapshot_fingerprints must
        // retain the legacy String instead of treating an empty map as empty.
        assert!(index.file_snapshot_fingerprints.is_empty());
        index.save(&path).unwrap();
        let before_generation = index.generation;
        let ((first_live, after_cas, manifest_peak), stats) =
            crate::retry_allocation_probe::measure(|| {
                let current = index.current_snapshot_fingerprints();
                assert!(current.contains(&legacy));
                let first_live = crate::retry_allocation_probe::stats().requested_live;
                assert!(first_live > 0);
                index.save(&path).unwrap(); // actual ordinary generation CAS
                assert_eq!(index.generation, before_generation + 1);
                let after_cas = crate::retry_allocation_probe::stats().requested_live;
                assert!(after_cas >= first_live);
                crate::retry_allocation_probe::phase_begin();
                let manifest = index
                    .manifest_for_window(
                        super::super::super::SnapshotSource::ClaudeCode,
                        "2026-10-17T00:00:00Z",
                        "2026-10-18T00:00:00Z",
                    )
                    .unwrap();
                assert_eq!(manifest.entity_count, 1);
                assert!(
                    current.contains(&legacy),
                    "first owned set survives the second manifest owner"
                );
                let manifest_peak = crate::retry_allocation_probe::phase_peak();
                drop(manifest);
                drop(current);
                (first_live, after_cas, manifest_peak)
            });
        assert_eq!(stats.requested_live, 0);
        assert!(manifest_peak > legacy.len());
        writeln!(std::io::stderr().lock(), "copy_containment_consumer_lifetime: legacy_bytes={} first_owned_live={first_live} after_actual_CAS={after_cas} manifest_incremental_peak={manifest_peak} final_live=0 ordinary_oracle_not_required_admission=true", legacy.len()).unwrap();
    }

    #[test]
    fn copy_containment_consumer_preflight_counts_legacy_and_fat_reference_boundaries() {
        use std::io::Write;
        let mut index = ScanIndex {
            claude_copy_holds: serde_json::from_value(serde_json::json!({
                "legacy.jsonl": {"revision": {"version":1, "reason":"copied_overlap_unproven",
                    "source_revision":"a".repeat(64), "comparison_context":"b".repeat(64),
                    "first_observed_unix_seconds":null}, "peers":["c".repeat(64)]}
            }))
            .unwrap(),
            ..ScanIndex::default()
        };
        index.files.insert(
            "legacy.jsonl".to_string(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":1, "modified_unix_seconds":1, "source_file_fingerprint":"a".repeat(64),
                "last_snapshot_fingerprint":"L".repeat(1024)
            }))
            .unwrap(),
        );
        if !super::super::required_decode::profile_supported() {
            assert!(consumer_costs(&index, &ScanIndex::default()).is_none());
            writeln!(std::io::stderr().lock(), "copy_containment_consumer_preflight: unsupported profile; positive bound branches UNEXECUTED").unwrap();
            return;
        }
        for count in [31usize, 32, 33, 47, 48, 49, 63, 64, 65] {
            index.file_snapshot_fingerprints.insert(
                "exact.jsonl".to_string(),
                (0..count).map(|n| format!("fp-{n}")).collect(),
            );
            let (cost, allocations) = crate::retry_allocation_probe::measure(|| {
                consumer_costs(&index, &ScanIndex::default()).unwrap()
            });
            assert_eq!(allocations.allocations, 0);
            assert_eq!(
                cost.cardinality_upper,
                count + 1,
                "one legacy file even with no exact map for it"
            );
            assert!(
                cost.affected_string_copies >= 2048,
                "two full legacy String copies, never assumed64B"
            );
            assert_eq!(
                cost.total,
                cost.full_collectors + cost.affected_string_copies
            );
            let mut thin = Counter::new(LIMIT);
            let mut fat = Counter::new(LIMIT);
            collector::<&String, ()>(cost.cardinality_upper, &mut thin).unwrap();
            collector::<&str, ()>(cost.cardinality_upper, &mut fat).unwrap();
            assert!(
                fat.bytes > thin.bytes,
                "actual fat-reference storage is separate"
            );
            writeln!(std::io::stderr().lock(), "copy_containment_consumer_preflight: count={count} upper={} full_collectors={} affected_owned_strings={} total={} preflight_allocations=0 status_escape_UNPAID=true", cost.cardinality_upper, cost.full_collectors, cost.affected_string_copies, cost.total).unwrap();
        }
    }
}
