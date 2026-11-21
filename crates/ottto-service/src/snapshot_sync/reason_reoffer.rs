//! Reason-scoped daily re-offer of exact permanent refusals.
//!
//! The backend refuses `original_pair_candidate_unproved` permanently until it
//! can prove the original request pair, so the refused body is offered again at
//! most once per 24 hours. A refusal recorded as `other` without this extension
//! is never re-offered. The refusal, its body binding and its terminal
//! quarantine stay durable throughout; this extension is local scheduling
//! permission only, never acceptance evidence.
//!
//! Disk form: the containing record keeps the old enum value `other`, so an
//! older daemon still reads, suppresses and never retries the refusal. The
//! optional `reoffer` member carries the exact classification. Its decoder is
//! bounded and isolating: a malformed member disables only this record's
//! retry, never the ledger, its siblings or the refusal itself.

use super::{
    cache_head_probe, current_unix_seconds, quarantine_retry_after, reason_reoffer,
    snapshot_upload_body_witness, PermanentSnapshotRejection, ScanIndex, SnapshotItem,
    SnapshotQuarantineDisposition, SnapshotQuarantineRecord, SnapshotSource,
    SnapshotUploadProgress, MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
    SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE,
};
use super::{
    codex_scan_diagnostics, stale_owed, CodexScanDiagnostics, SNAPSHOT_QUARANTINE_RETRY_SECONDS,
    UNPROVEN_TERMINAL_ATTEMPT_COUNT,
};
use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const ORIGINAL_PAIR_CANDIDATE_UNPROVED: &str = "original_pair_candidate_unproved";
/// One logical offer per record per day.
pub(super) const REOFFER_INTERVAL_SECONDS: u64 = 86_400;
/// Clock tolerance: a deadline past now + 24 h + 600 s is skipped and
/// re-clamped to now + 24 h, keeping suppression until the next due cycle.
pub(super) const REOFFER_CLOCK_TOLERANCE_SECONDS: u64 = 600;

const EXTENSION_VERSION: u64 = 1;
const CLASSIFIED: &str = "classified";
const MAX_MEMBERS: usize = 8;
const MAX_DEPTH: usize = 4;
const MAX_TOKEN_BYTES: usize = 64;
const MAX_NODES: usize = 32;

/// Persisted per-record scheduling state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RefusalReoffer {
    /// Exact `original_pair_candidate_unproved`: next logical offer not before.
    OriginalPair { retry_after_unix_seconds: u64 },
    /// Per-record done marker: the server classified this body, or the
    /// extension was unusable. Never re-offered automatically.
    Classified,
}

impl RefusalReoffer {
    pub(super) fn retry_after(self) -> Option<u64> {
        match self {
            Self::OriginalPair {
                retry_after_unix_seconds,
            } => Some(retry_after_unix_seconds),
            Self::Classified => None,
        }
    }

    pub(super) fn with_retry_after(self, retry_after_unix_seconds: u64) -> Self {
        match self {
            Self::OriginalPair { .. } => Self::OriginalPair {
                retry_after_unix_seconds,
            },
            Self::Classified => Self::Classified,
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for RefusalReoffer {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::OriginalPair { .. } | Self::Classified => counter.add(0),
        }
    }
}

/// Process-local count of extensions disabled by the decoder.
/// Clock-bound skips have their own per-cycle counter. Never retain raw bytes.
static INVALID_EXTENSIONS: AtomicU64 = AtomicU64::new(0);

pub(super) fn note_invalid_extension() {
    INVALID_EXTENSIONS.fetch_add(1, Ordering::Relaxed);
}

static LOGGED_INVALID_EXTENSIONS: AtomicU64 = AtomicU64::new(0);

/// Extensions disabled since the previous summary line.
pub(super) fn take_logged_invalid_extensions() -> usize {
    let total = INVALID_EXTENSIONS.load(Ordering::Relaxed);
    let logged = LOGGED_INVALID_EXTENSIONS.swap(total, Ordering::Relaxed);
    usize::try_from(total.saturating_sub(logged)).unwrap_or(usize::MAX)
}

/// The loaded, committed index and clock that bound one cycle's selection.
pub(super) struct Scope<'a> {
    pub(super) index: &'a crate::snapshots::ScanIndex,
    pub(super) now: u64,
    /// Start of the negotiated upload window. Older records stay disclosed
    /// and counted, not re-offered.
    pub(super) window_start_unix_seconds: u64,
}

/// Local scheduling clock. Tests inject a synthetic wall clock; production
/// reads the system clock. Never authority for acceptance.
pub(super) fn now_unix_seconds() -> u64 {
    #[cfg(test)]
    if let Some(now) =
        super::tests::permanent_finish_pipeline_tests::reason_reoffer_pipeline_tests::clock()
    {
        return now;
    }
    super::current_unix_seconds()
}

pub(super) fn next_offer_after(observed_at: u64) -> u64 {
    observed_at.saturating_add(REOFFER_INTERVAL_SECONDS)
}

/// The latest deadline a valid record may carry at `now`.
pub(super) fn latest_valid_deadline(now: u64) -> u64 {
    now.saturating_add(REOFFER_INTERVAL_SECONDS)
        .saturating_add(REOFFER_CLOCK_TOLERANCE_SECONDS)
}

pub(super) fn serialize<S: Serializer>(
    value: &Option<RefusalReoffer>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let Some(value) = value else {
        return serializer.serialize_none();
    };
    let (reason, retry_after) = match value {
        RefusalReoffer::OriginalPair {
            retry_after_unix_seconds,
        } => (
            ORIGINAL_PAIR_CANDIDATE_UNPROVED,
            Some(*retry_after_unix_seconds),
        ),
        RefusalReoffer::Classified => (CLASSIFIED, None),
    };
    let mut map = serializer.serialize_map(Some(2 + usize::from(retry_after.is_some())))?;
    map.serialize_entry("version", &EXTENSION_VERSION)?;
    map.serialize_entry("reason", reason)?;
    if let Some(retry_after) = retry_after {
        map.serialize_entry("retry_after_unix_seconds", &retry_after)?;
    }
    map.end()
}

/// Missing/null is `None`. Anything else that is not exactly a version-1
/// extension decodes to `Classified`: retry disabled, refusal kept.
pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RefusalReoffer>, D::Error> {
    deserializer.deserialize_any(ExtensionVisitor)
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    invalid: bool,
}

impl Budget {
    fn visit(&mut self, depth: usize) {
        self.nodes += 1;
        if self.nodes > MAX_NODES || depth > MAX_DEPTH {
            self.invalid = true;
        }
    }
}

fn disabled() -> Option<RefusalReoffer> {
    note_invalid_extension();
    Some(RefusalReoffer::Classified)
}

struct ExtensionVisitor;

impl<'de> Visitor<'de> for ExtensionVisitor {
    type Value = Option<RefusalReoffer>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an optional refusal re-offer extension")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut budget = Budget::default();
        while seq
            .next_element_seed(Skip {
                depth: 1,
                budget: &mut budget,
            })?
            .is_some()
        {}
        Ok(disabled())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut budget = Budget::default();
        let mut members = 0usize;
        let (mut version, mut reason, mut retry_after) = (None, None, None);
        while let Some(key) = map.next_key_seed(KeySeed)? {
            members += 1;
            budget.visit(1);
            if members > MAX_MEMBERS {
                budget.invalid = true;
            }
            let slot = match key {
                Key::Version => &mut version,
                Key::Reason => &mut reason,
                Key::RetryAfter => &mut retry_after,
                Key::Unknown | Key::Invalid => {
                    if key == Key::Invalid {
                        budget.invalid = true;
                    }
                    map.next_value_seed(Skip {
                        depth: 1,
                        budget: &mut budget,
                    })?;
                    continue;
                }
            };
            let value = map.next_value_seed(ScalarSeed {
                budget: &mut budget,
            })?;
            if slot.replace(value).is_some() {
                // A duplicate required member is ambiguous.
                budget.invalid = true;
            }
        }
        if budget.invalid {
            return Ok(disabled());
        }
        let parsed = match (version, reason, retry_after) {
            (Some(Scalar::U64(EXTENSION_VERSION)), Some(Scalar::Token(token)), retry_after) => {
                match (token, retry_after) {
                    (Token::OriginalPair, Some(Scalar::U64(retry_after_unix_seconds))) => {
                        Some(RefusalReoffer::OriginalPair {
                            retry_after_unix_seconds,
                        })
                    }
                    (Token::Classified, None) => Some(RefusalReoffer::Classified),
                    _ => None,
                }
            }
            _ => None,
        };
        Ok(parsed.or_else(disabled))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Version,
    Reason,
    RetryAfter,
    Unknown,
    Invalid,
}

struct KeySeed;

impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = Key;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Key, D::Error> {
        deserializer.deserialize_str(KeyVisitor)
    }
}

struct KeyVisitor;

impl Visitor<'_> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an extension member name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Key, E> {
        Ok(match value {
            _ if value.len() > MAX_TOKEN_BYTES => Key::Invalid,
            "version" => Key::Version,
            "reason" => Key::Reason,
            "retry_after_unix_seconds" => Key::RetryAfter,
            _ => Key::Unknown,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    OriginalPair,
    Classified,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scalar {
    U64(u64),
    Token(Token),
    Other,
}

struct ScalarSeed<'a> {
    budget: &'a mut Budget,
}

impl<'de> DeserializeSeed<'de> for ScalarSeed<'_> {
    type Value = Scalar;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Scalar, D::Error> {
        deserializer.deserialize_any(ScalarVisitor {
            budget: self.budget,
        })
    }
}

struct ScalarVisitor<'a> {
    budget: &'a mut Budget,
}

impl<'de> Visitor<'de> for ScalarVisitor<'_> {
    type Value = Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an extension scalar")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Scalar, E> {
        Ok(Scalar::U64(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Scalar, E> {
        // serde_json reports non-negative integers through visit_u64.
        Ok(u64::try_from(value).map_or(Scalar::Other, Scalar::U64))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Scalar, E> {
        if value.len() > MAX_TOKEN_BYTES {
            self.budget.invalid = true;
            return Ok(Scalar::Other);
        }
        Ok(match value {
            ORIGINAL_PAIR_CANDIDATE_UNPROVED => Scalar::Token(Token::OriginalPair),
            CLASSIFIED => Scalar::Token(Token::Classified),
            _ => Scalar::Other,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scalar, A::Error> {
        let budget = self.budget;
        while seq
            .next_element_seed(Skip {
                depth: 2,
                budget: &mut *budget,
            })?
            .is_some()
        {}
        Ok(Scalar::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Scalar, A::Error> {
        let budget = self.budget;
        while map
            .next_key_seed(Skip {
                depth: 2,
                budget: &mut *budget,
            })?
            .is_some()
        {
            map.next_value_seed(Skip {
                depth: 2,
                budget: &mut *budget,
            })?;
        }
        Ok(Scalar::Other)
    }
}

/// Consumes one value of unknown shape without retaining it. Within bounds
/// it counts nodes and depth; once out of bounds it marks the extension
/// invalid and consumes the rest with `IgnoredAny`, which allocates nothing.
struct Skip<'a> {
    depth: usize,
    budget: &'a mut Budget,
}

impl<'de> DeserializeSeed<'de> for Skip<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.budget.invalid {
            deserializer.deserialize_ignored_any(IgnoredAny)?;
            return Ok(());
        }
        deserializer.deserialize_any(SkipVisitor {
            depth: self.depth,
            budget: self.budget,
        })
    }
}

struct SkipVisitor<'a> {
    depth: usize,
    budget: &'a mut Budget,
}

impl<'de> Visitor<'de> for SkipVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any bounded value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.budget.visit(self.depth);
        if value.len() > MAX_TOKEN_BYTES {
            self.budget.invalid = true;
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let budget = self.budget;
        budget.visit(self.depth);
        while seq
            .next_element_seed(Skip {
                depth: self.depth + 1,
                budget: &mut *budget,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let budget = self.budget;
        budget.visit(self.depth);
        while map
            .next_key_seed(Skip {
                depth: self.depth + 1,
                budget: &mut *budget,
            })?
            .is_some()
        {
            map.next_value_seed(Skip {
                depth: self.depth + 1,
                budget: &mut *budget,
            })?;
        }
        Ok(())
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ReofferCounts {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        counter.add(0)
    }
}

/// Per-cycle, entity-grain counters. Content-free: no session ids,
/// fingerprints, account names, body details or paths.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReofferCounts {
    pub(super) due: usize,
    pub(super) selected: usize,
    pub(super) attempted: usize,
    pub(super) attempted_bytes: usize,
    pub(super) gate_held: usize,
    pub(super) ineligible_unbound: usize,
    pub(super) clock_bound_skipped: usize,
    pub(super) accepted: usize,
    pub(super) unchanged_unstored: usize,
    pub(super) refused_same: usize,
    pub(super) refused_other: usize,
    pub(super) retryable: usize,
    pub(super) shed: usize,
    pub(super) failed: usize,
    pub(super) not_materialized: usize,
    pub(super) deferred_budget: usize,
    pub(super) outside_policy_window: usize,
    pub(super) invalid_extension: usize,
    /// Current distinct exact-body cooldown debt, including entities not yet
    /// visited on a bounded page or whose ordinary retry timer is not due.
    pub(super) cooldown_conflict_deferred: usize,
}

impl ReofferCounts {
    pub(super) fn line(&self, source: &str) -> String {
        format!(
            "snapshot reason_reoffer source={source} reason={ORIGINAL_PAIR_CANDIDATE_UNPROVED} \
             due={} selected={} attempted={} attempted_bytes={} gate_held={} ineligible_unbound={} clock_bound_skipped={} accepted={} \
             unchanged_unstored={} refused_same={} refused_other={} retryable={} shed={} \
             failed={} not_materialized={} deferred_budget={} outside_policy_window={} \
             cooldown_conflict_deferred={} invalid_extension_process={}",
            self.due,
            self.selected,
            self.attempted,
            self.attempted_bytes,
            self.gate_held,
            self.ineligible_unbound,
            self.clock_bound_skipped,
            self.accepted,
            self.unchanged_unstored,
            self.refused_same,
            self.refused_other,
            self.retryable,
            self.shed,
            self.failed,
            self.not_materialized,
            self.deferred_budget,
            self.outside_policy_window,
            self.cooldown_conflict_deferred,
            self.invalid_extension,
        )
    }
}

/// Emit work every cycle, but an unchanged, quiet backlog only once. The
/// decoder counter is process-wide and explicitly labelled that way above.
pub(super) fn should_log(source: &str, counts: &ReofferCounts) -> bool {
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};
    static PREVIOUS: OnceLock<Mutex<BTreeMap<String, ReofferCounts>>> = OnceLock::new();
    let mut previous = PREVIOUS.get_or_init(Default::default).lock().unwrap();
    should_log_change(previous.insert(source.to_string(), *counts), counts)
}

pub(super) fn should_log_change(previous: Option<ReofferCounts>, counts: &ReofferCounts) -> bool {
    counts.selected > 0
        || counts.attempted > 0
        || counts.clock_bound_skipped > 0
        || counts.invalid_extension > 0
        || (previous.is_some_and(|old| old != *counts)
            || previous.is_none() && *counts != ReofferCounts::default())
}

impl SnapshotUploadProgress {
    pub(super) fn prepare_quarantine_retries(
        &mut self,
        index_quarantine: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) -> bool {
        self.prepare_quarantine_and_reason_retries(index_quarantine, None)
    }

    /// Select this cycle's ordinary quarantine retries and due refusal
    /// re-offers from one shared per-cycle budget, oldest deadline first.
    /// A selected re-offer reserves its next 24 h deadline here; the caller
    /// saves that claim before any scan or upload uses the lease.
    pub(super) fn prepare_quarantine_and_reason_retries(
        &mut self,
        index_quarantine: &BTreeMap<String, SnapshotQuarantineRecord>,
        reoffer: Option<&reason_reoffer::Scope<'_>>,
    ) -> bool {
        self.active_quarantine_retries.clear();
        self.active_reason_reoffers.clear();
        self.attempted_reason_reoffers.clear();
        self.reason_reoffer_counts = reason_reoffer::ReofferCounts::default();
        let mut contract_retry_changed =
            std::mem::take(&mut self.terminal_contract_retry_pending_save);
        // The upload ledger is saved immediately after an exact ACK, before
        // the index can retire its older quarantine. On crash/restart that ACK
        // is the stronger fact and must not be overwritten by restoring the
        // stale index-owned obligation.
        self.quarantined_fingerprints
            .retain(|fingerprint, _| !self.accepted_fingerprints.contains(fingerprint));
        let newer_retryable_refusals = self
            .quarantined_fingerprints
            .iter()
            .filter(|(fingerprint, record)| {
                record.disposition == SnapshotQuarantineDisposition::RetryPending
                    && self
                        .permanent_rejections
                        .get(*fingerprint)
                        .is_some_and(|refusal| {
                            record.upload_body_witness.as_deref()
                                == Some(refusal.body_witness.as_str())
                        })
            })
            .map(|(fingerprint, _)| fingerprint.clone())
            .collect::<BTreeSet<_>>();
        for (fingerprint, record) in index_quarantine {
            if !self.accepted_fingerprints.contains(fingerprint) {
                // The durable index claims a bounded admission re-offer before
                // this disposable ledger leases it. A stale terminal upload
                // record must not suppress that newer admission obligation.
                if self
                    .quarantined_fingerprints
                    .get(fingerprint)
                    .is_some_and(|old| {
                        old.reconstruction_contract < record.reconstruction_contract
                            || (old.reconstruction_contract == record.reconstruction_contract
                                && old.witness.item_wire_byte_limit
                                    < record.witness.item_wire_byte_limit)
                    })
                {
                    contract_retry_changed |= self.quarantined_fingerprints[fingerprint]
                        .reconstruction_contract
                        < record.reconstruction_contract;
                    let mut replacement = record.clone();
                    crate::snapshots::terminal_contract_retry::merge_claims(
                        &mut replacement,
                        &self.quarantined_fingerprints[fingerprint],
                    );
                    self.quarantined_fingerprints
                        .insert(fingerprint.clone(), replacement);
                }
                self.quarantined_fingerprints
                    .entry(fingerprint.clone())
                    .or_insert_with(|| {
                        contract_retry_changed |= record.reconstruction_contract > 1;
                        record.clone()
                    });
            }
        }
        contract_retry_changed |= crate::snapshots::terminal_contract_retry::merge_maps(
            &mut self.quarantined_fingerprints,
            index_quarantine,
        );
        for (fingerprint, record) in &mut self.quarantined_fingerprints {
            if !self
                .permanent_rejections
                .get(fingerprint)
                .is_some_and(PermanentSnapshotRejection::has_stale_debt)
            {
                contract_retry_changed |=
                    crate::snapshots::terminal_contract_retry::exhaust(record);
            }
        }
        // The server-permanent exact-body fact dominates an older index timer.
        // Keep the index-facing disposition truthful as well as suppressing I/O.
        for (fingerprint, record) in &mut self.quarantined_fingerprints {
            // A conflict recorded alongside the retained refusal is newer:
            // permanent refusal recording itself always writes terminal. Keep
            // that retry debt while the old refusal still suppresses early I/O.
            if newer_retryable_refusals.contains(fingerprint) {
                continue;
            }
            if self
                .permanent_rejections
                .get(fingerprint)
                .is_some_and(|permanent| {
                    !permanent.owed()
                        && record.upload_body_witness.as_deref()
                            == Some(permanent.body_witness.as_str())
                })
            {
                record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
                record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
                record.retry_after_unix_seconds = 0;
            }
        }
        let now = current_unix_seconds();
        let active = self
            .active_quarantine_witness
            .as_ref()
            .expect("upload progress always has an active quarantine witness");
        let mut version_only_kept = 0;
        for record in self.quarantined_fingerprints.values_mut() {
            if record.witness != *active && record.witness.same_retry_contract(active) {
                record.witness = active.clone();
                version_only_kept += 1;
            }
        }
        if version_only_kept > 0 {
            crate::local_resource_diagnostics::traversal_point(
                "quarantine_retry",
                "unknown",
                &serde_json::json!({"action": "version_only_kept", "count": version_only_kept}),
            );
        }
        let mut candidates = self
            .quarantined_fingerprints
            .iter()
            .filter(|(fingerprint, record)| {
                !self
                    .permanent_rejections
                    .get(*fingerprint)
                    .is_some_and(PermanentSnapshotRejection::has_stale_debt)
                    && !record
                        .upload_body_witness
                        .as_deref()
                        .is_some_and(|body| self.refused_body(fingerprint, body))
                    && record.disposition == SnapshotQuarantineDisposition::RetryPending
                    && ((record.contract_retry_claims.is_none()
                        && !record.witness.same_retry_contract(active)
                        && !crate::snapshots::quarantine_context_only_changed(
                            &record.witness,
                            active,
                        ))
                        || record.retry_after_unix_seconds <= now)
            })
            .map(|(fingerprint, record)| {
                (
                    record.witness.same_retry_contract(active) as u8,
                    record.retry_after_unix_seconds,
                    fingerprint.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        let mut reoffer_changed = false;
        let mut due_reoffers = BTreeMap::new();
        if let Some(scope) = reoffer {
            reoffer_changed = self.collect_due_reason_reoffers(scope, &mut due_reoffers);
            // A due re-offer has the same rank as a due ordinary retry under
            // the active witness: oldest deadline first, fingerprint ties.
            // A fingerprint owns one shared slot even if a crash left an
            // ordinary retry for a different body in the progress ledger.
            candidates.retain(|(_, _, fingerprint)| !due_reoffers.contains_key(fingerprint));
            candidates.extend(
                due_reoffers
                    .iter()
                    .map(|(fingerprint, (due, _))| (1u8, *due, fingerprint.clone())),
            );
        }
        let reoffer_now = reoffer.map_or(0, |scope| scope.now);
        let mut retry = BTreeSet::new();
        for (_, _, fingerprint) in candidates {
            if retry.len() + self.active_reason_reoffers.len()
                >= SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE
            {
                break;
            }
            match due_reoffers.remove(&fingerprint) {
                Some((_, body_witness)) => {
                    self.reserve_reason_reoffer(&fingerprint, body_witness, reoffer_now);
                    reoffer_changed = true;
                }
                None => {
                    retry.insert(fingerprint);
                }
            }
        }
        self.reason_reoffer_counts.deferred_budget = due_reoffers.len();
        for fingerprint in &retry {
            let record = self
                .quarantined_fingerprints
                .get_mut(fingerprint)
                .expect("selected quarantine retry exists");
            if record.contract_retry_claims.is_some() {
                crate::snapshots::terminal_contract_retry::claim(record);
                self.pace_retry(fingerprint);
            }
            // Selection is not a send. Offered or still-queued work keeps its
            // deadline; source-held work is paced at the final offer boundary.
        }
        self.active_quarantine_retries = retry;
        !self.active_quarantine_retries.is_empty()
            || version_only_kept > 0
            || reoffer_changed
            || contract_retry_changed
    }

    /// Due, exactly bound refusal re-offers: fingerprint -> (deadline, body).
    /// Returns whether a schedule was changed (re-clamped by the clock bound).
    pub(super) fn collect_due_reason_reoffers(
        &mut self,
        scope: &reason_reoffer::Scope<'_>,
        due: &mut BTreeMap<String, (u64, String)>,
    ) -> bool {
        use reason_reoffer::RefusalReoffer;
        let index = scope.index;
        // A missing or quarantined index cannot prove current membership.
        if index.generation == 0 || self.permanent_rejections.is_empty() {
            return false;
        }
        let current = index
            .eligible_snapshot_fingerprint_refs()
            .collect::<BTreeSet<_>>();
        let latest = reason_reoffer::latest_valid_deadline(scope.now);
        let counts = &mut self.reason_reoffer_counts;
        let mut changed = false;
        for (fingerprint, refusal) in &mut self.permanent_rejections {
            // Known reasons are never re-offered; only the old `other`
            // vocabulary can carry this reason, and only with its extension.
            if refusal.has_stale_debt()
                || refusal.reason != crate::upload_receipts::RejectedUsageReason::Other
            {
                continue;
            }
            let Some(RefusalReoffer::OriginalPair {
                retry_after_unix_seconds: retry_after,
            }) = refusal.reoffer
            else {
                continue;
            };
            if retry_after > latest {
                // A wall-clock rollback must not permanently disable daily
                // offers. Keep suppression this cycle and durably restart the
                // conservative 24 h cooldown.
                refusal.reoffer = Some(RefusalReoffer::OriginalPair {
                    retry_after_unix_seconds: reason_reoffer::next_offer_after(scope.now),
                });
                counts.clock_bound_skipped += 1;
                changed = true;
                continue;
            }
            let bound = index
                .quarantined_snapshot_fingerprints
                .get(fingerprint)
                .is_some_and(|record| {
                    record.disposition != SnapshotQuarantineDisposition::SupersededTerminal
                        && record.upload_body_witness.as_deref()
                            == Some(refusal.body_witness.as_str())
                });
            if !bound
                || !current.contains(fingerprint.as_str())
                || self.accepted_fingerprints.contains(fingerprint)
                || index.accepted_snapshot_fingerprint_recorded(fingerprint)
            {
                counts.ineligible_unbound += 1;
                continue;
            }
            if retry_after > scope.now {
                continue;
            }
            let outside_window = index
                .snapshot_activity_at
                .get(fingerprint)
                .and_then(Option::as_deref)
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                .is_some_and(|activity| {
                    activity.unix_timestamp() < scope.window_start_unix_seconds as i64
                });
            if outside_window {
                counts.outside_policy_window += 1;
                continue;
            }
            counts.due += 1;
            due.insert(
                fingerprint.clone(),
                (retry_after, refusal.body_witness.clone()),
            );
        }
        changed
    }

    /// Extend the existing cooldown view with stale debt. Its input-only hold
    /// survives old terminal dispositions, witness revisions and later ACKs;
    /// those facts do not prove that the retained refusal is covered.
    pub(super) fn reason_reoffer_cooldowns(
        &self,
        now: u64,
    ) -> BTreeMap<String, crate::snapshots::ReasonReofferCooldown> {
        use reason_reoffer::RefusalReoffer;
        let latest = reason_reoffer::latest_valid_deadline(now);
        self.permanent_rejections
            .iter()
            .filter_map(|(fingerprint, owner)| {
                let stale = std::iter::once(owner)
                    .chain(owner.revisions.values())
                    .find(|r| r.owed());
                if let Some(refusal) = stale {
                    return Some((
                        fingerprint.clone(),
                        crate::snapshots::ReasonReofferCooldown {
                            body_witness: refusal.body_witness.clone(),
                            input_change_only: true,
                        },
                    ));
                }
                let eligible =
                    owner.reason == crate::upload_receipts::RejectedUsageReason::Other
                        && matches!(owner.reoffer, Some(RefusalReoffer::OriginalPair { .. }))
                        && owner
                            .reoffer
                            .and_then(RefusalReoffer::retry_after)
                            .is_some_and(|deadline| deadline <= latest)
                        && !self.active_reason_reoffers.contains_key(fingerprint)
                        && !self.active_quarantine_retries.contains(fingerprint)
                        && !self.accepted_fingerprints.contains(fingerprint)
                        && self
                            .quarantined_fingerprints
                            .get(fingerprint)
                            .is_some_and(|record| {
                                record.disposition == SnapshotQuarantineDisposition::RetryPending
                                    && self.active_quarantine_witness.as_ref().is_some_and(
                                        |active| record.witness.same_retry_contract(active),
                                    )
                                    && record.upload_body_witness.as_deref()
                                        == Some(owner.body_witness.as_str())
                            });
                eligible.then(|| {
                    (
                        fingerprint.clone(),
                        crate::snapshots::ReasonReofferCooldown::from(owner.body_witness.clone()),
                    )
                })
            })
            .collect()
    }

    /// Reserve the next logical offer before any scan or upload can use it.
    /// A crash or an unmaterialized lease therefore waits a day.
    pub(super) fn reserve_reason_reoffer(
        &mut self,
        fingerprint: &str,
        body_witness: String,
        now: u64,
    ) {
        let refusal = self
            .permanent_rejections
            .get_mut(fingerprint)
            .expect("selected re-offer has its refusal");
        let next = reason_reoffer::next_offer_after(now);
        refusal.reoffer = refusal
            .reoffer
            .map(|reoffer| reoffer.with_retry_after(next));
        self.reason_reoffer_counts.selected += 1;
        self.active_reason_reoffers
            .insert(fingerprint.to_string(), body_witness);
    }

    /// Immediately before the first actual transmission of this cycle, move
    /// each materialized lease's next deadline to at least now + 24 h.
    /// Returns whether a deadline moved; the caller persists before POST.
    pub(super) fn extend_reason_reoffers_before_upload(
        &mut self,
        items: &[SnapshotItem],
        locally_held: &BTreeSet<String>,
    ) -> bool {
        if self.active_reason_reoffers.is_empty() {
            return false;
        }
        let materialized = items
            .iter()
            .filter(|item| {
                self.active_reason_reoffers
                    .get(&item.snapshot_fingerprint)
                    .is_some_and(|body| {
                        *body == snapshot_upload_body_witness(item)
                            || (item.cache_observations.is_some()
                                && item.cache_base_head_etag.is_none()
                                && *body == snapshot_upload_body_witness(&cache_head_probe(item)))
                    })
            })
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        self.reason_reoffer_counts.gate_held = self
            .active_reason_reoffers
            .keys()
            .filter(|fingerprint| locally_held.contains(*fingerprint))
            .count();
        // Unmaterialized leases are no longer usable this cycle.
        self.active_reason_reoffers
            .retain(|fingerprint, _| materialized.contains(fingerprint));
        self.reason_reoffer_counts.not_materialized = self
            .reason_reoffer_counts
            .selected
            .saturating_sub(materialized.len())
            .saturating_sub(self.reason_reoffer_counts.gate_held);
        let next = reason_reoffer::next_offer_after(reason_reoffer::now_unix_seconds());
        let mut changed = false;
        for fingerprint in &materialized {
            if let Some(refusal) = self.permanent_rejections.get_mut(fingerprint) {
                if let Some(reoffer) = refusal.reoffer {
                    if reoffer
                        .retry_after()
                        .is_some_and(|retry_after| retry_after < next)
                    {
                        refusal.reoffer = Some(reoffer.with_retry_after(next));
                        changed = true;
                    }
                }
            }
        }
        changed
    }

    /// Re-witness a quarantined retry at the active witness and give it the
    /// ordinary backoff, without spending a failure.
    pub(super) fn pace_retry(&mut self, fingerprint: &str) {
        let record = self
            .quarantined_fingerprints
            .get_mut(fingerprint)
            .expect("paced quarantine retry exists");
        record.witness = self
            .active_quarantine_witness
            .clone()
            .expect("upload progress always has an active quarantine witness");
        record.retry_after_unix_seconds = quarantine_retry_after(fingerprint);
    }

    /// Source-held retries use ordinary pacing without spending a failure.
    /// Offered bodies keep their lease: transport/token failures still owe it.
    pub(super) fn defer_held_quarantine_retries(
        &mut self,
        offered: &[SnapshotItem],
        index: &ScanIndex,
        source: SnapshotSource,
    ) -> bool {
        let mut deferred = 0;
        self.active_quarantine_retries.retain(|fingerprint| {
            if offered
                .iter()
                .any(|item| &item.snapshot_fingerprint == fingerprint)
                || index.quarantine_retry_is_queued(fingerprint)
            {
                return true;
            }
            let Some(record) = self.quarantined_fingerprints.get_mut(fingerprint) else {
                return true;
            };
            if record.contract_retry_claims.is_some()
                || record.disposition != SnapshotQuarantineDisposition::RetryPending
            {
                return true;
            }
            record.witness = self
                .active_quarantine_witness
                .clone()
                .expect("upload progress always has an active quarantine witness");
            record.retry_after_unix_seconds = quarantine_retry_after(fingerprint);
            deferred += 1;
            false
        });
        if deferred > 0 {
            crate::local_resource_diagnostics::traversal_point(
                "quarantine_retry",
                source.api_slug(),
                &serde_json::json!({"action": "deferred_held", "count": deferred}),
            );
        }
        deferred > 0
    }

    /// The logical offer ends with the main upload call. Classify each
    /// attempted lease by its validated durable outcome; a lease still held
    /// had no validated response and keeps its reserved cooldown.
    pub(super) fn finish_reason_reoffers(
        &mut self,
        attempted: &BTreeMap<String, String>,
        shed: bool,
        source: &str,
    ) {
        self.context_resend.emit(source);
        let counts = &mut self.reason_reoffer_counts;
        for fingerprint in attempted.keys() {
            if !self.attempted_reason_reoffers.contains(fingerprint) {
                counts.gate_held += 1;
            } else if self.active_reason_reoffers.contains_key(fingerprint) {
                if shed {
                    counts.shed += 1;
                } else {
                    counts.failed += 1;
                }
            }
            // Validated outcomes were counted when they consumed the exact
            // lease. Later cache enrichment cannot relabel a probe's ACK, and
            // an old refusal cannot relabel a fresh retryable conflict.
        }
        self.active_reason_reoffers.clear();
        counts.invalid_extension = counts
            .invalid_extension
            .max(reason_reoffer::take_logged_invalid_extensions());
        if reason_reoffer::should_log(source, counts) {
            eprintln!("{}", counts.line(source));
        }
    }
}

impl SnapshotUploadProgress {
    #[cfg(test)]
    pub(super) fn quarantine<'a>(&mut self, fingerprints: impl IntoIterator<Item = &'a str>) {
        for fingerprint in fingerprints {
            self.quarantine_body(fingerprint, fingerprint);
        }
    }

    pub(super) fn quarantine_body(&mut self, fingerprint: &str, body_witness: &str) {
        crate::snapshots::money_freshness::forget_usage_identical(fingerprint);
        let witness = self
            .active_quarantine_witness
            .clone()
            .expect("upload progress always has an active quarantine witness");
        let budget = self
            .quarantined_fingerprints
            .get(fingerprint)
            .filter(|record| {
                record.upload_body_witness.as_deref() == Some(body_witness)
                    || (record.upload_body_witness.is_none()
                        && record.contract_retry_claims.is_some())
            });
        let existing = budget.filter(|record| record.witness.same_retry_contract(&witness));
        let contract_retry_claims = budget.and_then(|record| record.contract_retry_claims);
        let reconstruction_contract = budget.map_or(
            crate::snapshots::terminal_contract_retry::current_contract(),
            |record| {
                record
                    .reconstruction_contract
                    .max(crate::snapshots::terminal_contract_retry::current_contract())
            },
        );
        let stale_owed = self.owed_stale_body(fingerprint, body_witness);
        // A refused stale body owes an answer; it spends no reconstruction
        // exhaustion budget. Keep the existing RetryPending decoder contract.
        let failed_reconstruction_count = if stale_owed {
            1
        } else {
            existing
                .map(|record| record.failed_reconstruction_count.saturating_add(1))
                .unwrap_or(1)
                .min(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES)
        };
        let disposition = if !stale_owed
            && failed_reconstruction_count == MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
        {
            if existing.map_or(0, |record| record.failed_reconstruction_count)
                < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
            {
                UNPROVEN_TERMINAL_ATTEMPT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            SnapshotQuarantineDisposition::UnprovenTerminal
        } else {
            SnapshotQuarantineDisposition::RetryPending
        };
        self.quarantined_fingerprints.insert(
            fingerprint.to_string(),
            SnapshotQuarantineRecord {
                contract_retry_claims,
                reconstruction_contract,
                witness,
                retry_after_unix_seconds: if disposition
                    == SnapshotQuarantineDisposition::UnprovenTerminal
                {
                    0
                } else {
                    quarantine_retry_after(fingerprint)
                },
                upload_body_witness: Some(body_witness.to_string()),
                failed_reconstruction_count,
                disposition,
            },
        );
        self.accepted_fingerprints.remove(fingerprint);
        self.accepted_body_witnesses.remove(fingerprint);
        self.accepted_body_contexts.remove(fingerprint);
        self.active_quarantine_retries.remove(fingerprint);
    }

    pub(super) fn quarantine_permanent_body(
        &mut self,
        fingerprint: &str,
        body_witness: &str,
        reason: &str,
    ) {
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            if reason == reason_reoffer::ORIGINAL_PAIR_CANDIDATE_UNPROVED {
                self.reason_reoffer_counts.refused_same += 1;
            } else {
                self.reason_reoffer_counts.refused_other += 1;
            }
        }
        self.quarantine_body(fingerprint, body_witness);
        let record = self.quarantined_fingerprints.get_mut(fingerprint).unwrap();
        // Current servers prove coverage before issuing a permanent stale
        // refusal. Fresh exposure records its recording generation; no legacy
        // record receives that marker without a new server answer.
        record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
        record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
        record.retry_after_unix_seconds = 0;
        let persisted_reason = crate::upload_receipts::RejectedUsageReason::from_wire(reason);
        // Each same-reason refusal restarts the 24 h clock. Any other `other`
        // answer is the server's classification of this body: done, never
        // re-offered. Known reasons keep their old record byte-for-byte.
        let reoffer = if reason == reason_reoffer::ORIGINAL_PAIR_CANDIDATE_UNPROVED {
            Some(reason_reoffer::RefusalReoffer::OriginalPair {
                retry_after_unix_seconds: reason_reoffer::next_offer_after(
                    reason_reoffer::now_unix_seconds(),
                ),
            })
        } else if persisted_reason == crate::upload_receipts::RejectedUsageReason::Other {
            Some(reason_reoffer::RefusalReoffer::Classified)
        } else {
            None
        };
        let revisions = self.retained_revisions(fingerprint, body_witness);
        self.permanent_rejections.insert(
            fingerprint.to_string(),
            PermanentSnapshotRejection {
                body_witness: body_witness.to_string(),
                reason: persisted_reason,
                reoffer,
                exposure: Some(stale_owed::Exposure::new(current_unix_seconds())),
                revisions,
            },
        );
        self.active_reason_reoffers.remove(fingerprint);
    }

    /// The server answered `unchanged` with an `unchanged_basis`: it did not
    /// store this body. Hold the exact body terminally, like a permanent
    /// refusal of the same body before that answer existed, but record no
    /// refusal: no usage was rejected. A changed body is a new fingerprint and
    /// is offered again; a historical replay rearms it once. A current-context
    /// re-offer answered `dominated_by_head` keeps 6h/12h retry custody; one
    /// answered `usage_identical` is terminal at once, and this process notes
    /// the exact body for the freshness walk (`note_usage_identical`).
    pub(super) fn hold_unstored_body(
        &mut self,
        fingerprint: &str,
        body_witness: &str,
        usage_identical: bool,
    ) {
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            self.reason_reoffer_counts.unchanged_unstored += 1;
        }
        // A validated unchanged answer for a re-offered refused body replaces
        // that refusal's verdict. Retire it, so its reason schedules no more
        // offers; the hold below keeps the no-body-stored disclosure.
        let stale_owed = self.owed_stale_body(fingerprint, body_witness);
        if !stale_owed
            && self
                .permanent_rejections
                .get(fingerprint)
                .is_some_and(|refusal| refusal.body_witness == body_witness)
        {
            self.permanent_rejections.remove(fingerprint);
        }
        self.active_reason_reoffers.remove(fingerprint);
        self.quarantine_body(fingerprint, body_witness);
        let record = self
            .quarantined_fingerprints
            .get_mut(fingerprint)
            .expect("quarantine just recorded");
        if stale_owed {
            record.disposition = SnapshotQuarantineDisposition::RetryPending;
            record.contract_retry_claims = None;
        } else if self.context_resend.is_candidate(fingerprint) && !usage_identical {
            // Current-context not_stored re-offers retain ordinary retry custody.
            // Exponential 6h/12h, capped by the existing 12h decoder bound.
            if record.disposition == SnapshotQuarantineDisposition::RetryPending {
                let delay = SNAPSHOT_QUARANTINE_RETRY_SECONDS.saturating_mul(
                    1u64 << record.failed_reconstruction_count.saturating_sub(1).min(1),
                );
                record.retry_after_unix_seconds =
                    reason_reoffer::now_unix_seconds().saturating_add(delay);
            }
        } else {
            record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
            record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
            record.retry_after_unix_seconds = 0;
            if usage_identical && let Some(context) = &self.context_resend.active {
                crate::snapshots::money_freshness::note_usage_identical(
                    fingerprint,
                    &self.destination_namespace_hash,
                    context,
                    self.historical_replay_generation.as_deref(),
                    body_witness,
                );
            }
        }
    }

    /// `retry_after_unix_seconds`: `quarantine_retry_after` for a refusal or
    /// conflict, the server's own `Retry-After` window for an identity deferral.
    pub(super) fn quarantine_retryable_body(
        &mut self,
        fingerprint: &str,
        body_witness: &str,
        retry_after_unix_seconds: u64,
    ) {
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            self.reason_reoffer_counts.retryable += 1;
        }
        self.active_reason_reoffers.remove(fingerprint);
        self.quarantine_body(fingerprint, body_witness);
        let record = self
            .quarantined_fingerprints
            .get_mut(fingerprint)
            .expect("quarantine just recorded");
        record.failed_reconstruction_count = if record.contract_retry_claims.is_some() {
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
        } else {
            1
        };
        record.disposition = SnapshotQuarantineDisposition::RetryPending;
        record.retry_after_unix_seconds = retry_after_unix_seconds;
        crate::snapshots::terminal_contract_retry::exhaust(record);
    }

    /// Outage custody: hold each body of the page that has no exact ACK, hold
    /// or refusal of these exact bytes yet, as an ordinary retryable
    /// quarantine until `retry_after_unix_seconds`. Returns how many were held.
    pub(super) fn hold_outage_bodies(
        &mut self,
        items: &[SnapshotItem],
        retry_after_unix_seconds: u64,
    ) -> usize {
        let mut held = 0;
        for item in items {
            let fingerprint = item.snapshot_fingerprint.as_str();
            let witness = snapshot_upload_body_witness(item);
            if self.accepted_body_witnesses.get(fingerprint) == Some(&witness)
                || self
                    .quarantined_fingerprints
                    .get(fingerprint)
                    .is_some_and(|record| record.upload_body_witness.as_ref() == Some(&witness))
                || self.refused_body(fingerprint, &witness)
            {
                continue;
            }
            self.quarantine_retryable_body(fingerprint, &witness, retry_after_unix_seconds);
            held += 1;
        }
        held
    }

    pub(super) fn retain_current_quarantines_with_diagnostics(
        &mut self,
        current: &BTreeSet<String>,
        index: &ScanIndex,
        diagnostic: Option<&mut CodexScanDiagnostics>,
    ) -> bool {
        let changed = self.retain_current_quarantines(current, index);
        if let Some(diagnostic) = diagnostic {
            for (fingerprint, record) in &self.quarantined_fingerprints {
                let fingerprint_digest = codex_scan_diagnostics::digest(fingerprint);
                for sample in diagnostic.lineage.iter_mut().flatten() {
                    if sample.fingerprint_digest == fingerprint_digest {
                        sample.after_current = current.contains(fingerprint);
                        sample.after_disposition = record.disposition;
                    }
                }
            }
        }
        changed
    }

    pub(super) fn retain_current_quarantines(
        &mut self,
        current: &BTreeSet<String>,
        index: &ScanIndex,
    ) -> bool {
        let eligible = index
            .eligible_snapshot_fingerprint_refs()
            .collect::<BTreeSet<_>>();
        let before = self.quarantined_fingerprints.clone();
        for (fingerprint, record) in &mut self.quarantined_fingerprints {
            if current.contains(fingerprint)
                && eligible.contains(fingerprint.as_str())
                && !index.decode_holds_entity(fingerprint)
                && !self.permanent_rejections.contains_key(fingerprint)
                && record.disposition == SnapshotQuarantineDisposition::SupersededTerminal
                && record.failed_reconstruction_count < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
                && record
                    .contract_retry_claims
                    .is_none_or(|n| n < crate::snapshots::terminal_contract_retry::MAX_CLAIMS)
            {
                record.disposition = SnapshotQuarantineDisposition::RetryPending;
                record.retry_after_unix_seconds = 0;
            } else if !current.contains(fingerprint)
                && !self
                    .permanent_rejections
                    .get(fingerprint)
                    .is_some_and(PermanentSnapshotRejection::has_stale_debt)
                && record.disposition != SnapshotQuarantineDisposition::SupersededTerminal
            {
                record.disposition = SnapshotQuarantineDisposition::SupersededTerminal;
                record.retry_after_unix_seconds = 0;
            }
        }
        self.active_quarantine_retries
            .retain(|fingerprint| current.contains(fingerprint));
        self.quarantined_fingerprints != before
    }
}
