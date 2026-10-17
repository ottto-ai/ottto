//! Interim copy containment components and inactive native integration seams.
//! The ordinary daemon owner does not attach a comparison context yet.
//! Pair observations are negative evidence only, never a uniqueness certificate,
//! accepted-request membership, account identity or provider ownership proof.
use super::{SnapshotItem, MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS};
use serde::{Deserialize, Serialize};

pub(in crate::snapshots) mod accounting;
pub(in crate::snapshots) mod membership;
pub(crate) mod pipeline;
// Inactive mechanical decoder/copy checkpoint. Production attachment awaits
// complete native ownership and settlement qualification.
#[allow(dead_code)]
pub(in crate::snapshots) mod required_budget;
#[allow(dead_code)]
pub(in crate::snapshots) mod required_decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativePairObservation {
    SameSession,
    /// No shared ID in these two inputs; says nothing about other transcripts.
    NoObservedOverlap,
    Overlap {
        request_count: usize,
    },
    /// No truncated count may authorize a body when existing bounds refuse it.
    Unavailable,
}

/// Borrow only actual transcript IDs already carried by the parser's items.
/// Do not accept provider envelopes, aggregate amounts or set fingerprints.
/// No IDs/rows/sets are copied or retained. A caller still needs actual native
/// completion and comparison coverage before any permissive offer decision.
pub(super) fn observe_native_pair(
    current: &SnapshotItem,
    other: &SnapshotItem,
) -> NativePairObservation {
    if current.source_session_id == other.source_session_id {
        return NativePairObservation::SameSession;
    }
    if current.claude_usage_request_ids.len() > MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
        || other.claude_usage_request_ids.len() > MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
    {
        return NativePairObservation::Unavailable;
    }
    let shared = current
        .claude_usage_request_ids
        .intersection(&other.claude_usage_request_ids)
        .count();
    if shared == 0 {
        NativePairObservation::NoObservedOverlap
    } else {
        NativePairObservation::Overlap {
            request_count: shared,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HoldReason {
    CopiedOverlapUnproven,
    ComparisonUnavailable,
    OwnerBudgetExceeded,
    IncidentCopySafety,
}

/// Parking is explicitly distinct from a normal unchanged-file Skip. Neither
/// this result nor the held revision contributes current request coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadDisposition {
    ReadRevisionOrEvidenceChanged,
    ParkUnchangedHeldRevision,
}

/// Local held-revision value in a separately validated ScanIndex ledger.
/// It is not wire data and cannot itself establish comparison scope or custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedHoldRevision")]
pub(super) struct HoldRevision {
    version: u8,
    reason: HoldReason,
    source_revision: String,
    comparison_context: String,
    /// First observation of this typed hold, not the transcript's historical
    /// hold age. None remains UNKNOWN across revision/context changes.
    first_observed_unix_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedHoldRevision {
    version: u8,
    reason: HoldReason,
    source_revision: String,
    comparison_context: String,
    #[serde(default)]
    first_observed_unix_seconds: Option<u64>,
}

impl TryFrom<UncheckedHoldRevision> for HoldRevision {
    type Error = &'static str;

    fn try_from(raw: UncheckedHoldRevision) -> Result<Self, Self::Error> {
        let record = Self {
            version: raw.version,
            reason: raw.reason,
            source_revision: raw.source_revision,
            comparison_context: raw.comparison_context,
            first_observed_unix_seconds: raw.first_observed_unix_seconds,
        };
        record
            .is_valid()
            .then_some(record)
            .ok_or("invalid local copy hold")
    }
}

impl HoldRevision {
    pub(super) fn new(
        reason: HoldReason,
        source_revision: String,
        comparison_context: String,
        first_observed_unix_seconds: Option<u64>,
    ) -> Option<Self> {
        let record = Self {
            version: 1,
            reason,
            source_revision,
            comparison_context,
            first_observed_unix_seconds,
        };
        record.is_valid().then_some(record)
    }

    fn is_valid(&self) -> bool {
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        self.version == 1
            && digest(&self.source_revision)
            && digest(&self.comparison_context)
            && self.first_observed_unix_seconds != Some(0)
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// A new revision is not an excuse to erase old debt, restart its clock or
    /// clear an incident hold. No parse, offer, partial save or ACK drains here.
    pub(super) fn revise(&self, revision: String, context: String) -> Option<Self> {
        Self::new(
            self.reason,
            revision,
            context,
            self.first_observed_unix_seconds,
        )
    }

    pub(super) fn known_observed_age_seconds(&self, now: u64) -> Option<u64> {
        now.checked_sub(self.first_observed_unix_seconds?)
    }

    /// Compare the actual opened revision and meaningful evidence/context,
    /// not the committed entry's fingerprint, which base rearm may clear on
    /// every traversal. The caller must establish the complete wake context;
    /// this component does not invent that witness or wire a scanner Skip.
    pub(super) fn read_disposition(
        &self,
        opened_revision: &str,
        comparison_context: &str,
    ) -> ReadDisposition {
        if self.source_revision == opened_revision && self.comparison_context == comparison_context
        {
            ReadDisposition::ParkUnchangedHeldRevision
        } else {
            ReadDisposition::ReadRevisionOrEvidenceChanged
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for HoldReason {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        counter.add(0)
    }
}
crate::heap_layout_bound::fields!(HoldRevision; version, reason, source_revision, comparison_context, first_observed_unix_seconds);

#[cfg(test)]
mod tests;
