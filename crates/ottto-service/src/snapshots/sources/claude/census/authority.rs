//! Claude usage authority: the fold's disposition (quarantined and
//! account-deferred sessions), the family authority record checks, the
//! accepted-body checks and the request-census shadow counts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use crate::snapshots::claude_context_file_birth::ClaudeFileBirthVerdict;
use crate::snapshots::scan_index::file_set_digest::update_length_prefixed;
use crate::snapshots::wire::SnapshotItem;
use crate::snapshots::{
    claude_authority_record_contract_is_valid, claude_request_accounts, claude_request_identity,
    claude_snapshot_family_root, usage_totals_from_item, ClaudeContextFileBirthCounts,
    ClaudeTranscriptUsageOccurrence, ClaudeUsageAuthorityQuarantineDisposition,
    ClaudeUsageAuthorityQuarantineRecord, ClaudeUsageFamilyWitness, ScanIndex, ScanIndexEntry,
    SourceScanResult, CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS, MAX_CLAUDE_USAGE_AUTHORITY_FAILURES,
    SNAPSHOT_ACCEPTED_LEDGER_VERSION,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeUsageAuthorityDisposition {
    /// Local counters for how this fold's Claude scalars were decided.
    pub(crate) context_file_birth: ClaudeContextFileBirthCounts,
    pub(in crate::snapshots) quarantined_source_session_ids: BTreeSet<String>,
    /// The account-deferred subset of `quarantined_source_session_ids`. Upload
    /// retention still uses the union; this only classifies settlement.
    pub(in crate::snapshots) account_deferred_source_session_ids: BTreeSet<String>,
    /// Fixed-label `e2` emission veto counts for this page. Diagnostic only;
    /// never serialized, persisted, or used to decide upload eligibility.
    pub(crate) request_owned_hold_reasons: BTreeMap<&'static str, u64>,
    pub(crate) mixed_uploads: claude_request_accounts::MixedUploads,
    /// Contract-5 only: each rebuilt item's requests, classified and folded
    /// into bounded row x authority-key groups during the rebuild.
    pub(crate) request_groupings: BTreeMap<String, claude_request_identity::Grouping>,
    /// Copy-derived rows (#944): the accepted rows this
    /// pass's bodies treat as never accepted. The sync loop tombstones them
    /// through `AcceptedBuckets` and saves before any upload.
    pub(crate) copy_invalidated: Vec<claude_request_identity::CopyInvalidation>,
    /// Why each folded item kept or lost its Claude posture scalars. Kept for
    /// tests only: never built in a release fold, never serialized, and never
    /// an index, account, identity, audit or upload input.
    #[cfg(test)]
    pub(crate) posture_admissions: BTreeMap<String, ClaudePostureAdmission>,
}

pub(in crate::snapshots) fn claude_usage_family_witness_fingerprint(
    witness: &ClaudeUsageFamilyWitness,
) -> String {
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, b"ottto:claude-usage-family-durable-witness:v1");
    update_length_prefixed(&mut digest, witness.evidence_fingerprint.as_bytes());
    update_length_prefixed(&mut digest, b"member_request_id_fingerprints");
    for (member, fingerprint) in &witness.member_request_id_fingerprints {
        update_length_prefixed(&mut digest, member.as_bytes());
        update_length_prefixed(&mut digest, fingerprint.as_bytes());
    }
    update_length_prefixed(&mut digest, b"member_occurrence_fingerprints");
    for (member, fingerprint) in &witness.member_occurrence_fingerprints {
        update_length_prefixed(&mut digest, member.as_bytes());
        update_length_prefixed(&mut digest, fingerprint.as_bytes());
    }
    update_length_prefixed(&mut digest, b"assigned_request_id_fingerprints");
    for (member, fingerprint) in &witness.assigned_request_id_fingerprints {
        update_length_prefixed(&mut digest, member.as_bytes());
        update_length_prefixed(&mut digest, fingerprint.as_bytes());
    }
    update_length_prefixed(&mut digest, b"legacy_excluded_request_id_hashes");
    for (member, excluded) in &witness.legacy_excluded_request_id_hashes {
        update_length_prefixed(&mut digest, member.as_bytes());
        for request_hash in excluded {
            update_length_prefixed(&mut digest, request_hash.as_bytes());
        }
    }
    update_length_prefixed(&mut digest, b"legacy_exclusion_evidence_fingerprint");
    update_length_prefixed(
        &mut digest,
        witness
            .legacy_exclusion_evidence_fingerprint
            .as_deref()
            .unwrap_or("none")
            .as_bytes(),
    );
    update_length_prefixed(&mut digest, b"legacy_owner_roots");
    for root in &witness.legacy_owner_roots {
        update_length_prefixed(&mut digest, root.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::snapshots) struct ClaudeTranscriptUsageOccurrenceWitness {
    #[serde(default)]
    pub(in crate::snapshots) sequence: u64,
    pub(in crate::snapshots) input_tokens: u64,
    pub(in crate::snapshots) output_tokens: u64,
    pub(in crate::snapshots) cache_read_tokens: u64,
    pub(in crate::snapshots) cache_creation_5m_tokens: u64,
    pub(in crate::snapshots) cache_creation_1h_tokens: u64,
    pub(in crate::snapshots) reasoning_output_tokens: u64,
    pub(in crate::snapshots) model: Option<String>,
    pub(in crate::snapshots) speed_mode: Option<String>,
    pub(in crate::snapshots) reasoning_effort: Option<String>,
}

impl From<&ClaudeTranscriptUsageOccurrence> for ClaudeTranscriptUsageOccurrenceWitness {
    fn from(occurrence: &ClaudeTranscriptUsageOccurrence) -> Self {
        Self {
            sequence: occurrence.sequence,
            input_tokens: occurrence.usage.input_tokens,
            output_tokens: occurrence.usage.output_tokens,
            cache_read_tokens: occurrence.usage.cache_read_tokens,
            cache_creation_5m_tokens: occurrence.usage.cache_creation_5m_tokens,
            cache_creation_1h_tokens: occurrence.usage.cache_creation_1h_tokens,
            reasoning_output_tokens: occurrence.usage.reasoning_output_tokens,
            model: occurrence.model.clone(),
            speed_mode: occurrence.selector.context.get("speed_mode").cloned(),
            reasoning_effort: occurrence.reasoning_effort.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::snapshots) struct ProvenClaudeUsageFamily {
    pub(in crate::snapshots) witness: ClaudeUsageFamilyWitness,
    pub(in crate::snapshots) rows_by_member:
        BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
}

/// Test-only, content-free copy of one family authority record and its
/// binding to the retained witness.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeAuthorityRecordForTest {
    pub(crate) contract: String,
    pub(crate) proven_witness_fingerprint: String,
    pub(crate) member_source_file_fingerprints: BTreeMap<String, String>,
    pub(crate) failed_reconstruction_count: u8,
    pub(crate) terminal: bool,
    pub(crate) retry_after_unix_seconds: u64,
    /// The pending correction's proof digest and owed members.
    pub(crate) correction: Option<(String, BTreeSet<String>)>,
    pub(crate) bound_to_retained_witness: bool,
}

/// The rule that admitted or withheld one Claude item's first/peak/last
/// context and compaction scalars in the ownership fold. Recorded by tests.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudePostureAdmission {
    /// The file birth rule decided.
    FileBirth(ClaudeFileBirthVerdict),
}

#[cfg(test)]
impl ClaudePostureAdmission {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::FileBirth(ClaudeFileBirthVerdict::Admitted) => "file_birth_rule",
            Self::FileBirth(ClaudeFileBirthVerdict::UnknownBirth) => "withheld_unknown_birth",
            Self::FileBirth(ClaudeFileBirthVerdict::UntimedRecord) => "withheld_untimed_record",
            Self::FileBirth(ClaudeFileBirthVerdict::AllCopied) => "withheld_all_copied",
            Self::FileBirth(ClaudeFileBirthVerdict::MultiFile) => "withheld_multi_file",
            Self::FileBirth(ClaudeFileBirthVerdict::Tripwire) => "withheld_tripwire",
            Self::FileBirth(ClaudeFileBirthVerdict::EvidenceBound) => "withheld_evidence_bound",
        }
    }
}

#[cfg(test)]
impl ClaudeUsageAuthorityDisposition {
    pub(crate) fn posture_admission(&self, source_session_id: &str) -> Option<&'static str> {
        self.posture_admissions
            .get(source_session_id)
            .map(|admission| admission.as_str())
    }
}

impl ClaudeUsageAuthorityDisposition {
    /// `e2` (gate on): request-owned entities `e2::finish_page` withheld (held
    /// twin, uncertified body, unread telemetry). Their items stay on the
    /// page but never upload; the hold is not bound to an authority record,
    /// so it blocks progress and the files are read again: delayed, never
    /// settled without their body. Not an account deferral.
    pub(crate) fn hold_request_owned(&mut self, session_ids: BTreeSet<String>) {
        self.quarantined_source_session_ids.extend(session_ids);
    }

    pub(crate) fn defer_sessions(&mut self, session_ids: BTreeSet<String>) {
        self.account_deferred_source_session_ids
            .extend(session_ids.iter().cloned());
        self.quarantined_source_session_ids.extend(session_ids);
    }

    /// Withheld tokens of each account-deferred snapshot, by fingerprint.
    pub(crate) fn account_deferred_tokens(
        &self,
        snapshots: &[SnapshotItem],
    ) -> BTreeMap<String, u64> {
        let deferred = self.account_deferred_fingerprints(snapshots);
        (snapshots.iter())
            .filter(|snapshot| deferred.contains(&snapshot.snapshot_fingerprint))
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    usage_totals_from_item(item).total_tokens(),
                )
            })
            .collect()
    }

    pub(crate) fn account_deferred_fingerprints(
        &self,
        snapshots: &[SnapshotItem],
    ) -> BTreeSet<String> {
        snapshots
            .iter()
            .filter(|snapshot| {
                self.account_deferred_source_session_ids
                    .contains(&snapshot.source_session_id)
            })
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect()
    }

    /// Held revisions that owe the traversal a clean follow-up. Two hold
    /// classes do not:
    ///
    /// - an authority demotion whose root carries a bounded record bound to
    ///   the retained witness and to this exact revision: `UnprovenTerminal`,
    ///   or `RetryPending` without a correction grant (the path-(a) bridge).
    ///   The record keeps the family's retry clock and quarantine, and the
    ///   candidate gate selects the family again only when it changes or its
    ///   retry is due; the held key keeps its committed revision;
    /// - an account deferral, whose verdict depends on the body and the local
    ///   request evidence rather than on traversal completeness. Its key keeps
    ///   the committed revision and is reparsed once per process and when its
    ///   content or account evidence changes (`withheld_account`).
    ///
    /// Everything else stays progress-blocking. Without a durable disclosure
    /// for every account deferral (`account_holds_recorded == false`), account
    /// deferrals stay progress-blocking too.
    pub(crate) fn progress_blocking_held_fingerprints(
        &self,
        snapshots: &[SnapshotItem],
        index: &ScanIndex,
        account_holds_recorded: bool,
    ) -> BTreeSet<String> {
        snapshots
            .iter()
            .filter(|snapshot| {
                self.quarantined_source_session_ids
                    .contains(&snapshot.source_session_id)
            })
            .filter(|snapshot| {
                if self
                    .account_deferred_source_session_ids
                    .contains(&snapshot.source_session_id)
                {
                    if !account_holds_recorded {
                        crate::local_resource_diagnostics::claude_reread::held_reason(
                            crate::local_resource_diagnostics::claude_reread::HeldReason::AccountHoldUnrecorded,
                        );
                    }
                    return !account_holds_recorded;
                }
                !claude_authority_hold_is_bound(snapshot, index)
            })
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect()
    }

    pub(crate) fn quarantined_fingerprints(&self, snapshots: &[SnapshotItem]) -> BTreeSet<String> {
        snapshots
            .iter()
            .filter(|snapshot| {
                self.quarantined_source_session_ids
                    .contains(&snapshot.source_session_id)
            })
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect()
    }

    pub(crate) fn retain_uploadable(&self, snapshots: &mut Vec<SnapshotItem>) {
        snapshots.retain(|snapshot| {
            !self
                .quarantined_source_session_ids
                .contains(&snapshot.source_session_id)
        });
    }

    pub(crate) fn quarantined_entity_count(&self) -> usize {
        self.quarantined_source_session_ids.len()
    }
}

pub(in crate::snapshots) fn claude_usage_authority_retry_deadline(
    root_session_id: &str,
    proven_witness_fingerprint: &str,
) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let digest = Sha256::digest(
        [
            root_session_id.as_bytes(),
            proven_witness_fingerprint.as_bytes(),
        ]
        .concat(),
    );
    let jitter = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("sha256 prefix is exactly eight bytes"),
    ) % CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS;
    now.saturating_add(CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS)
        .saturating_add(jitter)
}

pub(in crate::snapshots) fn claude_usage_authority_preserves_pending(
    quarantine: &ClaudeUsageAuthorityQuarantineRecord,
    witness: &ClaudeUsageFamilyWitness,
) -> bool {
    claude_usage_authority_deadline_is_bounded(quarantine)
        && quarantine.proven_witness_fingerprint == claude_usage_family_witness_fingerprint(witness)
}

/// Whether an indexed file's committed body is server-accepted: it has a
/// committed snapshot, and every current entity fingerprint is in the
/// persisted accepted ledger and not snapshot-quarantined. A settled
/// permanent refusal is not acceptance.
pub(in crate::snapshots) fn claude_index_file_body_accepted(
    index: &ScanIndex,
    index_key: &str,
    entry: &ScanIndexEntry,
) -> bool {
    !index.decode_holds_file(index_key)
        && entry.last_snapshot_fingerprint.is_some()
        && index
            .file_snapshot_fingerprints
            .get(index_key)
            .is_some_and(|fingerprints| {
                !fingerprints.is_empty()
                    && fingerprints.iter().all(|fingerprint| {
                        !index.decode_holds_indexed_entity(index_key, fingerprint)
                            && index.accepted_snapshot_fingerprints.contains(fingerprint)
                            && !index
                                .quarantined_snapshot_fingerprints
                                .contains_key(fingerprint)
                    })
            })
}

/// Whether the accepted ledger is current and not being rebuilt by the
/// legacy settlement reconciliation.
pub(in crate::snapshots) fn claude_accepted_ledger_is_current(index: &ScanIndex) -> bool {
    index.accepted_snapshot_fingerprint_ledger_version == SNAPSHOT_ACCEPTED_LEDGER_VERSION
        && index
            .legacy_settlement_reconcile_after_fingerprint
            .is_none()
}

/// A demoted revision owes no clean follow-up only while its family quarantine
/// is bounded, bound to the retained witness, and records exactly this
/// revision: the candidate gate then skips it until the family changes (or,
/// for RetryPending, its retry is due). A terminal record always qualifies. A
/// RetryPending record qualifies only without a correction grant (path-(a)
/// bridge): its hold, quarantine and retry clock are unchanged, and its
/// pending count keeps the census withheld. Every other shape still blocks.
fn claude_authority_hold_is_bound(snapshot: &SnapshotItem, index: &ScanIndex) -> bool {
    use crate::local_resource_diagnostics::claude_reread::{held_reason, HeldReason};
    let Some(revision) = snapshot.source_file_fingerprint.as_ref() else {
        held_reason(HeldReason::AuthorityUnboundRevision);
        return false;
    };
    let mut reason = HeldReason::AuthorityUnboundRevision;
    let root_session_id = claude_snapshot_family_root(snapshot);
    let bound = index
        .claude_usage_authority_quarantine
        .get(&root_session_id)
        .zip(index.claude_usage_family_witnesses.get(&root_session_id))
        .is_some_and(|(record, witness)| {
            let bounded_disposition = match record.disposition {
                ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal => true,
                ClaudeUsageAuthorityQuarantineDisposition::RetryPending => {
                    if record.proof_correction.is_some() {
                        reason = HeldReason::AuthorityCorrectionPending;
                    }
                    record.proof_correction.is_none()
                }
            };
            bounded_disposition
                && claude_usage_authority_preserves_pending(record, witness)
                && record
                    .member_source_file_fingerprints
                    .get(&snapshot.source_session_id)
                    == Some(revision)
        });
    if !bound {
        held_reason(reason);
    }
    bound
}

pub(in crate::snapshots) fn claude_usage_authority_deadline_is_bounded(
    record: &ClaudeUsageAuthorityQuarantineRecord,
) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    claude_authority_record_contract_is_valid(record)
        && sha256_hex_is_well_formed(&record.proven_witness_fingerprint)
        && !record.member_source_file_fingerprints.is_empty()
        && (1..=MAX_CLAUDE_USAGE_AUTHORITY_FAILURES).contains(&record.failed_reconstruction_count)
        && match record.disposition {
            ClaudeUsageAuthorityQuarantineDisposition::RetryPending => {
                record.failed_reconstruction_count < MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
            }
            ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal => {
                record.failed_reconstruction_count == MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
            }
        }
        && record
            .member_source_file_fingerprints
            .values()
            .all(|fingerprint| sha256_hex_is_well_formed(fingerprint))
        && record.retry_after_unix_seconds
            <= now.saturating_add(CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS.saturating_mul(2))
}

pub(in crate::snapshots) fn sha256_hex_is_well_formed(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// Account-deferred holds are disclosed from a durable map. A cycle that cannot
// record one keeps every account deferral progress-blocking: overflow costs a
// clean follow-up generation and never settles a traversal undisclosed.
pub(in crate::snapshots) const MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS: usize = 4_096;

/// The request-census shadow, measured by the scan on a complete
/// Claude terminal and reported on the local evidence line. Content-free counts; nothing reads them into a decision.
/// `would_open` is whether every indexed Claude family-member key (not
/// confirmed empty) has a record covering it, by fingerprint or by this
/// census window, within the hash budget and the duplicate-owner bound.
/// `missing_*` name, first match wins, why the other keys are not covered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeRequestCensusShadowCounts {
    pub would_open: bool,
    pub would_open_flips: u64,
    pub family_keys: usize,
    pub covered_by_fingerprint: usize,
    pub covered_by_window: usize,
    pub missing_residue: usize,
    pub missing_account_hold: usize,
    pub missing_placeholder: usize,
    pub missing_empty_fingerprint: usize,
    pub missing_fingerprint_mismatch: usize,
    pub missing_migrate: usize,
    pub missing_over_budget: usize,
    pub quarantine_without_record: usize,
    pub shape_exact: usize,
    pub shape_empty: usize,
    pub shape_identity_incomplete: usize,
    pub shape_lossy: usize,
    pub unverified: usize,
    pub twin: usize,
    pub family_unknown_roots: usize,
    pub records: usize,
    pub hashes: usize,
    pub hash_budget_usage_percent: usize,
    pub transient_limited: bool,
    pub transient_peak_bytes: usize,
    pub duplicate_hashes: usize,
    pub duplicate_owner_entries: usize,
    pub shared_keys: usize,
    pub derivation_drift: u64,
    pub json_bytes: usize,
    pub heap_bytes: usize,
}

impl ScanIndex {
    pub(crate) fn claude_usage_authority_pending_count(&self) -> usize {
        self.claude_usage_authority_quarantine
            .values()
            .filter(|record| {
                record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
            })
            .count()
    }

    pub(crate) fn claude_usage_authority_terminal_entity_count(&self) -> usize {
        self.claude_usage_authority_quarantine
            .values()
            .filter(|record| {
                record.disposition == ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
            })
            .map(|record| record.member_source_file_fingerprints.len())
            .fold(0_usize, usize::saturating_add)
    }

    pub(crate) fn account_claude_usage_authority_census_health(
        &self,
        scan_result: &mut SourceScanResult,
    ) -> bool {
        let terminal_entity_count = self.claude_usage_authority_terminal_entity_count();
        scan_result.ownership_incomplete_file_count = scan_result
            .ownership_incomplete_file_count
            .saturating_add(terminal_entity_count);
        scan_result.terminal_ownership_incomplete_file_count = scan_result
            .terminal_ownership_incomplete_file_count
            .saturating_add(terminal_entity_count);
        self.claude_usage_authority_pending_count() > 0
    }
}

crate::heap_layout_bound::fields!(ClaudeTranscriptUsageOccurrenceWitness; sequence, input_tokens, output_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, reasoning_output_tokens, model, speed_mode, reasoning_effort);
crate::heap_layout_bound::fields!(ProvenClaudeUsageFamily; witness, rows_by_member);
crate::heap_layout_bound::fields!(ClaudeRequestCensusShadowCounts; would_open, would_open_flips, family_keys, covered_by_fingerprint, covered_by_window, missing_residue, missing_account_hold, missing_placeholder, missing_empty_fingerprint, missing_fingerprint_mismatch, missing_migrate, missing_over_budget, quarantine_without_record, shape_exact, shape_empty, shape_identity_incomplete, shape_lossy, unverified, twin, family_unknown_roots, records, hashes, hash_budget_usage_percent, transient_limited, transient_peak_bytes, duplicate_hashes, duplicate_owner_entries, shared_keys, derivation_drift, json_bytes, heap_bytes);
