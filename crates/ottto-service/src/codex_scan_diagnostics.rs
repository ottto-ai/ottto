//! Local-only bounded evidence. This never enters a status/upload DTO.
use crate::snapshots::SnapshotQuarantineDisposition;
use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) const MAX_LOCAL_DIAGNOSTIC_BYTES: usize = 32 * 1024;
pub(crate) const LINEAGE_SAMPLES: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoaderReason {
    #[default]
    Complete,
    Io,
    SqliteBusy,
    SqliteOpenOrQuery,
    SqliteRowDecode,
    IncompleteShape,
    OtherFailure,
}

// Typed context tags identify the operation without inspecting error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoaderStage {
    Open,
    Prepare,
    Query,
    Row,
}
impl std::fmt::Display for LoaderStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Prepare => "prepare",
            Self::Query => "query",
            Self::Row => "row",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct LoaderEvidence {
    pub completed_roots: u32,
    pub failed_roots: u32,
    pub reason: LoaderReason,
    pub mixed_failure_reasons: bool,
    pub identity_conflict: bool,
    pub first_failure_root_digest: Option<[u8; 32]>,
    pub first_failure_stage: Option<LoaderStage>,
    // Same first failure as the root and stage; later failures only aggregate.
    pub sqlite_extended_code: Option<i32>,
}
impl LoaderEvidence {
    pub fn observe_root(&mut self, result: &Result<()>, conflict: bool, root_key: &str) {
        if self.failed_roots == 0 && result.is_err() {
            self.first_failure_root_digest = Some(digest(root_key));
        }
        self.observe(result, conflict);
    }

    pub fn observe(&mut self, result: &Result<()>, conflict: bool) {
        self.identity_conflict |= conflict;
        let Err(error) = result else {
            self.completed_roots = self.completed_roots.saturating_add(1);
            return;
        };
        let reason = if error.downcast_ref::<std::io::Error>().is_some() {
            LoaderReason::Io
        } else if let Some(error) = error.downcast_ref::<rusqlite::Error>() {
            match error {
                rusqlite::Error::SqliteFailure(code, _)
                    if matches!(
                        code.code,
                        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                    ) =>
                {
                    LoaderReason::SqliteBusy
                }
                rusqlite::Error::InvalidColumnType(..)
                | rusqlite::Error::FromSqlConversionFailure(..)
                | rusqlite::Error::IntegralValueOutOfRange(..) => LoaderReason::SqliteRowDecode,
                _ => LoaderReason::SqliteOpenOrQuery,
            }
        } else if error.downcast_ref::<IncompleteShape>().is_some() {
            LoaderReason::IncompleteShape
        } else {
            LoaderReason::OtherFailure
        };
        self.mixed_failure_reasons |= self.failed_roots > 0 && self.reason != reason;
        // Keep the first bounded reason and disclose aggregation, never error text.
        if self.failed_roots == 0 {
            self.reason = reason;
            self.first_failure_stage = error.downcast_ref::<LoaderStage>().copied();
            self.sqlite_extended_code = error.downcast_ref::<rusqlite::Error>().and_then(|error| {
                if let rusqlite::Error::SqliteFailure(code, _) = error {
                    Some(code.extended_code)
                } else {
                    None
                }
            });
        }
        self.failed_roots = self.failed_roots.saturating_add(1);
    }
}

#[derive(Debug)]
pub(crate) struct IncompleteShape;
impl std::fmt::Display for IncompleteShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Codex sidecar census shape was incomplete")
    }
}
impl std::error::Error for IncompleteShape {}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct CensusGates {
    pub discovery_done: bool,
    pub traversal_healthy: bool,
    pub frozen_generation: bool,
    pub state_complete: bool,
    pub sidecar_complete: bool,
    pub reconciliation_complete: bool,
    pub parent_restart: bool,
    pub clean_followup: bool,
    pub census_complete: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileReason {
    #[default]
    NotParsedThisCycle,
    Complete,
    ParentPending,
    OwnershipIncomplete,
    RecognizedUsageDropped,
    ReadOrLineLoss,
}

// Fixed-width digests are domain separated. No raw keys, source ids, paths,
// arbitrary strings or credentials can be placed in this diagnostic schema.
pub(crate) fn digest(value: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ottto_local_codex_recovery:v1\0");
    hash.update(value.as_bytes());
    hash.finalize().into()
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct RecoveryLineage {
    pub fingerprint_digest: [u8; 32],
    pub file_key_digest: Option<[u8; 32]>,
    pub associated_file_count: u64,
    pub legacy_file_association: bool,
    pub file_reason: FileReason,
    pub parsed_count: u64,
    pub finalized: bool,
    pub finalized_entity_count: u64,
    pub successor_digests: [[u8; 32]; LINEAGE_SAMPLES],
    pub previous_body_digest: Option<[u8; 32]>,
    pub final_body_digest: Option<[u8; 32]>,
    pub final_body_revision: u64,
    pub before_current: bool,
    pub after_current: bool,
    pub before_disposition: SnapshotQuarantineDisposition,
    pub after_disposition: SnapshotQuarantineDisposition,
}
impl RecoveryLineage {
    pub fn new(fingerprint: &str, disposition: SnapshotQuarantineDisposition) -> Self {
        Self {
            fingerprint_digest: digest(fingerprint),
            file_key_digest: None,
            associated_file_count: 0,
            legacy_file_association: false,
            file_reason: FileReason::NotParsedThisCycle,
            parsed_count: 0,
            finalized: false,
            finalized_entity_count: 0,
            successor_digests: [[0; 32]; LINEAGE_SAMPLES],
            previous_body_digest: None,
            final_body_digest: None,
            final_body_revision: 0,
            before_current: false,
            after_current: false,
            before_disposition: disposition,
            after_disposition: disposition,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct CodexScanDiagnostics {
    pub version: u8,
    pub generation: u64,
    pub state_titles: LoaderEvidence,
    pub state_threads: LoaderEvidence,
    pub spawn_edges: LoaderEvidence,
    pub rollout_extents: LoaderEvidence,
    pub session_index: LoaderEvidence,
    pub gates: CensusGates,
    pub quarantine_count: u64,
    pub sample_offset: u64,
    pub lineage: [Option<RecoveryLineage>; LINEAGE_SAMPLES],
}

// Exhaustive inventory preserves optional scan overlap admission on #493's
// existing layout contract. Fixed arrays add no separately owned heap bytes.
crate::heap_layout_bound::fields!(CodexScanDiagnostics; version, generation, state_titles, state_threads, spawn_edges, rollout_extents, session_index, gates, quarantine_count, sample_offset, lineage);
crate::heap_layout_bound::fields!(LoaderEvidence; completed_roots, failed_roots, reason, mixed_failure_reasons, identity_conflict, first_failure_root_digest, first_failure_stage, sqlite_extended_code);
crate::heap_layout_bound::fields!(CensusGates; discovery_done, traversal_healthy, frozen_generation, state_complete, sidecar_complete, reconciliation_complete, parent_restart, clean_followup, census_complete);
crate::heap_layout_bound::fields!(RecoveryLineage; fingerprint_digest, file_key_digest, associated_file_count, legacy_file_association, file_reason, parsed_count, finalized, finalized_entity_count, successor_digests, previous_body_digest, final_body_digest, final_body_revision, before_current, after_current, before_disposition, after_disposition);
impl crate::heap_layout_bound::HeapLayoutBound for LoaderReason {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Complete
            | Self::Io
            | Self::SqliteBusy
            | Self::SqliteOpenOrQuery
            | Self::SqliteRowDecode
            | Self::IncompleteShape
            | Self::OtherFailure => c.add(0),
        }
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for LoaderStage {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Open | Self::Prepare | Self::Query | Self::Row => c.add(0),
        }
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for FileReason {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::NotParsedThisCycle
            | Self::Complete
            | Self::ParentPending
            | Self::OwnershipIncomplete
            | Self::RecognizedUsageDropped
            | Self::ReadOrLineLoss => c.add(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_root_stage_and_native_code_survive_later_failures_without_error_text() {
        let fault = |code, stage| {
            Err(anyhow::Error::new(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                Some("private credential error text".to_owned()),
            ))
            .context(stage)
            .context("private provider path"))
        };
        let mut evidence = LoaderEvidence::default();
        evidence.observe_root(&Ok(()), false, "successful root");
        evidence.observe_root(&fault(26, LoaderStage::Prepare), false, "failed root one");
        evidence.observe_root(&fault(10, LoaderStage::Row), false, "failed root two");
        assert_eq!(evidence.completed_roots, 1);
        assert_eq!(evidence.failed_roots, 2);
        assert_eq!(
            evidence.first_failure_root_digest,
            Some(digest("failed root one"))
        );
        assert_eq!(evidence.first_failure_stage, Some(LoaderStage::Prepare));
        assert_eq!(evidence.sqlite_extended_code, Some(26));
        let text = serde_json::to_string(&evidence).unwrap();
        for forbidden in ["private", "credential", "successful root", "failed root"] {
            assert!(!text.contains(forbidden));
        }
    }
    #[test]
    fn reason_classification_never_uses_error_text() {
        let mut evidence = LoaderEvidence::default();
        evidence.observe(
            &Err(anyhow::Error::new(IncompleteShape).context("secret path")),
            true,
        );
        assert_eq!(evidence.reason, LoaderReason::IncompleteShape);
        evidence.observe(
            &Err(anyhow::anyhow!("credential and arbitrary provider error")),
            false,
        );
        evidence.observe(&Ok(()), false);
        assert!(evidence.mixed_failure_reasons);
        assert!(evidence.identity_conflict);
        assert_eq!(evidence.failed_roots, 2);
        assert_eq!(evidence.completed_roots, 1);
        assert!(!serde_json::to_string(&evidence).unwrap().contains("secret"));
    }
    #[test]
    fn fully_populated_schema_stays_bounded_and_content_free() {
        let mut diagnostics = CodexScanDiagnostics {
            version: 1,
            generation: u64::MAX,
            quarantine_count: u64::MAX,
            sample_offset: u64::MAX,
            ..Default::default()
        };
        let evidence = LoaderEvidence {
            completed_roots: u32::MAX,
            failed_roots: u32::MAX,
            first_failure_root_digest: Some([255; 32]),
            first_failure_stage: Some(LoaderStage::Prepare),
            sqlite_extended_code: Some(i32::MAX),
            ..Default::default()
        };
        diagnostics.state_titles = evidence;
        diagnostics.state_threads = evidence;
        diagnostics.spawn_edges = evidence;
        diagnostics.rollout_extents = evidence;
        diagnostics.session_index = evidence;
        let mut lineage = RecoveryLineage::new(
            "raw session id /Users/private credential",
            SnapshotQuarantineDisposition::RetryPending,
        );
        lineage.file_key_digest = Some([255; 32]);
        lineage.successor_digests = [[255; 32]; LINEAGE_SAMPLES];
        lineage.previous_body_digest = Some([255; 32]);
        lineage.final_body_digest = Some([255; 32]);
        lineage.parsed_count = u64::MAX;
        lineage.finalized_entity_count = u64::MAX;
        lineage.associated_file_count = u64::MAX;
        lineage.final_body_revision = u64::MAX;
        diagnostics.lineage = [Some(lineage); LINEAGE_SAMPLES];
        let bytes = serde_json::to_vec_pretty(&diagnostics).unwrap();
        assert!(bytes.len() < MAX_LOCAL_DIAGNOSTIC_BYTES);
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in ["/Users", "credential", "raw session id"] {
            assert!(!text.contains(forbidden));
        }
    }
}
