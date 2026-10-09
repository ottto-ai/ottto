//! Local-only bounded evidence. This never enters a status/upload DTO.
use crate::snapshots::SnapshotQuarantineDisposition;
use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) const MAX_LOCAL_DIAGNOSTIC_BYTES: usize = 32 * 1024;
pub(crate) const LINEAGE_SAMPLES: usize = 4;
pub(crate) const MAX_FENCED_CENSUS_BYTES: usize = 8 * 1024;
pub(crate) const MAX_FENCED_CENSUS_ENTRIES: usize = 32_768;
const FENCED_CENSUS_FILE: &str = "codex-fenced-census-v1.json";

/// Fixed projection of already-owned index metadata. None means unavailable,
/// not zero/healthy. Never serialize the index or its keys/owner proofs here.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct CensusIndexAggregates {
    pub schema_version: u16,
    pub generation: u64,
    pub file_count: u64,
    pub traversal_present: bool,
    pub pending_directories: Option<u64>,
    pub pending_candidates: Option<u64>,
    pub directory_census_present: bool,
    pub directory_census_stable: Option<bool>,
    pub directory_count: Option<u64>,
    pub reconciliation_started: Option<bool>,
    pub watcher_hint_seen: Option<bool>,
    pub retry_attempt: Option<u8>,
    pub retry_not_before_unix_seconds: Option<u64>,
    pub protected_aggregation_complete: bool,
    pub protected_history: Option<u64>,
    pub protected_absent_from_observed_rollouts: Option<u64>,
    pub protected_absent_valid_owner: Option<u64>,
}

#[derive(Default, Serialize)]
struct CensusLossCounts {
    discovered: u64,
    ownership_incomplete: u64,
    unreadable: u64,
    disappeared: u64,
    recognized_usage_dropped: u64,
    dropped_usage: u64,
    over_line_cap: u64,
}

#[derive(Serialize)]
struct FencedCensusRecord<'a> {
    schema: &'static str,
    source: &'static str,
    producer_pid: u32,
    producer_version: &'a str,
    observed_at: &'a str,
    scope: &'static str,
    index_view: &'static str,
    scan_input_generation: u64,
    gates: CensusGates,
    losses: CensusLossCounts,
    index: CensusIndexAggregates,
}

fn fenced_census_path(support_dir: &std::path::Path) -> std::path::PathBuf {
    support_dir.join("snapshots").join(FENCED_CENSUS_FILE)
}

fn invalidate_fenced_census(support_dir: &std::path::Path) {
    // Best effort only: a retained old record must still fail the consumer's
    // process-start/freshness-floor checks. This is not an account pointer.
    let _ = std::fs::remove_file(fenced_census_path(support_dir));
}

/// Replace an existing fence site, not add another authority/credential read.
/// Propagate the original rejection unchanged; diagnostic failures never enter
/// the scan result. An unsuccessful observation cannot re-offer an old record.
pub(crate) fn after_existing_census_fence(
    source: crate::snapshots::SnapshotSource,
    support_dir: &std::path::Path,
    fence: impl FnOnce() -> Result<()>,
    publish: impl FnOnce() -> std::io::Result<()>,
) -> Result<()> {
    let result = fence();
    if source == crate::snapshots::SnapshotSource::Codex && (result.is_err() || publish().is_err())
    {
        invalidate_fenced_census(support_dir);
    }
    result
}

fn write_fenced_census_record(
    support_dir: &std::path::Path,
    record: &FencedCensusRecord<'_>,
) -> std::io::Result<()> {
    // Hard serialization/allocation ceiling, independent of any future fields.
    let mut buffer = [0_u8; MAX_FENCED_CENSUS_BYTES];
    let mut writer = std::io::Cursor::new(buffer.as_mut_slice());
    serde_json::to_writer(&mut writer, record).map_err(std::io::Error::other)?;
    let len = writer.position() as usize;
    ottto_core::write_owner_only_cache_file_atomic(&fenced_census_path(support_dir), &buffer[..len])
}

/// Called only by the successful existing-fence callback. Captures the working
/// view before delivery, never certifies a later checkpoint, account or ACK.
pub(crate) fn write_fenced_census(
    support_dir: &std::path::Path,
    scan: &crate::snapshots::SourceScanResult,
    index: &crate::snapshots::ScanIndex,
) -> std::io::Result<()> {
    let diagnostic = scan.local_codex_diagnostics.as_ref().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "scan diagnostic unavailable")
    })?;
    let version = crate::snapshots::collector_version();
    let observed_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(std::io::Error::other)?;
    let record = FencedCensusRecord {
        schema: "local_fenced_codex_census:v1",
        source: "codex",
        producer_pid: std::process::id(),
        producer_version: &version,
        observed_at: &observed_at,
        scope: "last_completed_scan_at_destination_fence",
        index_view: "working_before_delivery",
        scan_input_generation: diagnostic.generation,
        gates: diagnostic.gates,
        losses: CensusLossCounts {
            discovered: scan.discovered_file_count as u64,
            ownership_incomplete: scan.ownership_incomplete_file_count as u64,
            unreadable: scan.unreadable_path_count as u64,
            disappeared: scan.disappeared_file_count as u64,
            recognized_usage_dropped: scan.recognized_usage_drop_count as u64,
            dropped_usage: scan.dropped_usage_record_count,
            over_line_cap: scan.over_line_cap_count as u64,
        },
        index: index.local_codex_census_aggregates(),
    };
    write_fenced_census_record(support_dir, &record)
}

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

#[cfg(test)]
mod fenced_census_tests {
    use super::*;
    use crate::snapshots::SnapshotSource;
    use std::path::{Path, PathBuf};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "ottto-fenced-census-{}",
                ottto_core::generate_control_token().unwrap()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record() -> FencedCensusRecord<'static> {
        FencedCensusRecord {
            schema: "local_fenced_codex_census:v1",
            source: "codex",
            producer_pid: std::process::id(),
            producer_version: "0.1.test",
            observed_at: "2026-10-09T10:00:00Z",
            scope: "last_completed_scan_at_destination_fence",
            index_view: "working_before_delivery",
            scan_input_generation: 7,
            gates: CensusGates::default(),
            losses: CensusLossCounts::default(),
            index: CensusIndexAggregates {
                generation: 8,
                ..Default::default()
            },
        }
    }

    #[test]
    fn fenced_census_fence_order_once_and_original_errors_invalidate_stale_record() {
        let fixture = Fixture::new();
        let calls = std::cell::RefCell::new(Vec::new());
        after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || {
                calls.borrow_mut().push("fence");
                Ok(())
            },
            || {
                calls.borrow_mut().push("write");
                write_fenced_census_record(fixture.path(), &record())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), vec!["fence", "write"]);
        assert!(fenced_census_path(fixture.path()).is_file());
        calls.borrow_mut().clear();
        let result = after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || {
                calls.borrow_mut().push("rejected");
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic authority change",
                )
                .into())
            },
            || panic!("rejected fence must not invoke projection or writer"),
        );
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(*calls.borrow(), vec!["rejected"]);
        assert!(!fenced_census_path(fixture.path()).exists());
    }

    #[test]
    fn fenced_census_private_bounded_latest_record_and_distinct_generations() {
        let fixture = Fixture::new();
        for generation in [8, 9] {
            let mut observed = record();
            observed.index.generation = generation;
            write_fenced_census_record(fixture.path(), &observed).unwrap();
        }
        let path = fenced_census_path(fixture.path());
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() <= MAX_FENCED_CENSUS_BYTES);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["scan_input_generation"], 7);
        assert_eq!(value["index"]["generation"], 9);
        assert_eq!(value["index_view"], "working_before_delivery");
        assert!(value["index"]["protected_history"].is_null());
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        let text = String::from_utf8(bytes).unwrap();
        for excluded in [
            "namespace",
            "fingerprint",
            "digest",
            "session_id",
            "device_id",
            "account_id",
            "lineage",
            "path",
            "committed",
            "ack",
        ] {
            assert!(
                !text.contains(excluded),
                "private/unproven field {excluded}"
            );
        }
        let enormous = "x".repeat(MAX_FENCED_CENSUS_BYTES + 1);
        let mut oversized = record();
        oversized.producer_version = &enormous;
        after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || Ok(()),
            || write_fenced_census_record(fixture.path(), &oversized),
        )
        .unwrap();
        assert!(
            !path.exists(),
            "oversize observation must not leave stale record offered"
        );
    }

    #[test]
    fn fenced_census_non_codex_and_failed_writes_leave_scan_result_unchanged() {
        let fixture = Fixture::new();
        after_existing_census_fence(
            SnapshotSource::ClaudeCode,
            fixture.path(),
            || Ok(()),
            || panic!("other provider must not publish Codex diagnostics"),
        )
        .unwrap();
        std::fs::write(
            fixture.path().join("snapshots"),
            b"synthetic unavailable directory",
        )
        .unwrap();
        after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || Ok(()),
            || write_fenced_census_record(fixture.path(), &record()),
        )
        .unwrap();
    }

    #[test]
    fn fenced_census_consumer_freshness_contract_rejects_old_process_or_change() {
        // Synthetic consumer contract using the actual emitted record; no local
        // runtime reader or current-account claim is added by this diagnostic.
        let fixture = Fixture::new();
        write_fenced_census_record(fixture.path(), &record()).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fenced_census_path(fixture.path())).unwrap())
                .unwrap();
        let acceptable = |pid: u32, floor: &str| {
            let clock = time::OffsetDateTime::parse(
                value["observed_at"].as_str().unwrap(),
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap();
            let floor =
                time::OffsetDateTime::parse(floor, &time::format_description::well_known::Rfc3339)
                    .unwrap();
            value["producer_pid"] == pid && clock >= floor
        };
        assert!(acceptable(std::process::id(), "2026-10-09T09:00:00Z"));
        assert!(!acceptable(
            std::process::id().wrapping_add(1),
            "2026-10-09T09:00:00Z"
        ));
        assert!(!acceptable(std::process::id(), "2026-10-09T11:00:00Z"));
    }

    #[test]
    #[ignore = "bounded synthetic diagnostic IO measurement"]
    fn fenced_census_cache_write_native_measurement() {
        let fixture = Fixture::new();
        let started = std::time::Instant::now();
        for _ in 0..100 {
            write_fenced_census_record(fixture.path(), &record()).unwrap();
        }
        println!(
            "fenced_census_cache_write iterations=100 elapsed_us={} bytes={} fsync=false",
            started.elapsed().as_micros(),
            fenced_census_path(fixture.path()).metadata().unwrap().len()
        );
    }
}
