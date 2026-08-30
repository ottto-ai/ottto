use crate::adaptive_collector::{CadenceConfig, SourceCadence};
use crate::agent_status::{collect_agent_status_collection, AgentStatusCollection};
use crate::backfill::{
    apply_backfill_cutoff, current_historical_replay, load_backfill_state,
    mark_backfill_complete_for_destination, pending_backfill_sources_for_destination,
    save_backfill_state,
};
use crate::detected_uses::{
    aggregate_detected_uses, merge_detected_uses, DETECTED_USE_RETENTION_DAYS,
};
use crate::session_attribution::SessionAttributionContext;
use crate::snapshot_client::{
    load_snapshot_device_credentials, AgentStatusSnapshotUploadRequest,
    AgentStatusSnapshotUploadResponse, BatchAuthorizationRejected, BatchRejected,
    LocalHealthAuthorizationRejected, LocalHealthProjectionRejected,
    RelayTokenAuthorizationRejected, SnapshotApiClient, SnapshotStatusReportKind,
    SnapshotStatusRequest, UploadFailureDiagnostics, UploadShed, CENSUS_RESIDUE_ERROR_CODE,
    CENSUS_RESIDUE_STATUS_CONTRACT,
};
use crate::snapshots::{
    apply_upload_policy, collector_version, context_curve_derivation_revision,
    finalize_scan_after_policy, scan_source_roots_with_attribution_and_claude_effort_and_hints,
    snapshot_quarantine_deadline_is_bounded, snapshot_quarantine_witness,
    snapshot_upload_body_witness, validate_snapshot_batch_request, ScanIndex, SnapshotBatchRequest,
    SnapshotItem, SnapshotQuarantineDisposition, SnapshotQuarantineRecord,
    SnapshotQuarantineWitness, SnapshotSource, SnapshotSourceManifest, SnapshotUploadPolicy,
    SourceScanResult, CONTEXT_CURVE_CONTRACT_VERSION, MAX_BACKFILL_FILES_PER_SOURCE,
    MAX_SNAPSHOT_RECONSTRUCTION_FAILURES, SNAPSHOT_QUARANTINE_RETRY_SECONDS,
    SNAPSHOT_SCHEMA_VERSION, SNAPSHOT_STATUS_SCHEMA_VERSION,
};
use crate::LocalDaemon;
use crate::LocalHealthUploadFailureKind;
use anyhow::{anyhow, Context, Result};
use ottto_core::{default_support_dir, FileConnectionStore, FileMachineStore, LocalDeviceBinding};
use ottto_protocol::{AgentStatusSnapshot, DetectedUse, SourceKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroize;

// Direct API host; the apex `ottto.net/backend` proxy is retired in the marketing cutover.
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const SNAPSHOT_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);
// Non-terminal collector check-in cadence. The sync loop sleeps a fixed
// SNAPSHOT_SYNC_INTERVAL AFTER a cycle completes, so terminal status receipts
// alone age by cycle_duration + interval; a long cycle (first onboarding scan,
// a post-restart backlog drain) makes an alive collector read as stale
// server-side even while uploads are progressing. The backend's sources.status
// freshness promise is a check-in within five minutes — beat well inside it so
// receipt age stays bounded no matter how long a cycle runs.
const COLLECTOR_CHECKIN_INTERVAL: Duration = Duration::from_secs(2 * 60);
// The backend status/manifest contract accepts a negotiated semantic evidence
// window of at most 183 days. Historical replay may traverse a wider local
// corpus, but it must never widen this receipt contract: the manifest is
// recomputed from semantic activity inside the negotiated window.
const MAX_SNAPSHOT_STATUS_WINDOW_DAYS: u64 = 183;
const LOCAL_HEALTH_PROJECTION_INTERVAL: Duration = Duration::from_secs(60);
const AGENT_STATUS_SNAPSHOT_TTL_MINUTES: i64 = 15;
// Match the backend's accepted entity count while retaining a separate byte
// bound for pathological backfill batches. Normal incremental scans are
// usually a single small chunk; historical replay avoids count-only 50-item
// requests that could consume the backend's full wire budget.
const SNAPSHOT_BATCH_LIMIT: usize = 50;
// Leave half of the backend's 4 MiB uncompressed request cap for derived
// semantic envelopes and bounded request metadata. The exact request serializer
// is still checked immediately before network I/O by
// `validate_snapshot_batch_request`.
const SNAPSHOT_BATCH_MAX_BYTES: usize = 2 * 1024 * 1024;
// A 50-item page needs at most six binary splits to isolate one poison item.
// Cap there so broad schema drift cannot turn one five-minute cycle into dozens
// of doomed backend calls.
const SNAPSHOT_ADAPTIVE_SPLIT_LIMIT: usize = 6;
const SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT: usize = SNAPSHOT_BATCH_LIMIT + 4;
const SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE: usize = SNAPSHOT_BATCH_LIMIT;
// A pre-ledger checkpoint with ambiguous settlement is re-entered through the
// existing entity-ACK upload machine. Arm at most one normal 50-entity page per
// five-minute source cycle; the scan-index cursor and quarantine map resume the
// remaining identities across restarts.
const LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE: usize = SNAPSHOT_BATCH_LIMIT;
const SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION: u16 = 3;
static ONE_SHOT_SYNC_IN_FLIGHT: OnceLock<Mutex<bool>> = OnceLock::new();
static CLAUDE_REFRESH_ACTIVITY: OnceLock<Mutex<ClaudeRefreshActivity>> = OnceLock::new();

#[derive(Default)]
struct ClaudeRefreshActivity {
    running: bool,
    pending: bool,
}
static SNAPSHOT_SYNC_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Durable, privacy-minimal progress for one policy-scoped scan index.
///
/// The scanner cannot commit its final `ScanIndex` until every changed
/// snapshot is accepted: committing it earlier would silently drop the files
/// represented by a later failed batch. Persisting only the stable semantic
/// snapshot fingerprints lets a restart skip already-accepted pages without
/// retaining titles, paths, prompts, usage payloads, or session ids locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotUploadProgress {
    schema_version: u16,
    #[serde(default)]
    generation: u64,
    destination_namespace_hash: String,
    /// Full replay generation whose ACKs populate this ledger. A new reviewed
    /// replay must not inherit ACKs for identical entities from an older
    /// generation, while a restart of the same generation must still resume.
    #[serde(default)]
    historical_replay_generation: Option<String>,
    #[serde(default)]
    accepted_fingerprints: BTreeSet<String>,
    /// Exact local body witness accepted for each semantic entity. Schema v3
    /// prevents a crash-resume ledger for curve A from suppressing corrected
    /// curve B, while the backend continues to ACK the stable semantic
    /// fingerprint.
    #[serde(default)]
    accepted_body_witnesses: BTreeMap<String, String>,
    #[serde(default)]
    quarantined_fingerprints: BTreeMap<String, SnapshotQuarantineRecord>,
    #[serde(skip)]
    active_quarantine_witness: Option<SnapshotQuarantineWitness>,
    /// Runtime leases for quarantine entries selected this cycle. The durable
    /// record stays armed with its next future deadline until an exact ACK
    /// clears it; this set only bypasses suppression for the current request.
    #[serde(skip)]
    active_quarantine_retries: BTreeSet<String>,
}

impl SnapshotUploadProgress {
    fn new(
        destination_namespace_hash: String,
        active_quarantine_witness: SnapshotQuarantineWitness,
    ) -> Self {
        Self {
            schema_version: SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
            generation: 0,
            destination_namespace_hash,
            historical_replay_generation: None,
            accepted_fingerprints: BTreeSet::new(),
            accepted_body_witnesses: BTreeMap::new(),
            quarantined_fingerprints: BTreeMap::new(),
            active_quarantine_witness: Some(active_quarantine_witness),
            active_quarantine_retries: BTreeSet::new(),
        }
    }

    fn load(
        path: &Path,
        expected_destination_namespace_hash: &str,
        active_quarantine_witness: SnapshotQuarantineWitness,
    ) -> Result<Self> {
        let _lock = SnapshotProgressLock::acquire(path)?;
        if !path.exists() {
            return Ok(Self::new(
                expected_destination_namespace_hash.to_string(),
                active_quarantine_witness,
            ));
        }
        let parsed = std::fs::read(path)
            .context("read snapshot upload progress")
            .and_then(|bytes| {
                serde_json::from_slice::<Self>(&bytes)
                    .context("parse v3 local snapshot upload progress")
            });
        let mut progress = match parsed {
            Ok(progress)
                if progress.schema_version == SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
                    && progress.destination_namespace_hash
                        == expected_destination_namespace_hash
                    && is_snapshot_fingerprint(&progress.destination_namespace_hash)
                    && progress
                        .accepted_fingerprints
                        .iter()
                        .all(|value| is_snapshot_fingerprint(value))
                    && progress.accepted_body_witnesses.len()
                        == progress.accepted_fingerprints.len()
                    && progress.accepted_body_witnesses.keys().all(|value| {
                        is_snapshot_fingerprint(value)
                            && progress.accepted_fingerprints.contains(value)
                    })
                    && progress
                        .accepted_body_witnesses
                        .values()
                        .all(|value| is_snapshot_fingerprint(value))
                    && progress
                        .quarantined_fingerprints
                        .keys()
                        .all(|value| is_snapshot_fingerprint(value))
                    && progress.quarantined_fingerprints.values().all(|record| {
                        snapshot_quarantine_deadline_is_bounded(record)
                            && record
                                .upload_body_witness
                                .as_deref()
                                .map_or(true, is_snapshot_fingerprint)
                    }) =>
            {
                progress
            }
            Ok(_) | Err(_) => {
                quarantine_invalid_progress(path)?;
                return Ok(Self::new(
                    expected_destination_namespace_hash.to_string(),
                    active_quarantine_witness,
                ));
            }
        };
        progress.active_quarantine_witness = Some(active_quarantine_witness);
        progress.active_quarantine_retries.clear();
        Ok(progress)
    }

    fn prepare_quarantine_retries(
        &mut self,
        index_quarantine: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) -> bool {
        self.active_quarantine_retries.clear();
        // The upload ledger is saved immediately after an exact ACK, before
        // the index can retire its older quarantine. On crash/restart that ACK
        // is the stronger fact and must not be overwritten by restoring the
        // stale index-owned obligation.
        self.quarantined_fingerprints
            .retain(|fingerprint, _| !self.accepted_fingerprints.contains(fingerprint));
        for (fingerprint, record) in index_quarantine {
            if !self.accepted_fingerprints.contains(fingerprint) {
                self.quarantined_fingerprints
                    .entry(fingerprint.clone())
                    .or_insert_with(|| record.clone());
            }
        }
        let now = current_unix_seconds();
        let active = self
            .active_quarantine_witness
            .as_ref()
            .expect("upload progress always has an active quarantine witness");
        let retry = self
            .quarantined_fingerprints
            .iter()
            .filter(|(_, record)| {
                record.disposition == SnapshotQuarantineDisposition::RetryPending
                    && (&record.witness != active || record.retry_after_unix_seconds <= now)
            })
            .map(|(fingerprint, record)| {
                (
                    (&record.witness == active) as u8,
                    record.retry_after_unix_seconds,
                    fingerprint.clone(),
                )
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE)
            .map(|(_, _, fingerprint)| fingerprint)
            .collect::<BTreeSet<_>>();
        for fingerprint in &retry {
            let record = self
                .quarantined_fingerprints
                .get(fingerprint)
                .expect("selected quarantine retry exists")
                .clone();
            self.quarantined_fingerprints.insert(
                fingerprint.clone(),
                SnapshotQuarantineRecord {
                    witness: active.clone(),
                    retry_after_unix_seconds: quarantine_retry_after(fingerprint),
                    upload_body_witness: record.upload_body_witness,
                    failed_reconstruction_count: record.failed_reconstruction_count,
                    disposition: record.disposition,
                },
            );
        }
        self.active_quarantine_retries = retry;
        !self.active_quarantine_retries.is_empty()
    }

    /// Rearm every current entity exactly once for a new historical replay.
    ///
    /// The scan index independently clears its file checkpoints, but stable
    /// semantic fingerprints mean an older accepted/quarantined progress entry
    /// could otherwise suppress the re-derived upload. Keep same-generation
    /// progress intact so page ACKs and conflict retries remain resumable.
    fn prepare_historical_replay(&mut self, generation: &str) -> bool {
        if self.historical_replay_generation.as_deref() == Some(generation) {
            return false;
        }
        self.historical_replay_generation = Some(generation.to_string());
        self.accepted_fingerprints.clear();
        self.accepted_body_witnesses.clear();
        self.quarantined_fingerprints.clear();
        true
    }

    #[cfg(test)]
    fn contains(&self, fingerprint: &str) -> bool {
        !self.active_quarantine_retries.contains(fingerprint)
            && (self.accepted_fingerprints.contains(fingerprint)
                || self.quarantined_fingerprints.contains_key(fingerprint))
    }

    fn contains_body(&self, fingerprint: &str, body_witness: &str) -> bool {
        if self.active_quarantine_retries.contains(fingerprint) {
            return false;
        }
        self.accepted_body_witnesses
            .get(fingerprint)
            .is_some_and(|accepted| accepted == body_witness)
            || self
                .quarantined_fingerprints
                .get(fingerprint)
                .is_some_and(|record| record.upload_body_witness.as_deref() == Some(body_witness))
    }

    #[cfg(test)]
    fn record<'a>(&mut self, fingerprints: impl IntoIterator<Item = &'a str>) {
        for fingerprint in fingerprints {
            self.record_body(fingerprint, fingerprint);
        }
    }

    fn record_body(&mut self, fingerprint: &str, body_witness: &str) {
        self.accepted_fingerprints.insert(fingerprint.to_string());
        self.accepted_body_witnesses
            .insert(fingerprint.to_string(), body_witness.to_string());
        self.quarantined_fingerprints.remove(fingerprint);
        self.active_quarantine_retries.remove(fingerprint);
    }

    #[cfg(test)]
    fn quarantine<'a>(&mut self, fingerprints: impl IntoIterator<Item = &'a str>) {
        for fingerprint in fingerprints {
            self.quarantine_body(fingerprint, fingerprint);
        }
    }

    fn quarantine_body(&mut self, fingerprint: &str, body_witness: &str) {
        let witness = self
            .active_quarantine_witness
            .clone()
            .expect("upload progress always has an active quarantine witness");
        let failed_reconstruction_count = self
            .quarantined_fingerprints
            .get(fingerprint)
            .filter(|record| {
                record.witness == witness
                    && record.upload_body_witness.as_deref() == Some(body_witness)
            })
            .map(|record| record.failed_reconstruction_count.saturating_add(1))
            .unwrap_or(1)
            .min(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES);
        let disposition = if failed_reconstruction_count == MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
            SnapshotQuarantineDisposition::UnprovenTerminal
        } else {
            SnapshotQuarantineDisposition::RetryPending
        };
        self.quarantined_fingerprints.insert(
            fingerprint.to_string(),
            SnapshotQuarantineRecord {
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
        self.active_quarantine_retries.remove(fingerprint);
    }

    fn retain_current_quarantines(&mut self, current: &BTreeSet<String>) -> bool {
        let before = self.quarantined_fingerprints.clone();
        for (fingerprint, record) in &mut self.quarantined_fingerprints {
            if !current.contains(fingerprint)
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

    fn save(&mut self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create snapshot upload progress directory")?;
        }
        let _lock = SnapshotProgressLock::acquire(path)?;
        if path.exists() {
            let current: Self = serde_json::from_slice(
                &std::fs::read(path).context("read current snapshot upload progress")?,
            )
            .context("parse current snapshot upload progress for compare-and-swap")?;
            if current.schema_version != SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
                || current.generation != self.generation
                || current.destination_namespace_hash != self.destination_namespace_hash
            {
                return Err(anyhow!("snapshot upload progress changed concurrently"));
            }
        } else if self.generation != 0 {
            return Err(anyhow!("snapshot upload progress disappeared concurrently"));
        }
        let previous_generation = self.generation;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("snapshot upload progress generation overflow"))?;
        let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut file =
            std::fs::File::create(&temp_path).context("create snapshot upload progress temp")?;
        let result = (|| -> Result<()> {
            serde_json::to_writer_pretty(&mut file, &*self)
                .context("write snapshot upload progress temp")?;
            file.sync_all()
                .context("sync snapshot upload progress temp")?;
            std::fs::rename(&temp_path, path).context("replace snapshot upload progress")?;
            sync_progress_parent(path)
        })();
        if result.is_err() {
            self.generation = previous_generation;
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }

    fn clear(&self, path: &Path) -> Result<()> {
        let _lock = SnapshotProgressLock::acquire(path)?;
        let current = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Self>(&bytes)
                .context("parse snapshot upload progress before clear")?,
            Err(error) if error.kind() == ErrorKind::NotFound && self.generation == 0 => {
                return Ok(())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(anyhow!("snapshot upload progress disappeared concurrently"))
            }
            Err(error) => return Err(error).context("read snapshot upload progress before clear"),
        };
        if current.schema_version != SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            || current.generation != self.generation
            || current.destination_namespace_hash != self.destination_namespace_hash
        {
            return Err(anyhow!("snapshot upload progress changed concurrently"));
        }
        let tombstone = unique_progress_sibling(path, "cleared");
        std::fs::rename(path, &tombstone).context("atomically clear snapshot upload progress")?;
        sync_progress_parent(path)?;
        std::fs::remove_file(&tombstone).context("remove cleared snapshot upload progress")?;
        sync_progress_parent(path)
    }
}

struct SnapshotProgressLock {
    file: std::fs::File,
}

impl SnapshotProgressLock {
    fn acquire(path: &Path) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).context("create snapshot upload progress directory")?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .context("open snapshot upload progress lock")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("snapshot upload progress is owned by another daemon");
            }
        }
        Ok(Self { file })
    }
}

impl Drop for SnapshotProgressLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            use std::os::fd::AsRawFd;
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn unique_progress_sibling(path: &Path, kind: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_extension(format!("{kind}.{}.{nanos}.json", std::process::id()))
}

fn sync_progress_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync snapshot upload progress directory")
}

fn quarantine_invalid_progress(path: &Path) -> Result<()> {
    let quarantine_path = unique_progress_sibling(path, "corrupt");
    std::fs::rename(path, quarantine_path)
        .context("quarantine invalid local snapshot upload progress")?;
    sync_progress_parent(path)
}

fn is_snapshot_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn quarantine_retry_after(fingerprint: &str) -> u64 {
    let digest = Sha256::digest(fingerprint.as_bytes());
    let jitter = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"))
        % SNAPSHOT_QUARANTINE_RETRY_SECONDS;
    current_unix_seconds()
        .saturating_add(SNAPSHOT_QUARANTINE_RETRY_SECONDS)
        .saturating_add(jitter)
}

/// Last computed scan-index manifest per (upload destination, source).
///
/// The check-in heartbeat runs on its own clock and does not know which
/// policy/attribution/destination-scoped index path the sync cycle chose, so it
/// cannot load the index itself. The sync cycle publishes the manifest it
/// already computed from the index it already had open, and both receipt shapes
/// read it from here. Missing means "no scan has completed in this process yet
/// for this destination", which is reported as an absent manifest rather than a
/// zeroed one.
///
/// The destination is part of the key, not an afterthought: a setup or account
/// switch replaces the relay binding without restarting the daemon (which is why
/// `ensure_snapshot_destination_current` exists), and a manifest keyed by source
/// alone would report the previous account's entity count and rolling hash to the
/// new one — a wrong witness and a disclosure of the previous account's local
/// session set.
static SOURCE_MANIFESTS: OnceLock<Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>> =
    OnceLock::new();

type SourceManifestCache = Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>;

fn source_manifests() -> &'static SourceManifestCache {
    SOURCE_MANIFESTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn publish_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
    manifest: SnapshotSourceManifest,
) {
    // These mutations preserve BTreeMap invariants even if an unrelated
    // consumer panics while holding the process-global cache. Recover poison
    // so one caught panic cannot permanently suppress every future manifest.
    let mut manifests = source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // One destination at a time: a machine that has moved is never coming
    // back to the old binding with the same secret, so retaining its
    // manifests would only risk reporting them.
    manifests.retain(|(namespace, _), _| namespace == destination_namespace);
    manifests.insert(
        (destination_namespace.to_string(), source.api_slug()),
        manifest,
    );
}

fn withdraw_source_manifest(destination_namespace: &str, source: SnapshotSource) {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&(destination_namespace.to_string(), source.api_slug()));
}

#[allow(clippy::too_many_arguments)]
fn save_index_and_publish_manifest(
    index: &mut ScanIndex,
    index_path: &Path,
    destination_namespace: &str,
    source: SnapshotSource,
    census_complete: bool,
    window_start: &str,
    window_end: &str,
) -> Result<()> {
    // The server may already hold this pass's new entities. Keep the previous
    // process-cache witness withdrawn until the exact replacement index is
    // durable; a failed CAS/save or manifest derivation must not let a
    // concurrent heartbeat repeat stale agreement.
    withdraw_source_manifest(destination_namespace, source);
    index.save(index_path)?;
    if census_complete {
        publish_source_manifest(
            destination_namespace,
            source,
            index.manifest_for_window(source, window_start, window_end)?,
        );
    }
    Ok(())
}

fn cached_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
) -> Option<SnapshotSourceManifest> {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(destination_namespace.to_string(), source.api_slug()))
        .cloned()
}

#[cfg(test)]
fn clear_source_manifests_for_test() {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

/// Hard ceiling on how long a source may go unscanned on cadence grounds alone.
///
/// The cost tiers are allowed to stretch a quiet source out to here and no
/// further, and the 6-hour full sweep is unconditional on top of it: neither the
/// filesystem watcher nor a server directive can suppress a sweep, because a
/// watcher that silently stops delivering events would otherwise stop collection
/// with every health signal green.
const MAX_CYCLE_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How long the loop is willing to sit inside one wait before re-deciding.
/// Filesystem events shorten a wait to the next tier boundary; they never
/// shorten it below the floor, which is what makes a 2-second debounce incapable
/// of producing a per-event upload.
const CADENCE_WAIT_SLICE: Duration = Duration::from_secs(30);

/// Per-source adaptive cadence state.
static SOURCE_CADENCES: OnceLock<Mutex<BTreeMap<&'static str, SourceCadence>>> = OnceLock::new();

fn source_cadences() -> &'static Mutex<BTreeMap<&'static str, SourceCadence>> {
    SOURCE_CADENCES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn with_source_cadence<T>(
    source: SnapshotSource,
    apply: impl FnOnce(&mut SourceCadence) -> T,
) -> Option<T> {
    let mut cadences = source_cadences().lock().ok()?;
    let cadence = cadences
        .entry(source.api_slug())
        .or_insert_with(|| SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL)));
    Some(apply(cadence))
}

/// The negotiated wait for one source: `clamp(directive, floor, ceiling)`.
///
/// The tier arithmetic — including the server's requested minimum interval — lives
/// in [`SourceCadence`], anchored to the last scan. That anchoring is load-bearing:
/// a *relative* directive re-read on every cycle would push its own deadline
/// forward forever and the scan would never run again, silently, on a healthy
/// machine. All that remains here is the ceiling, which bounds a directive that
/// would otherwise silence a source for a day.
fn negotiated_wait(cadence: &SourceCadence, now: Instant) -> Duration {
    cadence
        .next_scan_after(now)
        .clamp(Duration::ZERO, MAX_CYCLE_INTERVAL)
}

/// Remaining wait for `source`, or `None` when it is due now.
fn source_cadence_wait(source: SnapshotSource) -> Option<Duration> {
    let now = Instant::now();
    let wait = with_source_cadence(source, |cadence| negotiated_wait(cadence, now))
        .unwrap_or(Duration::ZERO);
    (!wait.is_zero()).then_some(wait)
}

/// Fold the server's `recommended_scan_after` into the source's cadence as a
/// minimum interval between scans.
///
/// An unparsable value leaves the previous directive alone rather than inventing
/// one, and a value in the past means "no minimum", not a negative wait.
fn record_server_scan_directive(source: SnapshotSource, recommended_scan_after: &str) {
    let Ok(recommended) = OffsetDateTime::parse(recommended_scan_after, &Rfc3339) else {
        return;
    };
    let delay = recommended - OffsetDateTime::now_utc();
    let requested = if delay.is_negative() {
        Duration::ZERO
    } else {
        Duration::from_secs(delay.whole_seconds().unsigned_abs()).min(MAX_CYCLE_INTERVAL)
    };
    with_source_cadence(source, |cadence| {
        cadence.set_server_min_interval(Some(requested))
    });
}

#[cfg(test)]
fn clear_cadence_state_for_test() {
    if let Ok(mut cadences) = source_cadences().lock() {
        cadences.clear();
    }
}

/// Base of the local backoff ladder used when the server sheds without saying
/// for how long.
const SHED_BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Uniform random in `[0, span]`, from the OS entropy source already used for
/// token material. Jitter that is not random is not jitter.
fn uniform_duration(span: Duration) -> Duration {
    if span.is_zero() {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Entropy is not available. Half the span is a poor sample but a correct
        // wait; refusing to wait would be the actual bug.
        return span / 2;
    }
    let fraction = u64::from_le_bytes(bytes) as f64 / u64::MAX as f64;
    Duration::from_secs_f64(span.as_secs_f64() * fraction)
}

/// The wait after a shed request.
///
/// With a server-supplied `Retry-After`, wait `Retry-After × uniform(1.0, 1.2)`.
/// The jitter is one-sided on purpose: the whole fleet was told the same number,
/// so obeying it exactly re-synchronises every machine onto the same instant —
/// which is how a shed becomes a thundering herd — but jittering *below* it
/// returns before the server said it would be ready, which is the overload the
/// shed was protecting against. Never early, sometimes late.
///
/// Without a `Retry-After`, full jitter over an exponential ladder: `random(0,
/// min(cap, base·2^n))`, which is the form that actually decorrelates retries,
/// not the "exponential plus a little noise" form.
///
/// The result is capped like a parsed `Retry-After` is, so the upper jitter
/// cannot push a wait past the longest silence the freshness promise tolerates.
fn shed_backoff(retry_after: Option<Duration>) -> Duration {
    match retry_after {
        Some(retry_after) => (retry_after + uniform_duration(retry_after.mul_f64(0.2)))
            .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER),
        None => full_jitter_backoff(0),
    }
}

/// `random(0, min(cap, base·2^attempt))` — full jitter, capped.
fn full_jitter_backoff(attempt: u32) -> Duration {
    let ceiling = SHED_BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(6))
        .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER);
    uniform_duration(ceiling)
}

/// A deterministic per-machine offset inside `interval`.
///
/// Cycle phase is otherwise set by install or restart time, so any fleet-wide
/// event — a deploy, a shed, a network partition healing — re-aligns every
/// machine onto the same tick and keeps them aligned. The offset is derived from
/// the client id so it is stable across restarts (a random offset would
/// re-scatter on every launch, which is worse for the freshness promise than
/// being predictable).
fn cadence_phase_offset(client_id: &str, interval: Duration) -> Duration {
    let seconds = interval.as_secs();
    if seconds == 0 {
        return Duration::ZERO;
    }
    let mut digest = Sha256::new();
    digest.update(b"ottto.cadence.phase:v1");
    digest.update(client_id.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[..8]);
    Duration::from_secs(u64::from_be_bytes(bytes) % seconds)
}

/// Consecutive sheds per source, so the no-`Retry-After` ladder actually climbs.
///
/// Without it every shed draws from `random(0, 30s)`, which the five-minute cycle
/// has already outlived by the next tick — a ladder that never leaves its first
/// rung is not backoff, it is a rounding error on the normal cadence. Reset by any
/// completed upload.
static SOURCE_SHED_STREAKS: OnceLock<Mutex<BTreeMap<&'static str, u32>>> = OnceLock::new();

fn source_shed_streaks() -> &'static Mutex<BTreeMap<&'static str, u32>> {
    SOURCE_SHED_STREAKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Count this shed and return the wait to honour.
fn note_shed_and_backoff(source: SnapshotSource, retry_after: Option<Duration>) -> Duration {
    let attempt = match source_shed_streaks().lock() {
        Ok(mut streaks) => {
            let streak = streaks.entry(source.api_slug()).or_insert(0);
            let attempt = *streak;
            *streak = streak.saturating_add(1);
            attempt
        }
        Err(_) => 0,
    };
    match retry_after {
        // The server named a time. Its number wins over our ladder — it knows
        // when it will be ready and we do not.
        Some(retry_after) => shed_backoff(Some(retry_after)),
        None => full_jitter_backoff(attempt),
    }
}

fn clear_shed_streak(source: SnapshotSource) {
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.remove(source.api_slug());
    }
}

#[cfg(test)]
fn shed_streak_for_test(source: SnapshotSource) -> u32 {
    source_shed_streaks()
        .lock()
        .expect("shed streaks")
        .get(source.api_slug())
        .copied()
        .unwrap_or(0)
}

/// Per-source "do not upload before" deadlines, set by an honoured shed.
static SOURCE_UPLOAD_DEADLINES: OnceLock<Mutex<BTreeMap<&'static str, Instant>>> = OnceLock::new();

fn source_upload_deadlines() -> &'static Mutex<BTreeMap<&'static str, Instant>> {
    SOURCE_UPLOAD_DEADLINES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn defer_source_uploads(source: SnapshotSource, retry_after: Duration) {
    if let Ok(mut deadlines) = source_upload_deadlines().lock() {
        deadlines.insert(source.api_slug(), Instant::now() + retry_after);
    }
}

/// Remaining backoff for `source`, or `None` when it may upload now.
fn source_upload_backoff_remaining(source: SnapshotSource) -> Option<Duration> {
    let mut deadlines = source_upload_deadlines().lock().ok()?;
    let deadline = *deadlines.get(source.api_slug())?;
    let now = Instant::now();
    if deadline <= now {
        deadlines.remove(source.api_slug());
        return None;
    }
    Some(deadline - now)
}

#[cfg(test)]
fn clear_source_upload_deadlines_for_test() {
    if let Ok(mut deadlines) = source_upload_deadlines().lock() {
        deadlines.clear();
    }
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.clear();
    }
}

/// Entity fingerprints already counted as a client-report poison loss.
///
/// Legacy validation failures are re-attempted every cycle because they have no
/// durable per-entity settlement. Counting each attempt would make one broken
/// session look like an unbounded stream of losses — and if the source has no
/// valid sibling, no request ever succeeds, so nothing commits the report and
/// the number only grows. Entity-ACK rejections and local corruption are counted
/// through the same ledger after their quarantine checkpoint is durable.
///
/// Pruned to the current scan on every upload pass, exactly like the accepted
/// fingerprint ledger, so it stays O(current scan) rather than O(all history).
///
/// Keyed by upload scope (the source) because the prune is per scan: a Codex pass
/// must not prune Claude's ledger, or the next Claude cycle would count its
/// already-counted poison a second time.
static COUNTED_POISON_FINGERPRINTS: OnceLock<Mutex<BTreeMap<String, BTreeSet<String>>>> =
    OnceLock::new();

fn counted_poison_fingerprints() -> &'static Mutex<BTreeMap<String, BTreeSet<String>>> {
    COUNTED_POISON_FINGERPRINTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn retain_counted_poison_fingerprints(scope: &str, current: &BTreeSet<String>) {
    if let Ok(mut counted) = counted_poison_fingerprints().lock() {
        if let Some(ledger) = counted.get_mut(scope) {
            ledger.retain(|value| current.contains(value));
            if ledger.is_empty() {
                counted.remove(scope);
            }
        }
    }
}

/// Record one poison loss for `fingerprint`, at most once per entity per scope.
fn record_poison_loss_once(scope: &str, fingerprint: &str) {
    let first_time = match counted_poison_fingerprints().lock() {
        Ok(mut counted) => counted
            .entry(scope.to_string())
            .or_default()
            .insert(fingerprint.to_string()),
        // A poisoned lock must not silently stop the accounting; over-reporting
        // a loss is recoverable, losing the signal is not.
        Err(_) => true,
    };
    if first_time {
        crate::client_report::record(crate::client_report::ClientReportReason::Poisoned, 1);
    }
}

#[cfg(test)]
fn counted_poison_fingerprints_for_test(scope: &str) -> BTreeSet<String> {
    counted_poison_fingerprints()
        .lock()
        .expect("poison ledger")
        .get(scope)
        .cloned()
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Default)]
struct SyncCounts {
    backfill_window_days: u64,
    backfill_file_limit: u64,
    discovered_file_count: u64,
    skipped_file_count_due_to_limit: u64,
    scan_cap_hit: bool,
    scanned_file_count: u64,
    scanned_session_count: u64,
    semantic_noop_count: u64,
    census_complete: bool,
    symlink_rejected_count: u64,
    unreadable_path_count: u64,
    oversized_file_count: u64,
    disappeared_file_count: u64,
    malformed_json_line_count: u64,
    invalid_utf8_line_count: u64,
    over_line_cap_count: u64,
    recognized_usage_drop_count: u64,
    ownership_incomplete_file_count: u64,
    snapshot_unproven_terminal_count: u64,
    snapshot_superseded_terminal_count: u64,
    zero_snapshot_confirmed_count: u64,
    zero_snapshot_usage_evidence_count: u64,
    dropped_usage_record_count: u64,
    /// The scan's settled share of each public loss counter above; see
    /// `SourceScanResult`. `terminal <= public` in every class.
    terminal_ownership_incomplete_file_count: u64,
    terminal_zero_snapshot_usage_evidence_count: u64,
    terminal_recognized_usage_drop_count: u64,
    terminal_dropped_usage_record_count: u64,
    terminal_over_line_cap_count: u64,
    /// Residue witness cardinalities, counts only.
    census_residue_index_key_count: u64,
    census_residue_archived_rollout_count: u64,
    census_residue_blocked_session_count: u64,
    uploaded_count: u64,
}

/// How the loss a completed cycle discloses reads on its terminal receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisclosedLoss {
    /// No ownership-incomplete file, no usage evidence without an entity, no
    /// dropped usage record.
    None,
    /// The census completed, no retryable problem remains, and every loss
    /// class equals its terminal counterpart: the receipt can prove, class by
    /// class, that all the loss it discloses is loss no retry can change.
    Terminal,
    /// Loss the daemon has not proved non-progressing: an incomplete census,
    /// a retryable problem beside the residue, or a class it has not settled.
    Unsettled,
}

impl SyncCounts {
    /// Loss a later traversal can still change. Mirrors
    /// `ScanTraversalCounts::has_retryable_problems` on the receipt's own
    /// counters so the receipt can never claim a settled residue the scan did
    /// not: a walk that could not enter, open, read, or parse something may
    /// simply not have seen the file that would resolve a fork.
    fn has_retryable_problems(&self) -> bool {
        self.symlink_rejected_count > 0
            || self.unreadable_path_count > 0
            || self.oversized_file_count > 0
            || self.disappeared_file_count > 0
            || self.malformed_json_line_count > 0
            || self.invalid_utf8_line_count > 0
            || self.over_line_cap_count > self.terminal_over_line_cap_count
    }

    /// The loss classes that have always turned a successful cycle's receipt
    /// into a `parse_error`. Unchanged, so the legacy shape is byte-identical.
    fn has_disclosed_loss(&self) -> bool {
        self.ownership_incomplete_file_count > 0
            || self.zero_snapshot_usage_evidence_count > 0
            || self.dropped_usage_record_count > 0
    }

    fn disclosed_loss(&self) -> DisclosedLoss {
        if !self.has_disclosed_loss() {
            return DisclosedLoss::None;
        }
        let every_class_terminal = self.ownership_incomplete_file_count
            == self.terminal_ownership_incomplete_file_count
            && self.zero_snapshot_usage_evidence_count
                == self.terminal_zero_snapshot_usage_evidence_count
            && self.recognized_usage_drop_count == self.terminal_recognized_usage_drop_count
            && self.dropped_usage_record_count == self.terminal_dropped_usage_record_count
            && self.over_line_cap_count == self.terminal_over_line_cap_count;
        if self.census_complete && !self.has_retryable_problems() && every_class_terminal {
            DisclosedLoss::Terminal
        } else {
            DisclosedLoss::Unsettled
        }
    }

    fn for_policy(backfill_window_days: u64) -> Self {
        Self {
            backfill_window_days,
            backfill_file_limit: MAX_BACKFILL_FILES_PER_SOURCE as u64,
            ..Self::default()
        }
    }

    fn from_scan_result(
        scan_result: &SourceScanResult,
        uploaded_count: u64,
        receipt_window_days: u64,
    ) -> Self {
        Self {
            // Scan coverage and receipt evidence are deliberately different
            // during replay. The counters below describe the wider traversal;
            // this field and the manifest describe only the server-negotiated
            // semantic activity window.
            backfill_window_days: receipt_window_days,
            backfill_file_limit: scan_result.backfill_file_limit as u64,
            discovered_file_count: scan_result.discovered_file_count as u64,
            skipped_file_count_due_to_limit: scan_result.skipped_file_count_due_to_limit as u64,
            scan_cap_hit: scan_result.scan_cap_hit,
            scanned_file_count: scan_result.scanned_file_count as u64,
            scanned_session_count: scan_result.scanned_session_count as u64,
            semantic_noop_count: scan_result.semantic_noop_count as u64,
            census_complete: scan_result.census_complete,
            symlink_rejected_count: scan_result.symlink_rejected_count as u64,
            unreadable_path_count: scan_result.unreadable_path_count as u64,
            oversized_file_count: scan_result.oversized_file_count as u64,
            disappeared_file_count: scan_result.disappeared_file_count as u64,
            malformed_json_line_count: scan_result.malformed_json_line_count as u64,
            invalid_utf8_line_count: scan_result.invalid_utf8_line_count as u64,
            over_line_cap_count: scan_result.over_line_cap_count as u64,
            recognized_usage_drop_count: scan_result.recognized_usage_drop_count as u64,
            ownership_incomplete_file_count: scan_result.ownership_incomplete_file_count as u64,
            snapshot_unproven_terminal_count: 0,
            snapshot_superseded_terminal_count: 0,
            zero_snapshot_confirmed_count: scan_result.zero_snapshot_confirmed_count as u64,
            zero_snapshot_usage_evidence_count: scan_result.zero_snapshot_usage_evidence_count
                as u64,
            dropped_usage_record_count: scan_result.dropped_usage_record_count,
            terminal_ownership_incomplete_file_count: scan_result
                .terminal_ownership_incomplete_file_count
                as u64,
            terminal_zero_snapshot_usage_evidence_count: scan_result
                .terminal_zero_snapshot_usage_evidence_count
                as u64,
            terminal_recognized_usage_drop_count: scan_result.terminal_recognized_usage_drop_count
                as u64,
            terminal_dropped_usage_record_count: scan_result.terminal_dropped_usage_record_count,
            terminal_over_line_cap_count: scan_result.terminal_over_line_cap_count as u64,
            census_residue_index_key_count: scan_result.census_residue_index_key_count as u64,
            census_residue_archived_rollout_count: scan_result.census_residue_archived_rollout_count
                as u64,
            census_residue_blocked_session_count: scan_result.census_residue_blocked_session_count
                as u64,
            uploaded_count,
        }
    }

    fn with_snapshot_terminal_counts(mut self, index: &ScanIndex) -> Self {
        self.snapshot_unproven_terminal_count = index.snapshot_unproven_terminal_count() as u64;
        self.snapshot_superseded_terminal_count = index.snapshot_superseded_terminal_count() as u64;
        // Mirror #389's disclosed-loss convention: terminal unproven entities
        // also contribute to the established incomplete-evidence health scalar.
        self.ownership_incomplete_file_count = self
            .ownership_incomplete_file_count
            .saturating_add(self.snapshot_unproven_terminal_count);
        // They are terminal by disposition (the bounded reconstruction ladder
        // is exhausted), so the settled share grows by exactly the same
        // number: the ownership-incomplete class stays matched, and the
        // receipt keeps `terminal <= public`.
        self.terminal_ownership_incomplete_file_count = self
            .terminal_ownership_incomplete_file_count
            .saturating_add(self.snapshot_unproven_terminal_count);
        self
    }
}

fn validated_receipt_window_days(negotiated_window_days: u64) -> Result<u64> {
    if negotiated_window_days > MAX_SNAPSHOT_STATUS_WINDOW_DAYS {
        return Err(anyhow!(
            "snapshot status evidence window is outside the supported 0..={MAX_SNAPSHOT_STATUS_WINDOW_DAYS} day range"
        ));
    }
    Ok(negotiated_window_days)
}

fn scan_request_window_days(
    receipt_window_days: u64,
    backfill_pending: bool,
    curve_replay_pending: bool,
) -> u64 {
    if backfill_pending || curve_replay_pending {
        // The scanner applies its own local safety ceiling. `u64::MAX` means
        // "walk the complete replay range", not "claim this width upstream".
        u64::MAX
    } else {
        receipt_window_days
    }
}

fn snapshot_manifest_window(
    census_window_end: &str,
    receipt_window_days: u64,
) -> Result<(String, String)> {
    let receipt_window_days = validated_receipt_window_days(receipt_window_days)?;
    if receipt_window_days == 0 {
        return Err(anyhow!(
            "zero-width snapshot status evidence must be manifest-free"
        ));
    }
    let window_end = OffsetDateTime::parse(census_window_end, &Rfc3339)
        .context("parse snapshot manifest window end")?;
    let window_start = window_end
        .checked_sub(TimeDuration::days(receipt_window_days as i64))
        .ok_or_else(|| anyhow!("snapshot manifest window overflow"))?;
    Ok((
        window_start
            .format(&Rfc3339)
            .context("format snapshot manifest window start")?,
        window_end
            .format(&Rfc3339)
            .context("format snapshot manifest window end")?,
    ))
}

fn snapshot_manifest_window_days(manifest: &SnapshotSourceManifest) -> Result<u64> {
    let window_start = OffsetDateTime::parse(&manifest.window_start, &Rfc3339)
        .context("parse cached snapshot manifest window start")?;
    let window_end = OffsetDateTime::parse(&manifest.window_end, &Rfc3339)
        .context("parse cached snapshot manifest window end")?;
    let window_seconds = (window_end - window_start).whole_seconds();
    let day_seconds = 24 * 60 * 60;
    if window_seconds <= 0 || window_seconds % day_seconds != 0 {
        return Err(anyhow!(
            "cached snapshot manifest window is not a positive whole-day interval"
        ));
    }
    let window_days = u64::try_from(window_seconds / day_seconds)
        .context("convert cached snapshot manifest window days")?;
    validated_receipt_window_days(window_days)
}

#[derive(Debug)]
enum CollectorState<'a> {
    Success,
    /// A server-authoritative zero-width policy withdraws the prior census
    /// without claiming either a successful scan or a collector failure.
    PolicyTombstone,
    Disabled(Option<String>),
    Error {
        code: &'a str,
        message: &'a str,
    },
}

#[derive(Debug)]
struct CollectorStatus<'a> {
    source: SnapshotSource,
    machine_id: &'a str,
    scan_started_at: &'a str,
    counts: SyncCounts,
    state: CollectorState<'a>,
}

#[derive(Clone, Copy)]
enum TerminalManifestSource<'a> {
    Withdraw,
    CompleteCensus(&'a ScanIndex),
}

pub fn spawn_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    let phase_offset = local_cadence_phase_offset(SNAPSHOT_SYNC_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-snapshot-sync".to_string())
        .spawn(move || {
            // Spread the fleet's cycle phase deterministically before the first
            // cycle. Otherwise phase is set by install or restart time, and every
            // fleet-wide event re-aligns every machine onto the same tick.
            std::thread::sleep(phase_offset);
            // Best effort, and deliberately so: the loop below is driven by the
            // cadence tiers and the unconditional sweep, and the watcher only ever
            // shortens a wait. A machine that cannot watch its transcripts (no
            // permission, exhausted descriptors, a root that does not exist yet)
            // collects on exactly the schedule it does today.
            let watcher = watch_snapshot_source_roots(&home);
            if watcher.is_none() {
                eprintln!(
                    "local snapshot sync: filesystem watch unavailable; cadence follows the scan tiers only"
                );
            }
            loop {
                match sync_once(&home, &support_dir, &daemon) {
                    Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                    Err(error) => {
                        eprintln!("local snapshot sync skipped: {}", safe_error(&error));
                        crate::net_resilience::handle_sync_failure(&daemon);
                    }
                }
                // The cycle cadence itself is unchanged. What the tiers gate is the
                // expensive part — the local transcript scan and its upload — while
                // agent-status/quota freshness keeps the cycle it already had.
                collect_file_activity_for(SNAPSHOT_SYNC_INTERVAL, watcher.as_ref());
            }
        })
        .context("spawn local snapshot sync")?;
    Ok(())
}

/// Watch every enabled source's transcript roots, if the platform allows it.
fn watch_snapshot_source_roots(home: &Path) -> Option<crate::snapshot_watcher::SnapshotWatcher> {
    let roots = [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .flat_map(|source| {
        source
            .default_roots(home)
            .into_iter()
            .map(move |root| (source, root))
    })
    .collect::<Vec<_>>();
    crate::snapshot_watcher::watch_snapshot_roots(roots).ok()
}

/// Sleep for `wait`, folding any filesystem activity into the cadence tiers.
///
/// This is where the watcher earns its place, and it is deliberately the only
/// thing it does: an event **promotes a tier**, it never triggers a scan. A
/// promoted source becomes due at its floor on a later tick, so a transcript being
/// written continuously cannot produce an upload per event — and a machine whose
/// watcher never fires still collects on the tiers and the ceiling.
fn collect_file_activity_for(
    wait: Duration,
    watcher: Option<&crate::snapshot_watcher::SnapshotWatcher>,
) {
    let Some(watcher) = watcher else {
        std::thread::sleep(wait);
        return;
    };
    let deadline = Instant::now() + wait;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let slice = (deadline - now).min(CADENCE_WAIT_SLICE);
        match watcher.events.recv_timeout(slice) {
            Ok(event) => {
                with_source_cadence(event.source, |cadence| {
                    cadence.record_file_event(Instant::now())
                });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            // The watcher thread is gone. Keep waiting plainly rather than
            // spinning: collection is not gated on the watcher.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                return;
            }
        }
    }
}

/// This machine's cadence phase offset inside `interval`.
///
/// Derived from the durable machine id when there is one. A machine that has not
/// been claimed yet has no stable id, and inventing a random one would re-scatter
/// the phase on every launch — so an unclaimed machine simply starts on time.
fn local_cadence_phase_offset(interval: Duration) -> Duration {
    match FileMachineStore::default().load() {
        Ok(Some(machine)) if !machine.machine_id.is_empty() => {
            cadence_phase_offset(&machine.machine_id, interval)
        }
        _ => Duration::ZERO,
    }
}

pub fn spawn_local_health_projection_sync(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-local-health-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = upload_local_health_projection_now(&daemon) {
                if !local_health_upload_can_wait_quietly(&error) {
                    eprintln!(
                        "local health projection upload skipped: {}",
                        safe_error(&error)
                    );
                }
            }
            std::thread::sleep(LOCAL_HEALTH_PROJECTION_INTERVAL);
        })
        .context("spawn local health projection sync")?;
    Ok(())
}

/// A freshly restarted daemon seeds registered sources as `verifying` (see
/// [`LocalDaemon::with_registered_device_sources`]) so a connected account never
/// momentarily shows zero sources while the first agent scan is pending. Nothing
/// else proactively runs that scan, so without this burst the seeded rows can
/// dwell in `verifying` for tens of seconds until a client polls with refresh or
/// the next session emits telemetry — a transient that can read as "not working"
/// to a customer right after a daemon restart. Reconfirm them shortly after
/// boot, retrying a few times so a cold CLI that is not yet ready on the first
/// pass still settles quickly. Honest by construction: this runs the same
/// agent-status scan a GUI/CLI refresh runs and only promotes `Available`
/// sources (see `LocalDaemon::reconfirm_verifying_sources_for_trusted_client`),
/// so it never reports `healthy` before the scan actually finds the source ready.
const STARTUP_REVERIFY_SCHEDULE: &[Duration] = &[
    Duration::from_secs(2),
    Duration::from_secs(6),
    Duration::from_secs(15),
];

pub fn spawn_startup_source_reverify(daemon: LocalDaemon) {
    let spawn_result = std::thread::Builder::new()
        .name("ottto-startup-reverify".to_string())
        .spawn(move || {
            for delay in STARTUP_REVERIFY_SCHEDULE {
                std::thread::sleep(*delay);
                let captured_at = current_rfc3339();
                let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
                    .unwrap_or_else(|| captured_at.clone());
                match daemon.reconfirm_verifying_sources_for_trusted_client(captured_at, expires_at)
                {
                    // All seeded rows reconfirmed (or none seeded / not
                    // connected) — nothing left to do.
                    Ok(0) => break,
                    // Some sources were not `Available` yet (cold CLI); retry on
                    // the next, longer tick once they have had time to warm up.
                    Ok(_) => continue,
                    Err(error) => {
                        eprintln!("startup source re-verify skipped: {error}");
                        break;
                    }
                }
            }
        });
    if let Err(error) = spawn_result {
        eprintln!("startup source re-verify unavailable: {error}");
    }
}

/// Startup/wake Claude freshness uses the normal collection and upload path.
/// This avoids a refresh-only worker winning the durable claim and leaving a
/// concurrent collector with no post-refresh reading to upload.
pub fn spawn_claude_agent_status_refresh(opportunity: &'static str) {
    let Some(refresh_claim) = claim_claude_refresh_slot() else {
        return;
    };
    let spawn = std::thread::Builder::new()
        .name(format!("ottto-claude-refresh-{opportunity}"))
        .spawn(move || {
            let mut refresh_claim = refresh_claim;
            loop {
                // Serialize with the cadence/full-sync path as well as other
                // startup/wake hooks. This bounds worker count and prevents a
                // hook collection from racing the same local indexes/uploads.
                {
                    let _sync_guard = SNAPSHOT_SYNC_LOCK
                        .get_or_init(|| Mutex::new(()))
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let captured_at = current_rfc3339();
                    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
                        .unwrap_or_else(|| captured_at.clone());
                    let collection = collect_agent_status_collection(
                        &SourceKind::ClaudeCode,
                        captured_at,
                        expires_at,
                    );
                    if let Err(error) = upload_agent_status_snapshots(&collection.snapshots) {
                        eprintln!(
                            "Claude agent-status {opportunity} refresh skipped: {}",
                            safe_error(&error)
                        );
                    }
                }
                if !refresh_claim.take_pending_or_finish() {
                    break;
                }
            }
        });
    if let Err(error) = spawn {
        eprintln!("Claude agent-status {opportunity} refresh unavailable: {error}");
    }
}

struct ClaudeRefreshClaim {
    active: bool,
}

impl ClaudeRefreshClaim {
    fn take_pending_or_finish(&mut self) -> bool {
        let lock =
            CLAUDE_REFRESH_ACTIVITY.get_or_init(|| Mutex::new(ClaudeRefreshActivity::default()));
        let mut activity = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if activity.pending {
            activity.pending = false;
            true
        } else {
            activity.running = false;
            self.active = false;
            false
        }
    }
}

impl Drop for ClaudeRefreshClaim {
    fn drop(&mut self) {
        if self.active {
            reset_claude_refresh_activity();
        }
    }
}

fn claim_claude_refresh_slot() -> Option<ClaudeRefreshClaim> {
    let lock = CLAUDE_REFRESH_ACTIVITY.get_or_init(|| Mutex::new(ClaudeRefreshActivity::default()));
    let mut activity = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if activity.running {
        activity.pending = true;
        None
    } else {
        activity.running = true;
        Some(ClaudeRefreshClaim { active: true })
    }
}

fn reset_claude_refresh_activity() {
    let lock = CLAUDE_REFRESH_ACTIVITY.get_or_init(|| Mutex::new(ClaudeRefreshActivity::default()));
    *lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = ClaudeRefreshActivity::default();
}

/// Cadence for the blocking-verification retry loop below: how often it checks
/// for sources stuck in a failed verification, and the exponential backoff for
/// actual re-verify attempts. Each attempt runs a real smoke session (a small
/// LLM call), so a fixed short interval would burn provider quota exactly when
/// the machine is quota-starved; exponential backoff recovers transient
/// failures (network blip, brief provider outage) within minutes while capping
/// steady-state cost at one smoke per source per half hour until it heals.
const FAILED_VERIFY_POLL_INTERVAL: Duration = Duration::from_secs(60);
const FAILED_VERIFY_RETRY_INITIAL: Duration = Duration::from_secs(2 * 60);
const FAILED_VERIFY_RETRY_MAX: Duration = Duration::from_secs(30 * 60);

/// Exponential backoff for background re-verify attempts: 2m, 4m, 8m, 16m,
/// then capped at 30m for as long as the source stays failed. The counter
/// resets whenever the source leaves the failed state (a successful retry,
/// a manual Verify, or a fresh sign-in).
fn reverify_backoff_delay(completed_attempts: u32) -> Duration {
    let factor = 1u32.checked_shl(completed_attempts).unwrap_or(u32::MAX);
    FAILED_VERIFY_RETRY_INITIAL
        .saturating_mul(factor)
        .min(FAILED_VERIFY_RETRY_MAX)
}

struct ReverifySchedule {
    source: SourceKind,
    completed_attempts: u32,
    next_attempt_at: std::time::Instant,
}

/// A blocking verification failure (`Failed` + `TelemetryNotVerified`) is
/// sticky by design: data refreshes only re-pin it and nothing re-runs the
/// smoke, so before this loop existed a transient failure sat on "needs
/// attention / Critical" until the customer pressed Verify by hand — even
/// though pressing Verify immediately healed it. Retry those sources
/// automatically with exponential backoff so the state converges on its own;
/// the companion app already self-heals once the daemon reports healthy.
pub fn spawn_failed_verification_reverify(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-failed-verify-retry".to_string())
        .spawn(move || {
            let mut schedules: Vec<ReverifySchedule> = Vec::new();
            loop {
                std::thread::sleep(FAILED_VERIFY_POLL_INTERVAL);
                let failed = match daemon.sources_with_blocking_verification_failure() {
                    Ok(failed) => failed,
                    Err(_) => continue,
                };
                // A source that healed (retry success, manual Verify, sign-in)
                // drops its schedule so a future failure restarts the backoff
                // from the initial delay.
                schedules.retain(|schedule| failed.contains(&schedule.source));
                for source in failed {
                    let now = std::time::Instant::now();
                    let Some(schedule) = schedules
                        .iter_mut()
                        .find(|schedule| schedule.source == source)
                    else {
                        schedules.push(ReverifySchedule {
                            source,
                            completed_attempts: 0,
                            next_attempt_at: now + reverify_backoff_delay(0),
                        });
                        continue;
                    };
                    if now < schedule.next_attempt_at {
                        continue;
                    }
                    match crate::control::reverify_failed_source(&daemon, source.clone()) {
                        Ok(result) => eprintln!(
                            "background re-verify for {} finished: {}",
                            crate::source_slug(&source),
                            result.message.code
                        ),
                        Err(error) => eprintln!(
                            "background re-verify for {} skipped: {error}",
                            crate::source_slug(&source)
                        ),
                    }
                    schedule.completed_attempts = schedule.completed_attempts.saturating_add(1);
                    schedule.next_attempt_at = std::time::Instant::now()
                        + reverify_backoff_delay(schedule.completed_attempts);
                }
            }
        })
        .context("spawn failed-verification re-verify loop")?;
    Ok(())
}

pub fn spawn_one_shot_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    if !claim_one_shot_sync_slot() {
        return Ok(());
    }
    let spawn_result = std::thread::Builder::new()
        .name("ottto-snapshot-sync-now".to_string())
        .spawn(move || {
            match sync_once(&home, &support_dir, &daemon) {
                Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                Err(error) => {
                    eprintln!(
                        "local snapshot sync after setup skipped: {}",
                        safe_error(&error)
                    );
                    crate::net_resilience::handle_sync_failure(&daemon);
                }
            }
            set_one_shot_sync_in_flight(false);
        });
    if let Err(error) = spawn_result {
        set_one_shot_sync_in_flight(false);
        return Err(error).context("spawn immediate local snapshot sync");
    }
    Ok(())
}

fn claim_one_shot_sync_slot() -> bool {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    match lock.lock() {
        Ok(mut in_flight) => {
            if *in_flight {
                false
            } else {
                *in_flight = true;
                true
            }
        }
        Err(_) => true,
    }
}

fn set_one_shot_sync_in_flight(value: bool) {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    if let Ok(mut in_flight) = lock.lock() {
        *in_flight = value;
    }
}

fn sync_once(home: &Path, support_dir: &Path, daemon: &LocalDaemon) -> Result<()> {
    // The periodic loop and setup/UI one-shot path can otherwise scan and save
    // the same per-source index concurrently. Serialize the full cycle so a
    // one-shot rescan cannot race the background loop or publish an older
    // incremental index after it.
    let _sync_guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url);
    let enabled_sources = enabled_snapshot_sources(&device);

    if let Some(source) = enabled_sources.first().copied() {
        if let Err(error) = upload_local_health_projection_reporting(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            daemon,
        ) {
            eprintln!(
                "local health projection upload skipped: {}",
                safe_error(&error)
            );
        }
    }

    // Cycle-start scan receipts: one cheap non-terminal status per enabled
    // source before any scanning. Sources late in the sequential cycle would
    // otherwise hold receipts from the PREVIOUS cycle for this whole cycle, and
    // a backlog drain (e.g. after a daemon restart) stretches that well past
    // the backend's five-minute freshness promise even though uploads are
    // healthy. Best-effort: a failed receipt must never block the actual sync.
    let cycle_started_at = current_rfc3339();
    for source in enabled_sources.iter().copied() {
        if let Err(error) = report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            Some(&cycle_started_at),
        ) {
            eprintln!(
                "local snapshot cycle-start receipt skipped for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
        }
    }

    // Transport-layer outage evidence is folded here, in the per-source loop,
    // because this is the last point where each failure still carries the
    // typed `UploadFailureDiagnostics` (the aggregate error below collapses
    // to a count). One folded verdict per cycle feeds the streak.
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    let mut failed_sources = Vec::new();
    for source in enabled_sources {
        match sync_source(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            home,
            support_dir,
            daemon,
            &mut transport_cycle,
        ) {
            Ok(()) => transport_cycle.note_success(),
            Err(error) => {
                transport_cycle.note_error(&error);
                eprintln!(
                    "local snapshot sync skipped for {}: {}",
                    source.api_slug(),
                    safe_error(&error)
                );
                failed_sources.push(source.api_slug());
            }
        }
    }
    crate::net_resilience::note_sync_cycle_transport(transport_cycle);
    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "local snapshot sync failed for {} source(s)",
            failed_sources.len()
        ));
    }
    Ok(())
}

pub fn upload_local_health_projection_now(daemon: &LocalDaemon) -> Result<()> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let Some(source) = enabled_snapshot_sources(&device).first().copied() else {
        return Err(anyhow!("registered device has no enabled sources"));
    };
    let client = SnapshotApiClient::new(snapshot_api_base_url());
    upload_local_health_projection_reporting(
        &client,
        &device,
        &device_secret,
        source,
        &machine_id,
        daemon,
    )
}

fn upload_local_health_projection_reporting(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Result<()> {
    match upload_local_health_projection_with(
        client,
        device,
        device_secret,
        source,
        machine_id,
        daemon,
    ) {
        Ok(()) => {
            let _ = daemon.record_local_health_upload_succeeded();
            Ok(())
        }
        Err(error) if local_health_upload_should_refresh_setup_run(&error) => {
            if let Err(refresh_error) =
                crate::control::refresh_setup_run_token_for_persisted_connection()
            {
                // Terminal refresh failure indicating the bound account was
                // deleted server-side: transition the binding to the
                // unbound-equivalent `account_not_found` state so the next
                // sign-in (by any user) is a fresh first claim instead of a
                // reset-required dead end.
                if crate::control::backend_error_indicates_account_gone(&refresh_error) {
                    let _ = daemon.mark_account_not_found();
                }
                let _ = daemon
                    .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected);
                return Err(error.context(format!(
                    "refresh setup-run credentials after relay auth rejection failed: {refresh_error}"
                )));
            }
            match upload_local_health_projection_with(
                client,
                device,
                device_secret,
                source,
                machine_id,
                daemon,
            ) {
                Ok(()) => {
                    let _ = daemon.record_local_health_upload_succeeded();
                    Ok(())
                }
                Err(retry_error) => {
                    let _ = daemon.record_local_health_upload_failed(
                        local_health_upload_failure_kind(&retry_error),
                    );
                    Err(retry_error)
                }
            }
        }
        Err(error) => {
            let _ =
                daemon.record_local_health_upload_failed(local_health_upload_failure_kind(&error));
            Err(error)
        }
    }
}

fn local_health_upload_should_refresh_setup_run(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<RelayTokenAuthorizationRejected>()
        .is_some()
        || error
            .downcast_ref::<LocalHealthAuthorizationRejected>()
            .is_some()
}

fn local_health_upload_failure_kind(error: &anyhow::Error) -> LocalHealthUploadFailureKind {
    if error
        .downcast_ref::<LocalHealthProjectionRejected>()
        .is_some()
    {
        LocalHealthUploadFailureKind::ContractRejected
    } else if local_health_upload_should_refresh_setup_run(error) {
        LocalHealthUploadFailureKind::AuthRejected
    } else {
        LocalHealthUploadFailureKind::BackendUnreachable
    }
}

fn local_health_upload_can_wait_quietly(error: &anyhow::Error) -> bool {
    let safe = safe_error(error);
    matches!(
        safe.as_str(),
        "relay device credentials are unavailable" | "machine identity is unavailable"
    ) || error
        .to_string()
        .contains("registered device has no enabled sources")
}

fn upload_local_health_projection_with(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let mut status = daemon
        .status_for_trusted_client()
        .map_err(|error| anyhow!("read local health status failed: {error}"))?;
    crate::refresh_canonical_local_health(&mut status);
    if status.machine.machine_id != machine_id {
        return Err(anyhow!(
            "local health machine identity does not match registered device"
        ));
    }
    let heartbeat = status
        .runtime_heartbeat
        .as_ref()
        .ok_or_else(|| anyhow!("runtime heartbeat projection is missing"))?;
    let health = status
        .canonical_health
        .as_ref()
        .ok_or_else(|| anyhow!("canonical local health projection is missing"))?;

    client.upload_local_health_heartbeat(&relay_token, heartbeat)?;
    client.upload_local_health_projection(&relay_token, health)?;
    Ok(())
}

pub fn upload_agent_status_snapshots(snapshots: &[AgentStatusSnapshot]) -> Result<usize> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let client = SnapshotApiClient::new(snapshot_api_base_url());

    let mut uploaded = 0;
    let mut failed_sources = Vec::new();
    // This standalone path runs on the shared agents too, so its transport
    // evidence feeds the same outage streak (folded per invocation): a
    // persistent agent-status-only transport failure must not stay invisible
    // to the recovery ladder just because snapshot sync was quiet.
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    for source in enabled_snapshot_sources(&device) {
        let source_kind = source_kind(source);
        let source_snapshots = snapshots
            .iter()
            .filter(|snapshot| snapshot.source == source_kind)
            .cloned()
            .map(AgentStatusSnapshot::redacted_for_backend)
            .collect::<Vec<_>>();
        if source_snapshots.is_empty() {
            continue;
        }
        let relay_token = match client.issue_relay_token(&device, &device_secret, source) {
            Ok(token) => token,
            Err(error) => {
                transport_cycle.note_error(&error);
                failed_sources.push(source.api_slug());
                continue;
            }
        };
        let request = AgentStatusSnapshotUploadRequest {
            machine_id: machine_id.clone(),
            snapshots: source_snapshots,
        };
        match client.upload_agent_status(&relay_token, &request) {
            Ok(response) => {
                uploaded += response.accepted as usize;
                persist_machine_icon(&response);
                transport_cycle.note_success();
                crate::net_resilience::note_upstream_upload_succeeded("agent_status");
            }
            Err(error) => {
                transport_cycle.note_error(&error);
                failed_sources.push(source.api_slug());
            }
        }
    }
    crate::net_resilience::note_sync_cycle_transport(transport_cycle);

    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "agent status upload failed for {} source(s)",
            failed_sources.len()
        ));
    }

    Ok(uploaded)
}

/// Best-effort: cache the AI-generated machine icon URL the backend echoes on the
/// agent-status sync response, so the status command can surface it on
/// `status.machine.icon_url`. Never fails sync on a write error.
fn persist_machine_icon(response: &AgentStatusSnapshotUploadResponse) {
    let payload = serde_json::json!({
        "machine_id": response.machine_id,
        "icon_url": response.machine_icon_url,
        "icon_version": response.machine_icon_version,
    });
    if let Ok(serialized) = serde_json::to_string(&payload) {
        let _ = std::fs::write(default_support_dir().join("machine_icon.json"), serialized);
    }
}

// Extra parameters (the daemon handle for caching the reconciliation policy,
// and the cycle's transport-evidence fold) push this over clippy's 7-arg
// threshold; the alternative is a throwaway context struct for an internal
// helper, which is not worth it.
#[allow(clippy::too_many_arguments)]
fn sync_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    transport_cycle: &mut crate::net_resilience::TransportCycleOutcome,
) -> Result<()> {
    if let Some(remaining) = source_upload_backoff_remaining(source) {
        // The server asked for room and we said yes. Re-running the cycle now
        // would scan, re-derive and re-POST the same pages it just shed, which is
        // precisely the loop the backoff exists to break. No status receipt: the
        // last one still describes reality, and the check-in heartbeat keeps
        // freshness alive on its own clock.
        eprintln!(
            "local snapshot sync deferred for {}: backend backoff has {}s remaining",
            source.api_slug(),
            remaining.as_secs()
        );
        return Ok(());
    }
    let scan_started_at = current_rfc3339();
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let mut activity_hint = client.get_activity_hint(&relay_token)?;
    // Treat the activity hint as the only authority for the semantic evidence
    // window. Missing/malformed hints already fail JSON decoding; future
    // out-of-contract widths fail here before any scan or receipt can
    // manufacture a fallback policy. Zero is an explicit tombstone control.
    let receipt_window_days = validated_receipt_window_days(activity_hint.backfill_window_days)?;
    let context_curve_enabled = source != SnapshotSource::Pi
        && activity_hint.session_context_curve_contract.as_deref()
            == Some(CONTEXT_CURVE_CONTRACT_VERSION);
    // The server's scan directive was parsed and discarded before this. It is a
    // cost lever, so it may only lengthen the local cadence (see
    // `negotiated_wait`), never shorten it.
    record_server_scan_directive(source, &activity_hint.recommended_scan_after);
    with_source_cadence(source, |cadence| {
        cadence.record_backend_hint(
            Instant::now(),
            activity_hint.record_count_15m,
            false,
            activity_hint.local_usage_reconciliation_enabled,
        )
    });
    // Cache the workspace reconciliation policy so the daemon can surface it on
    // SourceHealth.reconciliation_enabled. Best-effort: a poisoned lock is the
    // only error path and is not worth aborting the sync over.
    let _ = daemon.record_reconciliation_enabled(
        source_kind(source),
        activity_hint.local_usage_reconciliation_enabled,
    );
    if receipt_window_days == 0 {
        let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
        withdraw_source_manifest(&destination_namespace, source);
        let _ = crate::active_sessions::reconcile_active_sessions(
            support_dir,
            source,
            &[],
            None,
            &scan_started_at,
        );
        report_status_with_fresh_relay_token(
            client,
            device,
            device_secret,
            support_dir,
            source,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: &scan_started_at,
                counts: SyncCounts::for_policy(0),
                state: CollectorState::PolicyTombstone,
            },
        )?;
        return Ok(());
    }
    let agent_status_captured_at = current_rfc3339();
    let agent_status_expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| agent_status_captured_at.clone());
    let scan_agent_status_collection = collect_agent_status_collection(
        &source_kind(source),
        agent_status_captured_at,
        agent_status_expires_at,
    );
    let scan_agent_status = reconciliation_agent_status(&scan_agent_status_collection);
    if let Err(error) = upload_agent_status(
        client,
        &relay_token,
        machine_id,
        &scan_agent_status_collection.snapshots,
    ) {
        // Best-effort for the sync itself, but not for outage tracking: a
        // persistent transport-only failure here must still feed the streak
        // instead of being swallowed with the log line.
        transport_cycle.note_error(&error);
        eprintln!(
            "local agent status upload skipped for {}: {}",
            source.api_slug(),
            safe_error(&error)
        );
    }

    // The configured-MCP context-footprint harvest runs on its own slower
    // schedule (run-at-start + every 6 h, `spawn_mcp_inventory_sync`), NOT on the
    // 5-minute snapshot sync: each harvest spawns every configured MCP server's
    // stdio process, so doing it every cycle would be needlessly intrusive and
    // re-POST unchanged inventories 12×/hour. See `crate::mcp_inventory`.

    if !activity_hint.local_usage_reconciliation_enabled {
        withdraw_source_manifest(
            &snapshot_upload_destination_namespace(device, device_secret),
            source,
        );
        let _ = crate::active_sessions::reconcile_active_sessions(
            support_dir,
            source,
            &[],
            Some(scan_agent_status),
            &scan_started_at,
        );
        report_status_with_fresh_relay_token(
            client,
            device,
            device_secret,
            support_dir,
            source,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: &scan_started_at,
                counts: SyncCounts::for_policy(receipt_window_days),
                state: CollectorState::Disabled(Some("disabled_by_admin".to_string())),
            },
        )?;
        return Ok(());
    }

    // Everything above this line keeps the cycle it already had: quota and
    // agent-status freshness, the reconciliation policy cache, and the
    // active-session projection are all cheap and all product-visible. The
    // negotiated cadence gates what is actually expensive — the local transcript
    // scan below, which re-reads every changed transcript on this machine.
    if let Some(remaining) = source_cadence_wait(source) {
        eprintln!(
            "local snapshot scan deferred for {}: next scan in {}s on the negotiated cadence",
            source.api_slug(),
            remaining.as_secs()
        );
        return Ok(());
    }

    let roots = source.default_roots(home);
    let mut encoded_attribution_key = activity_hint.session_attribution_hmac_key.take();
    let attribution_context = SessionAttributionContext::from_activity_hint(
        source,
        home,
        activity_hint.session_attribution_enabled,
        encoded_attribution_key.as_deref(),
        activity_hint
            .session_attribution_hmac_key_version
            .as_deref(),
    );
    if let Some(encoded_key) = encoded_attribution_key.as_mut() {
        encoded_key.zeroize();
    }
    let upload_policy = SnapshotUploadPolicy {
        session_titles_enabled: activity_hint.session_titles_enabled,
        workspace_labels_enabled: activity_hint.workspace_labels_enabled,
        session_artifacts_enabled: activity_hint.session_artifacts_enabled,
        session_attribution_enabled: activity_hint.session_attribution_enabled,
        session_attribution_labels_enabled: activity_hint.session_attribution_enabled
            && activity_hint.session_titles_enabled
            && activity_hint.session_attribution_labels_enabled,
    };
    let upload_destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    let checkpoint_namespace = attribution_context
        .as_ref()
        .map(SessionAttributionContext::checkpoint_namespace);
    let legacy_policy_index_path = legacy_policy_scoped_snapshot_index_path(
        support_dir,
        source,
        upload_policy,
        checkpoint_namespace.as_deref(),
    );
    let v1_index_path = snapshot_destination_scoped_index_path(
        &legacy_policy_index_path,
        &upload_destination_namespace,
    );
    // Adopt both the scan checkpoint and any in-flight accepted-page ledger
    // from the exact pre-v2 namespace. This keeps a normal upgrade—and an
    // upgrade after a partially acknowledged batch—from replaying history.
    if let Some(legacy_namespace) = attribution_context
        .as_ref()
        .map(SessionAttributionContext::legacy_cache_namespace)
    {
        let legacy_policy_index_path = legacy_policy_scoped_snapshot_index_path(
            support_dir,
            source,
            upload_policy,
            Some(&legacy_namespace),
        );
        let legacy_index_path = snapshot_destination_scoped_index_path(
            &legacy_policy_index_path,
            &upload_destination_namespace,
        );
        adopt_legacy_checkpoint_file(&legacy_index_path, &v1_index_path)?;
    }
    // State schema, resumable cursor, and CAS generation are v2-only. Keep the
    // old daemon's path immutable so an overlapping downgrade cannot clobber
    // a new daemon's proof or progress. Adopt the v1 scan checkpoint once, but
    // never adopt v1 upload progress: it lacks entity-grain ACK/quarantine.
    let v2_index_path = snapshot_v2_index_path(&v1_index_path);
    adopt_legacy_checkpoint_file(&v1_index_path, &v2_index_path)?;
    let destination_index_path = snapshot_destination_scoped_index_path(
        &snapshot_index_path(support_dir, source),
        &upload_destination_namespace,
    );
    let index_path = snapshot_v3_index_path(&destination_index_path);
    adopt_legacy_checkpoint_file(&v2_index_path, &index_path)?;
    let legacy_upload_progress_path = snapshot_upload_progress_path(&v2_index_path);
    let upload_progress_path = snapshot_upload_progress_path(&index_path);
    adopt_legacy_checkpoint_file(&legacy_upload_progress_path, &upload_progress_path)?;
    let mut upload_progress = SnapshotUploadProgress::load(
        &upload_progress_path,
        &upload_destination_namespace,
        snapshot_quarantine_witness(source),
    )?;
    let mut index = ScanIndex::load(&index_path)?;
    index.activate_upload_context(snapshot_upload_context_fingerprint(
        upload_policy,
        checkpoint_namespace.as_deref(),
    ));
    if !context_curve_enabled {
        // Stamp the off transition before taking the partial-commit baseline.
        // If an ordinary no-curve upload is partially accepted and then shed,
        // `committable_subset` must persist the new epoch so an immediate
        // re-enable replays every file changed during that off cycle.
        index.mark_context_curve_capability_disabled();
    }
    let backfill_state = load_backfill_state(support_dir);
    let backfill_pending =
        pending_backfill_sources_for_destination(&backfill_state, &upload_destination_namespace)
            .contains(&source);
    let replay = current_historical_replay(source);
    let replay_generation = if context_curve_enabled {
        let curve_derivation_revision = context_curve_derivation_revision(source)
            .expect("curve capability is supported only for local Codex and Claude sources");
        format!(
            "{}:{}:{}:{}:{}:{}",
            source.api_slug(),
            replay.revision,
            CONTEXT_CURVE_CONTRACT_VERSION,
            curve_derivation_revision,
            index.context_curve_replay_epoch(),
            upload_destination_namespace
        )
    } else {
        format!(
            "{}:{}:{}",
            source.api_slug(),
            replay.revision,
            upload_destination_namespace
        )
    };
    let curve_replay_pending =
        context_curve_enabled && index.context_curve_replay_needed(&replay_generation);
    let historical_replay_pending = backfill_pending || curve_replay_pending;
    let mut legacy_reconciliation_pending = BTreeSet::new();
    if !historical_replay_pending && index.legacy_settlement_ledger_needs_migration() {
        let (armed, changed) = index.prepare_legacy_settlement_reconciliation(
            source,
            LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE,
        );
        legacy_reconciliation_pending =
            index.legacy_settlement_reconciliation_pending_fingerprints();
        if changed {
            // The bounded cursor and armed identities are durable before the
            // disposable upload ledger can lease this cycle's retry page.
            index.save(&index_path)?;
            if !armed.is_empty() {
                eprintln!(
                    "ottto-service: re-armed {} ambiguous legacy snapshot revision(s) through the existing entity-ACK contract for {}; remaining revisions resume on later source cycles",
                    armed.len(),
                    source.api_slug()
                );
            }
        }
    }
    if prepare_upload_progress_for_cycle(
        &mut upload_progress,
        &index,
        &replay_generation,
        historical_replay_pending,
    ) {
        // Claim the new generation before the potentially long historical
        // scan. This prevents ACKs from the prior revision from suppressing
        // identical entities and gives overlapping writers a CAS boundary.
        upload_progress.save(&upload_progress_path)?;
    }
    let active_legacy_reconciliation = upload_progress
        .active_quarantine_retries
        .intersection(&legacy_reconciliation_pending)
        .cloned()
        .collect::<BTreeSet<_>>();
    if historical_replay_pending {
        index.prepare_historical_replay(replay_generation.clone());
    }
    // The committed state, before the scan advances it. A partial commit needs
    // both: which entries this scan produced, and which ones the server was
    // already known to hold.
    let committed_index = index.clone();
    let watcher_hints = crate::snapshot_watcher::take_pending_snapshot_paths(source);
    if watcher_hints.overflowed {
        eprintln!(
            "local snapshot watcher hint queue overflowed for {}; durable traversal will reconcile",
            source.api_slug()
        );
    }
    let mut scan_result = match scan_source_roots_with_attribution_and_claude_effort_and_hints(
        source,
        &roots,
        &mut index,
        &scan_started_at,
        scan_request_window_days(receipt_window_days, backfill_pending, curve_replay_pending),
        upload_policy.session_artifacts_enabled,
        attribution_context.as_ref(),
        (source == SnapshotSource::ClaudeCode).then_some(support_dir),
        context_curve_enabled,
        &watcher_hints.paths,
        watcher_hints.overflowed,
    ) {
        Ok(scan_result) => scan_result,
        Err(error) => {
            withdraw_source_manifest(&upload_destination_namespace, source);
            let _ = report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: &scan_started_at,
                    counts: SyncCounts::for_policy(receipt_window_days),
                    state: CollectorState::Error {
                        code: "scan_error",
                        message: "local snapshot scan failed",
                    },
                },
            );
            return Err(error.context("scan local snapshots"));
        }
    };
    // State advances only after the exact paged replay census and its upload
    // both finish. Incomplete pages persist their cursor in the destination
    // index and remain pending across restarts.
    let mut backfill_succeeded = backfill_pending && scan_result.census_complete;
    if backfill_pending && !backfill_succeeded {
        eprintln!(
            "local snapshot backfill remains pending for {}: census incomplete",
            source.api_slug(),
        );
    }

    // Backfill snapshots are appended after the live scan, so run the same
    // content-free effort enrichment over the combined set. Already-split live
    // buckets are naturally skipped because they now have multiple effort rows.
    // This must precede upload-policy stripping: parent/root references are
    // identity evidence needed locally even when the org disables attribution
    // labels on the wire.
    let mut claude_authority_disposition =
        crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    if source == SnapshotSource::ClaudeCode {
        let census_complete = scan_result.census_complete;
        let mut session_ids = claude_evidence_session_ids(&scan_result.snapshots)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if census_complete {
            session_ids.extend(crate::snapshots::claude_pending_family_session_ids(&index));
        }
        if let Ok(evidence) =
            crate::claude_local_otel::load_claude_effort_evidence(support_dir, session_ids)
        {
            let census_window_end = scan_result.census_window_end.clone();
            crate::snapshots::apply_claude_effort_evidence_with_index(
                &mut scan_result.snapshots,
                &evidence,
                &mut index,
                census_complete,
                &census_window_end,
            );
        }
        let usage_roots = claude_evidence_root_session_ids(&scan_result.snapshots)
            .into_iter()
            .chain(crate::snapshots::claude_pending_family_session_ids(&index))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|session_id| {
                !crate::claude_local_otel::claude_effort_sidecar_fingerprint(
                    support_dir,
                    session_id,
                )
                .is_empty()
                    && !crate::claude_local_otel::claude_trace_ownership_sidecar_fingerprint(
                        support_dir,
                        session_id,
                    )
                    .is_empty()
            })
            .collect::<Vec<_>>();
        // Health is family-scoped: one malformed historical sidecar must make
        // that family unproven, not suppress an unrelated healthy family.
        let mut api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
        let mut trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
        for root_session_id in usage_roots {
            let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
                support_dir,
                [root_session_id.clone()],
            );
            let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
                support_dir,
                [root_session_id.clone()],
            );
            if !api.health.is_complete() || !trace.is_complete() {
                continue;
            }
            if let Some(rows) = api.evidence.get(&root_session_id) {
                api_report
                    .evidence
                    .insert(root_session_id.clone(), rows.clone());
            }
            if let Some(rows) = trace.evidence.get(&root_session_id) {
                trace_report.evidence.insert(root_session_id, rows.clone());
            }
        }
        let census_window_end = scan_result.census_window_end.clone();
        claude_authority_disposition = crate::snapshots::apply_claude_reported_usage_with_index(
            &mut scan_result.snapshots,
            &api_report,
            &trace_report,
            &mut index,
            census_complete,
            &census_window_end,
        );
        if index.account_claude_usage_authority_census_health(&mut scan_result) {
            // These revisions were fully readable, but uploading them would
            // demote a previously proven usage authority. They remain pending
            // local work: healthy siblings may settle, while this census and
            // any historical replay stay non-terminal until a complete family
            // pass reconstructs the exact witness. Exhausted families are not
            // pending here: the helper accounts each held entity through the
            // backend-admitted ownership-incomplete status counter while
            // allowing a complete-with-named-loss census.
            scan_result.census_complete = false;
            scan_result.scan_cap_hit = true;
            index.mark_bounded_sweep_unsettled();
            backfill_succeeded = false;
        }
    }

    apply_upload_policy(source, &mut scan_result.snapshots, upload_policy);

    // Account-switch backfill cutoff (server-issued at claim completion): a
    // machine claimed by a different same-org user must not re-attribute the
    // previous owner's already-ingested history. Applies to everything headed
    // upstream this cycle — sessions whose activity ended strictly before the
    // cutoff are historical by definition, whichever scan produced them; live
    // sessions always have activity at/after the cutoff and pass untouched.
    let skipped_before_cutoff = apply_backfill_cutoff(&mut scan_result.snapshots, &backfill_state);
    if skipped_before_cutoff > 0 {
        eprintln!(
            "ottto-service: skipped {} historical {} snapshot(s) that ended before the account-switch backfill cutoff",
            skipped_before_cutoff,
            source.api_slug(),
        );
    }
    finalize_scan_after_policy(source, &mut scan_result, &mut index);
    // A parsed file can emit several legacy siblings. Only the persisted
    // migration lease may re-enter an ambiguous old identity this cycle; new
    // fingerprints and ordinary changed entities continue through normally.
    scan_result.snapshots.retain(|snapshot| {
        !legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint)
            || active_legacy_reconciliation.contains(&snapshot.snapshot_fingerprint)
    });
    // A long-lived poison item can keep upload progress around while unrelated
    // files continue changing. Drop quarantine revisions no longer represented
    // by the authoritative current index before any early upload error can
    // preserve them forever.
    if upload_progress.retain_current_quarantines(&index.current_snapshot_fingerprints()) {
        upload_progress.save(&upload_progress_path)?;
    }
    if crate::active_sessions::reconcile_active_sessions(
        support_dir,
        source,
        &scan_result.snapshots,
        Some(scan_agent_status),
        &scan_started_at,
    )
    .is_err()
    {
        eprintln!(
            "local active-session cache update skipped for {}",
            source.api_slug()
        );
    }
    if !scan_result.census_complete {
        // A stale prior manifest must not survive a lossy census. The healthy
        // siblings may still upload, but no source-wide agreement witness is
        // publishable until every discovered path was read completely.
        withdraw_source_manifest(&upload_destination_namespace, source);
    }
    let (manifest_window_start, manifest_window_end) =
        snapshot_manifest_window(&scan_result.census_window_end, receipt_window_days)?;
    // A bounded traversal may span process restarts. Its manifest is scoped to
    // the first tick's pinned census boundary, so every post-scan terminal
    // receipt must identify that same logical scan start rather than the later
    // resume attempt. This gives the backend an exact, restart-stable binding:
    // manifest.window_end == last_scan_started_at.
    let terminal_scan_started_at = manifest_window_end.as_str();

    // Persist the Companion-facing posture projection as soon as an
    // activity-hint-authorized local scan is complete and account-switch
    // filtering has been applied. This deliberately stays behind the master
    // `local_usage_reconciliation_enabled` collection switch: an unavailable
    // hint or explicit disable must not cause an offline bypass of user/org
    // policy. Once a scan is authorized, however, a later batch-upload failure
    // must not discard its machine-local evidence. Cache writes are best-effort
    // and never block usage sync; omit raw filesystem errors.
    if source == SnapshotSource::ClaudeCode
        && crate::context_posture::update_context_posture_cache(
            support_dir,
            &scan_result.snapshots,
            OffsetDateTime::now_utc(),
        )
        .is_err()
    {
        eprintln!(
            "local context-posture cache update skipped for {}",
            source.api_slug()
        );
    }

    // Keep the full local scan available to active-session/context-posture
    // consumers above, then remove only authority-demoting revisions at the
    // network boundary. They are not backend poison and are not counted as
    // accepted/quarantined upload settlement.
    let deferred_local_authority_entity_count =
        claude_authority_disposition.quarantined_entity_count();
    let locally_held_fingerprints =
        claude_authority_disposition.quarantined_fingerprints(&scan_result.snapshots);
    claude_authority_disposition.retain_uploadable(&mut scan_result.snapshots);
    let deferred_local_authority_count = index.claude_usage_authority_pending_count();

    let mut accepted = 0;
    let upload_result = upload_resumable_batches_with_body_witness_partitioned(
        &scan_result.snapshots,
        source.api_slug(),
        &mut upload_progress,
        &mut accepted,
        |snapshot| snapshot.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |snapshot| legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint),
        |snapshots| {
            // A first Codex/Claude scan can spend several minutes parsing local
            // history and retroactive backfill before the first upload. Relay
            // tokens are intentionally short-lived, so mint them at the network
            // boundary instead of reusing the pre-scan activity-hint token.
            // Leased, not read: exactly one in-flight batch may claim the
            // counters, and dropping the lease on any failure below leaves the
            // losses owed instead of stranded.
            let client_report = crate::client_report::lease();
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: source.api_slug().to_string(),
                machine_id: machine_id.to_string(),
                collector_version: Some(collector_version()),
                snapshots,
                upload_policy,
                client_report: client_report.report().clone(),
            };
            let reconcile_class = request.snapshots.iter().all(|snapshot| {
                legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint)
            });
            debug_assert!(
                reconcile_class
                    || request.snapshots.iter().all(|snapshot| {
                        !legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint)
                    }),
                "legacy reconciliation must stay isolated at a batch boundary"
            );
            if let Err(reason) = validate_snapshot_batch_request(&request) {
                return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                    reason,
                }));
            }
            let upload_relay_token = client.issue_relay_token(device, device_secret, source)?;
            let response = client.upload_batch(&upload_relay_token, &request, reconcile_class)?;
            response.validate_entity_ack_with_head_cas(&request, reconcile_class)?;
            let request_fingerprints = request
                .snapshots
                .iter()
                .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                .collect::<BTreeSet<_>>();
            require_normal_write_ack_for_legacy_reconciliation(
                &response,
                &request_fingerprints,
                &legacy_reconciliation_pending,
            )?;
            // Clear only what this accepted request carried. A failed upload
            // leaves the counters in place so the losses are reported on the
            // next batch instead of vanishing with the request that died.
            client_report.commit();
            Ok(response)
        },
        |progress| progress.save(&upload_progress_path),
    )
    .and_then(|result| {
        if matches!(
            result,
            ResumableUploadResult::Completed | ResumableUploadResult::Conflicted { .. }
        ) {
            // A setup/account switch can replace the relay binding while a
            // long historical scan is uploading. Never commit destination A's
            // delivery cursor after the machine has moved to destination B.
            ensure_snapshot_destination_current(&upload_destination_namespace)?;
        }
        Ok(result)
    });

    // The server may have accepted new entities even when the final result is a
    // timeout, a disabled response, or a later local-state failure. Withdraw
    // the pre-cycle cache for every outcome; completed/shed branches republish
    // only after their exact replacement index is durable.
    withdraw_source_manifest(&upload_destination_namespace, source);

    let mut upload_fully_settled = true;
    let mut deferred_entity_conflict_count = None;
    match upload_result {
        Ok(ResumableUploadResult::Completed) => {
            clear_shed_streak(source);
            if deferred_local_authority_count > 0 {
                let mut accepted_fingerprints = upload_progress.accepted_fingerprints.clone();
                accepted_fingerprints
                    .retain(|fingerprint| !locally_held_fingerprints.contains(fingerprint));
                let mut server_quarantine = upload_progress.quarantined_fingerprints.clone();
                server_quarantine
                    .retain(|fingerprint, _| !locally_held_fingerprints.contains(fingerprint));
                index = index.committable_subset(
                    &committed_index,
                    &accepted_fingerprints,
                    &server_quarantine,
                );
                index.mark_bounded_sweep_unsettled();
                backfill_succeeded = false;
                upload_fully_settled = false;
                eprintln!(
                    "local snapshot sync retained {deferred_local_authority_count} Claude usage \
                     family/families ({deferred_local_authority_entity_count} revised \
                     entity/entities this pass) with unproven authority; healthy siblings settled \
                     and the retained revisions remain pending for bounded retry"
                );
            }
        }
        Ok(ResumableUploadResult::Conflicted { count }) => {
            clear_shed_streak(source);
            if deferred_local_authority_count > 0 {
                let mut accepted_fingerprints = upload_progress.accepted_fingerprints.clone();
                accepted_fingerprints
                    .retain(|fingerprint| !locally_held_fingerprints.contains(fingerprint));
                let mut server_quarantine = upload_progress.quarantined_fingerprints.clone();
                server_quarantine
                    .retain(|fingerprint, _| !locally_held_fingerprints.contains(fingerprint));
                index = index.committable_subset(
                    &committed_index,
                    &accepted_fingerprints,
                    &server_quarantine,
                );
            }
            // Accepted siblings are safe to commit, but a retryable conflict
            // is not proof that a broad historical replay is complete. Force
            // one clean follow-up sweep and leave the destination's backfill
            // marker pending until every replacement entity settles.
            index.mark_bounded_sweep_unsettled();
            backfill_succeeded = false;
            upload_fully_settled = false;
            deferred_entity_conflict_count = Some(count);
            eprintln!(
                "local snapshot upload checkpointed accepted siblings but left {count} \
                 conflicting entity(ies) pending for {}; a clean follow-up scan is required",
                source.api_slug()
            );
        }
        Ok(ResumableUploadResult::Shed { retry_after }) => {
            let retry_after = note_shed_and_backoff(source, retry_after);
            defer_source_uploads(source, retry_after);
            // Commit what the server demonstrably holds. Committing everything
            // would drop the pages it never received; committing nothing means
            // the next cycle replays the whole scan, which is today's behaviour
            // and the reason a shed request produces an identical re-upload every
            // five minutes forever.
            let mut accepted_fingerprints = upload_progress.accepted_fingerprints.clone();
            accepted_fingerprints
                .retain(|fingerprint| !locally_held_fingerprints.contains(fingerprint));
            let mut server_quarantine = upload_progress.quarantined_fingerprints.clone();
            server_quarantine
                .retain(|fingerprint, _| !locally_held_fingerprints.contains(fingerprint));
            let mut committable = index.committable_subset(
                &committed_index,
                &accepted_fingerprints,
                &server_quarantine,
            );
            committable.mark_bounded_sweep_unsettled();
            // `committable_subset` also retains an older quarantine witness for
            // restored prior entities. Replacing it with only this pass's
            // progress would make an absent retry look server-held.
            if let Err(error) = save_index_and_publish_manifest(
                &mut committable,
                &index_path,
                &upload_destination_namespace,
                source,
                scan_result.census_complete,
                &manifest_window_start,
                &manifest_window_end,
            ) {
                eprintln!(
                    "local snapshot partial scan checkpoint failed for {}: {}",
                    source.api_slug(),
                    safe_error(&error)
                );
            }
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                if scan_result.census_complete {
                    TerminalManifestSource::CompleteCensus(&committable)
                } else {
                    TerminalManifestSource::Withdraw
                },
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&committable),
                    // `server_error` is the closest code the receipt contract
                    // carries; the loss report is where the shed is named
                    // precisely.
                    state: CollectorState::Error {
                        code: "server_error",
                        message: "backend shed the snapshot upload; honouring backoff",
                    },
                },
            )?;
            return Ok(());
        }
        Ok(ResumableUploadResult::Disabled(disabled_reason)) => {
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&index),
                    state: CollectorState::Disabled(
                        disabled_reason.or_else(|| Some("disabled_by_admin".to_string())),
                    ),
                },
            )?;
            return Ok(());
        }
        Err(error) => {
            // Distinguish local serializer drift, authorization failures, and
            // backend payload rejection. The resumable driver has already
            // checkpointed every accepted sibling before this terminal error.
            let (state, context) = if snapshot_upload_error_class(&error)
                == Some(SnapshotUploadErrorClass::LocalState)
            {
                (
                    CollectorState::Error {
                        code: "local_state_error",
                        message: "local snapshot checkpoint or destination state failed",
                    },
                    "local snapshot state failed",
                )
            } else if snapshot_upload_error_class(&error)
                == Some(SnapshotUploadErrorClass::BackendResponse)
            {
                (
                    CollectorState::Error {
                        code: "backend_response_error",
                        message: "backend snapshot response did not match the request",
                    },
                    "backend snapshot response was invalid",
                )
            } else if let Some(rejected) = error.downcast_ref::<SnapshotBatchPreflightRejected>() {
                eprintln!(
                    "ottto-service: local snapshot batch failed daemon v{} contract preflight for {} — {}; usage/cost sync is NOT reaching the backend until the daemon serializer is fixed.",
                    SNAPSHOT_SCHEMA_VERSION,
                    source.api_slug(),
                    rejected.reason,
                );
                (
                    CollectorState::Error {
                        code: "backend_validation_error",
                        message: "local snapshot batch failed daemon/backend contract preflight",
                    },
                    "local snapshot batch failed daemon/backend contract preflight",
                )
            } else if let Some(rejected) = error.downcast_ref::<BatchAuthorizationRejected>() {
                eprintln!(
                    "ottto-service: snapshot batch authorization rejected by backend (HTTP {}) \
                     for {}; start setup or sign in from the Ottto app before retrying \
                     local usage sync.",
                    rejected.status,
                    source.api_slug(),
                );
                (
                    CollectorState::Error {
                        code: "auth_error",
                        message: "backend rejected snapshot batch authorization",
                    },
                    "backend rejected snapshot batch authorization",
                )
            } else if let Some(rejected) = error.downcast_ref::<BatchRejected>() {
                let body = rejected
                    .body_excerpt
                    .as_deref()
                    .unwrap_or("backend returned no validation detail");
                eprintln!(
                    "ottto-service: snapshot batch payload rejected by backend (HTTP {}) for {} — \
                     daemon SNAPSHOT_SCHEMA_VERSION={}; backend detail: {}; usage/cost sync is \
                     NOT reaching the backend until the daemon payload or backend validator is \
                     updated. This is a payload validation failure, not a network error.",
                    rejected.status,
                    source.api_slug(),
                    SNAPSHOT_SCHEMA_VERSION,
                    body,
                );
                (
                    CollectorState::Error {
                        code: "backend_validation_error",
                        message: "backend rejected snapshot batch payload validation",
                    },
                    "backend rejected snapshot batch payload validation",
                )
            } else {
                // A shed request is not a network failure. 429 is unambiguous in
                // the redacted diagnostics today; 503 joins it with the typed
                // `Retry-After` handling, which is where the backoff itself
                // lives. The collector status code stays `network_error` — that
                // string is a backend contract, and only the loss category is
                // being classified here.
                crate::client_report::record(
                    if is_shed_failure(&error) {
                        crate::client_report::ClientReportReason::RatelimitBackoff
                    } else {
                        crate::client_report::ClientReportReason::NetworkError
                    },
                    1,
                );
                // Everything above this arm names its own cause. This arm is
                // the catch-all, and it used to log the bare phrase "local
                // snapshot upload failed" with no status code, endpoint, or
                // body — which is undiagnosable from a log alone and cost a
                // full reverse-engineering pass to classify. Always emit the
                // redacted failure shape here: the typed transport/HTTP
                // diagnostic when the request reached the wire, and the
                // classified reason when it failed before that.
                eprintln!(
                    "ottto-service: local snapshot upload failed for {} — {}; \
                     daemon SNAPSHOT_SCHEMA_VERSION={}.",
                    source.api_slug(),
                    upload_failure_diagnostic(&error),
                    SNAPSHOT_SCHEMA_VERSION,
                );
                (
                    CollectorState::Error {
                        code: "network_error",
                        message: "local snapshot upload failed",
                    },
                    "upload local snapshots",
                )
            };
            with_source_cadence(source, |cadence| {
                cadence.record_scan_failure(Instant::now())
            });
            let _ = report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&index),
                    state,
                },
            );
            return Err(error.context(context));
        }
    }

    index.retain_quarantined_fingerprints(&upload_progress.quarantined_fingerprints);
    index.record_accepted_snapshot_fingerprints(&upload_progress.accepted_fingerprints);
    index.finish_legacy_settlement_reconciliation();
    settle_context_curve_replay_state(
        &mut index,
        context_curve_enabled,
        scan_result.census_complete && upload_fully_settled,
        &replay_generation,
    );
    save_index_and_publish_manifest(
        &mut index,
        &index_path,
        &upload_destination_namespace,
        source,
        scan_result.census_complete,
        &manifest_window_start,
        &manifest_window_end,
    )?;
    // A completed cycle is what moves the tier: uploads keep a source warm, a
    // quiet cycle lets it fall to idle and then cold. A conflict pass has still
    // durably committed its accepted siblings, but remains a source failure so
    // it returns to the retry cadence instead of advertising a clean terminal
    // scan. The sweep marker is stamped only for fully settled scans.
    with_source_cadence(source, |cadence| {
        let now = Instant::now();
        if deferred_entity_conflict_count.is_some() {
            cadence.record_scan_failure(now);
        } else {
            cadence.record_scan_success(now, accepted);
            cadence.record_full_sweep(now);
        }
    });

    // Refresh the per-source detected-uses cache the daemon health assembly
    // reads for the Companion's "Detected Uses" panel. The scan is incremental,
    // so this cycle's snapshots are a delta; the cache merge preserves
    // historical destinations. A failure here must never fail the sync, and the
    // error is not logged verbatim because it can embed a local filesystem path.
    if update_detected_uses_cache(support_dir, source, &scan_result.snapshots).is_err() {
        eprintln!(
            "local detected-uses cache update skipped for {}",
            source.api_slug()
        );
    }

    if backfill_succeeded {
        // Reload before mutating: a claim completion can persist an
        // account-switch backfill cutoff while this (potentially minutes-long)
        // sync is running, and saving the stale pre-scan copy would clobber it.
        let mut backfill_state = load_backfill_state(support_dir);
        mark_backfill_complete_for_destination(
            &mut backfill_state,
            source,
            &upload_destination_namespace,
        );
        backfill_state.last_completed_at = Some(scan_started_at.clone());
        if let Err(error) = save_backfill_state(support_dir, &backfill_state) {
            eprintln!(
                "local snapshot backfill state save failed for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
            return Err(anyhow!("local snapshot backfill state save failed"));
        }
    }

    // Final scan/backfill markers are durable before progress disappears. A
    // crash anywhere above leaves the hash-only ledger in place; the next run
    // safely resumes/finalizes without replaying accepted pages.
    upload_progress.clear(&upload_progress_path)?;

    if let Some(count) = deferred_entity_conflict_count {
        // The uploader drained its frozen, scan-capped queue before returning
        // `Conflicted`, and the index above now owns both accepted siblings and
        // retryable conflict quarantine. Surface the conflict only after those
        // facts are durable: returning earlier would recreate the per-source
        // starvation wedge, while reporting success would hide the backend's
        // capacity condition from source-level isolation and cadence handling.
        let _ = report_status_with_fresh_relay_token(
            client,
            device,
            device_secret,
            support_dir,
            source,
            if scan_result.census_complete {
                TerminalManifestSource::CompleteCensus(&index)
            } else {
                TerminalManifestSource::Withdraw
            },
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: terminal_scan_started_at,
                counts: SyncCounts::from_scan_result(&scan_result, accepted, receipt_window_days)
                    .with_snapshot_terminal_counts(&index),
                state: CollectorState::Error {
                    code: "server_error",
                    message: "backend deferred conflicting snapshot entities",
                },
            },
        );
        return Err(snapshot_entity_conflict_deferred(count));
    }

    report_status_with_fresh_relay_token(
        client,
        device,
        device_secret,
        support_dir,
        source,
        if scan_result.census_complete {
            TerminalManifestSource::CompleteCensus(&index)
        } else {
            TerminalManifestSource::Withdraw
        },
        CollectorStatus {
            source,
            machine_id,
            scan_started_at: terminal_scan_started_at,
            counts: SyncCounts::from_scan_result(&scan_result, accepted, receipt_window_days)
                .with_snapshot_terminal_counts(&index),
            state: CollectorState::Success,
        },
    )?;
    Ok(())
}

/// Prepare the disposable upload ledger against the durable scan-index replay.
///
/// The index owns both the replay generation and conflict quarantine after a
/// completed cycle clears upload progress. For a new generation, old index
/// quarantine must not be restored after progress is rearmed. For the same
/// generation, restore it only after progress has claimed that generation so a
/// clean follow-up cannot erase a replacement conflict before its retry.
fn prepare_upload_progress_for_cycle(
    upload_progress: &mut SnapshotUploadProgress,
    index: &ScanIndex,
    replay_generation: &str,
    historical_replay_pending: bool,
) -> bool {
    if !historical_replay_pending {
        return upload_progress
            .prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    }

    let same_index_replay = index.historical_replay_generation_matches(replay_generation);
    let mut progress_changed = upload_progress.prepare_historical_replay(replay_generation);
    if same_index_replay {
        progress_changed |=
            upload_progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    }
    progress_changed
}

fn settle_context_curve_replay_state(
    index: &mut ScanIndex,
    context_curve_enabled: bool,
    census_complete: bool,
    replay_generation: &str,
) {
    if context_curve_enabled && census_complete {
        // This point is reached only after every curve-bearing entity received
        // an exact durable v5/v6 proof and the bounded traversal reached the
        // end of its frozen census. Partial pages retain the replay epoch so a
        // later cycle keeps the full historical window and traversal cursor.
        index.mark_context_curve_replay_complete(replay_generation.to_string());
    } else if !context_curve_enabled {
        // Mark the off epoch only after the ordinary no-curve cycle succeeds.
        // A later re-enable uses the incremented epoch to force exactly one
        // fresh historical replay, including files changed while off.
        index.mark_context_curve_capability_disabled();
    }
}

fn reconciliation_agent_status(collection: &AgentStatusCollection) -> &AgentStatusSnapshot {
    &collection.source_health_snapshot
}

fn claude_evidence_session_ids(snapshots: &[SnapshotItem]) -> Vec<String> {
    snapshots
        .iter()
        .flat_map(|snapshot| {
            std::iter::once(snapshot.source_session_id.clone()).chain(
                snapshot
                    .attribution_facts
                    .iter()
                    .filter(|fact| {
                        matches!(
                            fact.field.as_str(),
                            "parent_session_ref" | "root_session_ref"
                        )
                    })
                    .map(|fact| fact.value.clone()),
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn claude_evidence_root_session_ids(snapshots: &[SnapshotItem]) -> Vec<String> {
    snapshots
        .iter()
        .map(|snapshot| {
            snapshot
                .attribution_facts
                .iter()
                .find(|fact| fact.field == "root_session_ref")
                .map(|fact| fact.value.clone())
                .or_else(|| {
                    snapshot
                        .source_session_id
                        .split_once("_agent-")
                        .map(|(root, _)| root.to_string())
                })
                .unwrap_or_else(|| snapshot.source_session_id.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum ResumableUploadResult {
    Completed,
    /// Every accepted sibling is durably checkpointed, while one or more
    /// retryable entity conflicts remain quarantined for a later clean sweep.
    Conflicted {
        count: usize,
    },
    Disabled(Option<String>),
    /// The backend shed a page. Every earlier page is accepted and
    /// checkpointed; this is a "come back later", not a failure.
    ///
    /// Carries the server's own `Retry-After` verbatim (absent when it sent
    /// none). Turning that into a wait needs the per-source shed history, which
    /// the caller owns, not this pass.
    Shed {
        retry_after: Option<Duration>,
    },
}

#[derive(Debug)]
struct SnapshotBatchPreflightRejected {
    reason: String,
}

impl std::fmt::Display for SnapshotBatchPreflightRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "local snapshot batch contract preflight failed: {}",
            self.reason
        )
    }
}

impl std::error::Error for SnapshotBatchPreflightRejected {}

#[derive(Debug)]
struct SnapshotLocalStateRejected {
    operation: &'static str,
}

impl std::fmt::Display for SnapshotLocalStateRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "local snapshot state failed: {}", self.operation)
    }
}

impl std::error::Error for SnapshotLocalStateRejected {}

#[derive(Debug)]
struct SnapshotBatchResponseRejected {
    expected: u64,
    accepted: u64,
}

impl std::fmt::Display for SnapshotBatchResponseRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "snapshot batch accepted-count mismatch: expected {}, received {}",
            self.expected, self.accepted
        )
    }
}

impl std::error::Error for SnapshotBatchResponseRejected {}

/// Legacy ambiguity is resolved by the normal upload/quarantine machine. The
/// deployed handler's exact-repeat contract is deliberately truthful: it
/// commits the source-freshness acceptance UPSERT, but skips the
/// bronze snapshot, payload, reconciliation revision, accepted-log sequence,
/// archive occurrence, and entity-head writes. Consequently an exact repeat
/// has zero census-membership delta. A genuinely missing head creates exactly
/// one new/updated census member; a divergent body is fenced by head CAS and
/// remains quarantined with zero census delta until an explicit resolution.
fn require_normal_write_ack_for_legacy_reconciliation(
    response: &crate::snapshot_client::SnapshotBatchResponse,
    request_fingerprints: &BTreeSet<String>,
    legacy_pending: &BTreeSet<String>,
) -> Result<()> {
    let carries_legacy_reconciliation = request_fingerprints
        .iter()
        .any(|fingerprint| legacy_pending.contains(fingerprint));
    if !carries_legacy_reconciliation {
        return Ok(());
    }
    if response.disabled {
        return Err(anyhow!(
            "disabled snapshot response cannot settle legacy reconciliation"
        ));
    }
    if response.entity_ack_contract.as_deref()
        != Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT)
    {
        return Err(anyhow!(
            "legacy snapshot reconciliation requires the exact entity ACK contract"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotEntityConflictDeferred {
    count: usize,
}

impl std::fmt::Display for SnapshotEntityConflictDeferred {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "snapshot upload deferred {} conflicting entity(ies)",
            self.count
        )
    }
}

impl std::error::Error for SnapshotEntityConflictDeferred {}

fn snapshot_entity_conflict_deferred(count: usize) -> anyhow::Error {
    anyhow::Error::new(SnapshotEntityConflictDeferred { count })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotUploadErrorClass {
    LocalState,
    BackendResponse,
}

fn snapshot_upload_error_class(error: &anyhow::Error) -> Option<SnapshotUploadErrorClass> {
    if error.downcast_ref::<SnapshotLocalStateRejected>().is_some() {
        Some(SnapshotUploadErrorClass::LocalState)
    } else if error
        .downcast_ref::<SnapshotBatchResponseRejected>()
        .is_some()
    {
        Some(SnapshotUploadErrorClass::BackendResponse)
    } else {
        None
    }
}

fn is_item_specific_validation_failure(error: &anyhow::Error) -> bool {
    if is_item_specific_local_preflight_failure(error) {
        return true;
    }
    error
        .downcast_ref::<BatchRejected>()
        .and_then(|rejected| rejected.body_excerpt.as_deref())
        .is_some_and(|body| {
            body.contains("\"loc\":[\"body\",\"snapshots\"")
                || body.contains("'loc': ['body', 'snapshots'")
        })
}

fn is_item_specific_local_preflight_failure(error: &anyhow::Error) -> bool {
    item_specific_local_preflight_index(error).is_some()
}

fn item_specific_local_preflight_index(error: &anyhow::Error) -> Option<usize> {
    error
        .downcast_ref::<SnapshotBatchPreflightRejected>()
        .and_then(|preflight| preflight.reason.strip_prefix("snapshot["))
        .and_then(|suffix| suffix.split_once(']'))
        .and_then(|(index, _)| index.parse().ok())
}

/// True when the backend shed this request rather than failing it.
fn is_shed_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| diagnostics.status_family() == "http_429")
}

fn is_snapshot_batch_deadline_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(UploadFailureDiagnostics::is_snapshot_batch_deadline)
}

/// Upload changed snapshots in bounded pages while durably checkpointing every
/// accepted page. Item-specific validation failures are bisected so one poison
/// snapshot cannot replay or block its valid siblings; pages that exceed the
/// client or gateway deadline are also bisected to reduce per-request
/// reconciliation work. Splits are capped so an outage or broad contract
/// mismatch cannot fan out into unbounded calls.
#[cfg(test)]
fn upload_resumable_batches<T, Fingerprint, Upload, Persist>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    upload: Upload,
    persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Clone + Serialize,
    Fingerprint: Fn(&T) -> &str + Copy,
    Upload: FnMut(Vec<T>) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    upload_resumable_batches_with_body_witness(
        items,
        poison_scope,
        progress,
        accepted,
        fingerprint,
        move |item| fingerprint(item).to_string(),
        upload,
        persist,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn upload_resumable_batches_with_body_witness<T, Fingerprint, BodyWitness, Upload, Persist>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    body_witness: BodyWitness,
    upload: Upload,
    persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Clone + Serialize,
    Fingerprint: Fn(&T) -> &str,
    BodyWitness: Fn(&T) -> String,
    Upload: FnMut(Vec<T>) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    upload_resumable_batches_with_body_witness_partitioned(
        items,
        poison_scope,
        progress,
        accepted,
        fingerprint,
        body_witness,
        |_| false,
        upload,
        persist,
    )
}

#[allow(clippy::too_many_arguments)]
fn upload_resumable_batches_with_body_witness_partitioned<
    T,
    Fingerprint,
    BodyWitness,
    BatchClass,
    Upload,
    Persist,
>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    body_witness: BodyWitness,
    batch_class: BatchClass,
    mut upload: Upload,
    mut persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Clone + Serialize,
    Fingerprint: Fn(&T) -> &str,
    BodyWitness: Fn(&T) -> String,
    BatchClass: Fn(&T) -> bool,
    Upload: FnMut(Vec<T>) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    // A permanently invalid snapshot can keep the final scan index uncommitted
    // across many cycles while valid sessions continue changing. Retain only
    // fingerprints present in this cycle's policy/cutoff-filtered work so the
    // hash-only ledger stays O(current scan), not O(all historical revisions).
    let mut current_body_witnesses = BTreeMap::new();
    for item in items {
        let item_fingerprint = fingerprint(item).to_string();
        let item_body_witness = body_witness(item);
        if current_body_witnesses
            .insert(item_fingerprint.clone(), item_body_witness.clone())
            .is_some_and(|previous| previous != item_body_witness)
        {
            return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "resolve conflicting snapshot body witnesses",
            }));
        }
    }
    let current_fingerprints = current_body_witnesses
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let progress_len_before_prune = progress.accepted_fingerprints.len();
    progress
        .accepted_body_witnesses
        .retain(|fingerprint, witness| current_body_witnesses.get(fingerprint) == Some(witness));
    progress
        .accepted_fingerprints
        .retain(|value| progress.accepted_body_witnesses.contains_key(value));
    retain_counted_poison_fingerprints(poison_scope, &current_fingerprints);
    if progress.accepted_fingerprints.len() != progress_len_before_prune {
        persist(progress).map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "prune upload checkpoint",
            })
        })?;
    }

    let mut pending_by_fingerprint: BTreeMap<String, (usize, Vec<u8>, String)> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        let witness = body_witness(item);
        if !progress.contains_body(fingerprint(item), &witness) {
            match pending_by_fingerprint.entry(fingerprint(item).to_string()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let body = serde_json::to_vec(item).map_err(|_| {
                        anyhow::Error::new(SnapshotLocalStateRejected {
                            operation: "serialize snapshot for batch packing",
                        })
                    })?;
                    entry.insert((index, body, witness));
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    // The finalized fingerprint covers every post-policy
                    // semantic field and production preflight recomputes it
                    // before upload. Observation/inventory fields deliberately
                    // excluded from that identity (for example collected_at or
                    // source_file_fingerprint after a rotate/recopy) may make
                    // whole item bytes differ without creating another remote
                    // entity. Upload one representative for that semantic
                    // identity; every local file entry settles from the same
                    // accepted fingerprint.
                }
            }
        }
    }
    let mut deferred_validation_error = None;
    let mut batches = VecDeque::new();
    let mut batch = Vec::new();
    let mut batch_bytes = 2usize;
    let mut current_batch_class = None;
    for (index, body, _) in pending_by_fingerprint.into_values() {
        let item_bytes = body.len().saturating_add(1);
        let item_batch_class = batch_class(&items[index]);
        if !batch.is_empty()
            && (batch.len() == SNAPSHOT_BATCH_LIMIT
                || batch_bytes.saturating_add(item_bytes) > SNAPSHOT_BATCH_MAX_BYTES
                || current_batch_class != Some(item_batch_class))
        {
            batches.push_back((std::mem::take(&mut batch), false));
            batch_bytes = 2;
        }
        current_batch_class = Some(item_batch_class);
        batch.push(index);
        batch_bytes = batch_bytes.saturating_add(item_bytes);
    }
    if !batch.is_empty() {
        batches.push_back((batch, false));
    }
    let mut adaptive_splits = 0usize;
    let mut adaptive_attempts = 0usize;
    let mut conflicted_entities = 0usize;

    while let Some((indices, adaptive)) = batches.pop_front() {
        // A duplicate fingerprint may occur in the live scan and historical
        // bootstrap. Re-check after earlier batches checkpointed it.
        let indices = indices
            .into_iter()
            .filter(|index| {
                !progress.contains_body(fingerprint(&items[*index]), &body_witness(&items[*index]))
            })
            .collect::<Vec<_>>();
        if indices.is_empty() {
            continue;
        }
        if adaptive {
            if adaptive_attempts >= SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT {
                return Err(deferred_validation_error
                    .take()
                    .unwrap_or_else(|| anyhow!("snapshot adaptive upload attempt limit reached"))
                    .context("snapshot adaptive upload attempt limit reached"));
            }
            adaptive_attempts += 1;
        }
        let batch = indices
            .iter()
            .map(|index| items[*index].clone())
            .collect::<Vec<_>>();

        match upload(batch) {
            Ok(response) if response.disabled => {
                return Ok(ResumableUploadResult::Disabled(response.disabled_reason));
            }
            Ok(response) => {
                let entity_ack = match response.entity_ack_contract.as_deref() {
                    None => false,
                    Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT) => true,
                    Some(_) => {
                        return Err(anyhow!(
                            "snapshot response uses an unsupported entity ACK contract"
                        ));
                    }
                };
                if !entity_ack && response.accepted != indices.len() as u64 {
                    return Err(anyhow::Error::new(SnapshotBatchResponseRejected {
                        expected: indices.len() as u64,
                        accepted: response.accepted,
                    }));
                }
                if entity_ack {
                    let settled = response
                        .accepted_entities
                        .iter()
                        .chain(&response.unchanged_entities)
                        .map(|entity| entity.snapshot_fingerprint.as_str())
                        .collect::<BTreeSet<_>>();
                    for index in &indices {
                        let item = &items[*index];
                        let item_fingerprint = fingerprint(item);
                        if settled.contains(item_fingerprint) {
                            progress.record_body(item_fingerprint, &body_witness(item));
                        }
                    }
                    let rejected = response
                        .rejected_entities
                        .iter()
                        .map(|entity| entity.snapshot_fingerprint.as_str())
                        .collect::<BTreeSet<_>>();
                    let conflicted = response
                        .conflict_entities
                        .iter()
                        .map(|entity| entity.snapshot_fingerprint.as_str())
                        .collect::<BTreeSet<_>>();
                    for index in &indices {
                        let item = &items[*index];
                        let item_fingerprint = fingerprint(item);
                        if rejected.contains(item_fingerprint)
                            || conflicted.contains(item_fingerprint)
                        {
                            progress.quarantine_body(item_fingerprint, &body_witness(item));
                        }
                    }
                    // A conflict is not a settlement, but it IS retryable: the
                    // backend is asking for this entity again later, not never.
                    // It therefore shares the quarantine ledger's bounded
                    // backoff with permanent rejections, so one conflicting
                    // entity defers only itself.
                    //
                    // Returning the whole page as an error here (the previous
                    // behaviour) discarded the entities the backend had ALREADY
                    // written in this same response, so nothing was ever
                    // checkpointed: the identical page replayed every cycle,
                    // the scan index could never commit, and the "fresh
                    // complete scan" that recovery waited on could never
                    // happen. One conflicting entity deadlocked its whole
                    // source permanently, across restarts.
                    conflicted_entities =
                        conflicted_entities.saturating_add(response.conflict_entities.len());
                } else {
                    for index in &indices {
                        let item = &items[*index];
                        progress.record_body(fingerprint(item), &body_witness(item));
                    }
                }
                // The remote write happened first. If this local atomic save
                // fails, stop: at most this one idempotent page can replay.
                persist(progress).map_err(|_| {
                    anyhow::Error::new(SnapshotLocalStateRejected {
                        operation: "save upload checkpoint",
                    })
                })?;
                if entity_ack {
                    for entity in &response.rejected_entities {
                        record_poison_loss_once(poison_scope, &entity.snapshot_fingerprint);
                    }
                }
                *accepted = accepted.saturating_add(response.accepted);
            }
            Err(error) if is_item_specific_local_preflight_failure(&error) => {
                // The daemon validator names the exact request-local item. It
                // has already proved those bytes cannot fit or satisfy the
                // current wire contract, so quarantine that entity directly
                // and retry only its siblings. This avoids spending remote
                // adaptive-request budget or turning one bad item into twenty
                // one-item network requests.
                let request_index = item_specific_local_preflight_index(&error)
                    .expect("local item preflight guard parsed an index");
                let Some(poison_index) = indices.get(request_index).copied() else {
                    return Err(error.context("local snapshot preflight index was out of bounds"));
                };
                let poison_fingerprint = fingerprint(&items[poison_index]);
                let progress_before_quarantine = progress.clone();
                progress.quarantine_body(
                    fingerprint(&items[poison_index]),
                    &body_witness(&items[poison_index]),
                );
                if persist(progress).is_err() {
                    *progress = progress_before_quarantine;
                    return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                        operation: "save local preflight quarantine",
                    }));
                }
                // Count the loss only after its quarantine is durable. A local
                // save failure must leave both the settlement and the once-set
                // untouched so a successful retry can report the real loss.
                record_poison_loss_once(poison_scope, poison_fingerprint);
                let remaining = indices
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, item)| (index != request_index).then_some(item))
                    .collect::<Vec<_>>();
                if !remaining.is_empty() {
                    batches.push_front((remaining, false));
                }
            }
            Err(error)
                if indices.len() > 1
                    && adaptive_splits < SNAPSHOT_ADAPTIVE_SPLIT_LIMIT
                    && is_item_specific_validation_failure(&error) =>
            {
                // Legacy 422 is a full-batch/no-write outcome. Retry exact
                // singletons so one poisoned item cannot strand healthy
                // siblings and no binary subset is mistaken for an ACK.
                adaptive_splits += 1;
                for index in indices.into_iter().rev() {
                    batches.push_front((vec![index], true));
                }
            }
            Err(error)
                if indices.len() > 1
                    && adaptive_splits < SNAPSHOT_ADAPTIVE_SPLIT_LIMIT
                    && is_snapshot_batch_deadline_failure(&error) =>
            {
                adaptive_splits += 1;
                let midpoint = indices.len() / 2;
                let right = indices[midpoint..].to_vec();
                let left = indices[..midpoint].to_vec();
                batches.push_front((right, true));
                batches.push_front((left, true));
            }
            Err(error) if indices.len() > 1 && is_item_specific_validation_failure(&error) => {
                // Keep the original typed validation error in the anyhow
                // chain so the caller still reports backend_validation_error
                // when the bounded isolation budget is exhausted.
                return Err(error.context("snapshot adaptive upload split limit reached"));
            }
            Err(error) if is_item_specific_validation_failure(&error) => {
                // Preserve the first poison-item diagnostic, but continue so
                // every valid sibling is accepted and checkpointed exactly
                // once. The caller still reports the cycle as failed and does
                // not commit the final scan index.
                for index in &indices {
                    record_poison_loss_once(poison_scope, fingerprint(&items[*index]));
                }
                if deferred_validation_error.is_none() {
                    deferred_validation_error = Some(error);
                }
            }
            Err(error) if error.downcast_ref::<UploadShed>().is_some() => {
                let shed = error
                    .downcast_ref::<UploadShed>()
                    .copied()
                    .expect("shed diagnostics");
                crate::client_report::record(
                    crate::client_report::ClientReportReason::RatelimitBackoff,
                    1,
                );
                // Stop the pass here rather than hammering the remaining pages
                // at a server that just asked for room. Everything accepted so
                // far is already checkpointed, so the retry resumes instead of
                // restarting.
                return Ok(ResumableUploadResult::Shed {
                    retry_after: shed.retry_after,
                });
            }
            Err(error) => return Err(error),
        }
    }

    if conflicted_entities > 0 {
        // Every conflicting entity is durably quarantined with the same
        // bounded backoff a rejection gets, and every sibling in the page is
        // checkpointed. The distinct result prevents the caller from marking
        // a broad historical backfill complete while preserving that progress.
        eprintln!(
            "local snapshot upload deferred {conflicted_entities} conflicting \
             entity(ies) for {poison_scope}; they are quarantined for a bounded \
             retry while every other entity in the page settled."
        );
    }
    if let Some(error) = deferred_validation_error {
        Err(error)
    } else if conflicted_entities > 0 {
        Ok(ResumableUploadResult::Conflicted {
            count: conflicted_entities,
        })
    } else {
        Ok(ResumableUploadResult::Completed)
    }
}

/// Aggregate this cycle's snapshots into detected uses, merge them into the
/// persisted per-source cache, and write it back atomically (temp + rename,
/// like the backfill-state writer). The merge keeps historical destinations
/// that this incremental cycle did not re-scan.
fn update_detected_uses_cache(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
) -> Result<()> {
    let dir = support_dir.join("detected_uses");
    let path = dir.join(format!("{}.json", source.api_slug()));
    let merged = merge_detected_uses(
        read_detected_uses_cache(&path),
        aggregate_detected_uses(snapshots),
        OffsetDateTime::now_utc(),
        TimeDuration::days(DETECTED_USE_RETENTION_DAYS),
    );

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create detected_uses dir {}", dir.display()))?;
    let payload = serde_json::to_vec_pretty(&merged).context("serialize detected uses to JSON")?;
    let temp_path = path.with_extension("json.tmp");
    let mut temp = std::fs::File::create(&temp_path)
        .with_context(|| format!("create detected_uses temp {}", temp_path.display()))?;
    temp.write_all(&payload)
        .with_context(|| format!("write detected_uses temp {}", temp_path.display()))?;
    temp.sync_all().ok();
    std::fs::rename(&temp_path, &path)
        .with_context(|| format!("rename detected_uses cache into place {}", path.display()))?;
    Ok(())
}

/// Read the persisted detected-uses cache, or an empty list when it is missing
/// or unreadable (a fresh machine, or a malformed file we simply rebuild).
fn read_detected_uses_cache(path: &Path) -> Vec<DetectedUse> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn upload_agent_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    machine_id: &str,
    snapshots: &[AgentStatusSnapshot],
) -> Result<()> {
    if snapshots.is_empty() {
        return Ok(());
    }
    let request = AgentStatusSnapshotUploadRequest {
        machine_id: machine_id.to_string(),
        snapshots: snapshots
            .iter()
            .cloned()
            .map(AgentStatusSnapshot::redacted_for_backend)
            .collect(),
    };
    let response = client.upload_agent_status(relay_token, &request)?;
    persist_machine_icon(&response);
    crate::net_resilience::note_upstream_upload_succeeded("agent_status");
    Ok(())
}

fn source_kind(source: SnapshotSource) -> SourceKind {
    match source {
        SnapshotSource::Codex => SourceKind::Codex,
        SnapshotSource::ClaudeCode => SourceKind::ClaudeCode,
        SnapshotSource::Pi => SourceKind::Pi,
    }
}

/// Build the terminal collector receipt for a completed cycle.
///
/// Split from the send so the live path can journal the exact typed receipt it
/// is about to POST, and so tests can assert against that same payload —
/// including its declared `report_kind` — rather than a hand-rolled lookalike.
fn collector_status_request(
    destination_namespace: &str,
    status: CollectorStatus<'_>,
    census_residue_status_admitted: bool,
) -> Result<SnapshotStatusRequest> {
    let finished_at = current_rfc3339();
    let disclosed_loss = status.counts.disclosed_loss();
    let (
        enabled,
        disabled_reason,
        last_error_code,
        last_error_message,
        consecutive_failures,
        terminal_succeeded,
    ) = match status.state {
        // A census that completed and whose every disclosed loss class is
        // exactly the loss the daemon settled as non-progressing. The scan
        // succeeded: the clock binds (`last_success_at`), nothing is retried,
        // and the code still names the residue so a consumer that needs a
        // fully clean receipt sees that loss was disclosed. Only under the
        // backend's explicit admission — its error-code set is closed, and an
        // unadmitted code would have the whole receipt rejected.
        CollectorState::Success
            if disclosed_loss == DisclosedLoss::Terminal && census_residue_status_admitted =>
        {
            (
                true,
                None,
                Some(CENSUS_RESIDUE_ERROR_CODE.to_string()),
                Some(census_residue_message(&status.counts)),
                0,
                true,
            )
        }
        // Loss the daemon has not proved non-progressing — or settled residue
        // that a backend predating the admission can only read in this legacy
        // shape. Byte-identical to every released daemon apart from the
        // additive residue counters, which such a backend ignores.
        CollectorState::Success if disclosed_loss != DisclosedLoss::None => (
            true,
            None,
            Some("parse_error".to_string()),
            Some("local usage evidence produced no session snapshot".to_string()),
            1,
            false,
        ),
        CollectorState::Success => (true, None, None, None, 0, true),
        CollectorState::PolicyTombstone => (true, None, None, None, 0, false),
        CollectorState::Disabled(disabled_reason) => (false, disabled_reason, None, None, 0, false),
        CollectorState::Error { code, message } => (
            true,
            None,
            Some(code.to_string()),
            Some(message.to_string()),
            1,
            false,
        ),
    };
    let manifest = cached_source_manifest(destination_namespace, status.source);
    if let Some(manifest) = manifest.as_ref() {
        if manifest.window_end != status.scan_started_at {
            return Err(anyhow!(
                "snapshot manifest window end does not match terminal scan start"
            ));
        }
        let manifest_window_days = snapshot_manifest_window_days(manifest)?;
        if manifest_window_days != status.counts.backfill_window_days {
            return Err(anyhow!(
                "snapshot manifest window does not match terminal receipt evidence window"
            ));
        }
    }
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: status.source.api_slug().to_string(),
        machine_id: status.machine_id.to_string(),
        // This function has exactly one caller shape: a completed collector
        // cycle reporting its outcome. Success, parse failure, scan/upload
        // error, policy tombstone, and the disabled transition are all NEW
        // scan results, so the kind is a constant here rather than anything
        // derived from the fields below.
        report_kind: SnapshotStatusReportKind::ScanStatus,
        enabled,
        disabled_reason,
        last_scan_started_at: Some(status.scan_started_at.to_string()),
        last_scan_finished_at: Some(finished_at.clone()),
        last_success_at: terminal_succeeded.then_some(finished_at),
        last_error_code,
        last_error_message,
        last_uploaded_count: status.counts.uploaded_count,
        last_scanned_session_count: status.counts.scanned_session_count,
        last_scanned_file_count: status.counts.scanned_file_count,
        last_zero_snapshot_confirmed_count: status.counts.zero_snapshot_confirmed_count,
        last_zero_snapshot_usage_evidence_count: status.counts.zero_snapshot_usage_evidence_count,
        last_dropped_usage_record_count: status.counts.dropped_usage_record_count,
        last_ownership_incomplete_file_count: status.counts.ownership_incomplete_file_count,
        last_snapshot_unproven_terminal_count: status.counts.snapshot_unproven_terminal_count,
        last_snapshot_superseded_terminal_count: status.counts.snapshot_superseded_terminal_count,
        last_backfill_window_days: status.counts.backfill_window_days,
        last_backfill_file_limit: status.counts.backfill_file_limit,
        last_discovered_file_count: status.counts.discovered_file_count,
        last_skipped_file_count_due_to_limit: status.counts.skipped_file_count_due_to_limit,
        last_scan_cap_hit: status.counts.scan_cap_hit,
        last_semantic_noop_count: status.counts.semantic_noop_count,
        last_census_complete: Some(status.counts.census_complete),
        last_symlink_rejected_count: status.counts.symlink_rejected_count,
        last_unreadable_path_count: status.counts.unreadable_path_count,
        last_oversized_file_count: status.counts.oversized_file_count,
        last_disappeared_file_count: status.counts.disappeared_file_count,
        last_malformed_json_line_count: status.counts.malformed_json_line_count,
        last_invalid_utf8_line_count: status.counts.invalid_utf8_line_count,
        last_over_line_cap_count: status.counts.over_line_cap_count,
        last_recognized_usage_drop_count: status.counts.recognized_usage_drop_count,
        // Always sent, whichever error code the receipt carries: the settled
        // shares are scan evidence like the counters they decompose, and a
        // backend that declares them journals the disclosure even while the
        // code still reads `parse_error`. A backend that predates them ignores
        // them.
        last_terminal_ownership_incomplete_file_count: status
            .counts
            .terminal_ownership_incomplete_file_count,
        last_terminal_zero_snapshot_usage_evidence_count: status
            .counts
            .terminal_zero_snapshot_usage_evidence_count,
        last_terminal_recognized_usage_drop_count: status
            .counts
            .terminal_recognized_usage_drop_count,
        last_terminal_dropped_usage_record_count: status.counts.terminal_dropped_usage_record_count,
        last_terminal_over_line_cap_count: status.counts.terminal_over_line_cap_count,
        // A census verdict, so it is a function of the counts alone and not of
        // the admission: true exactly when every disclosed loss class was
        // settled this generation.
        last_census_residue_settled: disclosed_loss == DisclosedLoss::Terminal,
        last_census_residue_index_key_count: status.counts.census_residue_index_key_count,
        last_census_residue_archived_rollout_count: status
            .counts
            .census_residue_archived_rollout_count,
        last_census_residue_blocked_session_count: status
            .counts
            .census_residue_blocked_session_count,
        consecutive_failures,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(status.source.parser_version().to_string()),
        manifest,
    };
    Ok(request)
}

/// The residue a `census_residue` receipt names: classes and settled counts
/// only. Never a path, an index key, or a session id — the backend rejects a
/// path-shaped message outright, and the witness identifiers stay in the local
/// index.
fn census_residue_message(counts: &SyncCounts) -> String {
    format!(
        "census completed with settled non-progressing residue: \
         ownership_incomplete_files={}, zero_snapshot_usage_evidence_files={}, \
         recognized_usage_drops={}, dropped_usage_records={}, over_line_cap_lines={}",
        counts.terminal_ownership_incomplete_file_count,
        counts.terminal_zero_snapshot_usage_evidence_count,
        counts.terminal_recognized_usage_drop_count,
        counts.terminal_dropped_usage_record_count,
        counts.terminal_over_line_cap_count,
    )
}

#[cfg(test)]
fn report_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    status: CollectorStatus<'_>,
) -> Result<()> {
    let request = collector_status_request(destination_namespace, status, false)?;
    client.report_status(relay_token, &request)?;
    Ok(())
}

/// What the server's activity hint decides for a terminal receipt: the
/// evidence width, and whether the backend admits the `census_residue` code.
#[derive(Debug, Clone, Copy)]
struct TerminalReceiptPolicy {
    receipt_window_days: u64,
    /// Exact match on `CENSUS_RESIDUE_STATUS_CONTRACT`, fail-closed: absent,
    /// null, and any other token keep the legacy receipt shape. The backend's
    /// error-code set is closed, so this is what keeps a daemon from having
    /// its entire terminal receipt rejected by a backend that predates the
    /// admission — whatever order the two are deployed in.
    census_residue_status_admitted: bool,
}

fn current_terminal_receipt_policy(
    client: &SnapshotApiClient,
    relay_token: &str,
) -> Result<TerminalReceiptPolicy> {
    let activity_hint = client.get_activity_hint(relay_token)?;
    Ok(TerminalReceiptPolicy {
        receipt_window_days: validated_receipt_window_days(activity_hint.backfill_window_days)?,
        census_residue_status_admitted: activity_hint.census_residue_status_contract.as_deref()
            == Some(CENSUS_RESIDUE_STATUS_CONTRACT),
    })
}

fn current_receipt_window_days(client: &SnapshotApiClient, relay_token: &str) -> Result<u64> {
    Ok(current_terminal_receipt_policy(client, relay_token)?.receipt_window_days)
}

fn refresh_terminal_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
    scan_started_at: &str,
    receipt_window_days: u64,
    manifest_source: TerminalManifestSource<'_>,
) -> Result<()> {
    // Withdraw first so a failed refresh cannot leave a stale-width witness for
    // the independent heartbeat to repeat. Zero has no v2 manifest by design.
    withdraw_source_manifest(destination_namespace, source);
    if receipt_window_days == 0 {
        return Ok(());
    }
    let TerminalManifestSource::CompleteCensus(index) = manifest_source else {
        return Ok(());
    };
    let (window_start, window_end) =
        snapshot_manifest_window(scan_started_at, receipt_window_days)?;
    publish_source_manifest(
        destination_namespace,
        source,
        index.manifest_for_window(source, &window_start, &window_end)?,
    );
    Ok(())
}

fn terminal_status_journal_path(
    support_dir: &Path,
    destination_namespace: &str,
    source: SnapshotSource,
) -> PathBuf {
    support_dir
        .join("snapshots")
        .join("destinations")
        .join(destination_namespace)
        .join(format!("{}-terminal-status-v1.json", source.api_slug()))
}

fn save_terminal_status_journal(path: &Path, request: &SnapshotStatusRequest) -> Result<()> {
    if request.last_scan_finished_at.is_none() {
        return Err(anyhow!("terminal status journal requires a finished scan"));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create terminal status journal directory")?;
    }
    let _lock = SnapshotProgressLock::acquire(path)?;
    let temp_path = unique_progress_sibling(path, "tmp");
    let mut file = std::fs::File::create(&temp_path).context("create terminal status journal")?;
    let result = (|| -> Result<()> {
        serde_json::to_writer_pretty(&mut file, request)
            .context("write terminal status journal")?;
        file.sync_all().context("sync terminal status journal")?;
        std::fs::rename(&temp_path, path).context("replace terminal status journal")?;
        sync_progress_parent(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

#[cfg(test)]
fn load_terminal_status_journal(path: &Path) -> Result<Option<SnapshotStatusRequest>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read terminal status journal"),
    };
    let request: SnapshotStatusRequest =
        serde_json::from_slice(&bytes).context("parse terminal status journal")?;
    if request.schema_version != SNAPSHOT_STATUS_SCHEMA_VERSION
        || request.last_scan_started_at.is_none()
        || request.last_scan_finished_at.is_none()
    {
        return Err(anyhow!("terminal status journal is not a terminal receipt"));
    }
    Ok(Some(request))
}

fn report_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    support_dir: &Path,
    source: SnapshotSource,
    manifest_source: TerminalManifestSource<'_>,
    mut status: CollectorStatus<'_>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    // This is the single terminal report boundary. Every terminal outcome
    // reacquires its width here, after scanning/uploading and immediately
    // before deriving both the manifest and status scalar from that same hint
    // — and reads the residue admission off the same hint, so the receipt
    // shape and the width are decided by one server answer.
    let TerminalReceiptPolicy {
        receipt_window_days,
        census_residue_status_admitted,
    } = current_terminal_receipt_policy(client, &relay_token)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    status.counts.backfill_window_days = receipt_window_days;
    if receipt_window_days == 0 {
        status.counts.census_complete = false;
        status.state = CollectorState::PolicyTombstone;
    }
    refresh_terminal_manifest(
        &destination_namespace,
        source,
        status.scan_started_at,
        receipt_window_days,
        manifest_source,
    )?;
    let request = collector_status_request(
        &destination_namespace,
        status,
        census_residue_status_admitted,
    )?;
    let journal_path = terminal_status_journal_path(support_dir, &destination_namespace, source);
    // Commit the exact typed receipt before it can reach the backend. A later
    // cycle-start or heartbeat therefore repeats one coherent scan result
    // instead of combining a fresh start/default counters with an old error.
    //
    // The ordering holds on the success path, but it is best-effort: the
    // journal is a local diagnostic artifact with no production reader, so a
    // full disk or an unwritable support dir must not suppress the terminal
    // report itself. Remote truth never waits on local disk; the failure is
    // disclosed on the daemon's error log instead.
    if let Err(error) = save_terminal_status_journal(&journal_path, &request) {
        eprintln!(
            "local snapshot terminal status journal write failed for {}: {}",
            source.api_slug(),
            safe_error(&error)
        );
    }
    client.report_status(&relay_token, &request)?;
    Ok(())
}

/// Post a non-terminal collector check-in receipt.
///
/// The receipt declares `report_kind: checkin`: it says "the collector is
/// alive" and nothing else. The backend bumps the server-received freshness
/// marker (and the scan-start marker when a cycle-start one is carried) while
/// preserving the previous terminal report's success evidence, error state, and
/// counters. Terminal reports stay the source of truth for scan outcomes.
///
/// The declaration is honest by construction, not by convention: this function
/// has no access to any scan outcome. It takes a source, a machine id, an
/// optional cycle-start clock, and the server's own width hint; every
/// scan-result field below is a literal absence or zero — census completeness
/// included, which is `None` here so it never reaches the wire at all — and the
/// only evidence
/// it forwards is the manifest witness the backend already accepted from the
/// last completed terminal report. `last_scan_finished_at` stays deliberately
/// absent so a backend that predates `report_kind` still infers the same
/// liveness classification from the shape.
///
/// That absence is also why this body must stay byte-identical to the shape the
/// backend classifies as a check-in (`last_scan_finished_at is None && enabled
/// && last_error_code is None && next_retry_at is None && consecutive_failures
/// == 0`). Replaying the journaled terminal receipt here — the local journal
/// `report_status_with_fresh_relay_token` writes — would silently retire
/// check-in receipts, make the cycle-start in-progress marker dead code, flip
/// manifest preservation to invalidation on every heartbeat while an error is
/// retained, and put a `scan_status` payload behind a `checkin` declaration.
fn report_checkin_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
    receipt_window_days: u64,
) -> Result<()> {
    let receipt_window_days = validated_receipt_window_days(receipt_window_days)?;
    let manifest = match cached_source_manifest(destination_namespace, source) {
        Some(manifest)
            if receipt_window_days > 0
                && snapshot_manifest_window_days(&manifest)? == receipt_window_days =>
        {
            Some(manifest)
        }
        Some(_) => {
            // A cached witness is usable only at the exact current hint width.
            // Withdrawing it prevents later heartbeats from repeating a stale
            // policy shape; the next complete terminal report can rebuild it.
            withdraw_source_manifest(destination_namespace, source);
            None
        }
        None => None,
    };
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: source.api_slug().to_string(),
        machine_id: machine_id.to_string(),
        // Liveness only. Both callers — the independent heartbeat and the
        // cycle-start in-progress marker — reach this one construction site,
        // and neither can supply a scan outcome to contradict the claim.
        report_kind: SnapshotStatusReportKind::Checkin,
        enabled: true,
        disabled_reason: None,
        last_scan_started_at: scan_started_at.map(str::to_string),
        last_scan_finished_at: None,
        last_success_at: None,
        last_error_code: None,
        last_error_message: None,
        last_uploaded_count: 0,
        last_scanned_session_count: 0,
        last_scanned_file_count: 0,
        last_zero_snapshot_confirmed_count: 0,
        last_zero_snapshot_usage_evidence_count: 0,
        last_dropped_usage_record_count: 0,
        last_ownership_incomplete_file_count: 0,
        last_snapshot_unproven_terminal_count: 0,
        last_snapshot_superseded_terminal_count: 0,
        last_backfill_window_days: receipt_window_days,
        last_backfill_file_limit: 0,
        last_discovered_file_count: 0,
        last_skipped_file_count_due_to_limit: 0,
        last_scan_cap_hit: false,
        last_semantic_noop_count: 0,
        // ABSENT, not `false`. A beat has run no census, and the backend
        // resolves an explicitly declared `false` by lowering the completeness
        // it already accepted while resolving an omitted one by retaining it.
        // Sending `false` here would retract a complete census on every
        // heartbeat; sending `true` would assert one it never measured.
        last_census_complete: None,
        last_symlink_rejected_count: 0,
        last_unreadable_path_count: 0,
        last_oversized_file_count: 0,
        last_disappeared_file_count: 0,
        last_malformed_json_line_count: 0,
        last_invalid_utf8_line_count: 0,
        last_over_line_cap_count: 0,
        last_recognized_usage_drop_count: 0,
        // Census evidence like the loss counters above; a beat measured none.
        last_terminal_ownership_incomplete_file_count: 0,
        last_terminal_zero_snapshot_usage_evidence_count: 0,
        last_terminal_recognized_usage_drop_count: 0,
        last_terminal_dropped_usage_record_count: 0,
        last_terminal_over_line_cap_count: 0,
        last_census_residue_settled: false,
        last_census_residue_index_key_count: 0,
        last_census_residue_archived_rollout_count: 0,
        last_census_residue_blocked_session_count: 0,
        consecutive_failures: 0,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(source.parser_version().to_string()),
        // The liveness-only shape carries the manifest deliberately: it is the
        // cheapest cadence the server gets it on, and a check-in that says
        // "alive" while the entity sets disagree is exactly the state the
        // manifest exists to expose.
        manifest,
    };
    client.report_status(relay_token, &request)?;
    Ok(())
}

fn report_checkin_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let receipt_window_days = current_receipt_window_days(client, &relay_token)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    report_checkin_status(
        client,
        &relay_token,
        &destination_namespace,
        source,
        machine_id,
        scan_started_at,
        receipt_window_days,
    )
}

/// Spawn the periodic non-terminal collector check-in heartbeat.
///
/// Terminal receipts track cycle completion, not liveness: the sync loop
/// sleeps a fixed interval AFTER each cycle and scans sources sequentially, so
/// a source's receipt can age by cycle_duration + interval — past the
/// backend's five-minute sources.status freshness promise — while the daemon
/// is healthy and actively uploading. This loop posts a cheap in-progress
/// status per enabled source on its own clock, independent of the sync cycle,
/// so the server-received check-in stays comfortably inside that promise even
/// during a multi-hour backlog drain.
pub fn spawn_collector_checkin_heartbeat() -> Result<()> {
    let phase_offset = local_cadence_phase_offset(COLLECTOR_CHECKIN_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-collector-checkin".to_string())
        .spawn(move || {
            std::thread::sleep(phase_offset);
            loop {
                if let Err(error) = collector_checkin_once() {
                    if !collector_checkin_can_wait_quietly(&error) {
                        eprintln!("collector check-in skipped: {}", safe_error(&error));
                    }
                }
                std::thread::sleep(COLLECTOR_CHECKIN_INTERVAL);
            }
        })
        .context("spawn collector check-in heartbeat")?;
    Ok(())
}

fn collector_checkin_once() -> Result<()> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let enabled_sources = enabled_snapshot_sources(&device);
    if enabled_sources.is_empty() {
        return Err(anyhow!("registered device has no enabled sources"));
    }
    let client = SnapshotApiClient::new(snapshot_api_base_url());
    let mut failed_sources = Vec::new();
    for source in enabled_sources {
        if report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            None,
        )
        .is_err()
        {
            failed_sources.push(source.api_slug());
        }
    }
    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "collector check-in failed for {} source(s)",
            failed_sources.len()
        ));
    }
    Ok(())
}

fn collector_checkin_can_wait_quietly(error: &anyhow::Error) -> bool {
    let safe = safe_error(error);
    matches!(
        safe.as_str(),
        "relay device credentials are unavailable" | "machine identity is unavailable"
    ) || error
        .to_string()
        .contains("registered device has no enabled sources")
}

pub(crate) fn enabled_snapshot_sources(device: &LocalDeviceBinding) -> Vec<SnapshotSource> {
    [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter(|source| {
        device
            .sources
            .iter()
            .any(|configured| configured == source.api_slug())
    })
    .collect()
}

pub(crate) fn snapshot_api_base_url() -> String {
    normalize_api_base_url(
        FileConnectionStore::default()
            .load()
            .ok()
            .flatten()
            .map(|binding| binding.api_base_url),
        std::env::var("OTTTO_API_BASE_URL").ok(),
    )
}

fn normalize_api_base_url(connection_value: Option<String>, env_value: Option<String>) -> String {
    connection_value
        .or(env_value)
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

pub(crate) fn snapshot_machine_id(device: &LocalDeviceBinding) -> Result<Option<String>> {
    if let Some(machine_id) = device.machine_id.as_ref().filter(|value| !value.is_empty()) {
        return Ok(Some(machine_id.clone()));
    }
    Ok(FileMachineStore::default()
        .load()?
        .map(|machine| machine.machine_id)
        .filter(|value| !value.is_empty()))
}

fn snapshot_upload_context_fingerprint(
    upload_policy: SnapshotUploadPolicy,
    attribution_checkpoint_namespace: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:snapshot-upload-context:v1\0");
    digest.update(serde_json::to_vec(&upload_policy).expect("upload policy is serializable"));
    digest.update(b"\0");
    digest.update(
        attribution_checkpoint_namespace
            .unwrap_or("none")
            .as_bytes(),
    );
    format!("{:x}", digest.finalize())
}

/// One destination-scoped index is shared by every privacy policy. The durable
/// upload-context witness inside the index forces a complete correction pass
/// whenever policy changes, including A→B→A. Keeping one file per policy made
/// the second transition reuse an old settled checkpoint and skip correction.
fn snapshot_index_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("snapshots")
        .join(format!("{}-scan-index.json", source.api_slug()))
}

fn legacy_policy_scoped_snapshot_index_path(
    support_dir: &Path,
    source: SnapshotSource,
    upload_policy: SnapshotUploadPolicy,
    attribution_checkpoint_namespace: Option<&str>,
) -> PathBuf {
    let mut suffixes: Vec<String> = Vec::new();
    if !upload_policy.session_titles_enabled {
        suffixes.push("no-titles".to_string());
    }
    if !upload_policy.workspace_labels_enabled {
        suffixes.push("no-labels".to_string());
    }
    // Artifacts are opt-in (default off), so the suffix marks the ENABLED state.
    // Enabling switches to the fresh `-artifacts` index, forcing a full re-scan
    // so existing/closed sessions retroactively gain artifacts. (Disabling
    // reverts to the base index; unchanged transcripts are not re-scanned, so
    // artifacts already uploaded persist on the backend until the file changes
    // — consistent with the titles/labels suffix behavior.)
    if upload_policy.session_artifacts_enabled {
        suffixes.push("artifacts".to_string());
    }
    // Attribution is opt-in. A separate index makes a later enablement revisit
    // unchanged transcripts instead of waiting for their next filesystem edit.
    // The namespace is key-epoch-only: scheduler inventory changes affect
    // sessions parsed from that point forward and require an explicit replay
    // for history. They must not silently invalidate every local checkpoint.
    if upload_policy.session_attribution_enabled {
        let namespace = attribution_checkpoint_namespace
            .map(str::to_string)
            .unwrap_or_else(|| "pending".to_string());
        suffixes.push(format!("attribution-{namespace}"));
    }
    // The capability changes only wire-safe display metadata, but it still
    // needs a fresh index so unchanged historical transcripts are revisited
    // once after backend support becomes available.
    if upload_policy.session_attribution_labels_enabled {
        suffixes.push("attribution-labels".to_string());
    }
    let policy_suffix = if suffixes.is_empty() {
        String::new()
    } else {
        format!("-{}", suffixes.join("-"))
    };
    support_dir.join("snapshots").join(format!(
        "{}-scan-index{}.json",
        source.api_slug(),
        policy_suffix
    ))
}

fn adopt_legacy_checkpoint_file(legacy_path: &Path, stable_path: &Path) -> Result<()> {
    if legacy_path == stable_path || stable_path.exists() || !legacy_path.exists() {
        return Ok(());
    }
    if let Some(parent) = stable_path.parent() {
        std::fs::create_dir_all(parent).context("create stable checkpoint directory")?;
    }
    // Adoption targets the same lock sibling used by scan-index/progress
    // load/save. Without it, two overlapping upgraded daemons can both observe
    // an absent stable path and a late legacy copy can overwrite the winner's
    // already-advanced CAS generation. Recheck after acquiring because another
    // process may have completed adoption between the optimistic check above
    // and this non-blocking lock attempt.
    let _lock = SnapshotProgressLock::acquire(stable_path)?;
    if stable_path.exists() || !legacy_path.exists() {
        return Ok(());
    }
    let temp_path = stable_path.with_extension(format!("json.{}.migrate", std::process::id()));
    let migration = (|| -> Result<()> {
        let mut source =
            std::fs::File::open(legacy_path).context("open legacy checkpoint for migration")?;
        let mut destination =
            std::fs::File::create(&temp_path).context("create stable checkpoint migration temp")?;
        std::io::copy(&mut source, &mut destination)
            .context("copy legacy checkpoint into stable namespace")?;
        destination
            .sync_all()
            .context("sync stable checkpoint migration temp")?;
        std::fs::rename(&temp_path, stable_path).context("publish stable checkpoint migration")?;
        if let Some(parent) = stable_path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("sync stable checkpoint migration directory")?;
        }
        Ok(())
    })();
    if migration.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    migration
}

fn snapshot_upload_progress_path(index_path: &Path) -> PathBuf {
    let stem = index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    index_path.with_file_name(format!("{stem}-upload-progress.json"))
}

fn snapshot_v2_index_path(v1_index_path: &Path) -> PathBuf {
    let stem = v1_index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    v1_index_path.with_file_name(format!("{stem}-v2.json"))
}

fn snapshot_v3_index_path(destination_index_path: &Path) -> PathBuf {
    let stem = destination_index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    destination_index_path.with_file_name(format!("{stem}-v3.json"))
}

fn snapshot_destination_scoped_index_path(
    policy_index_path: &Path,
    destination_namespace_hash: &str,
) -> PathBuf {
    let parent = policy_index_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = policy_index_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("snapshot-scan-index.json"));
    parent
        .join("destinations")
        .join(destination_namespace_hash)
        .join(file_name)
}

fn snapshot_upload_destination_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:snapshot-delivery-destination:relay-device:v1\0");
    hasher.update(device.device_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn ensure_snapshot_destination_current(expected_namespace_hash: &str) -> Result<()> {
    let (current_device, current_device_secret) =
        load_snapshot_device_credentials().map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "revalidate relay destination",
            })
        })?;
    validate_snapshot_destination(
        expected_namespace_hash,
        &current_device,
        &current_device_secret,
    )
}

fn validate_snapshot_destination(
    expected_namespace_hash: &str,
    current_device: &LocalDeviceBinding,
    current_device_secret: &str,
) -> Result<()> {
    if snapshot_upload_destination_namespace(current_device, current_device_secret)
        != expected_namespace_hash
    {
        return Err(anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "relay destination changed during snapshot sync",
        }));
    }
    Ok(())
}

pub(crate) fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

fn current_rfc3339() -> String {
    Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn rfc3339_after_minutes(minutes: i64) -> Option<String> {
    OffsetDateTime::now_utc()
        .checked_add(TimeDuration::minutes(minutes))
        .and_then(|value| value.format(&Rfc3339).ok())
}

/// Bounded, redacted cause for the catch-all snapshot upload failure log.
///
/// The catch-all arm has no status code of its own, so this reconstructs the
/// most specific failure shape still present in the error chain. Everything it
/// emits is either a typed redacted diagnostic (endpoint + status family, never
/// a URL or token) or one of this module's own compile-time reason literals —
/// never raw error text, which can carry file paths.
fn upload_failure_diagnostic(error: &anyhow::Error) -> String {
    if let Some(diagnostics) = error.downcast_ref::<UploadFailureDiagnostics>() {
        return diagnostics.safe_message();
    }
    if let Some(rejected) = error.downcast_ref::<BatchRejected>() {
        return format!(
            "endpoint=snapshot_batch, status={}, kind=payload_rejected, backend_detail={}",
            rejected.status,
            rejected
                .body_excerpt
                .as_deref()
                .unwrap_or("backend returned no validation detail"),
        );
    }
    if let Some(rejected) = error.downcast_ref::<BatchAuthorizationRejected>() {
        return format!(
            "endpoint=snapshot_batch, status={}, kind=authorization_rejected",
            rejected.status,
        );
    }
    if let Some(rejected) = error.downcast_ref::<SnapshotBatchPreflightRejected>() {
        return format!(
            "endpoint=snapshot_batch, kind=daemon_contract_preflight, detail={}",
            rejected.reason,
        );
    }
    if let Some(rejected) = error.downcast_ref::<SnapshotBatchResponseRejected>() {
        return format!(
            "endpoint=snapshot_batch, kind=response_count_mismatch, expected={}, accepted={}",
            rejected.expected, rejected.accepted,
        );
    }
    if let Some(rejected) = error.downcast_ref::<SnapshotLocalStateRejected>() {
        return format!("kind=local_state, operation={}", rejected.operation);
    }
    // This module's own upload-loop reasons. Matching on the literals keeps the
    // emitted text a fixed vocabulary rather than arbitrary chain content.
    let text = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    for reason in [
        "snapshot adaptive upload attempt limit reached",
        "snapshot adaptive upload split limit reached",
        "snapshot response uses an unsupported entity ACK contract",
        "local snapshot preflight index was out of bounds",
    ] {
        if text.contains(reason) {
            return format!("kind=uploader_guard, detail={reason}");
        }
    }
    "kind=unclassified (no typed diagnostic in the error chain)".to_string()
}

pub(crate) fn safe_error(error: &anyhow::Error) -> String {
    if let Some(diagnostics) = error.downcast_ref::<UploadFailureDiagnostics>() {
        return diagnostics.safe_message();
    }
    if error
        .downcast_ref::<SnapshotEntityConflictDeferred>()
        .is_some()
    {
        return "local snapshot upload deferred by entity conflict".to_string();
    }
    match snapshot_upload_error_class(error) {
        Some(SnapshotUploadErrorClass::LocalState) => {
            return "local snapshot state failed".to_string();
        }
        Some(SnapshotUploadErrorClass::BackendResponse) => {
            return "backend snapshot response was invalid".to_string();
        }
        None => {}
    }
    // Scan the whole context chain, not just the outermost message, so a known
    // failure phrase wrapped under another context still classifies instead of
    // collapsing to the undiagnosable bare "sync failed".
    let text = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    if text.contains("relay device") {
        "relay device credentials are unavailable".to_string()
    } else if text.contains("machine identity") {
        "machine identity is unavailable".to_string()
    } else if text.contains("issue relay token failed") {
        "relay token request failed".to_string()
    } else if text.contains("backend rejected local health projection") {
        "local health projection rejected".to_string()
    } else if text.contains("backend rejected local health authorization") {
        "local health authorization rejected".to_string()
    } else if text.contains("get activity hint failed") {
        "activity hint request failed".to_string()
    } else if text.contains("upload agent status failed")
        || text.contains("agent status upload failed")
    {
        "agent status upload failed".to_string()
    } else if text.contains("scan local snapshots") {
        "local snapshot scan failed".to_string()
    } else if text.contains("daemon/backend contract preflight")
        || text.contains("backend rejected snapshot batch payload")
    {
        "local snapshot payload validation failed".to_string()
    } else if text.contains("snapshot adaptive upload attempt limit reached")
        || text.contains("snapshot adaptive upload split limit reached")
    {
        // Distinct from a network failure: the page reached the backend and the
        // uploader exhausted its bounded poison-isolation budget. Collapsing
        // this into the generic upload message hid a whole failure family.
        "local snapshot upload isolation limit reached".to_string()
    } else if text.contains("snapshot response uses an unsupported entity ACK contract") {
        "backend snapshot response was invalid".to_string()
    } else if text.contains("upload local snapshots")
        || text.contains("upload snapshot batch failed")
    {
        "local snapshot upload failed".to_string()
    } else if text.contains("report snapshot status failed") {
        "local collector status upload failed".to_string()
    } else if text.contains("mcp inventory")
        || text.contains("mcp handshake")
        || text.contains("mcp server")
    {
        "mcp inventory sync failed".to_string()
    } else if text.contains("backend rejected context footprint") {
        "context footprint upload rejected".to_string()
    } else if text.contains("context footprint") {
        "context footprint upload failed".to_string()
    } else if text.contains("response failed") {
        // "parse <endpoint> response failed" family: the request went through
        // but the backend reply didn't decode.
        "backend response was invalid".to_string()
    } else {
        "sync failed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlToken;
    use ottto_core::{
        FileDeviceStore, LocalConnectionBinding, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
        OTTTO_SECRET_FALLBACK_DIR_ENV, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
    };
    use ottto_protocol::{
        AgentAccountStatus, AgentLoginState, AgentStatusCollectionMethod, AgentStatusConfidence,
        AgentStatusState, MachineIdentity, OperatingSystem,
    };
    use serial_test::serial;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    struct SourceManifestTestGuard;

    fn test_terminal_status_support_dir() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            std::env::temp_dir().join(format!(
                "ottto-terminal-status-tests-{}",
                std::process::id()
            ))
        })
        .as_path()
    }

    impl SourceManifestTestGuard {
        fn new() -> Self {
            clear_source_manifests_for_test();
            let _ = std::fs::remove_dir_all(test_terminal_status_support_dir());
            Self
        }
    }

    impl Drop for SourceManifestTestGuard {
        fn drop(&mut self) {
            clear_source_manifests_for_test();
            let _ = std::fs::remove_dir_all(test_terminal_status_support_dir());
        }
    }

    fn test_fingerprints(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    static TEST_POISON_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn partial_curve_replay_page_keeps_historical_epoch_pending() {
        let mut index = ScanIndex::default();
        let generation = "session_context_curve:v1:parser-test";

        assert!(index.context_curve_replay_needed(generation));
        settle_context_curve_replay_state(&mut index, true, false, generation);
        assert!(index.context_curve_replay_needed(generation));

        settle_context_curve_replay_state(&mut index, true, true, generation);
        assert!(!index.context_curve_replay_needed(generation));
    }

    #[test]
    fn collision_suppressed_codex_rollout_is_not_upload_reachable() {
        let root = test_dir("collision-suppressed-codex-upload");
        let codex_dir = root.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir).expect("create collision upload fixture");
        let session_id = "01a03e99-49cf-7460-9fd7-f7dbfd2f05e4";
        let alias = session_id.to_ascii_uppercase();
        let database = rusqlite::Connection::open(codex_dir.join("state_5.sqlite"))
            .expect("open collision upload state");
        database
            .execute_batch(
                "CREATE TABLE threads (\
                    id TEXT NOT NULL, title TEXT, tokens_used INTEGER NOT NULL,\
                    thread_source TEXT, first_user_message TEXT\
                );",
            )
            .expect("create collision upload table");
        for (id, title) in [(session_id, "Lower"), (alias.as_str(), "Upper")] {
            database
                .execute(
                    "INSERT INTO threads VALUES (?1, ?2, 1, 'agent_created_thread', NULL)",
                    rusqlite::params![id, title],
                )
                .expect("insert collision upload row");
        }
        drop(database);
        std::fs::write(
            sessions_dir.join(format!("rollout-{session_id}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-08-29T12:00:00Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{session_id}\",\"session_id\":\"{session_id}\",\"history_mode\":\"paginated\",\"history_base\":{{\"cursor\":\"file-controlled\"}}}}}}\n\
                 {{\"timestamp\":\"2026-08-29T12:00:01Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"collision-turn\",\"model\":\"gpt-5.6-sol\"}}}}\n\
                 {{\"timestamp\":\"2026-08-29T12:00:02Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":30,\"cached_input_tokens\":8,\"output_tokens\":12,\"reasoning_output_tokens\":1}},\"last_token_usage\":{{\"input_tokens\":30,\"cached_input_tokens\":8,\"output_tokens\":12,\"reasoning_output_tokens\":1}},\"model\":\"gpt-5.6-sol\"}}}}}}\n"
            ),
        )
        .expect("write collision upload rollout");

        let mut index = ScanIndex::default();
        let scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&sessions_dir),
            &mut index,
            "2026-08-29T12:30:00Z",
            183,
            10,
            true,
        )
        .expect("scan collision upload fixture");
        assert_eq!(scan.discovered_file_count, 1);
        assert_eq!(scan.scanned_file_count, 1);
        assert_eq!(scan.scanned_session_count, 0);
        assert!(scan.snapshots.is_empty());
        assert_eq!(scan.recognized_usage_drop_count, 1);
        assert_eq!(scan.ownership_incomplete_file_count, 1);
        assert_eq!(scan.dropped_usage_record_count, 1);

        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut upload_calls = 0;
        let result = upload_resumable_batches(
            &scan.snapshots,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            |batch| {
                upload_calls += 1;
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("empty suppressed workset settles without upload");
        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(upload_calls, 0);
        assert_eq!(accepted, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn claude_refresh_hook_coalesces_and_raii_releases() {
        reset_claude_refresh_activity();
        let mut first = claim_claude_refresh_slot().expect("first hook claim");
        assert!(claim_claude_refresh_slot().is_none());
        assert!(claim_claude_refresh_slot().is_none());
        assert!(
            first.take_pending_or_finish(),
            "triggers during startup queue one trailing wake run"
        );
        assert!(
            !first.take_pending_or_finish(),
            "trailing run drains pending"
        );
        let after_drop = claim_claude_refresh_slot().expect("RAII releases hook claim");
        drop(after_drop);
        assert!(claim_claude_refresh_slot().is_some());
        reset_claude_refresh_activity();
    }

    /// A unique poison-ledger scope per call, so tests that run in parallel
    /// cannot prune each other's ledgers.
    fn unique_poison_scope() -> String {
        format!(
            "test-scope-{}",
            TEST_POISON_SCOPE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    fn test_upload_progress() -> SnapshotUploadProgress {
        SnapshotUploadProgress::new(
            format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
    }

    #[test]
    fn curve_ack_retry_checkpoints_released_witness_then_becomes_noop() {
        let root = test_dir("curve-ack-retry-checkpoint");
        std::fs::create_dir_all(&root).expect("create curve snapshot fixture root");
        let path = root.join("curve-session.jsonl");
        std::fs::write(
            &path,
            "{\"timestamp\":\"2026-08-30T12:00:00Z\",\"sessionId\":\"curve-session\",\"requestId\":\"req-1\",\"message\":{\"id\":\"msg-1\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":42,\"output_tokens\":1}}}\n",
        )
        .expect("write curve snapshot fixture");
        let mut index = ScanIndex::default();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            "2026-08-30T12:05:00Z",
            183,
            10,
            true,
        )
        .expect("scan curve snapshot fixture");
        assert_eq!(scan.snapshots.len(), 1);
        let item = &mut scan.snapshots[0];
        item.context_curve = Some(crate::snapshots::SnapshotContextCurve {
            contract_version: CONTEXT_CURVE_CONTRACT_VERSION.to_string(),
            parser_revision: "claude_code_jsonl:v28".to_string(),
            ownership_revision: "claude_owned_request_start_proof:v1".to_string(),
            sampling_revision: "context_curve_sampling:v1".to_string(),
            coverage: "complete".to_string(),
            total_owned_request_count: 1,
            retained_point_count: 1,
            total_compaction_boundary_count: 0,
            retained_boundary_count: 0,
            points: vec![crate::snapshots::SnapshotContextCurvePoint {
                owned_request_ordinal: 1,
                observed_at: "2026-08-30T12:00:00Z".to_string(),
                effective_input_tokens: 42,
                model_window_index: 0,
                segment_ordinal: 0,
                retention_flags: 1,
                compaction_before_request_boundary_index: None,
                compaction_after_request_boundary_index: None,
            }],
            boundaries: Vec::new(),
            model_windows: vec![crate::snapshots::SnapshotContextCurveModelWindow {
                model_window_index: 0,
                model: "claude-opus-4-8".to_string(),
                context_window_tokens: None,
                evidence_kind: "unavailable".to_string(),
                evidence_revision: "claude_transcript_model:v1".to_string(),
            }],
        });
        let items = scan.snapshots;
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let first = upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |_| Err(anyhow!("response lost after durable remote write")),
            |_| Ok(()),
        );
        first.expect_err("lost response cannot advance local checkpoint");
        assert!(progress.accepted_fingerprints.is_empty());

        let mut retry_calls = 0;
        upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |batch| {
                retry_calls += 1;
                let request = SnapshotBatchRequest {
                    schema_version: SNAPSHOT_SCHEMA_VERSION,
                    source: "claude_code".to_string(),
                    machine_id: "machine".to_string(),
                    collector_version: None,
                    snapshots: batch,
                    upload_policy: SnapshotUploadPolicy::default(),
                    client_report: crate::client_report::ClientReport::empty(),
                };
                let uploaded = &request.snapshots[0];
                let response = crate::snapshot_client::SnapshotBatchResponse {
                    accepted: 1,
                    sessions_reconciled: 0,
                    session_ids: Vec::new(),
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: Some(
                        crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                    ),
                    accepted_entities: Vec::new(),
                    unchanged_entities: vec![crate::snapshot_client::SnapshotEntityRef {
                        source_session_id: uploaded.source_session_id.clone(),
                        snapshot_fingerprint: uploaded.snapshot_fingerprint.clone(),
                        occurrence_count: 1,
                        body_witness_version: Some(5),
                        body_witness_digest: Some(snapshot_upload_body_witness(uploaded)),
                        head_etag: None,
                        head_challenge: None,
                    }],
                    rejected_entities: Vec::new(),
                    conflict_entities: Vec::new(),
                };
                response.validate_entity_ack(&request)?;
                Ok(response)
            },
            |_| Ok(()),
        )
        .expect("released v5 unchanged ACK settles curve checkpoint");
        assert_eq!(retry_calls, 1);
        assert!(progress.contains_body(
            &items[0].snapshot_fingerprint,
            &snapshot_upload_body_witness(&items[0])
        ));

        let mut noop_calls = 0;
        upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |_| {
                noop_calls += 1;
                Ok(accepted_batch(1))
            },
            |_| Ok(()),
        )
        .expect("settled curve is a durable no-op");
        assert_eq!(noop_calls, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replay_generation_reuploads_prior_acks_once_and_resumes_its_own_progress() {
        let poison_scope = &unique_poison_scope();
        let root = test_dir("snapshot-replay-generation-progress");
        let path = root.join("codex-scan-index-v3-upload-progress.json");
        let items = test_fingerprints(2);
        let destination = format!("{:064x}", 99);
        let old_generation = format!("codex:codex_session_exclusive_usage:v2:{destination}");
        let new_generation = format!("codex:codex_session_exclusive_usage:v3:{destination}");

        // Model the exact pre-change v3 file from the admission gap: it has no
        // replay-generation field, one current entity was ACKed, and another
        // was quarantined while both backend heads still need replacement.
        let mut progress = test_upload_progress();
        progress.record([items[0].as_str()]);
        progress.quarantine([items[1].as_str()]);
        let mut old_index = ScanIndex::default();
        old_index.prepare_historical_replay(old_generation);
        old_index.file_snapshot_fingerprints.insert(
            "old-generation.jsonl".to_string(),
            BTreeSet::from([items[1].clone()]),
        );
        old_index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        let mut current_v3 = serde_json::to_value(&progress).expect("serialize v3 progress");
        current_v3
            .as_object_mut()
            .expect("progress is an object")
            .remove("historical_replay_generation");
        std::fs::create_dir_all(&root).expect("create progress fixture directory");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&current_v3).expect("serialize pre-change v3 progress"),
        )
        .expect("save pre-change v3 progress");

        let mut rearmed = SnapshotUploadProgress::load(
            &path,
            &destination,
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .expect("load pre-change v3 progress");
        assert!(rearmed.historical_replay_generation.is_none());
        assert!(prepare_upload_progress_for_cycle(
            &mut rearmed,
            &old_index,
            &new_generation,
            true,
        ));
        assert!(rearmed.accepted_fingerprints.is_empty());
        assert!(rearmed.quarantined_fingerprints.is_empty());
        rearmed
            .save(&path)
            .expect("persist replay rearm before scan");

        let mut accepted = 0;
        let mut upload_calls = 0;
        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut rearmed,
            &mut accepted,
            String::as_str,
            |batch| {
                upload_calls += 1;
                assert_eq!(batch, items);
                Ok(accepted_batch(batch.len()))
            },
            |state| state.save(&path),
        )
        .expect("new replay uploads every prior old-generation entity");
        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!((upload_calls, accepted), (1, 2));

        let mut resumed = SnapshotUploadProgress::load(
            &path,
            &destination,
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .expect("reload new replay progress");
        assert!(!resumed.prepare_historical_replay(&new_generation));
        let mut resumed_accepted = 0;
        let mut resumed_upload_calls = 0;
        let resumed_result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut resumed,
            &mut resumed_accepted,
            String::as_str,
            |_| {
                resumed_upload_calls += 1;
                Ok(accepted_batch(0))
            },
            |state| state.save(&path),
        )
        .expect("same replay generation resumes from its durable ACKs");
        assert_eq!(resumed_result, ResumableUploadResult::Completed);
        assert_eq!((resumed_upload_calls, resumed_accepted), (0, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial(client_report)]
    fn same_replay_generation_restores_cleared_conflict_progress_until_retry() {
        use crate::client_report::reset_for_test;

        reset_for_test();
        let poison_scope = unique_poison_scope();
        let root = test_dir("snapshot-replay-conflict-progress-restore");
        let index_path = root.join("codex-scan-index-v3.json");
        let progress_path = snapshot_upload_progress_path(&index_path);
        let destination = format!("{:064x}", 99);
        let replay_generation = format!("codex:codex_session_exclusive_usage:v3:{destination}");
        let conflicted_fingerprint = test_fingerprints(1).remove(0);

        let mut index = ScanIndex::default();
        index.prepare_historical_replay(replay_generation.clone());
        index.file_snapshot_fingerprints.insert(
            "conflicted.jsonl".to_string(),
            BTreeSet::from([conflicted_fingerprint.clone()]),
        );

        let mut progress = test_upload_progress();
        assert!(progress.prepare_historical_replay(&replay_generation));
        let mut accepted = 0;
        let result = upload_resumable_batches(
            std::slice::from_ref(&conflicted_fingerprint),
            &poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| {
                Ok(crate::snapshot_client::SnapshotBatchResponse {
                    accepted: 0,
                    sessions_reconciled: 0,
                    session_ids: Vec::new(),
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: Some(
                        crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                    ),
                    accepted_entities: Vec::new(),
                    unchanged_entities: Vec::new(),
                    rejected_entities: Vec::new(),
                    conflict_entities: vec![crate::snapshot_client::SnapshotEntityRef {
                        source_session_id: "conflicted".to_string(),
                        snapshot_fingerprint: conflicted_fingerprint.clone(),
                        occurrence_count: 1,
                        body_witness_version: None,
                        body_witness_digest: None,
                        head_etag: None,
                        head_challenge: None,
                    }],
                })
            },
            |state| state.save(&progress_path),
        )
        .expect("conflict remains retryable");
        assert_eq!(result, ResumableUploadResult::Conflicted { count: 1 });
        assert_eq!(accepted, 0);

        index.mark_bounded_sweep_unsettled();
        index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        index.save(&index_path).expect("persist conflicted index");
        progress
            .clear(&progress_path)
            .expect("completed conflict cycle clears disposable progress");

        let persisted_index = ScanIndex::load(&index_path).expect("reload conflicted index");
        let mut restored = SnapshotUploadProgress::load(
            &progress_path,
            &destination,
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .expect("load cleared progress");
        assert!(prepare_upload_progress_for_cycle(
            &mut restored,
            &persisted_index,
            &replay_generation,
            true,
        ));
        assert!(
            restored
                .quarantined_fingerprints
                .contains_key(&conflicted_fingerprint),
            "same-generation historical preparation must restore index-owned conflict"
        );
        restored
            .save(&progress_path)
            .expect("persist restored same-generation conflict");
        restored
            .clear(&progress_path)
            .expect("model another completed follow-up cycle");

        let mut due_index = persisted_index;
        due_index
            .quarantined_snapshot_fingerprints
            .get_mut(&conflicted_fingerprint)
            .expect("conflict remains in index")
            .retry_after_unix_seconds = 0;
        due_index.save(&index_path).expect("persist due conflict");

        let due_index = ScanIndex::load(&index_path).expect("reload due conflict index");
        let mut retry_progress = SnapshotUploadProgress::load(
            &progress_path,
            &destination,
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .expect("load progress for due retry");
        assert!(prepare_upload_progress_for_cycle(
            &mut retry_progress,
            &due_index,
            &replay_generation,
            true,
        ));
        assert!(
            !retry_progress.contains(&conflicted_fingerprint),
            "due same-generation conflict must be released for upload retry"
        );

        let mut retry_accepted = 0;
        let mut retry_uploads = 0;
        let retry_result = upload_resumable_batches(
            std::slice::from_ref(&conflicted_fingerprint),
            &poison_scope,
            &mut retry_progress,
            &mut retry_accepted,
            String::as_str,
            |batch| {
                retry_uploads += 1;
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("due same-generation conflict is retried");
        assert_eq!(retry_result, ResumableUploadResult::Completed);
        assert_eq!((retry_uploads, retry_accepted), (1, 1));

        let _ = std::fs::remove_dir_all(root);
        reset_for_test();
    }

    #[derive(Clone, Serialize)]
    struct BodyWitnessTestItem {
        snapshot_fingerprint: String,
        body_revision: String,
    }

    #[test]
    fn resumable_progress_tracks_hash_neutral_body_corrections() {
        let fingerprint = format!("{:064x}", 42);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut uploads = Vec::new();
        let mut run =
            |body_revision: &str, progress: &mut SnapshotUploadProgress, accepted: &mut u64| {
                let item = BodyWitnessTestItem {
                    snapshot_fingerprint: fingerprint.clone(),
                    body_revision: body_revision.to_string(),
                };
                upload_resumable_batches_with_body_witness(
                    &[item],
                    &unique_poison_scope(),
                    progress,
                    accepted,
                    |item| item.snapshot_fingerprint.as_str(),
                    |item| format!("{:064x}", if item.body_revision == "a" { 10 } else { 11 }),
                    |batch| {
                        uploads.push(batch[0].body_revision.clone());
                        Ok(accepted_batch(batch.len()))
                    },
                    |_| Ok(()),
                )
                .expect("body-witness upload")
            };

        assert_eq!(
            run("a", &mut progress, &mut accepted),
            ResumableUploadResult::Completed
        );
        assert_eq!(
            run("a", &mut progress, &mut accepted),
            ResumableUploadResult::Completed
        );
        assert_eq!(
            run("b", &mut progress, &mut accepted),
            ResumableUploadResult::Completed
        );
        assert_eq!(
            run("a", &mut progress, &mut accepted),
            ResumableUploadResult::Completed
        );
        assert_eq!(uploads, ["a", "b", "a"]);
        assert_eq!(accepted, 3);
        assert_eq!(
            progress.accepted_fingerprints,
            BTreeSet::from([fingerprint])
        );

        let mut corrected_progress = test_upload_progress();
        let witness_a = format!("{:064x}", 10);
        let witness_b = format!("{:064x}", 11);
        corrected_progress.quarantine_body(&format!("{:064x}", 42), &witness_a);
        assert!(corrected_progress.contains_body(&format!("{:064x}", 42), &witness_a));
        assert!(
            !corrected_progress.contains_body(&format!("{:064x}", 42), &witness_b),
            "a corrected hash-neutral body bypasses the old body's quarantine"
        );
        let mut corrected_accepted = 0;
        let mut corrected_uploads = 0;
        let corrected_item = BodyWitnessTestItem {
            snapshot_fingerprint: format!("{:064x}", 42),
            body_revision: "b".to_string(),
        };
        upload_resumable_batches_with_body_witness(
            &[corrected_item],
            &unique_poison_scope(),
            &mut corrected_progress,
            &mut corrected_accepted,
            |item| item.snapshot_fingerprint.as_str(),
            |_| witness_b.clone(),
            |batch| {
                corrected_uploads += 1;
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("corrected body bypasses quarantine");
        assert_eq!((corrected_uploads, corrected_accepted), (1, 1));
    }

    #[test]
    fn resumable_progress_rejects_conflicting_bodies_for_one_semantic_entity() {
        let fingerprint = format!("{:064x}", 42);
        let items = [
            BodyWitnessTestItem {
                snapshot_fingerprint: fingerprint.clone(),
                body_revision: "a".to_string(),
            },
            BodyWitnessTestItem {
                snapshot_fingerprint: fingerprint,
                body_revision: "b".to_string(),
            },
        ];
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut uploads = 0;
        let error = upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            |item| format!("{:064x}", if item.body_revision == "a" { 10 } else { 11 }),
            |batch| {
                uploads += 1;
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect_err("conflicting bodies fail before upload");
        assert!(error
            .to_string()
            .contains("resolve conflicting snapshot body witnesses"));
        assert_eq!((uploads, accepted), (0, 0));
        assert!(progress.accepted_fingerprints.is_empty());
    }

    fn test_quarantine_witness() -> SnapshotQuarantineWitness {
        snapshot_quarantine_witness(SnapshotSource::Codex)
    }

    fn accepted_batch(count: usize) -> crate::snapshot_client::SnapshotBatchResponse {
        crate::snapshot_client::SnapshotBatchResponse {
            accepted: count as u64,
            sessions_reconciled: count as u64,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
            entity_ack_contract: None,
            accepted_entities: Vec::new(),
            unchanged_entities: Vec::new(),
            rejected_entities: Vec::new(),
            conflict_entities: Vec::new(),
        }
    }

    fn entity_ack_ref(fingerprint: &str) -> crate::snapshot_client::SnapshotEntityRef {
        crate::snapshot_client::SnapshotEntityRef {
            source_session_id: format!("session-{fingerprint}"),
            snapshot_fingerprint: fingerprint.to_string(),
            occurrence_count: 1,
            body_witness_version: None,
            body_witness_digest: None,
            head_etag: None,
            head_challenge: None,
        }
    }

    fn entity_ack_batch(
        accepted: &[String],
        unchanged: &[String],
        conflicted: &[String],
    ) -> crate::snapshot_client::SnapshotBatchResponse {
        crate::snapshot_client::SnapshotBatchResponse {
            accepted: accepted.len().saturating_add(unchanged.len()) as u64,
            sessions_reconciled: accepted.len().saturating_add(unchanged.len()) as u64,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
            entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string()),
            accepted_entities: accepted
                .iter()
                .map(|fingerprint| entity_ack_ref(fingerprint))
                .collect(),
            unchanged_entities: unchanged
                .iter()
                .map(|fingerprint| entity_ack_ref(fingerprint))
                .collect(),
            rejected_entities: Vec::new(),
            conflict_entities: conflicted
                .iter()
                .map(|fingerprint| entity_ack_ref(fingerprint))
                .collect(),
        }
    }

    #[test]
    fn snapshot_upload_batches_enforce_the_entity_count_bound() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(101);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut chunk_lengths = Vec::new();

        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                chunk_lengths.push(batch.len());
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("upload succeeds");

        assert_eq!(SNAPSHOT_BATCH_LIMIT, 50);
        assert_eq!(chunk_lengths, vec![50, 50, 1]);
        assert!(chunk_lengths
            .iter()
            .all(|length| *length <= SNAPSHOT_BATCH_LIMIT));
        assert_eq!(accepted, 101);
        assert_eq!(result, ResumableUploadResult::Completed);
    }

    #[test]
    fn resumable_upload_rejects_unknown_ack_contract_before_progress_advances() {
        let items = test_fingerprints(1);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let error = upload_resumable_batches(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                let mut response = accepted_batch(batch.len());
                response.entity_ack_contract = Some("snapshot_entity_ack:v999".to_string());
                Ok(response)
            },
            |_| Ok(()),
        )
        .expect_err("unsupported ACK shapes cannot settle local progress");

        assert!(error
            .to_string()
            .contains("unsupported entity ACK contract"));
        assert_eq!(accepted, 0);
        assert!(progress.accepted_fingerprints.is_empty());
    }

    #[test]
    #[serial(client_report)]
    fn entity_ack_rejection_counts_one_poison_after_durable_quarantine() {
        use crate::client_report::{observe, reset_for_test, ClientReportReason};

        reset_for_test();
        let poison_scope = unique_poison_scope();
        let items = test_fingerprints(2);
        let accepted_fingerprint = items[0].clone();
        let rejected_fingerprint = items[1].clone();
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let result = upload_resumable_batches(
            &items,
            &poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| {
                Ok(crate::snapshot_client::SnapshotBatchResponse {
                    accepted: 1,
                    sessions_reconciled: 1,
                    session_ids: Vec::new(),
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: Some(
                        crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                    ),
                    accepted_entities: vec![crate::snapshot_client::SnapshotEntityRef {
                        source_session_id: "accepted".to_string(),
                        snapshot_fingerprint: accepted_fingerprint.clone(),
                        occurrence_count: 1,
                        body_witness_version: None,
                        body_witness_digest: None,
                        head_etag: None,
                        head_challenge: None,
                    }],
                    unchanged_entities: Vec::new(),
                    rejected_entities: vec![crate::snapshot_client::SnapshotEntityRejection {
                        source_session_id: "rejected".to_string(),
                        snapshot_fingerprint: rejected_fingerprint.clone(),
                        reason: "invalid".to_string(),
                        detail: "permanent validation failure".to_string(),
                        permanent: true,
                        occurrence_count: 1,
                    }],
                    conflict_entities: Vec::new(),
                })
            },
            |_| Ok(()),
        )
        .expect("permanent entity rejection is durably settled");

        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(accepted, 1);
        assert!(progress
            .accepted_fingerprints
            .contains(&accepted_fingerprint));
        assert!(progress
            .quarantined_fingerprints
            .contains_key(&rejected_fingerprint));
        assert_eq!(observe().quantity(ClientReportReason::Poisoned), 1);
        assert_eq!(
            counted_poison_fingerprints_for_test(&poison_scope),
            BTreeSet::from([rejected_fingerprint])
        );
        reset_for_test();
    }

    /// A conflicting entity must not strand its accepted siblings or later pages.
    ///
    /// Regression for the per-source starvation wedge: the uploader used to
    /// return the moment `conflict_entities` was non-empty, before recording the
    /// entities the backend had already written in that response and before
    /// visiting the next fingerprint-sorted page. A persistent capacity conflict
    /// therefore replayed its accepted siblings and starved every later entity on
    /// the source at the five-minute cadence.
    #[test]
    #[serial(client_report)]
    fn entity_ack_conflict_checkpoints_siblings_drains_later_batch_and_clears_on_revision() {
        use crate::client_report::{observe, reset_for_test, ClientReportReason};

        reset_for_test();
        let poison_scope = unique_poison_scope();
        let items = test_fingerprints(SNAPSHOT_BATCH_LIMIT + 1);
        let first_batch = items[..SNAPSHOT_BATCH_LIMIT].to_vec();
        let later_batch = items[SNAPSHOT_BATCH_LIMIT..].to_vec();
        let conflicted_fingerprint = first_batch[0].clone();
        let first_accepted = first_batch[1..SNAPSHOT_BATCH_LIMIT / 2].to_vec();
        let first_unchanged = first_batch[SNAPSHOT_BATCH_LIMIT / 2..].to_vec();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut uploaded_batches = Vec::new();
        let mut persisted = Vec::new();

        let result = upload_resumable_batches(
            &items,
            &poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                uploaded_batches.push(batch.clone());
                if uploaded_batches.len() == 1 {
                    Ok(entity_ack_batch(
                        &first_accepted,
                        &first_unchanged,
                        std::slice::from_ref(&conflicted_fingerprint),
                    ))
                } else {
                    Ok(entity_ack_batch(&batch, &[], &[]))
                }
            },
            |state| {
                persisted.push(state.clone());
                Ok(())
            },
        )
        .expect("a per-entity conflict is retryable, not a whole-page failure");

        assert_eq!(result, ResumableUploadResult::Conflicted { count: 1 });
        assert_eq!(uploaded_batches, vec![first_batch.clone(), later_batch]);
        assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
        assert_eq!(persisted.len(), 2);
        assert!(first_accepted
            .iter()
            .chain(&first_unchanged)
            .all(|fingerprint| persisted[0].accepted_fingerprints.contains(fingerprint)));
        assert!(persisted[0]
            .quarantined_fingerprints
            .contains_key(&conflicted_fingerprint));
        assert!(!progress
            .accepted_fingerprints
            .contains(&conflicted_fingerprint));
        assert!(progress
            .quarantined_fingerprints
            .contains_key(&conflicted_fingerprint));
        assert!(progress
            .accepted_fingerprints
            .contains(&items[SNAPSHOT_BATCH_LIMIT]));

        let deferred = snapshot_entity_conflict_deferred(1);
        assert_eq!(
            deferred
                .downcast_ref::<SnapshotEntityConflictDeferred>()
                .map(|error| error.count),
            Some(1)
        );
        assert_eq!(
            safe_error(&deferred),
            "local snapshot upload deferred by entity conflict"
        );

        // Model the next authoritative scan replacing the oversized canonical
        // body with a fitting revision. The old fingerprint disappears, so its
        // retry becomes an explicit superseded terminal before the replacement
        // is uploaded and settled.
        let replacement_fingerprint = format!("{:064x}", SNAPSHOT_BATCH_LIMIT + 1000);
        let mut revised_items = items[1..].to_vec();
        revised_items.push(replacement_fingerprint.clone());
        let revised_fingerprints = revised_items.iter().cloned().collect::<BTreeSet<_>>();
        assert!(progress.retain_current_quarantines(&revised_fingerprints));
        let mut revision_accepted = 0;
        let mut revision_uploads = Vec::new();
        let revision_result = upload_resumable_batches(
            &revised_items,
            &poison_scope,
            &mut progress,
            &mut revision_accepted,
            String::as_str,
            |batch| {
                revision_uploads.push(batch.clone());
                Ok(entity_ack_batch(&batch, &[], &[]))
            },
            |_| Ok(()),
        )
        .expect("a fitting replacement revision clears the conflict");

        assert_eq!(revision_result, ResumableUploadResult::Completed);
        assert_eq!(
            revision_uploads,
            vec![vec![replacement_fingerprint.clone()]]
        );
        assert_eq!(revision_accepted, 1);
        assert_eq!(progress.quarantined_fingerprints.len(), 1);
        assert_eq!(
            progress.quarantined_fingerprints[&conflicted_fingerprint].disposition,
            SnapshotQuarantineDisposition::SupersededTerminal
        );
        assert!(progress
            .accepted_fingerprints
            .contains(&replacement_fingerprint));
        assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
        assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
        reset_for_test();
    }

    #[test]
    fn entity_ack_all_conflict_page_stays_pending_and_surfaces_deferred_error() {
        let items = test_fingerprints(3);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut persisted = Vec::new();

        let result = upload_resumable_batches(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| Ok(entity_ack_batch(&[], &[], &batch)),
            |state| {
                persisted.push(state.clone());
                Ok(())
            },
        )
        .expect("an all-conflict page remains retryable");

        assert_eq!(result, ResumableUploadResult::Conflicted { count: 3 });
        assert_eq!(accepted, 0);
        assert!(progress.accepted_fingerprints.is_empty());
        assert_eq!(
            progress
                .quarantined_fingerprints
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            items.iter().cloned().collect()
        );
        assert_eq!(persisted.last(), Some(&progress));

        let deferred = snapshot_entity_conflict_deferred(3);
        assert_eq!(
            deferred
                .downcast_ref::<SnapshotEntityConflictDeferred>()
                .map(|error| error.count),
            Some(3)
        );
    }

    #[test]
    fn unchanged_conflict_is_unproven_terminal_on_fourth_failure_and_body_change_recovers() {
        let fingerprint = "f".repeat(64);
        let item = BodyWitnessTestItem {
            snapshot_fingerprint: fingerprint.clone(),
            body_revision: "a".to_string(),
        };
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut upload_count = 0;

        for expected_failure_count in 1..=MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
            if expected_failure_count > 1 {
                progress
                    .quarantined_fingerprints
                    .get_mut(&fingerprint)
                    .expect("retry remains accounted")
                    .retry_after_unix_seconds = 0;
                assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
            }
            let result = upload_resumable_batches_with_body_witness(
                std::slice::from_ref(&item),
                &unique_poison_scope(),
                &mut progress,
                &mut accepted,
                |item| item.snapshot_fingerprint.as_str(),
                |_| "a".repeat(64),
                |batch| {
                    upload_count += 1;
                    Ok(entity_ack_batch(
                        &[],
                        &[],
                        &[batch[0].snapshot_fingerprint.clone()],
                    ))
                },
                |_| Ok(()),
            )
            .expect("conflict remains an explicit outcome");
            assert_eq!(result, ResumableUploadResult::Conflicted { count: 1 });
            let record = &progress.quarantined_fingerprints[&fingerprint];
            assert_eq!(record.failed_reconstruction_count, expected_failure_count);
            assert_eq!(
                record.disposition,
                if expected_failure_count == MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
                    SnapshotQuarantineDisposition::UnprovenTerminal
                } else {
                    SnapshotQuarantineDisposition::RetryPending
                }
            );
        }
        assert_eq!(upload_count, 4);
        assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
        let mut terminal_index = ScanIndex::default();
        terminal_index.file_snapshot_fingerprints.insert(
            "terminal.jsonl".to_string(),
            BTreeSet::from([fingerprint.clone()]),
        );
        terminal_index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        assert_eq!(terminal_index.snapshot_unproven_terminal_count(), 1);
        let disclosed = SyncCounts::default().with_snapshot_terminal_counts(&terminal_index);
        assert_eq!(disclosed.snapshot_unproven_terminal_count, 1);
        assert_eq!(disclosed.ownership_incomplete_file_count, 1);
        // Terminal by disposition, so the settled share grows by the same
        // number and the ownership-incomplete class stays matched.
        assert_eq!(disclosed.terminal_ownership_incomplete_file_count, 1);

        let fifth = upload_resumable_batches_with_body_witness(
            std::slice::from_ref(&item),
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            |_| "a".repeat(64),
            |_| panic!("unchanged terminal body must not upload a fifth time"),
            |_| Ok(()),
        )
        .expect("terminal suppression is a completed local pass");
        assert_eq!(fifth, ResumableUploadResult::Completed);
        assert_eq!(
            progress.quarantined_fingerprints[&fingerprint].failed_reconstruction_count,
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
        );

        let corrected = BodyWitnessTestItem {
            snapshot_fingerprint: fingerprint.clone(),
            body_revision: "b".to_string(),
        };
        let recovered = upload_resumable_batches_with_body_witness(
            std::slice::from_ref(&corrected),
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            |_| "b".repeat(64),
            |batch| {
                Ok(entity_ack_batch(
                    &[batch[0].snapshot_fingerprint.clone()],
                    &[],
                    &[],
                ))
            },
            |_| Ok(()),
        )
        .expect("changed body reopens and settles terminal identity");
        assert_eq!(recovered, ResumableUploadResult::Completed);
        assert!(!progress.quarantined_fingerprints.contains_key(&fingerprint));
        assert!(progress.accepted_fingerprints.contains(&fingerprint));
    }

    #[test]
    #[serial(client_report)]
    fn entity_ack_rejection_is_not_counted_before_quarantine_persists() {
        use crate::client_report::{observe, reset_for_test, ClientReportReason};

        reset_for_test();
        let poison_scope = unique_poison_scope();
        let items = test_fingerprints(1);
        let rejected_fingerprint = items[0].clone();
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let error = upload_resumable_batches(
            &items,
            &poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| {
                Ok(crate::snapshot_client::SnapshotBatchResponse {
                    accepted: 0,
                    sessions_reconciled: 0,
                    session_ids: Vec::new(),
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: Some(
                        crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                    ),
                    accepted_entities: Vec::new(),
                    unchanged_entities: Vec::new(),
                    rejected_entities: vec![crate::snapshot_client::SnapshotEntityRejection {
                        source_session_id: "rejected".to_string(),
                        snapshot_fingerprint: rejected_fingerprint.clone(),
                        reason: "invalid".to_string(),
                        detail: "permanent validation failure".to_string(),
                        permanent: true,
                        occurrence_count: 1,
                    }],
                    conflict_entities: Vec::new(),
                })
            },
            |_| Err(anyhow!("checkpoint unavailable")),
        )
        .expect_err("an undurable rejection quarantine cannot settle the source");

        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
        assert_eq!(accepted, 0);
        assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
        assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
        reset_for_test();
    }

    #[test]
    fn snapshot_upload_coalesces_byte_equal_duplicate_occurrences() {
        let poison_scope = &unique_poison_scope();
        let duplicate = "a".repeat(64);
        let distinct = "b".repeat(64);
        let items = vec![duplicate.clone(), distinct.clone(), duplicate.clone()];
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_for_upload = observed.clone();

        upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            move |batch| {
                observed_for_upload
                    .lock()
                    .expect("observed")
                    .push(batch.clone());
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("byte-equal duplicates settle through one representative");

        let requests = observed.lock().expect("observed");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0], vec![duplicate.clone(), distinct]);
        assert_eq!(accepted, 2);
        assert_eq!(progress.accepted_fingerprints.len(), 2);

        let many_duplicates = vec![duplicate.clone(); SNAPSHOT_BATCH_LIMIT + 5];
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut batch_lengths = Vec::new();
        upload_resumable_batches(
            &many_duplicates,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                batch_lengths.push(batch.len());
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("an identical burst never fences the source");
        assert_eq!(batch_lengths, vec![1]);
        assert_eq!(accepted, 1);
    }

    #[derive(Clone, Serialize)]
    struct SizedUploadItem {
        fingerprint: String,
        body: String,
    }

    #[test]
    #[serial(client_report)]
    fn snapshot_upload_coalesces_duplicate_semantics_with_distinct_observation_metadata() {
        use crate::client_report::{observe, reset_for_test, ClientReportReason};

        reset_for_test();
        let poison_scope = unique_poison_scope();
        let duplicate = "d".repeat(64);
        let valid = "e".repeat(64);
        let items = vec![
            SizedUploadItem {
                fingerprint: duplicate.clone(),
                body: "source-file-observation-a".to_string(),
            },
            SizedUploadItem {
                fingerprint: valid.clone(),
                body: "valid".to_string(),
            },
            SizedUploadItem {
                fingerprint: duplicate.clone(),
                body: "source-file-observation-b".to_string(),
            },
        ];
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut uploaded = Vec::new();
        upload_resumable_batches(
            &items,
            &poison_scope,
            &mut progress,
            &mut accepted,
            |item| item.fingerprint.as_str(),
            |batch| {
                uploaded.extend(batch.iter().map(|item| item.fingerprint.clone()));
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("observation-only differences keep one semantic entity");

        assert_eq!(uploaded, vec![duplicate.clone(), valid.clone()]);
        assert_eq!(accepted, 2);
        assert!(progress.accepted_fingerprints.contains(&duplicate));
        assert!(progress.accepted_fingerprints.contains(&valid));
        assert!(progress.quarantined_fingerprints.is_empty());
        assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
        assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
        reset_for_test();
    }

    #[test]
    fn snapshot_upload_byte_bound_closes_mixed_size_batches_early() {
        let body_sizes = [400 * 1024, 800 * 1024, 1_000 * 1024, 100 * 1024];
        let items = body_sizes
            .into_iter()
            .enumerate()
            .map(|(index, body_size)| SizedUploadItem {
                fingerprint: format!("{index:064x}"),
                body: "x".repeat(body_size),
            })
            .collect::<Vec<_>>();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut observed_batches = Vec::new();
        upload_resumable_batches(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.fingerprint.as_str(),
            |batch| {
                observed_batches.push((batch.len(), serde_json::to_vec(&batch).unwrap().len()));
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("byte-packed upload succeeds");

        assert_eq!(accepted, 4);
        assert_eq!(
            observed_batches
                .iter()
                .map(|(count, _)| *count)
                .collect::<Vec<_>>(),
            vec![2, 2]
        );
        assert!(observed_batches
            .iter()
            .all(|(_, size)| *size <= SNAPSHOT_BATCH_MAX_BYTES));
    }

    #[test]
    fn snapshot_upload_single_oversize_entity_ships_alone() {
        let items = vec![
            SizedUploadItem {
                fingerprint: format!("{:064x}", 0),
                body: "x".repeat(SNAPSHOT_BATCH_MAX_BYTES + 1),
            },
            SizedUploadItem {
                fingerprint: format!("{:064x}", 1),
                body: "small".to_string(),
            },
        ];
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut observed_batches = Vec::new();
        upload_resumable_batches(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.fingerprint.as_str(),
            |batch| {
                observed_batches.push((batch.len(), serde_json::to_vec(&batch).unwrap().len()));
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("a single oversize entity is left for the server entity cap");

        assert_eq!(accepted, 2);
        assert_eq!(observed_batches.len(), 2);
        assert_eq!(observed_batches[0].0, 1);
        assert!(observed_batches[0].1 > SNAPSHOT_BATCH_MAX_BYTES);
        assert_eq!(observed_batches[1].0, 1);
        assert!(observed_batches[1].1 <= SNAPSHOT_BATCH_MAX_BYTES);
    }

    #[test]
    #[serial(client_report)]
    fn oversized_local_preflight_poison_cannot_pin_later_traversal_pages() {
        use crate::client_report::reset_for_test;

        reset_for_test();
        let poison_scope = &unique_poison_scope();
        let root = test_dir("snapshot-local-preflight-traversal");
        std::fs::create_dir_all(&root).expect("create traversal fixture root");
        for index in 0..3 {
            std::fs::write(
                root.join(format!("session-{index}.jsonl")),
                format!(
                    "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n",
                    index + 1
                ),
            )
            .expect("write traversal fixture");
        }

        let index_path = root.join("pi-scan-index-v3.json");
        let progress_path = root.join("pi-upload-progress-v2.json");
        let mut index = ScanIndex::default();
        let mut first = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-07-31T00:00:00Z",
            183,
            2,
            true,
        )
        .expect("scan first bounded page");
        assert!(!first.census_complete);
        assert_eq!(first.scanned_file_count, 2);
        assert_eq!(first.snapshots.len(), 2);
        let first_page_sessions = first
            .snapshots
            .iter()
            .map(|snapshot| snapshot.source_session_id.clone())
            .collect::<BTreeSet<_>>();

        // Model a long-lived session with enough ordinary hourly usage buckets
        // to exceed the daemon/backend per-item wire cap. Keep every aggregate
        // internally consistent so the only preflight failure is the byte cap.
        let bucket_count = 1_000_u64;
        let bucket_start =
            OffsetDateTime::parse("2026-06-01T00:00:00Z", &Rfc3339).expect("parse bucket start");
        let mut bucket_template = first.snapshots[0].usage_buckets[0].clone();
        assert_eq!(bucket_template.model_usage.len(), 1);
        let usage_buckets = (0..bucket_count)
            .map(|hour| {
                let timestamp = (bucket_start + TimeDuration::hours(hour as i64))
                    .format(&Rfc3339)
                    .expect("format bucket timestamp");
                bucket_template.bucket_start = timestamp.clone();
                bucket_template.first_activity_at = Some(timestamp.clone());
                bucket_template.last_activity_at = Some(timestamp);
                let row = &mut bucket_template.model_usage[0];
                row.input_tokens = 1;
                row.output_tokens = 1;
                row.cache_read_tokens = 0;
                row.cache_creation_5m_tokens = 0;
                row.cache_creation_1h_tokens = 0;
                row.reasoning_output_tokens = 0;
                row.unattributed_total_tokens = 0;
                row.request_count = 1;
                bucket_template.clone()
            })
            .collect::<Vec<_>>();
        let poison = &mut first.snapshots[0];
        assert_eq!(poison.model_usage.len(), 1);
        poison.input_tokens = bucket_count;
        poison.output_tokens = bucket_count;
        poison.cache_read_tokens = 0;
        poison.cache_creation_5m_tokens = 0;
        poison.cache_creation_1h_tokens = 0;
        poison.reasoning_output_tokens = 0;
        poison.unattributed_total_tokens = 0;
        poison.request_count = bucket_count;
        let top_row = &mut poison.model_usage[0];
        top_row.input_tokens = bucket_count;
        top_row.output_tokens = bucket_count;
        top_row.cache_read_tokens = 0;
        top_row.cache_creation_5m_tokens = 0;
        top_row.cache_creation_1h_tokens = 0;
        top_row.reasoning_output_tokens = 0;
        top_row.unattributed_total_tokens = 0;
        top_row.request_count = bucket_count;
        poison.usage_buckets = usage_buckets;
        finalize_scan_after_policy(SnapshotSource::Pi, &mut first, &mut index);
        let poison_fingerprint = first.snapshots[0].snapshot_fingerprint.clone();
        let healthy_fingerprint = first.snapshots[1].snapshot_fingerprint.clone();
        let poison_probe = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: SnapshotSource::Pi.api_slug().to_string(),
            machine_id: "machine-preflight-test".to_string(),
            collector_version: Some(collector_version()),
            snapshots: vec![first.snapshots[0].clone()],
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let poison_reason = validate_snapshot_batch_request(&poison_probe)
            .expect_err("long-lived session exceeds the item wire cap");
        assert!(poison_reason.contains("wire body"), "{poison_reason}");
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut network_uploads = Vec::new();
        let result = upload_resumable_batches(
            &first.snapshots,
            poison_scope,
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            |snapshots| {
                let request = SnapshotBatchRequest {
                    schema_version: SNAPSHOT_SCHEMA_VERSION,
                    source: SnapshotSource::Pi.api_slug().to_string(),
                    machine_id: "machine-preflight-test".to_string(),
                    collector_version: Some(collector_version()),
                    snapshots,
                    upload_policy: SnapshotUploadPolicy::default(),
                    client_report: crate::client_report::ClientReport::empty(),
                };
                if let Err(reason) = validate_snapshot_batch_request(&request) {
                    return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                        reason,
                    }));
                }
                network_uploads.extend(
                    request
                        .snapshots
                        .iter()
                        .map(|snapshot| snapshot.snapshot_fingerprint.clone()),
                );
                Ok(accepted_batch(request.snapshots.len()))
            },
            |state| state.save(&progress_path),
        )
        .expect("deterministic local poison is settled by quarantine");

        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(accepted, 1);
        assert_eq!(network_uploads, vec![healthy_fingerprint.clone()]);
        assert!(progress
            .accepted_fingerprints
            .contains(&healthy_fingerprint));
        assert!(progress
            .quarantined_fingerprints
            .contains_key(&poison_fingerprint));
        assert!(progress_path.is_file(), "quarantine must be durable first");

        // Mirror the completed caller boundary: the server-held sibling and
        // quarantined poison become durable together with the traversal cursor,
        // then the redundant upload ledger may be cleared.
        index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        index
            .save(&index_path)
            .expect("save settled traversal page");
        progress
            .clear(&progress_path)
            .expect("clear redundant upload progress");

        let mut resumed = ScanIndex::load(&index_path).expect("reload traversal cursor");
        let second = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut resumed,
            "2026-07-31T00:05:00Z",
            183,
            2,
            true,
        )
        .expect("scan later bounded page");
        assert!(second.census_complete);
        assert_eq!(second.scanned_file_count, 1);
        assert_eq!(second.snapshots.len(), 1);
        assert!(!first_page_sessions.contains(&second.snapshots[0].source_session_id));

        let _ = std::fs::remove_dir_all(root);
        reset_for_test();
    }

    #[test]
    fn metadata_only_snapshot_still_uploads_and_settles_after_manifest_omission() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/snapshot-manifest-v2-metadata-only-golden.json"
        ))
        .expect("parse shared metadata-only golden");
        assert!(golden["semantic_activity"].is_null());
        assert_eq!(golden["manifest"]["entity_count"], 0);
        let fingerprint = golden["snapshot_fingerprint"].as_str().unwrap().to_string();
        let expected_occurrences = golden["expected_upload_ack_occurrence_count"]
            .as_u64()
            .unwrap();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut attempts = 0;

        upload_resumable_batches(
            std::slice::from_ref(&fingerprint),
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                attempts += 1;
                assert_eq!(batch, vec![fingerprint.clone()]);
                Ok(accepted_batch(expected_occurrences as usize))
            },
            |_| Ok(()),
        )
        .expect("metadata-only snapshot upload is independently acknowledged");

        assert_eq!(attempts, 1);
        assert_eq!(accepted, expected_occurrences);
        assert!(progress.accepted_fingerprints.contains(&fingerprint));
    }

    #[test]
    #[serial(client_report)]
    fn poisoned_items_are_counted_for_the_client_report() {
        let poison_scope = &unique_poison_scope();
        use crate::client_report::{reset_for_test, ClientReportReason};
        reset_for_test();
        let items = test_fingerprints(3);
        let poison = items[1].clone();
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            move |batch| {
                if batch.contains(&poison) {
                    return Err(anyhow::Error::new(BatchRejected {
                        status: 422,
                        body_excerpt: Some(
                            r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#.to_string(),
                        ),
                    }));
                }
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect_err("a poison item still fails the cycle");

        assert!(is_item_specific_validation_failure(&error));
        // One item was lost and it is reported as exactly one item, so the
        // server can tell this apart from an empty scan.
        assert_eq!(
            crate::client_report::observe().quantity(ClientReportReason::Poisoned),
            1
        );
        reset_for_test();
    }

    #[test]
    #[serial(client_report)]
    fn a_permanently_poisoned_item_is_counted_once_not_once_per_cycle() {
        use crate::client_report::{observe, reset_for_test, ClientReportReason};
        let poison_scope = &unique_poison_scope();
        reset_for_test();
        let items = test_fingerprints(1);
        let poison = items[0].clone();
        let upload = |batch: Vec<String>| {
            assert!(batch.contains(&poison));
            Err(anyhow::Error::new(BatchRejected {
                status: 422,
                body_excerpt: Some(
                    r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#.to_string(),
                ),
            }))
        };

        // Three cycles over the same permanently invalid entity. Nothing ever
        // succeeds, so nothing ever commits the report; if each attempt counted,
        // one broken session would look like a growing stream of losses.
        for _ in 0..3 {
            let mut progress = test_upload_progress();
            let mut accepted = 0;
            upload_resumable_batches(
                &items,
                poison_scope,
                &mut progress,
                &mut accepted,
                String::as_str,
                upload,
                |_| Ok(()),
            )
            .expect_err("a poison item fails the cycle");
        }

        assert_eq!(observe().quantity(ClientReportReason::Poisoned), 1);

        // A later scan that no longer carries the entity prunes the ledger, so
        // it stays bounded by the current scan rather than by all history.
        let other_items = test_fingerprints(2)[1..].to_vec();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        upload_resumable_batches(
            &other_items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| Ok(accepted_batch(batch.len())),
            |_| Ok(()),
        )
        .expect("valid scan succeeds");
        assert!(counted_poison_fingerprints_for_test(poison_scope).is_empty());
        reset_for_test();
    }

    #[test]
    fn a_shed_upload_is_counted_as_backoff_not_as_a_network_error() {
        let shed = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "http_429",
            true,
            false,
        ));
        assert!(is_shed_failure(&shed));
        let server_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "http_5xx",
            true,
            false,
        ));
        assert!(!is_shed_failure(&server_error));
        let offline = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "transport_timeout",
            true,
            false,
        ));
        assert!(!is_shed_failure(&offline));
    }

    #[test]
    fn only_snapshot_page_deadlines_are_adaptively_split() {
        let gateway_timeout = anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
            "local snapshot upload",
            "snapshot_batch",
            504,
            true,
        ));
        assert!(is_snapshot_batch_deadline_failure(&gateway_timeout));
        assert_eq!(
            gateway_timeout.to_string(),
            "local snapshot upload failed (endpoint=snapshot_batch, status_family=http_5xx, retryable=true, request_id=present)"
        );

        let generic_server_error = anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
            "local snapshot upload",
            "snapshot_batch",
            500,
            true,
        ));
        assert!(!is_snapshot_batch_deadline_failure(&generic_server_error));

        let relay_gateway_timeout = anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
            "relay token request",
            "relay_token",
            504,
            true,
        ));
        assert!(!is_snapshot_batch_deadline_failure(&relay_gateway_timeout));

        let batch_transport_timeout = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "transport_timeout",
            true,
            false,
        ));
        assert!(is_snapshot_batch_deadline_failure(&batch_transport_timeout));

        let relay_transport_timeout = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "relay token request",
            "relay_token",
            "transport_timeout",
            true,
            false,
        ));
        assert!(!is_snapshot_batch_deadline_failure(
            &relay_transport_timeout
        ));
    }

    #[test]
    #[serial(client_report)]
    fn an_unacknowledged_client_report_survives_to_the_next_batch() {
        use crate::client_report::{lease, observe, record, reset_for_test, ClientReportReason};
        reset_for_test();
        record(ClientReportReason::NetworkError, 2);
        {
            // The upload died: the lease drops unacknowledged, so the losses stay
            // owed rather than vanishing with the request.
            let reported = lease();
            assert_eq!(
                reported.report().quantity(ClientReportReason::NetworkError),
                2
            );
        }
        assert_eq!(observe().quantity(ClientReportReason::NetworkError), 2);

        // The retry carries them and is acknowledged.
        lease().commit();
        assert_eq!(observe().quantity(ClientReportReason::NetworkError), 0);
        reset_for_test();
    }

    #[test]
    #[serial(client_report)]
    fn a_shed_page_stops_the_pass_and_keeps_earlier_pages_checkpointed() {
        let poison_scope = &unique_poison_scope();
        use crate::client_report::{observe, reset_for_test, ClientReportReason};
        reset_for_test();
        let items = test_fingerprints(75);
        let first_page = items[..SNAPSHOT_BATCH_LIMIT].to_vec();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut attempts = 0usize;

        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                attempts += 1;
                if batch == first_page {
                    Ok(accepted_batch(batch.len()))
                } else {
                    Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                    }))
                }
            },
            |_| Ok(()),
        )
        .expect("a shed page is not a cycle failure");

        // The shed page stops the pass instead of driving the remaining pages at
        // a server that just asked for room.
        assert_eq!(attempts, 2);
        assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
        assert_eq!(progress.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);
        match result {
            ResumableUploadResult::Shed { retry_after } => {
                // The pass reports the server's own number; turning it into a
                // wait belongs to the caller, which owns the shed history.
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
                let honoured = note_shed_and_backoff(SnapshotSource::Pi, retry_after);
                // Retry-After x uniform(1.0, 1.2): never before the server's 60s,
                // never more than 20% late.
                assert!(honoured >= Duration::from_secs(60));
                assert!(honoured <= Duration::from_secs(72));
            }
            other => panic!("expected a shed result, got {other:?}"),
        }
        assert_eq!(observe().quantity(ClientReportReason::RatelimitBackoff), 1);
        reset_for_test();
    }

    #[test]
    fn an_honoured_retry_after_is_never_shortened_by_jitter() {
        // Jitter that can fire early is not jitter, it is an early retry against
        // a server that just said it was not ready.
        let requested = Duration::from_secs(45);
        for _ in 0..64 {
            let wait = shed_backoff(Some(requested));
            assert!(wait >= requested, "{wait:?} is earlier than {requested:?}");
            assert!(wait <= requested.mul_f64(1.2));
        }
        let waits = (0..24)
            .map(|_| shed_backoff(Some(requested)))
            .collect::<BTreeSet<_>>();
        assert!(waits.len() > 1, "a constant wait re-synchronises the fleet");

        // The cap survives the upper jitter.
        assert_eq!(
            shed_backoff(Some(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER)),
            crate::snapshot_client::MAX_HONOURED_RETRY_AFTER
        );
    }

    #[test]
    fn a_shed_without_retry_after_uses_full_jitter_not_a_fixed_wait() {
        // Full jitter means random(0, ceiling): the point is that two machines
        // shed at the same instant do not come back at the same instant.
        let waits = (0..24).map(|_| shed_backoff(None)).collect::<BTreeSet<_>>();
        assert!(
            waits.len() > 1,
            "a constant backoff re-synchronises the fleet it is meant to spread"
        );
        assert!(waits.iter().all(|wait| *wait <= SHED_BACKOFF_BASE));

        // The ladder is exponential in its ceiling and capped.
        assert!(full_jitter_backoff(0) <= SHED_BACKOFF_BASE);
        assert!(full_jitter_backoff(3) <= SHED_BACKOFF_BASE * 8);
        assert!(
            full_jitter_backoff(30) <= crate::snapshot_client::MAX_HONOURED_RETRY_AFTER,
            "the ladder must saturate, not overflow"
        );
    }

    #[test]
    #[serial(source_upload_deadlines)]
    fn a_sustained_shed_climbs_the_ladder_and_a_success_resets_it() {
        clear_source_upload_deadlines_for_test();
        // A shed with no Retry-After must back off further each time. Without a
        // streak every shed draws from random(0, 30s), which the five-minute cycle
        // has already outlived by the next tick — no backoff at all under
        // sustained overload.
        let mut ceilings = Vec::new();
        for expected_attempt in 0..4 {
            assert_eq!(
                shed_streak_for_test(SnapshotSource::Codex),
                expected_attempt
            );
            let wait = note_shed_and_backoff(SnapshotSource::Codex, None);
            ceilings.push(wait);
        }
        assert_eq!(shed_streak_for_test(SnapshotSource::Codex), 4);
        // Full jitter means any single draw can be small, so the property to
        // assert is the ceiling, not the sample: the fourth rung may exceed the
        // first rung's ceiling, and the first never can.
        assert!(ceilings[0] <= SHED_BACKOFF_BASE);
        assert!(ceilings[3] <= SHED_BACKOFF_BASE * 8);

        // A server-named wait wins over the local ladder and still counts the shed.
        let named = note_shed_and_backoff(SnapshotSource::Codex, Some(Duration::from_secs(120)));
        assert!(named >= Duration::from_secs(120));
        assert_eq!(shed_streak_for_test(SnapshotSource::Codex), 5);

        // A completed upload clears it: the next shed starts at the first rung.
        clear_shed_streak(SnapshotSource::Codex);
        assert_eq!(shed_streak_for_test(SnapshotSource::Codex), 0);
        // The streak is per source, like the deadline.
        assert_eq!(shed_streak_for_test(SnapshotSource::ClaudeCode), 0);
        clear_source_upload_deadlines_for_test();
    }

    #[test]
    #[serial(source_upload_deadlines)]
    fn an_honoured_backoff_defers_the_source_until_it_expires() {
        clear_source_upload_deadlines_for_test();
        assert!(source_upload_backoff_remaining(SnapshotSource::Codex).is_none());

        defer_source_uploads(SnapshotSource::Codex, Duration::from_secs(60));
        let remaining =
            source_upload_backoff_remaining(SnapshotSource::Codex).expect("codex is deferred");
        assert!(remaining <= Duration::from_secs(60));
        // The backoff is per source: one shed source must not silence the others.
        assert!(source_upload_backoff_remaining(SnapshotSource::ClaudeCode).is_none());

        // An expired deadline clears itself rather than deferring forever.
        defer_source_uploads(SnapshotSource::Codex, Duration::ZERO);
        assert!(source_upload_backoff_remaining(SnapshotSource::Codex).is_none());
        clear_source_upload_deadlines_for_test();
    }

    #[test]
    #[serial(source_cadences)]
    fn the_negotiated_cadence_respects_the_floor_the_ceiling_and_the_directive() {
        clear_cadence_state_for_test();
        let floor = SNAPSHOT_SYNC_INTERVAL;
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(floor));
        cadence.record_scan_success(start, 1);

        // A server directive may only ask for LESS frequent scanning. A directive
        // shorter than the tier cannot buy a faster scan, or the fleet would be
        // paying for the server's own load.
        cadence.set_server_min_interval(Some(Duration::from_secs(1)));
        assert_eq!(negotiated_wait(&cadence, start), floor);
        cadence.set_server_min_interval(Some(floor * 2));
        assert_eq!(negotiated_wait(&cadence, start), floor * 2);
        // And it cannot silence a source past the ceiling.
        cadence.set_server_min_interval(Some(Duration::from_secs(24 * 60 * 60)));
        assert_eq!(negotiated_wait(&cadence, start), MAX_CYCLE_INTERVAL);
        // The ceiling is stricter than the 6-hour sweep, so a full scan of the
        // window happens at least every 30 minutes whatever the watcher does.
        assert!(MAX_CYCLE_INTERVAL < CadenceConfig::cost_first(floor).full_sweep_interval);
        clear_cadence_state_for_test();
    }

    #[test]
    #[serial(source_cadences)]
    fn a_quiet_source_stretches_and_file_activity_brings_it_back_to_the_floor() {
        clear_cadence_state_for_test();
        let floor = SNAPSHOT_SYNC_INTERVAL;
        let start = Instant::now();
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(floor));

        // Two quiet cycles: the source falls to the idle tier and is scanned less
        // often. That saving is the entire point of the wiring.
        cadence.record_scan_success(start, 0);
        let later = start + Duration::from_secs(20 * 60);
        cadence.record_scan_success(later, 0);
        let idle_wait = negotiated_wait(&cadence, later);
        assert!(idle_wait > floor);
        assert!(idle_wait <= MAX_CYCLE_INTERVAL);

        // A filesystem event promotes the tier back to the floor — and only to the
        // floor. Fifty events in a second cannot buy fifty scans.
        for offset in 0..50 {
            cadence.record_file_event(later + Duration::from_secs(offset));
        }
        assert_eq!(negotiated_wait(&cadence, later), floor);
        assert!(negotiated_wait(&cadence, later + Duration::from_secs(1)) > Duration::ZERO);
        clear_cadence_state_for_test();
    }

    #[test]
    #[serial(source_cadences)]
    fn a_server_scan_directive_is_read_bounded_and_cannot_starve_the_scan() {
        clear_cadence_state_for_test();
        let wait_for = |source, now| {
            with_source_cadence(source, |cadence| negotiated_wait(cadence, now)).expect("cadence")
        };

        // A directive in the past is "no minimum", not a negative wait.
        record_server_scan_directive(SnapshotSource::Codex, "2020-01-01T00:00:00Z");
        assert_eq!(
            wait_for(SnapshotSource::Codex, Instant::now()),
            Duration::ZERO
        );

        // A far-future directive is bounded by the ceiling: a server cannot
        // silence a source for a day.
        let scanned_at = Instant::now();
        with_source_cadence(SnapshotSource::Codex, |cadence| {
            cadence.record_scan_success(scanned_at, 1)
        });
        record_server_scan_directive(SnapshotSource::Codex, "2099-01-01T00:00:00Z");
        assert_eq!(
            wait_for(SnapshotSource::Codex, scanned_at),
            MAX_CYCLE_INTERVAL
        );

        // An unparsable directive leaves the previous one alone rather than
        // inventing a value.
        record_server_scan_directive(SnapshotSource::Codex, "soon");
        assert_eq!(
            wait_for(SnapshotSource::Codex, scanned_at),
            MAX_CYCLE_INTERVAL
        );

        // The starvation case: re-reading a directive on every cycle must not push
        // its own deadline forward. Anchored to the last scan, the wait strictly
        // decreases as time passes — otherwise the scan would never run again, on a
        // machine where nothing looks wrong.
        let mut previous = MAX_CYCLE_INTERVAL + Duration::from_secs(1);
        for elapsed in [0u64, 60, 600] {
            record_server_scan_directive(SnapshotSource::Codex, "2099-01-01T00:00:00Z");
            let wait = wait_for(
                SnapshotSource::Codex,
                scanned_at + Duration::from_secs(elapsed),
            );
            assert!(
                wait < previous,
                "a refreshed directive must never extend its own deadline"
            );
            previous = wait;
        }
        clear_cadence_state_for_test();
    }

    #[test]
    #[serial(source_cadences, source_manifests)]
    fn the_cadence_tier_never_reaches_the_wire_or_any_identity() {
        let _source_manifests = SourceManifestTestGuard::new();
        clear_cadence_state_for_test();
        // The cadence tier and the scan trigger are implementation state. If either
        // entered an identity, every session on a machine would re-mint its content
        // hash the moment the machine went idle.
        with_source_cadence(SnapshotSource::Codex, |cadence| {
            cadence.record_file_event(Instant::now())
        });
        record_server_scan_directive(SnapshotSource::Codex, "2099-01-01T00:00:00Z");

        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("report check-in while a tier is hot");
        let requests = captured.lock().expect("captured requests").clone();
        for forbidden in [
            "cadence",
            "scan_trigger",
            "recommended_scan_after",
            "\"hot\"",
            "\"idle\"",
            "\"cold\"",
        ] {
            assert!(
                !requests[1].contains(forbidden),
                "{forbidden} must not travel on a receipt"
            );
        }
        clear_cadence_state_for_test();
    }

    #[test]
    fn the_cadence_phase_offset_is_stable_per_machine_and_inside_the_interval() {
        let interval = Duration::from_secs(5 * 60);
        let first = cadence_phase_offset("otm_aaaa", interval);
        assert_eq!(first, cadence_phase_offset("otm_aaaa", interval));
        assert!(first < interval);
        let offsets = ["otm_a", "otm_b", "otm_c", "otm_d", "otm_e", "otm_f"]
            .into_iter()
            .map(|id| cadence_phase_offset(id, interval))
            .collect::<BTreeSet<_>>();
        assert!(
            offsets.len() > 1,
            "the offset must actually spread machines apart"
        );
        assert_eq!(
            cadence_phase_offset("otm_a", Duration::ZERO),
            Duration::ZERO
        );
    }

    #[test]
    fn checkpoint_persist_failure_is_local_state_not_transport() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(1);
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| Ok(accepted_batch(batch.len())),
            |_| Err(anyhow!("private/path/checkpoint.json")),
        )
        .expect_err("remote success without durable checkpoint must fail locally");

        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
        assert_eq!(safe_error(&error), "local snapshot state failed");
        assert!(!error.to_string().contains("private/path"));
        assert_eq!(accepted, 0);
    }

    #[test]
    #[serial(client_report)]
    fn local_preflight_quarantine_persist_failure_stays_unsettled() {
        use crate::client_report::{observe, reset_for_test, ClientReportReason};

        reset_for_test();
        let items = test_fingerprints(1);
        let poison_scope = unique_poison_scope();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let error = upload_resumable_batches(
            &items,
            &poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| {
                Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                    reason: format!(
                        "snapshot[0] wire body exceeds {} bytes",
                        crate::snapshots::MAX_SNAPSHOT_ITEM_WIRE_BYTES
                    ),
                }))
            },
            |_| Err(anyhow!("checkpoint unavailable")),
        )
        .expect_err("an undurable quarantine cannot settle the source");

        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
        assert_eq!(accepted, 0);
        assert!(progress.accepted_fingerprints.is_empty());
        assert!(progress.quarantined_fingerprints.is_empty());
        assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
        assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
        reset_for_test();
    }

    #[test]
    fn accepted_count_mismatch_is_backend_response_not_transport() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(1);
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| Ok(accepted_batch(0)),
            |_| Ok(()),
        )
        .expect_err("accepted-count mismatch must reject the response");

        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::BackendResponse)
        );
        assert_eq!(safe_error(&error), "backend snapshot response was invalid");
        assert_eq!(accepted, 0);
    }

    #[test]
    fn snapshot_upload_restart_resumes_after_durable_timeout_checkpoint() {
        let poison_scope = &unique_poison_scope();
        let root = test_dir("snapshot-upload-resume-timeout");
        let path = root.join("codex-scan-index-attribution-test-upload-progress.json");
        let items = test_fingerprints(75);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let first_page = items[..SNAPSHOT_BATCH_LIMIT].to_vec();

        let first_error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                if batch == first_page {
                    Ok(accepted_batch(batch.len()))
                } else {
                    Err(anyhow::Error::new(UploadFailureDiagnostics::for_test(
                        "local snapshot upload",
                        "snapshot_batch",
                        "transport_timeout",
                        true,
                        false,
                    )))
                }
            },
            |state| state.save(&path),
        )
        .expect_err("persistent timeout stops after checkpointing the first page");

        assert!(is_snapshot_batch_deadline_failure(&first_error));
        assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
        let mut resumed = SnapshotUploadProgress::load(
            &path,
            &progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .expect("reload progress");
        assert_eq!(resumed.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);

        let mut resumed_accepted = 0;
        let mut resumed_items = Vec::new();
        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut resumed,
            &mut resumed_accepted,
            String::as_str,
            |batch| {
                resumed_items.extend(batch.iter().cloned());
                Ok(accepted_batch(batch.len()))
            },
            |state| state.save(&path),
        )
        .expect("restart uploads only remaining pages");

        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(resumed_accepted, 25);
        assert_eq!(resumed_items, items[SNAPSHOT_BATCH_LIMIT..]);
        assert!(resumed_items
            .iter()
            .all(|fingerprint| !first_page.contains(fingerprint)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn gateway_timeout_bisection_converges_from_entity_cursor_after_ambiguous_commit() {
        let poison_scope = &unique_poison_scope();
        let root = test_dir("snapshot-upload-gateway-timeout-cursor");
        let path = root.join("claude-scan-index-v3-upload-progress.json");
        let items = test_fingerprints(SNAPSHOT_BATCH_LIMIT);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut attempts = Vec::new();
        let mut remotely_held = BTreeSet::new();

        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                attempts.push(batch.len());
                if batch.len() == SNAPSHOT_BATCH_LIMIT {
                    // A gateway timeout does not prove whether the backend
                    // committed. Model the ambiguous side as committed: the
                    // smaller retries must remain idempotent at entity grain.
                    remotely_held.extend(batch);
                    return Err(anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
                        "local snapshot upload",
                        "snapshot_batch",
                        504,
                        true,
                    )));
                }
                for fingerprint in &batch {
                    assert!(
                        !remotely_held.insert(fingerprint.clone()),
                        "a smaller retry may revisit a held entity but cannot mint a second one"
                    );
                }
                Ok(accepted_batch(batch.len()))
            },
            |state| state.save(&path),
        )
        .expect("gateway timeout is bisected into resumable child pages");

        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(
            attempts,
            vec![
                SNAPSHOT_BATCH_LIMIT,
                SNAPSHOT_BATCH_LIMIT / 2,
                SNAPSHOT_BATCH_LIMIT - (SNAPSHOT_BATCH_LIMIT / 2),
            ]
        );
        assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
        assert_eq!(remotely_held.len(), SNAPSHOT_BATCH_LIMIT);
        assert_eq!(progress.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);

        let mut resumed = SnapshotUploadProgress::load(
            &path,
            &progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .expect("reload entity-grain upload cursor");
        let mut resumed_accepted = 0;
        let mut resumed_upload_calls = 0;
        let resumed_result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut resumed,
            &mut resumed_accepted,
            String::as_str,
            |_| {
                resumed_upload_calls += 1;
                Ok(accepted_batch(0))
            },
            |state| state.save(&path),
        )
        .expect("restart settles entirely from the durable entity cursor");

        assert_eq!(resumed_result, ResumableUploadResult::Completed);
        assert_eq!(resumed_upload_calls, 0);
        assert_eq!(resumed_accepted, 0);
        assert_eq!(remotely_held.len(), SNAPSHOT_BATCH_LIMIT);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn backfill_finalization_is_idempotent_across_index_state_and_progress_crashes() {
        let poison_scope = &unique_poison_scope();
        let root = test_dir("snapshot-backfill-finalization-crash");
        let index_path = root.join("pi-scan-index-v3.json");
        let progress_path = root.join("pi-upload-progress-v2.json");
        let destination = format!("{:064x}", 77);
        let fingerprint = format!("{:064x}", 78);

        // This is the exact first durable boundary in the production order: a
        // complete replay has uploaded, and its destination index is saved,
        // while the historical completion marker and ledger clear have not run.
        let mut index = ScanIndex::default();
        index
            .save(&index_path)
            .expect("save completed replay index");
        let mut progress = SnapshotUploadProgress::new(
            destination.clone(),
            snapshot_quarantine_witness(SnapshotSource::Pi),
        );
        progress.record([fingerprint.as_str()]);
        progress
            .save(&progress_path)
            .expect("save accepted replay ledger");
        assert!(pending_backfill_sources_for_destination(
            &load_backfill_state(&root),
            &destination
        )
        .contains(&SnapshotSource::Pi));

        // A restart before the marker save re-derives the same entity but the
        // accepted ledger makes the network portion a no-op.
        let mut resumed = SnapshotUploadProgress::load(
            &progress_path,
            &destination,
            snapshot_quarantine_witness(SnapshotSource::Pi),
        )
        .expect("reload accepted replay ledger");
        let mut accepted = 0;
        let mut upload_calls = 0;
        let result = upload_resumable_batches(
            std::slice::from_ref(&fingerprint),
            poison_scope,
            &mut resumed,
            &mut accepted,
            String::as_str,
            |_| {
                upload_calls += 1;
                Ok(accepted_batch(1))
            },
            |state| state.save(&progress_path),
        )
        .expect("restart settles from the durable accepted ledger");
        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(accepted, 0);
        assert_eq!(upload_calls, 0);

        let mut state = load_backfill_state(&root);
        mark_backfill_complete_for_destination(&mut state, SnapshotSource::Pi, &destination);
        save_backfill_state(&root, &state).expect("save replay completion marker");
        resumed.clear(&progress_path).expect("clear final ledger");
        assert!(!pending_backfill_sources_for_destination(
            &load_backfill_state(&root),
            &destination
        )
        .contains(&SnapshotSource::Pi));
        assert!(!progress_path.exists());
        ScanIndex::load(&index_path).expect("completed replay index remains durable");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    // Records client-report poison losses into process-global counters,
    // so it shares the serial group with the tests that assert on them.
    #[serial(client_report)]
    fn item_specific_422_isolates_poison_and_checkpoints_valid_siblings() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(25);
        let poison = items[19].clone();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let uploaded = Arc::new(Mutex::new(Vec::new()));
        let uploaded_capture = uploaded.clone();

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            move |batch| {
                if batch.contains(&poison) {
                    return Err(anyhow::Error::new(BatchRejected {
                        status: 422,
                        body_excerpt: Some(
                            r#"{"errors":[{"loc":["body","snapshots",0,"compaction_timestamps"]}]}"#
                                .to_string(),
                        ),
                    }));
                }
                uploaded_capture
                    .lock()
                    .expect("capture lock")
                    .extend(batch.iter().cloned());
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect_err("poison snapshot keeps the cycle failed");

        assert!(is_item_specific_validation_failure(&error));
        assert_eq!(accepted, 24);
        assert_eq!(progress.accepted_fingerprints.len(), 24);
        assert!(progress.quarantined_fingerprints.is_empty());
        assert!(!progress.contains(&items[19]));
        let uploaded = uploaded.lock().expect("capture lock");
        assert_eq!(uploaded.len(), 24);
        assert!(uploaded.iter().all(|item| item != &items[19]));
        assert_eq!(uploaded.iter().collect::<BTreeSet<_>>().len(), 24);
        drop(uploaded);

        let mut retry_accepted = 0;
        let mut retry_attempts = Vec::new();
        let retry_error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut retry_accepted,
            String::as_str,
            |batch| {
                retry_attempts.push(batch.clone());
                Err(anyhow::Error::new(BatchRejected {
                    status: 422,
                    body_excerpt: Some(
                        r#"{"errors":[{"loc":["body","snapshots",0,"compaction_timestamps"]}]}"#
                            .to_string(),
                    ),
                }))
            },
            |_| Ok(()),
        )
        .expect_err("restart still reports the poison item");

        assert!(is_item_specific_validation_failure(&retry_error));
        assert_eq!(retry_accepted, 0);
        assert_eq!(retry_attempts, vec![vec![items[19].clone()]]);
    }

    #[test]
    // Records client-report poison losses into process-global counters,
    // so it shares the serial group with the tests that assert on them.
    #[serial(client_report)]
    fn broad_item_validation_failure_caps_adaptive_requests() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(75);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut attempts = 0usize;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_batch| {
                attempts += 1;
                Err(anyhow::Error::new(BatchRejected {
                    status: 422,
                    body_excerpt: Some(
                        r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#.to_string(),
                    ),
                }))
            },
            |_| Ok(()),
        )
        .expect_err("broad contract failure is bounded");

        assert_eq!(
            error.to_string(),
            "snapshot adaptive upload attempt limit reached"
        );
        assert!(is_item_specific_validation_failure(&error));
        assert!(error.downcast_ref::<BatchRejected>().is_some());
        assert_eq!(accepted, 0);
        assert!(
            attempts
                <= SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT + items.len().div_ceil(SNAPSHOT_BATCH_LIMIT)
        );
    }

    #[test]
    // Records client-report poison losses into process-global counters,
    // so it shares the serial group with the tests that assert on them.
    #[serial(client_report)]
    fn permanent_poison_prunes_old_revisions_from_progress() {
        let poison_scope = &unique_poison_scope();
        let poison = format!("{:064x}", 9000);
        let mut progress = test_upload_progress();

        for revision in 0..20 {
            let valid = format!("{:064x}", 10_000 + revision);
            let items = vec![valid.clone(), poison.clone()];
            let mut accepted = 0;
            let error = upload_resumable_batches(
                &items,
                poison_scope,
                &mut progress,
                &mut accepted,
                String::as_str,
                |batch| {
                    if batch.contains(&poison) {
                        Err(anyhow::Error::new(BatchRejected {
                            status: 422,
                            body_excerpt: Some(
                                r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#
                                    .to_string(),
                            ),
                        }))
                    } else {
                        Ok(accepted_batch(batch.len()))
                    }
                },
                |_| Ok(()),
            )
            .expect_err("permanent poison keeps the cycle incomplete");

            assert!(is_item_specific_validation_failure(&error));
            assert_eq!(accepted, 1);
            assert_eq!(progress.accepted_fingerprints.len(), 1);
            assert!(progress.contains(&valid));
        }
    }

    #[test]
    fn snapshot_upload_progress_path_stays_policy_scoped() {
        let index = Path::new(
            "/support/snapshots/codex-scan-index-attribution-key-attribution-labels.json",
        );

        assert_eq!(
            snapshot_upload_progress_path(index),
            PathBuf::from(
                "/support/snapshots/codex-scan-index-attribution-key-attribution-labels-upload-progress.json"
            )
        );
    }

    #[test]
    fn snapshot_v2_index_isolated_from_old_daemon_path() {
        let v1 =
            Path::new("/support/snapshots/destinations/hash/codex-scan-index-attribution.json");
        assert_eq!(
            snapshot_v2_index_path(v1),
            PathBuf::from(
                "/support/snapshots/destinations/hash/codex-scan-index-attribution-v2.json"
            )
        );
        assert_eq!(
            snapshot_upload_progress_path(&snapshot_v2_index_path(v1)),
            PathBuf::from(
                "/support/snapshots/destinations/hash/codex-scan-index-attribution-v2-upload-progress.json"
            )
        );
    }

    #[test]
    fn snapshot_scan_index_is_relay_destination_scoped() {
        let policy_index = Path::new("/support/snapshots/codex-scan-index-attribution-labels.json");
        let destination = format!("{:064x}", 42);

        assert_eq!(
            snapshot_destination_scoped_index_path(policy_index, &destination),
            PathBuf::from(format!(
                "/support/snapshots/destinations/{destination}/codex-scan-index-attribution-labels.json"
            ))
        );
    }

    #[test]
    fn snapshot_upload_progress_resets_when_relay_device_changes() {
        let root = test_dir("snapshot-upload-progress-destination-switch");
        let path = root.join("codex-scan-index-upload-progress.json");
        let device_a = LocalDeviceBinding {
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let device_b = LocalDeviceBinding {
            // Backend may preserve the device row while rotating its account
            // credential, so the secret participates in destination identity.
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let namespace_a = snapshot_upload_destination_namespace(&device_a, "secret-a");
        let namespace_b = snapshot_upload_destination_namespace(&device_b, "secret-b");
        assert_ne!(namespace_a, namespace_b);

        let accepted = format!("{:064x}", 7);
        let mut progress = SnapshotUploadProgress::new(namespace_a, test_quarantine_witness());
        progress.record([accepted.as_str()]);
        progress.save(&path).expect("save account A progress");

        let rebuilt = SnapshotUploadProgress::load(&path, &namespace_b, test_quarantine_witness())
            .expect("mismatched ledger is quarantined and rebuilt");
        assert_eq!(rebuilt.destination_namespace_hash, namespace_b);
        assert!(
            !path.exists(),
            "invalid live ledger moved out of the active path"
        );
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_upload_progress_compare_and_swap_rejects_stale_writer() {
        let root = test_dir("snapshot-upload-progress-cas");
        let path = root.join("progress-v2.json");
        let namespace = format!("{:064x}", 42);
        let mut initial = SnapshotUploadProgress::new(namespace, test_quarantine_witness());
        initial.save(&path).expect("initial progress");

        let mut stale = SnapshotUploadProgress::load(
            &path,
            &initial.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .expect("stale view");
        let mut winner = SnapshotUploadProgress::load(
            &path,
            &initial.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .expect("winner view");
        winner.record(["a".repeat(64).as_str()]);
        winner.save(&path).expect("winner save");
        stale.record(["b".repeat(64).as_str()]);
        stale
            .save(&path)
            .expect_err("stale upload progress must not clobber winner");
        let observed = SnapshotUploadProgress::load(
            &path,
            &initial.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .expect("load winner");
        assert!(observed.accepted_fingerprints.contains(&"a".repeat(64)));
        assert!(!observed.accepted_fingerprints.contains(&"b".repeat(64)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_upload_progress_stale_clear_cannot_delete_winner() {
        let root = test_dir("snapshot-upload-progress-clear-cas");
        let path = root.join("progress-v2.json");
        let namespace = format!("{:064x}", 43);
        let mut initial = SnapshotUploadProgress::new(namespace, test_quarantine_witness());
        initial.save(&path).expect("initial progress");
        let stale = SnapshotUploadProgress::load(
            &path,
            &initial.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .expect("stale view");
        let mut winner = stale.clone();
        winner.record(["c".repeat(64).as_str()]);
        winner.save(&path).expect("winner advances generation");

        stale
            .clear(&path)
            .expect_err("stale clear cannot delete a newer checkpoint");
        assert!(path.exists());
        winner.clear(&path).expect("winning generation clears");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_upload_progress_quarantines_truncated_state_and_rebuilds() {
        let root = test_dir("snapshot-upload-progress-corrupt");
        let path = root.join("progress-v2.json");
        std::fs::create_dir_all(&root).expect("create progress root");
        std::fs::write(&path, b"{\"schema_version\":2").expect("write truncated progress");
        let namespace = format!("{:064x}", 44);
        let rebuilt = SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness())
            .expect("truncated progress is quarantined");
        assert_eq!(
            rebuilt,
            SnapshotUploadProgress::new(namespace, test_quarantine_witness())
        );
        assert!(!path.exists());
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_upload_progress_quarantines_unbounded_retry_deadline() {
        let root = test_dir("snapshot-upload-progress-unbounded-retry");
        let path = root.join("progress-v2.json");
        let namespace = format!("{:064x}", 46);
        let fingerprint = "f".repeat(64);
        let mut corrupt = SnapshotUploadProgress::new(namespace.clone(), test_quarantine_witness());
        corrupt.quarantined_fingerprints.insert(
            fingerprint,
            SnapshotQuarantineRecord {
                witness: test_quarantine_witness(),
                retry_after_unix_seconds: u64::MAX,
                upload_body_witness: None,
                failed_reconstruction_count: 1,
                disposition: SnapshotQuarantineDisposition::RetryPending,
            },
        );
        corrupt.save(&path).expect("persist far-future deadline");

        let rebuilt = SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness())
            .expect("far-future deadline is quarantined rather than fencing forever");
        assert!(rebuilt.quarantined_fingerprints.is_empty());
        assert!(!path.exists());
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_upload_progress_retries_same_fingerprint_after_contract_upgrade() {
        let root = test_dir("snapshot-upload-progress-quarantine-upgrade");
        let path = root.join("progress-v2.json");
        let namespace = format!("{:064x}", 45);
        let fingerprint = "d".repeat(64);
        let old_witness = test_quarantine_witness();
        let mut progress = SnapshotUploadProgress::new(namespace.clone(), old_witness);
        progress.quarantine([fingerprint.as_str()]);
        progress.save(&path).expect("persist quarantine");

        let mut repaired_witness = test_quarantine_witness();
        repaired_witness.collector_version.push_str("-repair");
        let mut repaired = SnapshotUploadProgress::load(&path, &namespace, repaired_witness)
            .expect("load after repair");
        repaired.prepare_quarantine_retries(&BTreeMap::new());
        assert!(!repaired.contains(&fingerprint));
        assert!(repaired.active_quarantine_retries.contains(&fingerprint));
        assert!(repaired
            .quarantined_fingerprints
            .get(&fingerprint)
            .is_some_and(|record| record.retry_after_unix_seconds > current_unix_seconds()));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unchanged_quarantine_waits_without_hot_loop_then_retries_backend_recovery() {
        let fingerprint = "e".repeat(64);
        let mut progress = test_upload_progress();
        progress.quarantine([fingerprint.as_str()]);
        let mut accepted = 0;
        let mut attempts = 0;
        upload_resumable_batches(
            std::slice::from_ref(&fingerprint),
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| {
                attempts += 1;
                Ok(accepted_batch(1))
            },
            |_| Ok(()),
        )
        .expect("non-due quarantine is skipped");
        assert_eq!(attempts, 0);
        assert_eq!(accepted, 0);

        progress
            .quarantined_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        progress.prepare_quarantine_retries(&BTreeMap::new());
        upload_resumable_batches(
            std::slice::from_ref(&fingerprint),
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| {
                attempts += 1;
                Ok(accepted_batch(1))
            },
            |_| Ok(()),
        )
        .expect("backend-only recovery is retried after the bounded delay");
        assert_eq!(attempts, 1);
        assert_eq!(accepted, 1);
    }

    /// Regression for the live 0.1.121 strand: the quarantine deadline became
    /// due after a settled sibling had already advanced the shared backend
    /// head, but an independently backed-off terminal-unhealthy traversal
    /// yielded no upload item. A vacuous completed upload must not let the
    /// disposable ledger erase the index-owned retry obligation.
    #[test]
    fn due_quarantine_empty_scan_rearms_instead_of_clearing_the_obligation() {
        let root = test_dir("due-quarantine-terminal-unhealthy-empty-scan");
        let session_path = root.join("session.jsonl");
        std::fs::create_dir_all(&root).expect("create retry fixture root");
        std::fs::write(
            &session_path,
            concat!(
                "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-08-31T08:00:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1788163201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
            ),
        )
        .expect("write manifest-present source revision");
        let mut index = ScanIndex::default();
        let mut first_scan = crate::snapshots::scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            "2026-09-01T02:00:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
        )
        .expect("seed manifest-present revision");
        crate::snapshots::finalize_scan_after_policy(
            SnapshotSource::Pi,
            &mut first_scan,
            &mut index,
        );
        let fingerprint = first_scan.snapshots[0].snapshot_fingerprint.clone();
        let mut quarantine = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Pi);
        quarantine.retry_after_unix_seconds = 0;
        quarantine.upload_body_witness = Some(fingerprint.clone());
        index
            .quarantined_snapshot_fingerprints
            .insert(fingerprint.clone(), quarantine);
        let collected_at = "2026-09-01T03:27:03Z";
        index.install_terminal_unhealthy_traversal_for_retry_test(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            u64::try_from(
                OffsetDateTime::parse(collected_at, &time::format_description::well_known::Rfc3339)
                    .expect("fixture time")
                    .unix_timestamp(),
            )
            .expect("positive fixture time")
            .saturating_add(60 * 60),
        );

        let mut progress = SnapshotUploadProgress::new(
            format!("{:064x}", 42),
            snapshot_quarantine_witness(SnapshotSource::Pi),
        );
        progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
        let scan = crate::snapshots::scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            collected_at,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
        )
        .expect("independently backed-off terminal traversal returns a scan receipt");
        assert!(scan.snapshots.is_empty());
        assert!(!scan.census_complete);
        let mut accepted = 0;
        let mut upload_calls = 0;
        let result = upload_resumable_batches(
            &scan.snapshots,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            |_| {
                upload_calls += 1;
                Ok(accepted_batch(0))
            },
            |_| Ok(()),
        )
        .expect("an empty bounded scan is a vacuous completed upload");
        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!((upload_calls, accepted), (0, 0));

        index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        let retained = index
            .quarantined_snapshot_fingerprints
            .get(&fingerprint)
            .expect("an empty scan must leave the retry armed");
        assert!(
            retained.retry_after_unix_seconds > current_unix_seconds(),
            "the fired deadline must be replaced by a future deadline"
        );
        assert!(
            index
                .legacy_settlement_reconciliation_pending_fingerprints()
                .is_empty(),
            "the current-schema manifest revision stays armed rather than becoming unproven"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn due_retry_uploads_only_the_quarantined_revision_after_its_sibling_settled() {
        let settled_sibling = "d".repeat(64);
        let retry = "e".repeat(64);
        let mut progress = test_upload_progress();
        progress.record([settled_sibling.as_str()]);
        progress.quarantine([retry.as_str()]);
        progress
            .quarantined_fingerprints
            .get_mut(&retry)
            .expect("retry quarantine")
            .retry_after_unix_seconds = 0;
        assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));

        let mut accepted = 0;
        let mut uploaded = Vec::new();
        let result = upload_resumable_batches(
            &[settled_sibling.clone(), retry.clone()],
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                uploaded.push(batch.clone());
                Ok(entity_ack_batch(&batch, &[], &[]))
            },
            |_| Ok(()),
        )
        .expect("the later revision retries after its sibling settled");

        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(uploaded, vec![vec![retry.clone()]]);
        assert_eq!(accepted, 1);
        assert!(progress.accepted_fingerprints.contains(&settled_sibling));
        assert!(progress.accepted_fingerprints.contains(&retry));
        assert!(progress.quarantined_fingerprints.is_empty());
    }

    #[test]
    fn divergent_legacy_reconcile_is_batch_isolated_and_lands_in_bounded_quarantine() {
        let ordinary = "a".repeat(64);
        let divergent_reconcile = "b".repeat(64);
        let reconcile_class = BTreeSet::from([divergent_reconcile.clone()]);
        let mut progress = test_upload_progress();
        progress.quarantine([divergent_reconcile.as_str()]);
        progress
            .quarantined_fingerprints
            .get_mut(&divergent_reconcile)
            .expect("legacy retry is armed")
            .retry_after_unix_seconds = 0;
        assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));

        let mut accepted = 0;
        let mut observed_classes = Vec::new();
        let result = upload_resumable_batches_with_body_witness_partitioned(
            &[ordinary.clone(), divergent_reconcile.clone()],
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |item| item.clone(),
            |item| reconcile_class.contains(item),
            |batch| {
                let is_reconcile = batch
                    .iter()
                    .all(|fingerprint| reconcile_class.contains(fingerprint));
                assert!(
                    is_reconcile
                        || batch
                            .iter()
                            .all(|fingerprint| !reconcile_class.contains(fingerprint)),
                    "ordinary and CAS-bootstrap reconciliation must never share one request"
                );
                observed_classes.push(is_reconcile);
                if is_reconcile {
                    let mut response = entity_ack_batch(&[], &[], &batch);
                    for entity in &mut response.conflict_entities {
                        entity.head_challenge = Some("c".repeat(64));
                    }
                    Ok(response)
                } else {
                    Ok(entity_ack_batch(&batch, &[], &[]))
                }
            },
            |_| Ok(()),
        )
        .expect("a normal entity conflict is a closed-machine result");

        assert_eq!(result, ResumableUploadResult::Conflicted { count: 1 });
        assert_eq!(observed_classes, vec![false, true]);
        assert_eq!(accepted, 1);
        assert!(progress.accepted_fingerprints.contains(&ordinary));
        let quarantined = progress
            .quarantined_fingerprints
            .get(&divergent_reconcile)
            .expect("divergent reconcile remains quarantined");
        assert_eq!(
            quarantined.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert_eq!(quarantined.failed_reconstruction_count, 2);
        assert!(quarantined.retry_after_unix_seconds > current_unix_seconds());
    }

    #[test]
    fn durable_ack_dominates_stale_index_quarantine_after_restart() {
        let fingerprint = "c".repeat(64);
        let mut index_quarantine = BTreeMap::new();
        let mut stale = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
        stale.retry_after_unix_seconds = 0;
        stale.upload_body_witness = Some(fingerprint.clone());
        index_quarantine.insert(fingerprint.clone(), stale);

        let mut progress = test_upload_progress();
        progress.record([fingerprint.as_str()]);
        assert!(!progress.prepare_quarantine_retries(&index_quarantine));
        assert!(progress.accepted_fingerprints.contains(&fingerprint));
        assert!(!progress.quarantined_fingerprints.contains_key(&fingerprint));
        assert!(!progress.active_quarantine_retries.contains(&fingerprint));
    }

    #[test]
    fn supersede_while_quarantined_records_terminal_counter_and_cannot_rearm() {
        let current = "a".repeat(64);
        let stale = "b".repeat(64);
        let mut progress = test_upload_progress();
        progress.quarantine([current.as_str(), stale.as_str()]);

        assert!(progress.retain_current_quarantines(&BTreeSet::from([current.clone()])));
        assert_eq!(progress.quarantined_fingerprints.len(), 2);
        assert_eq!(
            progress
                .quarantined_fingerprints
                .get(&stale)
                .expect("superseded fingerprint remains explicitly accounted")
                .disposition,
            SnapshotQuarantineDisposition::SupersededTerminal
        );
        let mut index = ScanIndex::default();
        index.file_snapshot_fingerprints.insert(
            "current.jsonl".to_string(),
            BTreeSet::from([current.clone()]),
        );
        index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        assert_eq!(index.snapshot_superseded_terminal_count(), 1);
        assert!(!index
            .legacy_settlement_reconciliation_pending_fingerprints()
            .contains(&stale));
        assert!(!progress.retain_current_quarantines(&BTreeSet::from(["a".repeat(64)])));
    }

    #[test]
    fn legacy_reconciliation_is_fail_closed_until_exact_existing_entity_ack() {
        let fingerprint = "a".repeat(64);
        let request_fingerprints = BTreeSet::from([fingerprint.clone()]);
        let legacy_pending = request_fingerprints.clone();
        let mut progress = test_upload_progress();
        progress.quarantine([fingerprint.as_str()]);
        progress
            .quarantined_fingerprints
            .get_mut(&fingerprint)
            .expect("armed legacy identity")
            .retry_after_unix_seconds = 0;
        progress.prepare_quarantine_retries(&BTreeMap::new());

        let rejected_bool = serde_json::from_value::<crate::snapshot_client::SnapshotBatchResponse>(
            serde_json::json!({
                "accepted": false,
                "sessions_reconciled": 0,
                "session_ids": [],
                "disabled": false
            }),
        );
        assert!(rejected_bool.is_err(), "accepted:false is not a batch ACK");
        let rejected_status = serde_json::from_value::<
            crate::snapshot_client::SnapshotStatusResponse,
        >(serde_json::json!({
            "accepted": false,
            "source": "codex",
            "machine_id": "otm_test",
            "disabled": false,
            "disabled_reason": null,
            "settlement_ack": {
                "accepted_snapshot_fingerprints": [fingerprint.clone()]
            }
        }))
        .expect("forward-tolerant status receipt");
        assert!(!rejected_status.accepted);

        let mut disabled = accepted_batch(0);
        disabled.disabled = true;
        assert!(require_normal_write_ack_for_legacy_reconciliation(
            &disabled,
            &request_fingerprints,
            &legacy_pending,
        )
        .is_err());

        let missing_contract = accepted_batch(1);
        assert!(require_normal_write_ack_for_legacy_reconciliation(
            &missing_contract,
            &request_fingerprints,
            &legacy_pending,
        )
        .is_err());

        let partial = entity_ack_batch(&[], &[], &[]);
        assert!(partial
            .validate_entity_ack_identities(std::iter::once((
                format!("session-{fingerprint}").as_str(),
                fingerprint.as_str(),
            )))
            .is_err());
        assert!(progress.quarantined_fingerprints.contains_key(&fingerprint));
        assert!(progress.active_quarantine_retries.contains(&fingerprint));

        let exact = entity_ack_batch(std::slice::from_ref(&fingerprint), &[], &[]);
        exact
            .validate_entity_ack_identities(std::iter::once((
                format!("session-{fingerprint}").as_str(),
                fingerprint.as_str(),
            )))
            .expect("exact fingerprint-bound entity ACK");
        require_normal_write_ack_for_legacy_reconciliation(
            &exact,
            &request_fingerprints,
            &legacy_pending,
        )
        .expect("deployed entity ACK contract is sufficient");
    }

    #[test]
    fn due_quarantine_retries_are_fair_and_capped_to_one_batch_per_cycle() {
        let mut progress = test_upload_progress();
        let witness = test_quarantine_witness();
        for value in 0..(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE + 5) {
            progress.quarantined_fingerprints.insert(
                format!("{value:064x}"),
                SnapshotQuarantineRecord {
                    witness: witness.clone(),
                    retry_after_unix_seconds: value as u64,
                    upload_body_witness: None,
                    failed_reconstruction_count: 1,
                    disposition: SnapshotQuarantineDisposition::RetryPending,
                },
            );
        }
        progress.prepare_quarantine_retries(&BTreeMap::new());
        assert_eq!(
            progress.active_quarantine_retries.len(),
            SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE
        );
        assert_eq!(
            progress.quarantined_fingerprints.len(),
            SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE + 5,
            "leased retries remain durably armed until exact ACK settlement"
        );
        let first_deferred = format!("{SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE:064x}");
        let last_leased = format!("{:064x}", SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE - 1);
        assert_eq!(
            progress
                .active_quarantine_retries
                .iter()
                .next_back()
                .map(String::as_str),
            Some(last_leased.as_str())
        );
        assert!(!progress.active_quarantine_retries.contains(&first_deferred));
    }

    #[test]
    fn concurrent_relay_switch_rejects_final_cursor_commit() {
        let device_a = LocalDeviceBinding {
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let device_b = LocalDeviceBinding {
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let expected = snapshot_upload_destination_namespace(&device_a, "secret-a");

        let error = validate_snapshot_destination(&expected, &device_b, "secret-b")
            .expect_err("destination B must not commit destination A's cursor");
        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
        assert_eq!(safe_error(&error), "local snapshot state failed");
    }

    #[test]
    fn enabled_snapshot_sources_follow_device_grants() {
        let device = LocalDeviceBinding {
            device_id: "device".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string(), "pi".to_string()],
        };

        assert_eq!(
            enabled_snapshot_sources(&device),
            vec![SnapshotSource::Codex, SnapshotSource::Pi]
        );
    }

    #[test]
    fn enabled_snapshot_sources_excludes_sources_not_granted() {
        let device = LocalDeviceBinding {
            device_id: "device".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["claude_code".to_string()],
        };

        assert_eq!(
            enabled_snapshot_sources(&device),
            vec![SnapshotSource::ClaudeCode]
        );
    }

    #[test]
    fn one_shot_sync_slot_is_single_flight() {
        set_one_shot_sync_in_flight(false);

        assert!(claim_one_shot_sync_slot());
        assert!(!claim_one_shot_sync_slot());

        set_one_shot_sync_in_flight(false);
        assert!(claim_one_shot_sync_slot());
        set_one_shot_sync_in_flight(false);
    }

    #[test]
    fn snapshot_index_path_is_source_scoped() {
        let root = Path::new("/support");

        assert_eq!(
            snapshot_index_path(root, SnapshotSource::Codex),
            PathBuf::from("/support/snapshots/codex-scan-index.json")
        );
        assert_eq!(
            snapshot_index_path(root, SnapshotSource::ClaudeCode),
            PathBuf::from("/support/snapshots/claude_code-scan-index.json")
        );
        assert_eq!(
            snapshot_index_path(root, SnapshotSource::Pi),
            PathBuf::from("/support/snapshots/pi-scan-index.json")
        );
    }

    #[test]
    fn legacy_policy_paths_remain_available_for_one_time_adoption() {
        let root = Path::new("/support");
        assert_eq!(
            legacy_policy_scoped_snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: false,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: false,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-no-titles.json")
        );
        assert_eq!(
            legacy_policy_scoped_snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: false,
                    workspace_labels_enabled: false,
                    session_artifacts_enabled: false,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-no-titles-no-labels.json")
        );
        // Opt-in artifacts get a distinct path so toggling the flag re-scans
        // unchanged transcripts.
        assert_eq!(
            legacy_policy_scoped_snapshot_index_path(
                root,
                SnapshotSource::ClaudeCode,
                SnapshotUploadPolicy {
                    session_titles_enabled: true,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: true,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/claude_code-scan-index-artifacts.json")
        );
        assert_eq!(
            legacy_policy_scoped_snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: false,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: true,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-no-titles-artifacts.json")
        );
        assert_eq!(
            legacy_policy_scoped_snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: true,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: false,
                    session_attribution_enabled: true,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-attribution-pending.json")
        );
        assert_eq!(
            legacy_policy_scoped_snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_attribution_enabled: true,
                    session_attribution_labels_enabled: true,
                    ..SnapshotUploadPolicy::default()
                },
                None,
            ),
            PathBuf::from(
                "/support/snapshots/codex-scan-index-attribution-pending-attribution-labels.json"
            )
        );
    }

    #[test]
    fn upload_context_is_inventory_independent_but_key_epoch_and_policy_sensitive() {
        let policy = SnapshotUploadPolicy {
            session_attribution_enabled: true,
            session_attribution_labels_enabled: true,
            ..SnapshotUploadPolicy::default()
        };
        let stable = snapshot_upload_context_fingerprint(policy, Some("stable-key-epoch"));
        assert_eq!(
            stable,
            snapshot_upload_context_fingerprint(policy, Some("stable-key-epoch"))
        );
        assert_ne!(
            stable,
            snapshot_upload_context_fingerprint(policy, Some("rotated-key-epoch"))
        );
        assert_ne!(
            stable,
            snapshot_upload_context_fingerprint(SnapshotUploadPolicy::default(), None)
        );
    }

    #[test]
    fn exact_legacy_checkpoint_is_adopted_once_without_overwrite() {
        let root = test_dir("snapshot-index-legacy-adoption");
        let legacy = root.join("legacy.json");
        let stable = root.join("stable").join("index.json");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(&legacy, br#"{"files":{"legacy":{"size_bytes":1,"modified_unix_seconds":2,"source_file_fingerprint":"source","last_snapshot_fingerprint":"snapshot"}}}"#)
            .expect("write legacy index");

        let held = SnapshotProgressLock::acquire(&stable).expect("hold destination lock");
        adopt_legacy_checkpoint_file(&legacy, &stable)
            .expect_err("overlapping adopter must not copy outside the destination lock");
        assert!(!stable.exists());
        drop(held);

        adopt_legacy_checkpoint_file(&legacy, &stable).expect("adopt exact legacy checkpoint");
        assert_eq!(
            std::fs::read(&stable).expect("read stable index"),
            std::fs::read(&legacy).expect("read legacy index"),
        );

        std::fs::write(&legacy, b"newer legacy bytes").expect("replace legacy index");
        adopt_legacy_checkpoint_file(&legacy, &stable).expect("keep stable checkpoint");
        assert_ne!(
            std::fs::read(&stable).expect("read stable index"),
            std::fs::read(&legacy).expect("read replaced legacy index"),
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reverify_backoff_doubles_from_initial_and_caps() {
        assert_eq!(reverify_backoff_delay(0), Duration::from_secs(2 * 60));
        assert_eq!(reverify_backoff_delay(1), Duration::from_secs(4 * 60));
        assert_eq!(reverify_backoff_delay(2), Duration::from_secs(8 * 60));
        assert_eq!(reverify_backoff_delay(3), Duration::from_secs(16 * 60));
        assert_eq!(reverify_backoff_delay(4), FAILED_VERIFY_RETRY_MAX);
        assert_eq!(reverify_backoff_delay(20), FAILED_VERIFY_RETRY_MAX);
        assert_eq!(reverify_backoff_delay(u32::MAX), FAILED_VERIFY_RETRY_MAX);
    }

    #[test]
    fn agent_status_ttl_has_jitter_buffer_over_sync_interval() {
        let ttl = Duration::from_secs(AGENT_STATUS_SNAPSHOT_TTL_MINUTES as u64 * 60);

        assert!(ttl > SNAPSHOT_SYNC_INTERVAL);
    }

    #[test]
    fn local_health_heartbeat_cadence_is_not_bound_to_snapshot_scans() {
        assert!(LOCAL_HEALTH_PROJECTION_INTERVAL < SNAPSHOT_SYNC_INTERVAL);
        assert!(LOCAL_HEALTH_PROJECTION_INTERVAL <= Duration::from_secs(60));
    }

    #[test]
    fn api_base_url_prefers_persisted_connection_then_env() {
        assert_eq!(
            normalize_api_base_url(
                Some("https://ottto.test/backend/".to_string()),
                Some("http://127.0.0.1:4318".to_string()),
            ),
            "https://ottto.test/backend"
        );
        assert_eq!(
            normalize_api_base_url(None, Some("http://127.0.0.1:4318/".to_string())),
            "http://127.0.0.1:4318"
        );
        assert_eq!(normalize_api_base_url(None, None), DEFAULT_API_BASE_URL);
    }

    #[test]
    fn safe_error_reports_sync_phase_without_raw_details() {
        let snapshot_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "http_5xx",
            true,
            true,
        ))
        .context("upload local snapshots");
        assert_eq!(
            safe_error(&snapshot_error),
            "local snapshot upload failed (endpoint=snapshot_batch, status_family=http_5xx, retryable=true, request_id=present)"
        );

        let agent_status_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "agent status upload",
            "agent_status",
            "transport_timeout",
            true,
            false,
        ));
        assert_eq!(
            safe_error(&agent_status_error),
            "agent status upload failed (endpoint=agent_status, status_family=transport_timeout, retryable=true, request_id=absent)"
        );

        assert_eq!(
            safe_error(&anyhow!("upload agent status failed: HTTP 500")),
            "agent status upload failed"
        );
        assert_eq!(
            safe_error(&anyhow!("upload local snapshots: request timed out")),
            "local snapshot upload failed"
        );
        assert_eq!(
            safe_error(&anyhow!("issue relay token failed: rejected")),
            "relay token request failed"
        );
        assert_eq!(
            safe_error(&anyhow!(
                "local snapshot batch failed daemon/backend contract preflight: snapshot[0]"
            )),
            "local snapshot payload validation failed"
        );
        assert_eq!(
            safe_error(&anyhow!(
                "backend rejected snapshot batch payload validation: HTTP 422"
            )),
            "local snapshot payload validation failed"
        );
        assert_eq!(
            safe_error(&anyhow::Error::new(LocalHealthProjectionRejected {
                status: 422
            })),
            "local health projection rejected"
        );
        assert_eq!(
            safe_error(&anyhow::Error::new(LocalHealthAuthorizationRejected {
                status: 401
            })),
            "local health authorization rejected"
        );
    }

    #[test]
    fn local_health_loop_waits_quietly_for_claim_credentials() {
        assert!(local_health_upload_can_wait_quietly(&anyhow!(
            "relay device credentials are missing"
        )));
        assert!(local_health_upload_can_wait_quietly(&anyhow!(
            "machine identity is missing"
        )));
        assert!(local_health_upload_can_wait_quietly(&anyhow!(
            "registered device has no enabled sources"
        )));
        assert!(!local_health_upload_can_wait_quietly(&anyhow!(
            "upload local health projection failed"
        )));
    }

    #[test]
    fn local_health_upload_failures_are_classified_by_contract_boundary() {
        assert_eq!(
            local_health_upload_failure_kind(&anyhow::Error::new(LocalHealthProjectionRejected {
                status: 422
            })),
            LocalHealthUploadFailureKind::ContractRejected
        );
        assert_eq!(
            local_health_upload_failure_kind(&anyhow::Error::new(
                LocalHealthAuthorizationRejected { status: 401 }
            )),
            LocalHealthUploadFailureKind::AuthRejected
        );
        assert_eq!(
            local_health_upload_failure_kind(&anyhow!("upload local health projection failed")),
            LocalHealthUploadFailureKind::BackendUnreachable
        );
    }

    #[test]
    #[serial]
    fn manual_agent_status_upload_posts_granted_refreshed_snapshots() {
        let root = test_dir("manual-agent-status-upload");
        let support_dir = root.join("support");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = agent_status_upload_server(captured.clone());
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);

        FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("otm_test".to_string()),
                sources: vec!["codex".to_string()],
            })
            .expect("save device");
        std::fs::write(
            secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .expect("save device secret");

        let uploaded = upload_agent_status_snapshots(&[
            test_agent_status(SourceKind::Codex),
            test_agent_status(SourceKind::ClaudeCode),
        ])
        .expect("upload agent status");

        assert_eq!(uploaded, 1);
        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[0].contains("\"source\":\"codex\""));
        assert!(requests[0].contains("\"client_name\":\"ottto-service\""));
        assert!(requests[0].contains("\"client_version\":"));
        assert!(requests[0].contains("\"machine_id\":\"otm_test\""));
        assert!(requests[0].contains("\"platform\":"));
        assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
        assert!(requests[1].contains("POST /api/v1/agent-status/snapshots"));
        assert!(requests[1].contains("Authorization:"));
        assert!(requests[1].contains("relay-token-codex"));
        assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
        assert!(requests[1].contains("\"source\":\"codex\""));
        assert!(!requests[1].contains("claude_code"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn per_source_agent_status_upload_batches_two_claude_accounts() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_server = captured.clone();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status batch backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept agent status batch");
            let request = read_complete_http_request(&mut stream);
            captured_server
                .lock()
                .expect("capture agent status batch")
                .push(request);
            let body = r#"{"accepted":2,"machine_id":"otm_test","sources":["claude_code"]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write agent status batch response");
        });
        let client = SnapshotApiClient::new(format!("http://{address}"));
        let mut first = test_agent_status(SourceKind::ClaudeCode);
        first.account = Some(test_agent_account("account-hash-a", "organization-hash-a"));
        let mut second = test_agent_status(SourceKind::ClaudeCode);
        second.account = Some(test_agent_account("account-hash-b", "organization-hash-b"));

        upload_agent_status(&client, "relay-token-claude", "otm_test", &[first, second])
            .expect("upload two-account batch");

        let requests = captured.lock().expect("captured batch requests");
        assert_eq!(requests.len(), 1);
        let body = requests[0].split("\r\n\r\n").nth(1).expect("request body");
        let request: serde_json::Value = serde_json::from_str(body).expect("parse request body");
        let snapshots = request["snapshots"].as_array().expect("snapshot batch");
        assert_eq!(snapshots.len(), 2);
        assert!(snapshots
            .iter()
            .all(|snapshot| snapshot["source"] == "claude_code"));
        assert_eq!(snapshots[0]["captured_at"], snapshots[1]["captured_at"]);
        assert_ne!(
            snapshots[0]["account"]["account_identifier_hash"],
            snapshots[1]["account"]["account_identifier_hash"]
        );
    }

    #[test]
    fn empty_agent_status_upload_is_a_noop_and_reconciliation_keeps_default_owner() {
        let client = SnapshotApiClient::new("http://127.0.0.1:1".to_string());
        upload_agent_status(&client, "unused", "otm_test", &[])
            .expect("empty upload must not touch the network or abort scanning");

        let mut default_health = test_agent_status(SourceKind::ClaudeCode);
        default_health.account = Some(test_agent_account(
            "default-account-hash",
            "default-organization-hash",
        ));
        let mut custom_upload = test_agent_status(SourceKind::ClaudeCode);
        custom_upload.account = Some(test_agent_account(
            "custom-account-hash",
            "custom-organization-hash",
        ));
        let collection = AgentStatusCollection {
            snapshots: vec![custom_upload],
            source_health_snapshot: default_health,
        };

        let reconciliation = reconciliation_agent_status(&collection);
        assert_eq!(
            reconciliation
                .account
                .as_ref()
                .and_then(|account| account.account_identifier_hash.as_deref()),
            Some("default-account-hash"),
            "a custom upload row must never become default-session ownership evidence"
        );
    }

    #[test]
    #[serial]
    fn manual_agent_status_upload_attempts_remaining_sources_after_failure() {
        let root = test_dir("manual-agent-status-partial-failure");
        let support_dir = root.join("support");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = agent_status_partial_failure_server(captured.clone());
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);

        FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("otm_test".to_string()),
                sources: vec!["codex".to_string(), "claude_code".to_string()],
            })
            .expect("save device");
        std::fs::write(
            secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .expect("save device secret");

        let error = upload_agent_status_snapshots(&[
            test_agent_status(SourceKind::Codex),
            test_agent_status(SourceKind::ClaudeCode),
        ])
        .expect_err("partial upload should report aggregate failure");

        assert_eq!(safe_error(&error), "agent status upload failed");
        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].contains("\"source\":\"codex\""));
        assert!(requests[1].contains("\"source\":\"claude_code\""));
        assert!(requests[2].contains("POST /api/v1/agent-status/snapshots"));
        assert!(requests[2].contains("\"source\":\"claude_code\""));
        assert!(!requests[2].contains("\"source\":\"codex\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn local_health_upload_refreshes_inactive_device_before_retry() {
        let root = test_dir("local-health-upload-reactivates-device");
        let support_dir = root.join("support");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = local_health_reactivation_server(captured.clone());

        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        FileDeviceStore::default()
            .save(&device)
            .expect("save device");
        FileConnectionStore::default()
            .save(&LocalConnectionBinding {
                setup_run_id: "setup_stale".to_string(),
                setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
                machine_id: Some("otm_test".to_string()),
                claim_code: None,
                api_base_url: api_base_url.clone(),
            })
            .expect("save connection");
        std::fs::write(
            secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .expect("save device secret");
        std::fs::write(
            secrets_dir.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT),
            "otsr_stale",
        )
        .expect("save setup token");

        let client = SnapshotApiClient::new(api_base_url);
        upload_local_health_projection_reporting(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            &test_daemon("otm_test"),
        )
        .expect("upload retries after refresh");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[1].contains("POST /api/v1/setup-runs/setup_stale/local-client/refresh"));
        assert!(requests[1].contains("\"device_secret\":\"device-secret\""));
        assert!(requests[2].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[3].contains("POST /api/v1/apps/health/heartbeat"));
        assert!(requests[4].contains("POST /api/v1/apps/health/projection"));
        assert_eq!(
            FileConnectionStore::default()
                .load()
                .expect("load refreshed connection")
                .expect("connection exists")
                .setup_run_id,
            "setup_fresh"
        );
        assert_eq!(
            std::fs::read_to_string(secrets_dir.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT))
                .expect("read refreshed setup token"),
            "otsr_fresh"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial(source_manifests)]
    fn collector_status_report_mints_fresh_relay_token() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = snapshot_status_server(captured.clone());
        let client = SnapshotApiClient::new(api_base_url);
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };

        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts: SyncCounts::for_policy(30),
                state: CollectorState::Success,
            },
        )
        .expect("report status with fresh relay token");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
        assert!(requests[0].contains("\"source\":\"codex\""));
        assert!(requests[1].contains("POST /api/v1/agent-session-snapshots/status"));
        assert!(requests[1].contains("Authorization:"));
        assert!(requests[1].contains("relay-token-codex"));
        assert!(requests[1].contains("\"schema_version\":5"));
        assert!(requests[1].contains("\"source\":\"codex\""));
        assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
    }

    fn report_kind_test_device() -> LocalDeviceBinding {
        LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        }
    }

    /// Capture the wire body of one liveness beat, with or without a
    /// cycle-start clock.
    fn captured_checkin_receipt(scan_started_at: Option<&str>) -> serde_json::Value {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        report_checkin_status_with_fresh_relay_token(
            &client,
            &report_kind_test_device(),
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            scan_started_at,
        )
        .expect("liveness beat");
        let requests = captured.lock().expect("captured requests").clone();
        http_request_json(&requests[1])
    }

    /// Capture the wire body of one terminal receipt for a given outcome.
    fn captured_terminal_receipt(
        counts: SyncCounts,
        state: CollectorState<'_>,
        manifest_source: TerminalManifestSource<'_>,
        hint_days: u64,
    ) -> serde_json::Value {
        captured_terminal_receipt_under_hint(counts, state, manifest_source, hint_days, "")
    }

    /// Same, with extra JSON members appended to the activity hint the server
    /// answers — the backend's additive capability advertisements.
    fn captured_terminal_receipt_under_hint(
        counts: SyncCounts,
        state: CollectorState<'_>,
        manifest_source: TerminalManifestSource<'_>,
        hint_days: u64,
        hint_extra: &'static str,
    ) -> serde_json::Value {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server_with_hint_extras(
            captured.clone(),
            vec![(hint_days, hint_extra)],
        ));
        report_status_with_fresh_relay_token(
            &client,
            &report_kind_test_device(),
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            manifest_source,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts,
                state,
            },
        )
        .expect("terminal receipt");
        let requests = captured.lock().expect("captured requests").clone();
        http_request_json(&requests[1])
    }

    #[test]
    #[serial(source_manifests)]
    fn the_independent_heartbeat_declares_a_checkin() {
        let _source_manifests = SourceManifestTestGuard::new();
        let beat = captured_checkin_receipt(None);
        assert_eq!(beat["report_kind"], "checkin");
        // The pre-`report_kind` shape is unchanged, so a backend that predates
        // the field still infers exactly the same classification from it.
        assert!(beat["last_scan_started_at"].is_null());
        assert!(beat["last_scan_finished_at"].is_null());
    }

    #[test]
    #[serial(source_manifests)]
    fn the_cycle_start_marker_declares_a_checkin() {
        let _source_manifests = SourceManifestTestGuard::new();
        // `sync_once` posts this before any scanning: an in-progress marker,
        // not a result.
        let marker = captured_checkin_receipt(Some("2026-06-01T10:00:00Z"));
        assert_eq!(marker["report_kind"], "checkin");
        assert_eq!(marker["last_scan_started_at"], "2026-06-01T10:00:00Z");
        assert!(marker["last_scan_finished_at"].is_null());
    }

    /// A liveness beat may only repeat evidence the backend has already
    /// accepted. A durable terminal journal now exists (ottto#393), but no
    /// beat reads it — `report_checkin_status` has no path to it — so a beat
    /// replays nothing at all: every scan-result field is literally absent,
    /// zero, or false, and the only carried witness is the cached manifest
    /// from the last completed terminal report.
    #[test]
    #[serial(source_manifests)]
    fn a_liveness_beat_discloses_nothing_the_backend_has_not_accepted() {
        let _source_manifests = SourceManifestTestGuard::new();
        let beat = captured_checkin_receipt(Some("2026-06-01T10:00:00Z"));
        assert_eq!(beat["report_kind"], "checkin");
        assert_eq!(beat["enabled"], true);
        for absent in [
            "disabled_reason",
            "last_scan_finished_at",
            "last_success_at",
            "last_error_code",
            "last_error_message",
            "next_retry_at",
        ] {
            assert!(beat[absent].is_null(), "{absent} must be absent on a beat");
        }
        assert_eq!(beat["last_scan_cap_hit"], false);
        // The KEY must be missing, not present-and-false. The backend resolves
        // census completeness by whether the field was declared at all: an
        // omitted one retains what it already accepted, an explicit `false`
        // lowers it. `is_null()` would pass for a serialized `null` too, so
        // assert on the object's keys.
        assert!(
            !beat
                .as_object()
                .expect("beat is a JSON object")
                .contains_key("last_census_complete"),
            "a beat must not put last_census_complete on the wire at all: {beat}"
        );
        for counter in [
            "last_uploaded_count",
            "last_scanned_session_count",
            "last_scanned_file_count",
            "last_zero_snapshot_confirmed_count",
            "last_zero_snapshot_usage_evidence_count",
            "last_dropped_usage_record_count",
            "last_ownership_incomplete_file_count",
            "last_snapshot_unproven_terminal_count",
            "last_snapshot_superseded_terminal_count",
            "last_backfill_file_limit",
            "last_discovered_file_count",
            "last_skipped_file_count_due_to_limit",
            "last_semantic_noop_count",
            "last_symlink_rejected_count",
            "last_unreadable_path_count",
            "last_oversized_file_count",
            "last_disappeared_file_count",
            "last_malformed_json_line_count",
            "last_invalid_utf8_line_count",
            "last_over_line_cap_count",
            "last_recognized_usage_drop_count",
            "consecutive_failures",
        ] {
            assert_eq!(beat[counter], 0, "{counter} must be zero on a beat");
        }
    }

    /// Census completeness is the one census field with no arithmetic identity,
    /// so its wire treatment differs from every counter above and is asserted
    /// on its own.
    ///
    /// The backend merges a check-in's census into what it already accepted.
    /// Counters take a `max`, for which a beat's honest `0` is the identity and
    /// therefore harmless. Completeness takes a conjunction resolved through
    /// `model_fields_set`: an OMITTED value retains the accepted one, an
    /// explicitly declared `false` asserts incompleteness and lowers it. A beat
    /// has run no census, so it must send neither `false` (which would retract
    /// a complete census on every heartbeat) nor `true` (which would assert one
    /// it never measured) — it must send nothing. The terminal path, which did
    /// run the census, still states the measured value in both directions.
    #[test]
    #[serial(source_manifests)]
    fn only_a_scan_result_puts_census_completeness_on_the_wire() {
        let _source_manifests = SourceManifestTestGuard::new();

        for scan_started_at in [None, Some("2026-06-01T10:00:00Z")] {
            let beat = captured_checkin_receipt(scan_started_at);
            assert_eq!(beat["report_kind"], "checkin");
            assert!(
                !beat
                    .as_object()
                    .expect("beat is a JSON object")
                    .contains_key("last_census_complete"),
                "the key must be absent, not null and not false: {beat}"
            );
        }

        // Both terminal outcomes still declare what the census actually found.
        let mut complete = SyncCounts::for_policy(30);
        complete.census_complete = true;
        let terminal_complete = captured_terminal_receipt(
            complete,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            30,
        );
        assert_eq!(terminal_complete["report_kind"], "scan_status");
        assert_eq!(terminal_complete["last_census_complete"], true);

        let mut incomplete = SyncCounts::for_policy(30);
        incomplete.census_complete = false;
        let terminal_incomplete = captured_terminal_receipt(
            incomplete,
            CollectorState::Error {
                code: "scan_error",
                message: "local snapshot scan failed",
            },
            TerminalManifestSource::Withdraw,
            30,
        );
        assert_eq!(terminal_incomplete["report_kind"], "scan_status");
        assert_eq!(terminal_incomplete["last_census_complete"], false);
    }

    #[test]
    #[serial(source_manifests)]
    fn a_fresh_terminal_report_declares_a_scan_status() {
        let _source_manifests = SourceManifestTestGuard::new();
        let mut counts = SyncCounts::for_policy(30);
        counts.census_complete = true;
        counts.uploaded_count = 3;
        counts.scanned_session_count = 3;
        let terminal = captured_terminal_receipt(
            counts,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            30,
        );
        assert_eq!(terminal["report_kind"], "scan_status");
        assert!(terminal["last_scan_finished_at"].is_string());
        assert_eq!(terminal["last_census_complete"], true);
        assert_eq!(terminal["last_uploaded_count"], 3);
    }

    #[test]
    #[serial(source_manifests)]
    fn a_new_or_changed_error_declares_a_scan_status() {
        let _source_manifests = SourceManifestTestGuard::new();
        for (code, message) in [
            ("scan_error", "local snapshot scan failed"),
            ("upload_error", "local snapshot upload failed"),
        ] {
            let terminal = captured_terminal_receipt(
                SyncCounts::for_policy(30),
                CollectorState::Error { code, message },
                TerminalManifestSource::Withdraw,
                30,
            );
            assert_eq!(terminal["report_kind"], "scan_status");
            assert_eq!(terminal["last_error_code"], code);
            assert_eq!(terminal["consecutive_failures"], 1);
        }

        // The derived parse_error: a scan that "succeeded" while losing
        // recognized usage is a changed loss census, never a liveness beat.
        let mut counts = SyncCounts::for_policy(30);
        counts.discovered_file_count = 1;
        counts.dropped_usage_record_count = 1_105;
        counts.recognized_usage_drop_count = 1_105;
        counts.ownership_incomplete_file_count = 1;
        let lossy = captured_terminal_receipt(
            counts,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            30,
        );
        assert_eq!(lossy["report_kind"], "scan_status");
        assert_eq!(lossy["last_error_code"], "parse_error");
        assert_eq!(lossy["last_dropped_usage_record_count"], 1_105);
    }

    #[test]
    #[serial(source_manifests)]
    fn a_cap_hit_change_declares_a_scan_status() {
        let _source_manifests = SourceManifestTestGuard::new();
        let mut counts = SyncCounts::for_policy(30);
        counts.scan_cap_hit = true;
        counts.discovered_file_count = 1_100;
        counts.skipped_file_count_due_to_limit = 100;
        let terminal = captured_terminal_receipt(
            counts,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            30,
        );
        assert_eq!(terminal["report_kind"], "scan_status");
        assert_eq!(terminal["last_scan_cap_hit"], true);
        assert_eq!(terminal["last_skipped_file_count_due_to_limit"], 100);
    }

    /// `checkin` + disabled is a backend 400 by contract. It is also
    /// unreachable here: the disabled transition is a durable state report and
    /// only the terminal path can express it.
    #[test]
    #[serial(source_manifests)]
    fn a_disabled_state_report_declares_a_scan_status_and_never_a_checkin() {
        let _source_manifests = SourceManifestTestGuard::new();
        let disabled = captured_terminal_receipt(
            SyncCounts::for_policy(30),
            CollectorState::Disabled(Some("disabled_by_admin".to_string())),
            TerminalManifestSource::Withdraw,
            30,
        );
        assert_eq!(disabled["report_kind"], "scan_status");
        assert_eq!(disabled["enabled"], false);
        assert_eq!(disabled["disabled_reason"], "disabled_by_admin");

        // The server-authoritative zero-width tombstone withdraws the census
        // without claiming a scan; it is still a state report, not liveness.
        let tombstone = captured_terminal_receipt(
            SyncCounts::for_policy(0),
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            0,
        );
        assert_eq!(tombstone["report_kind"], "scan_status");
        assert_eq!(tombstone["last_backfill_window_days"], 0);
        assert_eq!(tombstone["last_census_complete"], false);
    }

    /// After a reinstall the scan index is empty, so the first cycle is a full
    /// traversal that re-asserts census completeness and resets every loss
    /// counter to zero. Only a scan status may lower counters or re-assert
    /// completeness, so this receipt must never claim to be a beat.
    #[test]
    #[serial(source_manifests)]
    fn the_first_report_after_a_reinstall_declares_a_scan_status() {
        let _source_manifests = SourceManifestTestGuard::new();
        let index = ScanIndex::default();
        let mut counts = SyncCounts::for_policy(183);
        counts.census_complete = true;
        let first = captured_terminal_receipt(
            counts,
            CollectorState::Success,
            TerminalManifestSource::CompleteCensus(&index),
            183,
        );
        assert_eq!(first["report_kind"], "scan_status");
        assert_eq!(first["last_census_complete"], true);
        assert_eq!(first["last_recognized_usage_drop_count"], 0);
        assert_eq!(first["last_dropped_usage_record_count"], 0);
        assert_eq!(first["consecutive_failures"], 0);
    }

    /// Mutation proof for Attack 2: take the REAL receipt the collector builds
    /// for a fresh error and force its declared kind to `checkin`. The egress
    /// guard refuses it, so no code path — present or future — can beat while
    /// disclosing scan evidence the backend has not accepted.
    #[test]
    #[serial(source_manifests)]
    fn forcing_a_checkin_onto_a_receipt_carrying_a_new_error_never_reaches_the_wire() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));

        let mut request = collector_status_request(
            "destination",
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts: SyncCounts::for_policy(30),
                state: CollectorState::Error {
                    code: "scan_error",
                    message: "local snapshot scan failed",
                },
            },
            false,
        )
        .expect("terminal error receipt");
        assert_eq!(request.report_kind, SnapshotStatusReportKind::ScanStatus);
        assert_eq!(request.last_error_code.as_deref(), Some("scan_error"));
        // Truthfully declared, it travels.
        client
            .report_status("relay-token-codex", &request)
            .expect("a scan status carrying an error is accepted");

        // The mutation: only the declaration changes.
        request.report_kind = SnapshotStatusReportKind::Checkin;
        let refused = client
            .report_status("relay-token-codex", &request)
            .expect_err("a beat may not disclose a new error");
        assert!(
            refused.to_string().contains("report_kind=checkin"),
            "unexpected refusal: {refused}"
        );

        // Exactly one receipt reached the server: the truthful one.
        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            http_request_json(&requests[0])["report_kind"],
            "scan_status"
        );
    }

    #[test]
    #[serial(source_manifests)]
    fn settled_zero_snapshot_usage_evidence_reports_persistent_parse_error() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["pi".to_string()],
        };
        let mut counts = SyncCounts::for_policy(30);
        counts.discovered_file_count = 1;
        counts.zero_snapshot_usage_evidence_count = 1;

        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Pi,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source: SnapshotSource::Pi,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("report parser liveness failure");

        let requests = captured.lock().expect("captured requests").clone();
        assert!(requests[1].contains("\"last_error_code\":\"parse_error\""));
        assert!(requests[1].contains("\"last_zero_snapshot_usage_evidence_count\":1"));
        assert!(requests[1].contains("\"last_success_at\":null"));
        assert!(requests[1].contains("\"consecutive_failures\":1"));
    }

    /// The M1 codex witness once its residue settles (ottto#399): a COMPLETED
    /// census whose every nonzero loss class equals its terminal counterpart,
    /// with the witness reported as counts only.
    fn m1_named_residue_counts() -> SyncCounts {
        let mut counts = SyncCounts::for_policy(183);
        counts.census_complete = true;
        counts.discovered_file_count = 448;
        counts.scanned_file_count = 448;
        counts.scanned_session_count = 442;
        counts.ownership_incomplete_file_count = 1;
        counts.zero_snapshot_usage_evidence_count = 1;
        counts.recognized_usage_drop_count = 1_105;
        counts.dropped_usage_record_count = 1_105;
        counts.terminal_ownership_incomplete_file_count = 1;
        counts.terminal_zero_snapshot_usage_evidence_count = 1;
        counts.terminal_recognized_usage_drop_count = 1_105;
        counts.terminal_dropped_usage_record_count = 1_105;
        counts.census_residue_index_key_count = 1;
        counts.census_residue_archived_rollout_count = 1;
        counts.census_residue_blocked_session_count = 1;
        counts
    }

    /// The activity-hint member a backend that admits the code advertises.
    const RESIDUE_ADMITTING_HINT: &str =
        r#","census_residue_status_contract":"census_residue_status:v1""#;

    /// A named mutation of the receipt counts, for table-driven vetoes.
    type CountsMutation = (&'static str, fn(&mut SyncCounts));

    const RESIDUE_TERMINAL_PAIRS: [(&str, &str); 5] = [
        (
            "last_terminal_ownership_incomplete_file_count",
            "last_ownership_incomplete_file_count",
        ),
        (
            "last_terminal_zero_snapshot_usage_evidence_count",
            "last_zero_snapshot_usage_evidence_count",
        ),
        (
            "last_terminal_recognized_usage_drop_count",
            "last_recognized_usage_drop_count",
        ),
        (
            "last_terminal_dropped_usage_record_count",
            "last_dropped_usage_record_count",
        ),
        (
            "last_terminal_over_line_cap_count",
            "last_over_line_cap_count",
        ),
    ];

    /// A census that completed with only settled, non-progressing residue is
    /// a successful scan. Once the backend admits the code the receipt says
    /// so: `census_residue`, zero failures, and the success clock bound to
    /// the finish clock — with each settled share equal to the public loss it
    /// settles, so a consumer can prove the residue class by class instead of
    /// trusting the code.
    #[test]
    #[serial(source_manifests)]
    fn a_settled_residue_census_reports_census_residue_once_the_backend_admits_it() {
        let _source_manifests = SourceManifestTestGuard::new();
        let receipt = captured_terminal_receipt_under_hint(
            m1_named_residue_counts(),
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            183,
            RESIDUE_ADMITTING_HINT,
        );
        assert_eq!(receipt["report_kind"], "scan_status");
        assert_eq!(receipt["enabled"], true);
        assert_eq!(receipt["last_error_code"], "census_residue");
        assert_eq!(
            receipt["last_error_message"],
            "census completed with settled non-progressing residue: \
             ownership_incomplete_files=1, zero_snapshot_usage_evidence_files=1, \
             recognized_usage_drops=1105, dropped_usage_records=1105, over_line_cap_lines=0"
        );
        assert_eq!(receipt["consecutive_failures"], 0);
        assert!(receipt["next_retry_at"].is_null());
        assert_eq!(receipt["last_census_complete"], true);
        assert_eq!(receipt["last_scan_cap_hit"], false);
        assert_eq!(receipt["last_skipped_file_count_due_to_limit"], 0);
        // The scan succeeded, so the clock binds. This is the identity every
        // backend terminal predicate reads.
        assert!(receipt["last_success_at"].is_string());
        assert_eq!(receipt["last_success_at"], receipt["last_scan_finished_at"]);
        for (terminal, public) in RESIDUE_TERMINAL_PAIRS {
            assert_eq!(receipt[terminal], receipt[public], "{terminal}");
        }
        assert_eq!(receipt["last_terminal_ownership_incomplete_file_count"], 1);
        assert_eq!(
            receipt["last_terminal_zero_snapshot_usage_evidence_count"],
            1
        );
        assert_eq!(receipt["last_terminal_recognized_usage_drop_count"], 1_105);
        assert_eq!(receipt["last_terminal_dropped_usage_record_count"], 1_105);
        assert_eq!(receipt["last_terminal_over_line_cap_count"], 0);
        assert_eq!(receipt["last_census_residue_settled"], true);
        assert_eq!(receipt["last_census_residue_index_key_count"], 1);
        assert_eq!(receipt["last_census_residue_archived_rollout_count"], 1);
        assert_eq!(receipt["last_census_residue_blocked_session_count"], 1);
        // Counts only. The backend refuses a path-shaped message outright,
        // and the witness's index keys and session ids never leave the index.
        let message = receipt["last_error_message"].as_str().expect("message");
        for fragment in [
            "/",
            "\\",
            ".jsonl",
            ".codex",
            ".claude",
            "transcript_path",
            "workspace_path",
        ] {
            assert!(!message.contains(fragment), "{fragment:?} in {message:?}");
        }
    }

    /// The backend's error-code set is closed and its forward tolerance covers
    /// unknown fields, never unknown values: `census_residue` against a backend
    /// that does not admit it would reject the ENTIRE receipt. So until the
    /// exact contract is advertised the receipt keeps today's shape —
    /// `parse_error`, one failure, no success clock — while the additive
    /// counters still travel for a backend that declares them.
    #[test]
    #[serial(source_manifests)]
    fn a_settled_residue_census_keeps_the_legacy_shape_until_the_backend_admits_the_code() {
        let _source_manifests = SourceManifestTestGuard::new();
        for hint_extra in [
            "",
            r#","census_residue_status_contract":null"#,
            r#","census_residue_status_contract":"census_residue_status:v2""#,
            r#","census_residue_status_contract":"census_residue""#,
        ] {
            let receipt = captured_terminal_receipt_under_hint(
                m1_named_residue_counts(),
                CollectorState::Success,
                TerminalManifestSource::Withdraw,
                183,
                hint_extra,
            );
            assert_eq!(receipt["report_kind"], "scan_status", "{hint_extra:?}");
            assert_eq!(receipt["last_error_code"], "parse_error", "{hint_extra:?}");
            assert_eq!(
                receipt["last_error_message"], "local usage evidence produced no session snapshot",
                "{hint_extra:?}"
            );
            assert_eq!(receipt["consecutive_failures"], 1, "{hint_extra:?}");
            assert!(receipt["last_success_at"].is_null(), "{hint_extra:?}");
            assert_eq!(receipt["last_census_complete"], true, "{hint_extra:?}");
            // The disclosure is the same either way; only the code differs.
            assert_eq!(
                receipt["last_census_residue_settled"], true,
                "{hint_extra:?}"
            );
            for (terminal, public) in RESIDUE_TERMINAL_PAIRS {
                assert_eq!(receipt[terminal], receipt[public], "{terminal}");
            }
            assert_eq!(receipt["last_terminal_dropped_usage_record_count"], 1_105);
            assert_eq!(receipt["last_census_residue_index_key_count"], 1);
            assert_eq!(receipt["last_census_residue_archived_rollout_count"], 1);
            assert_eq!(receipt["last_census_residue_blocked_session_count"], 1);
        }
    }

    /// A retryable problem beside the residue vetoes the settled verdict even
    /// when the backend admits the code: a walk that could not enter, open,
    /// read, or parse something has not proved the residue non-progressing.
    /// The receipt keeps the retryable shape.
    #[test]
    #[serial(source_manifests)]
    fn a_retryable_problem_beside_settled_residue_still_reports_parse_error() {
        let _source_manifests = SourceManifestTestGuard::new();
        let vetoes: [CountsMutation; 7] = [
            ("symlink_rejected", |counts| {
                counts.symlink_rejected_count = 1
            }),
            ("unreadable_path", |counts| counts.unreadable_path_count = 1),
            ("oversized_file", |counts| counts.oversized_file_count = 1),
            ("disappeared_file", |counts| {
                counts.disappeared_file_count = 1
            }),
            ("malformed_json_line", |counts| {
                counts.malformed_json_line_count = 1
            }),
            ("invalid_utf8_line", |counts| {
                counts.invalid_utf8_line_count = 1
            }),
            // Over-line-cap loss beyond its terminal share is bounded line
            // loss not yet given its per-file terminal disposition.
            ("unterminal_over_line_cap", |counts| {
                counts.over_line_cap_count = 1
            }),
        ];
        for (veto_name, veto) in vetoes {
            let mut counts = m1_named_residue_counts();
            veto(&mut counts);
            let receipt = captured_terminal_receipt_under_hint(
                counts,
                CollectorState::Success,
                TerminalManifestSource::Withdraw,
                183,
                RESIDUE_ADMITTING_HINT,
            );
            assert_eq!(receipt["last_error_code"], "parse_error", "{veto_name}");
            assert_eq!(receipt["consecutive_failures"], 1, "{veto_name}");
            assert!(receipt["last_success_at"].is_null(), "{veto_name}");
            assert_eq!(receipt["last_census_residue_settled"], false, "{veto_name}");
            // The settled shares are still disclosed as measured.
            assert_eq!(
                receipt["last_terminal_dropped_usage_record_count"], 1_105,
                "{veto_name}"
            );
        }
    }

    /// Residue the generation has not settled — one class above its terminal
    /// counterpart — and residue on a census that did not complete both keep
    /// the retryable shape, admission or not. Only the exact per-class
    /// equality on a completed census earns the settled verdict.
    #[test]
    #[serial(source_manifests)]
    fn unsettled_residue_and_an_incomplete_census_still_report_parse_error() {
        let _source_manifests = SourceManifestTestGuard::new();
        let unsettled: [CountsMutation; 6] = [
            ("ownership_incomplete unsettled", |counts| {
                counts.terminal_ownership_incomplete_file_count = 0
            }),
            ("zero_snapshot_usage_evidence unsettled", |counts| {
                counts.terminal_zero_snapshot_usage_evidence_count = 0
            }),
            ("recognized_usage_drop unsettled", |counts| {
                counts.terminal_recognized_usage_drop_count = 1_104
            }),
            ("dropped_usage_record unsettled", |counts| {
                counts.terminal_dropped_usage_record_count = 1_104
            }),
            // A settled share above its public counter is not a shape the
            // scan can produce; it must never read as settled either.
            ("terminal above public", |counts| {
                counts.terminal_ownership_incomplete_file_count = 2
            }),
            ("census incomplete", |counts| counts.census_complete = false),
        ];
        for (case, mutate) in unsettled {
            let mut counts = m1_named_residue_counts();
            mutate(&mut counts);
            let receipt = captured_terminal_receipt_under_hint(
                counts,
                CollectorState::Success,
                TerminalManifestSource::Withdraw,
                183,
                RESIDUE_ADMITTING_HINT,
            );
            assert_eq!(receipt["last_error_code"], "parse_error", "{case}");
            assert_eq!(receipt["consecutive_failures"], 1, "{case}");
            assert!(receipt["last_success_at"].is_null(), "{case}");
            assert_eq!(receipt["last_census_residue_settled"], false, "{case}");
        }

        // And a clean census is untouched by the admission: no code, no
        // message, no settled verdict.
        let mut clean = SyncCounts::for_policy(183);
        clean.census_complete = true;
        let receipt = captured_terminal_receipt_under_hint(
            clean,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            183,
            RESIDUE_ADMITTING_HINT,
        );
        assert!(receipt["last_error_code"].is_null());
        assert!(receipt["last_error_message"].is_null());
        assert_eq!(receipt["consecutive_failures"], 0);
        assert_eq!(receipt["last_success_at"], receipt["last_scan_finished_at"]);
        assert_eq!(receipt["last_census_residue_settled"], false);
    }

    /// The exact body the backend admits for a named-residue census — its
    /// status model's residue admission — pinned as a fixture. Exact equality
    /// is also the privacy fence: any member added to the wire, an index key
    /// or a session id included, fails here. Only the finish/success clock and
    /// the build identity are live.
    #[test]
    #[serial(source_manifests)]
    fn the_census_residue_receipt_matches_the_backend_admitted_wire_fixture() {
        let _source_manifests = SourceManifestTestGuard::new();
        let index = ScanIndex::default();
        let mut receipt = captured_terminal_receipt_under_hint(
            m1_named_residue_counts(),
            CollectorState::Success,
            TerminalManifestSource::CompleteCensus(&index),
            183,
            RESIDUE_ADMITTING_HINT,
        );
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/collector-status/census-residue-scan-status-v1.json"
        ))
        .expect("census residue wire fixture");

        let finished_at = receipt["last_scan_finished_at"].clone();
        assert!(finished_at.is_string());
        assert_eq!(receipt["last_success_at"], finished_at);
        for clock in ["last_scan_finished_at", "last_success_at"] {
            receipt[clock] = expected[clock].clone();
        }
        assert_eq!(receipt["collector_version"], collector_version());
        receipt["collector_version"] = expected["collector_version"].clone();

        assert_eq!(receipt, expected);
        // The fixture itself carries no identifier-shaped member and no path.
        let serialized = serde_json::to_string(&expected).expect("fixture text");
        for forbidden in ["index_keys", "session_ids", "/Users/", ".codex", ".claude"] {
            assert!(!serialized.contains(forbidden), "{forbidden}");
        }
    }

    /// The journal commits the exact receipt about to go on the wire, residue
    /// fields included, and reloads it byte-for-byte.
    #[test]
    #[serial(source_manifests)]
    fn the_journaled_census_residue_receipt_reloads_byte_for_byte() {
        let _source_manifests = SourceManifestTestGuard::new();
        let request = collector_status_request(
            "destination",
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-09-03T04:00:00Z",
                counts: m1_named_residue_counts(),
                state: CollectorState::Success,
            },
            true,
        )
        .expect("census residue receipt");
        assert_eq!(request.last_error_code.as_deref(), Some("census_residue"));
        assert!(request.last_census_residue_settled);

        let path = terminal_status_journal_path(
            test_terminal_status_support_dir(),
            "destination",
            SnapshotSource::Codex,
        );
        save_terminal_status_journal(&path, &request).expect("journal the receipt");
        let reloaded = load_terminal_status_journal(&path)
            .expect("read journal")
            .expect("journal exists");
        assert_eq!(
            serde_json::to_value(&reloaded).expect("reloaded JSON"),
            serde_json::to_value(&request).expect("committed JSON")
        );
        assert_eq!(reloaded.last_terminal_dropped_usage_record_count, 1_105);
        assert_eq!(reloaded.last_census_residue_blocked_session_count, 1);
    }

    #[test]
    #[serial(source_manifests)]
    fn healthy_sibling_upload_does_not_hide_dropped_usage_record() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["pi".to_string()],
        };
        let mut counts = SyncCounts::for_policy(30);
        counts.discovered_file_count = 1;
        counts.scanned_session_count = 1;
        counts.uploaded_count = 1;
        counts.dropped_usage_record_count = 1;

        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Pi,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source: SnapshotSource::Pi,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("report partial parser liveness failure");

        let requests = captured.lock().expect("captured requests").clone();
        assert!(requests[1].contains("\"last_error_code\":\"parse_error\""));
        assert!(requests[1].contains("\"last_dropped_usage_record_count\":1"));
        assert!(requests[1].contains("\"last_uploaded_count\":1"));
    }

    #[test]
    #[serial(source_manifests)]
    fn terminal_receipt_is_journaled_before_post_and_liveness_stays_liveness() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
            captured.clone(),
            vec![30, 30],
        ));
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let mut counts = SyncCounts::for_policy(30);
        counts.scan_cap_hit = false;
        counts.census_complete = true;
        counts.recognized_usage_drop_count = 1_105;
        counts.dropped_usage_record_count = 1_105;
        counts.ownership_incomplete_file_count = 1;

        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-09-01T07:44:00Z",
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("persist and emit terminal loss receipt");
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            Some("2026-09-01T08:12:28Z"),
        )
        .expect("post a liveness receipt");

        let requests = captured.lock().expect("captured requests").clone();
        let terminal = http_request_json(&requests[1]);
        assert_eq!(terminal["last_recognized_usage_drop_count"], 1_105);
        assert_eq!(terminal["last_dropped_usage_record_count"], 1_105);
        assert_eq!(terminal["last_ownership_incomplete_file_count"], 1);
        assert_eq!(terminal["last_error_code"], "parse_error");
        assert_eq!(terminal["last_scan_started_at"], "2026-09-01T07:44:00Z");
        assert!(terminal["last_scan_finished_at"].is_string());

        // The durable journal holds exactly the body that was committed before
        // the POST: one coherent scan result - timestamps, counters, cap state
        // and error all from the same `SourceScanResult`.
        let destination = snapshot_upload_destination_namespace(&device, "device-secret");
        let journal = load_terminal_status_journal(&terminal_status_journal_path(
            test_terminal_status_support_dir(),
            &destination,
            SnapshotSource::Codex,
        ))
        .expect("read journal")
        .expect("journal exists");
        assert_eq!(
            serde_json::to_value(journal).expect("journal JSON"),
            terminal
        );

        // The liveness beat that follows it is NOT the terminal body. Its wire
        // shape is exactly what the backend classifies as a check-in receipt,
        // so the terminal report stays the single source of scan truth.
        let checkin = http_request_json(&requests[3]);
        assert_ne!(checkin, terminal);
        assert!(checkin["last_scan_finished_at"].is_null());
        assert!(checkin["last_error_code"].is_null());
        assert!(checkin["last_error_message"].is_null());
        assert!(checkin["next_retry_at"].is_null());
        assert_eq!(checkin["enabled"], true);
        assert_eq!(checkin["consecutive_failures"], 0);
        assert_eq!(checkin["last_scan_cap_hit"], false);
        assert_eq!(checkin["last_scan_started_at"], "2026-09-01T08:12:28Z");
        assert_eq!(checkin["last_recognized_usage_drop_count"], 0);
        assert_eq!(checkin["last_dropped_usage_record_count"], 0);
    }

    /// The journal is a local diagnostic artifact with no production reader, so
    /// it must never gate remote truth. An unwritable support dir - a full or
    /// read-only disk in the field - has to log and continue, with the terminal
    /// receipt reaching the backend carrying exactly the same counters.
    #[test]
    #[serial(source_manifests)]
    fn terminal_receipt_is_posted_when_the_journal_write_fails() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
            captured.clone(),
            vec![30],
        ));
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };

        // Inject the write failure without a test-only seam: the journal's
        // parent chain runs through a regular file, so `create_dir_all` fails
        // exactly as it would on an unwritable support directory.
        let support_dir = test_terminal_status_support_dir().join("blocked-support-dir");
        std::fs::create_dir_all(test_terminal_status_support_dir())
            .expect("create terminal status test root");
        std::fs::write(&support_dir, b"not a directory").expect("block the support dir");

        let mut counts = SyncCounts::for_policy(30);
        counts.scan_cap_hit = false;
        counts.census_complete = true;
        counts.recognized_usage_drop_count = 1_105;
        counts.dropped_usage_record_count = 1_105;
        counts.ownership_incomplete_file_count = 1;

        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            &support_dir,
            SnapshotSource::Codex,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-09-01T07:44:00Z",
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("a failed local journal write must not suppress the terminal report");

        let requests = captured.lock().expect("captured requests").clone();
        let terminal = http_request_json(&requests[1]);
        assert_eq!(terminal["last_recognized_usage_drop_count"], 1_105);
        assert_eq!(terminal["last_dropped_usage_record_count"], 1_105);
        assert_eq!(terminal["last_ownership_incomplete_file_count"], 1);
        assert_eq!(terminal["last_error_code"], "parse_error");
        assert_eq!(terminal["last_scan_started_at"], "2026-09-01T07:44:00Z");
        assert!(terminal["last_scan_finished_at"].is_string());
        assert_eq!(terminal["last_scan_cap_hit"], false);

        let destination = snapshot_upload_destination_namespace(&device, "device-secret");
        assert!(
            !terminal_status_journal_path(&support_dir, &destination, SnapshotSource::Codex)
                .exists(),
            "the journal genuinely failed to write; the POST proceeded anyway"
        );
    }

    /// The journal persists the exact typed `SnapshotStatusRequest` that is
    /// about to go on the wire, so the declared `report_kind` has to survive
    /// the disk round trip like every other field. Without `Deserialize` on
    /// `SnapshotStatusReportKind` the journal would not compile at all; with a
    /// `skip`/`default` escape hatch it would silently reload as some other
    /// kind and a replayed receipt would lie about what it is. This asserts the
    /// reloaded receipt is byte-for-byte the one that was committed.
    #[test]
    #[serial(source_manifests)]
    fn the_journaled_receipt_reloads_with_its_declared_report_kind() {
        let _source_manifests = SourceManifestTestGuard::new();
        let mut counts = SyncCounts::for_policy(30);
        counts.census_complete = true;
        counts.recognized_usage_drop_count = 7;
        counts.dropped_usage_record_count = 7;
        let request = collector_status_request(
            "destination",
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-09-01T07:44:00Z",
                counts,
                state: CollectorState::Error {
                    code: "scan_error",
                    message: "local snapshot scan failed",
                },
            },
            false,
        )
        .expect("terminal receipt");
        assert_eq!(request.report_kind, SnapshotStatusReportKind::ScanStatus);

        let path = terminal_status_journal_path(
            test_terminal_status_support_dir(),
            "destination",
            SnapshotSource::Codex,
        );
        save_terminal_status_journal(&path, &request).expect("journal the terminal receipt");
        let reloaded = load_terminal_status_journal(&path)
            .expect("read journal")
            .expect("journal exists");

        // The declaration itself survives...
        assert_eq!(reloaded.report_kind, SnapshotStatusReportKind::ScanStatus);
        // ...as the snake_case wire token, not a re-derived guess...
        let reloaded_json = serde_json::to_value(&reloaded).expect("reloaded JSON");
        assert_eq!(reloaded_json["report_kind"], "scan_status");
        // ...and the whole receipt is unchanged by the round trip, so a replay
        // could never post a body that differs from the one committed.
        assert_eq!(
            reloaded_json,
            serde_json::to_value(&request).expect("committed JSON")
        );
        // A journaled scan result stays a scan result on the egress guard: it
        // can never re-enter the wire wearing a check-in declaration.
        reloaded
            .validate_declared_report_kind()
            .expect("a journaled scan status is truthfully declared");
    }

    #[test]
    #[serial(source_manifests)]
    fn cycle_start_checkin_posts_in_progress_receipt() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = snapshot_status_server(captured.clone());
        let client = SnapshotApiClient::new(api_base_url);
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };

        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            Some("2026-06-01T10:00:00Z"),
        )
        .expect("report cycle-start check-in with fresh relay token");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[1].contains("POST /api/v1/agent-session-snapshots/status"));
        assert!(requests[1].contains("relay-token-codex"));
        assert!(requests[1].contains("\"schema_version\":5"));
        assert!(requests[1].contains("\"enabled\":true"));
        // The in-progress shape: a scan-start marker with NO terminal fields, so
        // the backend bumps freshness without clobbering the last terminal report.
        assert!(requests[1].contains("\"last_scan_started_at\":\"2026-06-01T10:00:00Z\""));
        assert!(requests[1].contains("\"last_scan_finished_at\":null"));
        assert!(requests[1].contains("\"last_success_at\":null"));
        assert!(requests[1].contains("\"last_error_code\":null"));
        assert!(!requests[1].contains("\"manifest\""));
    }

    #[test]
    #[serial(source_manifests)]
    fn heartbeat_checkin_posts_liveness_only_receipt() {
        let _source_manifests = SourceManifestTestGuard::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = snapshot_status_server(captured.clone());
        let client = SnapshotApiClient::new(api_base_url);
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };

        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("report heartbeat check-in with fresh relay token");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("POST /api/v1/agent-session-snapshots/status"));
        // A pure liveness beat carries neither scan markers nor terminal fields:
        // the backend bumps reported_at and leaves the whole scan lifecycle alone.
        assert!(requests[1].contains("\"last_scan_started_at\":null"));
        assert!(requests[1].contains("\"last_scan_finished_at\":null"));
        assert!(requests[1].contains("\"last_success_at\":null"));
        assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
        assert!(!requests[1].contains("\"manifest\""));
    }

    #[test]
    #[serial(source_manifests)]
    fn receipts_carry_the_scan_index_manifest_once_a_scan_has_published_one() {
        let _source_manifests = SourceManifestTestGuard::new();
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let destination_namespace =
            &snapshot_upload_destination_namespace(&device, "device-secret");

        // Before any scan completes the manifest is absent, not zeroed: a
        // fabricated `entity_count: 0` would read as "this machine has nothing",
        // which is a different and wrong statement.
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("report check-in before any scan");
        let requests = captured.lock().expect("captured requests").clone();
        assert!(!requests[1].contains("\"manifest\""));

        let mut index =
            ScanIndex::load(Path::new("/nonexistent/scan-index.json")).expect("empty scan index");
        index
            .codex_state_only_snapshot_fingerprints
            .insert("session-1".to_string(), "a".repeat(64));
        index
            .snapshot_activity_at
            .insert("a".repeat(64), Some("2099-12-31T12:00:00Z".to_string()));
        let mut manifest = index.manifest(SnapshotSource::Codex, 30);
        manifest.window_start = "2099-12-02T00:00:00Z".to_string();
        manifest.window_end = "2100-01-01T00:00:00Z".to_string();
        publish_source_manifest(
            destination_namespace,
            SnapshotSource::Codex,
            manifest.clone(),
        );

        for scan_started_at in [None, Some("2026-06-01T10:00:00Z")] {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
            report_checkin_status_with_fresh_relay_token(
                &client,
                &device,
                "device-secret",
                SnapshotSource::Codex,
                "otm_test",
                scan_started_at,
            )
            .expect("report check-in after a scan");
            let requests = captured.lock().expect("captured requests").clone();
            assert!(requests[1].contains("\"entity_count\":1"));
            assert!(
                requests[1].contains(&format!("\"rolling_hash\":\"{}\"", manifest.rolling_hash))
            );
            // The scope and window travel with the count. Without them a
            // consumer would compare this against its whole stored set and
            // report a mismatch for every session the historical bootstrap
            // uploaded from outside the scan window.
            assert!(requests[1].contains("\"contract_version\":\"snapshot_manifest:v2\""));
            assert!(requests[1].contains("\"scope\":\"semantic_activity_window\""));
            assert!(requests[1].contains("\"window_start\":\"2099-12-02T00:00:00Z\""));
            assert!(requests[1].contains("\"window_end\":\"2100-01-01T00:00:00Z\""));
            assert!(requests[1].contains("\"last_backfill_window_days\":30"));
            assert!(!requests[1].contains("\"window_days\""));
            assert!(!requests[1].contains("\"server_accepted_entity_count\""));
        }

        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        let mut counts = SyncCounts::for_policy(30);
        counts.semantic_noop_count = 718;
        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            TerminalManifestSource::CompleteCensus(&index),
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2100-01-01T00:00:00Z",
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("report terminal status");
        let requests = captured.lock().expect("captured requests").clone();
        // The suppression count is the difference between "nothing changed" and
        // "the collector dropped what changed".
        assert!(requests[1].contains("\"last_semantic_noop_count\":718"));
        assert!(requests[1].contains("\"entity_count\":1"));
        assert!(requests[1].contains("\"last_scan_started_at\":\"2100-01-01T00:00:00Z\""));

        let mismatch = report_status(
            &client,
            "relay-token-codex",
            destination_namespace,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts: SyncCounts::for_policy(30),
                state: CollectorState::Success,
            },
        )
        .expect_err("terminal receipt cannot detach a manifest from its census boundary");
        assert!(mismatch
            .to_string()
            .contains("manifest window end does not match terminal scan start"));

        // An account switch replaces the relay binding without restarting the
        // daemon. The new destination must not receive the previous account's
        // entity count and rolling hash — that is both a false witness and a
        // disclosure of the previous account's local session set.
        let switched = LocalDeviceBinding {
            device_id: "device_switched".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        report_checkin_status_with_fresh_relay_token(
            &client,
            &switched,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("report check-in after an account switch");
        let requests = captured.lock().expect("captured requests").clone();
        assert!(!requests[1].contains("\"manifest\""));
        assert!(!requests[1].contains(&manifest.rolling_hash));

        // Publishing for the new destination retires the old one outright.
        let new_namespace = snapshot_upload_destination_namespace(&switched, "device-secret");
        publish_source_manifest(&new_namespace, SnapshotSource::Codex, manifest.clone());
        assert!(cached_source_manifest(destination_namespace, SnapshotSource::Codex).is_none());
    }

    #[test]
    #[serial(source_manifests)]
    fn incomplete_census_withdraws_only_its_stale_source_manifest() {
        let _source_manifests = SourceManifestTestGuard::new();
        let destination = "destination";
        let codex = ScanIndex::default().manifest(SnapshotSource::Codex, 183);
        let claude = ScanIndex::default().manifest(SnapshotSource::ClaudeCode, 183);
        publish_source_manifest(destination, SnapshotSource::Codex, codex);
        publish_source_manifest(destination, SnapshotSource::ClaudeCode, claude.clone());

        withdraw_source_manifest(destination, SnapshotSource::Codex);

        assert!(cached_source_manifest(destination, SnapshotSource::Codex).is_none());
        assert_eq!(
            cached_source_manifest(destination, SnapshotSource::ClaudeCode),
            Some(claude)
        );
    }

    #[test]
    #[serial(source_manifests)]
    fn poisoned_manifest_cache_recovers_publish_read_and_withdraw() {
        let _source_manifests = SourceManifestTestGuard::new();
        let poisoned = std::thread::spawn(|| {
            let _manifests = source_manifests()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("intentional source-manifest cache poison");
        })
        .join();
        assert!(poisoned.is_err());

        let destination = "destination";
        let manifest = ScanIndex::default().manifest(SnapshotSource::Codex, 183);
        publish_source_manifest(destination, SnapshotSource::Codex, manifest.clone());
        assert_eq!(
            cached_source_manifest(destination, SnapshotSource::Codex),
            Some(manifest)
        );
        withdraw_source_manifest(destination, SnapshotSource::Codex);
        assert!(cached_source_manifest(destination, SnapshotSource::Codex).is_none());
    }

    #[test]
    #[serial(source_manifests)]
    fn terminal_incomplete_error_and_disabled_receipts_carry_explicit_withdrawal_shape() {
        let _source_manifests = SourceManifestTestGuard::new();
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let destination = snapshot_upload_destination_namespace(&device, "device-secret");
        let manifest = ScanIndex::default().manifest(SnapshotSource::Codex, 183);
        let capture_terminal_without_manifest = |state| {
            publish_source_manifest(&destination, SnapshotSource::Codex, manifest.clone());
            withdraw_source_manifest(&destination, SnapshotSource::Codex);
            let captured = Arc::new(Mutex::new(Vec::new()));
            let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
            let mut counts = SyncCounts::for_policy(183);
            counts.census_complete = false;
            report_status_with_fresh_relay_token(
                &client,
                &device,
                "device-secret",
                test_terminal_status_support_dir(),
                SnapshotSource::Codex,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source: SnapshotSource::Codex,
                    machine_id: "otm_test",
                    scan_started_at: "2026-06-01T10:00:00Z",
                    counts,
                    state,
                },
            )
            .expect("report terminal manifest withdrawal");
            let request = captured.lock().expect("captured requests")[1].clone();
            request
        };

        for request in [
            capture_terminal_without_manifest(CollectorState::Success),
            capture_terminal_without_manifest(CollectorState::Error {
                code: "scan_error",
                message: "local snapshot scan failed",
            }),
            capture_terminal_without_manifest(CollectorState::Disabled(Some(
                "disabled_by_admin".to_string(),
            ))),
        ] {
            assert!(!request.contains("\"last_scan_finished_at\":null"));
            assert!(request.contains("\"last_census_complete\":false"));
            // Terminal + absent manifest is the explicit withdrawal shape.
            // Nonterminal + absent manifest remains liveness-only/unknown.
            assert!(!request.contains("\"manifest\""));
        }
    }

    #[test]
    #[serial(source_manifests)]
    fn completed_upload_save_failure_cannot_leave_the_stale_manifest_cached() {
        let _source_manifests = SourceManifestTestGuard::new();
        let destination = "destination";
        publish_source_manifest(
            destination,
            SnapshotSource::Codex,
            ScanIndex::default().manifest(SnapshotSource::Codex, 183),
        );
        let root = test_dir("completed-upload-index-save-failure");
        let invalid_index_path = root.join("index-is-a-directory");
        std::fs::create_dir_all(&invalid_index_path).expect("create invalid index target");
        let mut replacement = ScanIndex::default();

        save_index_and_publish_manifest(
            &mut replacement,
            &invalid_index_path,
            destination,
            SnapshotSource::Codex,
            true,
            "2026-01-01T00:00:00Z",
            "2026-07-01T00:00:00Z",
        )
        .expect_err("post-ACK index save must fail at the invalid target");

        assert!(cached_source_manifest(destination, SnapshotSource::Codex).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn collector_checkin_interval_stays_inside_freshness_promise() {
        // The backend's sources.status freshness SLO is five minutes measured
        // from the server-received check-in. The heartbeat must beat with real
        // headroom, and faster than the sync loop's own sleep.
        assert!(COLLECTOR_CHECKIN_INTERVAL <= Duration::from_secs(4 * 60));
        assert!(COLLECTOR_CHECKIN_INTERVAL < SNAPSHOT_SYNC_INTERVAL);
    }

    #[test]
    fn backfill_and_curve_replay_keep_report_width_at_current_hint() {
        let receipt_window_days = validated_receipt_window_days(183).expect("valid hint");
        assert_eq!(
            scan_request_window_days(receipt_window_days, false, false),
            receipt_window_days,
            "after replay the scan returns to the current policy width"
        );

        for (replay_name, backfill_pending, curve_replay_pending) in
            [("backfill", true, false), ("curve", false, true)]
        {
            assert_eq!(
                scan_request_window_days(
                    receipt_window_days,
                    backfill_pending,
                    curve_replay_pending,
                ),
                u64::MAX,
                "{replay_name} replay requests the scanner's broad local range"
            );

            for source in [
                SnapshotSource::Codex,
                SnapshotSource::ClaudeCode,
                SnapshotSource::Pi,
            ] {
                let root = test_dir(&format!(
                    "{replay_name}-replay-window-{}",
                    source.api_slug()
                ));
                std::fs::create_dir_all(&root).expect("create empty source root");
                let mut index = ScanIndex::default();
                let result = crate::snapshots::scan_source_roots(
                    source,
                    std::slice::from_ref(&root),
                    &mut index,
                    "2026-08-30T12:00:00Z",
                    scan_request_window_days(
                        receipt_window_days,
                        backfill_pending,
                        curve_replay_pending,
                    ),
                )
                .expect("broad replay scan");
                assert_eq!(
                    result.backfill_window_days,
                    crate::snapshots::BACKFILL_WINDOW_DAYS,
                    "the local scanner keeps its 730-day replay ceiling"
                );
                let counts = SyncCounts::from_scan_result(&result, 0, receipt_window_days);
                assert_eq!(
                    counts.backfill_window_days, receipt_window_days,
                    "{replay_name} terminal status reports the exact hint"
                );
                let (window_start, window_end) =
                    snapshot_manifest_window(&result.census_window_end, receipt_window_days)
                        .expect("policy-width replay manifest");
                let manifest = index
                    .manifest_for_window(source, &window_start, &window_end)
                    .expect("replay manifest");
                assert_eq!(
                    snapshot_manifest_window_days(&manifest).unwrap(),
                    receipt_window_days,
                    "{replay_name} terminal manifest reports the exact hint"
                );
                assert!(counts.census_complete);
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }

    #[test]
    fn replay_scan_discovers_session_older_than_policy_window() {
        let root = test_dir("replay-discovers-beyond-policy-window");
        std::fs::create_dir_all(&root).expect("create replay root");
        let path = root.join("session.jsonl");
        std::fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"id\":\"replay-session\",\"timestamp\":\"2026-01-01T00:00:00Z\"}\n",
                "{\"type\":\"message\",\"timestamp\":\"2026-01-01T00:01:00Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"usage\":{\"input\":12,\"output\":4}}}\n"
            ),
        )
        .expect("write old replay fixture");
        let old_mtime = OffsetDateTime::parse("2026-01-01T00:02:00Z", &Rfc3339)
            .expect("old fixture mtime")
            .unix_timestamp() as u64;
        std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("open old replay fixture")
            .set_times(
                std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(old_mtime),
                ),
            )
            .expect("set old replay fixture mtime");

        let mut policy_index = ScanIndex::default();
        let policy_scan = crate::snapshots::scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut policy_index,
            "2026-08-30T12:00:00Z",
            scan_request_window_days(183, false, false),
        )
        .expect("policy-width scan");
        assert_eq!(policy_scan.discovered_file_count, 0);
        assert!(policy_scan.snapshots.is_empty());

        let mut replay_index = ScanIndex::default();
        let replay_scan = crate::snapshots::scan_source_roots(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut replay_index,
            "2026-08-30T12:00:00Z",
            scan_request_window_days(183, true, false),
        )
        .expect("wide replay scan");
        assert_eq!(replay_scan.backfill_window_days, 730);
        assert_eq!(replay_scan.discovered_file_count, 1);
        assert_eq!(replay_scan.scanned_file_count, 1);
        assert_eq!(replay_scan.snapshots.len(), 1);
        assert_eq!(replay_scan.snapshots[0].source_session_id, "replay-session");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial(source_manifests)]
    fn mid_replay_policy_change_rebuilds_terminal_manifest_from_report_time_hint() {
        let _source_manifests = SourceManifestTestGuard::new();
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let destination = snapshot_upload_destination_namespace(&device, "device-secret");
        let inside = "a".repeat(64);
        let replay_only = "b".repeat(64);
        let mut index = ScanIndex::default();
        index
            .file_snapshot_fingerprints
            .insert("inside.jsonl".to_string(), BTreeSet::from([inside.clone()]));
        index.file_snapshot_fingerprints.insert(
            "replay-only.jsonl".to_string(),
            BTreeSet::from([replay_only.clone()]),
        );
        index.snapshot_activity_at = BTreeMap::from([
            (inside, Some("2026-08-29T00:00:00Z".to_string())),
            (replay_only, Some("2026-04-01T00:00:00Z".to_string())),
        ]);
        let scan_started_at = "2026-08-30T12:00:00Z";
        let (old_start, old_end) = snapshot_manifest_window(scan_started_at, 183).unwrap();
        publish_source_manifest(
            &destination,
            SnapshotSource::Codex,
            index
                .manifest_for_window(SnapshotSource::Codex, &old_start, &old_end)
                .unwrap(),
        );

        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
            captured.clone(),
            vec![30],
        ));
        let mut counts = SyncCounts::for_policy(183);
        counts.census_complete = true;
        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            TerminalManifestSource::CompleteCensus(&index),
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at,
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("report terminal with refreshed policy");

        let requests = captured.lock().expect("captured requests").clone();
        let status = http_request_json(&requests[1]);
        assert_eq!(status["last_backfill_window_days"], 30);
        assert_eq!(status["manifest"]["entity_count"], 1);
        let manifest = cached_source_manifest(&destination, SnapshotSource::Codex)
            .expect("report-time manifest cached");
        assert_eq!(snapshot_manifest_window_days(&manifest).unwrap(), 30);
        assert_eq!(status["manifest"]["window_start"], manifest.window_start);
        assert_eq!(status["manifest"]["window_end"], manifest.window_end);
        assert_eq!(status["manifest"]["rolling_hash"], manifest.rolling_hash);
        assert_eq!(scan_request_window_days(183, false, true), u64::MAX);
    }

    #[test]
    #[serial(source_manifests)]
    fn first_contact_under_30_days_reports_30_on_every_receipt_shape() {
        let _source_manifests = SourceManifestTestGuard::new();
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
            captured.clone(),
            vec![30, 30, 30],
        ));
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            Some("2026-08-30T12:00:00Z"),
        )
        .expect("cycle-start receipt");
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("heartbeat receipt");
        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-08-30T12:00:00Z",
                counts: SyncCounts::for_policy(183),
                state: CollectorState::Success,
            },
        )
        .expect("terminal receipt");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 6);
        for (shape, request_index) in [("cycle-start", 1), ("heartbeat", 3), ("terminal", 5)] {
            let status = http_request_json(&requests[request_index]);
            assert_eq!(
                status["last_backfill_window_days"], 30,
                "{shape} must carry the first server hint"
            );
            assert!(status.get("manifest").is_none());
        }
    }

    #[test]
    #[serial(source_manifests)]
    fn zero_hint_emits_manifest_free_terminal_tombstone_and_manifest_free_heartbeats() {
        let _source_manifests = SourceManifestTestGuard::new();
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let destination = snapshot_upload_destination_namespace(&device, "device-secret");
        let index = ScanIndex::default();
        publish_source_manifest(
            &destination,
            SnapshotSource::Codex,
            index.manifest(SnapshotSource::Codex, 183),
        );
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
            captured.clone(),
            vec![0, 0],
        ));

        let mut counts = SyncCounts::for_policy(183);
        counts.census_complete = true;
        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            TerminalManifestSource::CompleteCensus(&index),
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-08-30T12:00:00Z",
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("zero-width terminal tombstone");
        assert!(cached_source_manifest(&destination, SnapshotSource::Codex).is_none());
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("zero-width heartbeat");

        let requests = captured.lock().expect("captured requests").clone();
        let terminal = http_request_json(&requests[1]);
        assert_eq!(terminal["last_backfill_window_days"], 0);
        assert_eq!(terminal["last_census_complete"], false);
        assert_eq!(terminal["enabled"], true);
        assert!(terminal["last_scan_finished_at"].is_string());
        assert!(terminal["last_success_at"].is_null());
        assert!(terminal["last_error_code"].is_null());
        assert!(terminal["last_error_message"].is_null());
        assert!(terminal.get("manifest").is_none());

        let heartbeat = http_request_json(&requests[3]);
        assert_eq!(heartbeat["last_backfill_window_days"], 0);
        assert!(heartbeat["last_scan_finished_at"].is_null());
        assert!(heartbeat.get("manifest").is_none());
    }

    #[test]
    #[serial(source_manifests)]
    fn every_terminal_path_reports_exactly_the_report_time_hint() {
        let _source_manifests = SourceManifestTestGuard::new();
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let fingerprint = "a".repeat(64);
        let mut index = ScanIndex::default();
        index.file_snapshot_fingerprints.insert(
            "inside.jsonl".to_string(),
            BTreeSet::from([fingerprint.clone()]),
        );
        index
            .snapshot_activity_at
            .insert(fingerprint, Some("2026-08-30T11:59:00Z".to_string()));
        let paths = [
            ("early-disabled", 0_u8, false),
            ("scan-error", 1, false),
            ("shed", 2, true),
            ("backend-disabled", 3, false),
            ("upload-error", 4, false),
            ("preflight-error", 5, false),
            ("auth-error", 6, false),
            ("network-error", 7, false),
            ("deferred-conflict", 8, true),
            ("success", 9, true),
        ];
        let widths = [1_u64, 30, 90, 183];
        let hints = paths.iter().flat_map(|_| widths).collect::<Vec<_>>();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client =
            SnapshotApiClient::new(snapshot_status_server_with_hints(captured.clone(), hints));

        let mut receipt_index = 0;
        for (path, state_kind, publishes_manifest) in paths {
            for expected_width in widths {
                let state = match state_kind {
                    0 | 3 => CollectorState::Disabled(Some("disabled_by_admin".to_string())),
                    1 => CollectorState::Error {
                        code: "scan_error",
                        message: "local snapshot scan failed",
                    },
                    2 | 8 => CollectorState::Error {
                        code: "server_error",
                        message: "backend deferred snapshot work",
                    },
                    5 => CollectorState::Error {
                        code: "backend_validation_error",
                        message: "snapshot preflight failed",
                    },
                    6 => CollectorState::Error {
                        code: "auth_error",
                        message: "snapshot authorization failed",
                    },
                    _ => CollectorState::Error {
                        code: "network_error",
                        message: "local snapshot upload failed",
                    },
                };
                let mut counts = SyncCounts::for_policy(183);
                counts.census_complete = publishes_manifest;
                report_status_with_fresh_relay_token(
                    &client,
                    &device,
                    "device-secret",
                    test_terminal_status_support_dir(),
                    SnapshotSource::Codex,
                    if publishes_manifest {
                        TerminalManifestSource::CompleteCensus(&index)
                    } else {
                        TerminalManifestSource::Withdraw
                    },
                    CollectorStatus {
                        source: SnapshotSource::Codex,
                        machine_id: "otm_test",
                        scan_started_at: "2026-08-30T12:00:00Z",
                        counts,
                        state: if state_kind == 9 {
                            CollectorState::Success
                        } else {
                            state
                        },
                    },
                )
                .unwrap_or_else(|error| panic!("{path}/{expected_width} report failed: {error}"));

                let requests = captured.lock().expect("captured requests");
                let status = http_request_json(&requests[receipt_index * 2 + 1]);
                assert_eq!(
                    status["last_backfill_window_days"], expected_width,
                    "{path} reported a width other than its report-time hint"
                );
                if publishes_manifest {
                    let start = OffsetDateTime::parse(
                        status["manifest"]["window_start"].as_str().unwrap(),
                        &Rfc3339,
                    )
                    .unwrap();
                    let end = OffsetDateTime::parse(
                        status["manifest"]["window_end"].as_str().unwrap(),
                        &Rfc3339,
                    )
                    .unwrap();
                    assert_eq!((end - start).whole_days(), expected_width as i64, "{path}");
                } else {
                    assert!(status.get("manifest").is_none(), "{path}");
                }
                receipt_index += 1;
            }
        }

        assert_eq!(receipt_index, paths.len() * widths.len());
    }

    #[test]
    fn replay_manifest_folds_only_entities_inside_the_negotiated_semantic_window() {
        let inside = "a".repeat(64);
        let replay_only = "b".repeat(64);
        let mut index = ScanIndex::default();
        index
            .file_snapshot_fingerprints
            .insert("inside.jsonl".to_string(), BTreeSet::from([inside.clone()]));
        index.file_snapshot_fingerprints.insert(
            "replay-only.jsonl".to_string(),
            BTreeSet::from([replay_only.clone()]),
        );
        index.snapshot_activity_at = BTreeMap::from([
            (inside, Some("2026-08-29T00:00:00Z".to_string())),
            (replay_only, Some("2025-08-29T00:00:00Z".to_string())),
        ]);
        let (window_start, window_end) =
            snapshot_manifest_window("2026-08-30T12:00:00Z", 183).expect("manifest window");

        for source in [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ] {
            let manifest = index
                .manifest_for_window(source, &window_start, &window_end)
                .expect("source-generic semantic manifest");
            assert_eq!(manifest.entity_count, 1);
            assert_eq!(snapshot_manifest_window_days(&manifest).unwrap(), 183);
        }
    }

    #[test]
    fn invalid_or_future_receipt_window_hints_fail_closed() {
        assert_eq!(validated_receipt_window_days(0).unwrap(), 0);
        assert!(snapshot_manifest_window("2026-08-30T12:00:00Z", 0).is_err());
        assert_eq!(validated_receipt_window_days(1).unwrap(), 1);
        assert_eq!(validated_receipt_window_days(183).unwrap(), 183);
        assert!(validated_receipt_window_days(184).is_err());
        assert!(validated_receipt_window_days(u64::MAX).is_err());
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &Path) -> Self {
            Self::set_os(key, value.as_os_str().to_os_string())
        }

        fn set_str(key: &'static str, value: &str) -> Self {
            Self::set_os(key, std::ffi::OsString::from(value))
        }

        fn set_os(key: &'static str, value: std::ffi::OsString) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ottto-{name}-{}-{}",
            std::process::id(),
            current_rfc3339().replace([':', '-'], "")
        ))
    }

    fn test_agent_status(source: SourceKind) -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            source,
            status: AgentStatusState::Available,
            collection_method: AgentStatusCollectionMethod::ManualFallback,
            captured_at: "2026-06-01T10:00:00Z".to_string(),
            expires_at: "2026-06-01T10:15:00Z".to_string(),
            account: None,
            model: None,
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
            context: None,
            capabilities: Vec::new(),
            plan_observations: Vec::new(),
            diagnostics: Vec::new(),
            runtime_defaults: None,
        }
    }

    fn test_agent_account(account_hash: &str, organization_hash: &str) -> AgentAccountStatus {
        AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            provider: Some("anthropic".to_string()),
            auth_method: Some("oauth".to_string()),
            email: None,
            account_id: None,
            organization_id: None,
            organization_label: None,
            plan_type: Some("max".to_string()),
            subscription_product: Some("claude_max".to_string()),
            billing_channel: Some("subscription".to_string()),
            subscription_period_start: None,
            subscription_period_end: None,
            subscription_period_last_checked_at: None,
            account_identifier_hash: Some(account_hash.to_string()),
            organization_identifier_hash: Some(organization_hash.to_string()),
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("provider_account_id".to_string()),
            claude_quota_access_state: None,
            claude_anchor_durability: None,
            claude_anchor_health: None,
            billing_identity_confidence: AgentStatusConfidence::High,
            confidence: AgentStatusConfidence::High,
        }
    }

    fn test_daemon(machine_id: &str) -> LocalDaemon {
        LocalDaemon::new(
            MachineIdentity {
                machine_id: machine_id.to_string(),
                installation_id: "install_test".to_string(),
                display_name: "Test Mac".to_string(),
                hostname: "test-mac.local".to_string(),
                os: OperatingSystem::Macos,
                arch: "arm64".to_string(),
                local_platform_version: "0.1.35".to_string(),
                hardware_uuid: None,
                account_scope: None,
            },
            ControlToken::new("token").expect("valid token"),
            "2026-06-16T10:00:00Z",
        )
    }

    fn agent_status_upload_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept agent status request");
                let request = read_complete_http_request(&mut stream);
                captured
                    .lock()
                    .expect("capture agent status request")
                    .push(request);
                let body = if index == 0 {
                    r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#
                } else {
                    r#"{"accepted":1,"machine_id":"otm_test","sources":["codex"]}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write agent status response");
            }
        });
        format!("http://{address}")
    }

    fn agent_status_partial_failure_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            for index in 0..3 {
                let (mut stream, _) = listener.accept().expect("accept agent status request");
                let request = read_complete_http_request(&mut stream);
                captured
                    .lock()
                    .expect("capture agent status request")
                    .push(request);
                let (status, body) = match index {
                    0 => ("500 Internal Server Error", r#"{"error":"temporary"}"#),
                    1 => (
                        "200 OK",
                        r#"{"token":"relay-token-claude","expires_at":"2026-06-01T10:15:00Z"}"#,
                    ),
                    _ => (
                        "200 OK",
                        r#"{"accepted":1,"machine_id":"otm_test","sources":["claude_code"]}"#,
                    ),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write agent status response");
            }
        });
        format!("http://{address}")
    }

    fn local_health_reactivation_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local health backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            for index in 0..5 {
                let (mut stream, _) = listener.accept().expect("accept local health request");
                let request = read_complete_http_request(&mut stream);
                captured
                    .lock()
                    .expect("capture local health request")
                    .push(request);
                let (status, body) = match index {
                    0 => ("403 Forbidden", r#"{"error":"inactive"}"#),
                    1 => (
                        "200 OK",
                        r#"{"setup_run_id":"setup_fresh","setup_run_token":"otsr_fresh","expires_at":"2026-06-11T18:30:00Z"}"#,
                    ),
                    2 => (
                        "200 OK",
                        r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#,
                    ),
                    _ => ("200 OK", r#"{"ok":true}"#),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write local health response");
            }
        });
        format!("http://{address}")
    }

    fn snapshot_status_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        snapshot_status_server_with_hints(captured, vec![30])
    }

    fn snapshot_status_server_with_hints(
        captured: Arc<Mutex<Vec<String>>>,
        hints: Vec<u64>,
    ) -> String {
        snapshot_status_server_with_hint_extras(
            captured,
            hints.into_iter().map(|days| (days, "")).collect(),
        )
    }

    /// One `(backfill_window_days, extra JSON members)` pair per receipt; the
    /// extra members are appended verbatim to the activity hint body.
    fn snapshot_status_server_with_hint_extras(
        captured: Arc<Mutex<Vec<String>>>,
        hints: Vec<(u64, &'static str)>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind snapshot status backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            let receipt_count = hints.len();
            let mut hints = hints.into_iter();
            for _ in 0..receipt_count * 3 {
                let (mut stream, _) = listener.accept().expect("accept snapshot status request");
                let request = read_complete_http_request(&mut stream);
                let body = if request.contains("/telemetry/devices/") {
                    captured
                        .lock()
                        .expect("capture snapshot status request")
                        .push(request);
                    r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#
                        .to_string()
                } else if request.contains("/activity-hints") {
                    let (hint, extra) = hints.next().expect("one hint per receipt");
                    format!(
                        r#"{{"source":"codex","server_time":"2026-06-01T10:00:00Z","last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,"backfill_window_days":{hint}{extra},"recommended_scan_after":"2026-06-01T10:05:00Z"}}"#
                    )
                } else {
                    captured
                        .lock()
                        .expect("capture snapshot status request")
                        .push(request);
                    r#"{"accepted":true,"source":"codex","machine_id":"otm_test","disabled":false}"#
                        .to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write snapshot status response");
            }
        });
        format!("http://{address}")
    }

    fn http_request_json(request: &str) -> serde_json::Value {
        serde_json::from_str(request.split("\r\n\r\n").nth(1).expect("HTTP request body"))
            .expect("JSON request body")
    }

    fn read_complete_http_request(stream: &mut std::net::TcpStream) -> String {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    request.extend_from_slice(&buffer[..bytes_read]);
                    if http_request_complete(&request) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&request).to_string()
    }

    fn http_request_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        });
        content_length
            .map(|length| request.len() >= body_start + length)
            .unwrap_or(true)
    }
}
