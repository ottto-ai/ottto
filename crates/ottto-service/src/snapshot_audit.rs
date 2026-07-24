//! Privacy-safe local snapshot audit support.
//!
//! The audit is a validation surface, not a second collector. It calls the
//! production scanner, applies the normal upload policy, and reports only
//! content-free counters plus HMAC-blinded identifiers/fingerprints. Raw
//! transcript paths, provider session ids, titles, repository labels, and
//! transcript content never enter the report.

use crate::session_attribution::{SessionAttributionContext, SESSION_ATTRIBUTION_HMAC_KEY_VERSION};
use crate::snapshots::{
    apply_upload_policy, collector_version, scan_source_roots_with_attribution,
    snapshot_fingerprint_from_component_hashes, snapshot_semantic_component_hashes,
    snapshot_semantic_envelope, ScanIndex, SnapshotBatchRequest, SnapshotItem, SnapshotSource,
    SnapshotUploadPolicy, BACKFILL_WINDOW_DAYS, SNAPSHOT_REVISION_CONTRACT_VERSION,
    SNAPSHOT_SCHEMA_VERSION, SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
};
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const AUDIT_SCHEMA_VERSION: &str = "local_snapshot_audit:v2";
const AUDIT_STATE_SCHEMA_VERSION: &str = "local_snapshot_audit_state:v3";
const AUDIT_STATE_MARKER_FILE: &str = "audit-state.json";
const AUDIT_SCAN_INDEX_FILE: &str = "scan-index.json";
const MIN_AUDIT_KEY_BYTES: usize = 32;
const MAX_LEGACY_POLICY_CANDIDATES: usize = 24;
const POLICY_NEUTRAL_COMPONENTS: [&str; 4] = [
    "usage_accounting",
    "lifecycle_activity",
    "latency",
    "context_posture",
];
const POLICY_SENSITIVE_COMPONENTS: [&str; 3] = ["display_identity", "attribution", "artifacts"];

#[derive(Debug, Clone)]
pub struct SnapshotAuditOptions {
    pub source: SnapshotSource,
    pub roots: Vec<PathBuf>,
    pub audit_state_dir: PathBuf,
    pub audit_key_path: PathBuf,
    pub session_attribution_hmac_key_path: PathBuf,
    pub attribution_home: Option<PathBuf>,
    pub machine_id: String,
    pub collected_at: String,
    pub backfill_window_days: u64,
    pub private_upload_payload_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotAuditReport {
    pub schema_version: &'static str,
    pub component_contract_version: &'static str,
    pub revision_contract_version: &'static str,
    pub source: String,
    pub machine_key: String,
    pub upload_policy: SnapshotAuditUploadPolicy,
    pub collector_version: String,
    pub parser_version: String,
    pub scan_identity_version: String,
    pub backfill_window_days: u64,
    pub backfill_file_limit: usize,
    pub discovered_file_count: usize,
    pub skipped_file_count_due_to_limit: usize,
    pub scan_cap_hit: bool,
    pub scanned_file_count: usize,
    pub scanned_session_count: usize,
    pub semantic_noop_count: usize,
    pub emitted_session_count: usize,
    pub sessions: Vec<SnapshotAuditSession>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotAuditSession {
    pub session_key: String,
    pub semantic_key: String,
    pub revision_key: String,
    pub legacy_revision_proof_available: bool,
    pub legacy_policy_candidate_semantic_keys: Vec<String>,
    pub policy_neutral_component_keys: BTreeMap<String, String>,
    pub policy_sensitive_component_keys: BTreeMap<String, String>,
    pub status: String,
    pub input_token_scope: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub unattributed_total_tokens: u64,
    pub request_count: u64,
    pub model_usage_row_count: usize,
    pub usage_bucket_count: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct SnapshotAuditUploadPolicy {
    pub session_titles_enabled: bool,
    pub workspace_labels_enabled: bool,
    pub session_artifacts_enabled: bool,
    pub session_attribution_enabled: bool,
    pub session_attribution_labels_enabled: bool,
}

impl Default for SnapshotAuditOptions {
    fn default() -> Self {
        Self {
            source: SnapshotSource::Codex,
            roots: Vec::new(),
            audit_state_dir: PathBuf::new(),
            audit_key_path: PathBuf::new(),
            session_attribution_hmac_key_path: PathBuf::new(),
            attribution_home: None,
            machine_id: String::new(),
            collected_at: String::new(),
            backfill_window_days: BACKFILL_WINDOW_DAYS,
            private_upload_payload_out: None,
        }
    }
}

pub fn snapshot_source_from_slug(value: &str) -> Result<SnapshotSource> {
    match value {
        "codex" => Ok(SnapshotSource::Codex),
        "claude" | "claude_code" | "claude-code" => Ok(SnapshotSource::ClaudeCode),
        "pi" => Ok(SnapshotSource::Pi),
        _ => Err(anyhow!(
            "unsupported snapshot source; expected codex, claude_code, or pi"
        )),
    }
}

pub fn run_snapshot_audit<W: Write>(
    options: SnapshotAuditOptions,
    output: &mut W,
) -> Result<SnapshotAuditReport> {
    if options.roots.is_empty() {
        return Err(anyhow!("at least one snapshot root is required"));
    }
    if options.machine_id.trim().is_empty() {
        return Err(anyhow!("machine id cannot be empty"));
    }
    let audit_key = read_audit_key(&options.audit_key_path)?;
    let attribution_home = match options.attribution_home.as_ref() {
        Some(path) => path.clone(),
        None => crate::snapshot_sync::home_dir()?,
    };
    let encoded_attribution_key = Zeroizing::new(
        fs::read_to_string(&options.session_attribution_hmac_key_path)
            .with_context(|| {
                format!(
                    "read session attribution HMAC key {}",
                    options.session_attribution_hmac_key_path.display()
                )
            })?
            .trim()
            .to_string(),
    );
    let attribution_context = SessionAttributionContext::from_activity_hint(
        options.source,
        &attribution_home,
        true,
        Some(encoded_attribution_key.as_str()),
        Some(SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .ok_or_else(|| {
        anyhow!(
            "session attribution HMAC key must be the exact 32-byte URL-safe no-pad activity-hint key"
        )
    })?;
    let index_path = prepare_audit_state_dir(&options.audit_state_dir)?;
    let mut index = ScanIndex::load(&index_path)?;
    let mut scan = scan_source_roots_with_attribution(
        options.source,
        &options.roots,
        &mut index,
        &options.collected_at,
        options.backfill_window_days,
        true,
        Some(&attribution_context),
    )?;
    let pre_policy_snapshots = scan.snapshots.clone();
    let upload_policy = SnapshotUploadPolicy {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        session_artifacts_enabled: false,
        session_attribution_enabled: false,
        session_attribution_labels_enabled: false,
    };
    apply_upload_policy(options.source, &mut scan.snapshots, upload_policy);
    let audit_upload_policy = SnapshotAuditUploadPolicy {
        session_titles_enabled: upload_policy.session_titles_enabled,
        workspace_labels_enabled: upload_policy.workspace_labels_enabled,
        session_artifacts_enabled: upload_policy.session_artifacts_enabled,
        session_attribution_enabled: upload_policy.session_attribution_enabled,
        session_attribution_labels_enabled: upload_policy.session_attribution_labels_enabled,
    };
    let parser_version = options.source.parser_version();
    let scan_identity_version = options.source.scan_identity_version();

    let mut sessions = scan
        .snapshots
        .iter()
        .zip(pre_policy_snapshots.iter())
        .map(|(snapshot, pre_policy_snapshot)| {
            let envelope = snapshot_semantic_envelope(options.source, snapshot, upload_policy);
            SnapshotAuditSession {
                session_key: keyed_hex(
                    &audit_key,
                    &[
                        AUDIT_SCHEMA_VERSION,
                        options.source.api_slug(),
                        &options.machine_id,
                        &snapshot.source_session_id,
                    ],
                ),
                semantic_key: keyed_hex(
                    &audit_key,
                    &[
                        AUDIT_SCHEMA_VERSION,
                        "semantic",
                        &snapshot.snapshot_fingerprint,
                    ],
                ),
                revision_key: blinded_revision_key(&audit_key, &envelope.revision_hash),
                legacy_revision_proof_available: false,
                legacy_policy_candidate_semantic_keys: legacy_policy_candidate_semantic_keys(
                    &audit_key,
                    options.source,
                    pre_policy_snapshot,
                )
                .expect("valid upload policies stay within the audited candidate cap"),
                policy_neutral_component_keys: blinded_component_keys(
                    &audit_key,
                    &envelope.component_hashes,
                    &POLICY_NEUTRAL_COMPONENTS,
                ),
                policy_sensitive_component_keys: blinded_component_keys(
                    &audit_key,
                    &envelope.component_hashes,
                    &POLICY_SENSITIVE_COMPONENTS,
                ),
                status: snapshot.status.clone(),
                input_token_scope: snapshot
                    .provenance
                    .input_token_scope
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_string()),
                input_tokens: snapshot.input_tokens,
                output_tokens: snapshot.output_tokens,
                cache_read_tokens: snapshot.cache_read_tokens,
                cache_creation_5m_tokens: snapshot.cache_creation_5m_tokens,
                cache_creation_1h_tokens: snapshot.cache_creation_1h_tokens,
                reasoning_output_tokens: snapshot.reasoning_output_tokens,
                unattributed_total_tokens: snapshot.unattributed_total_tokens,
                request_count: snapshot.request_count,
                model_usage_row_count: snapshot.model_usage.len(),
                usage_bucket_count: snapshot.usage_buckets.len(),
            }
        })
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| left.session_key.cmp(&right.session_key));

    if let Some(path) = options.private_upload_payload_out.as_deref() {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: options.source.api_slug().to_string(),
            machine_id: options.machine_id.clone(),
            collector_version: Some(collector_version()),
            snapshots: scan.snapshots.clone(),
            upload_policy,
        };
        write_private_json(path, &request)?;
    }

    let report = SnapshotAuditReport {
        schema_version: AUDIT_SCHEMA_VERSION,
        component_contract_version: SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
        revision_contract_version: SNAPSHOT_REVISION_CONTRACT_VERSION,
        source: options.source.api_slug().to_string(),
        machine_key: keyed_hex(
            &audit_key,
            &[AUDIT_SCHEMA_VERSION, "machine", &options.machine_id],
        ),
        upload_policy: audit_upload_policy,
        collector_version: collector_version(),
        parser_version: parser_version.to_string(),
        scan_identity_version: scan_identity_version.to_string(),
        backfill_window_days: scan.backfill_window_days,
        backfill_file_limit: scan.backfill_file_limit,
        discovered_file_count: scan.discovered_file_count,
        skipped_file_count_due_to_limit: scan.skipped_file_count_due_to_limit,
        scan_cap_hit: scan.scan_cap_hit,
        scanned_file_count: scan.scanned_file_count,
        scanned_session_count: scan.scanned_session_count,
        semantic_noop_count: scan.semantic_noop_count,
        emitted_session_count: sessions.len(),
        sessions,
    };

    // The report is the acknowledgement for an audit scan. Commit its private
    // state only after both optional payload output and stdout are durable from
    // this process's point of view; a closed pipe must remain retryable.
    serde_json::to_writer_pretty(&mut *output, &report).context("write snapshot audit report")?;
    output
        .write_all(b"\n")
        .context("finish snapshot audit report")?;
    output.flush().context("flush snapshot audit report")?;
    write_private_json(&index_path, &index)?;

    Ok(report)
}

fn blinded_component_keys(
    audit_key: &[u8],
    component_hashes: &BTreeMap<&'static str, String>,
    component_names: &[&str],
) -> BTreeMap<String, String> {
    component_names
        .iter()
        .filter_map(|component_name| {
            component_hashes.get(component_name).map(|component_hash| {
                (
                    (*component_name).to_string(),
                    keyed_hex(
                        audit_key,
                        &[
                            AUDIT_SCHEMA_VERSION,
                            "semantic_component",
                            SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
                            component_name,
                            component_hash,
                        ],
                    ),
                )
            })
        })
        .collect()
}

fn blinded_revision_key(audit_key: &[u8], revision_hash: &str) -> String {
    keyed_hex(
        audit_key,
        &[
            AUDIT_SCHEMA_VERSION,
            "revision",
            SNAPSHOT_REVISION_CONTRACT_VERSION,
            revision_hash,
        ],
    )
}

#[cfg(test)]
fn snapshot_revision_key(
    audit_key: &[u8],
    source: SnapshotSource,
    snapshot: &SnapshotItem,
) -> String {
    let envelope = snapshot_semantic_envelope(source, snapshot, SnapshotUploadPolicy::default());
    blinded_revision_key(audit_key, &envelope.revision_hash)
}

pub(crate) fn valid_upload_policies() -> Vec<SnapshotUploadPolicy> {
    let mut policies = Vec::new();
    for bits in 0_u8..16 {
        let session_titles_enabled = bits & 1 != 0;
        let workspace_labels_enabled = bits & 2 != 0;
        let session_artifacts_enabled = bits & 4 != 0;
        let session_attribution_enabled = bits & 8 != 0;
        for session_attribution_labels_enabled in [false, true] {
            if session_attribution_labels_enabled
                && (!session_titles_enabled || !session_attribution_enabled)
            {
                continue;
            }
            policies.push(SnapshotUploadPolicy {
                session_titles_enabled,
                workspace_labels_enabled,
                session_artifacts_enabled,
                session_attribution_enabled,
                session_attribution_labels_enabled,
            });
        }
    }
    policies
}

fn legacy_policy_candidate_semantic_keys(
    audit_key: &[u8],
    source: SnapshotSource,
    snapshot: &SnapshotItem,
) -> Result<Vec<String>> {
    let mut candidates = BTreeSet::new();
    for policy in valid_upload_policies() {
        let mut candidate = snapshot.clone();
        apply_upload_policy(source, std::slice::from_mut(&mut candidate), policy);
        let component_hashes = snapshot_semantic_component_hashes(source, &candidate);
        let fingerprint = snapshot_fingerprint_from_component_hashes(
            source,
            &candidate.source_session_id,
            &component_hashes,
        );
        candidates.insert(keyed_hex(
            audit_key,
            &[AUDIT_SCHEMA_VERSION, "semantic", &fingerprint],
        ));
    }
    if candidates.len() > MAX_LEGACY_POLICY_CANDIDATES {
        return Err(anyhow!(
            "legacy policy candidate count {} exceeds cap {}",
            candidates.len(),
            MAX_LEGACY_POLICY_CANDIDATES
        ));
    }
    Ok(candidates.into_iter().collect())
}

#[derive(Debug, Serialize)]
struct AuditStateMarker {
    schema_version: &'static str,
}

fn prepare_audit_state_dir(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(anyhow!("audit state directory cannot be empty"));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(anyhow!(
                    "audit state must be a dedicated directory, not a production index file"
                ));
            }
            require_private_mode(path, &metadata, 0o700, "audit state directory")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .with_context(|| format!("create private audit state {}", path.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect audit state {}", path.display()));
        }
    }

    let marker_path = path.join(AUDIT_STATE_MARKER_FILE);
    if marker_path.exists() {
        reject_symlink(&marker_path, "audit state marker")?;
        require_private_mode(
            &marker_path,
            &fs::metadata(&marker_path)?,
            0o600,
            "audit state marker",
        )?;
        let marker: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker_path)?).context("parse audit state marker")?;
        let valid = marker.as_object().is_some_and(|value| {
            value.len() == 1
                && value.get("schema_version").and_then(|item| item.as_str())
                    == Some(AUDIT_STATE_SCHEMA_VERSION)
        });
        if !valid {
            return Err(anyhow!("audit state marker is invalid or unsupported"));
        }
    } else {
        if fs::read_dir(path)
            .with_context(|| format!("read audit state directory {}", path.display()))?
            .next()
            .is_some()
        {
            return Err(anyhow!(
                "existing audit state directory is unmarked; choose a new dedicated directory"
            ));
        }
        write_private_json(
            &marker_path,
            &AuditStateMarker {
                schema_version: AUDIT_STATE_SCHEMA_VERSION,
            },
        )?;
    }

    let index_path = path.join(AUDIT_SCAN_INDEX_FILE);
    if index_path.exists() {
        reject_symlink(&index_path, "audit scan index")?;
        require_private_mode(
            &index_path,
            &fs::metadata(&index_path)?,
            0o600,
            "audit scan index",
        )?;
    }
    Ok(index_path)
}

fn reject_symlink(path: &Path, label: &str) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(anyhow!("{label} cannot be a symlink"));
    }
    Ok(())
}

#[cfg(unix)]
fn require_private_mode(
    path: &Path,
    metadata: &fs::Metadata,
    expected: u32,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != expected {
        return Err(anyhow!(
            "{label} {} must have mode {expected:04o}; found {mode:04o}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
    _expected: u32,
    _label: &str,
) -> Result<()> {
    Ok(())
}

fn read_audit_key(path: &Path) -> Result<Vec<u8>> {
    let key = fs::read(path).with_context(|| format!("read audit key {}", path.display()))?;
    if key.len() < MIN_AUDIT_KEY_BYTES {
        return Err(anyhow!(
            "audit key must contain at least {MIN_AUDIT_KEY_BYTES} bytes"
        ));
    }
    Ok(key)
}

fn keyed_hex(key: &[u8], parts: &[&str]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    hex_bytes(&mac.finalize().into_bytes())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write to string");
    }
    output
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create audit output directory {}", parent.display()))?;
    }
    let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp_path)
        .with_context(|| format!("create private audit output {}", temp_path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("write private audit output {}", temp_path.display()))?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp_path, path)
        .with_context(|| format!("replace private audit output {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::scan_source_roots_with_artifacts;
    use base64::Engine as _;
    use std::io;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ottto-snapshot-audit-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn attribution_key_file(root: &Path) -> PathBuf {
        let path = root.join("session-attribution.key");
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([11_u8; 32]);
        fs::write(&path, encoded).expect("write attribution key");
        path
    }

    #[test]
    fn report_blinds_session_identity_and_never_contains_paths() {
        let home = temp_dir("redaction");
        let sessions = home.join(".pi").join("agent").join("sessions");
        fs::create_dir_all(&sessions).expect("create sessions");
        let raw_session_id = "fixture-session-019e2700-1111-7000-9000-111111111111";
        let transcript = sessions.join("session.jsonl");
        fs::write(
            &transcript,
            include_str!("../../../fixtures/snapshot-audit/pi-session.jsonl"),
        )
        .expect("write transcript");
        let key_path = home.join("audit.key");
        let fixture = include_bytes!("../../../fixtures/snapshot-audit/pi-session.jsonl");
        fs::write(&key_path, &fixture[..MIN_AUDIT_KEY_BYTES]).expect("write key");

        let audit_state_dir = home.join("audit-state");
        let private_payload_path = home.join("private-upload.json");
        let mut encoded = Vec::new();
        let report = run_snapshot_audit(
            SnapshotAuditOptions {
                source: SnapshotSource::Pi,
                roots: vec![sessions],
                audit_state_dir: audit_state_dir.clone(),
                audit_key_path: key_path,
                session_attribution_hmac_key_path: attribution_key_file(&home),
                attribution_home: Some(home.clone()),
                machine_id: "fixture-machine".to_string(),
                collected_at: "2026-07-22T08:02:00Z".to_string(),
                backfill_window_days: BACKFILL_WINDOW_DAYS,
                private_upload_payload_out: Some(private_payload_path.clone()),
            },
            &mut encoded,
        )
        .expect("audit");
        let encoded = String::from_utf8(encoded).expect("utf8 report");
        let private_payload: serde_json::Value =
            serde_json::from_slice(&fs::read(private_payload_path).expect("read private payload"))
                .expect("parse private payload");
        let raw_fingerprint = private_payload["snapshots"][0]["snapshot_fingerprint"]
            .as_str()
            .expect("raw fingerprint");
        let raw_source_file_fingerprint = private_payload["snapshots"][0]
            ["source_file_fingerprint"]
            .as_str()
            .expect("raw source file fingerprint");
        assert_eq!(report.emitted_session_count, 1);
        assert_eq!(report.schema_version, "local_snapshot_audit:v2");
        assert_eq!(report.component_contract_version, "snapshot_semantic:v1");
        assert_eq!(
            report.upload_policy,
            SnapshotAuditUploadPolicy {
                session_titles_enabled: false,
                workspace_labels_enabled: false,
                session_artifacts_enabled: false,
                session_attribution_enabled: false,
                session_attribution_labels_enabled: false,
            }
        );
        assert_eq!(
            report.sessions[0]
                .policy_neutral_component_keys
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["latency", "lifecycle_activity", "usage_accounting"]
        );
        assert_eq!(
            report.sessions[0]
                .policy_sensitive_component_keys
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["artifacts", "attribution", "display_identity"]
        );
        assert_eq!(report.sessions[0].revision_key.len(), 64);
        assert!(!report.sessions[0].legacy_revision_proof_available);
        assert!(!report.sessions[0]
            .legacy_policy_candidate_semantic_keys
            .is_empty());
        assert!(
            report.sessions[0]
                .legacy_policy_candidate_semantic_keys
                .len()
                <= MAX_LEGACY_POLICY_CANDIDATES
        );
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/v2-golden-keys.json"
        ))
        .expect("parse golden keys");
        assert_eq!(
            report.machine_key,
            golden["machine_key"].as_str().expect("golden machine key")
        );
        assert_eq!(
            report.sessions[0].session_key,
            golden["session_key"].as_str().expect("golden session key")
        );
        assert_eq!(
            report.sessions[0].semantic_key,
            golden["semantic_key"]
                .as_str()
                .expect("golden semantic key")
        );
        assert_eq!(
            serde_json::to_value(&report.sessions[0].policy_neutral_component_keys)
                .expect("serialize neutral keys"),
            golden["policy_neutral_component_keys"]
        );
        assert_eq!(
            serde_json::to_value(&report.sessions[0].policy_sensitive_component_keys)
                .expect("serialize sensitive keys"),
            golden["policy_sensitive_component_keys"]
        );
        assert!(!encoded.contains(raw_session_id));
        assert!(!encoded.contains("/private/work"));
        assert!(!encoded.contains(transcript.to_string_lossy().as_ref()));
        assert!(!encoded.contains("fixture-machine"));
        assert!(!encoded.contains(raw_fingerprint));
        assert!(!encoded.contains(raw_source_file_fingerprint));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&audit_state_dir)
                    .expect("audit state metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(audit_state_dir.join(AUDIT_SCAN_INDEX_FILE))
                    .expect("audit index metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn legacy_candidates_include_pre_policy_artifact_enabled_fingerprint() {
        let home = temp_dir("legacy-artifact-candidate");
        let sessions = home.join(".claude").join("projects").join("fixture");
        fs::create_dir_all(&sessions).expect("create sessions");
        fs::write(
            sessions.join("artifact-session.jsonl"),
            concat!(
                "{\"timestamp\":\"2026-05-29T00:00:00Z\",\"sessionId\":\"artifact-scan-session\",\"summary\":\"Artifact scan session\"}\n",
                "{\"timestamp\":\"2026-05-29T00:01:00Z\",\"sessionId\":\"artifact-scan-session\",\"message\":{\"id\":\"msg_01artifact\",\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-05-29T00:02:00Z\",\"sessionId\":\"artifact-scan-session\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"content\":[{\"type\":\"text\",\"text\":\"Opened https://github.com/ottto-ai/repo/pull/42\"}]}]}}\n",
            ),
        )
        .expect("write transcript");
        let audit_key = b"0123456789abcdef0123456789abcdef";
        let audit_key_path = home.join("audit.key");
        fs::write(&audit_key_path, audit_key).expect("write audit key");
        let attribution_key_path = attribution_key_file(&home);
        let encoded_attribution_key =
            Zeroizing::new(fs::read_to_string(&attribution_key_path).expect("read key"));
        let attribution_context = SessionAttributionContext::from_activity_hint(
            SnapshotSource::ClaudeCode,
            &home,
            true,
            Some(encoded_attribution_key.trim()),
            Some(SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .expect("attribution context");
        let mut expected_index = ScanIndex::default();
        let expected_scan = scan_source_roots_with_attribution(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&sessions),
            &mut expected_index,
            "2026-05-29T00:05:00Z",
            BACKFILL_WINDOW_DAYS,
            true,
            Some(&attribution_context),
        )
        .expect("production-equivalent scan");
        let expected_snapshot = expected_scan.snapshots.first().expect("snapshot");
        assert!(!expected_snapshot.session_artifacts.is_empty());
        let expected_candidate = keyed_hex(
            audit_key,
            &[
                AUDIT_SCHEMA_VERSION,
                "semantic",
                &expected_snapshot.snapshot_fingerprint,
            ],
        );

        let report = run_snapshot_audit(
            SnapshotAuditOptions {
                source: SnapshotSource::ClaudeCode,
                roots: vec![sessions],
                audit_state_dir: home.join("audit-state"),
                audit_key_path,
                session_attribution_hmac_key_path: attribution_key_path,
                attribution_home: Some(home.clone()),
                machine_id: "fixture-machine".to_string(),
                collected_at: "2026-05-29T00:05:00Z".to_string(),
                backfill_window_days: BACKFILL_WINDOW_DAYS,
                private_upload_payload_out: None,
            },
            &mut Vec::new(),
        )
        .expect("audit");
        assert!(report.sessions[0]
            .legacy_policy_candidate_semantic_keys
            .contains(&expected_candidate));
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn component_keys_are_policy_partitioned_and_domain_separated() {
        let key = b"0123456789abcdef0123456789abcdef";
        let component_hashes = BTreeMap::from([
            ("usage_accounting", "same-hash".to_string()),
            ("lifecycle_activity", "lifecycle-hash".to_string()),
            ("latency", "same-hash".to_string()),
            ("display_identity", "identity-hash".to_string()),
            ("attribution", "attribution-hash".to_string()),
            ("artifacts", "artifact-hash".to_string()),
        ]);
        let neutral = blinded_component_keys(key, &component_hashes, &POLICY_NEUTRAL_COMPONENTS);
        let sensitive =
            blinded_component_keys(key, &component_hashes, &POLICY_SENSITIVE_COMPONENTS);

        assert_eq!(
            neutral.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["latency", "lifecycle_activity", "usage_accounting"]
        );
        assert_eq!(
            sensitive.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["artifacts", "attribution", "display_identity"]
        );
        assert_ne!(neutral["usage_accounting"], neutral["latency"]);
        assert!(!neutral.values().any(|value| value == "same-hash"));
    }

    #[test]
    fn policy_neutral_and_revision_keys_ignore_upload_policy() {
        let fixture = include_bytes!("../../../fixtures/snapshot-audit/pi-session.jsonl");
        let key = &fixture[..MIN_AUDIT_KEY_BYTES];
        let root = temp_dir("policy-boundary");
        let sessions = root.join("sessions");
        fs::create_dir_all(&sessions).expect("create sessions");
        fs::write(
            sessions.join("session.jsonl"),
            include_str!("../../../fixtures/snapshot-audit/pi-session.jsonl"),
        )
        .expect("write transcript");
        let mut index = ScanIndex::default();
        let scan = scan_source_roots_with_artifacts(
            SnapshotSource::Pi,
            &[sessions],
            &mut index,
            "2026-07-22T08:02:00Z",
            BACKFILL_WINDOW_DAYS,
            false,
        )
        .expect("scan");
        let mut original = scan.snapshots.into_iter().next().expect("snapshot");
        original.source_file_fingerprint = Some("sha256:fixture-input".to_string());
        original.session_display_name = Some("private title".to_string());
        original.session_display_name_source = Some("fixture".to_string());
        original.workspace_display_label = Some("private workspace".to_string());
        original.session_artifacts = vec![crate::snapshots::SessionArtifact {
            kind: "pull_request".to_string(),
            value: "https://github.com/example/repo/pull/1".to_string(),
        }];

        let mut stripped = original.clone();
        apply_upload_policy(
            SnapshotSource::Pi,
            std::slice::from_mut(&mut stripped),
            SnapshotUploadPolicy {
                session_titles_enabled: false,
                workspace_labels_enabled: false,
                session_artifacts_enabled: false,
                session_attribution_enabled: false,
                session_attribution_labels_enabled: false,
            },
        );
        let original_components = snapshot_semantic_component_hashes(SnapshotSource::Pi, &original);
        let stripped_components = snapshot_semantic_component_hashes(SnapshotSource::Pi, &stripped);
        let original_neutral =
            blinded_component_keys(key, &original_components, &POLICY_NEUTRAL_COMPONENTS);
        let stripped_neutral =
            blinded_component_keys(key, &stripped_components, &POLICY_NEUTRAL_COMPONENTS);
        let original_sensitive =
            blinded_component_keys(key, &original_components, &POLICY_SENSITIVE_COMPONENTS);
        let stripped_sensitive =
            blinded_component_keys(key, &stripped_components, &POLICY_SENSITIVE_COMPONENTS);

        assert_eq!(original_neutral, stripped_neutral);
        assert_ne!(original_sensitive, stripped_sensitive);
        let original_revision = snapshot_revision_key(key, SnapshotSource::Pi, &original);
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/v2-golden-keys.json"
        ))
        .expect("parse golden keys");
        assert_eq!(
            original_revision,
            golden["revision_key_with_fixture_input_fingerprint"]
                .as_str()
                .expect("golden revision key")
        );
        let stripped_revision = snapshot_revision_key(key, SnapshotSource::Pi, &stripped);
        assert_eq!(original_revision, stripped_revision);
        let mut later_observation = stripped.clone();
        later_observation.collected_at = "2026-07-22T09:00:00Z".to_string();
        assert_eq!(
            snapshot_revision_key(key, SnapshotSource::Pi, &later_observation,),
            stripped_revision
        );

        let mut later_revision = stripped;
        later_revision.source_file_fingerprint = Some("changed-input-revision".to_string());
        assert_ne!(
            snapshot_revision_key(key, SnapshotSource::Pi, &later_revision,),
            stripped_revision
        );
        let mut changed_state_only_bucket = original;
        changed_state_only_bucket.usage_buckets[0].bucket_start =
            "2026-07-22T09:00:00Z".to_string();
        changed_state_only_bucket.usage_buckets[0].first_activity_at =
            Some("2026-07-22T09:00:00Z".to_string());
        changed_state_only_bucket.usage_buckets[0].last_activity_at =
            Some("2026-07-22T09:00:00Z".to_string());
        assert_ne!(
            snapshot_revision_key(key, SnapshotSource::Pi, &changed_state_only_bucket,),
            original_revision
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn short_audit_keys_fail_closed() {
        let root = temp_dir("short-key");
        let key_path = root.join("audit.key");
        fs::write(&key_path, b"too-short").expect("write key");
        let error = read_audit_key(&key_path).expect_err("short key rejected");
        assert!(error.to_string().contains("at least 32 bytes"));
        let _ = fs::remove_dir_all(root);
    }

    struct ClosedOutput;

    impl Write for ClosedOutput {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_report_output_does_not_advance_audit_index() {
        let root = temp_dir("closed-output");
        let sessions = root.join("sessions");
        fs::create_dir_all(&sessions).expect("create sessions");
        fs::write(
            sessions.join("session.jsonl"),
            "{\"type\":\"session\",\"session_id\":\"fixture\",\"timestamp\":\"2026-07-22T08:00:00Z\"}\n{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}\n",
        )
        .expect("write transcript");
        let key_path = root.join("audit.key");
        fs::write(&key_path, b"0123456789abcdef0123456789abcdef").expect("write key");
        let audit_state_dir = root.join("audit-state");
        let error = run_snapshot_audit(
            SnapshotAuditOptions {
                source: SnapshotSource::Pi,
                roots: vec![sessions],
                audit_state_dir: audit_state_dir.clone(),
                audit_key_path: key_path,
                session_attribution_hmac_key_path: attribution_key_file(&root),
                attribution_home: Some(root.clone()),
                machine_id: "fixture-machine".to_string(),
                collected_at: "2026-07-22T08:02:00Z".to_string(),
                backfill_window_days: BACKFILL_WINDOW_DAYS,
                private_upload_payload_out: None,
            },
            &mut ClosedOutput,
        )
        .expect_err("closed output fails");
        assert!(error.to_string().contains("write snapshot audit report"));
        assert!(!audit_state_dir.join(AUDIT_SCAN_INDEX_FILE).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn production_index_files_and_unmarked_directories_are_rejected() {
        let root = temp_dir("state-boundary");
        let production_index = root.join("snapshot-index.json");
        fs::write(&production_index, b"{}").expect("write production index");
        assert!(prepare_audit_state_dir(&production_index)
            .expect_err("production index rejected")
            .to_string()
            .contains("dedicated directory"));

        let unmarked = root.join("unmarked");
        fs::create_dir(&unmarked).expect("create unmarked dir");
        fs::write(unmarked.join("foreign"), b"data").expect("write foreign file");
        assert!(prepare_audit_state_dir(&unmarked)
            .expect_err("unmarked dir rejected")
            .to_string()
            .contains("unmarked"));

        let legacy = root.join("legacy-v1");
        fs::create_dir(&legacy).expect("create legacy state");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700))
                .expect("secure legacy state");
        }
        write_private_json(
            &legacy.join(AUDIT_STATE_MARKER_FILE),
            &serde_json::json!({"schema_version": "local_snapshot_audit_state:v1"}),
        )
        .expect("write legacy marker");
        assert!(prepare_audit_state_dir(&legacy)
            .expect_err("legacy v1 state rejected")
            .to_string()
            .contains("invalid or unsupported"));
        let _ = fs::remove_dir_all(root);
    }
}
