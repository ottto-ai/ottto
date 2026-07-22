//! Privacy-safe local snapshot audit support.
//!
//! The audit is a validation surface, not a second collector. It calls the
//! production scanner, applies the normal upload policy, and reports only
//! content-free counters plus HMAC-blinded identifiers/fingerprints. Raw
//! transcript paths, provider session ids, titles, repository labels, and
//! transcript content never enter the report.

use crate::snapshots::{
    apply_upload_policy, collector_version, scan_source_roots_with_artifacts, ScanIndex,
    SnapshotBatchRequest, SnapshotSource, SnapshotUploadPolicy, BACKFILL_WINDOW_DAYS,
    SNAPSHOT_SCHEMA_VERSION,
};
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const AUDIT_SCHEMA_VERSION: &str = "local_snapshot_audit:v1";
const AUDIT_STATE_SCHEMA_VERSION: &str = "local_snapshot_audit_state:v1";
const AUDIT_STATE_MARKER_FILE: &str = "audit-state.json";
const AUDIT_SCAN_INDEX_FILE: &str = "scan-index.json";
const MIN_AUDIT_KEY_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct SnapshotAuditOptions {
    pub source: SnapshotSource,
    pub roots: Vec<PathBuf>,
    pub audit_state_dir: PathBuf,
    pub audit_key_path: PathBuf,
    pub machine_id: String,
    pub collected_at: String,
    pub backfill_window_days: u64,
    pub private_upload_payload_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotAuditReport {
    pub schema_version: &'static str,
    pub source: String,
    pub machine_key: String,
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

impl Default for SnapshotAuditOptions {
    fn default() -> Self {
        Self {
            source: SnapshotSource::Codex,
            roots: Vec::new(),
            audit_state_dir: PathBuf::new(),
            audit_key_path: PathBuf::new(),
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
    let index_path = prepare_audit_state_dir(&options.audit_state_dir)?;
    let mut index = ScanIndex::load(&index_path)?;
    let mut scan = scan_source_roots_with_artifacts(
        options.source,
        &options.roots,
        &mut index,
        &options.collected_at,
        options.backfill_window_days,
        false,
    )?;
    let upload_policy = SnapshotUploadPolicy {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        session_artifacts_enabled: false,
        session_attribution_enabled: false,
        session_attribution_labels_enabled: false,
    };
    apply_upload_policy(options.source, &mut scan.snapshots, upload_policy);

    let mut sessions = scan
        .snapshots
        .iter()
        .map(|snapshot| SnapshotAuditSession {
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
        };
        write_private_json(path, &request)?;
    }

    let report = SnapshotAuditReport {
        schema_version: AUDIT_SCHEMA_VERSION,
        source: options.source.api_slug().to_string(),
        machine_key: keyed_hex(
            &audit_key,
            &[AUDIT_SCHEMA_VERSION, "machine", &options.machine_id],
        ),
        collector_version: collector_version(),
        parser_version: options.source.parser_version().to_string(),
        scan_identity_version: options.source.scan_identity_version().to_string(),
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

    #[test]
    fn report_blinds_session_identity_and_never_contains_paths() {
        let home = temp_dir("redaction");
        let sessions = home.join(".pi").join("agent").join("sessions");
        fs::create_dir_all(&sessions).expect("create sessions");
        let raw_session_id = "fixture-session-019e2700-1111-7000-9000-111111111111";
        let transcript = sessions.join("session.jsonl");
        fs::write(
            &transcript,
            format!(
                "{{\"type\":\"session\",\"session_id\":\"{raw_session_id}\",\"cwd\":\"/private/work\",\"timestamp\":\"2026-07-22T08:00:00Z\"}}\n{{\"type\":\"message_end\",\"message\":{{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1784707201000,\"usage\":{{\"input\":12,\"output\":4,\"cacheRead\":0,\"cacheWrite\":0}}}}}}\n"
            ),
        )
        .expect("write transcript");
        let key_path = home.join("audit.key");
        fs::write(&key_path, b"0123456789abcdef0123456789abcdef").expect("write key");

        let audit_state_dir = home.join("audit-state");
        let mut encoded = Vec::new();
        let report = run_snapshot_audit(
            SnapshotAuditOptions {
                source: SnapshotSource::Pi,
                roots: vec![sessions],
                audit_state_dir: audit_state_dir.clone(),
                audit_key_path: key_path,
                machine_id: "fixture-machine".to_string(),
                collected_at: "2026-07-22T08:02:00Z".to_string(),
                backfill_window_days: BACKFILL_WINDOW_DAYS,
                private_upload_payload_out: None,
            },
            &mut encoded,
        )
        .expect("audit");
        let encoded = String::from_utf8(encoded).expect("utf8 report");
        assert_eq!(report.emitted_session_count, 1);
        assert!(!encoded.contains(raw_session_id));
        assert!(!encoded.contains("/private/work"));
        assert!(!encoded.contains(transcript.to_string_lossy().as_ref()));
        assert!(!encoded.contains("fixture-machine"));
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
        let _ = fs::remove_dir_all(root);
    }
}
