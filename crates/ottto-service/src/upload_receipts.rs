//! Bounded, privacy-safe snapshot upload receipts.

use anyhow::{Context, Result};
use ottto_core::write_owner_only_file_atomic;
use ottto_protocol::{
    LocalAccountState, SourceKind, UploadReceiptEntityV1, UploadReceiptOutcomeV1, UploadReceiptV1,
    UploadReceiptsResponseV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef, SnapshotEntityRejection};

pub const UPLOAD_RECEIPT_RING_CAPACITY: usize = 500;
const UPLOAD_RECEIPTS_FILENAME: &str = "snapshot_upload_receipts.json";
const UPLOAD_RECEIPTS_DISK_SCHEMA_VERSION: u16 = 1;
const UPLOAD_RECEIPTS_RESPONSE_SCHEMA: &str = "ottto.upload_receipts.v1";
const ID_PREFIX_LEN: usize = 12;
const MAX_SERVER_REQUEST_ID_LEN: usize = 128;
const MAX_RECEIPT_FILE_BYTES: u64 = 4 * 1024 * 1024;
static RECEIPT_FILE_LOCK: Mutex<()> = Mutex::new(());
static CORRUPTION_LOGGED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedReceiptRing {
    schema_version: u16,
    receipts: Vec<UploadReceiptV1>,
}

/// Status-safe labels captured with a receipt. Neither value contains a raw
/// device, user, account, or organization identifier.
#[derive(Debug, Clone, Default)]
pub struct UploadReceiptContext {
    pub device_label: Option<String>,
    pub account_binding: Option<LocalAccountState>,
}

pub fn upload_receipts_path(state_dir: &Path) -> PathBuf {
    state_dir.join(UPLOAD_RECEIPTS_FILENAME)
}

/// Remove the active ring and any quarantined corrupt predecessors.
pub fn clear(state_dir: &Path) -> Result<()> {
    let _guard = RECEIPT_FILE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let active = upload_receipts_path(state_dir);
    if active.exists() {
        std::fs::remove_file(&active).context("remove upload receipt ring")?;
    }
    let Ok(entries) = std::fs::read_dir(state_dir) else {
        return Ok(());
    };
    let corrupt_prefix = format!("{UPLOAD_RECEIPTS_FILENAME}.corrupt.");
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(&corrupt_prefix) && entry.path().is_file() {
            std::fs::remove_file(entry.path()).context("remove quarantined upload receipt ring")?;
        }
    }
    Ok(())
}

pub fn append_success(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    http_status: u16,
    server_request_id: Option<&str>,
    response: &SnapshotBatchResponse,
) -> Result<()> {
    append_success_with_context(
        state_dir,
        source,
        batch_item_count,
        http_status,
        server_request_id,
        response,
        &UploadReceiptContext::default(),
    )
}

pub fn append_success_with_context(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    http_status: u16,
    server_request_id: Option<&str>,
    response: &SnapshotBatchResponse,
    context: &UploadReceiptContext,
) -> Result<()> {
    let outcome = if response.disabled {
        UploadReceiptOutcomeV1::Rejected
    } else if response.rejected_entities.is_empty() && response.conflict_entities.is_empty() {
        UploadReceiptOutcomeV1::Accepted
    } else if response.accepted > 0
        || !response.accepted_entities.is_empty()
        || !response.unchanged_entities.is_empty()
    {
        UploadReceiptOutcomeV1::Partial
    } else {
        UploadReceiptOutcomeV1::Rejected
    };
    let entity_limit = batch_item_count.min(50);
    let accepted_entities = response
        .accepted_entities
        .iter()
        .take(entity_limit)
        .map(sanitize_entity_ref)
        .collect::<Vec<_>>();
    let remaining = entity_limit.saturating_sub(accepted_entities.len());
    let unchanged_entities = response
        .unchanged_entities
        .iter()
        .take(remaining)
        .map(sanitize_entity_ref)
        .collect::<Vec<_>>();
    let remaining = remaining.saturating_sub(unchanged_entities.len());
    let conflict_entities = response
        .conflict_entities
        .iter()
        .take(remaining)
        .map(sanitize_entity_ref)
        .collect::<Vec<_>>();
    let remaining = remaining.saturating_sub(conflict_entities.len());
    let rejected_entities = response
        .rejected_entities
        .iter()
        .take(remaining)
        .map(sanitize_entity_rejection)
        .collect();
    append(
        state_dir,
        UploadReceiptV1 {
            uploaded_at: now_rfc3339(),
            outcome,
            http_status: Some(http_status),
            server_request_id: sanitize_server_request_id(server_request_id),
            retry_after_seconds: None,
            source,
            device_label: sanitize_device_label(context.device_label.as_deref()),
            account_binding: context.account_binding.clone(),
            batch_item_count: batch_item_count as u64,
            accepted_count: response.accepted,
            accepted_entities,
            unchanged_entities,
            conflict_entities,
            rejected_entities,
        },
    )
}

pub fn append_http_failure(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    outcome: UploadReceiptOutcomeV1,
    http_status: u16,
    server_request_id: Option<&str>,
    retry_after_seconds: Option<u64>,
) -> Result<()> {
    append_http_failure_with_context(
        state_dir,
        source,
        batch_item_count,
        outcome,
        http_status,
        server_request_id,
        retry_after_seconds,
        &UploadReceiptContext::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn append_http_failure_with_context(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    outcome: UploadReceiptOutcomeV1,
    http_status: u16,
    server_request_id: Option<&str>,
    retry_after_seconds: Option<u64>,
    context: &UploadReceiptContext,
) -> Result<()> {
    append(
        state_dir,
        empty_receipt(
            source,
            batch_item_count,
            outcome,
            Some(http_status),
            sanitize_server_request_id(server_request_id),
            retry_after_seconds,
            context,
        ),
    )
}

pub fn append_transport_error(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
) -> Result<()> {
    append_transport_error_with_context(
        state_dir,
        source,
        batch_item_count,
        &UploadReceiptContext::default(),
    )
}

pub fn append_transport_error_with_context(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    context: &UploadReceiptContext,
) -> Result<()> {
    append(
        state_dir,
        empty_receipt(
            source,
            batch_item_count,
            UploadReceiptOutcomeV1::TransportError,
            None,
            None,
            None,
            context,
        ),
    )
}

pub fn read(
    state_dir: &Path,
    limit: u16,
    since: Option<&str>,
    source: Option<SourceKind>,
) -> Result<UploadReceiptsResponseV1> {
    let since = since
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .with_context(|| format!("invalid receipts --since timestamp {value:?}"))
        })
        .transpose()?;
    let _guard = RECEIPT_FILE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = upload_receipts_path(state_dir);
    let ring = load_locked(&path)?;
    let state_path_present = path.is_file();
    let receipts = ring
        .receipts
        .into_iter()
        .rev()
        .filter(|receipt| {
            source
                .as_ref()
                .map_or(true, |source| receipt.source == *source)
        })
        .filter(|receipt| {
            since.map_or(true, |since| {
                OffsetDateTime::parse(&receipt.uploaded_at, &Rfc3339)
                    .is_ok_and(|uploaded_at| uploaded_at >= since)
            })
        })
        .take(usize::from(limit.min(UPLOAD_RECEIPT_RING_CAPACITY as u16)))
        .collect();
    Ok(UploadReceiptsResponseV1 {
        schema: UPLOAD_RECEIPTS_RESPONSE_SCHEMA.to_string(),
        receipts,
        ring_capacity: UPLOAD_RECEIPT_RING_CAPACITY as u16,
        state_path_present,
    })
}

fn empty_receipt(
    source: SourceKind,
    batch_item_count: usize,
    outcome: UploadReceiptOutcomeV1,
    http_status: Option<u16>,
    server_request_id: Option<String>,
    retry_after_seconds: Option<u64>,
    context: &UploadReceiptContext,
) -> UploadReceiptV1 {
    UploadReceiptV1 {
        uploaded_at: now_rfc3339(),
        outcome,
        http_status,
        server_request_id,
        retry_after_seconds,
        source,
        device_label: sanitize_device_label(context.device_label.as_deref()),
        account_binding: context.account_binding.clone(),
        batch_item_count: batch_item_count as u64,
        accepted_count: 0,
        accepted_entities: Vec::new(),
        unchanged_entities: Vec::new(),
        conflict_entities: Vec::new(),
        rejected_entities: Vec::new(),
    }
}

fn append(state_dir: &Path, receipt: UploadReceiptV1) -> Result<()> {
    let _guard = RECEIPT_FILE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = upload_receipts_path(state_dir);
    let mut ring = load_locked(&path)?;
    ring.receipts.push(receipt);
    if ring.receipts.len() > UPLOAD_RECEIPT_RING_CAPACITY {
        let overflow = ring.receipts.len() - UPLOAD_RECEIPT_RING_CAPACITY;
        ring.receipts.drain(..overflow);
    }
    let payload = serde_json::to_vec(&ring).context("serialize upload receipt ring")?;
    if payload.len() as u64 > MAX_RECEIPT_FILE_BYTES {
        anyhow::bail!("upload receipt ring exceeds its private state size bound");
    }
    write_owner_only_file_atomic(&path, &payload).context("persist upload receipt ring")
}

fn load_locked(path: &Path) -> Result<PersistedReceiptRing> {
    if !path.exists() {
        return Ok(PersistedReceiptRing {
            schema_version: UPLOAD_RECEIPTS_DISK_SCHEMA_VERSION,
            receipts: Vec::new(),
        });
    }
    if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > MAX_RECEIPT_FILE_BYTES) {
        quarantine_corrupt_file(path);
        return Ok(PersistedReceiptRing {
            schema_version: UPLOAD_RECEIPTS_DISK_SCHEMA_VERSION,
            receipts: Vec::new(),
        });
    }
    let parsed = std::fs::read(path)
        .context("read upload receipt ring")
        .and_then(|bytes| {
            serde_json::from_slice::<PersistedReceiptRing>(&bytes)
                .context("parse upload receipt ring")
        });
    match parsed {
        Ok(mut ring) if ring.schema_version == UPLOAD_RECEIPTS_DISK_SCHEMA_VERSION => {
            if ring.receipts.len() > UPLOAD_RECEIPT_RING_CAPACITY {
                let overflow = ring.receipts.len() - UPLOAD_RECEIPT_RING_CAPACITY;
                ring.receipts.drain(..overflow);
            }
            Ok(ring)
        }
        Ok(_) | Err(_) => {
            quarantine_corrupt_file(path);
            Ok(PersistedReceiptRing {
                schema_version: UPLOAD_RECEIPTS_DISK_SCHEMA_VERSION,
                receipts: Vec::new(),
            })
        }
    }
}

fn quarantine_corrupt_file(path: &Path) {
    let suffix = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let quarantine = path.with_extension(format!("json.corrupt.{suffix}"));
    let _ = std::fs::rename(path, quarantine);
    if !CORRUPTION_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "ottto-service: corrupt snapshot upload receipt state was quarantined; starting a fresh ring"
        );
    }
}

fn sanitize_entity_ref(entity: &SnapshotEntityRef) -> UploadReceiptEntityV1 {
    sanitized_entity(
        &entity.source_session_id,
        &entity.snapshot_fingerprint,
        entity.occurrence_count,
    )
}

fn sanitize_entity_rejection(entity: &SnapshotEntityRejection) -> UploadReceiptEntityV1 {
    sanitized_entity(
        &entity.source_session_id,
        &entity.snapshot_fingerprint,
        entity.occurrence_count,
    )
}

fn sanitized_entity(
    source_session_id: &str,
    snapshot_fingerprint: &str,
    occurrence_count: u64,
) -> UploadReceiptEntityV1 {
    UploadReceiptEntityV1 {
        source_session_id_hash: digest_prefix(
            b"ottto.upload_receipt.source_session_id:v1",
            source_session_id,
        ),
        snapshot_fingerprint_prefix: if snapshot_fingerprint.len() >= ID_PREFIX_LEN
            && snapshot_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            snapshot_fingerprint[..ID_PREFIX_LEN].to_ascii_lowercase()
        } else {
            digest_prefix(
                b"ottto.upload_receipt.snapshot_fingerprint:v1",
                snapshot_fingerprint,
            )
        },
        occurrence_count,
    }
}

fn digest_prefix(domain: &[u8], value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(value.as_bytes());
    let encoded = format!("{:x}", digest.finalize());
    encoded[..ID_PREFIX_LEN].to_string()
}

fn sanitize_server_request_id(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= MAX_SERVER_REQUEST_ID_LEN)
        .filter(|value| {
            value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        })
        .map(str::to_string)
}

fn sanitize_device_label(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .chars()
                .filter(|character| !character.is_control())
                .take(80)
                .collect::<String>()
        })
        .filter(|value| !value.is_empty())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ottto-upload-receipts-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn response(raw_id: &str) -> SnapshotBatchResponse {
        SnapshotBatchResponse {
            accepted: 1,
            sessions_reconciled: 1,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
            entity_ack_contract: Some("snapshot_entity_ack:v1".to_string()),
            accepted_entities: vec![SnapshotEntityRef {
                source_session_id: raw_id.to_string(),
                snapshot_fingerprint:
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
                occurrence_count: 1,
                body_witness_version: None,
                body_witness_digest: None,
                head_etag: None,
                head_challenge: None,
            }],
            unchanged_entities: Vec::new(),
            rejected_entities: Vec::new(),
            conflict_entities: Vec::new(),
        }
    }

    #[test]
    fn append_is_private_atomic_bounded_and_sanitized() {
        let dir = temp_dir();
        let raw_id = "raw-session-id-must-never-be-stored";
        let context = UploadReceiptContext {
            device_label: Some("  Test\nMac  ".to_string()),
            account_binding: Some(LocalAccountState::Connected),
        };
        for _ in 0..=UPLOAD_RECEIPT_RING_CAPACITY {
            append_success_with_context(
                &dir,
                SourceKind::Codex,
                1,
                200,
                Some("request-safe-123"),
                &response(raw_id),
                &context,
            )
            .unwrap();
        }
        let result = read(&dir, 500, None, None).unwrap();
        assert_eq!(result.receipts.len(), UPLOAD_RECEIPT_RING_CAPACITY);
        assert_eq!(
            result.receipts[0].accepted_entities[0]
                .source_session_id_hash
                .len(),
            12
        );
        assert_eq!(
            result.receipts[0].accepted_entities[0].snapshot_fingerprint_prefix,
            "abcdef012345"
        );
        assert_eq!(result.receipts[0].device_label.as_deref(), Some("TestMac"));
        assert_eq!(
            result.receipts[0].account_binding,
            Some(LocalAccountState::Connected)
        );
        let bytes = std::fs::read(upload_receipts_path(&dir)).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(raw_id));
        assert_eq!(
            std::fs::metadata(upload_receipts_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let state_files = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(state_files, vec![UPLOAD_RECEIPTS_FILENAME]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_ring_is_quarantined_and_recovers_on_append() {
        let dir = temp_dir();
        std::fs::write(upload_receipts_path(&dir), b"not json").unwrap();
        let empty = read(&dir, 50, None, None).unwrap();
        assert!(empty.receipts.is_empty());
        assert!(std::fs::read_dir(&dir).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".corrupt.")));
        append_transport_error(&dir, SourceKind::Pi, 3).unwrap();
        assert_eq!(read(&dir, 50, None, None).unwrap().receipts.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn outcomes_and_filters_cover_each_upload_path() {
        let dir = temp_dir();
        append_success(&dir, SourceKind::Codex, 1, 200, None, &response("a")).unwrap();
        let mut partial = response("b");
        partial.conflict_entities = partial.accepted_entities.clone();
        append_success(&dir, SourceKind::Codex, 1, 200, None, &partial).unwrap();
        append_http_failure(
            &dir,
            SourceKind::ClaudeCode,
            2,
            UploadReceiptOutcomeV1::Shed,
            429,
            None,
            Some(30),
        )
        .unwrap();
        append_http_failure(
            &dir,
            SourceKind::Pi,
            3,
            UploadReceiptOutcomeV1::Rejected,
            422,
            None,
            None,
        )
        .unwrap();
        append_http_failure(
            &dir,
            SourceKind::Pi,
            3,
            UploadReceiptOutcomeV1::AuthRejected,
            401,
            None,
            None,
        )
        .unwrap();
        append_transport_error(&dir, SourceKind::Pi, 4).unwrap();
        let outcomes = read(&dir, 500, None, None)
            .unwrap()
            .receipts
            .into_iter()
            .map(|receipt| receipt.outcome)
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes,
            vec![
                UploadReceiptOutcomeV1::TransportError,
                UploadReceiptOutcomeV1::AuthRejected,
                UploadReceiptOutcomeV1::Rejected,
                UploadReceiptOutcomeV1::Shed,
                UploadReceiptOutcomeV1::Partial,
                UploadReceiptOutcomeV1::Accepted
            ]
        );
        assert_eq!(
            read(&dir, 10, None, Some(SourceKind::Codex))
                .unwrap()
                .receipts
                .len(),
            2
        );
        assert!(read(&dir, 10, Some("2999-01-01T00:00:00Z"), None)
            .unwrap()
            .receipts
            .is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
