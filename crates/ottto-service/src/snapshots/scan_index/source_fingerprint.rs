//! Per-file source and scan fingerprints, and the local index key of a path.

use super::file_set_digest::sha256_hex;
use std::path::Path;

pub fn source_file_fingerprint(
    path: &Path,
    size_bytes: u64,
    modified_unix_seconds: u64,
    parser_version: &str,
) -> String {
    source_file_fingerprint_with_context(
        path,
        size_bytes,
        modified_unix_seconds,
        parser_version,
        "",
    )
}

pub(in crate::snapshots) fn source_file_fingerprint_with_context(
    path: &Path,
    size_bytes: u64,
    modified_unix_seconds: u64,
    parser_version: &str,
    source_fingerprint_context: &str,
) -> String {
    sha256_hex(&[
        &path.to_string_lossy(),
        &size_bytes.to_string(),
        &modified_unix_seconds.to_string(),
        parser_version,
        source_fingerprint_context,
    ])
}

pub(in crate::snapshots) fn scan_file_fingerprint_with_opened_identity(
    path: &Path,
    size_bytes: u64,
    modified_unix_nanos: u64,
    scan_identity_version: &str,
    session_sidecar_fingerprint: &str,
    opened_object_identity: &str,
) -> String {
    sha256_hex(&[
        &path.to_string_lossy(),
        &size_bytes.to_string(),
        &modified_unix_nanos.to_string(),
        scan_identity_version,
        session_sidecar_fingerprint,
        opened_object_identity,
    ])
}

pub(in crate::snapshots) fn local_index_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}
