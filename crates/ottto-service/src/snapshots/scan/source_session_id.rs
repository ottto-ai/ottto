//! The source session id a transcript resolves to on the snapshot wire, and
//! the UUID shape check shared by Codex identity readers.

use crate::snapshots::wire::SnapshotSource;
use crate::snapshots::{claude_subagent_identity, resolve_codex_identity};
use std::path::Path;

pub(in crate::snapshots) fn codex_identity_is_uuid_shaped(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Resolve the source session id used on the snapshot wire from the first
/// in-file id. Claude subagents take their parent from the path; Codex UUIDs
/// use the same case normalization as snapshot identity comparisons.
/// Callers must exclude Claude workflow journals before resolving an id.
pub(crate) fn snapshot_source_session_id(
    source: SnapshotSource,
    path: &Path,
    first_id: String,
) -> String {
    match source {
        SnapshotSource::ClaudeCode => claude_subagent_identity(path)
            .map(|identity| identity.source_session_id())
            .unwrap_or(first_id),
        SnapshotSource::Codex => resolve_codex_identity(&first_id),
        _ => first_id,
    }
}
