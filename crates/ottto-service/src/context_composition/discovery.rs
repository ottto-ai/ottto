//! Transcript-copy identity shared by the composition reader.

use std::path::Path;

/// Claude subagent ids are unique only within their parent session
/// (`<session>/subagents/agent-<id>.jsonl`), so that key keeps the parent.
pub(super) fn transcript_copy_key(path: &Path) -> Vec<std::ffi::OsString> {
    let name = path.file_name().map(|name| name.to_os_string());
    let session = path
        .parent()
        .filter(|dir| dir.file_name() == Some(std::ffi::OsStr::new("subagents")))
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .map(|session| session.to_os_string());
    session.into_iter().chain(name).collect()
}
