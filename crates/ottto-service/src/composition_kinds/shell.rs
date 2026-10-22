//! Lexical shell-command parsing shared by the session-start facts and
//! composition kinds: file-like tokens, directory changes and path
//! normalization against the session folder. No `stat`, no IO.

use std::path::Path;

pub(crate) const MAX_SHELL_PATH_TOKENS: usize = 16;
const MAX_PATH_BYTES: usize = 512;

/// `ext` of a path's last segment: 1-8 ASCII alphanumerics after the last dot.
pub(crate) fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let (_, ext) = name.rsplit_once('.')?;
    ((1..=8).contains(&ext.len()) && ext.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .then_some(ext)
}

/// File-like tokens of a shell command, taken lexically (no `stat`): not a
/// flag, no URL or shell syntax, and either a path (`/`) or a file extension.
pub(crate) fn shell_path_tokens(command: &str) -> impl Iterator<Item = &str> {
    command
        .split(|ch: char| {
            ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '(' | ')' | '<' | '>' | '`')
        })
        .map(|token| token.trim_matches(|ch| matches!(ch, '"' | '\'' | ',')))
        .filter(|token| {
            !token.is_empty()
                && !token.starts_with('-')
                && !token.contains("://")
                && !token.contains(['*', '?', '$', '{', '}', '=', '[', ']'])
                && (token.contains('/') || extension(token).is_some())
        })
        .take(MAX_SHELL_PATH_TOKENS)
}

/// True when a shell command may change its working directory, so its
/// relative paths cannot be shown to be inside the session's checkout.
pub(crate) fn shell_changes_directory(command: &str) -> bool {
    // Quotes and braces split too, so `bash -lc 'cd x && ...'` is caught.
    command
        .split(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    ';' | '|' | '&' | '(' | ')' | '`' | '\'' | '"' | '{' | '}'
                )
        })
        .any(|word| {
            matches!(word, "cd" | "pushd" | "popd" | "chdir")
                // `-C dir` and attached `-Cdir` (git, make, tar, `env -C`).
                || word.starts_with("-C")
                || [
                    "--chdir",
                    "--directory",
                    "--git-dir",
                    "--work-tree",
                    "-chdir",
                    "--cwd",
                    "--prefix",
                ]
                .iter()
                .any(|flag| word.starts_with(flag))
        })
}

fn is_repo_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('~')
        && !path.split('/').any(|segment| segment == "..")
}

/// Admission's forbidden fragments for any plain path (from the server's
/// footprint schema), matched case-insensitively.
const PLAIN_PATH_FORBIDDEN_FRAGMENTS: [&str; 15] = [
    "/users/",
    "\\users\\",
    "/home/",
    "\\home\\",
    "file://",
    "transcript_path",
    "workspace_path",
    "full_transcript_path",
    "authorization:",
    "bearer ",
    "otdev_",
    "otsi_",
    "otsr_",
    "otel_",
    "otrelay_",
];

/// True when admission takes `path` as a plain `repo_path` unchanged (its
/// `_safe_relative_path`): any other path travels hashed or is withheld, so
/// one unsafe path never clears the whole session-start block.
pub(crate) fn is_plain_path(path: &str) -> bool {
    let lowered = path.to_lowercase();
    is_repo_relative(path)
        && path.chars().count() <= MAX_PATH_BYTES
        // No backslash form (`\x`, `a\..\b`, `C:\x`) and no drive or URL form.
        && !path.contains('\\')
        && !path.contains(":/")
        // Admission collapses whitespace runs; only single inner spaces survive it.
        && !path.starts_with(' ')
        && !path.ends_with(' ')
        && !path.contains("  ")
        && !path
            .chars()
            .any(|ch| ch != ' ' && (ch.is_whitespace() || ch.is_control()))
        && !PLAIN_PATH_FORBIDDEN_FRAGMENTS
            .iter()
            .any(|fragment| lowered.contains(fragment))
}

/// `(key, plain path)`: the key is the repo-relative path when the file is
/// inside the session's working directory (a lexical prefix test), else the
/// path as written. The plain path is set only when admission accepts it and
/// its base is proven: an absolute path under `cwd`, or a relative one when
/// `trust_relative` and the session directory is known. Every other file can
/// only travel hashed.
pub(crate) fn normalize_path(
    raw: &str,
    cwd: Option<&Path>,
    trust_relative: bool,
) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    let raw = raw.strip_prefix("./").unwrap_or(raw);
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES {
        return None;
    }
    if raw.starts_with('/') {
        let inside = cwd
            .and_then(Path::to_str)
            .and_then(|cwd| raw.strip_prefix(cwd.trim_end_matches('/')))
            .and_then(|rest| rest.strip_prefix('/'))
            .filter(|rest| is_repo_relative(rest));
        return Some(match inside {
            Some(rest) => (
                rest.to_string(),
                is_plain_path(rest).then(|| rest.to_string()),
            ),
            None => (raw.to_string(), None),
        });
    }
    let plain = trust_relative && cwd.is_some() && is_plain_path(raw);
    Some((raw.to_string(), plain.then(|| raw.to_string())))
}
