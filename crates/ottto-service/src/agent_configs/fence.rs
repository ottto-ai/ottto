use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const FENCE_START: &str = "# ottto:start";
pub const FENCE_END: &str = "# ottto:end";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceWriteResult {
    pub changed: bool,
    pub created: bool,
}

#[derive(Debug)]
pub enum AgentConfigError {
    Io { path: PathBuf, source: io::Error },
    AmbiguousFence { path: PathBuf, reason: &'static str },
    InvalidBody { reason: &'static str },
    ValidationFailed { path: PathBuf, message: String },
}

impl fmt::Display for AgentConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentConfigError::Io { path, source } => {
                write!(formatter, "failed to update {}: {source}", path.display())
            }
            AgentConfigError::AmbiguousFence { path, reason } => {
                write!(
                    formatter,
                    "ambiguous Ottto fence in {}: {reason}",
                    path.display()
                )
            }
            AgentConfigError::InvalidBody { reason } => {
                write!(formatter, "invalid Ottto fence body: {reason}")
            }
            AgentConfigError::ValidationFailed { path, message } => {
                write!(
                    formatter,
                    "proposed config for {} is invalid: {message}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for AgentConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentConfigError::Io { source, .. } => Some(source),
            AgentConfigError::AmbiguousFence { .. }
            | AgentConfigError::InvalidBody { .. }
            | AgentConfigError::ValidationFailed { .. } => None,
        }
    }
}

pub type AgentConfigResult<T> = Result<T, AgentConfigError>;

/// Lines of the Ottto-managed fence region (markers included), or `None`
/// when the body has no single complete fence. Used to report the real
/// managed region to the dashboard's "View managed config" preview; it is
/// display-only evidence, so ambiguous fences yield `None` instead of an
/// error and never fail a scan.
pub fn extract_fence_lines(body: &str) -> Option<Vec<String>> {
    let mut lines: Vec<String> = Vec::new();
    let mut inside = false;
    let mut found = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed == FENCE_START {
            if found || inside {
                return None;
            }
            inside = true;
            lines.push(line.to_string());
            continue;
        }
        if trimmed == FENCE_END {
            if !inside {
                return None;
            }
            lines.push(line.to_string());
            inside = false;
            found = true;
            continue;
        }
        if inside {
            lines.push(line.to_string());
        }
    }
    if found && !inside {
        Some(lines)
    } else {
        None
    }
}

pub fn upsert_fence(path: &Path, body: &str) -> AgentConfigResult<FenceWriteResult> {
    upsert_fence_with_validator(path, body, |_| Ok(()))
}

pub fn upsert_would_change(path: &Path, body: &str) -> AgentConfigResult<bool> {
    upsert_would_change_with_validator(path, body, |_| Ok(()))
}

pub fn remove_fence(path: &Path) -> AgentConfigResult<FenceWriteResult> {
    remove_fence_with_validator(path, |_| Ok(()))
}

pub(crate) fn upsert_fence_with_validator(
    path: &Path,
    body: &str,
    validator: impl Fn(&str) -> Result<(), String>,
) -> AgentConfigResult<FenceWriteResult> {
    let created = !path.exists();
    let (existing, next) = planned_upsert(path, body)?;
    if next == existing {
        return Ok(FenceWriteResult {
            changed: false,
            created,
        });
    }
    write_atomic_validated(path, &next, validator)?;
    Ok(FenceWriteResult {
        changed: true,
        created,
    })
}

pub(crate) fn upsert_would_change_with_validator(
    path: &Path,
    body: &str,
    validator: impl Fn(&str) -> Result<(), String>,
) -> AgentConfigResult<bool> {
    let (existing, next) = planned_upsert(path, body)?;
    if next == existing {
        return Ok(false);
    }
    if let Err(message) = validator(&next) {
        return Err(AgentConfigError::ValidationFailed {
            path: path.to_path_buf(),
            message,
        });
    }
    Ok(true)
}

pub(crate) fn remove_fence_with_validator(
    path: &Path,
    validator: impl Fn(&str) -> Result<(), String>,
) -> AgentConfigResult<FenceWriteResult> {
    if !path.exists() {
        return Ok(FenceWriteResult {
            changed: false,
            created: false,
        });
    }
    let existing = read_existing(path)?;
    let Some(range) = find_fence(&existing, path)? else {
        return Ok(FenceWriteResult {
            changed: false,
            created: false,
        });
    };
    let mut next = String::with_capacity(existing.len() - (range.end - range.start));
    next.push_str(&existing[..range.start]);
    next.push_str(&existing[range.end..]);
    write_atomic_validated(path, &next, validator)?;
    Ok(FenceWriteResult {
        changed: true,
        created: false,
    })
}

fn planned_upsert(path: &Path, body: &str) -> AgentConfigResult<(String, String)> {
    validate_body(body)?;
    let existing = read_existing(path)?;
    let eol = detect_line_ending(&existing).unwrap_or("\n");
    let block = render_block(body, eol);
    let next = match find_fence(&existing, path)? {
        Some(range) => {
            let mut next =
                String::with_capacity(existing.len() - (range.end - range.start) + block.len());
            next.push_str(&existing[..range.start]);
            next.push_str(&block);
            next.push_str(&existing[range.end..]);
            next
        }
        None => {
            let mut next = String::with_capacity(existing.len() + block.len());
            next.push_str(&block);
            next.push_str(&existing);
            next
        }
    };
    Ok((existing, next))
}

fn read_existing(path: &Path) -> AgentConfigResult<String> {
    match fs::read_to_string(path) {
        Ok(body) => Ok(body),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(AgentConfigError::Io {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

fn write_atomic_validated(
    path: &Path,
    body: &str,
    validator: impl Fn(&str) -> Result<(), String>,
) -> AgentConfigResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| AgentConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let temp_path = temp_path_for(path);
    fs::write(&temp_path, body).map_err(|source| AgentConfigError::Io {
        path: temp_path.clone(),
        source,
    })?;
    if let Ok(metadata) = fs::metadata(path) {
        let _ = fs::set_permissions(&temp_path, metadata.permissions());
    }
    let written = fs::read_to_string(&temp_path).map_err(|source| AgentConfigError::Io {
        path: temp_path.clone(),
        source,
    })?;
    if let Err(message) = validator(&written) {
        let _ = fs::remove_file(&temp_path);
        return Err(AgentConfigError::ValidationFailed {
            path: path.to_path_buf(),
            message,
        });
    }
    fs::rename(&temp_path, path).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        AgentConfigError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn temp_path_for(path: &Path) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let temp_name = format!(".{file_name}.ottto-tmp-{}-{counter}", std::process::id());
    path.with_file_name(temp_name)
}

fn validate_body(body: &str) -> AgentConfigResult<()> {
    for line in body_lines(body) {
        if line == FENCE_START || line == FENCE_END {
            return Err(AgentConfigError::InvalidBody {
                reason: "body must not contain Ottto fence marker lines",
            });
        }
    }
    Ok(())
}

fn render_block(body: &str, eol: &str) -> String {
    let normalized_body = normalize_body_eol(body, eol);
    let mut block = String::new();
    block.push_str(FENCE_START);
    block.push_str(eol);
    block.push_str(&normalized_body);
    if !normalized_body.is_empty() && !normalized_body.ends_with(eol) {
        block.push_str(eol);
    }
    block.push_str(FENCE_END);
    block.push_str(eol);
    block
}

fn normalize_body_eol(body: &str, eol: &str) -> String {
    body.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', eol)
}

fn detect_line_ending(body: &str) -> Option<&'static str> {
    let bytes = body.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] == b'\n' {
            return if index > 0 && bytes[index - 1] == b'\r' {
                Some("\r\n")
            } else {
                Some("\n")
            };
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FenceRange {
    start: usize,
    end: usize,
}

fn find_fence(body: &str, path: &Path) -> AgentConfigResult<Option<FenceRange>> {
    let mut start: Option<LineRange> = None;
    let mut end: Option<LineRange> = None;
    let mut starts = 0;
    let mut ends = 0;
    for line in line_ranges(body) {
        match line.text {
            FENCE_START => {
                starts += 1;
                if start.is_none() {
                    start = Some(line);
                }
            }
            FENCE_END => {
                ends += 1;
                if end.is_none() {
                    end = Some(line);
                }
            }
            _ => {}
        }
    }
    match (starts, ends, start, end) {
        (0, 0, None, None) => Ok(None),
        (1, 1, Some(start), Some(end)) if start.start < end.start => Ok(Some(FenceRange {
            start: start.start,
            end: end.end,
        })),
        (1, 1, Some(_), Some(_)) => Err(AgentConfigError::AmbiguousFence {
            path: path.to_path_buf(),
            reason: "end marker appears before start marker",
        }),
        _ => Err(AgentConfigError::AmbiguousFence {
            path: path.to_path_buf(),
            reason: "expected exactly one complete Ottto fence or no fence",
        }),
    }
}

#[derive(Debug, Clone, Copy)]
struct LineRange<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

fn line_ranges(body: &str) -> Vec<LineRange<'_>> {
    let bytes = body.as_bytes();
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < body.len() {
        let mut cursor = start;
        while cursor < body.len() && bytes[cursor] != b'\n' {
            cursor += 1;
        }
        let mut text_end = cursor;
        let end = if cursor < body.len() {
            cursor += 1;
            cursor
        } else {
            cursor
        };
        if text_end > start && bytes[text_end - 1] == b'\r' {
            text_end -= 1;
        }
        ranges.push(LineRange {
            text: &body[start..text_end],
            start,
            end,
        });
        start = end;
    }
    if body.is_empty() {
        ranges.push(LineRange {
            text: "",
            start: 0,
            end: 0,
        });
    }
    ranges
}

fn body_lines(body: &str) -> Vec<&str> {
    line_ranges(body)
        .into_iter()
        .filter_map(|line| {
            if line.start == line.end && body.is_empty() {
                None
            } else {
                Some(line.text)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_path(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join("ottto-fence-tests").join(format!(
            "{}-{}-{counter}",
            std::process::id(),
            name
        ))
    }

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, body).expect("write test file");
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).expect("read test file")
    }

    #[test]
    fn upsert_replaces_existing_fence() {
        let path = test_path("replace");
        write(&path, "# ottto:start\nold=1\n# ottto:end\nuser=true\n");

        upsert_fence(&path, "new=1").expect("upsert");

        assert_eq!(
            read(&path),
            "# ottto:start\nnew=1\n# ottto:end\nuser=true\n"
        );
    }

    #[test]
    fn upsert_noops_when_body_matches() {
        let path = test_path("noop-upsert");
        write(
            &path,
            "# ottto:start\nmanaged=true\n# ottto:end\nuser=true\n",
        );

        let result = upsert_fence(&path, "managed=true").expect("upsert");

        assert!(!result.changed);
        assert!(!result.created);
    }

    #[test]
    fn body_marker_line_is_rejected() {
        let path = test_path("body-marker");
        let error = upsert_fence(&path, "safe\n# ottto:start\nunsafe").expect_err("reject");

        assert!(matches!(error, AgentConfigError::InvalidBody { .. }));
        assert!(!path.exists());
    }

    #[test]
    fn missing_end_marker_is_rejected() {
        for original in [
            "# ottto:start\nmanaged=true\n",
            "# ottto:start\none=1\n# ottto:end\n# ottto:start\ntwo=2\n# ottto:end\n",
        ] {
            let path = test_path("ambiguous-markers");
            write(&path, original);
            for error in [
                upsert_fence(&path, "new=true").unwrap_err(),
                remove_fence(&path).unwrap_err(),
            ] {
                assert!(matches!(error, AgentConfigError::AmbiguousFence { .. }));
                assert_eq!(read(&path), original);
            }
        }
    }

    #[test]
    fn validator_failure_leaves_original_file_and_removes_temp() {
        let path = test_path("validator");
        write(&path, "user=true\n");

        let error =
            upsert_fence_with_validator(
                &path,
                "managed=true",
                |_| Err("not parseable".to_string()),
            )
            .expect_err("validation failed");

        assert!(matches!(error, AgentConfigError::ValidationFailed { .. }));
        assert_eq!(read(&path), "user=true\n");
        let path_file_name = path.file_name().expect("file name").to_string_lossy();
        let temp_count = fs::read_dir(path.parent().expect("parent"))
            .expect("read parent")
            .filter_map(Result::ok)
            .filter(|entry| {
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                file_name.contains(path_file_name.as_ref()) && file_name.contains("ottto-tmp")
            })
            .count();
        assert_eq!(temp_count, 0);
    }

    #[test]
    fn property_sequence_preserves_lf_outside_fence() {
        for original in [
            "alpha=1\n# user comment\nbeta=2\n",
            "alpha=1\r\n# user comment\r\nbeta=2\r\n",
            "alpha=1\nbeta=2",
            "echo before\nvalue='# ottto:start'\necho after",
        ] {
            let path = test_path("property-sequence");
            write(&path, original);
            for body in ["one=1", "two=2", "three=3"] {
                upsert_fence(&path, body).expect("upsert");
                remove_fence(&path).expect("remove");
            }
            assert_eq!(read(&path), original);
        }
    }
}
