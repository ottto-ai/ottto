use std::ops::Range;
use std::path::Path;

use toml_edit::{DocumentMut, ImDocument, Item, Key, TableLike};

use super::fence::{
    remove_fence_with_validator, upsert_fence_with_validator, upsert_would_change_with_validator,
    AgentConfigResult, FenceWriteResult,
};

pub fn upsert_fence(path: &Path, body: &str) -> AgentConfigResult<FenceWriteResult> {
    upsert_fence_with_validator(path, body, validate_toml)
}

pub fn upsert_would_change(path: &Path, body: &str) -> AgentConfigResult<bool> {
    upsert_would_change_with_validator(path, body, validate_toml)
}

pub fn remove_fence(path: &Path) -> AgentConfigResult<FenceWriteResult> {
    remove_fence_with_validator(path, validate_toml)
}

fn validate_toml(body: &str) -> Result<(), String> {
    body.parse::<DocumentMut>()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(crate) enum SourceOffFence {
    Absent,
    Complete {
        start: Range<usize>,
        end: Range<usize>,
    },
    Recovered(String),
}

/// The orphan exception authorizes byte ranges, never a reconstructed fence.
/// A parsed value's span excludes marker-looking lines inside TOML strings.
pub(crate) fn source_off_fence(
    body: &str,
    owned_port: impl Fn(&dyn TableLike, &str, &str) -> Option<u16>,
) -> Result<SourceOffFence, ()> {
    let document = ImDocument::parse(body).map_err(|_| ())?;
    let mut values = Vec::new();
    value_spans(document.as_item(), &mut values);
    let mut offset = 0;
    let mut markers = Vec::new();
    for line in body.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let trimmed = line.trim();
        if matches!(trimmed, "# ottto:start" | "# ottto:end")
            && !values.iter().any(|span| span.contains(&start))
        {
            markers.push((trimmed == "# ottto:start", start..offset));
        }
    }
    match markers.as_slice() {
        [] => Ok(SourceOffFence::Absent),
        [(true, start), (false, end)] => Ok(SourceOffFence::Complete {
            start: start.clone(),
            end: end.clone(),
        }),
        [(false, end)] => recover_orphan(body, &document, end.clone(), owned_port),
        _ => Err(()),
    }
}

fn value_spans(item: &Item, spans: &mut Vec<Range<usize>>) {
    if let Some(value) = item.as_value() {
        if let Some(span) = value.span() {
            spans.push(span);
        }
    } else if let Some(table) = item.as_table() {
        for (_, child) in table.iter() {
            value_spans(child, spans);
        }
    } else if let Some(tables) = item.as_array_of_tables() {
        for table in tables.iter() {
            for (_, child) in table.iter() {
                value_spans(child, spans);
            }
        }
    }
}

fn recover_orphan(
    body: &str,
    document: &ImDocument<&str>,
    end: Range<usize>,
    owned_port: impl Fn(&dyn TableLike, &str, &str) -> Option<u16>,
) -> Result<SourceOffFence, ()> {
    let otel = document
        .get("otel")
        .and_then(Item::as_table_like)
        .ok_or(())?;
    let mut ranges = Vec::new();
    let mut ports = std::collections::BTreeSet::new();
    for (key, signal) in [
        ("exporter", "logs"),
        ("trace_exporter", "traces"),
        ("metrics_exporter", "metrics"),
    ] {
        let Some(port) = owned_port(otel, key, signal) else {
            continue;
        };
        if port == 0 {
            return Err(());
        }
        let exporter = otel.get(key).ok_or(())?;
        let table = exporter.as_table_like().ok_or(())?;
        let http = table.get("otlp-http").ok_or(())?;
        let fields = http.as_table_like().ok_or(())?;
        // A familiar header cannot authorize deleting additional user settings.
        if fields
            .iter()
            .any(|(key, _)| !matches!(key, "endpoint" | "protocol" | "headers"))
            || fields
                .get("protocol")
                .is_some_and(|value| value.as_str() != Some("binary"))
            || fields
                .get("headers")
                .and_then(Item::as_table_like)
                .ok_or(())?
                .iter()
                .count()
                != 1
        {
            return Err(());
        }
        let endpoint = fields.get("endpoint").and_then(Item::as_str).ok_or(())?;
        if endpoint != format!("http://127.0.0.1:{port}/v1/{signal}")
            && endpoint != format!("http://localhost:{port}/v1/{signal}")
        {
            return Err(());
        }
        // Accept the generated dotted leaf, or the sole inline exporter in an
        // [otel] assignment. Nested section tables / mixed inline parents need
        // manual review: removing them could change subsequent TOML scope.
        let assignment = if exporter.as_inline_table().is_some() {
            if table.iter().count() != 1 {
                return Err(());
            }
            exporter
        } else {
            http
        };
        if assignment.as_inline_table().is_none() {
            return Err(());
        }
        let span = assignment.span().ok_or(())?;
        let start = body[..span.start].rfind('\n').map_or(0, |index| index + 1);
        let prefix = body[start..span.start].trim();
        let key_text = prefix.strip_suffix('=').ok_or(())?.trim();
        // Parsing the complete prefix as a key rejects values embedded inside
        // an unrelated inline assignment on the same physical line.
        let keys = Key::parse(key_text).map_err(|_| ())?;
        let names = keys.iter().map(Key::get).collect::<Vec<_>>();
        let expected = if exporter.as_inline_table().is_some() {
            vec![key]
        } else {
            vec![key, "otlp-http"]
        };
        if names != expected && names != [vec!["otel"], expected].concat() {
            return Err(());
        }
        if span.end > end.start {
            return Err(());
        }
        ports.insert(port);
        ranges.push(start..span.end);
    }
    if ranges.is_empty() || ports.len() != 1 {
        return Err(());
    }
    ranges.push(end);
    ranges.sort_by_key(|span| span.start);
    if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(());
    }
    let mut next = body.to_string();
    for span in ranges.into_iter().rev() {
        next.replace_range(span, "");
    }
    ImDocument::parse(next.as_str()).map_err(|_| ())?;
    Ok(SourceOffFence::Recovered(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_configs::fence::AgentConfigError;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_path(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join("ottto-codex-toml-fence-tests")
            .join(format!("{}-{name}-{counter}.toml", std::process::id()))
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
    fn upsert_valid_toml_block() {
        let path = test_path("valid");
        write(&path, "[profile]\nname = \"work\"\n");

        upsert_fence(&path, "[otel]\nenvironment = \"prod\"").expect("upsert");

        let body = read(&path);
        body.parse::<DocumentMut>().expect("toml parses");
        assert!(body.contains("[otel]"));
        assert!(body.ends_with("[profile]\nname = \"work\"\n"));
    }

    #[test]
    fn upsert_invalid_toml_body_rolls_back() {
        let path = test_path("invalid-body");
        let original = "[profile]\nname = \"work\"\n";
        write(&path, original);

        let error = upsert_fence(&path, "[otel]\nnot valid =").expect_err("reject invalid toml");

        assert!(matches!(error, AgentConfigError::ValidationFailed { .. }));
        assert_eq!(read(&path), original);
    }

    #[test]
    fn upsert_preserves_invalid_original_on_validation_failure() {
        let path = test_path("invalid-original");
        let original = "[profile\nname = \"work\"\n";
        write(&path, original);

        let error = upsert_fence(&path, "[otel]\nenvironment = \"prod\"").expect_err("reject");

        assert!(matches!(error, AgentConfigError::ValidationFailed { .. }));
        assert_eq!(read(&path), original);
    }

    #[test]
    fn remove_validates_remaining_toml() {
        let path = test_path("remove");
        write(
            &path,
            "# ottto:start\n[otel]\nenvironment = \"prod\"\n# ottto:end\n[profile]\nname = \"work\"\n",
        );

        remove_fence(&path).expect("remove");

        assert_eq!(read(&path), "[profile]\nname = \"work\"\n");
    }

    #[test]
    fn remove_rolls_back_when_remaining_toml_is_invalid() {
        let path = test_path("remove-invalid");
        let original = "# ottto:start\n[otel]\nenvironment = \"prod\"\n# ottto:end\n[profile\n";
        write(&path, original);

        let error = remove_fence(&path).expect_err("reject invalid remaining toml");

        assert!(matches!(error, AgentConfigError::ValidationFailed { .. }));
        assert_eq!(read(&path), original);
    }
}
