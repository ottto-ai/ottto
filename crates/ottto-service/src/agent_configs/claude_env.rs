use std::path::Path;

use super::fence::{remove_fence as remove_text_fence, upsert_fence as upsert_text_fence};
use super::fence::{AgentConfigResult, FenceWriteResult};

pub fn upsert_fence(path: &Path, body: &str) -> AgentConfigResult<FenceWriteResult> {
    upsert_text_fence(path, body)
}

pub fn remove_fence(path: &Path) -> AgentConfigResult<FenceWriteResult> {
    remove_text_fence(path)
}

pub fn render_export_block(entries: &[(&str, &str)]) -> String {
    entries
        .iter()
        .map(|(key, value)| format!("export {key}={}", shell_quote(value)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_path(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join("ottto-claude-env-fence-tests")
            .join(format!("{}-{name}-{counter}.env", std::process::id()))
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
    fn upsert_env_block_preserves_user_shell_rc() {
        let path = test_path("shellrc");
        let original = "alias ll='ls -la'\n";
        write(&path, original);

        upsert_fence(&path, "export CLAUDE_CODE_ENABLE_TELEMETRY='1'").expect("upsert");
        remove_fence(&path).expect("remove");

        assert_eq!(read(&path), original);
    }

    #[test]
    fn render_export_block_quotes_values() {
        let body = render_export_block(&[
            ("CLAUDE_CODE_ENABLE_TELEMETRY", "1"),
            (
                "OTEL_RESOURCE_ATTRIBUTES",
                "service.name=claude-code,ottto.source=claude_code",
            ),
        ]);

        assert_eq!(
            body,
            "export CLAUDE_CODE_ENABLE_TELEMETRY='1'\nexport OTEL_RESOURCE_ATTRIBUTES='service.name=claude-code,ottto.source=claude_code'"
        );
    }

    #[test]
    fn render_export_block_escapes_single_quotes() {
        let body = render_export_block(&[("OTTTO_TEST", "don't leak")]);

        assert_eq!(body, "export OTTTO_TEST='don'\"'\"'t leak'");
    }
}
