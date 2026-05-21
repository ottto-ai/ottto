use std::path::Path;

use toml_edit::DocumentMut;

use super::fence::{
    remove_fence_with_validator, upsert_fence_with_validator, AgentConfigResult, FenceWriteResult,
};

pub fn upsert_fence(path: &Path, body: &str) -> AgentConfigResult<FenceWriteResult> {
    upsert_fence_with_validator(path, body, validate_toml)
}

pub fn remove_fence(path: &Path) -> AgentConfigResult<FenceWriteResult> {
    remove_fence_with_validator(path, validate_toml)
}

fn validate_toml(body: &str) -> Result<(), String> {
    body.parse::<DocumentMut>()
        .map(|_| ())
        .map_err(|error| error.to_string())
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
