//! Conservative evaluators for Claude Code 2.x and Codex 0.x. Unknown routing
//! or unevaluable policy fails closed. No helpers, login or doctor are run.
use super::{binding::Binding, block, Block, Reason};
use ottto_protocol::{SessionLaunchProviderV1 as Provider, SessionLaunchSettingLayerV1 as Layer};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub(super) const CLAUDE_UNSET: &[&str] = &[
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_SECURESTORAGE_CONFIG_DIR",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_PROFILE",
    "ANTHROPIC_CONFIG_DIR",
    "ANTHROPIC_CUSTOM_HEADERS",
    "ANTHROPIC_ORGANIZATION_ID",
    "ANTHROPIC_WORKSPACE_ID",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    "ANTHROPIC_AWS_API_KEY",
    "ANTHROPIC_AWS_BASE_URL",
    "ANTHROPIC_AWS_WORKSPACE_ID",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "ANTHROPIC_FOUNDRY_RESOURCE",
    "CLAUDECODE",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SSE_PORT",
    "CLAUDE_CODE_OAUTH_TOKEN_FD",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "OTTTO_CONTROL_TOKEN",
];
pub(super) const CODEX_UNSET: &[&str] = &[
    "CODEX_HOME",
    "CODEX_SQLITE_HOME",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    // Codex 0.150 auth/manager.rs: ambient PAT/agent identity wins over
    // persisted home auth; refresh/revoke overrides must not redirect that credential.
    "CODEX_ACCESS_TOKEN",
    "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
    "CODEX_REVOKE_TOKEN_URL_OVERRIDE",
    "CODEX_APP_SERVER_LOGIN_CLIENT_ID",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "CHATGPT_BASE_URL",
    "CODEX_PROFILE",
    "OTTTO_CONTROL_TOKEN",
];

fn failure(reason: Reason, layer: Layer) -> Block {
    Block {
        setting_layer: Some(layer),
        ..block(reason)
    }
}

/// No special files, redirects, unbounded reads or parse-error-as-empty layers.
pub(super) fn read_layer(path: &Path, layer: Layer) -> Result<Option<String>, Block> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(failure(Reason::SettingsUnreadable, layer)),
    };
    let metadata = file
        .metadata()
        .map_err(|_| failure(Reason::SettingsUnreadable, layer))?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(failure(Reason::SettingsUnreadable, layer));
    }
    let mut text = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| failure(Reason::SettingsUnreadable, layer))?;
    if text.len() > 1024 * 1024 {
        return Err(failure(Reason::SettingsUnreadable, layer));
    }
    Ok(Some(text))
}

fn ancestors(cwd: &Path) -> impl Iterator<Item = &Path> {
    cwd.ancestors().take(128)
}

pub(super) fn evaluate(binding: &Binding, cwd: &Path) -> Result<(), Block> {
    match binding.provider {
        Provider::ClaudeCode => claude(binding, cwd),
        Provider::Codex => codex(binding, cwd, Path::new("/etc/codex")),
        Provider::Unknown => Err(block(Reason::Unknown)),
    }
}

fn claude(binding: &Binding, cwd: &Path) -> Result<(), Block> {
    // User < project < project-local < machine policy. Ancestor layers are
    // checked conservatively too: a repository root can differ from cwd.
    let mut paths = vec![
        (Layer::User, binding.root.join("settings.json")),
        (Layer::Local, binding.root.join("settings.local.json")),
    ];
    for ancestor in ancestors(cwd) {
        paths.push((Layer::Project, ancestor.join(".claude/settings.json")));
        paths.push((
            Layer::ProjectLocal,
            ancestor.join(".claude/settings.local.json"),
        ));
    }
    if let Some(main) = main_checkout_for_settings(cwd)? {
        paths.push((
            Layer::ProjectLocal,
            main.join(".claude/settings.local.json"),
        ));
        paths.push((Layer::Project, main.join(".claude/settings.json")));
    }
    // These policy sources are not statically evaluable by this version.
    for path in [
        binding.root.join("remote-settings.json"),
        binding.root.join("managed-settings.json"),
        binding
            .user
            .home
            .join("Library/Preferences/com.anthropic.claudecode.plist"),
        PathBuf::from("/Library/Managed Preferences")
            .join(&binding.user.name)
            .join("com.anthropic.claudecode.plist"),
    ] {
        refuse_present(&path, Layer::Managed)?;
    }
    paths.push((
        Layer::Managed,
        PathBuf::from(if cfg!(target_os = "macos") {
            "/Library/Application Support/ClaudeCode/managed-settings.json"
        } else {
            "/etc/claude-code/managed-settings.json"
        }),
    ));
    for path in [
        "/Library/Managed Preferences/com.anthropic.claudecode.plist",
        "/Library/Application Support/ClaudeCode/managed-settings.d",
        "/etc/claude-code/managed-settings.d",
    ] {
        refuse_present(Path::new(path), Layer::Managed)?;
    }
    let mut layers = Vec::new();
    for (layer, path) in paths {
        if let Some(text) = read_layer(&path, layer)? {
            let value: Value = serde_json::from_str(&text)
                .map_err(|_| failure(Reason::SettingsMalformed, layer))?;
            validate_claude_layer(&value, layer, &binding.organization)?;
            layers.push(value);
        }
    }
    layers.reverse();
    if let Some(auth) =
        crate::agent_status::claude_alternative_auth_layers(&layers, &|_| None, true, &[], false)
    {
        use crate::agent_status::ClaudeAlternativeAuth;
        return Err(block(match auth {
            ClaudeAlternativeAuth::Bedrock | ClaudeAlternativeAuth::Vertex => {
                Reason::CloudProviderRoute
            }
            ClaudeAlternativeAuth::ApiKey => Reason::ApiKeyRoute,
        }));
    }
    Ok(())
}

/// Resolve the usual linked-worktree common directory without starting git
/// (and without consulting inherited GIT_DIR/GIT_WORK_TREE or running helpers).
fn main_checkout_for_settings(cwd: &Path) -> Result<Option<PathBuf>, Block> {
    for root in ancestors(cwd) {
        let git = root.join(".git");
        match fs::symlink_metadata(&git) {
            Ok(metadata) if metadata.is_dir() => return Ok(None),
            Ok(_) => {
                let Some(text) = read_layer(&git, Layer::Project)? else {
                    return Err(failure(Reason::ConfigUnsupported, Layer::Project));
                };
                let target = text
                    .trim()
                    .strip_prefix("gitdir: ")
                    .ok_or_else(|| failure(Reason::ConfigUnsupported, Layer::Project))?;
                let gitdir = root.join(target);
                let Some(common) = read_layer(&gitdir.join("commondir"), Layer::Project)? else {
                    return Ok(None);
                };
                let common = gitdir
                    .join(common.trim())
                    .canonicalize()
                    .map_err(|_| failure(Reason::SettingsUnreadable, Layer::Project))?;
                if common.file_name().map_or(true, |name| name != ".git") {
                    return Err(failure(Reason::ConfigUnsupported, Layer::Project));
                }
                return Ok(common.parent().map(Path::to_path_buf));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failure(Reason::SettingsUnreadable, Layer::Project)),
        }
    }
    Ok(None)
}

fn validate_claude_layer(value: &Value, layer: Layer, organization: &str) -> Result<(), Block> {
    let object = value
        .as_object()
        .ok_or_else(|| failure(Reason::SettingsMalformed, layer))?;
    if object.contains_key("policyHelper") || object.contains_key("forceLoginGatewayUrl") {
        return Err(failure(Reason::ConfigUnsupported, layer));
    }
    if let Some(env) = object.get("env") {
        let env = env
            .as_object()
            .ok_or_else(|| failure(Reason::SettingsMalformed, layer))?;
        for key in env.keys() {
            if [
                "CLAUDE_CODE_USE_BEDROCK",
                "CLAUDE_CODE_USE_VERTEX",
                "CLAUDE_CODE_USE_FOUNDRY",
                "CLAUDE_CODE_USE_ANTHROPIC_AWS",
                "ANTHROPIC_AWS_API_KEY",
                "ANTHROPIC_AWS_BASE_URL",
                "ANTHROPIC_AWS_WORKSPACE_ID",
                "ANTHROPIC_FOUNDRY_API_KEY",
                "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
                "ANTHROPIC_FOUNDRY_RESOURCE",
            ]
            .contains(&key.as_str())
            {
                return Err(failure(Reason::CloudProviderRoute, layer));
            }
            if [
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "CLAUDE_CODE_OAUTH_TOKEN",
            ]
            .contains(&key.as_str())
            {
                return Err(failure(Reason::ApiKeyRoute, layer));
            }
            if CLAUDE_UNSET.contains(&key.as_str())
                || ["HOME", "USER", "LOGNAME"].contains(&key.as_str())
            {
                return Err(failure(Reason::SettingsEnvOverride, layer));
            }
        }
    }
    if object
        .get("apiKeyHelper")
        .is_some_and(|value| !value.is_null())
    {
        return Err(failure(Reason::ApiKeyRoute, layer));
    }
    if object
        .get("forceLoginMethod")
        .is_some_and(|value| value.as_str() != Some("claudeai"))
    {
        return Err(failure(Reason::ForcedLoginMethod, layer));
    }
    if let Some(org) = object.get("forceLoginOrgUUID") {
        if org
            .as_str()
            .and_then(|org| ottto_core::billing_identity_hash("anthropic", "organization", org))
            .as_deref()
            != Some(organization)
        {
            return Err(failure(Reason::ForcedOrgMismatch, layer));
        }
    }
    Ok(())
}

fn refuse_present(path: &Path, layer: Layer) -> Result<(), Block> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(failure(Reason::ConfigUnsupported, layer)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(failure(Reason::SettingsUnreadable, layer)),
    }
}

pub(super) fn codex(binding: &Binding, cwd: &Path, system_dir: &Path) -> Result<(), Block> {
    // Codex 0.x project and MDM requirements/config cannot be evaluated by
    // this local-only evaluator. Presence is a typed refusal, never ignored.
    for ancestor in ancestors(cwd).filter(|ancestor| *ancestor != binding.user.home) {
        refuse_present(&ancestor.join(".codex/config.toml"), Layer::Project)?;
    }
    // Codex 0.150 also loads the system config layer.
    for name in ["config.toml", "managed_config.toml", "requirements.toml"] {
        refuse_present(&system_dir.join(name), Layer::Managed)?;
    }
    refuse_present(
        Path::new("/Library/Managed Preferences/com.openai.codex.plist"),
        Layer::Managed,
    )?;
    refuse_present(&binding.root.join("managed_config.toml"), Layer::Managed)?;
    for path in [
        binding
            .user
            .home
            .join("Library/Preferences/com.openai.codex.plist"),
        PathBuf::from("/Library/Managed Preferences")
            .join(&binding.user.name)
            .join("com.openai.codex.plist"),
    ] {
        refuse_present(&path, Layer::Managed)?;
    }
    if let Some(raw) = read_layer(&binding.root.join("config.toml"), Layer::User)? {
        let doc = raw
            .parse::<toml_edit::DocumentMut>()
            .map_err(|_| failure(Reason::SettingsMalformed, Layer::User))?;
        validate_codex_table(doc.as_table(), &binding.organization)?;
        if let Some(profile) = doc.get("profile") {
            let profile = profile
                .as_str()
                .ok_or_else(|| failure(Reason::SettingsMalformed, Layer::User))?;
            let table = doc
                .get("profiles")
                .and_then(|profiles| profiles.get(profile))
                .and_then(toml_edit::Item::as_table)
                .ok_or_else(|| failure(Reason::ConfigUnsupported, Layer::User))?;
            validate_codex_table(table, &binding.organization)?;
        }
        if doc
            .get("model_providers")
            .and_then(|providers| providers.get("openai"))
            .is_some()
        {
            return Err(failure(Reason::CodexProviderNotOpenai, Layer::User));
        }
    }
    Ok(())
}

fn validate_codex_table(table: &toml_edit::Table, organization: &str) -> Result<(), Block> {
    let fail = |reason| failure(reason, Layer::User);
    if table
        .get("model_provider")
        .is_some_and(|value| value.as_str() != Some("openai"))
    {
        return Err(fail(Reason::CodexProviderNotOpenai));
    }
    for key in [
        "openai_base_url",
        "chatgpt_base_url",
        "env_key",
        "experimental_bearer_token",
        "api_key",
    ] {
        if table.contains_key(key) {
            return Err(fail(Reason::SettingsEnvOverride));
        }
    }
    if table
        .get("forced_login_method")
        .is_some_and(|value| value.as_str() != Some("chatgpt"))
        || table
            .get("preferred_auth_method")
            .is_some_and(|value| value.as_str() != Some("chatgpt"))
    {
        return Err(fail(Reason::CodexApiKeyLogin));
    }
    if table
        .get("cli_auth_credentials_store")
        .is_some_and(|value| value.as_str() != Some("file"))
    {
        return Err(fail(Reason::ConfigUnsupported));
    }
    if let Some(workspace) = table.get("forced_chatgpt_workspace_id") {
        if workspace
            .as_str()
            .and_then(|workspace| {
                ottto_core::billing_identity_hash("openai", "workspace", workspace)
            })
            .as_deref()
            != Some(organization)
        {
            return Err(fail(Reason::ForcedOrgMismatch));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn claude_project_routes_and_selectors_fail_closed() {
        for (value, reason) in [
            (
                json!({"env":{"CLAUDE_CODE_USE_BEDROCK":"1"}}),
                Reason::CloudProviderRoute,
            ),
            (
                json!({"apiKeyHelper":"do not execute"}),
                Reason::ApiKeyRoute,
            ),
            (
                json!({"env":{"ANTHROPIC_BASE_URL":"https://example.invalid"}}),
                Reason::SettingsEnvOverride,
            ),
            (
                json!({"env":{"CLAUDE_CONFIG_DIR":"/other"}}),
                Reason::SettingsEnvOverride,
            ),
            (
                json!({"forceLoginMethod":"console"}),
                Reason::ForcedLoginMethod,
            ),
            (
                json!({"forceLoginOrgUUID":"other"}),
                Reason::ForcedOrgMismatch,
            ),
            (json!({"env":[]}), Reason::SettingsMalformed),
        ] {
            let error = validate_claude_layer(&value, Layer::ProjectLocal, "").unwrap_err();
            assert_eq!(error.reason, reason);
            assert_eq!(error.setting_layer, Some(Layer::ProjectLocal));
        }
        assert!(validate_claude_layer(&json!({}), Layer::User, "").is_ok());
    }
    #[test]
    fn codex_routes_and_workspace_are_checked() {
        for text in [
            "model_provider='custom'",
            "openai_base_url='https://example.invalid'",
            "forced_login_method='api'",
            "cli_auth_credentials_store='keyring'",
            "forced_chatgpt_workspace_id='foreign'",
        ] {
            let doc = text.parse::<toml_edit::DocumentMut>().unwrap();
            assert!(validate_codex_table(doc.as_table(), "").is_err(), "{text}");
        }
        let doc = "model_provider='openai'\nforced_login_method='chatgpt'"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        assert!(validate_codex_table(doc.as_table(), "").is_ok());
    }
}
