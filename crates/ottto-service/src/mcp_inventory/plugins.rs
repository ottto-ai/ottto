//! Installed plugin MCP declarations. Discard transport/credential fields while
//! deserializing: these rows report names/state and must never launch a server.

use super::{ConfiguredServer, Transport};
use ottto_core::{FileClaudeConfigSlotSettingsStore, CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME};
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(untagged)]
enum Declaration {
    Servers(BTreeMap<String, IgnoredAny>),
    File(String),
    Files(Vec<String>),
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "mcpServers")]
    servers: Option<Declaration>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ServerFile {
    Wrapped {
        #[serde(rename = "mcpServers")]
        servers: BTreeMap<String, IgnoredAny>,
    },
    Bare(BTreeMap<String, IgnoredAny>),
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn server_names(path: &Path, names: &mut BTreeSet<String>) {
    let servers = match read::<ServerFile>(path) {
        Some(ServerFile::Wrapped { servers }) => servers,
        Some(ServerFile::Bare(servers)) if !servers.contains_key("mcpServers") => servers,
        _ => return,
    };
    names.extend(servers.into_keys());
}

fn declared_names(root: &Path, manifest: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    server_names(&root.join(".mcp.json"), &mut names);
    match read::<Manifest>(manifest).and_then(|m| m.servers) {
        Some(Declaration::Servers(servers)) => names.extend(servers.into_keys()),
        Some(declaration) => {
            let paths = match declaration {
                Declaration::File(path) => vec![path],
                Declaration::Files(paths) => paths,
                Declaration::Servers(_) => unreachable!(),
            };
            for path in paths {
                // Manifest references must remain inside the installed plugin,
                // including after symlink resolution. Never read arbitrary files.
                if let (Ok(root), Ok(path)) = (root.canonicalize(), root.join(path).canonicalize())
                {
                    if path.starts_with(root) {
                        server_names(&path, &mut names);
                    }
                }
            }
        }
        None => {}
    }
    names
}

fn server(name: String, enabled: bool) -> ConfiguredServer {
    ConfiguredServer {
        name,
        transport: Transport::Plugin,
        disabled: !enabled,
        always_load: false,
        config_dir: None,
    }
}

#[derive(Deserialize, Default)]
struct ClaudeSettings {
    #[serde(default, rename = "enabledPlugins")]
    enabled: BTreeMap<String, bool>,
}

#[derive(Deserialize)]
struct InstalledPlugin {
    #[serde(rename = "installPath")]
    path: PathBuf,
}

#[derive(Deserialize, Default)]
struct InstalledPlugins {
    #[serde(default)]
    plugins: BTreeMap<String, Vec<InstalledPlugin>>,
}

pub(super) fn discover_claude(home: &Path) -> Vec<ConfiguredServer> {
    let mut dirs = vec![home.join(".claude")];
    // Use the same registration decoder as transcript discovery, not a glob
    // of managed folders (which also contain unregistered/reusable roots).
    // Keep synthetic-home discovery isolated from the operator's real slots.
    let support = if std::env::var_os("HOME").as_deref().map(Path::new) == Some(home) {
        ottto_core::default_support_dir()
    } else {
        home.join("Library/Application Support/Ottto")
    };
    let store =
        FileClaudeConfigSlotSettingsStore::new(support.join(CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME));
    // A failed registry read grants no account roots; user config remains.
    dirs.extend(store.registered_config_dirs().unwrap_or_default());
    dirs.sort();
    dirs.dedup();
    let mut servers: BTreeMap<String, ConfiguredServer> = BTreeMap::new();
    for dir in dirs {
        let installed = read::<InstalledPlugins>(&dir.join("plugins/installed_plugins.json"))
            .unwrap_or_default();
        let mut enabled = BTreeMap::new();
        for settings in ["settings.json", "settings.local.json"] {
            enabled.extend(
                read::<ClaudeSettings>(&dir.join(settings))
                    .unwrap_or_default()
                    .enabled,
            );
        }
        for (id, entries) in installed.plugins {
            let Some(&is_enabled) = enabled.get(&id) else {
                continue;
            };
            let Some((plugin, _marketplace)) = id.split_once('@') else {
                continue;
            };
            for entry in entries {
                let mut names =
                    declared_names(&entry.path, &entry.path.join(".claude-plugin/plugin.json"));
                names.extend(declared_names(&entry.path, &entry.path.join("plugin.json")));
                for name in names {
                    let name = format!("plugin_{plugin}_{name}");
                    // The inventory is per app/Mac, not per account slot. An
                    // enabled installation in any slot keeps the row active.
                    servers
                        .entry(name.clone())
                        .and_modify(|s| s.disabled &= !is_enabled)
                        .or_insert_with(|| server(name, is_enabled));
                }
            }
        }
    }
    servers.into_values().collect()
}

fn child_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<_> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn numeric_version(path: &Path) -> Option<Vec<u64>> {
    path.file_name()?
        .to_str()?
        .split('.')
        .map(|part| part.parse().ok())
        .collect()
}

/// No active-version registry is available in the inspected Codex config. A
/// single cached version is unambiguous. For explicitly enabled plugins only,
/// fall back to the highest numeric dotted version, or newest directory mtime
/// for opaque version hashes (stable path tie break). Disabled multi-version
/// caches are ambiguous and contribute no row.
fn installed_codex_version(root: &Path, enabled: bool) -> Option<PathBuf> {
    let mut versions = child_dirs(root);
    versions.retain(|path| path.join(".codex-plugin/plugin.json").is_file());
    if versions.len() > 1 && !enabled {
        return None;
    }
    let all_numeric = versions.iter().all(|path| numeric_version(path).is_some());
    versions.sort_by(|a, b| {
        if all_numeric {
            numeric_version(a).cmp(&numeric_version(b))
        } else {
            a.metadata()
                .and_then(|m| m.modified())
                .ok()
                .cmp(&b.metadata().and_then(|m| m.modified()).ok())
        }
        .then_with(|| a.cmp(b))
    });
    versions.pop()
}

pub(super) fn discover_codex(
    codex_dir: &Path,
    document: &toml_edit::DocumentMut,
) -> Vec<ConfiguredServer> {
    let mut servers: BTreeMap<String, ConfiguredServer> = BTreeMap::new();
    for (id, plugin) in document
        .get("plugins")
        .and_then(|item| item.as_table())
        .into_iter()
        .flat_map(|table| table.iter())
    {
        let Some(enabled) = plugin.get("enabled").and_then(toml_edit::Item::as_bool) else {
            continue;
        };
        let Some((name, marketplace)) = id.split_once('@') else {
            continue;
        };
        // Config ids are cache path components, never relative/absolute paths.
        if [name, marketplace].iter().any(|part| {
            part.is_empty() || part.contains(['/', '\\']) || *part == "." || *part == ".."
        }) {
            continue;
        }
        let cache = codex_dir.join("plugins/cache").join(marketplace).join(name);
        let Some(root) = installed_codex_version(&cache, enabled) else {
            continue;
        };
        for name in declared_names(&root, &root.join(".codex-plugin/plugin.json")) {
            servers
                .entry(name.clone())
                .and_modify(|s| s.disabled &= !enabled)
                .or_insert_with(|| server(name, enabled));
        }
    }
    servers.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            Self(std::env::temp_dir().join(format!(
                "ottto-plugin-mcp-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }

        fn write(&self, path: &Path, value: serde_json::Value) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        }

        fn claude(&self, config: &Path, enabled: Option<bool>, installed: bool) {
            let root = config.join("plugins/cache/test-market/ottto-ask/1.0.0");
            self.write(
                &root.join(".mcp.json"),
                json!({"mcpServers": {"ottto-ask": {"command": "never-launch-plugin"}}}),
            );
            if installed {
                self.write(
                    &config.join("plugins/installed_plugins.json"),
                    json!({"plugins": {"ottto-ask@test-market": [{"installPath": root}]}}),
                );
            }
            if let Some(enabled) = enabled {
                self.write(
                    &config.join("settings.json"),
                    json!({"enabledPlugins": {"ottto-ask@test-market": enabled}}),
                );
            }
        }

        fn codex_version(&self, version: &str, name: &str) -> PathBuf {
            let root = self
                .0
                .join(".codex/plugins/cache/openai-bundled/unified-computer-use")
                .join(version);
            self.write(
                &root.join(".codex-plugin/plugin.json"),
                json!({"mcpServers": ".mcp.json"}),
            );
            self.write(
                &root.join(".mcp.json"),
                json!({"mcpServers": {name: {"command": "never-launch-plugin"}}}),
            );
            root
        }

        fn codex(&self, enabled: Option<bool>) -> Vec<ConfiguredServer> {
            let text = enabled
                .map(|enabled| {
                    format!(
                        "[plugins.\"unified-computer-use@openai-bundled\"]\nenabled = {enabled}\n"
                    )
                })
                .unwrap_or_default();
            // Use the public discovery entry point: plugin-only configs must
            // work even without any [mcp_servers] block.
            let path = self.0.join(".codex/config.toml");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
            super::super::discover_codex(&self.0)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn assert_row(servers: &[ConfiguredServer], name: &str, disabled: bool) {
        assert_eq!(servers.len(), 1);
        let server = &servers[0];
        assert_eq!(server.name, name);
        assert_eq!(server.disabled, disabled);
        assert_eq!(server.transport, Transport::Plugin);
        let (wire, deferred) = super::super::harvest_server(
            server,
            &super::super::SpawnEnv {
                path: None,
                provider: BTreeMap::new(),
            },
        );
        assert!(!deferred);
        assert_eq!(wire.disabled, disabled);
        assert_eq!(wire.server, name);
        assert_eq!(wire.transport, None);
        assert!(!wire.reachable);
        assert!(wire.tools.is_empty());
    }

    #[test]
    fn claude_installed_enabled_uses_observed_runtime_name() {
        let f = Fixture::new();
        f.claude(&f.0.join(".claude"), Some(true), true);
        assert_row(
            &super::super::discover_claude_code(&f.0),
            "plugin_ottto-ask_ottto-ask",
            false,
        );
    }

    #[test]
    fn claude_installed_disabled_preserves_wire_state() {
        let f = Fixture::new();
        let config = f.0.join(".claude");
        f.claude(&config, Some(true), true);
        f.write(
            &config.join("settings.local.json"),
            json!({
                "enabledPlugins": {"ottto-ask@test-market": false}
            }),
        );
        assert_row(
            &super::super::discover_claude_code(&f.0),
            "plugin_ottto-ask_ottto-ask",
            true,
        );
    }

    #[test]
    fn claude_cache_only_and_missing_enablement_are_absent() {
        let f = Fixture::new();
        f.claude(&f.0.join(".claude"), Some(true), false);
        assert!(super::super::discover_claude_code(&f.0).is_empty());
        f.claude(&f.0.join(".claude"), None, true);
        std::fs::remove_file(f.0.join(".claude/settings.json")).unwrap();
        assert!(super::super::discover_claude_code(&f.0).is_empty());
    }

    #[test]
    fn claude_only_registered_account_slots_can_enable_aggregated_row() {
        let f = Fixture::new();
        f.claude(&f.0.join(".claude"), Some(false), true);
        let stale =
            f.0.join("Library/Application Support/Ottto/claude-accounts/stale");
        f.claude(&stale, Some(true), true);
        assert_row(&discover_claude(&f.0), "plugin_ottto-ask_ottto-ask", true);
        let slot = f.0.join("customer-owned-login");
        let store = FileClaudeConfigSlotSettingsStore::new(
            f.0.join("Library/Application Support/Ottto")
                .join(CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME),
        );
        store
            .register_path(1, slot.to_string_lossy().into_owned())
            .unwrap();
        f.claude(&slot, Some(true), false);
        assert_row(&discover_claude(&f.0), "plugin_ottto-ask_ottto-ask", true);
        f.claude(&slot, Some(true), true);
        assert_row(&discover_claude(&f.0), "plugin_ottto-ask_ottto-ask", false);
    }

    #[test]
    fn claude_unreadable_registry_cannot_reenable_disabled_user_plugin() {
        let f = Fixture::new();
        f.claude(&f.0.join(".claude"), Some(false), true);
        let slot =
            f.0.join("Library/Application Support/Ottto/claude-accounts/stale");
        f.claude(&slot, Some(true), true);
        let registry =
            f.0.join("Library/Application Support/Ottto")
                .join(CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME);
        std::fs::write(registry, "not a registry").unwrap();
        assert_row(&discover_claude(&f.0), "plugin_ottto-ask_ottto-ask", true);
    }

    #[test]
    fn codex_enabled_uses_declared_name_from_newest_numeric_version() {
        let f = Fixture::new();
        f.codex_version("1.9.0", "old_name");
        f.codex_version("1.10.0", "cua_repl");
        assert_row(&f.codex(Some(true)), "cua_repl", false);
    }

    #[test]
    fn codex_disabled_preserves_state_without_guessing_multiple_versions() {
        let f = Fixture::new();
        f.codex_version("1.0.0", "cua_repl");
        assert_row(&f.codex(Some(false)), "cua_repl", true);
        f.codex_version("2.0.0", "ambiguous");
        assert!(f.codex(Some(false)).is_empty());
    }

    #[test]
    fn codex_absent_config_or_install_never_uses_cache_only() {
        let f = Fixture::new();
        assert!(f.codex(Some(true)).is_empty());
        f.codex_version("1.0.0", "cua_repl");
        assert!(f.codex(None).is_empty());
    }

    #[test]
    fn manifest_inline_and_relative_file_declarations_discard_launch_values() {
        let f = Fixture::new();
        let root = f.codex_version("1.0.0", "cua_repl");
        f.write(
            &root.join(".codex-plugin/plugin.json"),
            json!({
                "mcpServers": {"inline": {"env": {"PRIVATE": "fixture-only"}}}
            }),
        );
        assert_eq!(
            f.codex(Some(true))
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["cua_repl", "inline"]
        );
        f.write(
            &root.join("extra.json"),
            json!({"extra": {"command": "never-launch"}}),
        );
        f.write(
            &root.join(".codex-plugin/plugin.json"),
            json!({"mcpServers": ["extra.json", "../../../../outside.json"]}),
        );
        assert_eq!(
            f.codex(Some(true))
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["cua_repl", "extra"]
        );
    }

    #[test]
    fn explicit_mcp_config_wins_over_plugin_declarations() {
        let f = Fixture::new();
        f.codex_version("1.0.0", "cua_repl");
        let config = f.0.join(".codex/config.toml");
        std::fs::write(&config, "[plugins.\"unified-computer-use@openai-bundled\"]\nenabled = true\n[mcp_servers.cua_repl]\nurl = \"https://example.test\"\nenabled = false\n").unwrap();
        let servers = super::super::discover_codex(&f.0);
        assert_eq!(servers.len(), 1);
        assert!(servers[0].disabled);
        assert!(matches!(servers[0].transport, Transport::Http { .. }));
    }
}
