// Included in mcp_inventory::tests: plugin-declared servers, synthetic inputs only.
fn write_json(path: &Path, value: Value) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    fs::write(path, value.to_string()).expect("write json");
}

#[test]
fn claude_plugin_servers_need_install_and_enablement() {
    let home = test_home("claude-plugins");
    let cache = home.join(".claude").join("plugins").join("cache").join("m");
    for plugin in ["ask", "off", "cached"] {
        write_json(
            &cache.join(plugin).join(".mcp.json"),
            json!({"mcpServers": {plugin: {"command": "${CLAUDE_PLUGIN_ROOT}/bin/server"}}}),
        );
    }
    let install = |plugin: &str| json!([{"installPath": cache.join(plugin)}]);
    write_json(
        &home
            .join(".claude")
            .join("plugins")
            .join("installed_plugins.json"),
        json!({"plugins": {"ask@m": install("ask"), "off@m": install("off")}}),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"enabledPlugins": {"ask@m": true, "off@m": false, "cached@m": true}}),
    );

    let servers = discover_claude_code(&home);

    assert_eq!(
        servers.len(),
        1,
        "disabled and cache-only plugins add nothing"
    );
    assert_eq!(servers[0].name, "plugin_ask_ask");
    let root = cache.join("ask");
    assert_eq!(servers[0].config_dir.as_deref(), Some(root.as_path()));
    assert!(matches!(
        &servers[0].transport,
        Transport::Stdio { command, .. } if Path::new(command) == root.join("bin").join("server")
    ));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn codex_plugin_servers_come_from_the_manifest_declaration() {
    let home = test_home("codex-plugins");
    let codex = home.join(".codex");
    let cache = codex.join("plugins").join("cache").join("m");
    let declared = cache.join("tools").join("1.0");
    write_json(
        &declared.join(".codex-plugin").join("plugin.json"),
        json!({"mcpServers": "./.mcp.json"}),
    );
    write_json(
        &declared.join(".mcp.json"),
        json!({"mcpServers": {
            "tools": {"command": "node", "cwd": "srv"},
            "shared": {"command": "plugin-copy"},
        }}),
    );
    // [regress] a root .mcp.json the manifest does not name declares nothing.
    let undeclared = cache.join("chat").join("1.0");
    write_json(
        &undeclared.join(".codex-plugin").join("plugin.json"),
        json!({}),
    );
    write_json(
        &undeclared.join(".mcp.json"),
        json!({"mcpServers": {"chat": {"command": "chat"}}}),
    );
    fs::write(
        codex.join("config.toml"),
        r#"
[mcp_servers.shared]
command = "explicit"

[plugins."tools@m"]
enabled = true

[plugins."chat@m"]
enabled = true
"#,
    )
    .expect("write config.toml");

    let servers: BTreeMap<String, ConfiguredServer> = discover_codex(&home)
        .into_iter()
        .map(|server| (server.name.clone(), server))
        .collect();

    assert_eq!(
        servers.keys().map(String::as_str).collect::<Vec<_>>(),
        ["shared", "tools"]
    );
    assert!(matches!(
        &servers["shared"].transport,
        Transport::Stdio { command, .. } if command == "explicit"
    ));
    let root = declared.canonicalize().expect("canonical root");
    assert_eq!(servers["tools"].config_dir.as_deref(), Some(root.as_path()));
    let _ = fs::remove_dir_all(&home);
}
