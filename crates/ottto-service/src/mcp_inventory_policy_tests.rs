// Included in mcp_inventory::tests: Claude Code's managed and deny policy vetoes
// servers before they start. Synthetic homes and a synthetic managed directory.

/// A home whose `~/.claude.json` declares the user server `user-srv`, which
/// creates `<home>/started` when it runs. Returns `(home, managed_dir, marker)`;
/// the managed directory starts empty.
fn policy_home(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let home = test_home(name);
    let marker = home.join("started");
    write_json(
        &home.join(".claude.json"),
        json!({"mcpServers": {"user-srv": {
            "command": "/usr/bin/touch",
            "args": [marker.to_string_lossy()],
        }}}),
    );
    let managed = home.join("managed");
    fs::create_dir_all(&managed).expect("managed dir");
    (home, managed, marker)
}

fn policy_server(home: &Path, managed: &Path, name: &str) -> ConfiguredServer {
    discover_servers_in(home, SnapshotSource::ClaudeCode, Some(managed))
        .into_iter()
        .find(|server| server.name == name)
        .expect("the server is still reported")
}

/// Harvest `user-srv` and return whether its process ran.
fn policy_started(home: &Path, managed: &Path, marker: &Path) -> bool {
    let server = policy_server(home, managed, "user-srv");
    let (input, deferred) = harvest_server(&server, &test_spawn_env());
    assert!(!deferred);
    assert_eq!(input.disabled, server.disabled);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !server.disabled && !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    marker.exists()
}

fn user_srv_command(marker: &Path) -> Value {
    json!(["/usr/bin/touch", marker.to_string_lossy()])
}

#[test]
fn without_policy_a_user_server_still_starts() {
    let (home, managed, marker) = policy_home("policy-none");
    assert!(!policy_server(&home, &managed, "user-srv").disabled);
    assert!(policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn managed_deny_by_name_vetoes_a_user_server() {
    let (home, managed, marker) = policy_home("policy-deny-name");
    write_json(
        &managed.join("managed-settings.json"),
        json!({"deniedMcpServers": [{"serverName": "user-srv"}]}),
    );
    assert!(policy_server(&home, &managed, "user-srv").disabled);
    assert!(!policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn managed_deny_by_command_vetoes_and_needs_the_exact_command() {
    let (home, managed, marker) = policy_home("policy-deny-command");
    write_json(
        &managed.join("managed-settings.json"),
        json!({"deniedMcpServers": [{"serverCommand": ["/usr/bin/touch"]}]}),
    );
    assert!(
        !policy_server(&home, &managed, "user-srv").disabled,
        "a command entry matches every argument, not a prefix"
    );
    write_json(
        &managed.join("managed-settings.d").join("10-mcp.json"),
        json!({"deniedMcpServers": [{"serverCommand": user_srv_command(&marker)}]}),
    );
    assert!(policy_server(&home, &managed, "user-srv").disabled);
    assert!(!policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn managed_allowlist_vetoes_unlisted_servers_and_loads_listed_ones() {
    let (home, managed, marker) = policy_home("policy-allow");
    write_json(
        &managed.join("managed-settings.json"),
        json!({"allowedMcpServers": [{"serverCommand": ["/usr/bin/other"]}]}),
    );
    assert!(policy_server(&home, &managed, "user-srv").disabled);
    assert!(!policy_started(&home, &managed, &marker));

    // A name entry does not admit a stdio server once command entries exist.
    write_json(
        &managed.join("managed-settings.json"),
        json!({"allowedMcpServers": [
            {"serverName": "user-srv"},
            {"serverCommand": ["/usr/bin/other"]},
        ]}),
    );
    assert!(policy_server(&home, &managed, "user-srv").disabled);

    write_json(
        &managed.join("managed-settings.json"),
        json!({"allowedMcpServers": [{"serverCommand": user_srv_command(&marker)}]}),
    );
    assert!(!policy_server(&home, &managed, "user-srv").disabled);
    assert!(policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn allowlist_edges_follow_the_documented_rules() {
    let (home, managed, _marker) = policy_home("policy-allow-edges");
    let settings = managed.join("managed-settings.json");
    let disabled = || policy_server(&home, &managed, "user-srv").disabled;

    // An empty list blocks every server; a value that is not a list is
    // enforced as an empty list.
    write_json(&settings, json!({"allowedMcpServers": []}));
    assert!(disabled());
    write_json(&settings, json!({"allowedMcpServers": "user-srv"}));
    assert!(disabled());

    // A name entry admits the server when the list has no command entries.
    write_json(
        &settings,
        json!({"allowedMcpServers": [{"serverName": "user-srv"}]}),
    );
    assert!(!disabled());

    // Without the lock a user allowlist merges in; with it only the managed
    // list counts.
    write_json(
        &settings,
        json!({"allowedMcpServers": [{"serverName": "other"}]}),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"allowedMcpServers": [{"serverName": "user-srv"}]}),
    );
    assert!(!disabled());
    write_json(
        &settings,
        json!({
            "allowManagedMcpServersOnly": true,
            "allowedMcpServers": [{"serverName": "other"}],
        }),
    );
    assert!(disabled());

    // A user allowlist alone also restricts.
    fs::remove_file(&settings).expect("remove managed settings");
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"allowedMcpServers": [{"serverName": "other"}]}),
    );
    assert!(disabled());
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn managed_mcp_json_vetoes_every_discovered_server() {
    let (home, managed, marker) = policy_home("policy-exclusive");
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.test/mcp"}}}),
    );
    write_json(&managed.join("managed-mcp.json"), json!({"mcpServers": {}}));

    let servers = discover_servers_in(&home, SnapshotSource::ClaudeCode, Some(&managed));
    assert_eq!(servers.len(), 2);
    assert!(servers.iter().all(|server| server.disabled));
    assert!(!policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn user_deny_list_vetoes_a_server() {
    let (home, managed, marker) = policy_home("policy-user-deny");
    write_json(
        &home.join(".claude").join("settings.local.json"),
        json!({"deniedMcpServers": [{"serverName": "user-srv"}]}),
    );
    assert!(policy_server(&home, &managed, "user-srv").disabled);
    assert!(!policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn managed_disabled_names_veto_a_server() {
    let (home, managed, _marker) = policy_home("policy-disabled-names");
    write_json(
        &managed.join("managed-settings.json"),
        json!({"disabledMcpjsonServers": ["user-srv"]}),
    );
    assert!(policy_server(&home, &managed, "user-srv").disabled);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn malformed_managed_files_grant_and_veto_nothing() {
    let (home, managed, marker) = policy_home("policy-malformed");
    write_json(
        &home.join(".claude.json"),
        json!({"mcpServers": {
            "user-srv": {"command": "/usr/bin/touch", "args": [marker.to_string_lossy()]},
            "off-srv": {"command": "/usr/bin/true"},
        }}),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"disabledMcpjsonServers": ["off-srv"]}),
    );
    fs::write(managed.join("managed-settings.json"), "{not json").expect("write");
    fs::write(managed.join("managed-mcp.json"), "{\"mcpServers\":").expect("write");
    fs::create_dir_all(managed.join("managed-settings.d")).expect("drop-in dir");
    fs::write(managed.join("managed-settings.d").join("10.json"), "[1, 2]").expect("write");
    // Not a JSON object, a hidden file and a non-JSON name are all left out.
    write_json(
        &managed.join("managed-settings.d").join(".hidden.json"),
        json!({"deniedMcpServers": [{"serverName": "user-srv"}]}),
    );
    write_json(
        &managed.join("managed-settings.d").join("deny.txt"),
        json!({"deniedMcpServers": [{"serverName": "user-srv"}]}),
    );
    // Invalid entries are stripped rather than denying anything.
    write_json(
        &managed.join("managed-settings.d").join("20.json"),
        json!({"deniedMcpServers": [
            {"serverName": "user-srv", "serverUrl": "https://x.test"},
            {"serverCommand": []},
            {"other": "user-srv"},
        ]}),
    );

    assert!(!policy_server(&home, &managed, "user-srv").disabled);
    assert!(policy_server(&home, &managed, "off-srv").disabled);
    assert!(policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn deny_wins_over_every_approval() {
    let (home, managed, marker) = policy_home("policy-deny-wins");
    let project = home.join("proj");
    write_json(
        &project.join(".mcp.json"),
        json!({"mcpServers": {"project-srv": {"command": "/usr/bin/true"}}}),
    );
    write_json(
        &home.join(".claude.json"),
        json!({
            "mcpServers": {"user-srv": {
                "command": "/usr/bin/touch",
                "args": [marker.to_string_lossy()],
            }},
            "projects": {project.to_string_lossy(): {
                "hasTrustDialogAccepted": true,
                "enabledMcpjsonServers": ["project-srv"],
            }},
        }),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({
            "enableAllProjectMcpServers": true,
            "enabledMcpjsonServers": ["project-srv"],
            "allowedMcpServers": [{"serverName": "user-srv"}, {"serverName": "project-srv"}],
        }),
    );
    write_json(
        &managed.join("managed-settings.json"),
        json!({
            "allowManagedMcpServersOnly": true,
            "allowedMcpServers": [
                {"serverCommand": user_srv_command(&marker)},
                {"serverCommand": ["/usr/bin/true"]},
            ],
            "enableAllProjectMcpServers": true,
            "enabledMcpjsonServers": ["project-srv"],
            "deniedMcpServers": [
                {"serverCommand": user_srv_command(&marker)},
                {"serverName": "project-srv"},
            ],
        }),
    );

    assert!(policy_server(&home, &managed, "user-srv").disabled);
    assert!(policy_server(&home, &managed, "project-srv").disabled);
    assert!(!policy_started(&home, &managed, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn deny_by_url_and_plugin_name_veto_remote_and_plugin_servers() {
    let (home, managed, _marker) = policy_home("policy-url-plugin");
    let root = home.join("plugin-root");
    write_json(
        &root.join(".mcp.json"),
        json!({"mcpServers": {"tool": {"command": "/usr/bin/true"}}}),
    );
    write_json(
        &home
            .join(".claude")
            .join("plugins")
            .join("installed_plugins.json"),
        json!({"plugins": {"kit@m": [{"installPath": root}]}}),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({
            "enabledPlugins": {"kit@m": true},
            "mcpServers": {
                "remote": {"type": "http", "url": "https://Staging.Example.test/api"},
                "remote-port": {"type": "sse", "url": "https://staging.example.test:8443/api"},
            },
        }),
    );
    write_json(
        &managed.join("managed-settings.json"),
        json!({"deniedMcpServers": [
            {"serverUrl": "https://staging.example.test/*"},
            {"serverName": "plugin:kit:tool"},
        ]}),
    );

    assert!(policy_server(&home, &managed, "remote").disabled);
    assert!(
        !policy_server(&home, &managed, "remote-port").disabled,
        "a host written out matches only the default port"
    );
    assert!(policy_server(&home, &managed, "plugin_kit_tool").disabled);
    assert!(!policy_server(&home, &managed, "user-srv").disabled);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn server_url_patterns_follow_the_documented_matching() {
    use super::managed_policy::url_matches;
    let cases = [
        (
            "https://mcp.example.com/*",
            "https://mcp.example.com/api",
            true,
        ),
        ("https://mcp.example.com/*", "https://mcp.example.com", true),
        (
            "https://mcp.example.com",
            "https://mcp.example.com/any/path",
            true,
        ),
        (
            "https://mcp.example.com/*",
            "https://mcp.example.com:8443/api",
            false,
        ),
        (
            "https://mcp.example.com:8443/*",
            "https://mcp.example.com:8443/api",
            true,
        ),
        (
            "https://mcp.example.com:*/*",
            "https://mcp.example.com:9000/api",
            true,
        ),
        (
            "https://*.example.com/*",
            "https://a.example.com:9000/x",
            true,
        ),
        ("https://*.example.com/*", "https://example.org/x", false),
        ("http://localhost:*/*", "http://localhost:3000/mcp", true),
        ("*://mcp.example.com/*", "http://mcp.example.com/x", true),
        (
            "*://mcp.example.com/*",
            "http://mcp.example.com:8080/x",
            false,
        ),
        (
            "https://Mcp.Example.com/*",
            "https://mcp.example.com./api",
            true,
        ),
        (
            "https://mcp.example.com/API",
            "https://mcp.example.com/api",
            false,
        ),
        ("https://mcp.example.com/*", "not a url", false),
    ];
    for (pattern, url, expected) in cases {
        assert_eq!(url_matches(pattern, url), expected, "{pattern} vs {url}");
    }
}
