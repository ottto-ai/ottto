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

/// Harvest `server` and return whether its process ran (it creates `marker`).
/// Shared by the policy and project-approval marker tests.
fn harvest_started(server: &ConfiguredServer, marker: &Path) -> bool {
    let (input, deferred) = harvest_server(server, &test_spawn_env());
    assert!(!deferred);
    assert_eq!(input.disabled, server.disabled);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !server.disabled && !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    marker.exists()
}

/// Harvest `user-srv` and return whether its process ran.
fn policy_started(home: &Path, managed: &Path, marker: &Path) -> bool {
    harvest_started(&policy_server(home, managed, "user-srv"), marker)
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
fn deny_rows_from_every_source_veto_a_server() {
    let (home, managed, marker) = policy_home("policy-deny-rows");
    let name = json!({"deniedMcpServers": [{"serverName": "user-srv"}]});
    let command = json!({"deniedMcpServers": [{"serverCommand": user_srv_command(&marker)}]});
    let rows = [
        (managed.join("managed-settings.json"), name.clone(), true),
        (home.join(".claude").join("settings.local.json"), name, true),
        (
            managed.join("managed-settings.d").join("10-mcp.json"),
            command,
            true,
        ),
        // A command entry matches every argument, not a prefix.
        (
            managed.join("managed-settings.json"),
            json!({"deniedMcpServers": [{"serverCommand": ["/usr/bin/touch"]}]}),
            false,
        ),
    ];
    for (path, settings, blocked) in rows {
        write_json(&path, settings);
        let server = policy_server(&home, &managed, "user-srv");
        assert_eq!(server.disabled, blocked, "{}", path.display());
        if blocked {
            assert!(!harvest_started(&server, &marker));
        }
        fs::remove_file(&path).expect("remove policy file");
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn allowlist_rows_follow_the_documented_rules() {
    let (home, managed, marker) = policy_home("policy-allow");
    let allow = |entries: Value| json!({"allowedMcpServers": entries});
    let name = |name: &str| json!([{"serverName": name}]);
    let other_command = json!({"serverCommand": ["/usr/bin/other"]});
    // (managed settings, user settings, blocked)
    let rows = [
        (Some(allow(json!([other_command.clone()]))), None, true),
        // A name entry does not admit a stdio server once command entries exist.
        (
            Some(allow(json!([{"serverName": "user-srv"}, other_command]))),
            None,
            true,
        ),
        // An empty list blocks everything; a value that is not a list is empty.
        (Some(allow(json!([]))), None, true),
        (Some(allow(json!("user-srv"))), None, true),
        (Some(allow(name("user-srv"))), None, false),
        // Without the lock a user list merges in; with it only managed counts.
        (
            Some(allow(name("other"))),
            Some(allow(name("user-srv"))),
            false,
        ),
        (
            Some(json!({"allowManagedMcpServersOnly": true, "allowedMcpServers": name("other")})),
            Some(allow(name("user-srv"))),
            true,
        ),
        (None, Some(allow(name("other"))), true),
        (
            Some(allow(json!([{"serverCommand": user_srv_command(&marker)}]))),
            None,
            false,
        ),
    ];
    let managed_file = managed.join("managed-settings.json");
    let user_file = home.join(".claude").join("settings.json");
    for (row, (managed_settings, user_settings, blocked)) in rows.into_iter().enumerate() {
        let _ = fs::remove_file(&marker);
        for (path, settings) in [
            (&managed_file, managed_settings),
            (&user_file, user_settings),
        ] {
            match settings {
                Some(settings) => write_json(path, settings),
                None => {
                    let _ = fs::remove_file(path);
                }
            }
        }
        let server = policy_server(&home, &managed, "user-srv");
        assert_eq!(server.disabled, blocked, "row {row}");
        assert_eq!(harvest_started(&server, &marker), !blocked, "row {row}");
    }
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
fn malformed_or_non_object_managed_settings_veto_every_server() {
    let (home, managed, marker) = policy_home("policy-malformed");
    let drop_in = managed.join("managed-settings.d").join("10.json");
    fs::create_dir_all(drop_in.parent().expect("parent")).expect("drop-in dir");
    for (path, text) in [
        (managed.join("managed-settings.json"), "{not json"),
        (managed.join("managed-settings.json"), "[1, 2]"),
        (drop_in, "\"text\""),
    ] {
        fs::write(&path, text).expect("write");
        assert!(policy_server(&home, &managed, "user-srv").disabled);
        assert!(!policy_started(&home, &managed, &marker));
        fs::remove_file(&path).expect("remove");
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn absent_unreadable_or_ignored_managed_input_grants_and_vetoes_nothing() {
    let (home, managed, marker) = policy_home("policy-skipped");
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
    // A path that cannot be read as a file, and an empty file (read as `{}`).
    fs::create_dir_all(managed.join("managed-settings.json")).expect("unreadable");
    let drop_ins = managed.join("managed-settings.d");
    fs::create_dir_all(&drop_ins).expect("drop-in dir");
    fs::write(drop_ins.join("05.json"), "").expect("write");
    // A managed-mcp.json that does not parse takes no control.
    fs::write(managed.join("managed-mcp.json"), "{\"mcpServers\":").expect("write");
    // Hidden files and non-JSON names are left out.
    let deny = json!({"deniedMcpServers": [{"serverName": "user-srv"}]});
    write_json(&drop_ins.join(".hidden.json"), deny.clone());
    write_json(&drop_ins.join("deny.txt"), deny);
    // Invalid entries are stripped rather than denying anything.
    write_json(
        &drop_ins.join("20.json"),
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
fn deny_by_url_vetoes_a_remote_server() {
    let (home, managed, _marker) = policy_home("policy-url");
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"mcpServers": {
            "remote": {"type": "http", "url": "https://Staging.Example.test/api"},
        }}),
    );
    write_json(
        &managed.join("managed-settings.json"),
        json!({"deniedMcpServers": [{"serverUrl": "https://staging.example.test/*"}]}),
    );
    assert!(policy_server(&home, &managed, "remote").disabled);
    assert!(!policy_server(&home, &managed, "user-srv").disabled);
    let _ = fs::remove_dir_all(&home);
}

/// The three servers of [`provenance_home`], each creating `<home>/<name>.started`.
const PROVENANCE_SERVERS: [&str; 3] = ["user-srv", "plugin_kit_tool", "project-srv"];

/// A home with a user server, the enabled plugin `kit` declaring `tool`, and an
/// approved server in a trusted project's `.mcp.json`. Returns
/// `(home, managed_dir, project_dir)`.
fn provenance_home(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let home = test_home(name);
    let touch = |server: &str| {
        let marker = home.join(format!("{server}.started"));
        json!({"command": "/usr/bin/touch", "args": [marker]})
    };
    let project = home.join("proj");
    let root = home.join("plugin-root");
    write_json(
        &home.join(".claude.json"),
        json!({
            "mcpServers": {"user-srv": touch("user-srv")},
            "projects": {project.to_string_lossy(): {
                "hasTrustDialogAccepted": true,
                "enabledMcpjsonServers": ["project-srv"],
            }},
        }),
    );
    write_json(
        &project.join(".mcp.json"),
        json!({"mcpServers": {"project-srv": touch("project-srv")}}),
    );
    write_json(
        &root.join(".mcp.json"),
        json!({"mcpServers": {"tool": touch("plugin_kit_tool")}}),
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
        json!({"enabledPlugins": {"kit@m": true}}),
    );
    let managed = home.join("managed");
    fs::create_dir_all(&managed).expect("managed dir");
    (home, managed, project)
}

/// Harvest each provenance server; `true` where it is vetoed: reported disabled
/// and its process never ran. A server that is not vetoed must start.
fn provenance_vetoes(home: &Path, managed: &Path, names: &[&str]) -> Vec<bool> {
    names
        .iter()
        .map(|name| {
            let marker = home.join(format!("{name}.started"));
            let _ = fs::remove_file(&marker);
            let server = policy_server(home, managed, name);
            let started = harvest_started(&server, &marker);
            assert_eq!(started, !server.disabled, "{name}");
            server.disabled
        })
        .collect()
}

#[test]
fn identity_and_scope_rows_veto_only_the_servers_they_name() {
    let (home, managed, project) = provenance_home("policy-provenance");
    let user_marker = home.join("user-srv.started");
    let settings = managed.join("managed-settings.json");
    let drop_in = managed.join("managed-settings.d").join("10.json");
    let user = home.join(".claude").join("settings.local.json");
    let project_local = project.join(".claude").join("settings.local.json");
    let deny = |entry: Value| json!({"deniedMcpServers": [entry]});
    let allow = |entries: Value| json!({"allowedMcpServers": entries});
    let names = |names: &[&str]| -> Value {
        names
            .iter()
            .map(|name| json!({"serverName": name}))
            .collect()
    };
    let unset = "OTTTO_POLICY_TEST_UNSET";
    let (cmd_var, fill_var) = ("OTTTO_POLICY_TEST_CMD", "OTTTO_POLICY_TEST_FILL");
    let by_var = |var: &str| json!([{"serverCommand": [format!("${{{var}}}"), &user_marker]}]);
    let defaulted = json!([format!("${{{unset}:-/usr/bin/touch}}"), &user_marker]);
    let lock = |on: bool| {
        let allowed = names(&["project-srv"]);
        json!({"allowManagedMcpServersOnly": on, "allowedMcpServers": allowed})
    };
    // (policy files to write, vetoed [user, plugin, project])
    let rows = vec![
        (vec![], [false, false, false]),
        // Names match the client identity, never the inventory row name.
        (
            vec![(&settings, deny(json!({"serverName": "plugin:kit:tool"})))],
            [false, true, false],
        ),
        (
            vec![(&settings, deny(json!({"serverName": "plugin_kit_tool"})))],
            [false, false, false],
        ),
        (
            vec![(
                &settings,
                allow(names(&["user-srv", "project-srv", "plugin_kit_tool"])),
            )],
            [false, true, false],
        ),
        // An allowlist whose names are all invalid is empty and blocks everything.
        (
            vec![(&settings, allow(names(&["plugin:kit:tool"])))],
            [true, true, true],
        ),
        // Plugin-only customization keeps plugin servers alone.
        (
            vec![(&settings, json!({"strictPluginOnlyCustomization": ["mcp"]}))],
            [true, false, true],
        ),
        (
            vec![(&settings, json!({"strictPluginOnlyCustomization": true}))],
            [true, false, true],
        ),
        (
            vec![(
                &settings,
                json!({"strictPluginOnlyCustomization": ["skills"]}),
            )],
            [false, false, false],
        ),
        // `disabledMcpjsonServers` rejects project `.mcp.json` servers only.
        (
            vec![(
                &settings,
                json!({"disabledMcpjsonServers": ["project-srv", "user-srv"]}),
            )],
            [false, false, true],
        ),
        // The declaring project's own deny list applies to its servers only.
        (
            vec![(
                &project_local,
                deny(
                    json!({"serverCommand": ["/usr/bin/touch", home.join("project-srv.started")]}),
                ),
            )],
            [false, false, true],
        ),
        (
            vec![(&project_local, deny(json!({"serverName": "user-srv"})))],
            [false, false, false],
        ),
        // Command entries expand variables before matching; an allow entry left
        // with an unset variable matches nothing.
        (
            vec![(&user, deny(json!({"serverCommand": defaulted.clone()})))],
            [true, false, false],
        ),
        (
            vec![(&settings, allow(json!([{"serverCommand": defaulted}])))],
            [false, true, true],
        ),
        (
            vec![(
                &settings,
                allow(json!([{"serverCommand": [format!("${{{unset}}}"), &user_marker]}])),
            )],
            [true, true, true],
        ),
        // Entries expand from the managed `env` first; a deny entry also fills
        // from the user settings `env`.
        (
            vec![(
                &settings,
                json!({"env": {cmd_var: "/usr/bin/touch"}, "deniedMcpServers": by_var(cmd_var)}),
            )],
            [true, false, false],
        ),
        (
            vec![
                (&settings, json!({"deniedMcpServers": by_var(fill_var)})),
                (&user, json!({"env": {fill_var: "/usr/bin/touch"}})),
            ],
            [true, false, false],
        ),
        (
            vec![(
                &settings,
                json!({"env": {cmd_var: "/usr/bin/touch"}, "allowedMcpServers": by_var(cmd_var)}),
            )],
            [false, true, true],
        ),
        // In the managed drop-ins a later single value wins.
        (
            vec![
                (&settings, lock(true)),
                (&drop_in, json!({"allowManagedMcpServersOnly": false})),
                (&user, allow(names(&["user-srv"]))),
            ],
            [false, true, false],
        ),
        (
            vec![
                (&settings, lock(false)),
                (&drop_in, json!({"allowManagedMcpServersOnly": true})),
                (&user, allow(names(&["user-srv"]))),
            ],
            [true, true, false],
        ),
    ];
    for (row, (files, expected)) in rows.into_iter().enumerate() {
        for path in [&settings, &drop_in, &user, &project_local] {
            let _ = fs::remove_file(path);
        }
        for (path, policy) in files {
            write_json(path, policy);
        }
        let vetoes = provenance_vetoes(&home, &managed, &PROVENANCE_SERVERS);
        assert_eq!(vetoes, expected, "row {row}");
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn local_scope_servers_keep_their_project_and_identity() {
    let home = test_home("policy-local-scope");
    let touch = |server: &str| {
        let marker = home.join(format!("{server}.started"));
        json!({"command": "/usr/bin/touch", "args": [marker]})
    };
    let project = home.join("proj");
    let root = home.join("plugin-root");
    // A local-scope row whose name looks like a plugin row, in a project at the
    // plugin's own root, stays a local server.
    write_json(
        &home.join(".claude.json"),
        json!({"projects": {
            project.to_string_lossy(): {"mcpServers": {"local-srv": touch("local-srv")}},
            root.to_string_lossy(): {"mcpServers": {"plugin_kit_tool": touch("plugin_kit_tool")}},
        }}),
    );
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
        json!({"enabledPlugins": {"kit@m": true}}),
    );
    let managed = home.join("managed");
    let settings = managed.join("managed-settings.json");
    let project_local = project.join(".claude").join("settings.local.json");
    let project_shared = project.join(".claude").join("settings.json");
    let deny = |entry: Value| json!({"deniedMcpServers": [entry]});
    let local_command = json!(["/usr/bin/touch", home.join("local-srv.started")]);
    // (policy file, policy, vetoed [local-srv, plugin_kit_tool])
    let rows = [
        (&settings, json!({}), [false, false]),
        // The declaring project's settings deny its local-scope servers.
        (
            &project_local,
            deny(json!({"serverName": "local-srv"})),
            [true, false],
        ),
        (
            &project_shared,
            deny(json!({"serverCommand": local_command})),
            [true, false],
        ),
        // The lookalike row is not a plugin server.
        (
            &settings,
            json!({"strictPluginOnlyCustomization": ["mcp"]}),
            [true, true],
        ),
        (
            &settings,
            deny(json!({"serverName": "plugin_kit_tool"})),
            [false, true],
        ),
        (
            &settings,
            deny(json!({"serverName": "plugin:kit:tool"})),
            [false, false],
        ),
    ];
    for (row, (path, policy, expected)) in rows.into_iter().enumerate() {
        for path in [&settings, &project_local, &project_shared] {
            let _ = fs::remove_file(path);
        }
        write_json(path, policy);
        let vetoes = provenance_vetoes(&home, &managed, &["local-srv", "plugin_kit_tool"]);
        assert_eq!(vetoes, expected, "row {row}");
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn a_deny_matches_configured_values_expanded_from_the_settings_env() {
    let (home, managed, marker) = policy_home("policy-configured-env");
    // Absent from the daemon's environment; only the settings `env` sets it.
    let var = "OTTTO_POLICY_TEST_ID1_ARG";
    write_json(
        &home.join(".claude.json"),
        json!({"mcpServers": {"user-srv": {
            "command": "/usr/bin/touch",
            "args": [marker.to_string_lossy(), format!("${{{var}}}")],
        }}}),
    );
    let deny = json!([{"serverCommand": ["/usr/bin/touch", marker.to_string_lossy(), "blocked"]}]);
    let settings = managed.join("managed-settings.json");
    let user = home.join(".claude").join("settings.local.json");
    assert!(!policy_server(&home, &managed, "user-srv").disabled);
    // (managed settings, user settings): the managed `env`, or the user's.
    let rows = [
        (
            json!({"env": {var: "blocked"}, "deniedMcpServers": deny}),
            json!({}),
        ),
        (
            json!({"deniedMcpServers": deny}),
            json!({"env": {var: "blocked"}}),
        ),
    ];
    for (row, (managed_settings, user_settings)) in rows.into_iter().enumerate() {
        write_json(&settings, managed_settings);
        write_json(&user, user_settings);
        assert!(
            policy_server(&home, &managed, "user-srv").disabled,
            "row {row}"
        );
        assert!(!policy_started(&home, &managed, &marker), "row {row}");
    }
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
