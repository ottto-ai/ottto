// Included in mcp_inventory::tests: project `.mcp.json` servers load only once
// the client has approved them. Synthetic homes only.

/// A home with one project whose `.mcp.json` declares `project-srv`, a server
/// that creates `<home>/started` when it runs. `project_entry` is the project's
/// `~/.claude.json` entry. Returns `(home, project, marker)`.
fn approval_home(name: &str, project_entry: Value) -> (PathBuf, PathBuf, PathBuf) {
    let home = test_home(name);
    let project = home.join("proj");
    let marker = home.join("started");
    write_json(
        &project.join(".mcp.json"),
        json!({"mcpServers": {"project-srv": {
            "command": "/usr/bin/touch",
            "args": [marker.to_string_lossy()],
        }}}),
    );
    write_json(
        &home.join(".claude.json"),
        json!({"projects": {project.to_string_lossy(): project_entry}}),
    );
    (home, project, marker)
}

fn project_server(home: &Path) -> ConfiguredServer {
    discover_claude_code(home)
        .into_iter()
        .find(|server| server.name == "project-srv")
        .expect("the project server is still reported")
}

/// Run the harvest for the project server and return whether its process ran.
fn started(home: &Path, marker: &Path) -> bool {
    let server = project_server(home);
    let (input, deferred) = harvest_server(&server, &test_spawn_env());
    assert!(!deferred);
    assert_eq!(input.disabled, server.disabled);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !server.disabled && !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    marker.exists()
}

#[test]
fn project_server_without_approval_is_reported_but_not_started() {
    let (home, _project, marker) =
        approval_home("approval-none", json!({"hasTrustDialogAccepted": true}));

    let server = project_server(&home);
    assert!(server.disabled, "pending approval counts as not loaded");
    assert_eq!(server.transport.label(), "stdio");
    assert!(!started(&home, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn project_server_approved_by_name_in_user_settings_is_started() {
    let (home, _project, marker) = approval_home(
        "approval-user-name",
        json!({"hasTrustDialogAccepted": true}),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"enabledMcpjsonServers": ["project-srv"]}),
    );

    assert!(!project_server(&home).disabled);
    assert!(started(&home, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn project_server_approved_for_all_in_user_settings_is_loaded() {
    let (home, _project, _marker) =
        approval_home("approval-user-all", json!({"hasTrustDialogAccepted": true}));
    write_json(
        &home.join(".claude").join("settings.local.json"),
        json!({"enableAllProjectMcpServers": true}),
    );

    assert!(!project_server(&home).disabled);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn project_server_approved_in_the_projects_own_user_scopes_is_loaded() {
    // The client records approvals on the project's `~/.claude.json` entry or
    // in the project's local (uncommitted) settings file.
    let (home, _project, _marker) = approval_home(
        "approval-project-entry",
        json!({"hasTrustDialogAccepted": true, "enabledMcpjsonServers": ["project-srv"]}),
    );
    assert!(!project_server(&home).disabled);
    let _ = fs::remove_dir_all(&home);

    let (home, project, _marker) = approval_home(
        "approval-project-local",
        json!({"hasTrustDialogAccepted": true}),
    );
    write_json(
        &project.join(".claude").join("settings.local.json"),
        json!({"enabledMcpjsonServers": "project-srv"}),
    );
    assert!(!project_server(&home).disabled);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn approval_in_the_projects_shared_settings_does_not_start_a_server() {
    let (home, project, marker) = approval_home(
        "approval-shared-settings",
        json!({"hasTrustDialogAccepted": true}),
    );
    write_json(
        &project.join(".claude").join("settings.json"),
        json!({
            "enabledMcpjsonServers": ["project-srv"],
            "enableAllProjectMcpServers": true,
        }),
    );

    assert!(project_server(&home).disabled);
    assert!(!started(&home, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn approval_does_not_start_a_server_in_an_untrusted_project() {
    for (name, entry) in [
        ("approval-untrusted-absent", json!({})),
        (
            "approval-untrusted-false",
            json!({"hasTrustDialogAccepted": false, "enabledMcpjsonServers": ["project-srv"]}),
        ),
    ] {
        let (home, _project, marker) = approval_home(name, entry);
        write_json(
            &home.join(".claude").join("settings.json"),
            json!({"enabledMcpjsonServers": ["project-srv"], "enableAllProjectMcpServers": true}),
        );

        assert!(project_server(&home).disabled, "{name}");
        assert!(!started(&home, &marker), "{name}");
        let _ = fs::remove_dir_all(&home);
    }
}

#[test]
fn disabled_list_wins_over_project_approval() {
    let (home, _project, marker) = approval_home(
        "approval-disabled-wins",
        json!({"hasTrustDialogAccepted": true, "disabledMcpjsonServers": ["project-srv"]}),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"enableAllProjectMcpServers": true}),
    );

    assert!(project_server(&home).disabled);
    assert!(!started(&home, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn user_and_local_scope_servers_load_without_project_approval() {
    let home = test_home("approval-user-servers");
    let project = home.join("proj");
    write_json(
        &project.join(".mcp.json"),
        json!({"mcpServers": {
            "shared-name": {"command": "/project/server"},
            "project-only": {"command": "/project/other"},
        }}),
    );
    write_json(
        &home.join(".claude.json"),
        json!({
            "mcpServers": {"shared-name": {"command": "/user/server"}},
            "projects": {project.to_string_lossy(): {
                "mcpServers": {"local-srv": {"command": "/user/local"}},
            }},
        }),
    );
    write_json(
        &home.join(".claude").join("settings.json"),
        json!({"mcpServers": {"settings-srv": {"command": "/user/settings"}}}),
    );

    let servers = discover_claude_code(&home);
    let by_name = |name: &str| {
        servers
            .iter()
            .find(|server| server.name == name)
            .unwrap_or_else(|| panic!("{name}"))
    };
    for name in ["shared-name", "local-srv", "settings-srv"] {
        assert!(!by_name(name).disabled, "{name}");
    }
    // A project server awaiting approval never replaces a user server.
    assert!(matches!(
        &by_name("shared-name").transport,
        Transport::Stdio { command, .. } if command == "/user/server"
    ));
    assert!(by_name("project-only").disabled);
    let _ = fs::remove_dir_all(&home);
}
