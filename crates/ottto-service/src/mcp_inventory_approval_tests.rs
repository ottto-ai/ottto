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
fn project_server_approved_on_its_claude_json_entry_is_loaded() {
    let (home, _project, _marker) = approval_home(
        "approval-project-entry",
        json!({"hasTrustDialogAccepted": true, "enabledMcpjsonServers": ["project-srv"]}),
    );
    assert!(!project_server(&home).disabled);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn approval_in_settings_files_inside_the_project_does_not_start_a_server() {
    let approval =
        json!({"enabledMcpjsonServers": ["project-srv"], "enableAllProjectMcpServers": true});
    // A plain local settings file in the project.
    let (home, project, marker) = approval_home(
        "approval-project-local",
        json!({"hasTrustDialogAccepted": true}),
    );
    write_json(
        &project.join(".claude").join("settings.local.json"),
        approval.clone(),
    );
    assert!(project_server(&home).disabled);
    assert!(!started(&home, &marker));
    let _ = fs::remove_dir_all(&home);

    // A `.claude` directory that links elsewhere.
    let (home, project, marker) = approval_home(
        "approval-project-linked",
        json!({"hasTrustDialogAccepted": true}),
    );
    let elsewhere = home.join("elsewhere");
    write_json(&elsewhere.join("settings.local.json"), approval);
    std::os::unix::fs::symlink(&elsewhere, project.join(".claude")).expect("link .claude");
    assert!(project_server(&home).disabled);
    assert!(!started(&home, &marker));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn explicit_enable_all_false_in_any_scope_keeps_project_servers_pending() {
    // User settings enable all; the project's entry or the user's local
    // settings file turns it off.
    for (name, entry, local) in [
        (
            "approval-all-false-entry",
            json!({"hasTrustDialogAccepted": true, "enableAllProjectMcpServers": false}),
            None,
        ),
        (
            "approval-all-false-local",
            json!({"hasTrustDialogAccepted": true}),
            Some(json!({"enableAllProjectMcpServers": false})),
        ),
    ] {
        let (home, _project, marker) = approval_home(name, entry);
        write_json(
            &home.join(".claude").join("settings.json"),
            json!({"enableAllProjectMcpServers": true}),
        );
        if let Some(local) = local {
            write_json(&home.join(".claude").join("settings.local.json"), local);
        }
        assert!(project_server(&home).disabled, "{name}");
        assert!(!started(&home, &marker), "{name}");
        let _ = fs::remove_dir_all(&home);
    }

    // A named approval is separate from enable-all and still loads the server.
    let (home, _project, _marker) = approval_home(
        "approval-all-false-named",
        json!({
            "hasTrustDialogAccepted": true,
            "enableAllProjectMcpServers": false,
            "enabledMcpjsonServers": ["project-srv"],
        }),
    );
    assert!(!project_server(&home).disabled);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn malformed_or_non_list_approvals_do_not_start_a_server() {
    for (name, settings) in [
        // A single name instead of a list.
        (
            "approval-string",
            json!({"enabledMcpjsonServers": "project-srv"}).to_string(),
        ),
        // A text flag instead of a boolean.
        (
            "approval-text-flag",
            json!({"enableAllProjectMcpServers": "true"}).to_string(),
        ),
        // A name that only differs in case.
        (
            "approval-case",
            json!({"enabledMcpjsonServers": ["Project-Srv"]}).to_string(),
        ),
        // A settings file that is not valid JSON.
        (
            "approval-malformed",
            r#"{"enabledMcpjsonServers": ["project-srv"], "enableAllProjectMcpServers": true"#
                .to_string(),
        ),
    ] {
        let (home, _project, marker) = approval_home(name, json!({"hasTrustDialogAccepted": true}));
        fs::create_dir_all(home.join(".claude")).expect("create .claude");
        fs::write(home.join(".claude").join("settings.json"), settings).expect("write settings");
        assert!(project_server(&home).disabled, "{name}");
        assert!(!started(&home, &marker), "{name}");
        let _ = fs::remove_dir_all(&home);
    }
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

/// Write a home where a local-scope server and an approved project server
/// share the name `same`; each command creates its own marker. Returns the
/// home and the (local, project) markers.
fn collision_home(name: &str, local_dir: &str, project_dir: &str) -> (PathBuf, PathBuf, PathBuf) {
    let home = test_home(name);
    let (local_marker, project_marker) = (home.join("local-started"), home.join("project-started"));
    let touch =
        |marker: &Path| json!({"command": "/usr/bin/touch", "args": [marker.to_string_lossy()]});
    let local_dir = home.join(local_dir);
    let project_dir = home.join(project_dir);
    write_json(
        &project_dir.join(".mcp.json"),
        json!({"mcpServers": {"same": touch(&project_marker)}}),
    );
    let mut projects = Map::new();
    projects.insert(
        project_dir.to_string_lossy().into_owned(),
        json!({"hasTrustDialogAccepted": true, "enabledMcpjsonServers": ["same"]}),
    );
    let local_entry = projects
        .entry(local_dir.to_string_lossy().into_owned())
        .or_insert_with(|| json!({}));
    local_entry["mcpServers"] = json!({"same": touch(&local_marker)});
    write_json(&home.join(".claude.json"), json!({"projects": projects}));
    (home, local_marker, project_marker)
}

#[test]
fn a_local_scope_server_wins_over_an_approved_project_server_of_the_same_name() {
    // Same project; then the project dir sorting before and after the local one.
    for (name, local_dir, project_dir) in [
        ("collision-same-project", "proj", "proj"),
        ("collision-project-first", "b-local", "a-project"),
        ("collision-local-first", "a-local", "b-project"),
    ] {
        let (home, local_marker, project_marker) = collision_home(name, local_dir, project_dir);
        let server = discover_claude_code(&home)
            .into_iter()
            .find(|server| server.name == "same")
            .expect("same");
        assert!(!server.disabled, "{name}");
        let (_input, deferred) = harvest_server(&server, &test_spawn_env());
        assert!(!deferred, "{name}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !local_marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(local_marker.exists(), "{name}: the local command is probed");
        assert!(
            !project_marker.exists(),
            "{name}: the project command is not"
        );
        let _ = fs::remove_dir_all(&home);
    }
}

#[test]
fn enable_all_false_in_the_projects_settings_keeps_project_servers_pending() {
    for file in ["settings.local.json", "settings.json"] {
        // Home settings enable all; the project's own file turns it off.
        let (home, project, marker) = approval_home(
            &format!("approval-project-false-{file}"),
            json!({"hasTrustDialogAccepted": true}),
        );
        write_json(
            &home.join(".claude").join("settings.json"),
            json!({"enableAllProjectMcpServers": true}),
        );
        write_json(
            &project.join(".claude").join(file),
            json!({"enableAllProjectMcpServers": false}),
        );
        assert!(project_server(&home).disabled, "{file}");
        assert!(!started(&home, &marker), "{file}");

        // A named approval in home settings still loads the server.
        write_json(
            &home.join(".claude").join("settings.json"),
            json!({"enableAllProjectMcpServers": true, "enabledMcpjsonServers": ["project-srv"]}),
        );
        assert!(!project_server(&home).disabled, "{file}");
        assert!(started(&home, &marker), "{file}");
        let _ = fs::remove_dir_all(&home);
    }
}

#[test]
fn a_missing_project_directory_declares_no_project_servers() {
    let home = test_home("approval-missing-project");
    let gone = home.join("gone");
    write_json(
        &home.join(".claude.json"),
        json!({"projects": {gone.to_string_lossy(): {
            "hasTrustDialogAccepted": true,
            "enableAllProjectMcpServers": true,
            "mcpServers": {"local-srv": {"command": "/user/local"}},
        }}}),
    );
    let servers = discover_claude_code(&home);
    assert_eq!(
        servers
            .iter()
            .map(|server| (server.name.as_str(), server.disabled))
            .collect::<Vec<_>>(),
        [("local-srv", false)]
    );
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn the_first_approved_project_server_keeps_a_shared_name() {
    let home = test_home("approval-two-projects");
    let markers = [home.join("a-started"), home.join("b-started")];
    let mut projects = Map::new();
    for (dir, marker) in ["a-proj", "b-proj"].into_iter().zip(&markers) {
        let dir = home.join(dir);
        write_json(
            &dir.join(".mcp.json"),
            json!({"mcpServers": {"dup": {
                "command": "/usr/bin/touch",
                "args": [marker.to_string_lossy()],
            }}}),
        );
        projects.insert(
            dir.to_string_lossy().into_owned(),
            json!({"hasTrustDialogAccepted": true, "enabledMcpjsonServers": ["dup"]}),
        );
    }
    write_json(&home.join(".claude.json"), json!({"projects": projects}));

    let server = discover_claude_code(&home)
        .into_iter()
        .find(|server| server.name == "dup")
        .expect("dup");
    assert!(!server.disabled);
    let (_input, deferred) = harvest_server(&server, &test_spawn_env());
    assert!(!deferred);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !markers[0].exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(markers[0].exists(), "the first project's command is probed");
    assert!(!markers[1].exists(), "a later project does not replace it");
    let _ = fs::remove_dir_all(&home);
}
