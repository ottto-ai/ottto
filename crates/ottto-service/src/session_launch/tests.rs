use super::*;
use ottto_core::{billing_identity_hash, session_launch::LaunchUser, ClaudeConfigDirSlot};
use std::os::unix::fs::symlink;

fn fixture_binding(home: &Path) -> Binding {
    Binding {
        provider: Provider::ClaudeCode,
        slot_id: "default".into(),
        account: "a".repeat(64),
        organization: "b".repeat(64),
        root: home.join(".claude"),
        claude_slot: Some(ClaudeConfigDirSlot::Default),
        user: LaunchUser {
            home: home.into(),
            name: "synthetic".into(),
        },
    }
}

fn fixture_entry(root: &Path) -> Entry {
    let cwd = root.join("project");
    fs::create_dir_all(&cwd).unwrap();
    let metadata = fs::metadata(&cwd).unwrap();
    Entry {
        binding: fixture_binding(root),
        cwd,
        dev: metadata.dev(),
        ino: metadata.ino(),
        program: PathBuf::from("/bin/false"),
        program_identity: program_identity(Path::new("/bin/false")).unwrap(),
        secret: Sha256::digest(b"secret").into(),
        created: Instant::now(),
        state: State::Pending,
        block: None,
        attempt: None,
        launcher: root.join("old.command"),
        generation: (0, None),
    }
}

#[test]
fn launcher_permissions_symlinks_and_content() {
    let scratch = crate::test_scratch::ScratchDir::new("session-launch");
    let root = scratch.as_ref();
    let directory = launcher_directory(root, true).unwrap();
    assert_eq!(directory.metadata().unwrap().mode() & 0o777, 0o700);
    let (id, path) = write_launcher(
        &directory,
        root,
        Path::new("/Applications/Ottto's 雪 $(x)`/ottto"),
        "synthetic",
    )
    .unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert!(text.contains("launch-check --exec"));
    assert!(text.contains(&id));
    assert!(!text.contains("project"));
    assert!(!text.contains("CLAUDE_CONFIG_DIR"));
    assert!(text.contains("Ottto'\\''s"));
    assert_eq!(text.lines().count(), 3);
    fs::set_permissions(
        root.join("session-launch"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(
        launcher_directory(root, true).unwrap_err().reason,
        Reason::LauncherDirUnsafe
    );
    fs::set_permissions(
        root.join("session-launch"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::remove_dir_all(root.join("session-launch")).unwrap();
    symlink(root, root.join("session-launch")).unwrap();
    assert_eq!(
        launcher_directory(root, true).unwrap_err().reason,
        Reason::LauncherDirUnsafe
    );
}

#[test]
fn expiry_cancel_wrong_secret_and_attempt_bound_failure() {
    let scratch = crate::test_scratch::ScratchDir::new("launch-lifecycle");
    let mut registry = Registry::default();
    registry
        .entries
        .insert("once".into(), fixture_entry(scratch.as_ref()));
    let first = registry.consume("once", "wrong");
    assert_eq!(first.block.unwrap().reason, Reason::LaunchUnknown);
    assert_eq!(
        registry.consume("once", "secret").block.unwrap().reason,
        Reason::LaunchAlreadyUsed
    );
    let mut expired = fixture_entry(scratch.as_ref());
    expired.created = Instant::now() - TTL;
    registry.entries.insert("expired".into(), expired);
    assert_eq!(
        registry.status("expired", false).state,
        Some(State::Expired)
    );
    registry
        .entries
        .insert("cancel".into(), fixture_entry(scratch.as_ref()));
    assert_eq!(
        registry.status("cancel", true).block.unwrap().reason,
        Reason::LaunchCancelled
    );
    let mut starting = fixture_entry(scratch.as_ref());
    starting.state = State::Starting;
    starting.attempt = Some(SecretString::new("attempt"));
    registry.entries.insert("starting".into(), starting);
    assert_eq!(
        registry
            .report("starting", "wrong", Reason::ExecFailed)
            .state,
        Some(State::Starting)
    );
    assert_eq!(
        registry
            .report("starting", "attempt", Reason::ExecFailed)
            .state,
        Some(State::Blocked)
    );
    assert_eq!(
        Registry::default()
            .consume("once", "secret")
            .block
            .unwrap()
            .reason,
        Reason::LaunchUnknown
    );
}

#[test]
fn environment_preserves_exact_slot_and_default_semantics() {
    let mut binding = fixture_binding(Path::new("/synthetic-home"));
    let (unset, set) = environment(&binding);
    assert!(unset.iter().any(|key| key == "CLAUDE_CONFIG_DIR"));
    assert!(unset.iter().any(|key| key == "OTTTO_CONTROL_TOKEN"));
    assert!(!set.contains_key("CLAUDE_CONFIG_DIR"));
    assert_eq!(set["HOME"], "/synthetic-home");
    binding.claude_slot = Some(ClaudeConfigDirSlot::registered("/synthetic/slot/").unwrap());
    assert_eq!(
        environment(&binding).1["CLAUDE_CONFIG_DIR"],
        "/synthetic/slot/"
    );
    binding.provider = Provider::Codex;
    binding.claude_slot = None;
    binding.root = "/synthetic-home/.codex".into();
    let (unset, set) = environment(&binding);
    assert!(unset.iter().any(|key| key == "OPENAI_API_KEY"));
    assert_eq!(set["CODEX_HOME"], set["CODEX_SQLITE_HOME"]);
    assert_eq!(set["CODEX_HOME"], "/synthetic-home/.codex");
}

#[test]
fn supported_major_versions_only() {
    assert_eq!(
        parse_version(b"2.1.310 (Claude Code)\n", Provider::ClaudeCode).as_deref(),
        Some("2.1.310")
    );
    assert_eq!(
        parse_version(b"codex-cli 0.138.0\n", Provider::Codex).as_deref(),
        Some("0.138.0")
    );
    for (text, provider) in [
        ("3.0.0", Provider::ClaudeCode),
        ("1.0.0", Provider::Codex),
        ("future", Provider::Codex),
        ("0.1\nunsafe", Provider::Codex),
    ] {
        assert!(parse_version(text.as_bytes(), provider).is_none());
    }
}

#[test]
fn folder_restrictions_and_inode_replacement() {
    let scratch = crate::test_scratch::ScratchDir::new("launch-folder");
    let root = scratch.as_ref();
    let home = root.join("home");
    let support = root.join("support");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&support).unwrap();
    for path in [Path::new("/"), &home, &support, Path::new("relative")] {
        assert!(validate_folder(path, &home, &support).is_err());
    }
    let entry = fixture_entry(root);
    fs::rename(&entry.cwd, root.join("old-project")).unwrap();
    fs::create_dir(&entry.cwd).unwrap();
    assert_ne!(fs::metadata(&entry.cwd).unwrap().ino(), entry.ino);
}

#[test]
fn project_settings_and_malformed_files_are_not_ignored() {
    let scratch = crate::test_scratch::ScratchDir::new("launch-preflight");
    let root = scratch.as_ref();
    let binding = fixture_binding(root);
    fs::create_dir(root.join(".claude")).unwrap();
    let project = root.join("project");
    fs::create_dir_all(project.join(".claude")).unwrap();
    let settings = project.join(".claude/settings.local.json");
    fs::write(&settings, "{bad").unwrap();
    assert_eq!(
        preflight::evaluate(&binding, &project).unwrap_err().reason,
        Reason::SettingsMalformed
    );
    fs::write(&settings, r#"{"apiKeyHelper":"never execute this"}"#).unwrap();
    assert_eq!(
        preflight::evaluate(&binding, &project).unwrap_err().reason,
        Reason::ApiKeyRoute
    );
    fs::remove_file(&settings).unwrap();
    symlink(root.join("missing"), &settings).unwrap();
    assert_eq!(
        preflight::evaluate(&binding, &project).unwrap_err().reason,
        Reason::SettingsUnreadable
    );
}

#[test]
fn fresh_identity_switch_and_needs_login_are_refused_without_spawning() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let scratch = crate::test_scratch::ScratchDir::new("launch-binding");
    let root = scratch.as_ref();
    let support = root.join("support");
    fs::create_dir(&support).unwrap();
    std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let account = billing_identity_hash("anthropic", "account", "account-one").unwrap();
    let org = billing_identity_hash("anthropic", "organization", "org-one").unwrap();
    fs::write(
        root.join(".claude.json"),
        r#"{"oauthAccount":{"accountUuid":"account-one","organizationUuid":"org-one"}}"#,
    )
    .unwrap();
    let mut collection = ottto_protocol::ClaudeConfigSlotCollectionStatusV1 {
        state: ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account.clone()),
        organization_identifier_hash: Some(org.clone()),
        ..Default::default()
    };
    let save = |collection: &ottto_protocol::ClaudeConfigSlotCollectionStatusV1| {
        fs::write(
            support.join("claude-config-slot-collection-state.json"),
            serde_json::to_vec(
                &serde_json::json!({"schema_version":1,"slots":{"default":collection}}),
            )
            .unwrap(),
        )
        .unwrap()
    };
    save(&collection);
    let user = LaunchUser {
        home: root.into(),
        name: "synthetic".into(),
    };
    let binding = binding::resolve(
        Provider::ClaudeCode,
        "default",
        &account,
        &org,
        user.clone(),
    )
    .unwrap();
    fs::write(
        root.join(".claude.json"),
        r#"{"oauthAccount":{"accountUuid":"account-two","organizationUuid":"org-one"}}"#,
    )
    .unwrap();
    assert_eq!(
        binding::recheck(&binding).unwrap_err().reason,
        Reason::AccountMismatch
    );
    collection.state = ottto_protocol::ClaudeConfigSlotCollectionStateV1::NeedsLogin;
    save(&collection);
    assert_eq!(
        binding::resolve(Provider::ClaudeCode, "default", &account, &org, user)
            .err()
            .unwrap()
            .reason,
        Reason::SlotNeedsLogin
    );
    std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
}

#[test]
fn prepare_consume_rechecks_settings_binding_folder_and_retry() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let scratch = crate::test_scratch::ScratchDir::new("launch-roundtrip");
    let root = scratch.as_ref();
    let support = root.join("support");
    let home = root.join("home");
    let project = root.join("project");
    let bin = root.join("bin");
    for path in [&support, &home, &project, &bin] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::create_dir(home.join(".claude")).unwrap();
    std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let cli = bin.join("claude");
    fs::write(
        &cli,
        "#!/bin/sh\n[ \"$1\" = --version ] || exit 99\nprintf '2.1.310 (Claude Code)\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        home.join(".claude.json"),
        r#"{"oauthAccount":{"accountUuid":"account-one","organizationUuid":"org-one"}}"#,
    )
    .unwrap();
    let account = billing_identity_hash("anthropic", "account", "account-one").unwrap();
    let organization = billing_identity_hash("anthropic", "organization", "org-one").unwrap();
    fs::write(support.join("claude-config-slot-collection-state.json"), serde_json::to_vec(&serde_json::json!({
        "schema_version":1,"slots":{"default":{"state":"fresh","account_identifier_hash":account,"organization_identifier_hash":organization}}
    })).unwrap()).unwrap();
    let user = LaunchUser {
        home: home.clone(),
        name: "synthetic".into(),
    };
    let prepare = |registry: &mut Registry| {
        registry
            .prepare_for_user(
                Provider::ClaudeCode,
                "default",
                &account,
                &organization,
                SessionLaunchFolderV1 {
                    path: Some(project.to_string_lossy().into_owned()),
                    recent_id: None,
                },
                Some(PathBuf::from("/bin/true")),
                &support,
                user.clone(),
            )
            .unwrap()
    };
    let mut registry = Registry::default();
    let one = prepare(&mut registry);
    let old = one.launch_id.unwrap();
    let old_path = one.launcher_path.unwrap();
    let two = prepare(&mut registry);
    let id = two.launch_id.unwrap();
    assert_eq!(
        registry.status(&old, false).block.unwrap().reason,
        Reason::LaunchCancelled
    );
    assert!(!Path::new(&old_path).exists());
    let secret = fs::read_to_string(two.launcher_path.unwrap())
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_owned();
    let result = registry.consume(&id, &secret);
    assert_eq!(result.state, Some(State::Starting));
    assert!(result
        .plan
        .unwrap()
        .env_set
        .unwrap()
        .get("CLAUDE_CONFIG_DIR")
        .is_none());
    assert_eq!(
        registry.consume(&id, &secret).block.unwrap().reason,
        Reason::LaunchAlreadyUsed
    );
    assert_eq!(
        registry
            .report(
                &id,
                result.attempt_id.unwrap().expose_secret(),
                Reason::ExecFailed
            )
            .block
            .unwrap()
            .reason,
        Reason::ExecFailed
    );
    for reason in [
        Reason::SettingsEnvOverride,
        Reason::AccountMismatch,
        Reason::FolderChanged,
    ] {
        let result = prepare(&mut registry);
        let id = result.launch_id.unwrap();
        let secret = fs::read_to_string(result.launcher_path.unwrap())
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_owned();
        match reason {
            Reason::SettingsEnvOverride => fs::write(
                home.join(".claude/settings.json"),
                r#"{"env":{"ANTHROPIC_BASE_URL":"https://example.invalid"}}"#,
            )
            .unwrap(),
            Reason::AccountMismatch => fs::write(
                home.join(".claude.json"),
                r#"{"oauthAccount":{"accountUuid":"account-two","organizationUuid":"org-one"}}"#,
            )
            .unwrap(),
            _ => {
                fs::rename(&project, root.join("old-project")).unwrap();
                fs::create_dir(&project).unwrap();
            }
        }
        assert_eq!(registry.consume(&id, &secret).block.unwrap().reason, reason);
        let _ = fs::remove_file(home.join(".claude/settings.json"));
        fs::write(
            home.join(".claude.json"),
            r#"{"oauthAccount":{"accountUuid":"account-one","organizationUuid":"org-one"}}"#,
        )
        .unwrap();
    }
    std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
    std::env::remove_var("OTTTO_COMMAND_SEARCH_PATH");
}
