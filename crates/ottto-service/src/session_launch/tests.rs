use super::*;
use ottto_core::{billing_identity_hash, session_launch::LaunchUser, ClaudeConfigDirSlot};
use std::os::unix::fs::symlink;

fn test_executable() -> PathBuf {
    std::env::current_exe()
        .expect("current test executable")
        .canonicalize()
        .expect("canonical test executable")
}

fn write_login(home: &Path) {
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::write(home.join(".claude/.credentials.json"), serde_json::to_vec(&serde_json::json!({"claudeAiOauth":{
        "accessToken":"synthetic-access", "refreshToken":"synthetic-refresh", "expiresAt":4102444800000_i64,
        "refreshTokenExpiresAt":4102444800000_i64, "scopes":["user:inference","user:profile"]
    }})).unwrap()).unwrap();
    fs::set_permissions(
        home.join(".claude/.credentials.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

fn write_refreshable_login(home: &Path) {
    write_login(home);
    let path = home.join(".claude/.credentials.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["claudeAiOauth"]["expiresAt"] = serde_json::json!(1);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

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
    let program = test_executable();
    let program_identity = program_identity(&program).expect("test executable identity");
    Entry {
        binding: fixture_binding(root),
        cwd,
        dev: metadata.dev(),
        ino: metadata.ino(),
        program,
        program_identity,
        cli_version: "2.1.310".into(),
        path_env: "/usr/bin:/bin".into(),
        secret: Sha256::digest(b"secret").into(),
        created: Instant::now(),
        created_wall: std::time::SystemTime::now(),
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
    let mut slept = fixture_entry(scratch.as_ref());
    slept.created_wall = std::time::SystemTime::now() - Duration::from_secs(3600);
    registry.entries.insert("slept".into(), slept);
    assert_eq!(registry.status("slept", false).state, Some(State::Expired));
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
    fs::create_dir_all(root.join(".claude")).unwrap();
    write_login(root);
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
    fs::remove_file(root.join(".claude/.credentials.json")).unwrap();
    assert_eq!(
        binding::recheck(&binding).unwrap_err().reason,
        Reason::SlotNeedsLogin
    );
    fs::write(
        root.join(".claude/.credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0}}"#,
    )
    .unwrap();
    fs::set_permissions(
        root.join(".claude/.credentials.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        binding::recheck(&binding).unwrap_err().reason,
        Reason::SlotNeedsLogin
    );
    fs::write(root.join(".claude/.credentials.json"), "{bad").unwrap();
    assert_eq!(
        binding::recheck(&binding).unwrap_err().reason,
        Reason::SlotNotVerified
    );
    write_refreshable_login(root);
    collection.state = ottto_protocol::ClaudeConfigSlotCollectionStateV1::UpkeepNotConsented;
    save(&collection);
    assert!(binding::recheck(&binding).is_ok());
    let pair = ottto_protocol::AccountNicknamePairV1 {
        source: Provider::ClaudeCode,
        account_identifier_hash: Some(account.clone()),
        organization_identifier_hash: Some(org.clone()),
    };
    assert!(nickname_target_is_current_for_user(&pair, user.clone()));
    collection.upkeep =
        Some(serde_json::from_value(serde_json::json!({"result":"in_progress"})).unwrap());
    save(&collection);
    assert_eq!(
        binding::recheck(&binding).unwrap_err().reason,
        Reason::SlotNotVerified
    );
    collection.upkeep = None;
    collection.state = ottto_protocol::ClaudeConfigSlotCollectionStateV1::Fresh;
    save(&collection);
    write_login(root);

    fs::write(
        root.join(".claude.json"),
        r#"{"oauthAccount":{"accountUuid":"account-one"}}"#,
    )
    .unwrap();
    assert!(crate::agent_status::session_launch_claude_identity(
        &ClaudeConfigDirSlot::Default,
        root
    )
    .is_none());
    let mut missing_org_pair = pair.clone();
    missing_org_pair.organization_identifier_hash = Some(String::new());
    assert!(!nickname_target_is_current_for_user(
        &missing_org_pair,
        user.clone()
    ));

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
    write_refreshable_login(&home);
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
                Some(test_executable()),
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
    let env = result.plan.unwrap().env_set.unwrap();
    assert!(!env.contains_key("CLAUDE_CONFIG_DIR"));
    assert!(env["PATH"].split(':').any(|part| Path::new(part) == bin));
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
    let pending = prepare(&mut registry);
    let old_id = pending.launch_id.unwrap();
    let old_path = pending.launcher_path.unwrap();
    let bad = registry.prepare_for_user(
        Provider::ClaudeCode,
        "default",
        &account,
        &organization,
        SessionLaunchFolderV1 {
            path: Some(root.join("missing").to_string_lossy().into_owned()),
            recent_id: None,
        },
        Some(test_executable()),
        &support,
        user.clone(),
    );
    assert_eq!(bad.err().unwrap().reason, Reason::FolderMissing);
    assert!(!Path::new(&old_path).exists());
    assert_eq!(
        registry.status(&old_id, false).block.unwrap().reason,
        Reason::LaunchCancelled
    );
    let original_cli = fs::read(&cli).unwrap();
    for reason in [
        Reason::SlotNeedsLogin,
        Reason::SettingsEnvOverride,
        Reason::AccountMismatch,
        Reason::CliChanged,
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
            Reason::SlotNeedsLogin => {
                fs::remove_file(home.join(".claude/.credentials.json")).unwrap();
            }
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
            Reason::CliChanged => {
                use std::io::Write;
                fs::OpenOptions::new()
                    .append(true)
                    .open(&cli)
                    .unwrap()
                    .write_all(b"# changed after prepare\n")
                    .unwrap();
            }
            _ => {
                fs::rename(&project, root.join("old-project")).unwrap();
                fs::create_dir(&project).unwrap();
            }
        }
        assert_eq!(registry.consume(&id, &secret).block.unwrap().reason, reason);
        fs::write(&cli, &original_cli).unwrap();
        let _ = fs::remove_file(home.join(".claude/settings.json"));
        write_login(&home);
        fs::write(
            home.join(".claude.json"),
            r#"{"oauthAccount":{"accountUuid":"account-one","organizationUuid":"org-one"}}"#,
        )
        .unwrap();
    }
    std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
    std::env::remove_var("OTTTO_COMMAND_SEARCH_PATH");
}

/// A Codex ChatGPT login with saved quota proof in `root/home`, and the
/// support and project directories a Codex prepare reads. Returns the
/// account and organization hashes of that login.
fn codex_login_fixture(root: &Path) -> (String, String) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let home = root.join("home");
    let codex = home.join(".codex");
    let support = root.join("support");
    let project = root.join("project");
    for path in [&home, &codex, &support, &project] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({"iss":"https://auth.openai.com","aud":"synthetic","exp":now+3600,
        "https://api.openai.com/auth":{"chatgpt_user_id":"user-one","chatgpt_account_id":"workspace-one"}});
    let token = format!(
        "{}.{}.synthetic-signature",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    fs::write(codex.join("auth.json"), serde_json::to_vec(&serde_json::json!({"auth_mode":"chatgpt","OPENAI_API_KEY":"synthetic-exchanged-key","tokens":{"account_id":"workspace-one","access_token":token}})).unwrap()).unwrap();
    fs::set_permissions(codex.join("auth.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let account = billing_identity_hash("openai", "account", "user-one").unwrap();
    let org = billing_identity_hash("openai", "workspace", "workspace-one").unwrap();
    let mut hash = Sha256::new();
    hash.update(b"ottto:codex-quota-home:v1\0");
    hash.update(codex.as_os_str().as_encoded_bytes());
    let home_key = format!("{:x}", hash.finalize());
    let saved_dir = support.join("codex-quota/homes").join(&home_key);
    fs::create_dir_all(&saved_dir).unwrap();
    let window = ottto_protocol::AgentQuotaWindow {
        freshness: ottto_protocol::AgentQuotaWindowFreshness::Fresh,
        ..Default::default()
    };
    fs::write(saved_dir.join("saved-quota.json"), serde_json::to_vec(&serde_json::json!({
        "schema_version":1,"home_key":home_key,"reading":{"observed_at_epoch_seconds":now,"login":{"binding":format!("{account}:{org}")},
        "identity":{"account_identifier_hash":account,"workspace_identifier_hash":org},"provider_account_signed_in":true,"quota_windows":[window]}
    })).unwrap()).unwrap();
    (account, org)
}

#[test]
fn codex_launch_and_nickname_read_only_saved_proof_and_never_probe_login() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let scratch = crate::test_scratch::ScratchDir::new("codex-launch");
    // The credential reader refuses symlinked ancestors; macOS TMPDIR uses /var.
    let canonical_root = scratch.canonicalize().expect("canonical scratch directory");
    let root = canonical_root.as_path();
    let (account, org) = codex_login_fixture(root);
    let home = root.join("home");
    let codex = home.join(".codex");
    let support = root.join("support");
    let project = root.join("project");
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", &bin);
    let ambient_keys = [
        "CODEX_ACCESS_TOKEN",
        "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
        "CODEX_REVOKE_TOKEN_URL_OVERRIDE",
        "CODEX_APP_SERVER_LOGIN_CLIENT_ID",
    ];
    for key in ambient_keys {
        std::env::set_var(key, "synthetic-override");
    }
    let witness = root.join("commands");
    let quoted = quote_launch_executable(witness.to_str().unwrap()).unwrap();
    let cli = bin.join("codex");
    let write_cli = |version: &str| {
        fs::write(&cli, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {quoted}\n[ \"$1\" = --version ] || exit 99\ntest -z \"${{CODEX_ACCESS_TOKEN+x}}${{CODEX_REFRESH_TOKEN_URL_OVERRIDE+x}}${{CODEX_REVOKE_TOKEN_URL_OVERRIDE+x}}${{CODEX_APP_SERVER_LOGIN_CLIENT_ID+x}}\" || exit 97\nprintf 'codex-cli {version}\\n'\n")).unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
    };
    write_cli("0.170.0");
    let user = LaunchUser {
        home: home.clone(),
        name: "synthetic".into(),
    };
    let pair = ottto_protocol::AccountNicknamePairV1 {
        source: Provider::Codex,
        account_identifier_hash: Some(account.clone()),
        organization_identifier_hash: Some(org.clone()),
    };
    assert!(nickname_target_is_current_for_user(&pair, user.clone()));
    assert!(!witness.exists());
    let mut registry = Registry::default();
    let prepare = |registry: &mut Registry| {
        registry.prepare_for_user(
            Provider::Codex,
            "default",
            &account,
            &org,
            SessionLaunchFolderV1 {
                path: Some(project.to_string_lossy().into_owned()),
                recent_id: None,
            },
            Some(test_executable()),
            &support,
            user.clone(),
        )
    };
    let result = prepare(&mut registry).unwrap();
    let secret = fs::read_to_string(result.launcher_path.unwrap())
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_owned();
    let consumed = registry.consume(&result.launch_id.unwrap(), &secret);
    assert_eq!(consumed.state, Some(State::Starting));
    let unset = consumed.plan.unwrap().env_unset.unwrap();
    for key in ambient_keys {
        assert!(unset.iter().any(|name| name == key));
    }
    assert_eq!(fs::read_to_string(&witness).unwrap(), "--version\n");
    write_cli("1.0.0");
    assert_eq!(
        prepare(&mut registry).err().unwrap().reason,
        Reason::CliVersionUnsupported
    );
    assert_eq!(
        fs::read_to_string(&witness).unwrap(),
        "--version\n--version\n"
    );
    let mut auth: serde_json::Value =
        serde_json::from_slice(&fs::read(codex.join("auth.json")).unwrap()).unwrap();
    auth.as_object_mut().unwrap().remove("auth_mode");
    fs::write(codex.join("auth.json"), serde_json::to_vec(&auth).unwrap()).unwrap();
    assert_eq!(
        prepare(&mut registry).err().unwrap().reason,
        Reason::CodexApiKeyLogin
    );
    assert!(!nickname_target_is_current_for_user(&pair, user.clone()));
    auth["auth_mode"] = serde_json::json!("apikey");
    auth["OPENAI_API_KEY"] = serde_json::json!("synthetic-api-key");
    fs::write(codex.join("auth.json"), serde_json::to_vec(&auth).unwrap()).unwrap();
    assert_eq!(
        prepare(&mut registry).err().unwrap().reason,
        Reason::CodexApiKeyLogin
    );
    assert!(!nickname_target_is_current_for_user(&pair, user.clone()));
    assert_eq!(
        fs::read_to_string(&witness).unwrap(),
        "--version\n--version\n"
    );
    fs::remove_file(codex.join("auth.json")).unwrap();
    assert!(!nickname_target_is_current_for_user(&pair, user));
    assert_eq!(
        fs::read_to_string(&witness).unwrap(),
        "--version\n--version\n"
    );
    std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
    std::env::remove_var("OTTTO_COMMAND_SEARCH_PATH");
    for key in ambient_keys {
        std::env::remove_var(key);
    }
}

/// [regress] A stale Codex CLI earlier in the search order failed its version
/// probe and blocked the launch while agent status used a desktop-bundled CLI.
#[test]
fn codex_launch_uses_the_bundled_cli_before_a_stale_path_install() {
    if !crate::test_isolation::run_here() {
        return;
    }
    // A real desktop bundle in /Applications would be searched first.
    if ["Codex.app", "ChatGPT.app"]
        .into_iter()
        .any(|bundle| Path::new("/Applications").join(bundle).exists())
    {
        return;
    }
    let scratch = crate::test_scratch::ScratchDir::new("codex-launch-bundle");
    let canonical_root = scratch.canonicalize().expect("canonical scratch directory");
    let root = canonical_root.as_path();
    let (account, org) = codex_login_fixture(root);
    let home = root.join("home");
    let stale = root.join("stale-bin");
    let bundle = home.join("Applications/Codex.app/Contents/Resources");
    for (dir, script) in [
        (&stale, "#!/bin/sh\nexit 1\n"),
        (&bundle, "#!/bin/sh\nprintf 'codex-cli 0.170.0\\n'\n"),
    ] {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("codex"), script).unwrap();
        fs::set_permissions(dir.join("codex"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::env::remove_var("OTTTO_COMMAND_SEARCH_PATH");
    std::env::set_var("PATH", &stale);
    let mut registry = Registry::default();
    let result = registry
        .prepare_for_user(
            Provider::Codex,
            "default",
            &account,
            &org,
            SessionLaunchFolderV1 {
                path: Some(root.join("project").to_string_lossy().into_owned()),
                recent_id: None,
            },
            Some(test_executable()),
            &root.join("support"),
            LaunchUser {
                home,
                name: "synthetic".into(),
            },
        )
        .unwrap();
    assert_eq!(result.outcome, Some(Outcome::Ready));
    assert_eq!(result.cli_version.as_deref(), Some("0.170.0"));
    assert_eq!(
        registry.entries[&result.launch_id.unwrap()].program,
        bundle.join("codex").canonicalize().unwrap()
    );
    std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
}

#[test]
fn version_probe_finds_the_selected_installs_shebang_interpreter() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let scratch = crate::test_scratch::ScratchDir::new("launch-probe-path");
    let root = scratch.as_ref();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    symlink("/bin/sh", bin.join("ottto-synthetic-interpreter")).unwrap();
    let cli = bin.join("claude");
    fs::write(
        &cli,
        "#!/usr/bin/env ottto-synthetic-interpreter\nprintf '2.1.310 (Claude Code)\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
    std::env::set_var("PATH", "/usr/bin:/bin");
    let path = crate::command_env::interactive_probe_path(root, &cli);
    assert_eq!(
        supported_version(&cli, &fixture_binding(root), root, path.as_deref()).unwrap(),
        "2.1.310"
    );
}

#[test]
fn codex_system_configuration_is_presence_refused() {
    let scratch = crate::test_scratch::ScratchDir::new("codex-config-layers");
    let home = scratch.as_ref().join("home");
    let cwd = scratch.as_ref().join("project");
    let system = scratch.as_ref().join("system-codex");
    for path in [&home, &cwd, &system] {
        fs::create_dir(path).unwrap();
    }
    let mut binding = fixture_binding(&home);
    binding.provider = Provider::Codex;
    binding.claude_slot = None;
    binding.root = home.join(".codex");
    assert!(preflight::codex(&binding, &cwd, &system).is_ok());
    // The loader reads .codex/config.toml project files, not an unrelated
    // application config.toml directly in cwd.
    fs::write(
        cwd.join("config.toml"),
        "model_provider = 'unrelated-app'\n",
    )
    .unwrap();
    assert!(preflight::codex(&binding, &cwd, &system).is_ok());
    let path = system.join("config.toml");
    fs::write(&path, "model_provider = 'custom'\n").unwrap();
    let error = preflight::codex(&binding, &cwd, &system).unwrap_err();
    assert_eq!(error.reason, Reason::ConfigUnsupported);
    assert_eq!(
        error.setting_layer,
        Some(ottto_protocol::SessionLaunchSettingLayerV1::Managed)
    );
    fs::remove_file(path).unwrap();
    assert!(preflight::codex(&binding, &cwd, &system).is_ok());
}

#[test]
fn claude_remote_settings_are_validated_not_presence_refused() {
    let scratch = crate::test_scratch::ScratchDir::new("claude-remote-settings");
    let home = scratch.as_ref().join("home");
    let cwd = scratch.as_ref().join("project");
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir(&cwd).unwrap();
    let binding = fixture_binding(&home);
    let path = home.join(".claude/remote-settings.json");
    // Team and Enterprise logins cache organization settings in this file.
    fs::write(&path, r#"{"channelsEnabled":false}"#).unwrap();
    assert!(preflight::evaluate(&binding, &cwd).is_ok());
    fs::write(&path, "{}").unwrap();
    assert!(preflight::evaluate(&binding, &cwd).is_ok());
    fs::write(&path, r#"{"forceLoginMethod":"console"}"#).unwrap();
    let error = preflight::evaluate(&binding, &cwd).unwrap_err();
    assert_eq!(error.reason, Reason::ForcedLoginMethod);
    assert_eq!(
        error.setting_layer,
        Some(ottto_protocol::SessionLaunchSettingLayerV1::Managed)
    );
}

#[test]
fn codex_app_preferences_are_read_for_managed_keys_only() {
    let scratch = crate::test_scratch::ScratchDir::new("codex-user-preferences");
    let home = scratch.as_ref().join("home");
    let cwd = scratch.as_ref().join("project");
    let system = scratch.as_ref().join("system-codex");
    let preferences = home.join("Library/Preferences");
    for path in [&preferences, &cwd, &system] {
        fs::create_dir_all(path).unwrap();
    }
    let mut binding = fixture_binding(&home);
    binding.provider = Provider::Codex;
    binding.claude_slot = None;
    binding.root = home.join(".codex");
    let path = preferences.join("com.openai.codex.plist");
    // The Codex desktop app writes ordinary preferences to this domain.
    let mut app = plist::Dictionary::new();
    app.insert("SUHasLaunchedBefore".into(), plist::Value::Boolean(true));
    plist::Value::Dictionary(app.clone())
        .to_file_binary(&path)
        .unwrap();
    assert!(preflight::codex(&binding, &cwd, &system).is_ok());
    for key in ["config_toml_base64", "requirements_toml_base64"] {
        let mut managed = app.clone();
        managed.insert(key.into(), plist::Value::String("synthetic".into()));
        plist::Value::Dictionary(managed)
            .to_file_xml(&path)
            .unwrap();
        let error = preflight::codex(&binding, &cwd, &system).unwrap_err();
        assert_eq!(error.reason, Reason::ConfigUnsupported, "{key}");
        assert_eq!(
            error.setting_layer,
            Some(ottto_protocol::SessionLaunchSettingLayerV1::Managed)
        );
    }
    fs::write(&path, "not a plist").unwrap();
    let error = preflight::codex(&binding, &cwd, &system).unwrap_err();
    assert_eq!(error.reason, Reason::SettingsMalformed);
}
