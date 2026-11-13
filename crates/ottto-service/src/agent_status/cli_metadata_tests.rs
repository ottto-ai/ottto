use super::*;

/// [behaviour] A reaped child's cached status prevents a later PID kill.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_child_kill_preserves_cached_exit() {
    let (root, _) = cli_meta_fixture("cli-meta-child-exit");
    let binary = root.join("codex");
    fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
    let mut command = Command::new(binary);
    let mut child = crate::local_resource_diagnostics::cli_children::spawn(&mut command).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
    assert_eq!(child.try_wait().unwrap(), Some(status));
    assert_eq!(
        child.kill().unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(child.wait().unwrap(), status);
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Metadata input stamps, setup reads and age invalidate reuse.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_cache_input_changes() {
    let (root, home) = cli_meta_fixture("cli-meta-inputs");
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let starts = || {
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count()
    };
    let read = || {
        assert!(codex_cli_meta(&home, false, true).0.is_ok());
    };
    read();
    for (i, row) in ["binary", "auth", "config", "age", "setup"]
        .iter()
        .enumerate()
    {
        match *row {
            "binary" => {
                let binary = root.join("codex");
                let script = fs::read_to_string(&binary).unwrap();
                fs::write(binary, format!("{script}\n# upgraded\n")).unwrap();
            }
            "auth" => fs::write(home.join("auth.json"), "{ \"tokens\": {} }").unwrap(),
            "config" => fs::write(home.join("config.toml"), "model = \"gpt-5\"\n").unwrap(),
            "age" => {
                CODEX_CLI_META
                    .get()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .kept
                    .get_mut(&home)
                    .unwrap()
                    .1
                    .loaded_at = Instant::now() - CLI_META_MAX_AGE;
            }
            "setup" => {}
            _ => unreachable!(),
        }
        if *row == "setup" {
            crate::provider_calls::with_trigger(crate::provider_calls::Trigger::Setup, read);
        } else {
            read();
        }
        read();
        assert_eq!(starts(), 4 + 2 * i, "{row} reruns then reuses");
    }
    fs::remove_file(home.join("auth.json")).unwrap();
    read();
    read();
    assert_eq!(starts(), 16, "absent auth never reuses");
    assert!(!CODEX_CLI_META
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .kept
        .contains_key(&home));
    fs::write(home.join("auth.json"), "{}").unwrap();
    read();
    let mut cache = CODEX_CLI_META.get().unwrap().lock().unwrap();
    cache.retain_listed(&BTreeSet::new());
    assert!(!cache.kept.contains_key(&home), "removed home evicted");
    drop(cache);
    read();
    assert_eq!(starts(), 20, "evicted home reruns");
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Nonzero and unparsed CLI results never cache.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_cache_failures_are_not_kept() {
    let (root, home) = cli_meta_fixture("cli-meta-failure");
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let binary = root.join("codex");
    let successful = fs::read_to_string(&binary).unwrap();
    for row in ["nonzero", "stderr-nonzero", "unparsed", "models-unparsed"] {
        let script = match row {
            "nonzero" => successful.replace(
                "print(\"Logged in\")",
                "print(\"not logged in\"); sys.exit(1)",
            ),
            "stderr-nonzero" => successful.replace(
                "print(\"Logged in\")",
                "print(\"Not logged in\", file=sys.stderr); sys.exit(1)",
            ),
            "unparsed" => successful.replace("Logged in", "unrecognized"),
            _ => successful.replace("gpt-5", "unrecognized"),
        };
        fs::write(&binary, script).unwrap();
        for _ in 0..2 {
            let _ = codex_cli_meta(&home, false, true);
        }
        assert!(
            !CODEX_CLI_META
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .kept
                .contains_key(&home),
            "{row}"
        );
    }
    assert_eq!(
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count(),
        16
    );
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] A loader error is never retained, regardless of runner cause.
#[test]
fn cli_metadata_loader_error_is_not_cached() {
    use crate::transcript_acquisition::SourceStamp;
    let cache = Mutex::new(CliFacts::<u8, (), 1>::default());
    let mut runs = 0;
    for _ in 0..2 {
        let result = cli_meta(
            &cache,
            0,
            || Ok([SourceStamp::Absent]),
            || {
                runs += 1;
                Err::<(), _>(())
            },
            Instant::now(),
            false,
        );
        assert!(result.is_err());
    }
    assert_eq!(runs, 2);
    assert!(cache.lock().unwrap().kept.is_empty());
}

/// [behaviour] Identity-bearing CLI text retains its fresh legacy fallback.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_identity_text_stays_fresh() {
    let (root, home) = cli_meta_fixture("cli-meta-identity");
    let binary = root.join("codex");
    let script = fs::read_to_string(&binary)
        .unwrap()
        .replace("Logged in", "Logged in owner@example.invalid pro");
    fs::write(binary, script).unwrap();
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    // Keep all auth claims except email: main fills exactly that field from CLI.
    let mut auth: Value =
        serde_json::from_slice(&fs::read(home.join("auth.json")).unwrap()).unwrap();
    let token = auth["tokens"]["id_token"].as_str().unwrap().to_string();
    let mut parts = token.split('.');
    let header = parts.next().unwrap();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap()).unwrap();
    claims.as_object_mut().unwrap().remove("email");
    auth["tokens"]["id_token"] = Value::String(format!(
        "{header}.{}.synthetic-signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    ));
    fs::write(home.join("auth.json"), serde_json::to_vec(&auth).unwrap()).unwrap();
    for _ in 0..2 {
        let (snapshot, _, _) = collect_codex_status_for_home(
            "2026-08-26T00:00:00Z".to_string(),
            "2026-08-26T00:15:00Z".to_string(),
            &home,
            CodexHomeTrust::ProviderDefault,
            CodexQuotaRead::Saved,
        );
        let account = snapshot.account.unwrap();
        assert_eq!(account.email.as_deref(), Some("owner@example.invalid"));
        assert_eq!(account.plan_type.as_deref(), Some("pro"));
        assert_eq!(account.subscription_product.as_deref(), Some("chatgpt_pro"));
        assert_eq!(account.billing_channel.as_deref(), Some("subscription"));
    }
    assert_eq!(
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count(),
        4
    );
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Complete auth reuses login and matches main's full account merge.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_complete_auth_matches_legacy_merge() {
    let (root, home) = cli_meta_fixture("cli-meta-complete-auth");
    let binary = root.join("codex");
    let cli_text = "Logged in fallback@example.invalid plus";
    let script = fs::read_to_string(&binary)
        .unwrap()
        .replace("Logged in", cli_text);
    fs::write(binary, script).unwrap();
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let expected = merge_codex_accounts(
        parse_codex_account_text(cli_text),
        read_codex_auth_account_at(&home, CodexHomeTrust::ProviderDefault)
            .unwrap()
            .unwrap(),
    );
    for _ in 0..2 {
        let (snapshot, _, _) = collect_codex_status_for_home(
            "2026-08-26T00:00:00Z".to_string(),
            "2026-08-26T00:15:00Z".to_string(),
            &home,
            CodexHomeTrust::ProviderDefault,
            CodexQuotaRead::Saved,
        );
        assert_eq!(snapshot.account.as_ref(), Some(&expected));
    }
    assert_eq!(
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Version reuse follows only Claude's binary, not home files.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_cache_claude_binary() {
    let (root, home) = cli_meta_fixture("cli-meta-claude");
    let binary = root.join("claude");
    let script = format!(
        "#!/bin/sh\necho start >> '{}'\n",
        home.join("starts").display()
    );
    fs::write(&binary, &script).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    assert!(claude_version_detected());
    assert!(claude_version_detected());
    fs::write(home.join("config.toml"), "unrelated = true").unwrap();
    assert!(claude_version_detected());
    assert_eq!(
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    fs::write(&binary, format!("{script}# upgrade\n")).unwrap();
    assert!(claude_version_detected());
    assert_eq!(
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Shared witnesses never follow symlinks or keep racing loads.
#[cfg(unix)]
#[test]
fn cli_metadata_source_stamps() {
    use crate::transcript_acquisition::{SourceStamp, StampedFacts};
    let root = std::env::temp_dir().join(format!("ottto-cli-stamps-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("source");
    assert!(matches!(
        SourceStamp::capture_file(&path).unwrap(),
        SourceStamp::Absent
    ));
    assert!(SourceStamp::capture_file(&root).is_err());
    fs::write(&path, "a").unwrap();
    let a = SourceStamp::capture_file(&path).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(SourceStamp::capture_file(&link).is_err());
    let mut cache = StampedFacts::default();
    let mut runs = 0;
    for _ in 0..2 {
        let facts = cache
            .reuse_or_load(
                0,
                || SourceStamp::capture_file(&path),
                || {
                    runs += 1;
                    Ok::<_, ()>(7)
                },
            )
            .unwrap();
        assert_eq!(facts, 7);
    }
    assert_eq!(runs, 1);
    fs::write(&path, "changed").unwrap();
    assert!(!a.same(&SourceStamp::capture_file(&path).unwrap()));
    cache
        .reuse_or_load(
            0,
            || SourceStamp::capture_file(&path),
            || {
                fs::write(&path, "changed during load").unwrap();
                Ok::<_, ()>(8)
            },
        )
        .unwrap();
    assert!(cache.kept.is_empty(), "before differs from after");
    for _ in 0..2 {
        assert!(cache
            .reuse_or_load(0, || SourceStamp::capture_file(&path), || Err::<i32, _>(()))
            .is_err());
    }
    assert!(cache.kept.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
fn cli_meta_fixture(label: &str) -> (PathBuf, PathBuf) {
    let (root, home) = synthetic_codex_collector_home(label, 0o600);
    let binary = root.join("codex");
    let script = fs::read_to_string(&binary).unwrap().replace(
        "import sys", "import sys, os\nif sys.argv[1:] in ([\"login\", \"status\"], [\"debug\", \"models\", \"--bundled\"]):\n    with open(os.path.join(os.environ[\"CODEX_HOME\"], \"starts\"), \"a\") as f: f.write(\"start\\n\")"
    ).replace("synthetic-model", "gpt-5");
    fs::write(binary, script).unwrap();
    (root, home)
}

/// [regress] Repeated status collection must not spawn unchanged CLI metadata.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_cache_hit_skips_spawn() {
    let (root, home) = cli_meta_fixture("cli-meta-hit");
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        crate::local_resource_diagnostics::source_prepare(
            "codex",
            || {
                for _ in 0..2 {
                    let (snapshot, _, _) = collect_codex_status_for_home(
                        "2026-08-26T00:00:00Z".to_string(),
                        "2026-08-26T00:15:00Z".to_string(),
                        &home,
                        CodexHomeTrust::ProviderDefault,
                        CodexQuotaRead::Saved,
                    );
                    assert_eq!(
                        snapshot.account.unwrap().login_state,
                        AgentLoginState::SignedIn
                    );
                }
            },
            |_| false,
        );
    });
    assert!(rows
        .iter()
        .filter(|r| r["observation"].get("cli_children").is_some())
        .all(|r| r["stage"] == "source_prepare"));
    let children = rows.last().unwrap()["observation"]["cli_children"]
        .as_array()
        .unwrap();
    for argv in ["codex login status", "codex models"] {
        let counts = children
            .iter()
            .find(|counts| counts["argv"] == argv)
            .unwrap();
        assert_eq!(counts["starts"], 1, "{argv}");
        assert!(counts["cpu_us"].as_u64().unwrap() > 0, "{argv} child CPU");
    }
    assert_eq!(
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count(),
        2,
        "unchanged login/models must spawn once each"
    );
    fs::remove_dir_all(root).unwrap();
}

/// [regress] Codex prints `login status` to stderr: unchanged inputs reuse it
/// and return the fresh result; incomplete auth keeps today's account surface.
#[cfg(unix)]
#[test]
#[serial]
fn cli_metadata_stderr_login_status_is_cached() {
    let (root, home) = cli_meta_fixture("cli-meta-stderr");
    let binary = root.join("codex");
    let script = fs::read_to_string(&binary).unwrap().replace(
        "print(\"Logged in\")",
        "print(\"Logged in using ChatGPT\", file=sys.stderr)",
    );
    fs::write(binary, script).unwrap();
    let _commands =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
    let starts = || {
        fs::read_to_string(home.join("starts"))
            .unwrap()
            .lines()
            .count()
    };
    let collect = || {
        let (snapshot, _, _) = collect_codex_status_for_home(
            "2026-08-26T00:00:00Z".to_string(),
            "2026-08-26T00:15:00Z".to_string(),
            &home,
            CodexHomeTrust::ProviderDefault,
            CodexQuotaRead::Saved,
        );
        serde_json::to_value((&snapshot.account, &snapshot.model, &snapshot.status)).unwrap()
    };
    let first = collect();
    assert_eq!(collect(), first);
    assert_eq!(
        starts(),
        2,
        "unchanged stderr login status spawns once each"
    );
    CODEX_CLI_META.get().unwrap().lock().unwrap().kept.clear();
    assert_eq!(collect(), first, "cache hit equals a fresh load");
    assert_eq!(starts(), 4);
    assert_eq!(first[0]["login_state"], "signed_in");
    let (login, _, account) = codex_cli_meta(&home, false, false);
    assert!(
        login.is_err() && account.is_none(),
        "bypass parses stdout only"
    );
    let stderr = |text: &str| CommandOutput {
        command_found: true,
        success: false,
        status_code: Some(1),
        stdout: String::new(),
        stderr: text.to_string(),
    };
    assert_eq!(
        parse_codex_account_text(&command_output_text(&stderr("Not logged in")))
            .unwrap()
            .login_state,
        AgentLoginState::SignedOut
    );
    fs::remove_dir_all(root).unwrap();
}
