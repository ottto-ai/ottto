use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ottto-bootstrap-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn lock(&self) -> ServiceLifecycleTransaction {
        ServiceLifecycleTransaction::acquire(&self.0, Duration::from_secs(1)).unwrap()
    }
    fn config(&self) -> LaunchAgentConfig {
        LaunchAgentConfig::local_user_default(
            &self.0,
            PathBuf::from("/Applications/Ottto.app/Contents/Helpers/ottto-service"),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn failed_mutation_stops_before_later_commands() {
    for fail_at in 0..3 {
        let fixture = Fixture::new();
        let config = fixture.config();
        let mut seen = Vec::new();
        let result = install_with(
            &config,
            &fixture.0.join("agent.plist"),
            false,
            true,
            || Ok(Some(config.executable_path.clone())),
            |args| {
                seen.push(args[1].clone());
                anyhow::ensure!(seen.len() != fail_at + 1, "injected nonzero command");
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(seen.len(), fail_at + 1);
        assert_eq!(seen, ["bootout", "enable", "bootstrap"][..=fail_at]);
    }
}

#[test]
fn unknown_probe_changes_neither_plist_nor_job() {
    let fixture = Fixture::new();
    let plist = fixture.0.join("agent.plist");
    let result = install_with(
        &fixture.config(),
        &plist,
        true,
        true,
        || anyhow::bail!("probe failed"),
        |_| panic!("mutation after unknown probe"),
    );
    assert!(result.is_err());
    assert!(!plist.exists());
    assert!(parse_loaded_program(Some(1), b"").is_err());
    assert!(parse_loaded_program(Some(112), b"").is_err());
    assert_eq!(parse_loaded_program(Some(113), b"").unwrap(), None);
    assert!(parse_loaded_program(Some(0), b"path = /tmp/agent.plist").is_err());
    assert!(parse_loaded_program(None, b"").is_err());
    assert!(parse_loaded_program(Some(0), b"unparseable").is_err());
    assert_eq!(parse_loaded_program(Some(libc::ESRCH), b"").unwrap(), None);
}

#[test]
fn external_owner_keeps_plist_and_job_unchanged() {
    let fixture = Fixture::new();
    let plist = fixture.0.join("agent.plist");
    let mut external = fixture.config();
    external.executable_path = PathBuf::from("/opt/homebrew/opt/ottto/bin/ottto-service");
    macos_service::write_launch_agent(&external, &plist).unwrap();
    let original = fs::read(&plist).unwrap();
    let result = install_with(
        &fixture.config(),
        &plist,
        false,
        true,
        || Ok(Some(external.executable_path.clone())),
        |_| panic!("external job mutated"),
    );
    assert!(result.is_err());
    assert_eq!(fs::read(&plist).unwrap(), original);
    // Also protect a loaded external job when no plist remains on disk.
    fs::remove_file(&plist).unwrap();
    assert!(install_with(
        &fixture.config(),
        &plist,
        false,
        true,
        || Ok(Some(external.executable_path.clone())),
        |_| panic!("external job mutated")
    )
    .is_err());
    assert!(!plist.exists());
}

#[test]
fn nonzero_command_status_is_not_success() {
    let fixture = Fixture::new();
    let lock = fixture.lock();
    let mut calls = 0;
    let config = fixture.config();
    let result = install_with(
        &config,
        &fixture.0.join("agent.plist"),
        false,
        true,
        || Ok(Some(config.executable_path.clone())),
        |_| {
            calls += 1;
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "exit 7"]);
            let (status, _) = lock.run(&mut command, Duration::from_secs(1))?;
            anyhow::ensure!(status.success(), "nonzero: {status}");
            Ok(())
        },
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("installation may be partial"));
    assert_eq!(calls, 1);
}

#[test]
fn busy_preflight_json_is_retryable_and_has_not_written_a_plist() {
    let fixture = Fixture::new();
    let _owner = fixture.lock();
    let busy = ServiceLifecycleTransaction::acquire(&fixture.0, Duration::ZERO)
        .err()
        .unwrap();
    let payload = crate::service_command_error_payload(&busy.context("bootstrap preflight"));
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["error"]["code"], "launch_agent_transaction_busy");
    assert_eq!(payload["error"]["retryable"], true);
    assert_eq!(payload.as_object().unwrap().len(), 2);
    assert_eq!(payload["error"].as_object().unwrap().len(), 3);
    assert!(!fixture.0.join("agent.plist").exists());
}

#[test]
fn actual_failed_decisions_map_to_nonretryable_lifecycle_json() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let probe_error = install_with(
        &config,
        &fixture.0.join("agent.plist"),
        false,
        true,
        || anyhow::bail!("unknown loaded owner"),
        |_| panic!("mutation after failed query"),
    )
    .unwrap_err();
    assert!(!fixture.0.join("agent.plist").exists());
    let mut calls = 0;
    let mutation_error = install_with(
        &config,
        &fixture.0.join("agent.plist"),
        false,
        true,
        || Ok(Some(config.executable_path.clone())),
        |_| {
            calls += 1;
            Err(ottto_core::service_lifecycle::ServiceLifecycleBusy.into())
        },
    )
    .unwrap_err();
    assert_eq!(calls, 1);
    for error in [
        probe_error,
        mutation_error,
        anyhow::anyhow!("unclassified filesystem failure"),
    ] {
        let payload = crate::service_command_error_payload(&error);
        assert_eq!(payload["error"]["code"], "launch_agent_lifecycle_failed");
        assert_eq!(payload["error"]["retryable"], false);
    }
}

#[test]
fn owner_refusal_json_preserves_current_owner_and_specific_repair_hint() {
    for (path, owner, hint) in [
        (
            "/opt/homebrew/opt/ottto/bin/ottto-service",
            "Homebrew",
            "Use brew services restart ottto",
        ),
        (
            "/Users/test/.ottto/bin/ottto-service",
            "hosted-installer",
            "Rerun the hosted installer",
        ),
    ] {
        let fixture = Fixture::new();
        let plist = fixture.0.join("agent.plist");
        let mut external = fixture.config();
        external.executable_path = PathBuf::from(path);
        macos_service::write_launch_agent(&external, &plist).unwrap();
        let before = fs::read(&plist).unwrap();
        let error = install_with(
            &fixture.config(),
            &plist,
            false,
            true,
            || Ok(Some(external.executable_path.clone())),
            |_| panic!("owner refusal mutated job"),
        )
        .unwrap_err();
        assert!(error
            .downcast_ref::<macos_service::LaunchAgentOwnerConflict>()
            .is_some());
        let payload = crate::service_command_error_payload(&error);
        assert_eq!(payload["error"]["code"], "launch_agent_owner_conflict");
        assert_eq!(payload["error"]["retryable"], false);
        let message = payload["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(&format!(
                "existing owner is {owner}, requested owner is app-bundle"
            )),
            "{message}"
        );
        assert!(message.contains(hint), "{message}");
        assert_eq!(fs::read(&plist).unwrap(), before);
    }
}

#[test]
fn explicit_owner_migration_still_allows_the_locked_plan() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let mut calls = Vec::new();
    install_with(
        &config,
        &fixture.0.join("agent.plist"),
        true,
        true,
        || {
            Ok(Some(PathBuf::from(
                "/opt/homebrew/opt/ottto/bin/ottto-service",
            )))
        },
        |args| {
            calls.push(args[1].clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(calls, ["bootout", "enable", "bootstrap"]);
}
