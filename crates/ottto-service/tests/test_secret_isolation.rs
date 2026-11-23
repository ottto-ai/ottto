//! Verify the core crate's test isolation when it is built as a dependency,
//! where cfg(test) alone cannot protect the host Keychain.
use ottto_core::token_store::{isolated_test_secret_dir, test_secret_store_enabled};
use ottto_core::{ControlTokenStore, KeychainSecretStore, TokenStoreError};
use ottto_protocol::SourceKind;
use ottto_service::keychain::{TelemetryKeyStore, TELEMETRY_KEY_FILE_STORE_ENV};

#[test]
fn missing_fixture_overrides_never_use_host_credentials() {
    const CHILD: &str = "OTTTO_SECRET_ISOLATION_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // A separate process avoids racing the suite's environment guards.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "missing_fixture_overrides_never_use_host_credentials",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove(ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV)
            .env_remove(TELEMETRY_KEY_FILE_STORE_ENV)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Assert the compile-time boundary before attempting any credential call.
    assert!(test_secret_store_enabled());
    let root = isolated_test_secret_dir().unwrap();
    assert!(!root.starts_with(ottto_core::default_support_dir()));
    for account in [
        ottto_core::OTTTO_KEYCHAIN_ACCOUNT,
        ottto_core::OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
        ottto_core::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
        ottto_core::token_store::OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT,
        ottto_core::token_store::OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT,
        ottto_core::token_store::OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT,
    ] {
        let store = KeychainSecretStore::new(account);
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
        store.save("synthetic-test-secret").unwrap();
        assert_eq!(store.load().unwrap(), "synthetic-test-secret");
        assert!(root.join(account).exists());
        store.delete().unwrap();
        assert!(matches!(store.load(), Err(TokenStoreError::Missing)));
    }

    let telemetry = TelemetryKeyStore::production();
    assert_eq!(telemetry.latest_key_id(&SourceKind::Codex).unwrap(), None);
    telemetry
        .save(&SourceKind::Codex, "test-key", "synthetic-telemetry-secret")
        .unwrap();
    assert_eq!(
        telemetry.load(&SourceKind::Codex, "test-key").unwrap(),
        "synthetic-telemetry-secret"
    );
    assert!(root.join("telemetry-keys").exists());
    let swept = telemetry.sweep_all().unwrap();
    assert_eq!(swept.removed.len(), 1);
    assert!(swept.removed_unindexed_services.is_empty());
    assert!(swept.warnings.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}
