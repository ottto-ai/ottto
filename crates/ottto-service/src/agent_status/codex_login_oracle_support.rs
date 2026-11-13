//! Test only: the status side of the Codex login-identity oracle rows
//! (`snapshots/sampled_scan/codex_login_identity_oracle_tests.rs`). Real
//! scratch homes in; the saved-file and collection paths the daemon runs,
//! with no provider and no settings store.
use super::*;

/// What one provider read of a home answers.
pub(crate) enum ProviderRead {
    /// Validated this (account, workspace) hash pair, answered `.2` seconds
    /// ago.
    Bound(String, String, u64),
    /// Named no signed-in user (`account: null` or `auth_rejected`).
    DeadLogin,
    /// Failed for another reason: a gap.
    Failed,
}

/// Saves `read` as a provider read of the managed `home`; `during` runs
/// inside the read (a login written meanwhile).
pub(crate) fn save_read(home: &Path, during: impl FnOnce(), read: ProviderRead) {
    codex_saved_quota::save_read_for_test(home, || {
        during();
        match read {
            ProviderRead::Bound(account_identifier_hash, workspace_identifier_hash, age) => {
                let at = current_unix_seconds().saturating_sub(age) as i64;
                let at = OffsetDateTime::from_unix_timestamp(at)
                    .unwrap()
                    .format(&Rfc3339)
                    .unwrap();
                Ok(CodexUsageProbe {
                    quota_windows: vec![AgentQuotaWindow {
                        name: "primary".to_string(),
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        observed_at: Some(at.clone()),
                        used_percent: Some(42),
                        ..Default::default()
                    }],
                    credit_balances: Vec::new(),
                    account: Some(AgentAccountStatus {
                        login_state: AgentLoginState::SignedIn,
                        plan_type: Some("pro".to_string()),
                        ..unsupported_account("openai")
                    }),
                    provider_account_absent: false,
                    identity: None,
                    saved_identity: Some(CodexIdentityHashes {
                        account_identifier_hash,
                        workspace_identifier_hash,
                        superseded_account_identifier_hash: None,
                        superseded_organization_identifier_hash: None,
                    }),
                    credential_read_failed: false,
                    response_completed_at: Some(at),
                    reset_credit_detail_summary: None,
                    rate_limit_pool_summary: None,
                })
            }
            ProviderRead::DeadLogin => Err(format!(
                "{CODEX_NO_ACCOUNT_FAILURE_PREFIX}Codex app-server account read failed."
            )),
            ProviderRead::Failed => Err("Codex app-server account read failed.".to_string()),
        }
    });
}

/// `body` as `home`'s saved file, as another release wrote it; `{home_key}`
/// stands for the home's key.
pub(crate) fn write_saved(home: &Path, body: &str) {
    codex_saved_quota::write_saved_bytes_for_test(home, body);
}

/// The directory of `home`'s saved file: the saved-quota store's support dir
/// (a per-process scratch dir unless a test chose one) and the home's key.
fn saved_dir(home: &Path) -> PathBuf {
    let support = std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "ottto-codex-saved-quota-tests-{}",
                std::process::id()
            ))
        });
    let dir = support
        .join("codex-quota/homes")
        .join(codex_saved_quota::home_key(home));
    assert!(
        dir.join("saved-quota.json").is_file(),
        "no saved file where the store keeps it"
    );
    dir
}

/// `home`'s saved file as it is on disk.
pub(crate) fn saved_bytes(home: &Path) -> Vec<u8> {
    std::fs::read(saved_dir(home).join("saved-quota.json")).unwrap()
}

/// What a save of `body` leaves when it stops after writing its temp file and
/// before the rename (`write_owner_only_cache_file_atomic`): an owner-only
/// temp file, named as that writer names it, beside the untouched saved file.
/// `{home_key}` as in [`write_saved`].
pub(crate) fn interrupt_save(home: &Path, body: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let before = saved_bytes(home);
    let temp = saved_dir(home).join(format!(
        ".saved-quota.json.tmp.{}.{}.0",
        std::process::id(),
        current_unix_seconds()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .unwrap();
    let body = body.replace("{home_key}", &codex_saved_quota::home_key(home));
    file.write_all(body.as_bytes()).unwrap();
    assert_eq!(saved_bytes(home), before, "the saved file is untouched");
}

/// The collection the Codex status lane publishes for these managed homes,
/// each read from its saved reading; bindings built as
/// `collect_codex_status_snapshots` builds them.
pub(crate) fn collection(homes: &[PathBuf]) -> AgentStatusCollection {
    let (captured_at, expires_at) = ("2026-10-27T08:00:00Z", "2026-10-27T08:15:00Z");
    let candidates = homes
        .iter()
        .enumerate()
        .map(|(index, home)| {
            let slot = CodexHomeSlot {
                slot_id: format!("codex_slot_{index}"),
                ownership: CodexAccountSlotOwnershipV1::Managed,
                home: home.clone(),
                registered_binding: None,
            };
            collect_codex_home_candidate(slot, captured_at, expires_at, CodexQuotaRead::Saved)
        })
        .collect::<Vec<_>>();
    let codex_home_bindings = candidates
        .iter()
        .filter_map(|candidate| {
            let (account_identifier_hash, workspace_identifier_hash) = candidate.binding.clone()?;
            Some(CodexHomeBinding {
                home: candidate.slot.home.clone(),
                account_identifier_hash,
                workspace_identifier_hash,
                auth_modified_at: candidate.auth_modified_at?,
            })
        })
        .collect();
    let source_health_snapshot = codex_source_health_snapshot(&candidates, captured_at, expires_at);
    AgentStatusCollection {
        snapshots: vec![source_health_snapshot.clone()],
        source_health_snapshot,
        codex_scan_homes: homes.to_vec(),
        codex_home_bindings,
    }
}
