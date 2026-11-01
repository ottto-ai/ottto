//! The status-coverage feed (plan §2a.9) only listens: with it working, with
//! its lock poisoned, and with a conflicting prior history, the same status
//! pass produces byte-identical SOURCE account/plan observations, quota
//! output, source health and persisted slot state.
use super::*;
use crate::claude_status_coverage::{self as coverage, Observation};

fn copy_tree(from: &Path, to: &Path) {
    let _ = fs::remove_dir_all(to);
    fs::create_dir_all(to).expect("create copy root");
    for entry in fs::read_dir(from).expect("read copy source") {
        let entry = entry.expect("copy entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

/// Masks the RFC 3339 instants that fall inside a pass's own wall-clock window
/// (diagnostics stamp "now"); every fixed or input-derived value is compared.
fn mask_wall_clock(text: &str, from: i64, to: i64) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('"') {
        out.push_str(&rest[..=at]);
        rest = &rest[at + 1..];
        let Some(close) = rest.find('"') else { break };
        let value = &rest[..close];
        let masked = OffsetDateTime::parse(value, &Rfc3339)
            .ok()
            .is_some_and(|instant| (from..=to).contains(&instant.unix_timestamp()));
        out.push_str(if masked { "<pass-wall-clock>" } else { value });
        out.push('"');
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

#[test]
#[serial]
fn status_coverage_feed_never_changes_source_or_quota_status_output() {
    let root =
        std::env::temp_dir().join(format!("ottto-status-coverage-feed-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let home = root.join("home");
    let support = root.join("support");
    let pristine = root.join("support-pristine");
    let bin = root.join("bin");
    for dir in [home.join(".claude"), support.clone(), bin.clone()] {
        fs::create_dir_all(dir).expect("create fixture dir");
    }
    // No keychain item: credentials come from the slot's own file.
    let security = bin.join("security");
    fs::write(&security, "#!/bin/sh\nexit 44\n").expect("write fake security");
    let mut permissions = fs::metadata(&security).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&security, permissions).expect("chmod fake security");
    let write_identity = |dir: &Path, account: &str, organization: &str| {
        fs::create_dir_all(dir).expect("create slot dir");
        fs::write(
            dir.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": account,
                    "organizationUuid": organization,
                    "emailAddress": "same@example.invalid",
                    "organizationType": "max",
                    "userRateLimitTier": "default_claude_max_20x"
                }
            }))
            .expect("serialize identity"),
        )
        .expect("write identity");
    };
    let write_credential = |dir: &Path| {
        fs::write(
            dir.join(".credentials.json"),
            serde_json::to_vec(&claude_credential_fixture(
                "fixture",
                TimeDuration::hours(6),
                Some("max"),
            ))
            .expect("serialize credential fixture"),
        )
        .expect("write credential fixture");
    };
    write_identity(&home, "account-default", "organization-default");
    write_credential(&home.join(".claude"));
    let slot_a = root.join("slot-a");
    write_identity(&slot_a, "account-a", "organization-a");
    write_credential(&slot_a);
    let slot_b = root.join("slot-b");
    write_identity(&slot_b, "account-b", "organization-b");
    write_credential(&slot_b);
    // Signed in to an account but no stored login: an unavailable observation.
    let no_login = root.join("slot-no-login");
    write_identity(&no_login, "account-c", "organization-c");

    let _home_guard = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
    let _support_guard = EnvVarGuard::set_os(
        "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
        support.as_os_str().to_os_string(),
    );
    let _command_guard =
        EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string());
    let store = FileClaudeConfigSlotSettingsStore::default();
    for slot in [&slot_a, &slot_b, &no_login] {
        store
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                slot.to_string_lossy().to_string(),
            )
            .expect("register slot");
    }
    // A minute old: input instants never fall inside a pass's masked window.
    let now = current_unix_seconds() - 60;
    let hashes = |account: &str, organization: &str| {
        (
            billing_identity_hash("anthropic", "account", account).expect("account hash"),
            billing_identity_hash("anthropic", "organization", organization).expect("org hash"),
        )
    };
    let (hash_a, org_a) = hashes("account-a", "organization-a");
    let (hash_b, org_b) = hashes("account-b", "organization-b");
    for (account_hash, organization_hash, used) in [(&hash_a, &org_a, 41), (&hash_b, &org_b, 63)] {
        let mut usage = ClaudeOAuthUsage {
            windows: vec![AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                used_percent: Some(used),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        };
        claude_oauth_stamp_account_identity(&mut usage, account_hash, Some(organization_hash));
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_hash.clone(),
            organization_identifier_hash: organization_hash.clone(),
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
            windows: usage.windows,
            credit_balances: usage.credit_balances,
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        })
        .expect("write usage cache");
    }
    copy_tree(&support, &pristine);

    // One status pass from the same pristine state; every output it produces.
    let pass = || {
        copy_tree(&pristine, &support);
        let from = OffsetDateTime::now_utc().unix_timestamp();
        let collection = collect_agent_status_collection(
            &SourceKind::ClaudeCode,
            "2026-10-12T08:00:00Z".to_string(),
            "2026-10-12T08:15:00Z".to_string(),
        );
        let backend = collection
            .snapshots
            .iter()
            .map(|snapshot| snapshot.clone().redacted_for_backend())
            .collect::<Vec<_>>();
        let plan_observations = collection
            .snapshots
            .iter()
            .map(|snapshot| {
                (
                    serde_json::to_string(&snapshot.account).expect("account"),
                    serde_json::to_string(&snapshot.plan_observations).expect("plans"),
                )
            })
            .collect::<Vec<_>>();
        let to = OffsetDateTime::now_utc().unix_timestamp();
        let mask = |text: String| mask_wall_clock(&text, from, to);
        (
            mask(serde_json::to_string(&backend).expect("backend wire")),
            mask(serde_json::to_string(&collection.snapshots).expect("local snapshots")),
            plan_observations
                .into_iter()
                .map(|(account, plans)| (mask(account), mask(plans)))
                .collect::<Vec<_>>(),
            mask(serde_json::to_string(&collection.source_health_snapshot).expect("health")),
            mask(
                String::from_utf8(
                    fs::read(claude_slot_collection_state_path()).expect("persisted slot state"),
                )
                .expect("utf-8 slot state"),
            ),
        )
    };

    coverage::clear_global_for_test();
    let working = pass();
    // The feed did run: qualified pairings for both healthy slots only, never
    // the default folder or the slot without a stored login.
    let pairings = coverage::with_global(|ledger| {
        ledger
            .pairings()
            .map(|(login, org)| (login.to_string(), org.to_string()))
            .collect::<BTreeSet<_>>()
    });
    assert_eq!(
        pairings,
        BTreeSet::from([
            (hash_a.clone(), org_a.clone()),
            (hash_b.clone(), org_b.clone())
        ])
    );
    // The pass recorded the registered folders, never the default one.
    coverage::with_global(|ledger| {
        for slot in [&slot_a, &slot_b, &no_login] {
            assert_eq!(ledger.is_registered(&coverage::home_key(slot)), Some(true));
        }
        assert_eq!(
            ledger.is_registered(&coverage::home_key(&home.join(".claude"))),
            Some(false)
        );
    });
    // SOURCE outputs are really in the fixture.
    assert!(working.0.contains(&hash_a) && working.0.contains(&hash_b));
    assert!(working.2.iter().any(|(_, plans)| plans != "[]"));

    coverage::poison_global_for_test();
    let failed = pass();
    assert!(coverage::snapshot().is_none(), "feed stayed failed");
    coverage::clear_global_for_test();

    // A conflicting, regressed prior history for the same folders.
    coverage::with_global(|ledger| {
        for slot in [&slot_a, &slot_b] {
            ledger.observe_at(
                coverage::home_key(slot),
                [9; 32],
                Some(u64::MAX / 2),
                Observation::Qualified {
                    login: &"c".repeat(64),
                    org: &"d".repeat(64),
                },
            );
        }
    });
    let conflicting = pass();
    coverage::clear_global_for_test();

    assert_eq!(failed, working, "a failed feed changes no status byte");
    assert_eq!(conflicting, working, "feed history changes no status byte");
    let _ = fs::remove_dir_all(root);
}
