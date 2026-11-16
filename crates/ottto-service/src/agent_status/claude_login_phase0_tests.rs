//! Tests for local Claude login evidence and credential expiry.
//! Loaded by the agent-status module under its existing test gate.
//! Uses isolated provider stand-ins and temporary slot fixtures.

use super::*;
use serial_test::serial;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;

struct Guard {
    key: &'static str,
    previous: Option<OsString>,
}

impl Guard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

struct ForbidProviderCalls;

impl ForbidProviderCalls {
    fn new() -> Self {
        CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for ForbidProviderCalls {
    fn drop(&mut self) {
        CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.store(false, Ordering::SeqCst);
    }
}

fn provider_calls() -> usize {
    CLAUDE_OAUTH_PROVIDER_CALLS.load(Ordering::SeqCst)
}

const DEFAULT_ACCOUNT: (&str, &str) = ("account-default", "organization-default");
const SLOT_ACCOUNTS: [(&str, &str); 3] = [
    ("account-slot-a", "organization-slot-a"),
    ("account-slot-b", "organization-slot-b"),
    ("account-slot-c", "organization-slot-c"),
];

struct Phase0Fixture {
    root: PathBuf,
    items: PathBuf,
    spawn_log: PathBuf,
    security_log: PathBuf,
    slot_dirs: Vec<PathBuf>,
    slot_ids: Vec<String>,
    _forbid: ForbidProviderCalls,
    _guards: Vec<Guard>,
}

impl Phase0Fixture {
    /// `managed` registers the slots as Ottto-managed anchors.
    fn new(label: &str, managed: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-phase0-{label}-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let home = root.join("home");
        let support = root.join("support");
        let bin = root.join("bin");
        let items = root.join("keychain-items");
        for dir in [&home.join(".claude"), &support, &bin, &items] {
            fs::create_dir_all(dir).expect("fixture dir");
        }
        let spawn_log = root.join("claude-spawns.log");
        let security_log = root.join("security-reads.log");
        let claude = bin.join("claude");
        fs::write(
            &claude,
            format!(
                "#!/bin/sh\necho \"$CLAUDE_CONFIG_DIR|$*\" >> '{}'\n[ \"$1\" = \"--version\" ] && echo 2.1.288\nexit 0\n",
                spawn_log.display()
            ),
        )
        .expect("fake claude");
        let security = bin.join("security");
        fs::write(
            &security,
            format!(
                r#"#!/bin/sh
service=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-s" ]; then service="$2"; shift; fi
  shift
done
echo "$service" >> '{log}'
if [ -f '{items}'/"$service.json" ]; then
  /bin/cat '{items}'/"$service.json"
  exit 0
fi
exit 44
"#,
                log = security_log.display(),
                items = items.display()
            ),
        )
        .expect("fake security");
        for executable in [&claude, &security] {
            let mut permissions = fs::metadata(executable).expect("meta").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(executable, permissions).expect("chmod");
        }
        let guards = vec![
            Guard::set("HOME", &home),
            Guard::set("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &home),
            Guard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            Guard::set("OTTTO_COMMAND_SEARCH_PATH", &bin),
        ];
        // "Keep my Claude accounts signed in" off: these passes must start
        // no Claude process at all. Refresher tests turn it on.
        let store = FileClaudeConfigSlotSettingsStore::default();
        store
            .set_upkeep_consent(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                false,
            )
            .expect("consent");
        let mut fixture = Self {
            root: root.clone(),
            items,
            spawn_log,
            security_log,
            slot_dirs: Vec::new(),
            slot_ids: Vec::new(),
            _forbid: ForbidProviderCalls::new(),
            _guards: guards,
        };
        fixture.write_identity(&home, DEFAULT_ACCOUNT);
        for (index, account) in SLOT_ACCOUNTS.iter().enumerate() {
            let dir = root.join(format!("slot-{index}"));
            fs::create_dir_all(&dir).expect("slot dir");
            fixture.write_identity(&dir, *account);
            let status = if managed {
                store.register_managed_path(
                    ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                    dir.to_string_lossy().to_string(),
                )
            } else {
                store.register_path(
                    ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                    dir.to_string_lossy().to_string(),
                )
            }
            .expect("register slot");
            let slot_id = status
                .managed_slots
                .iter()
                .chain(status.external_slots.iter())
                .find(|slot| slot.config_dir.as_deref() == dir.to_str())
                .expect("registered")
                .slot_id
                .clone();
            fixture.slot_dirs.push(dir);
            fixture.slot_ids.push(slot_id);
        }
        for account in std::iter::once(DEFAULT_ACCOUNT).chain(SLOT_ACCOUNTS) {
            fixture.write_cache(account, 0);
        }
        fixture
    }

    fn write_identity(&self, dir: &Path, (account, organization): (&str, &str)) {
        fs::write(
            dir.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": account,
                    "organizationUuid": organization,
                    "emailAddress": format!("{account}@example.invalid"),
                    "organizationType": "claude_max"
                }
            }))
            .expect("identity"),
        )
        .expect("write identity");
    }

    fn hashes((account, organization): (&str, &str)) -> (String, String) {
        (
            billing_identity_hash("anthropic", "account", account).expect("hash"),
            billing_identity_hash("anthropic", "organization", organization).expect("hash"),
        )
    }

    /// A usage cache `age_seconds` old. Age 0 is served without a request.
    fn write_cache(&self, account: (&str, &str), age_seconds: u64) {
        let (account_hash, organization_hash) = Self::hashes(account);
        let now = current_unix_seconds();
        // Distinct meters per account: identical readings on two accounts
        // are quarantined as a cross-account collision.
        let percent =
            u8::try_from(account.0.bytes().map(u32::from).sum::<u32>() % 90 + 5).expect("percent");
        let mut usage = ClaudeOAuthUsage {
            windows: ["session", "weekly"]
                .into_iter()
                .map(|name| AgentQuotaWindow {
                    name: name.to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    status: AgentQuotaWindowStatus::Ok,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    used_percent: Some(percent),
                    ..Default::default()
                })
                .chain(std::iter::once(AgentQuotaWindow {
                    name: "weekly_sonnet".to_string(),
                    scope: AgentQuotaWindowScope::Model,
                    status: AgentQuotaWindowStatus::Ok,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    model: Some("claude-sonnet".to_string()),
                    used_percent: Some(percent),
                    ..Default::default()
                }))
                .collect(),
            credit_balances: Vec::new(),
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        };
        claude_oauth_stamp_account_identity(&mut usage, &account_hash, Some(&organization_hash));
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_hash,
            organization_identifier_hash: organization_hash,
            observed_at_epoch_seconds: now - age_seconds,
            next_refresh_after_epoch_seconds: if age_seconds == 0 {
                now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS
            } else {
                now - 1
            },
            windows: usage.windows,
            credit_balances: usage.credit_balances,
            account_weekly_not_offered: false,
            account_session_not_offered: false,
        })
        .expect("write cache");
    }

    fn item(&self, slot: &ClaudeConfigDirSlot, expires_in: TimeDuration) {
        self.item_token(slot, expires_in, "fixture-access");
    }

    /// The slot's stored login, with its own access token.
    fn item_token(&self, slot: &ClaudeConfigDirSlot, expires_in: TimeDuration, token: &str) {
        let credential = serde_json::json!({
            "claudeAiOauth": {
                "accessToken": token,
                "refreshToken": "fixture-refresh",
                "expiresAt": (OffsetDateTime::now_utc() + expires_in).unix_timestamp() * 1_000,
                "refreshTokenExpiresAt":
                    (OffsetDateTime::now_utc() + TimeDuration::days(25)).unix_timestamp() * 1_000,
                "scopes": ["user:inference", "user:profile"],
                "subscriptionType": "max"
            }
        });
        self.write_login(slot, &credential);
    }

    /// Stores `credential` where Claude Code keeps this slot's login: the
    /// fake keychain item macOS reads and the native credentials file
    /// (mode `0o600`) other platforms read.
    fn write_login(&self, slot: &ClaudeConfigDirSlot, credential: &Value) {
        let body = serde_json::to_vec(credential).expect("item");
        fs::write(
            self.items.join(format!("{}.json", slot.service_name())),
            &body,
        )
        .expect("write item");
        let native = slot.credentials_path(&self.root.join("home"));
        fs::create_dir_all(native.parent().expect("credentials dir")).expect("credentials dir");
        crate::test_scratch::write_private_file(native, body);
    }

    fn slot(&self, index: usize) -> ClaudeConfigDirSlot {
        ClaudeConfigDirSlot::registered(self.slot_dirs[index].to_string_lossy().to_string())
            .expect("slot")
    }

    fn set_all_expiries(&self, expires_in: TimeDuration) {
        self.item(&ClaudeConfigDirSlot::Default, expires_in);
        for index in 0..self.slot_dirs.len() {
            self.item(&self.slot(index), expires_in);
        }
    }

    fn collect(&self) -> AgentStatusCollection {
        let now = OffsetDateTime::now_utc();
        collect_agent_status_collection(
            &SourceKind::ClaudeCode,
            now.format(&Rfc3339).expect("time"),
            (now + TimeDuration::minutes(15))
                .format(&Rfc3339)
                .expect("time"),
        )
    }

    fn status(&self) -> ClaudeAccountsStatusV1 {
        annotate_claude_accounts_status(
            FileClaudeConfigSlotSettingsStore::default()
                .load()
                .expect("load slots"),
        )
    }

    fn slot_collection(&self, index: usize) -> ClaudeConfigSlotCollectionStatusV1 {
        let status = self.status();
        status
            .managed_slots
            .iter()
            .chain(status.external_slots.iter())
            .find(|slot| slot.slot_id == self.slot_ids[index])
            .expect("slot status")
            .collection
            .clone()
    }

    fn spawns(&self) -> Vec<String> {
        fs::read_to_string(&self.spawn_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn security_reads(&self) -> Vec<String> {
        fs::read_to_string(&self.security_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn clear_logs(&self) {
        let _ = fs::remove_file(&self.spawn_log);
        let _ = fs::remove_file(&self.security_log);
    }
}

impl Drop for Phase0Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_only_version_probes(spawns: &[String], context: &str) {
    assert!(
        spawns.iter().all(|line| line == "|--version"),
        "{context}: only `claude --version` on the default target may run: {spawns:?}"
    );
}

/// T3: full status passes for the default login plus three slots across
/// the expiry boundary spawn nothing but `--version`, and read each
/// login's keychain item once per pass on macOS (its native credentials
/// file elsewhere, never running `security`).
#[test]
#[serial]
fn status_passes_spawn_only_version_probes_across_the_expiry_boundary() {
    let fixture = Phase0Fixture::new("no-spawn", false);
    let calls_before = provider_calls();
    for (label, expires_in) in [
        ("T-14min", TimeDuration::minutes(14)),
        ("T-1min", TimeDuration::minutes(1)),
        ("T+1min", -TimeDuration::minutes(1)),
        ("T+8h", -TimeDuration::hours(8)),
        ("after-wake", -TimeDuration::minutes(30)),
    ] {
        fixture.clear_logs();
        fixture.set_all_expiries(expires_in);
        fixture.collect();
        let spawns = fixture.spawns();
        assert_only_version_probes(&spawns, label);
        assert!(
            spawns.iter().all(|line| fixture
                .slot_dirs
                .iter()
                .all(|dir| !line.contains(dir.to_str().unwrap()))),
            "{label}: zero slot spawns"
        );
        let reads = fixture.security_reads();
        if claude_credentials_in_keychain() {
            for slot in std::iter::once(ClaudeConfigDirSlot::Default)
                .chain((0..3).map(|index| fixture.slot(index)))
            {
                assert_eq!(
                    reads
                        .iter()
                        .filter(|service| **service == slot.service_name())
                        .count(),
                    1,
                    "{label}: one keychain read per login per pass: {reads:?}"
                );
            }
        } else {
            // Off macOS each login comes from its native credentials
            // file; the `security` on the search path never runs.
            assert!(reads.is_empty(), "{label}: no keychain tool: {reads:?}");
        }
        let expired = expires_in <= TimeDuration::seconds(CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS);
        for index in 0..3 {
            let collection = fixture.slot_collection(index);
            if expired {
                let expected_state = ClaudeConfigSlotCollectionStateV1::RefreshDue;
                assert_eq!(collection.state, expected_state, "{label}");
                assert_ne!(
                    collection.state,
                    ClaudeConfigSlotCollectionStateV1::StaleAccessToken
                );
            } else {
                assert_eq!(
                    collection.state,
                    ClaudeConfigSlotCollectionStateV1::Fresh,
                    "{label}"
                );
            }
        }
    }
    assert_eq!(
        provider_calls(),
        calls_before,
        "every reading came from cache"
    );

    // The connect workflow's single-slot check and identity proof read
    // local metadata only.
    fixture.clear_logs();
    fixture.set_all_expiries(TimeDuration::hours(3));
    let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("time");
    let proof = verify_claude_local_identity(
        &fixture.slot_ids[0],
        fixture.slot_dirs[0].to_str().expect("utf8"),
        &now,
    )
    .expect("identity proof from local metadata");
    assert_eq!(
        proof.account_identifier_hash,
        Phase0Fixture::hashes(SLOT_ACCOUNTS[0]).0
    );
    let single = collect_registered_claude_slot_status(&fixture.slot_ids[1], now.clone(), now);
    assert_eq!(single.state, ClaudeConfigSlotCollectionStateV1::Fresh);
    assert!(fixture.spawns().is_empty(), "no `claude` of any kind");
}

/// "Keep my Claude accounts signed in" on: an expiring slot gets exactly
/// one background refresher (`-p /usage --no-session-persistence
/// --strict-mcp-config`, in the slot's own config dir) and shows a refresh
/// in progress. This fake refresher does not advance the expiry but
/// leaves the login intact, so one retry follows on a pass at least five
/// minutes later; after it fails too the slot asks to sign in again and
/// no third refresher starts.
#[test]
#[serial]
fn expiring_slot_gets_one_background_refresher_then_sign_in_again_on_failure() {
    let fixture = Phase0Fixture::new("refresher", false);
    FileClaudeConfigSlotSettingsStore::default()
        .set_upkeep_consent(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            true,
        )
        .expect("keep signed in");
    fixture.set_all_expiries(TimeDuration::hours(3));
    fixture.collect();
    assert_eq!(
        fixture.slot_collection(0).state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );
    fixture.clear_logs();
    fixture.item(&fixture.slot(0), -TimeDuration::minutes(2));
    fixture.collect();
    let collection = fixture.slot_collection(0);
    assert_eq!(
        collection.state,
        ClaudeConfigSlotCollectionStateV1::RefreshDue
    );
    assert_eq!(
        collection.upkeep.as_ref().map(|upkeep| upkeep.result),
        Some(ClaudeConfigSlotUpkeepResultV1::InProgress)
    );
    crate::claude_refresher::wait_until_idle(&fixture.slot_ids[0]);
    let slot_dir = fixture.slot_dirs[0].to_string_lossy().to_string();
    let refreshers = fixture
        .spawns()
        .into_iter()
        .filter(|line| line != "|--version")
        .collect::<Vec<_>>();
    assert_eq!(
        refreshers,
        vec![format!(
            "{slot_dir}|-p /usage --no-session-persistence --strict-mcp-config"
        )],
        "exactly one refresher, for the expiring slot only"
    );

    // First failure, login intact: the retry waits for a later pass.
    fixture.collect();
    assert_eq!(
        fixture
            .slot_collection(0)
            .upkeep
            .as_ref()
            .map(|upkeep| upkeep.result),
        Some(ClaudeConfigSlotUpkeepResultV1::InProgress)
    );
    assert_eq!(
        fixture
            .spawns()
            .into_iter()
            .filter(|line| line != "|--version")
            .count(),
        1,
        "the retry is not immediate"
    );
    crate::claude_refresher::backdate_failure_for_test(
        &fixture.slot_ids[0],
        crate::claude_refresher::RETRY_AFTER,
    );
    fixture.collect();
    crate::claude_refresher::wait_until_idle(&fixture.slot_ids[0]);
    assert_eq!(
        fixture
            .spawns()
            .into_iter()
            .filter(|line| line != "|--version")
            .count(),
        2,
        "exactly one retry"
    );

    fixture.collect();
    let after = fixture.slot_collection(0);
    assert_eq!(after.state, ClaudeConfigSlotCollectionStateV1::NeedsLogin);
    assert_eq!(
        projected_claude_quota_access_state(&after),
        Some(ClaudeQuotaAccessState::ReconnectRequired),
        "the existing sign-in-again state"
    );
    assert_eq!(
        fixture
            .spawns()
            .into_iter()
            .filter(|line| line != "|--version")
            .count(),
        2,
        "no further retry until a new credential appears"
    );
    // The user signs in again: a new credential clears it.
    fixture.item(&fixture.slot(0), TimeDuration::hours(8));
    fixture.collect();
    assert_eq!(
        fixture.slot_collection(0).state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );
}

/// A pass whose registered-slot settings cannot be read sees only the
/// default login. When that login is an account a registered slot owns,
/// the pass uploads nothing for it (no default-only snapshot, no Desktop
/// or current claims), and the persisted slot states are kept.
#[test]
#[serial]
fn a_registered_set_dropout_uploads_nothing_misleading() {
    let fixture = Phase0Fixture::new("dropout", true);
    fixture.write_identity(&fixture.root.join("home"), SLOT_ACCOUNTS[0]);
    fixture.set_all_expiries(TimeDuration::hours(3));
    let (owned_account, owned_organization) = Phase0Fixture::hashes(SLOT_ACCOUNTS[0]);
    let first = fixture.collect();
    let anchored = first
        .snapshots
        .iter()
        .find(|snapshot| {
            snapshot
                .account
                .as_ref()
                .and_then(|account| account.account_identifier_hash.as_deref())
                == Some(owned_account.as_str())
        })
        .expect("the slot uploads its account");
    assert_eq!(
        anchored
            .account
            .as_ref()
            .and_then(|account| account.claude_anchor_durability),
        Some(ClaudeAccountAnchorDurabilityV1::Anchored)
    );

    let settings_path = FileClaudeConfigSlotSettingsStore::default()
        .path()
        .to_path_buf();
    let original = fs::read(&settings_path).expect("settings");
    fs::write(&settings_path, b"{").expect("unreadable settings");
    let dropout = fixture.collect();
    fs::write(&settings_path, original).expect("restore settings");

    for snapshot in &dropout.snapshots {
        let account = snapshot.account.as_ref();
        assert_ne!(
            account.and_then(|account| account.account_identifier_hash.as_deref()),
            Some(owned_account.as_str()),
            "no default-only snapshot for a slot-owned account"
        );
        assert_ne!(
            account.and_then(|account| account.claude_anchor_durability),
            Some(ClaudeAccountAnchorDurabilityV1::DefaultOnly)
        );
        assert!(snapshot.plan_observations.iter().all(|observation| {
            observation.account_identifier_hash.as_deref() != Some(owned_account.as_str())
                || observation.organization_identifier_hash.as_deref()
                    != Some(owned_organization.as_str())
        }));
    }
    assert_eq!(
        fixture.slot_collection(0).state,
        ClaudeConfigSlotCollectionStateV1::Fresh,
        "the persisted slot states are kept"
    );
}

/// A settings-read failure keeps the saved slot states and withholds the
/// default upload only for a bounded run (6 passes or 1 hour): then the
/// default uploads again and the saved fresh slot states turn into a
/// transient read failure.
#[test]
#[serial]
fn a_settings_read_failure_stops_suppressing_after_the_bound() {
    let since = Instant::now();
    assert!(!claude_settings_failure_outlasted(since, 5, since));
    assert!(claude_settings_failure_outlasted(since, 6, since));
    assert!(claude_settings_failure_outlasted(
        since,
        1,
        since + CLAUDE_SETTINGS_FAILURE_BOUND
    ));

    let fixture = Phase0Fixture::new("dropout-bound", true);
    fixture.write_identity(&fixture.root.join("home"), SLOT_ACCOUNTS[0]);
    fixture.set_all_expiries(TimeDuration::hours(3));
    let (owned_account, _) = Phase0Fixture::hashes(SLOT_ACCOUNTS[0]);
    fixture.collect();
    let uploads_owned = |collection: &AgentStatusCollection| {
        collection.snapshots.iter().any(|snapshot| {
            snapshot
                .account
                .as_ref()
                .and_then(|account| account.account_identifier_hash.as_deref())
                == Some(owned_account.as_str())
        })
    };
    let settings_path = FileClaudeConfigSlotSettingsStore::default()
        .path()
        .to_path_buf();
    let original = fs::read(&settings_path).expect("settings");
    fs::write(&settings_path, b"{").expect("unreadable settings");
    for pass in 1..CLAUDE_SETTINGS_FAILURE_BOUND_PASSES {
        assert!(!uploads_owned(&fixture.collect()), "pass {pass} withholds");
    }
    assert!(
        uploads_owned(&fixture.collect()),
        "past the bound the default uploads"
    );
    let saved = read_persisted_claude_slot_collection_state();
    assert_eq!(
        saved.slots[&fixture.slot_ids[0]].state,
        ClaudeConfigSlotCollectionStateV1::ProbeFailed,
        "saved fresh slot states are marked stale"
    );
    fs::write(&settings_path, original).expect("restore settings");
    fixture.collect();
}

/// "Keep my Claude accounts signed in" is re-read right before a
/// refresher spawn: a pass holding an older "on" starts nothing once the
/// user turned it off.
#[test]
#[serial]
fn a_refresher_never_starts_after_keep_signed_in_is_turned_off() {
    let fixture = Phase0Fixture::new("consent-race", false);
    fixture.item(&fixture.slot(0), -TimeDuration::minutes(2));
    let live = read_claude_live_login_for_slot(&fixture.slot(0));
    // The pass read "on"; the user has turned it off since (the fixture
    // stores off).
    assert_eq!(
        crate::claude_refresher::maybe_refresh(&fixture.slot_ids[0], &fixture.slot(0), &live, true),
        crate::claude_refresher::RefreshDecision::NotNeeded
    );
    crate::claude_refresher::wait_until_idle(&fixture.slot_ids[0]);
    assert!(
        fixture
            .spawns()
            .into_iter()
            .all(|line| line == "|--version"),
        "no refresher started"
    );
}

/// The default login's upload drops plan observations (for example a
/// Claude Desktop session bucket marked current) for accounts registered
/// slots own, and keeps its own and unowned ones. A default candidate for
/// a slot-owned account uploads only while that account has an anchor.
#[test]
fn default_upload_never_speaks_for_a_slot_owned_account() {
    let binding = |account: &str, organization: &str| {
        ClaudeStrongBinding::new(account, organization).expect("binding")
    };
    let observation = |account: &str, organization: Option<&str>| {
        serde_json::from_value::<AgentStatusPlanObservation>(serde_json::json!({
            "evidence_method": "claude_desktop_session_bucket",
            "account_label": "Claude Desktop",
            "account_identifier_hash": account,
            "organization_identifier_hash": organization,
            "confidence": "high",
            "is_current": true
        }))
        .expect("observation")
    };
    let own = binding("acct-default", "org-default");
    let owned = BTreeSet::from([binding("acct-slot", "org-slot"), own.clone()]);
    let mut observations = vec![
        observation("acct-default", Some("org-default")),
        observation("acct-slot", Some("org-slot")),
        observation("acct-slot", None),
        observation("acct-slot", Some("org-other")),
        observation("acct-unowned", Some("org-unowned")),
    ];
    strip_slot_owned_plan_observations(&mut observations, &own, &owned);
    let kept = observations
        .iter()
        .map(|observation| {
            (
                observation
                    .account_identifier_hash
                    .clone()
                    .unwrap_or_default(),
                observation.organization_identifier_hash.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        kept,
        vec![
            ("acct-default".to_string(), Some("org-default".to_string())),
            ("acct-slot".to_string(), Some("org-other".to_string())),
            ("acct-unowned".to_string(), Some("org-unowned".to_string())),
        ]
    );

    let status = |account: Option<&str>| ClaudeConfigSlotCollectionStatusV1 {
        account_identifier_hash: account.map(str::to_string),
        organization_identifier_hash: account.map(|_| "org-slot".to_string()),
        ..ClaudeConfigSlotCollectionStatusV1::default()
    };
    let previous = BTreeMap::from([
        ("default".to_string(), status(Some("acct-default"))),
        ("slot-a".to_string(), status(Some("acct-slot"))),
    ]);
    // Registered set unknown: every non-default persisted slot owns.
    assert_eq!(
        claude_registered_owned_bindings(false, &[], &BTreeMap::new(), &previous),
        BTreeSet::from([binding("acct-slot", "org-slot")])
    );
    // Known: this pass's status (binding cleared) or the persisted one.
    let current = BTreeMap::from([("slot-a".to_string(), status(None))]);
    assert_eq!(
        claude_registered_owned_bindings(true, &["slot-a".to_string()], &current, &previous),
        BTreeSet::from([binding("acct-slot", "org-slot")])
    );
}

/// Exactly one upload carries this Mac's Claude Code settings: the upload
/// for the default login's account, otherwise the lowest slot id. None
/// when an upload already carries them or this pass built none.
#[test]
fn one_upload_carries_the_machine_claude_settings() {
    let binding = |account: &str| ClaudeStrongBinding::new(account, "org").expect("binding");
    let snapshot = |carries: bool| {
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-10-17T12:00:00Z".to_string(),
            "2026-10-17T12:15:00Z".to_string(),
        );
        snapshot.runtime_defaults = carries.then(AgentRuntimeDefaults::default);
        snapshot
    };
    let slots = |ids: &[&str]| {
        ids.iter()
            .map(|id| (id.to_string(), binding(&format!("account-{id}"))))
            .collect::<Vec<_>>()
    };
    let uploads = slots(&["slot-c", "slot-a", "slot-b"]);
    let plain = vec![snapshot(false), snapshot(false), snapshot(false)];
    let carrier = |snapshots: &[AgentStatusSnapshot],
                   uploads: &[(String, ClaudeStrongBinding)],
                   built: bool,
                   default: Option<&ClaudeStrongBinding>| {
        claude_runtime_defaults_carrier(snapshots, uploads, built, default)
            .map(|index| uploads[index].0.clone())
    };

    // The default login's account is uploaded by a slot: that slot.
    let default_login = binding("account-slot-b");
    assert_eq!(
        carrier(&plain, &uploads, true, Some(&default_login)),
        Some("slot-b".to_string())
    );
    // Otherwise the lowest slot id, whatever the upload order.
    let elsewhere = binding("account-elsewhere");
    assert_eq!(
        carrier(&plain, &uploads, true, Some(&elsewhere)),
        Some("slot-a".to_string())
    );
    assert_eq!(
        carrier(&plain, &uploads, true, None),
        Some("slot-a".to_string())
    );
    let reordered = slots(&["slot-b", "slot-a", "slot-c"]);
    assert_eq!(
        carrier(&plain, &reordered, true, None),
        Some("slot-a".to_string())
    );
    // Same inputs, same carrier on every pass.
    assert_eq!(
        carrier(&plain, &uploads, true, Some(&default_login)),
        carrier(&plain, &uploads, true, Some(&default_login))
    );
    // The default login uploaded its own snapshot (with the settings): no
    // second copy.
    let with_default = vec![snapshot(true), snapshot(false)];
    let default_uploads = slots(&["default", "slot-a"]);
    assert_eq!(carrier(&with_default, &default_uploads, true, None), None);
    // No settings built this pass, or nothing uploaded: nothing to carry.
    assert_eq!(carrier(&plain, &uploads, false, Some(&default_login)), None);
    assert_eq!(carrier(&[], &[], true, Some(&default_login)), None);
}

/// The quiet paused presentation: no new wire values, never
/// `stale_access_token`, stale reading kept, quota access `paused`.
#[test]
#[serial]
fn expired_slot_is_presented_as_paused_with_its_stale_reading() {
    let fixture = Phase0Fixture::new("paused-presentation", false);
    fixture.set_all_expiries(TimeDuration::hours(3));
    fixture.collect();
    assert_eq!(
        fixture.slot_collection(0).state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );
    fixture.set_all_expiries(-TimeDuration::hours(1));
    fixture.collect();
    let paused = fixture.slot_collection(0);
    assert_eq!(paused.state, ClaudeConfigSlotCollectionStateV1::RefreshDue);
    assert_eq!(
        paused.upkeep.as_ref().map(|upkeep| upkeep.result),
        Some(ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled)
    );
    assert_eq!(
        projected_claude_quota_access_state(&paused),
        Some(ClaudeQuotaAccessState::Paused),
        "quiet: never attention_required or reconnect_required"
    );
    assert_eq!(
        paused.diagnostics[0].code,
        ClaudeConfigSlotDiagnosticCodeV1::RefreshDue
    );
    assert!(paused.diagnostics[0]
        .message
        .starts_with("Claude Code has not refreshed this sign-in since it expired at "));
    let snapshot = paused.quota_snapshot.as_ref().expect("last reading kept");
    assert_eq!(snapshot.state, ClaudeConfigSlotQuotaSnapshotStateV1::Stale);
    assert_eq!(
        paused.account_identifier_hash.as_deref(),
        Some(Phase0Fixture::hashes(SLOT_ACCOUNTS[0]).0.as_str())
    );
}

/// T6: a paused slot resumes in the same pass once Claude Code refreshed
/// the login (the stored `expiresAt` advanced); no reconnect is needed.
#[test]
#[serial]
fn paused_slot_resumes_in_the_same_pass_when_the_stored_expiry_advances() {
    let fixture = Phase0Fixture::new("auto-resume", false);
    // Readings older than the refresh gate, so a resumed slot asks the
    // provider (forbidden here, and counted).
    for account in SLOT_ACCOUNTS {
        fixture.write_cache(account, 2 * 60 * 60);
    }
    fixture.set_all_expiries(-TimeDuration::minutes(20));
    let before = provider_calls();
    fixture.collect();
    fixture.collect();
    assert_eq!(provider_calls(), before, "paused slots make no request");
    assert_ne!(
        fixture.slot_collection(0).state,
        ClaudeConfigSlotCollectionStateV1::Fresh
    );

    fixture.item(&fixture.slot(0), TimeDuration::hours(8));
    let before = provider_calls();
    fixture.collect();
    assert_eq!(
        provider_calls(),
        before + 1,
        "the refreshed slot is read again in the same pass, once"
    );
    let resumed = fixture.slot_collection(0);
    assert!(
        resumed.state != ClaudeConfigSlotCollectionStateV1::RefreshDue
            && resumed.upkeep.as_ref().map(|upkeep| upkeep.result)
                != Some(ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled),
        "no longer paused: {resumed:?}"
    );
    assert!(fixture.spawns().iter().all(|line| line == "|--version"));
}

/// Every profile request's token, in order.
static PROFILE_TOKENS: Mutex<Vec<String>> = Mutex::new(Vec::new());
const OTHER_ACCOUNT: (&str, &str) = ("account-other", "organization-other");

/// The profile endpoint, answering for the token sent: slot 0's own
/// token is slot 0's approved account, `token-other` another account.
fn profile_by_token(token: &str) -> Result<Value, u16> {
    PROFILE_TOKENS.lock().unwrap().push(token.to_string());
    let (account, organization) = match token {
        "token-slot-a" => SLOT_ACCOUNTS[0],
        "token-other" => OTHER_ACCOUNT,
        _ => return Err(404),
    };
    Ok(serde_json::json!({
        "account": {"uuid": account},
        "organization": {"uuid": organization},
    }))
}

fn profile_calls() -> usize {
    PROFILE_TOKENS.lock().unwrap().len()
}

/// Installs a profile stand-in with an empty log; removes it on drop.
struct ProfileStandIn;

impl ProfileStandIn {
    fn answer(respond: claude_token_owner::ProfileResponder) -> Self {
        PROFILE_TOKENS.lock().unwrap().clear();
        claude_token_owner::PROFILE_TEST_RESPONSE.with(|cell| cell.set(Some(respond)));
        Self
    }
}

impl Drop for ProfileStandIn {
    fn drop(&mut self) {
        claude_token_owner::PROFILE_TEST_RESPONSE.with(|cell| cell.set(None));
    }
}

impl Phase0Fixture {
    fn descriptor(&self, index: usize) -> ClaudeConfigSlotDescriptorV1 {
        let status = self.status();
        status
            .managed_slots
            .into_iter()
            .chain(status.external_slots)
            .find(|slot| slot.slot_id == self.slot_ids[index])
            .expect("slot")
    }

    fn slot_dir_spawns(&self, index: usize) -> usize {
        let marker = format!("{}|", self.slot_dirs[index].display());
        self.spawns()
            .iter()
            .filter(|line| line.starts_with(&marker))
            .count()
    }

    fn grant_upkeep(&self) {
        FileClaudeConfigSlotSettingsStore::default()
            .set_upkeep_consent(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                true,
            )
            .expect("keep signed in");
    }
}

/// [regress] T6, the observed case: another app rewrites an approved
/// slot's `.claude.json` to another account; the slot's stored token stays
/// the approved login and decides. Lapsed with no verdict (as after a
/// restart): owner unproven, last reading kept, no request; with "Keep my
/// Claude accounts signed in" on, exactly one background refresh of the
/// slot's own login starts, and a failed one leaves the slot as it was.
/// Refreshed (valid): one profile call with the fresh token, then
/// collection on the approved pair with no other login's label; the
/// usage call gets that token. Reconnect's identity check and the upkeep
/// fence agree. Lapsed again: its background refresh runs, binding kept.
#[test]
#[serial]
fn slot_with_another_accounts_cached_login_collects_on_its_proven_token() {
    let fixture = Phase0Fixture::new("cached-other-login", false);
    let _profile = ProfileStandIn::answer(profile_by_token);
    let (slot, dir) = (fixture.slot(0), fixture.slot_dirs[0].clone());
    let approved = Phase0Fixture::hashes(SLOT_ACCOUNTS[0]);
    let approved_account = Some(approved.0.as_str());
    fixture.set_all_expiries(TimeDuration::hours(3));
    fixture.item_token(&slot, TimeDuration::hours(3), "token-slot-a");
    fixture.collect();
    let first = fixture.slot_collection(0);
    assert_eq!(first.state, ClaudeConfigSlotCollectionStateV1::Fresh);
    assert_eq!(profile_calls(), 0, "a matching account file needs no proof");

    fixture.write_identity(&dir, OTHER_ACCOUNT);
    fixture.item_token(&slot, -TimeDuration::hours(1), "token-slot-a-lapsed");
    fixture.clear_logs();
    let unproven = |context: &str| {
        fixture.collect();
        crate::claude_refresher::wait_until_idle(&fixture.slot_ids[0]);
        let unproven = fixture.slot_collection(0);
        assert_eq!(
            unproven.state,
            ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
            "{context}"
        );
        assert!(unproven.diagnostics[0]
            .message
            .contains("could not yet confirm"));
        assert_eq!(
            unproven.account_identifier_hash.as_deref(),
            approved_account
        );
        assert!(unproven.quota_snapshot.is_some(), "{context}: reading kept");
        assert_eq!(
            profile_calls(),
            0,
            "{context}: a lapsed token is never sent"
        );
    };
    unproven("consent off");
    assert_eq!(fixture.slot_dir_spawns(0), 0, "consent off: no refresh");
    fixture.grant_upkeep();
    unproven("refreshing");
    assert_eq!(fixture.slot_dir_spawns(0), 1, "the slot's own refresh");
    // The stand-in CLI leaves the expiry as it was: a failed refresh.
    unproven("refresh failed");
    assert_eq!(fixture.slot_dir_spawns(0), 1, "its retry waits");

    // Claude Code stored the refreshed login.
    fixture.item_token(&slot, TimeDuration::hours(8), "token-slot-a");
    let usage_calls = provider_calls();
    let collection = fixture.collect();
    let collected = fixture.slot_collection(0);
    assert_eq!(collected.state, ClaudeConfigSlotCollectionStateV1::Fresh);
    let other = Phase0Fixture::hashes(OTHER_ACCOUNT);
    let hashes = |status: &ClaudeConfigSlotCollectionStatusV1| {
        [
            status.account_identifier_hash.clone(),
            status.organization_identifier_hash.clone(),
            status.cached_account_hash.clone(),
            status.token_owner_account_hash.clone(),
            status.token_owner_organization_hash.clone(),
        ]
    };
    assert_eq!(
        hashes(&collected),
        [&approved.0, &approved.1, &other.0, &approved.0, &approved.1].map(|h| Some(h.clone()))
    );
    assert!(collected.owner_proven_at.is_some());
    let profile = collected.account_profile.expect("approved profile");
    assert_eq!(
        profile.email.as_deref(),
        Some("account-slot-a@example.invalid")
    );
    assert_eq!(
        *PROFILE_TOKENS.lock().unwrap(),
        ["token-slot-a"],
        "the slot's own token"
    );
    assert_eq!(provider_calls(), usage_calls, "the reading came from cache");
    let wire = serde_json::to_string(&collection.snapshots).expect("serialize");
    let persisted = fs::read_to_string(
        fixture
            .root
            .join("support/claude-config-slot-collection-state.json"),
    )
    .expect("persisted state");
    for text in [wire, persisted] {
        assert!(!text.contains("account-other"), "no other login's label");
    }
    // The resolution the usage call reads sends the proven token and
    // takes nothing from the stale file.
    let local = read_registered_claude_slot_locally(&fixture.descriptor(0)).expect("read");
    let owner = local.token_owner(&fixture.slot_ids[0], None, false);
    let resolved = resolve_registered_claude_slot_from_local(local, Some(&owner))
        .expect("proven owner resolves");
    assert_eq!(
        resolved.credential.access_token.as_deref(),
        Some("token-slot-a")
    );
    let account = resolved.account;
    assert_eq!(
        [
            account.email,
            account.organization_label,
            account.plan_type,
            account.account_id
        ],
        [None, None, None, None]
    );

    let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("time");
    let proof = verify_claude_local_identity(&fixture.slot_ids[0], &dir.to_string_lossy(), &now)
        .expect("Reconnect's identity check");
    assert_eq!(
        (
            proof.account_identifier_hash,
            proof.organization_identifier_hash
        ),
        approved.clone()
    );
    assert!(!claude_slot_login_unapproved(&fixture.descriptor(0)));

    fixture.clear_logs();
    fixture.item_token(&slot, -TimeDuration::minutes(2), "token-slot-a");
    fixture.collect();
    let refreshing = fixture.slot_collection(0);
    assert_eq!(
        refreshing.state,
        ClaudeConfigSlotCollectionStateV1::RefreshDue
    );
    assert_eq!(
        refreshing.account_identifier_hash.as_deref(),
        approved_account
    );
    crate::claude_refresher::wait_until_idle(&fixture.slot_ids[0]);
    assert_eq!(
        fixture.slot_dir_spawns(0),
        1,
        "one refresher, for the proven login"
    );
}

/// [behaviour] T6 twin: a real sign-in to another account in the slot (its
/// token changes owner) stays `identity_mismatch`: one profile call for
/// that token, no usage call, no refresher once it lapses; the upkeep
/// fence refuses and Reconnect's identity check reads the other account.
#[test]
#[serial]
fn slot_whose_token_changes_owner_stays_mismatched_without_requests() {
    let fixture = Phase0Fixture::new("token-other-owner", false);
    let _profile = ProfileStandIn::answer(profile_by_token);
    let slot = fixture.slot(0);
    fixture.set_all_expiries(TimeDuration::hours(3));
    fixture.collect();
    fixture.grant_upkeep();
    fixture.write_identity(&fixture.slot_dirs[0], OTHER_ACCOUNT);
    fixture.item_token(&slot, TimeDuration::hours(8), "token-other");
    let usage_calls = provider_calls();
    fixture.collect();
    fixture.clear_logs();
    fixture.item_token(&slot, -TimeDuration::minutes(2), "token-other");
    fixture.collect();
    crate::claude_refresher::wait_until_idle(&fixture.slot_ids[0]);
    let mismatched = fixture.slot_collection(0);
    assert_eq!(
        mismatched.state,
        ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    );
    assert_eq!(
        mismatched.account_identifier_hash,
        Some(Phase0Fixture::hashes(SLOT_ACCOUNTS[0]).0)
    );
    assert_eq!(*PROFILE_TOKENS.lock().unwrap(), ["token-other"], "one call");
    assert_eq!(provider_calls(), usage_calls, "no usage call");
    assert_eq!(
        fixture.slot_dir_spawns(0),
        0,
        "no refresh for another login"
    );
    assert!(claude_slot_login_unapproved(&fixture.descriptor(0)));
    let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("time");
    let dir = fixture.slot_dirs[0].to_string_lossy();
    let proof = verify_claude_local_identity(&fixture.slot_ids[0], &dir, &now).expect("read");
    assert_eq!(
        proof.account_identifier_hash,
        Phase0Fixture::hashes(OTHER_ACCOUNT).0
    );
}

/// T7: a locally expired default login sends nothing and serves its
/// last reading as stale.
#[test]
#[serial]
fn expired_default_login_makes_no_request_and_serves_its_stale_reading() {
    let fixture = Phase0Fixture::new("default-expired", false);
    fixture.write_cache(DEFAULT_ACCOUNT, 2 * 60 * 60);
    fixture.set_all_expiries(-TimeDuration::minutes(10));
    let before = provider_calls();
    let collection = fixture.collect();
    assert_eq!(provider_calls(), before, "zero provider calls");
    let default = &collection.source_health_snapshot;
    assert!(!default.quota_windows.is_empty(), "last reading served");
    assert!(default
        .quota_windows
        .iter()
        .filter(|window| window.account_identifier_hash.is_some())
        .all(|window| window.freshness == AgentQuotaWindowFreshness::Stale));
    assert!(default.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "claude_oauth_usage_check_suppressed"
            && diagnostic.message.contains("expired locally")
    }));
}

/// T7: once a managed slot that owned the account's reads is paused, the
/// default login (same account, valid) becomes the provider caller again.
#[test]
#[serial]
fn default_login_takes_over_reads_when_the_owning_slot_is_paused() {
    let fixture = Phase0Fixture::new("default-takeover", true);
    // Slot 0 is the same account as the default login.
    fixture.write_identity(&fixture.slot_dirs[0], DEFAULT_ACCOUNT);
    fixture.set_all_expiries(TimeDuration::hours(3));
    fixture.collect();
    fixture.collect();
    fixture.write_cache(DEFAULT_ACCOUNT, 2 * 60 * 60);
    fixture.item(&fixture.slot(0), -TimeDuration::minutes(5));
    // The pass after the slot paused still defers once (it reads the
    // previous pass's state); the next one reads through the default.
    fixture.collect();
    let before = provider_calls();
    let collection = fixture.collect();
    assert!(
        !collection
            .source_health_snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "claude_oauth_usage_deferred_to_registered_slot"),
        "a paused slot no longer owns the account's reads"
    );
    assert_eq!(provider_calls(), before + 1, "the default login asks once");
    assert_only_version_probes(&fixture.spawns(), "takeover");
}

/// The default login off macOS, end to end with no `security` on the
/// search path: `~/.claude/.credentials.json` (0600, Max) and
/// `~/.claude.json` (Max organization, 20x tier) give one status pass a
/// `max_20x` plan row for exactly that account and organization.
#[cfg(not(target_os = "macos"))]
#[test]
#[serial]
fn default_home_plan_row_comes_from_the_native_credentials_file() {
    let fixture = Phase0Fixture::new("native-default-plan", false);
    fs::remove_file(fixture.root.join("bin").join("security")).expect("no keychain tool");
    let home = fixture.root.join("home");
    fs::write(
        home.join(".claude.json"),
        serde_json::to_vec(&serde_json::json!({
            "oauthAccount": {
                "accountUuid": DEFAULT_ACCOUNT.0,
                "organizationUuid": DEFAULT_ACCOUNT.1,
                "emailAddress": format!("{}@example.invalid", DEFAULT_ACCOUNT.0),
                "organizationType": "claude_max",
                "organizationRateLimitTier": "default_claude_max_20x"
            }
        }))
        .expect("identity"),
    )
    .expect("write identity");
    // Native file mode 0600 with `subscriptionType` "max".
    fixture.item(&ClaudeConfigDirSlot::Default, TimeDuration::hours(3));
    let native = home.join(".claude").join(".credentials.json");
    assert_eq!(
        fs::metadata(&native)
            .expect("native file")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let collection = fixture.collect();
    let (account_hash, organization_hash) = Phase0Fixture::hashes(DEFAULT_ACCOUNT);
    let rows: Vec<_> = collection
        .source_health_snapshot
        .plan_observations
        .iter()
        .filter(|row| row.account_identifier_hash.as_deref() == Some(account_hash.as_str()))
        .collect();
    assert!(!rows.is_empty(), "a plan row for the default login");
    for row in rows {
        assert_eq!(row.plan_type.as_deref(), Some("max_20x"), "{row:?}");
        assert_eq!(
            row.organization_identifier_hash.as_deref(),
            Some(organization_hash.as_str()),
            "{row:?}"
        );
    }
    assert!(fixture.security_reads().is_empty());
    assert_only_version_probes(&fixture.spawns(), "native-default-plan");
}

/// An API-key-only installation (settings `apiKeyHelper`, no OAuth login)
/// is still reported as signed in with the API-key method, not as a
/// missing login.
#[test]
#[serial]
fn api_key_only_default_install_is_signed_in_without_subscription_identity() {
    let fixture = Phase0Fixture::new("api-key-only", false);
    let home = fixture.root.join("home");
    fs::write(
        home.join(".claude").join("settings.json"),
        r#"{"apiKeyHelper":"/usr/local/bin/print-key"}"#,
    )
    .expect("settings");
    let collection = fixture.collect();
    let account = collection
        .source_health_snapshot
        .account
        .clone()
        .expect("default account");
    assert_eq!(account.login_state, AgentLoginState::SignedIn);
    assert_eq!(account.auth_method.as_deref(), Some("api_key"));
    assert_eq!(account.billing_channel.as_deref(), Some("direct_api"));
    assert_eq!(account.account_identifier_hash, None);
    assert_ne!(
        fixture.status().default_slot.collection.state,
        ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
    );
    assert_only_version_probes(&fixture.spawns(), "api-key");
}

/// Review round 1: a working API key outranks the OAuth state, so a
/// CLI-cleared OAuth item does not make the default login look signed
/// out; a Bedrock-only default login is signed in too.
#[test]
#[serial]
fn api_key_or_bedrock_outranks_a_cleared_oauth_login() {
    let fixture = Phase0Fixture::new("api-key-over-cleared", false);
    let home = fixture.root.join("home");
    fixture.write_login(
        &ClaudeConfigDirSlot::Default,
        &serde_json::json!({
            "claudeAiOauth": {
                "accessToken": "",
                "refreshToken": "",
                "expiresAt": 0,
                "scopes": ["user:inference"]
            }
        }),
    );
    for (settings, method) in [
        (r#"{"apiKeyHelper":"/usr/local/bin/print-key"}"#, "api_key"),
        (r#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1"}}"#, "bedrock"),
    ] {
        fs::write(home.join(".claude").join("settings.json"), settings).expect("settings");
        let collection = fixture.collect();
        let account = collection
            .source_health_snapshot
            .account
            .clone()
            .expect("default account");
        assert_eq!(account.login_state, AgentLoginState::SignedIn, "{method}");
        assert_eq!(account.auth_method.as_deref(), Some(method));
        assert_ne!(
            fixture.status().default_slot.collection.state,
            ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
            "{method}"
        );
    }
    // With a valid OAuth login next to Bedrock, the account keeps its
    // OAuth identity but reports the Bedrock route and billing channel.
    fixture.set_all_expiries(TimeDuration::hours(3));
    let collection = fixture.collect();
    let account = collection
        .source_health_snapshot
        .account
        .clone()
        .expect("default account");
    assert_eq!(account.auth_method.as_deref(), Some("bedrock"));
    assert_eq!(account.billing_channel.as_deref(), Some("amazon_bedrock"));
    assert!(account.account_identifier_hash.is_some());
    assert_only_version_probes(&fixture.spawns(), "api-key-over-cleared");
}

/// Review round 1: the expiry check uses a clock read immediately before
/// the request, not the sample taken when collection started. A token
/// that lapses while the collection path blocks is never sent.
#[test]
#[serial]
fn token_that_lapses_during_collection_is_never_sent() {
    let _fixture = Phase0Fixture::new("lapse-before-send", false);
    fn wait_past_the_margin() {
        std::thread::sleep(Duration::from_millis(3_100));
    }
    let (account_hash, organization_hash) = Phase0Fixture::hashes(("account-lapse", "org-lapse"));
    let expires_at = OffsetDateTime::from_unix_timestamp(
        i64::try_from(current_unix_seconds()).expect("time") + 62,
    )
    .expect("time")
    .format(&Rfc3339)
    .expect("format");
    *CLAUDE_OAUTH_BEFORE_SEND_HOOK.lock().unwrap() = Some(wait_past_the_margin);
    let before = provider_calls();
    let outcome = collect_claude_oauth_usage_with_credential(
        &account_hash,
        &organization_hash,
        Some("fixture-access".to_string()),
        Some(expires_at),
        &ClaudeOAuthUsageCaller::Default,
        current_unix_seconds,
    );
    *CLAUDE_OAUTH_BEFORE_SEND_HOOK.lock().unwrap() = None;
    assert_eq!(provider_calls(), before, "the lapsed token was not sent");
    assert!(outcome.result.is_err());
}

#[test]
#[serial]
fn settings_api_key_presence_is_reported_without_reading_values() {
    let root = std::env::temp_dir().join(format!(
        "ottto-claude-settings-api-key-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("root");
    let plain = root.join("plain.json");
    let helper = root.join("helper.json");
    let env_key = root.join("env.json");
    fs::write(&plain, r#"{"model":"opus"}"#).expect("plain");
    fs::write(&helper, r#"{"apiKeyHelper":"/usr/local/bin/key"}"#).expect("helper");
    fs::write(&env_key, r#"{"env":{"ANTHROPIC_API_KEY":"x"}}"#).expect("env");
    let paths = |path: &Path| vec![("settings".to_string(), path.to_path_buf())];
    let none = |_: &str| None;
    let detect = |path: &Path| claude_alternative_auth(&paths(path), &none, true, &[], false);
    assert_eq!(detect(&plain), None);
    assert_eq!(detect(&helper), Some(ClaudeAlternativeAuth::ApiKey));
    assert_eq!(detect(&root.join("missing.json")), None);
    let bedrock = root.join("bedrock.json");
    fs::write(&bedrock, r#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1"}}"#).expect("bedrock");
    assert_eq!(detect(&bedrock), Some(ClaudeAlternativeAuth::Bedrock));
    let vertex_off = root.join("vertex-off.json");
    fs::write(&vertex_off, r#"{"env":{"CLAUDE_CODE_USE_VERTEX":"0"}}"#).expect("vertex");
    assert_eq!(detect(&vertex_off), None);

    // Review round 2: the highest settings layer wins. Managed settings
    // turning Bedrock off override user settings turning it on.
    let managed_off = root.join("managed.json");
    fs::write(&managed_off, r#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"0"}}"#).expect("managed");
    let layered = vec![
        ("user".to_string(), bedrock.clone()),
        ("managed".to_string(), managed_off.clone()),
    ];
    assert_eq!(
        claude_alternative_auth(&layered, &none, false, &[], false),
        None
    );
    let reversed = vec![
        ("user".to_string(), managed_off.clone()),
        ("managed".to_string(), bedrock.clone()),
    ];
    assert_eq!(
        claude_alternative_auth(&reversed, &none, false, &[], false),
        Some(ClaudeAlternativeAuth::Bedrock)
    );
    // Settings env outranks the ambient environment.
    let ambient_bedrock = |key: &str| (key == "CLAUDE_CODE_USE_BEDROCK").then(|| "1".to_string());
    assert_eq!(
        claude_alternative_auth(&paths(&managed_off), &ambient_bedrock, false, &[], false),
        None
    );

    // Review round 2: ANTHROPIC_API_KEY outranks a usable OAuth login only
    // once approved in Claude Code; otherwise only without OAuth.
    let key = "sk-ant-fixture-0123456789abcdefghijklmnop";
    let suffix = key[key.len() - 20..].to_string();
    let ambient_key = |name: &str| (name == "ANTHROPIC_API_KEY").then(|| key.to_string());
    assert_eq!(
        claude_alternative_auth(&paths(&plain), &ambient_key, true, &[], false),
        None,
        "a declined or unapproved key leaves the subscription login in charge"
    );
    assert_eq!(
        claude_alternative_auth(&paths(&plain), &ambient_key, true, &[suffix], false),
        Some(ClaudeAlternativeAuth::ApiKey)
    );
    assert_eq!(
        claude_alternative_auth(&paths(&plain), &ambient_key, false, &[], false),
        Some(ClaudeAlternativeAuth::ApiKey)
    );
    // A Console API key saved by `/login` counts only without OAuth.
    assert_eq!(
        claude_alternative_auth(&paths(&plain), &none, false, &[], true),
        Some(ClaudeAlternativeAuth::ApiKey)
    );
    assert_eq!(
        claude_alternative_auth(&paths(&plain), &none, true, &[], true),
        None
    );
    assert_eq!(
        claude_alternative_auth(&paths(&env_key), &none, true, &[], false),
        None,
        "settings env ANTHROPIC_API_KEY follows the same approval rule"
    );
    let _ = fs::remove_dir_all(root);
}

/// The refresher runs only where Claude Code's `/usage` refreshes: a
/// `user:profile` login, not usage-billed, no other credential first,
/// no plan-usage snapshot under 60 seconds old. Fixture files only.
#[test]
fn refresher_runs_only_for_logins_whose_usage_refreshes() {
    let dir = std::env::temp_dir().join(format!(
        "ottto-claude-refresher-eligibility-{}-{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    fs::create_dir_all(&dir).expect("dir");
    let slot = ClaudeConfigDirSlot::registered(dir.to_string_lossy().to_string()).expect("slot");
    let now = OffsetDateTime::now_utc();
    let now_ms = i64::try_from(now.unix_timestamp_nanos() / 1_000_000).expect("ms");
    let login = |has_profile_scope: bool| ClaudeLiveLogin {
        state: ClaudeLocalLoginState::RefreshPending,
        metadata: Some(ClaudeOAuthCredentialMetadata {
            access_expires_at: Some(
                (now - time::Duration::minutes(1))
                    .format(&Rfc3339)
                    .expect("format"),
            ),
            refresh_token_expires_at: None,
            has_refresh_token: true,
            cleared_by_cli: false,
            has_profile_scope,
        }),
    };
    let skip = |has_profile_scope: bool| {
        claude_refresher_skip_reason(&slot, &login(has_profile_scope), now)
    };
    let write = |name: &str, body: Value| {
        fs::write(dir.join(name), body.to_string()).expect("write");
    };
    assert_eq!(skip(false), Some("no_profile_scope"));
    assert_eq!(skip(true), None);
    write(
        ".claude.json",
        serde_json::json!({"oauthAccount": {"billingType": "usage_based"}}),
    );
    assert_eq!(skip(true), Some("usage_billing"));
    write(
        ".claude.json",
        serde_json::json!({
            "oauthAccount": {"billingType": "stripe_subscription"},
            "cachedUsageUtilization": {"fetchedAtMs": now_ms - 10_000}
        }),
    );
    assert_eq!(skip(true), Some("usage_cached"));
    write(
        ".claude.json",
        serde_json::json!({"cachedUsageUtilization": {"fetchedAtMs": now_ms - 120_000}}),
    );
    assert_eq!(skip(true), None);
    write(
        "settings.json",
        serde_json::json!({"env": {"CLAUDE_CODE_USE_BEDROCK": "1"}}),
    );
    assert_eq!(skip(true), Some("other_auth"));
    write(
        "settings.json",
        serde_json::json!({"apiKeyHelper": "/bin/echo"}),
    );
    assert_eq!(skip(true), Some("other_auth"));
    let key = "sk-ant-fixture-key-0123456789abcdefghij";
    write(
        "settings.json",
        serde_json::json!({"env": {"ANTHROPIC_API_KEY": key}}),
    );
    assert_eq!(
        skip(true),
        Some("other_auth"),
        "`-p` uses an ANTHROPIC_API_KEY even when the user did not approve it"
    );
    write(
        ".claude.json",
        serde_json::json!({
            "customApiKeyResponses": {"approved": [&key[key.len() - 20..]]}
        }),
    );
    assert_eq!(
        skip(true),
        Some("other_auth"),
        "an approved key comes first"
    );
    let _ = fs::remove_dir_all(dir);
}

/// One classifier: the status, the spawn gate and the refresher agree on
/// absent, malformed, expired and valid access deadlines. An absent or
/// malformed deadline fails closed everywhere.
#[test]
fn status_gate_and_refresher_agree_on_the_access_deadline() {
    use crate::claude_refresher::{decide_refresh, RefreshDecision};
    use crate::claude_spawn_gate::{evaluate_short_run, ClaudeSpawnRefusal};
    let now = OffsetDateTime::now_utc();
    let at = |offset: TimeDuration| Some((now + offset).format(&Rfc3339).expect("format"));
    let read = |access_expires_at: Option<String>| {
        ClaudeCredentialRead::Present(ClaudeOAuthCredential {
            access_token: Some("fixture-access".to_string()),
            has_refresh_token: true,
            access_expires_at,
            relogin_required_at: at(TimeDuration::days(20)),
            has_inference_scope: Some(true),
            has_profile_scope: true,
            subscription_type: None,
        })
    };
    for (label, deadline, state, spawn, refresh) in [
        (
            "absent",
            None,
            ClaudeLocalLoginState::Unreadable,
            Err(ClaudeSpawnRefusal::CredentialReadFailed),
            RefreshDecision::NotNeeded,
        ),
        (
            "malformed",
            Some("not-a-time".to_string()),
            ClaudeLocalLoginState::Unreadable,
            Err(ClaudeSpawnRefusal::CredentialReadFailed),
            RefreshDecision::NotNeeded,
        ),
        (
            "expired",
            at(-TimeDuration::minutes(10)),
            ClaudeLocalLoginState::RefreshPending,
            Err(ClaudeSpawnRefusal::QuietWindow),
            RefreshDecision::Started,
        ),
        (
            "valid",
            at(TimeDuration::hours(3)),
            ClaudeLocalLoginState::AccessValid,
            Ok(()),
            RefreshDecision::NotNeeded,
        ),
    ] {
        let read = read(deadline);
        assert_eq!(claude_local_login_state(&read, now), state, "{label}");
        assert_eq!(
            evaluate_short_run(claude_gate_credential(&read, now), None, now),
            spawn,
            "{label}"
        );
        let live = ClaudeLiveLogin {
            state: claude_local_login_state(&read, now),
            metadata: read.metadata(),
        };
        assert_eq!(
            decide_refresh(&live, true, false, None, now),
            refresh,
            "{label}"
        );
    }
}

/// [behaviour] No proof for a slot whose `.claude.json` names another
/// account: with the network off (no request) or a failed check the slot
/// is owner unproven, never a mismatch, and keeps its approved account
/// and last reading. Once lapsed, with "Keep my Claude accounts signed
/// in" on, it starts no refresh while the network is off or the pass
/// serves saved readings only.
#[test]
#[serial]
fn unprovable_slot_owner_keeps_the_approved_reading_without_a_mismatch() {
    fn unavailable(token: &str) -> Result<Value, u16> {
        PROFILE_TOKENS.lock().unwrap().push(token.to_string());
        Err(503)
    }
    let fixture = Phase0Fixture::new("owner-unprovable", false);
    let _profile = ProfileStandIn::answer(unavailable);
    let approved = Phase0Fixture::hashes(SLOT_ACCOUNTS[0]).0;
    fixture.set_all_expiries(TimeDuration::hours(3));
    fixture.collect();
    fixture.write_identity(&fixture.slot_dirs[0], OTHER_ACCOUNT);
    let network_off = fixture
        .root
        .join("support")
        .join(CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE);
    for (context, calls) in [("network off", 0), ("failed", 1)] {
        if context == "network off" {
            fs::write(&network_off, b"disabled\n").expect("network off");
        } else {
            let _ = fs::remove_file(&network_off);
        }
        fixture.collect();
        let status = fixture.slot_collection(0);
        assert_eq!(
            status.state,
            ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
            "{context}"
        );
        assert_eq!(status.account_identifier_hash.as_ref(), Some(&approved));
        assert!(status.quota_snapshot.is_some(), "{context}: reading kept");
        assert_eq!(profile_calls(), calls, "{context}");
    }

    fixture.grant_upkeep();
    fixture.item(&fixture.slot(0), -TimeDuration::hours(1));
    fixture.clear_logs();
    for context in ["network off", "saved readings only"] {
        if context == "network off" {
            fs::write(&network_off, b"disabled\n").expect("network off");
            fixture.collect();
            fs::remove_file(&network_off).expect("network on");
        } else {
            with_claude_pass(true, current_unix_seconds(), || fixture.collect());
        }
        crate::claude_refresher::wait_until_idle(&fixture.slot_ids[0]);
        assert_eq!(
            fixture.slot_collection(0).state,
            ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
            "{context}"
        );
        assert_eq!(fixture.slot_dir_spawns(0), 0, "{context}: no refresh");
    }
}
