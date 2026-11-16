//! Source registration, persisted health and agent-status projections.
//! Owns connector descriptors, detected-use caches and quota selection.
//! Called by daemon state, verification and health projections.

use crate::agent_configs;
use crate::agent_status;
use crate::claude_connected_health;
use crate::claude_shell_telemetry;
use crate::detected_uses::prune_stale_detected_uses;
use crate::detected_uses::DETECTED_USE_RETENTION_DAYS;
use crate::keychain;
use crate::preserve_blocking_verification_state;
use crate::usage_checks_paused_problem;
use crate::DaemonState;
use crate::CODEX_USAGE_READ_RETRYING_TITLE;
use ottto_core::default_support_dir;
use ottto_core::source_state_file_name;
use ottto_core::FileSourceStateStore;
use ottto_core::LocalDeviceBinding;
use ottto_protocol::AccountBindingState;
use ottto_protocol::AgentQuotaWindow;
use ottto_protocol::AgentQuotaWindowFreshness;
use ottto_protocol::AgentQuotaWindowStatus;
use ottto_protocol::AgentStatusSnapshot;
use ottto_protocol::AgentStatusState;
use ottto_protocol::CollectorDataSourceKind;
use ottto_protocol::CollectorDefaultState;
use ottto_protocol::CollectorDescriptor;
use ottto_protocol::CollectorRiskClass;
use ottto_protocol::ConnectorMaturity;
use ottto_protocol::ConnectorReviewTier;
use ottto_protocol::DetectedUse;
use ottto_protocol::DetectedUseQuotaWindowState;
use ottto_protocol::HealthGrade;
use ottto_protocol::HealthProblem;
use ottto_protocol::LocalAccountBinding;
use ottto_protocol::LocalAccountState;
use ottto_protocol::LocalAccountUser;
use ottto_protocol::SourceConfigState;
use ottto_protocol::SourceDescriptor;
use ottto_protocol::SourceHealth;
use ottto_protocol::SourceKind;
use ottto_protocol::SourceOperation;
use ottto_protocol::SourceOperationDescriptor;
use ottto_protocol::SourceOperationState;
use ottto_protocol::SourceState;
use ottto_protocol::SourceStateOwner;
use ottto_protocol::StableProblemCode;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use time::Duration as TimeDuration;
use time::OffsetDateTime;

pub(crate) fn bound_user(account: &LocalAccountBinding) -> Option<&LocalAccountUser> {
    account.user.as_ref()
}

pub(crate) fn source_slug(source: &SourceKind) -> &'static str {
    match source {
        SourceKind::Codex => "codex",
        SourceKind::ClaudeCode => "claude_code",
        SourceKind::Pi => "pi",
    }
}

fn source_from_slug(slug: &str) -> Option<SourceKind> {
    match slug {
        "codex" => Some(SourceKind::Codex),
        "claude_code" | "claude-code" => Some(SourceKind::ClaudeCode),
        "pi" => Some(SourceKind::Pi),
        _ => None,
    }
}

pub(crate) fn seed_registered_sources(
    state: &mut DaemonState,
    device: Option<&LocalDeviceBinding>,
) {
    seed_registered_sources_with_presence(state, device, source_present_locally)
}

/// Seed `verifying` placeholder rows for account-registered sources, but ONLY
/// for sources that are genuinely present on THIS machine. `device.sources` is
/// the account-wide registered set (sources set up on ANY of the user's Macs),
/// so seeding it blindly makes a Mac that never had an app show a phantom
/// "1 account / needs attention" row that then fails verification. The
/// presence probe (binary found or genuine user config) is the gate; absent
/// sources are simply omitted and can still be discovered later by a real scan
/// if the app is installed. `present` is injected so tests can drive each state
/// deterministically.
pub(crate) fn seed_registered_sources_with_presence(
    state: &mut DaemonState,
    device: Option<&LocalDeviceBinding>,
    present: impl Fn(&SourceKind) -> bool,
) {
    state.registered_source_grants = device.map(|d| d.sources.clone()).unwrap_or_default();
    if state.account.state != LocalAccountState::Connected {
        return;
    }
    let Some(device) = device else {
        return;
    };
    let sources = device
        .sources
        .iter()
        .filter_map(|slug| source_from_slug(slug))
        .filter(|source| !state.sources.iter().any(|health| health.source == *source))
        .filter(|source| present(source))
        .collect::<Vec<_>>();
    for source in sources {
        state.sources.push(cached_source_health(state, source));
    }
}

/// Local-presence probe used by seeding. Delegates to the canonical detector so
/// "is this app really here" has one definition across seeding, status
/// collection, and verification.
fn source_present_locally(source: &SourceKind) -> bool {
    agent_configs::detection::source_present_locally(source)
}

fn cached_source_health(state: &DaemonState, source: SourceKind) -> SourceHealth {
    let expected_account_id = state.account.user.as_ref().map(|user| user.id.clone());
    SourceHealth {
        source: source.clone(),
        descriptor: source_descriptor(&source),
        state: SourceState::Verifying,
        grade: HealthGrade::Unknown,
        account_binding: AccountBindingState {
            expected_account_id,
            observed_account_id: None,
            matched: None,
        },
        config: SourceConfigState {
            discovered: true,
            path_hint: config_path_hint(&source).map(str::to_string),
            fingerprint: None,
            drift: Vec::new(),
        },
        collector: None,
        agent_status: None,
        plan_observations: Vec::new(),
        detected_uses: Vec::new(),
        active_session_reconciliation: None,
        collection: None,
        tracking_confirmation: None,
        last_seen_at: None,
        last_verified_at: None,
        problems: Vec::new(),
        recommended_actions: Vec::new(),
        connected_at: state.first_seen(&source),
        telemetry_configured: telemetry_configured_for_source(&source),
        reconciliation_enabled: state.reconciliation_enabled(&source),
        source_paused: false,
    }
}

fn config_path_hint(source: &SourceKind) -> Option<&'static str> {
    match source {
        SourceKind::Codex => Some("~/.codex/config.toml"),
        SourceKind::ClaudeCode => Some("~/.claude/settings.json"),
        SourceKind::Pi => None,
    }
}

/// Boot-load first-seen, health and the optional Repair episode in one pass.
/// Missing/unreadable files are skipped; mismatched health sources are ignored.
pub(crate) fn load_source_state(state: &mut DaemonState, dir: &Path) {
    state.source_first_seen.clear();
    state.sources.clear();
    for source in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
        let slug = source_slug(&source);
        let store = FileSourceStateStore::new(dir.join(source_state_file_name(slug)));
        let Ok(Some(saved)) = store.load() else {
            continue;
        };
        if let Some(first_seen) = saved.first_seen_at {
            state.source_first_seen.insert(slug.to_string(), first_seen);
        }
        if let Some(episode) = saved.tracking_confirmation {
            state.tracking_confirmation.restore(&source, episode);
        }
        let Some(mut health) = saved.last_health else {
            continue;
        };
        if health.source != source {
            continue;
        }
        normalize_persisted_source_health(state, &mut health);
        state.sources.push(health);
    }
}

fn normalize_persisted_source_health(state: &DaemonState, health: &mut SourceHealth) {
    health.tracking_confirmation = None;
    health.collection = None;
    health.descriptor = source_descriptor(&health.source);
    health.account_binding.expected_account_id =
        state.account.user.as_ref().map(|user| user.id.clone());
    if health.connected_at.is_none() {
        health.connected_at = state.first_seen(&health.source);
    }
    health.telemetry_configured = telemetry_configured_for_source(&health.source);
    health.reconciliation_enabled = state.reconciliation_enabled(&health.source);
}

/// Whether local live telemetry credentials are configured for `source`.
/// Telemetry is a Codex / Claude Code concept, so Pi returns `None`. Both the
/// legacy per-source key store and the relay-device setup-run path count: the
/// latter is what Companion install actions provision on this Mac.
pub(crate) fn telemetry_configured_for_source(source: &SourceKind) -> Option<bool> {
    match source {
        SourceKind::Codex => Some(false),
        SourceKind::ClaudeCode => Some(
            keychain::TelemetryKeyStore::production()
                .latest_key_id(source)
                .is_ok_and(|key| key.is_some())
                || relay_device_credentials_include_source(source),
        ),
        SourceKind::Pi => None,
    }
}

fn relay_device_credentials_include_source(source: &SourceKind) -> bool {
    let slug = source_slug(source);
    crate::snapshot_client::load_snapshot_device_credentials()
        .ok()
        .is_some_and(|(device, _secret)| {
            device
                .sources
                .iter()
                .any(|configured_source| configured_source == slug)
        })
}

const CONNECTOR_REGISTRY_JSON: &str = include_str!(env!("OTTTO_CONNECTOR_REGISTRY_PATH"));

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorRegistry {
    schema_version: String,
    sources: Vec<RegistrySourceEntry>,
}

#[allow(dead_code, reason = "fields pin the registry schema; some unread")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySourceEntry {
    source_id: String,
    app_slug: String,
    display_name: String,
    publisher: String,
    review_tier: ConnectorReviewTier,
    maturity: ConnectorMaturity,
    operations: Vec<SourceOperation>,
    manifest_path: String,
    collectors: Vec<RegistryCollectorEntry>,
}

#[allow(dead_code, reason = "fields pin the registry schema; some unread")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryCollectorEntry {
    collector_id: String,
    display_name: String,
    operations: Vec<SourceOperation>,
    data_source_kind: CollectorDataSourceKind,
    default_state: CollectorDefaultState,
    review_tier: ConnectorReviewTier,
    maturity: ConnectorMaturity,
    risk_classes: Vec<CollectorRiskClass>,
    uploads_raw_content: bool,
    emits: Vec<String>,
    manifest_path: String,
}

fn connector_registry() -> &'static ConnectorRegistry {
    static REGISTRY: OnceLock<ConnectorRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry: ConnectorRegistry = serde_json::from_str(CONNECTOR_REGISTRY_JSON)
            .expect("generated connector registry should match the local protocol");
        if registry.schema_version != "connector_registry.v1" {
            panic!(
                "unsupported generated connector registry schema version: {}",
                registry.schema_version
            );
        }
        registry
    })
}

fn registry_source(source: &SourceKind) -> &'static RegistrySourceEntry {
    let source_id = source_slug(source);
    connector_registry()
        .sources
        .iter()
        .find(|entry| entry.source_id == source_id)
        .unwrap_or_else(|| panic!("generated connector registry is missing source {source_id}"))
}

pub(crate) fn upsert_agent_status_snapshot(state: &mut DaemonState, snapshot: AgentStatusSnapshot) {
    state.stamp_first_seen(&snapshot.source, Some(&snapshot.captured_at));
    // Recompute the mutable companion fields up front: the in-place branch
    // below updates an existing row without rebuilding it, so telemetry/
    // reconciliation would otherwise go stale (e.g. after telemetry is
    // configured). connected_at is left untouched — it is a stable first-seen.
    let telemetry_configured = telemetry_configured_for_source(&snapshot.source);
    let reconciliation_enabled = state.reconciliation_enabled(&snapshot.source);
    if let Some(index) = state
        .sources
        .iter()
        .position(|health| health.source == snapshot.source)
    {
        let existing = state.sources[index].clone();
        let mut refreshed = source_health_from_agent_status(state, snapshot);
        if refreshed.config.path_hint.is_none() {
            refreshed.config.path_hint = existing.config.path_hint.clone();
        }
        if refreshed.config.fingerprint.is_none() {
            refreshed.config.fingerprint = existing.config.fingerprint.clone();
        }
        refreshed.config.discovered |= existing.config.discovered;
        if refreshed.collector.is_none() {
            refreshed.collector = existing.collector.clone();
        }
        if refreshed.connected_at.is_none() {
            refreshed.connected_at = existing.connected_at.clone();
        }
        if refreshed.detected_uses.is_empty() {
            refreshed.detected_uses = existing.detected_uses.clone();
        }
        refreshed.telemetry_configured = telemetry_configured;
        refreshed.reconciliation_enabled = reconciliation_enabled;
        preserve_blocking_verification_state(&mut refreshed, &existing);
        if let Some(problem) = existing
            .problems
            .iter()
            .find(|p| claude_shell_telemetry::is_problem(p))
        {
            claude_shell_telemetry::apply(&mut refreshed, Some(problem.clone()));
        }
        state.sources[index] = refreshed;
        return;
    }
    let health = source_health_from_agent_status(state, snapshot);
    state.sources.push(health);
}

pub(crate) fn source_health_from_agent_status(
    state: &DaemonState,
    snapshot: AgentStatusSnapshot,
) -> SourceHealth {
    let observed_account_id = snapshot
        .account
        .as_ref()
        .and_then(|account| account.account_id.clone().or_else(|| account.email.clone()));
    let expected_account_id = state.account.user.as_ref().map(|user| user.id.clone());
    let (source_state, grade, problems) = match snapshot.status {
        AgentStatusState::Available if agent_status::claude_default_check_skipped(&snapshot) => claude_connected_health(),
        AgentStatusState::Available => match usage_checks_paused_problem(&snapshot) {
            // The current login works, so the source stays healthy; paused
            // usage checks for an account are an attention grade with a
            // plain-words problem, never a repair or sign-in request.
            Some(problem) => (SourceState::Healthy, HealthGrade::Warning, vec![problem]),
            None => (SourceState::Healthy, HealthGrade::Ok, Vec::new()),
        },
        AgentStatusState::NotInstalled => (
            SourceState::NotFound,
            HealthGrade::Unknown,
            vec![HealthProblem {
                code: StableProblemCode::SourceNotInstalled,
                title: format!("{} is not installed", source_display_name(&snapshot.source)),
                detail: "The local CLI or safe metadata was not found on this machine.".to_string(),
                retryable: false,
            }],
        ),
        AgentStatusState::Unsupported => (
            SourceState::Unsupported,
            HealthGrade::Unknown,
            vec![HealthProblem {
                code: StableProblemCode::UnsupportedPlatform,
                title: format!(
                    "{} status is unsupported",
                    source_display_name(&snapshot.source)
                ),
                detail: "This source does not expose richer local account or limit status yet."
                    .to_string(),
                retryable: false,
            }],
        ),
        AgentStatusState::Degraded if snapshot.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.code.as_str(),
                    "claude_registered_slot_needs_attention_current_available"
                        | "codex_registered_slot_needs_attention_current_available"
                )
            }) => {
            (
                SourceState::NeedsConfirmation,
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::SecretExpired,
                    title: format!(
                        "{} durable connections need attention",
                        source_display_name(&snapshot.source)
                    ),
                    detail: "The current login remains available. One or more saved account connections need attention; their last verified identities remain separate.".to_string(),
                    retryable: true,
                }],
            )
        }
        // A failed Codex usage check (for example a timeout) is retried at
        // the next poll; the login is not in question.
        AgentStatusState::Degraded
            if snapshot
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "codex_usage_read_retrying") =>
        {
            (
                SourceState::Healthy,
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::Unknown,
                    title: CODEX_USAGE_READ_RETRYING_TITLE.to_string(),
                    detail: "The last Codex usage check failed, for example it timed out. It is retried at the next check; until then the last readings are shown as stale.".to_string(),
                    retryable: true,
                }],
            )
        }
        AgentStatusState::AuthRequired | AgentStatusState::Degraded | AgentStatusState::Unknown => {
            (
                SourceState::NeedsConfirmation,
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::SecretMissing,
                    title: format!(
                        "{} needs account confirmation",
                        source_display_name(&snapshot.source)
                    ),
                    detail:
                        "Ottto could not confirm a signed-in local account from safe CLI metadata."
                            .to_string(),
                    retryable: true,
                }],
            )
        }
        AgentStatusState::Error => (
            SourceState::Failed,
            HealthGrade::Critical,
            vec![HealthProblem {
                code: StableProblemCode::Unknown,
                title: format!(
                    "{} status collection failed",
                    source_display_name(&snapshot.source)
                ),
                detail: "Local status collection failed without exposing raw command output."
                    .to_string(),
                retryable: true,
            }],
        ),
    };
    let detected_uses = detected_uses_for_health(&snapshot.source, Some(&snapshot));
    SourceHealth {
        source: snapshot.source.clone(),
        descriptor: source_descriptor(&snapshot.source),
        state: source_state,
        grade,
        account_binding: AccountBindingState {
            expected_account_id,
            observed_account_id,
            matched: None,
        },
        config: SourceConfigState {
            discovered: !matches!(snapshot.status, AgentStatusState::NotInstalled),
            path_hint: None,
            fingerprint: None,
            drift: Vec::new(),
        },
        collector: None,
        agent_status: Some(snapshot.clone()),
        plan_observations: snapshot.plan_observations.clone(),
        detected_uses,
        active_session_reconciliation: None,
        collection: None,
        tracking_confirmation: None,
        last_seen_at: Some(snapshot.captured_at.clone()),
        last_verified_at: None,
        problems,
        recommended_actions: Vec::new(),
        connected_at: state.first_seen(&snapshot.source),
        telemetry_configured: telemetry_configured_for_source(&snapshot.source),
        reconciliation_enabled: state.reconciliation_enabled(&snapshot.source),
        source_paused: false,
    }
}

/// Per-source detected-uses cache file:
/// `<support_dir>/detected_uses/<source slug>.json`. Written by `snapshot_sync`
/// after each scan, read here to attach to health.
fn detected_uses_cache_path(support_dir: &Path, source: &SourceKind) -> PathBuf {
    support_dir
        .join("detected_uses")
        .join(format!("{}.json", source_slug(source)))
}

/// Load the persisted detected uses for a source. A missing or unreadable cache
/// yields an empty list (graceful empty — the panel shows nothing rather than
/// erroring), as does a malformed file.
fn load_detected_uses_for_source(source: &SourceKind) -> Vec<DetectedUse> {
    let path = detected_uses_cache_path(&default_support_dir(), source);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Vec<DetectedUse>>(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Detected uses for a source's health, with live quota overlaid onto the
/// destination matching the current account's plan when `agent_status` carries
/// quota windows. Historical destinations keep `Unknown`/`None` quota.
pub(crate) fn detected_uses_for_health(
    source: &SourceKind,
    agent_status: Option<&AgentStatusSnapshot>,
) -> Vec<DetectedUse> {
    let mut detected = prune_detected_uses_for_health(
        load_detected_uses_for_source(source),
        OffsetDateTime::now_utc(),
    );
    if let Some(snapshot) = agent_status {
        merge_current_plan_quota(&mut detected, snapshot);
    }
    detected
}

pub(crate) fn prune_detected_uses_for_health(
    detected: Vec<DetectedUse>,
    now: OffsetDateTime,
) -> Vec<DetectedUse> {
    prune_stale_detected_uses(
        detected,
        now,
        TimeDuration::days(DETECTED_USE_RETENTION_DAYS),
    )
}

/// Overlay the current plan's live quota onto the detected use whose
/// `subscription_product` matches the account's plan. Other destinations are
/// left at `Unknown`/`None`: smearing the current plan's quota across
/// destinations it does not bill to would be misleading.
pub(crate) fn merge_current_plan_quota(
    detected: &mut [DetectedUse],
    snapshot: &AgentStatusSnapshot,
) {
    let Some(account) = snapshot.account.as_ref() else {
        return;
    };
    let plan_keys: Vec<String> = [
        account.plan_type.as_deref(),
        account.subscription_product.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(|value| value.trim().to_ascii_lowercase())
    .filter(|value| !value.is_empty())
    .collect();
    if plan_keys.is_empty() {
        return;
    }
    let account_windows: Vec<AgentQuotaWindow> = snapshot
        .quota_windows
        .iter()
        .filter(|window| quota_window_matches_snapshot_account(snapshot, window))
        .cloned()
        .collect();
    let Some(window) = pick_quota_window(&account_windows) else {
        return;
    };
    let (state, used_percent, resets_at) = quota_state_from_window(window);
    for entry in detected.iter_mut() {
        let matches_current = entry
            .subscription_product
            .as_deref()
            .map(|product| plan_keys.contains(&product.trim().to_ascii_lowercase()))
            .unwrap_or(false);
        if matches_current {
            entry.quota_window_state = state.clone();
            entry.quota_used_percent = used_percent;
            entry.quota_resets_at = resets_at.clone();
        }
    }
}

pub(crate) fn quota_window_matches_snapshot_account(
    snapshot: &AgentStatusSnapshot,
    window: &AgentQuotaWindow,
) -> bool {
    let window_account_hash = window
        .account_identifier_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let window_organization_hash = window
        .organization_identifier_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if window_account_hash.is_some() || window_organization_hash.is_some() {
        let Some(account) = snapshot.account.as_ref() else {
            return false;
        };
        if let Some(window_account_hash) = window_account_hash {
            let account_matches = account
                .account_identifier_hash
                .as_deref()
                .map(str::trim)
                .is_some_and(|account_hash| account_hash == window_account_hash);
            if !account_matches {
                return false;
            }
        }
        return match window_organization_hash {
            Some(window_organization_hash) => account
                .organization_identifier_hash
                .as_deref()
                .map(str::trim)
                .is_some_and(|organization_hash| organization_hash == window_organization_hash),
            None => true,
        };
    }
    let Some(window_label) = window
        .account_label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return true;
    };
    snapshot
        .account
        .as_ref()
        .and_then(|account| account.email.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|account_label| account_label.eq_ignore_ascii_case(window_label))
}

/// Pick the most constraining quota window: a rate-limited window first, then
/// the highest used-percent. `None` when there are no windows.
fn pick_quota_window(windows: &[AgentQuotaWindow]) -> Option<&AgentQuotaWindow> {
    windows.iter().max_by_key(|window| {
        let rate_limited = matches!(window.status, AgentQuotaWindowStatus::RateLimited);
        (rate_limited, window.used_percent.unwrap_or(0))
    })
}

/// Map a quota window to the Companion's detected-use quota state. A
/// rate-limited or stale window maps directly; otherwise used-percent decides:
/// `>= 100` exhausted, `>= 80` near limit, else ok. A window with no percent is
/// `Unknown`.
fn quota_state_from_window(
    window: &AgentQuotaWindow,
) -> (DetectedUseQuotaWindowState, Option<u8>, Option<String>) {
    let stale = matches!(window.freshness, AgentQuotaWindowFreshness::Stale)
        || matches!(window.status, AgentQuotaWindowStatus::Stale);
    let state = if matches!(window.status, AgentQuotaWindowStatus::RateLimited) {
        DetectedUseQuotaWindowState::RateLimited
    } else if stale {
        DetectedUseQuotaWindowState::Stale
    } else {
        match window.used_percent {
            Some(percent) if percent >= 100 => DetectedUseQuotaWindowState::Exhausted,
            Some(percent) if percent >= 80 => DetectedUseQuotaWindowState::NearLimit,
            Some(_) => DetectedUseQuotaWindowState::Ok,
            None => DetectedUseQuotaWindowState::Unknown,
        }
    };
    (state, window.used_percent, window.resets_at.clone())
}

pub(crate) fn source_descriptor(source: &SourceKind) -> SourceDescriptor {
    let registry_source = registry_source(source);
    require_local_source_operations(registry_source);
    let mut operations: Vec<SourceOperationDescriptor> = registry_source
        .operations
        .iter()
        .cloned()
        .map(source_operation)
        .collect();
    if !registry_source
        .operations
        .contains(&SourceOperation::UninstallRestore)
    {
        operations.push(source_operation(SourceOperation::UninstallRestore));
    }

    SourceDescriptor {
        source: source.clone(),
        display_name: registry_source.display_name.clone(),
        operations,
        review_tier: registry_source.review_tier.clone(),
        maturity: registry_source.maturity.clone(),
        collectors: registry_source
            .collectors
            .iter()
            .map(collector_descriptor)
            .collect(),
        local_state_owner: SourceStateOwner::LocalDaemon,
        telemetry_owner: SourceStateOwner::LocalDaemon,
        repair_owner: SourceStateOwner::LocalDaemon,
    }
}

fn require_local_source_operations(source: &RegistrySourceEntry) {
    for operation in [
        SourceOperation::Detect,
        SourceOperation::Verify,
        SourceOperation::Repair,
        SourceOperation::CollectUsage,
        SourceOperation::MonitorQuota,
        SourceOperation::UploadSnapshot,
        SourceOperation::Diagnostics,
    ] {
        if !source.operations.contains(&operation) {
            panic!(
                "generated connector registry source {} is missing required local operation {:?}",
                source.source_id, operation
            );
        }
    }
}

fn collector_descriptor(collector: &RegistryCollectorEntry) -> CollectorDescriptor {
    CollectorDescriptor {
        collector_id: collector.collector_id.clone(),
        display_name: collector.display_name.clone(),
        operations: collector.operations.clone(),
        data_source_kind: collector.data_source_kind.clone(),
        default_state: collector.default_state.clone(),
        review_tier: collector.review_tier.clone(),
        maturity: collector.maturity.clone(),
        risk_classes: collector.risk_classes.clone(),
        uploads_raw_content: collector.uploads_raw_content,
        emits: collector.emits.clone(),
    }
}

fn source_operation(operation: SourceOperation) -> SourceOperationDescriptor {
    let requires_approval = matches!(
        &operation,
        SourceOperation::Repair | SourceOperation::UninstallRestore
    );
    let reason = match &operation {
        SourceOperation::MonitorQuota => {
            Some("Quota windows are display-only plan facts and never imply spend.".to_string())
        }
        SourceOperation::UninstallRestore => Some(
            "Restore uses daemon-owned backups and avoids revoke, delete, or disconnect actions."
                .to_string(),
        ),
        _ => None,
    };

    SourceOperationDescriptor {
        operation,
        supported: true,
        state: SourceOperationState::Available,
        requires_approval,
        destructive: false,
        reason,
    }
}

pub(crate) fn source_display_name(source: &SourceKind) -> String {
    registry_source(source).display_name.clone()
}
