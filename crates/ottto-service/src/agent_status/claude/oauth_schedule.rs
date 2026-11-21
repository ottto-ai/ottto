//! Claude status oauth schedule operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::claude_cli_config_path;
use crate::agent_status::claude_config_slot_for_descriptor;
use crate::agent_status::claude_credit_pools;
use crate::agent_status::claude_oauth_account_session_not_offered;
use crate::agent_status::claude_oauth_account_weekly_not_offered;
use crate::agent_status::claude_oauth_binding_key;
use crate::agent_status::claude_oauth_credit_balances;
use crate::agent_status::claude_oauth_quota_windows;
use crate::agent_status::claude_oauth_stamp_account_identity;
use crate::agent_status::claude_oauth_usage_account_state_dir;
use crate::agent_status::credit_amount_input;
use crate::agent_status::current_unix_seconds;
use crate::agent_status::default_support_dir;
use crate::agent_status::fs;
use crate::agent_status::home_dir;
use crate::agent_status::read_claude_oauth_usage_cache_with_legacy_migration;
use crate::agent_status::read_claude_statusline_cache;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::write_claude_oauth_usage_cache;
use crate::agent_status::AgentCreditBalance;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentStatusCollection;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeOAuthUsage;
use crate::agent_status::ClaudeOAuthUsageCache;
use crate::agent_status::ClaudeOAuthUsageCaller;
use crate::agent_status::ClaudeOAuthUsageOutcome;
use crate::agent_status::Digest;
use crate::agent_status::FileClaudeConfigSlotSettingsStore;
use crate::agent_status::Mutex;
use crate::agent_status::PathBuf;
use crate::agent_status::Sha256;
use crate::agent_status::Value;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION;
use crate::agent_status::CLAUDE_OAUTH_USAGE_REFRESH_SECONDS;
use crate::agent_status::CLAUDE_PASS;

/// The next time, strictly after `now` (unix seconds), that a Claude binding
/// in `collection` is due its reset read, so the status lane can run its pass
/// then rather than up to one interval later. Read from each binding's stored
/// reading, the same inputs the collector's due check uses.
pub(crate) fn claude_next_reset_read_at(
    collection: &AgentStatusCollection,
    now: u64,
) -> Option<u64> {
    collection
        .snapshots
        .iter()
        .flat_map(|snapshot| &snapshot.quota_windows)
        .filter_map(|window| {
            Some((
                window.account_identifier_hash.as_deref()?,
                window.organization_identifier_hash.as_deref()?,
            ))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|(account, organization)| {
            let cache =
                read_claude_oauth_usage_cache_with_legacy_migration(account, organization, false)?;
            claude_credit_pools::claude_reset_read_at(
                &cache.windows,
                cache.observed_at_epoch_seconds,
                cache.next_refresh_after_epoch_seconds,
                claude_credit_pools::claude_reset_read_delay_seconds(account, organization),
            )
        })
        .filter(|at| *at > now)
        .min()
}

/// Per caller: the binding its login was seen on, pass after pass. In memory
/// only, so a restart starts every run afresh.
pub(in crate::agent_status) static CLAUDE_OAUTH_CALLER_BINDINGS: Mutex<
    BTreeMap<String, claude_credit_pools::ClaudeCallerBinding>,
> = Mutex::new(BTreeMap::new());

/// Callers that reached the usage collector during the open full collection
/// pass(es), with the number of open passes.
pub(in crate::agent_status) static CLAUDE_OAUTH_PASS_CALLERS: Mutex<(usize, BTreeSet<String>)> =
    Mutex::new((0, BTreeSet::new()));

/// One full collection pass (`collect_claude_status_snapshots`). When the last
/// open pass ends, every caller run not seen at the collector during it ends.
///
/// Overlapping passes share one reached set (their union), and the sweep runs
/// when the last of them ends: a caller reached by one overlapping pass but
/// skipped by another keeps its run here. The skipping pass's explicit run-end
/// on that skip return, and the 15 min run gap, still apply, so the sweep is
/// defense in depth for that case rather than the only guard.
pub(in crate::agent_status) struct ClaudeOAuthCollectionPass;

impl ClaudeOAuthCollectionPass {
    pub(in crate::agent_status) fn begin() -> Self {
        let mut open = CLAUDE_OAUTH_PASS_CALLERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if open.0 == 0 {
            open.1.clear();
        }
        open.0 += 1;
        Self
    }
}

impl Drop for ClaudeOAuthCollectionPass {
    fn drop(&mut self) {
        let reached = {
            let mut open = CLAUDE_OAUTH_PASS_CALLERS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            open.0 = open.0.saturating_sub(1);
            if open.0 > 0 {
                return;
            }
            std::mem::take(&mut open.1)
        };
        claude_credit_pools::claude_keep_caller_bindings(
            &mut CLAUDE_OAUTH_CALLER_BINDINGS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &reached,
        );
    }
}

pub(in crate::agent_status) fn claude_oauth_pass_reached_collector(
    caller: &ClaudeOAuthUsageCaller,
) {
    let mut open = CLAUDE_OAUTH_PASS_CALLERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if open.0 > 0 {
        open.1.insert(caller.breaker_key());
    }
}

/// A pass did not see this caller signed in to a usable binding (an identity
/// gate refused it, its identity did not resolve, or a browser re-sign-in
/// suppressed it): end its run so no passive body fetched meanwhile is ever
/// adopted.
pub(in crate::agent_status) fn claude_oauth_end_caller_run(caller: &ClaudeOAuthUsageCaller) {
    claude_credit_pools::claude_end_caller_binding(
        &mut CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        &caller.breaker_key(),
    );
}

pub(in crate::agent_status) fn claude_oauth_end_slot_run(slot_id: &str) {
    claude_oauth_end_caller_run(&ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.to_string()));
}

/// One usable OAuth usage body: a provider response, or a passive reading
/// Claude Code made for the same binding.
#[derive(Clone, Copy)]
pub(in crate::agent_status) struct ClaudeOAuthReading<'a> {
    pub(in crate::agent_status) account_identifier_hash: &'a str,
    pub(in crate::agent_status) organization_identifier_hash: &'a str,
    pub(in crate::agent_status) body: &'a Value,
    pub(in crate::agent_status) read: claude_credit_pools::ClaudeUsageRead,
    /// When the body was read: the local response time, or the passive
    /// reading's own fetch time.
    pub(in crate::agent_status) observed_at_epoch_seconds: u64,
    pub(in crate::agent_status) previous_credit_balances: &'a [AgentCreditBalance],
    pub(in crate::agent_status) latest_activity_at: Option<u64>,
    pub(in crate::agent_status) now: u64,
    pub(in crate::agent_status) legacy_root_migration: bool,
}

/// Parse, merge and store one reading. `Err` carries the unstored parse when
/// the body has no supported quota window (a shape change).
pub(in crate::agent_status) fn claude_oauth_usage_record_reading(
    reading: ClaudeOAuthReading<'_>,
    read_schedule: &mut claude_credit_pools::ClaudeReadSchedule,
) -> Result<ClaudeOAuthUsage, ClaudeOAuthUsage> {
    let observed_at = rfc3339_from_unix_seconds(reading.observed_at_epoch_seconds);
    let mut usage = ClaudeOAuthUsage {
        windows: claude_oauth_quota_windows(reading.body),
        credit_balances: Vec::new(),
        account_weekly_not_offered: claude_oauth_account_weekly_not_offered(reading.body),
        account_session_not_offered: claude_oauth_account_session_not_offered(reading.body),
    };
    let Some(observed_at) = observed_at.filter(|_| !usage.windows.is_empty()) else {
        usage.credit_balances = claude_oauth_credit_balances(reading.body);
        return Err(usage);
    };
    let credit_read =
        claude_credit_pools::claude_credit_read(reading.body, reading.read, &observed_at);
    if !credit_read.diagnostics.is_empty() {
        // Field paths only, never values.
        let fields = credit_read
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{}:{}", diagnostic.code, diagnostic.field))
            .collect::<BTreeSet<_>>();
        eprintln!(
            "claude_status credit_fields_refused fields={}",
            fields.into_iter().collect::<Vec<_>>().join(",")
        );
    }
    usage.credit_balances = claude_credit_pools::claude_merge_credit_sections(
        &claude_oauth_binding_key(
            reading.account_identifier_hash,
            reading.organization_identifier_hash,
        ),
        reading.previous_credit_balances,
        &credit_read,
    );
    claude_oauth_stamp_account_identity(
        &mut usage,
        reading.account_identifier_hash,
        Some(reading.organization_identifier_hash),
    );
    claude_credit_pools::label_credit_freshness(
        &mut usage.credit_balances,
        claude_oauth_usage_serve_gate_seconds(
            reading.account_identifier_hash,
            reading.organization_identifier_hash,
            reading.now,
        ),
        reading.observed_at_epoch_seconds,
        reading.now,
    );
    for window in &mut usage.windows {
        window.observed_at = Some(observed_at.clone());
    }
    let cache = ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: reading.account_identifier_hash.to_string(),
        organization_identifier_hash: reading.organization_identifier_hash.to_string(),
        observed_at_epoch_seconds: reading.observed_at_epoch_seconds,
        next_refresh_after_epoch_seconds: claude_spacing_anchor(reading.now)
            + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
        windows: usage.windows.clone(),
        credit_balances: usage.credit_balances.clone(),
        account_weekly_not_offered: usage.account_weekly_not_offered,
        account_session_not_offered: usage.account_session_not_offered,
    };
    let _ = write_claude_oauth_usage_cache(&cache);
    read_schedule.after_reading(
        reading.read,
        reading.observed_at_epoch_seconds,
        reading.latest_activity_at,
        reading.now,
    );
    let _ = claude_credit_pools::write_claude_read_schedule(
        &claude_oauth_usage_account_state_dir(
            reading.account_identifier_hash,
            reading.organization_identifier_hash,
        ),
        read_schedule,
    );
    Ok(usage)
}

/// The Claude Code config file of this caller's own login, whose passive
/// reading may stand in for a call.
pub(in crate::agent_status) fn claude_oauth_caller_identity_path(
    caller: &ClaudeOAuthUsageCaller,
) -> Option<PathBuf> {
    match caller {
        ClaudeOAuthUsageCaller::Default | ClaudeOAuthUsageCaller::DefaultDeferredToSlot => {
            Some(claude_cli_config_path())
        }
        ClaudeOAuthUsageCaller::RegisteredSlot(slot_id) => {
            let registry = FileClaudeConfigSlotSettingsStore::default().load().ok()?;
            registry
                .managed_slots
                .iter()
                .chain(registry.external_slots.iter())
                .find(|descriptor| &descriptor.slot_id == slot_id)
                .and_then(claude_config_slot_for_descriptor)
                .map(|slot| slot.identity_path(&home_dir()))
        }
    }
}

/// This caller's Claude Code config checked against the binding. An
/// unreadable config is not signed in to it. Reads only
/// `cachedUsageUtilization` and `oauthAccount`.
pub(in crate::agent_status) fn claude_oauth_passive_config(
    caller: &ClaudeOAuthUsageCaller,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> claude_credit_pools::ClaudePassiveConfig {
    claude_oauth_caller_identity_path(caller)
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|body| {
            credit_amount_input::decode(&body, credit_amount_input::CreditBody::ClaudeConfig)
        })
        .map(|config| {
            claude_credit_pools::claude_passive_config(
                &config,
                account_identifier_hash,
                organization_identifier_hash,
            )
        })
        .unwrap_or_default()
}

/// Latest activity for this exact binding and its feed's observation horizon,
/// read together from the daemon's completed Claude active-session scan.
pub(in crate::agent_status) fn claude_oauth_activity(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> (Option<u64>, Option<u64>) {
    let reconciliation = crate::active_sessions::read_active_session_reconciliation(
        &default_support_dir(),
        crate::snapshots::SnapshotSource::ClaudeCode,
    );
    (
        claude_credit_pools::claude_latest_activity_at(
            reconciliation.as_ref(),
            account_identifier_hash,
            organization_identifier_hash,
        ),
        claude_credit_pools::claude_activity_feed_fresh_at(reconciliation.as_ref()),
    )
}

/// The binding's read slot: in use (5 min) or unused (the jittered gate
/// below).
pub(in crate::agent_status) fn claude_oauth_usage_slot_seconds(
    read_schedule: &claude_credit_pools::ClaudeReadSchedule,
    latest_activity_at: Option<u64>,
    feed_fresh_at: Option<u64>,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: u64,
) -> u64 {
    claude_credit_pools::claude_usage_slot_seconds(
        read_schedule,
        latest_activity_at,
        feed_fresh_at,
        claude_oauth_usage_fresh_age_seconds(account_identifier_hash, organization_identifier_hash),
        now,
    )
}

/// How old a stored reading may be and still be labelled fresh: the
/// unused-account gate plus one collection interval. A read becomes due at
/// the gate, but the next scheduled collection can be up to five minutes
/// later. Keep that bounded scheduling gap from making healthy idle accounts
/// flash stale. This does not defer a provider read or move its observation.
/// The shorter in-use slot never labels a reading stale sooner.
pub(in crate::agent_status) fn claude_oauth_usage_serve_gate_seconds(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    _now: u64,
) -> u64 {
    claude_oauth_usage_fresh_age_seconds(account_identifier_hash, organization_identifier_hash)
        .saturating_add(CLAUDE_OAUTH_USAGE_REFRESH_SECONDS)
}

/// Whether Claude Code's local statusLine wrote a reading for exactly this
/// account and organization within the in-use slot: the free local data an
/// in-use account prefers over a provider read. Only an exact v4 stamp from a
/// method the serve path attributes (`config_dir`, `session_store`) counts.
pub(in crate::agent_status) fn claude_statusline_fresh_for_binding(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: u64,
) -> bool {
    let Ok(Some(cache)) = read_claude_statusline_cache(&default_support_dir()) else {
        return false;
    };
    !cache.windows.is_empty()
        && cache.observed_at_epoch_seconds <= now.saturating_add(60)
        && now.saturating_sub(cache.observed_at_epoch_seconds)
            <= claude_credit_pools::ACTIVE_SLOT_SECONDS
        && !account_identifier_hash.is_empty()
        && cache.observed_under_account_identifier_hash == account_identifier_hash
        && cache.observed_under_organization_identifier_hash.as_deref()
            == Some(organization_identifier_hash)
        && matches!(
            cache.observed_under_account_method.as_str(),
            "config_dir" | "session_store"
        )
}

/// Explicit refresh requests from the companion's Refresh button, for the
/// Claude usage gate: refresh every account now, at most once a minute per
/// account. A request lapses after [`CLAUDE_EXPLICIT_REFRESH_TTL_SECONDS`] so
/// a request whose read keeps failing never turns into a retry loop.
pub(in crate::agent_status) const CLAUDE_EXPLICIT_REFRESH_TTL_SECONDS: u64 = 2 * 60;

pub(in crate::agent_status) const CLAUDE_EXPLICIT_REFRESH_MIN_GAP_SECONDS: u64 = 60;

/// The last explicit refresh request: when it was made (0: never) and why,
/// for the provider-call log of the reads it causes on the lane thread.
pub(in crate::agent_status) struct ClaudeExplicitRefreshRequest {
    pub(in crate::agent_status) at: u64,
    pub(in crate::agent_status) trigger: crate::provider_calls::Trigger,
}

pub(in crate::agent_status) fn claude_explicit_refresh_request(
) -> std::sync::MutexGuard<'static, ClaudeExplicitRefreshRequest> {
    static REQUEST: Mutex<ClaudeExplicitRefreshRequest> =
        Mutex::new(ClaudeExplicitRefreshRequest {
            at: 0,
            trigger: crate::provider_calls::Trigger::ExplicitRefresh,
        });
    REQUEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Ask the next Claude collection to read every account now, each only when
/// its stored reading and its last explicit refresh are both at least a
/// minute old. The caller's trigger (setup or sign-in) labels
/// those reads; a person's Refresh is the default.
pub(crate) fn request_claude_explicit_refresh() {
    *claude_explicit_refresh_request() = ClaudeExplicitRefreshRequest {
        at: current_unix_seconds(),
        trigger: crate::provider_calls::trigger_or(crate::provider_calls::Trigger::ExplicitRefresh),
    };
}

/// Whether an explicit refresh asks to read this binding now: a live request
/// made after the stored reading and after the last refresh this binding
/// answered, both at least a minute ago. The read still passes every hold,
/// breaker and Retry-After check after this.
pub(in crate::agent_status) fn claude_explicit_refresh_requested(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    reading_observed_at: u64,
    now: u64,
) -> bool {
    let requested_at = claude_explicit_refresh_request().at;
    let last = claude_binding_time(
        &claude_explicit_refresh_attempts(),
        account_identifier_hash,
        organization_identifier_hash,
    )
    .map_or(reading_observed_at, |at| at.max(reading_observed_at));
    let skewed = last > now.saturating_add(60);
    requested_at != 0
        && now.saturating_sub(requested_at) <= CLAUDE_EXPLICIT_REFRESH_TTL_SECONDS
        && (skewed || now.saturating_sub(last) >= CLAUDE_EXPLICIT_REFRESH_MIN_GAP_SECONDS)
        && requested_at > last
}

/// A per-binding time kept in memory (bounded): the last explicit refresh a
/// binding answered, or its last transient read failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::agent_status) struct ClaudeBindingTime {
    pub(in crate::agent_status) account_identifier_hash: String,
    pub(in crate::agent_status) organization_identifier_hash: String,
    pub(in crate::agent_status) at: u64,
}

pub(in crate::agent_status) const CLAUDE_BINDING_TIMES_MAX: usize = 64;

pub(in crate::agent_status) fn claude_binding_time(
    times: &[ClaudeBindingTime],
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<u64> {
    times
        .iter()
        .find(|time| {
            time.account_identifier_hash == account_identifier_hash
                && time.organization_identifier_hash == organization_identifier_hash
        })
        .map(|time| time.at)
}

pub(in crate::agent_status) fn set_claude_binding_time(
    times: &mut Vec<ClaudeBindingTime>,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    at: u64,
) {
    times.retain(|time| {
        time.account_identifier_hash != account_identifier_hash
            || time.organization_identifier_hash != organization_identifier_hash
    });
    times.push(ClaudeBindingTime {
        account_identifier_hash: account_identifier_hash.to_string(),
        organization_identifier_hash: organization_identifier_hash.to_string(),
        at,
    });
    let excess = times.len().saturating_sub(CLAUDE_BINDING_TIMES_MAX);
    times.drain(..excess);
}

/// The last time each binding answered an explicit refresh, whatever the
/// read's outcome: a failed read consumes the request and still counts for
/// the once-a-minute limit.
pub(in crate::agent_status) fn claude_explicit_refresh_attempts(
) -> std::sync::MutexGuard<'static, Vec<ClaudeBindingTime>> {
    static ATTEMPTS: Mutex<Vec<ClaudeBindingTime>> = Mutex::new(Vec::new());
    ATTEMPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(in crate::agent_status) fn note_claude_explicit_refresh_attempt(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: u64,
) {
    set_claude_binding_time(
        &mut claude_explicit_refresh_attempts(),
        account_identifier_hash,
        organization_identifier_hash,
        now,
    );
}

/// Until when each binding's last 429 asked us to wait, kept in memory too: an
/// explicit refresh never reads inside it, even if the persisted breaker is
/// not usable (for example after a configuration change).
pub(in crate::agent_status) fn claude_rate_limit_holds(
) -> std::sync::MutexGuard<'static, Vec<ClaudeBindingTime>> {
    static HOLDS: Mutex<Vec<ClaudeBindingTime>> = Mutex::new(Vec::new());
    HOLDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(in crate::agent_status) fn claude_rate_limit_held(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: u64,
) -> bool {
    claude_binding_time(
        &claude_rate_limit_holds(),
        account_identifier_hash,
        organization_identifier_hash,
    )
    .is_some_and(|until| now < until)
}

/// The collection pass running on this thread: set by the status lane around
/// each collection.
#[derive(Debug, Clone, Copy)]
pub(in crate::agent_status) struct ClaudePass {
    /// An app's status request: serve stored readings. Only an explicit
    /// refresh reads the provider in such a pass.
    pub(in crate::agent_status) saved_only: bool,
    /// When the pass started (unix seconds).
    pub(in crate::agent_status) started_at: u64,
}

/// Run one collection as a pass that started at `started_at`. `saved_only`
/// marks a pass an app's status request started.
pub(crate) fn with_claude_pass<T>(
    saved_only: bool,
    started_at: u64,
    collect: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<ClaudePass>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CLAUDE_PASS.with(|pass| pass.set(self.0));
        }
    }
    let _restore = Restore(CLAUDE_PASS.with(|pass| {
        pass.replace(Some(ClaudePass {
            saved_only,
            started_at,
        }))
    }));
    collect()
}

/// Whether this thread's collection serves stored Claude readings only.
pub(crate) fn claude_pass_saved_only() -> bool {
    CLAUDE_PASS.with(|pass| pass.get().is_some_and(|pass| pass.saved_only))
}

pub(in crate::agent_status) const CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE: &str =
    "Claude quota for this account has no stored reading, and background limit refresh is off; use Refresh limits to read it now.";

/// Whether this read is a background one that "Background limit refresh"
/// (the Claude upkeep consent) withholds: it runs in a collection pass of the
/// status lane (the daemon's schedule, or an app's status request) while the
/// switch is off, and its caller is not a setup check. Reads outside a pass
/// (setup and account checks, a standalone collection) and an explicit
/// refresh, which the caller checks first, are never withheld. Unreadable
/// settings count as off, as for the sign-in renewal.
pub(in crate::agent_status) fn claude_background_read_withheld() -> bool {
    use crate::provider_calls::Trigger;
    if CLAUDE_PASS.with(|pass| pass.get().is_none())
        || matches!(
            crate::provider_calls::current_trigger(),
            Some(Trigger::Setup | Trigger::ExplicitRefresh)
        )
    {
        return false;
    }
    !FileClaudeConfigSlotSettingsStore::default()
        .load()
        .is_ok_and(|status| {
            status.consent == ottto_protocol::ClaudeAccountUpkeepConsentState::Granted
        })
}

/// A pass longer than this no longer anchors its reads' spacing.
pub(in crate::agent_status) const CLAUDE_PASS_ANCHOR_MAX_SECONDS: u64 = 2 * 60;

/// Where the spacing after a successful read is measured from: the start of
/// the collection pass that read, so the next pass 5 min later finds the
/// account due wherever in that pass the read falls; `now` outside a pass.
pub(in crate::agent_status) fn claude_spacing_anchor(now: u64) -> u64 {
    CLAUDE_PASS
        .with(|pass| pass.get())
        .map(|pass| pass.started_at)
        .filter(|started| *started <= now && now - started <= CLAUDE_PASS_ANCHOR_MAX_SECONDS)
        .unwrap_or(now)
}

/// A read that failed without a status the provider asks us to act on (a
/// server error or a network failure) records no backoff of its own. The
/// binding then waits [`CLAUDE_TRANSIENT_FAILURE_RETRY_SECONDS`] before the
/// next provider request, so repeated status passes do not retry it at once.
/// Every other hold, breaker and Retry-After still applies on top.
pub(in crate::agent_status) const CLAUDE_TRANSIENT_FAILURE_RETRY_SECONDS: u64 = 60;

pub(in crate::agent_status) fn claude_transient_failures(
) -> std::sync::MutexGuard<'static, Vec<ClaudeBindingTime>> {
    static FAILURES: Mutex<Vec<ClaudeBindingTime>> = Mutex::new(Vec::new());
    FAILURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(in crate::agent_status) fn claude_transient_failure_held(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: u64,
) -> bool {
    claude_binding_time(
        &claude_transient_failures(),
        account_identifier_hash,
        organization_identifier_hash,
    )
    .is_some_and(|at| {
        at <= now.saturating_add(60)
            && now.saturating_sub(at) < CLAUDE_TRANSIENT_FAILURE_RETRY_SECONDS
    })
}

impl From<Result<ClaudeOAuthUsage, String>> for ClaudeOAuthUsageOutcome {
    fn from(result: Result<ClaudeOAuthUsage, String>) -> Self {
        Self {
            result,
            diagnostics: Vec::new(),
        }
    }
}

impl ClaudeOAuthUsageOutcome {
    pub(in crate::agent_status) fn with_check_outcome(
        mut self,
        code: &str,
        detail: &str,
        now: u64,
    ) -> Self {
        self.diagnostics
            .push(claude_quota_check_diagnostic(code, detail, now));
        self
    }
}

pub(in crate::agent_status) fn claude_quota_check_diagnostic(
    code: &str,
    detail: &str,
    now: u64,
) -> AgentStatusDiagnostic {
    AgentStatusDiagnostic::source(code, AgentDiagnosticSeverity::Info, detail)
        .with_observed_at(rfc3339_from_unix_seconds(now))
}

/// Effective freshness gate for the Claude OAuth usage read of an unused
/// account: the ~40-minute base cadence spread deterministically across a
/// 38-42 minute band.
///
/// The spread is load-spreading across OUR OWN users - it stops every Ottto
/// install from refreshing on the same wall-clock minute. It is explicitly NOT
/// evasion and hides nothing: the request carries an honest
/// `ottto/<version> (subscription-usage-reader; ...)` User-Agent, and a
/// timer-driven daemon is identifiable from its behaviour regardless of phase.
/// Recorded provider-endpoints posture, 2026-07-26.
///
/// Derived from the account hash rather than a random draw so the gate is
/// stable for a machine: a per-tick random offset would make the cadence
/// jitter around every refresh instead of holding one steady phase.
pub(in crate::agent_status) fn claude_oauth_usage_fresh_age_seconds(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-cadence:");
    hasher.update(account_identifier_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(organization_identifier_hash.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let span = CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS * 2 + 1;
    let offset = u64::from_be_bytes(bytes) % span;
    CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS + offset
        - CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS
}
