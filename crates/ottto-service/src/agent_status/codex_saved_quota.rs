//! Saved Codex quota per home, and the schedule that keeps it current.
//!
//! The daemon decides when a Codex home's quota is read from the provider
//! (one `codex app-server` run). A scheduler thread reads each home on its
//! schedule and saves the outcome on disk, one owner-only file per home.
//! Every status read (the companion's accounts poll, agent-status refreshes,
//! startup re-verify, the collection lane) serves that saved copy and never
//! starts `codex app-server` itself. Setup checks and an explicit refresh read
//! the provider directly and update the same copy.
//!
//! Schedule per home:
//! - in use on this Mac (a Codex process held a rollout in the home, or a
//!   session that belongs to it was written, in the last 30 min): every 5 min;
//! - otherwise every 15 min;
//! - a failed read waits the same interval before the next attempt;
//! - a changed local login (`auth.json` changed since the last read) is read
//!   again after at least 1 min;
//! - an explicit refresh reads now, at most once a minute per home.
//!
//! A saved reading is served only while the home's local credential still
//! names the same account and workspace (or, when the credential cannot be
//! decoded, while `auth.json` is unchanged since the read), so a reading never
//! moves to another login. A reading carries identity hashes only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use ottto_core::{default_support_dir, CodexHomeTrust, FileCodexAccountSlotSettingsStore};
use ottto_protocol::{
    ActiveSession, AgentAccountStatus, AgentCreditBalance, AgentLoginState, AgentQuotaWindow,
    AgentStatusConfidence, CodexAccountSlotOwnershipV1, SourceKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    chatgpt_subscription_product, codex_credential_claimed_binding, codex_credit_grants,
    codex_home_slots, codex_last_known, current_unix_seconds, empty_codex_accounts_status,
    mark_quota_meters_stale, read_codex_auth_credentials_at, read_codex_usage_from_provider,
    unsupported_account, CodexHomeSlot, CodexIdentityHashes, CodexUsageProbe,
};

/// In use on this Mac: one provider read per 5 min.
pub(super) const IN_USE_REFRESH_SECONDS: u64 = 5 * 60;
/// Not in use: one provider read per 15 min.
pub(super) const UNUSED_REFRESH_SECONDS: u64 = 15 * 60;
/// A home is in use while its latest session or process sighting is this
/// recent.
pub(super) const IN_USE_WINDOW_SECONDS: u64 = 30 * 60;
/// An explicit refresh reads a home at most this often.
pub(super) const EXPLICIT_REFRESH_MIN_GAP_SECONDS: u64 = 60;
/// A changed local login is read again after at least this long.
const LOGIN_CHANGED_MIN_GAP_SECONDS: u64 = 60;
/// How often the scheduler looks for due homes. Reads start at most this late.
const SCHEDULER_TICK: Duration = Duration::from_secs(15);
/// The upload-grant check behind automatic reads is re-read this often.
const SOURCE_ENABLED_RECHECK: Duration = Duration::from_secs(5 * 60);
/// A served reading older than this (two unused intervals: the schedule
/// failed to run) is labelled stale.
const SERVED_FRESH_MAX_AGE_SECONDS: u64 = 2 * UNUSED_REFRESH_SECONDS;
/// Beyond this a saved reading is not served at all (the last-known cap).
const SERVED_MAX_AGE_SECONDS: u64 = codex_last_known::LAST_KNOWN_MAX_AGE_SECS;
/// A local clock this far behind a stored time means the clock stepped back.
const CLOCK_SKEW_SECONDS: u64 = 60;

const CODEX_QUOTA_STATE_DIR: &str = "codex-quota/homes";
const SAVED_QUOTA_FILE: &str = "saved-quota.json";
const SAVED_QUOTA_SCHEMA_VERSION: u16 = 1;
/// Size bounds: a file over this is ignored, meters and texts are truncated.
const SAVED_QUOTA_MAX_BYTES: u64 = 256 * 1024;
const SAVED_METERS_MAX: usize = 32;
const SAVED_TEXT_MAX_CHARS: usize = 1024;
/// Running-process sightings kept (the process scan reports at most 32).
const RUNNING_HOMES_MAX: usize = 32;

/// Served when a home has no usable saved reading yet: first start, or its
/// local login changed since the last read. Not a failed read.
pub(super) const CODEX_QUOTA_NOT_READ_YET: &str =
    "Codex quota for this account has not been read since its login was last seen; the daemon reads it shortly.";

/// Local metadata of a home's `auth.json`: the witness that the login a
/// reading belongs to has not been rewritten since.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AuthWitness {
    modified_secs: u64,
    modified_nanos: u32,
    len: u64,
}

fn auth_witness(home: &Path) -> Option<AuthWitness> {
    let metadata = std::fs::metadata(home.join("auth.json")).ok()?;
    let modified = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(AuthWitness {
        modified_secs: modified.as_secs(),
        modified_nanos: modified.subsec_nanos(),
        len: metadata.len(),
    })
}

/// One home's saved quota and read history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedCodexQuota {
    schema_version: u16,
    /// [`home_key`] of the home this file belongs to.
    home_key: String,
    /// The last successful provider reading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reading: Option<SavedCodexReading>,
    /// Last provider read attempt, successful or not (local unix seconds).
    #[serde(default)]
    last_attempt_at_epoch_seconds: u64,
    /// `auth.json` as it was right after that attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_attempt_auth: Option<AuthWitness>,
    /// The last attempt's failure, while it is newer than `reading`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_failure: Option<SavedCodexFailure>,
    #[serde(default)]
    consecutive_failures: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedCodexReading {
    observed_at_epoch_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<AuthWitness>,
    /// Provider-validated identity at read time; absent when the read could
    /// not bind the meters to an account (they are then never shown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<CodexIdentityHashes>,
    /// The provider named a signed-in ChatGPT account in this read.
    #[serde(default)]
    provider_account_signed_in: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plan_type: Option<String>,
    #[serde(default)]
    quota_windows: Vec<AgentQuotaWindow>,
    #[serde(default)]
    credit_balances: Vec<AgentCreditBalance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reset_credit_detail_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit_pool_summary: Option<String>,
    #[serde(default)]
    credential_read_failed: bool,
}

/// A failed read: its time and the collector's fixed failure text (never
/// provider text).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedCodexFailure {
    at_epoch_seconds: u64,
    message: String,
}

impl SavedCodexQuota {
    fn new(home: &Path) -> Self {
        Self {
            schema_version: SAVED_QUOTA_SCHEMA_VERSION,
            home_key: home_key(home),
            reading: None,
            last_attempt_at_epoch_seconds: 0,
            last_attempt_auth: None,
            last_failure: None,
            consecutive_failures: 0,
        }
    }

    /// The account and workspace binding key of the saved reading.
    fn binding(&self) -> Option<String> {
        let identity = self.reading.as_ref()?.identity.as_ref()?;
        Some(codex_credit_grants::binding_key(
            &identity.account_identifier_hash,
            &identity.workspace_identifier_hash,
        ))
    }

    fn bound(&mut self) {
        if let Some(reading) = self.reading.as_mut() {
            reading.quota_windows.truncate(SAVED_METERS_MAX);
            reading.credit_balances.truncate(SAVED_METERS_MAX);
            for text in [
                &mut reading.reset_credit_detail_summary,
                &mut reading.rate_limit_pool_summary,
                &mut reading.plan_type,
                &mut reading.response_completed_at,
            ] {
                if let Some(value) = text.as_mut() {
                    truncate_chars(value, SAVED_TEXT_MAX_CHARS);
                }
            }
        }
        if let Some(failure) = self.last_failure.as_mut() {
            truncate_chars(&mut failure.message, SAVED_TEXT_MAX_CHARS);
        }
    }
}

fn truncate_chars(value: &mut String, max: usize) {
    if let Some((index, _)) = value.char_indices().nth(max) {
        value.truncate(index);
    }
}

impl SavedCodexReading {
    fn from_probe(probe: &CodexUsageProbe, observed_at: u64, auth: Option<AuthWitness>) -> Self {
        Self {
            observed_at_epoch_seconds: observed_at,
            auth,
            identity: probe
                .identity
                .as_ref()
                .map(CodexIdentityHashes::from)
                .or_else(|| probe.saved_identity.clone()),
            provider_account_signed_in: probe.account.is_some(),
            plan_type: probe
                .account
                .as_ref()
                .and_then(|account| account.plan_type.clone()),
            quota_windows: probe.quota_windows.clone(),
            credit_balances: probe.credit_balances.clone(),
            response_completed_at: probe.response_completed_at.clone(),
            reset_credit_detail_summary: probe.reset_credit_detail_summary.clone(),
            rate_limit_pool_summary: probe.rate_limit_pool_summary.clone(),
            credential_read_failed: probe.credential_read_failed,
        }
    }

    fn to_probe(&self) -> CodexUsageProbe {
        // The provider's account, as the read saw it. The email is not kept:
        // the local id token supplies it, as for a provider read.
        let account = self.provider_account_signed_in.then(|| AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            provider: Some("openai".to_string()),
            auth_method: Some("oauth".to_string()),
            plan_type: self.plan_type.clone(),
            subscription_product: self.plan_type.clone().map(chatgpt_subscription_product),
            billing_channel: Some("subscription".to_string()),
            confidence: AgentStatusConfidence::High,
            ..unsupported_account("openai")
        });
        CodexUsageProbe {
            quota_windows: self.quota_windows.clone(),
            credit_balances: self.credit_balances.clone(),
            account,
            identity: None,
            saved_identity: self.identity.clone(),
            credential_read_failed: self.credential_read_failed,
            response_completed_at: self.response_completed_at.clone(),
            reset_credit_detail_summary: self.reset_credit_detail_summary.clone(),
            rate_limit_pool_summary: self.rate_limit_pool_summary.clone(),
        }
    }
}

/// Where saved copies live. Unit tests that did not choose a support dir get
/// a per-process scratch dir, never the real one.
fn saved_quota_support_dir() -> PathBuf {
    #[cfg(test)]
    if std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR").is_none() {
        return std::env::temp_dir().join(format!(
            "ottto-codex-saved-quota-tests-{}",
            std::process::id()
        ));
    }
    default_support_dir()
}

/// Opaque, domain-separated key of a home path; the path itself is never
/// written.
pub(super) fn home_key(home: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:codex-quota-home:v1\0");
    digest.update(home.as_os_str().as_encoded_bytes());
    format!("{:x}", digest.finalize())
}

fn saved_path(support_dir: &Path, home: &Path) -> PathBuf {
    support_dir
        .join(CODEX_QUOTA_STATE_DIR)
        .join(home_key(home))
        .join(SAVED_QUOTA_FILE)
}

/// Bumped on every saved write, so a cached status read can notice a newer
/// reading.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Changes whenever any saved Codex quota changes.
pub(crate) fn saved_codex_quota_generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

fn read_saved_at(support_dir: &Path, home: &Path) -> Option<SavedCodexQuota> {
    let path = saved_path(support_dir, home);
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > SAVED_QUOTA_MAX_BYTES {
        return None;
    }
    let body = std::fs::read(&path).ok()?;
    if body.len() as u64 > SAVED_QUOTA_MAX_BYTES {
        return None;
    }
    let saved: SavedCodexQuota = serde_json::from_slice(&body).ok()?;
    (saved.schema_version == SAVED_QUOTA_SCHEMA_VERSION && saved.home_key == home_key(home))
        .then_some(saved)
}

fn write_saved_at(support_dir: &Path, home: &Path, saved: &SavedCodexQuota) {
    let mut saved = saved.clone();
    saved.bound();
    let Ok(body) = serde_json::to_vec(&saved) else {
        return;
    };
    match ottto_core::write_owner_only_file_atomic(&saved_path(support_dir, home), &body) {
        Ok(()) => {
            GENERATION.fetch_add(1, Ordering::SeqCst);
        }
        Err(error) => eprintln!("saved Codex quota not written: {}", error.kind()),
    }
}

/// The last attempt per saved file, kept in memory too: a file that cannot be
/// written must not make every scheduler tick read the provider again.
#[derive(Debug, Clone, Copy)]
struct Attempt {
    at: u64,
    auth: Option<AuthWitness>,
}

const ATTEMPTS_MAX: usize = 64;

fn attempts() -> MutexGuard<'static, BTreeMap<PathBuf, Attempt>> {
    static ATTEMPTS: OnceLock<Mutex<BTreeMap<PathBuf, Attempt>>> = OnceLock::new();
    ATTEMPTS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn note_attempt(support_dir: &Path, home: &Path, attempt: Attempt) {
    let mut attempts = attempts();
    attempts.insert(saved_path(support_dir, home), attempt);
    while attempts.len() > ATTEMPTS_MAX {
        let Some(oldest) = attempts
            .iter()
            .min_by_key(|(_, attempt)| attempt.at)
            .map(|(path, _)| path.clone())
        else {
            break;
        };
        attempts.remove(&oldest);
    }
}

/// The saved state with the in-memory attempt applied when it is newer than
/// the one on disk.
fn saved_with_attempt(support_dir: &Path, home: &Path) -> Option<SavedCodexQuota> {
    let saved = read_saved_at(support_dir, home);
    let Some(attempt) = attempts().get(&saved_path(support_dir, home)).copied() else {
        return saved;
    };
    let mut saved = saved.unwrap_or_else(|| SavedCodexQuota::new(home));
    if attempt.at > saved.last_attempt_at_epoch_seconds {
        saved.last_attempt_at_epoch_seconds = attempt.at;
        saved.last_attempt_auth = attempt.auth;
    }
    Some(saved)
}

/// One lock per home: provider reads of one home never overlap, and a saved
/// file's read-modify-write is never interleaved.
fn home_lock(home: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(home_key(home))
        .or_default()
        .clone()
}

fn lock(mutex: &Mutex<()>) -> MutexGuard<'_, ()> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The home's saved reading, for a status read. Never reads the provider.
pub(super) fn serve_saved(
    home: &Path,
    home_trust: CodexHomeTrust,
    now: u64,
) -> Result<CodexUsageProbe, String> {
    serve_saved_at(&saved_quota_support_dir(), home, home_trust, now)
}

fn serve_saved_at(
    support_dir: &Path,
    home: &Path,
    home_trust: CodexHomeTrust,
    now: u64,
) -> Result<CodexUsageProbe, String> {
    let not_read = || Err(CODEX_QUOTA_NOT_READ_YET.to_string());
    let Some(saved) = read_saved_at(support_dir, home) else {
        return not_read();
    };
    // A failed read newer than the reading is served as that failure, exactly
    // as the read itself reported it; the collector's last-known display
    // handles it from there.
    if let Some(failure) = saved.last_failure.as_ref() {
        if saved.reading.as_ref().map_or(true, |reading| {
            failure.at_epoch_seconds >= reading.observed_at_epoch_seconds
        }) {
            return Err(failure.message.clone());
        }
    }
    let Some(reading) = saved.reading.as_ref() else {
        return not_read();
    };
    if !reading_matches_login(&saved, reading, home, home_trust) {
        return not_read();
    }
    let observed_at = reading.observed_at_epoch_seconds;
    if observed_at > now.saturating_add(CLOCK_SKEW_SECONDS)
        || now.saturating_sub(observed_at) > SERVED_MAX_AGE_SECONDS
    {
        return not_read();
    }
    let mut probe = reading.to_probe();
    if now.saturating_sub(observed_at) > SERVED_FRESH_MAX_AGE_SECONDS {
        mark_quota_meters_stale(&mut probe.quota_windows, &mut probe.credit_balances);
    }
    Ok(probe)
}

/// Whether the home's current local login is the one the reading belongs to.
fn reading_matches_login(
    saved: &SavedCodexQuota,
    reading: &SavedCodexReading,
    home: &Path,
    home_trust: CodexHomeTrust,
) -> bool {
    let Ok(Some(credentials)) = read_codex_auth_credentials_at(home, home_trust) else {
        return false;
    };
    match (
        saved.binding(),
        codex_credential_claimed_binding(&credentials),
    ) {
        (Some(saved), Some(claimed)) => saved == claimed,
        // The credential cannot name a binding (for example its access token
        // expired) or the reading had none: only an unchanged auth file keeps
        // the reading.
        _ => reading.auth.is_some() && reading.auth == auth_witness(home),
    }
}

/// Read `home` from the provider now and save the outcome, when `admit`
/// (given the saved state under the home's lock, and the time) allows it.
/// `None` means `admit` declined: another trigger read the home meanwhile.
pub(super) fn read_provider_and_save(
    home: &Path,
    home_trust: CodexHomeTrust,
    admit: impl FnOnce(Option<&SavedCodexQuota>, u64) -> bool,
) -> Option<Result<CodexUsageProbe, String>> {
    read_and_save_at(
        &saved_quota_support_dir(),
        home,
        current_unix_seconds(),
        admit,
        || read_codex_usage_from_provider(home, home_trust),
    )
}

/// `admit` decides at `now` (the trigger's clock), under the home's lock.
fn read_and_save_at(
    support_dir: &Path,
    home: &Path,
    now: u64,
    admit: impl FnOnce(Option<&SavedCodexQuota>, u64) -> bool,
    read: impl FnOnce() -> Result<CodexUsageProbe, String>,
) -> Option<Result<CodexUsageProbe, String>> {
    let lock_for_home = home_lock(home);
    let _guard = lock(&lock_for_home);
    let saved = saved_with_attempt(support_dir, home);
    if !admit(saved.as_ref(), now) {
        return None;
    }
    // The login the read starts under. A login that changes while the read
    // runs leaves the reading unsaved: it cannot be told which login it
    // belongs to, and the changed login is read again after a minute.
    let auth = auth_witness(home);
    let result = read();
    let finished_at = current_unix_seconds();
    let login_unchanged = auth_witness(home) == auth;
    note_attempt(
        support_dir,
        home,
        Attempt {
            at: finished_at,
            auth,
        },
    );
    let mut next = saved.unwrap_or_else(|| SavedCodexQuota::new(home));
    next.last_attempt_at_epoch_seconds = finished_at;
    next.last_attempt_auth = auth;
    match &result {
        Ok(_) if !login_unchanged => {}
        Ok(probe) => {
            let observed_at = probe
                .response_completed_at
                .as_deref()
                .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
                .and_then(|at| u64::try_from(at.unix_timestamp()).ok())
                .filter(|at| *at <= finished_at.saturating_add(CLOCK_SKEW_SECONDS))
                .unwrap_or(finished_at);
            next.reading = Some(SavedCodexReading::from_probe(probe, observed_at, auth));
            next.last_failure = None;
            next.consecutive_failures = 0;
        }
        Err(message) => {
            next.last_failure = Some(SavedCodexFailure {
                at_epoch_seconds: finished_at,
                message: message.clone(),
            });
            next.consecutive_failures = next.consecutive_failures.saturating_add(1);
        }
    }
    write_saved_at(support_dir, home, &next);
    Some(result)
}

/// The refresh interval of a home.
pub(super) fn refresh_interval_seconds(in_use: bool) -> u64 {
    if in_use {
        IN_USE_REFRESH_SECONDS
    } else {
        UNUSED_REFRESH_SECONDS
    }
}

/// Whether the schedule reads the home now. Measured from the last attempt,
/// so a failed read waits a full interval too.
pub(super) fn scheduled_read_due(
    saved: Option<&SavedCodexQuota>,
    current_auth: Option<AuthWitness>,
    in_use: bool,
    now: u64,
) -> bool {
    let Some(saved) = saved else {
        return true;
    };
    let last = saved.last_attempt_at_epoch_seconds;
    if last == 0 || last > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return true;
    }
    let elapsed = now.saturating_sub(last);
    if saved.last_attempt_auth != current_auth && elapsed >= LOGIN_CHANGED_MIN_GAP_SECONDS {
        return true;
    }
    elapsed >= refresh_interval_seconds(in_use)
}

/// Whether an explicit refresh may read the home now: at most once a minute,
/// counting any read.
pub(super) fn explicit_refresh_allowed(saved: Option<&SavedCodexQuota>, now: u64) -> bool {
    saved.map_or(true, |saved| {
        let last = saved.last_attempt_at_epoch_seconds;
        last > now.saturating_add(CLOCK_SKEW_SECONDS)
            || now.saturating_sub(last) >= EXPLICIT_REFRESH_MIN_GAP_SECONDS
    })
}

/// Running Codex processes seen holding a rollout in a home, by home.
fn running_homes() -> MutexGuard<'static, BTreeMap<PathBuf, u64>> {
    static RUNNING: OnceLock<Mutex<BTreeMap<PathBuf, u64>>> = OnceLock::new();
    RUNNING
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Record homes where a running Codex process holds a rollout (from the
/// collection's process scan).
pub(super) fn note_running_homes<'a>(homes: impl Iterator<Item = &'a Path>, now: u64) {
    let mut running = running_homes();
    for home in homes {
        running.insert(home.to_path_buf(), now);
    }
    while running.len() > RUNNING_HOMES_MAX {
        let Some(oldest) = running
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(home, _)| home.clone())
        else {
            break;
        };
        running.remove(&oldest);
    }
}

fn recent(at: u64, now: u64) -> bool {
    at <= now.saturating_add(CLOCK_SKEW_SECONDS) && now.saturating_sub(at) <= IN_USE_WINDOW_SECONDS
}

/// Latest activity of each recent session, with its account binding key.
fn recent_session_bindings(sessions: &[ActiveSession], now: u64) -> Vec<Option<String>> {
    sessions
        .iter()
        .filter(|session| {
            OffsetDateTime::parse(&session.source_last_activity_at, &Rfc3339)
                .ok()
                .and_then(|at| u64::try_from(at.unix_timestamp()).ok())
                .is_some_and(|at| recent(at, now))
        })
        .map(|session| {
            session
                .account_identifier_hash
                .as_deref()
                .zip(session.organization_identifier_hash.as_deref())
                .map(|(account, workspace)| codex_credit_grants::binding_key(account, workspace))
        })
        .collect()
}

/// One home as the schedule sees it.
#[derive(Debug, Clone)]
pub(super) struct ScheduledHome {
    pub(super) home: PathBuf,
    pub(super) trust: CodexHomeTrust,
    pub(super) ownership: CodexAccountSlotOwnershipV1,
    /// The account binding of its saved reading.
    pub(super) binding: Option<String>,
    /// Latest running-process sighting in this home.
    pub(super) process_seen_at: Option<u64>,
}

/// Which homes are in use. Codex sessions run in the default home unless a
/// session is clearly tied to a managed home: its account and workspace are
/// that home's and not the default home's. A running process holding a
/// rollout in a home ties it to that home outright.
pub(super) fn homes_in_use(
    homes: &[ScheduledHome],
    sessions: &[ActiveSession],
    now: u64,
) -> Vec<bool> {
    let default_binding = homes
        .iter()
        .find(|home| home.ownership == CodexAccountSlotOwnershipV1::Default)
        .and_then(|home| home.binding.clone());
    let managed_bindings = homes
        .iter()
        .filter(|home| home.ownership == CodexAccountSlotOwnershipV1::Managed)
        .filter_map(|home| home.binding.clone())
        .filter(|binding| Some(binding) != default_binding.as_ref())
        .collect::<BTreeSet<_>>();
    let sessions = recent_session_bindings(sessions, now);
    homes
        .iter()
        .map(|home| {
            if home.process_seen_at.is_some_and(|at| recent(at, now)) {
                return true;
            }
            match home.ownership {
                CodexAccountSlotOwnershipV1::Default => sessions.iter().any(|binding| {
                    binding
                        .as_ref()
                        .map_or(true, |binding| !managed_bindings.contains(binding))
                }),
                CodexAccountSlotOwnershipV1::Managed => home.binding.as_ref().is_some_and(|own| {
                    managed_bindings.contains(own)
                        && sessions.iter().any(|binding| binding.as_ref() == Some(own))
                }),
            }
        })
        .collect()
}

/// The homes the schedule keeps: the default home, every accepted managed
/// slot, and recently seen process homes. With automatic reads off (the
/// device does not collect Codex status) only the managed slots the user set
/// up stay scheduled.
fn scheduled_homes(support_dir: &Path, automatic: bool, now: u64) -> Vec<ScheduledHome> {
    let status = FileCodexAccountSlotSettingsStore::default()
        .load()
        .unwrap_or_else(|_| empty_codex_accounts_status());
    let running = running_homes().clone();
    let mut homes = codex_home_slots(&status)
        .into_iter()
        .filter(|slot| automatic || slot.ownership == CodexAccountSlotOwnershipV1::Managed)
        .map(|slot: CodexHomeSlot| scheduled_home(support_dir, &running, slot))
        .collect::<Vec<_>>();
    if automatic {
        for (home, seen_at) in running {
            if recent(seen_at, now) && !homes.iter().any(|known| known.home == home) {
                homes.push(scheduled_home(
                    support_dir,
                    &BTreeMap::from([(home.clone(), seen_at)]),
                    CodexHomeSlot {
                        slot_id: "process_home".to_string(),
                        ownership: CodexAccountSlotOwnershipV1::Managed,
                        home,
                        registered_binding: None,
                    },
                ));
            }
        }
    }
    homes
}

fn scheduled_home(
    support_dir: &Path,
    running: &BTreeMap<PathBuf, u64>,
    slot: CodexHomeSlot,
) -> ScheduledHome {
    let trust = match slot.ownership {
        CodexAccountSlotOwnershipV1::Default => CodexHomeTrust::ProviderDefault,
        CodexAccountSlotOwnershipV1::Managed => CodexHomeTrust::Managed,
    };
    ScheduledHome {
        binding: read_saved_at(support_dir, &slot.home)
            .as_ref()
            .and_then(SavedCodexQuota::binding),
        process_seen_at: running.get(&slot.home).copied(),
        home: slot.home,
        trust,
        ownership: slot.ownership,
    }
}

/// Read every home `due` selects, in parallel (one thread per home, as the
/// collection does). Returns how many provider reads ran.
fn read_homes(
    support_dir: &Path,
    homes: Vec<ScheduledHome>,
    now: u64,
    due: impl Fn(Option<&SavedCodexQuota>, &ScheduledHome, u64) -> bool + Sync,
) -> usize {
    let due = &due;
    thread::scope(|scope| {
        homes
            .into_iter()
            .map(|home| {
                scope.spawn(move || {
                    read_and_save_at(
                        support_dir,
                        &home.home,
                        now,
                        |saved, now| due(saved, &home, now),
                        || read_codex_usage_from_provider(&home.home, home.trust),
                    )
                    .is_some()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(|read| *read)
            .count()
    })
}

/// One scheduler pass: read every due home. Returns how many were read.
pub(super) fn scheduled_round(support_dir: &Path, automatic: bool, now: u64) -> usize {
    let homes = scheduled_homes(support_dir, automatic, now);
    if homes.is_empty() {
        return 0;
    }
    let sessions = crate::active_sessions::read_active_session_reconciliation(
        &default_support_dir(),
        crate::snapshots::SnapshotSource::Codex,
    )
    .map(|reconciliation| reconciliation.sessions)
    .unwrap_or_default();
    let in_use = homes_in_use(&homes, &sessions, now);
    let in_use_by_home = homes
        .iter()
        .zip(in_use)
        .map(|(home, in_use)| (home.home.clone(), in_use))
        .collect::<BTreeMap<_, _>>();
    read_homes(support_dir, homes, now, |saved, home, now| {
        scheduled_read_due(
            saved,
            auth_witness(&home.home),
            in_use_by_home.get(&home.home).copied().unwrap_or(false),
            now,
        )
    })
}

/// What an explicit refresh did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CodexExplicitRefresh {
    /// Homes read from the provider now.
    pub(crate) read: usize,
    /// Matching homes not read: one was read in the last minute.
    pub(crate) rate_limited: usize,
}

/// Explicit refresh: read the matching Codex homes now, each at most once a
/// minute. `account`/`workspace` narrow it to one account (hashes as in
/// status snapshots); `None` refreshes every home.
pub(crate) fn refresh_codex_quota_now(
    account_identifier_hash: Option<&str>,
    workspace_identifier_hash: Option<&str>,
) -> CodexExplicitRefresh {
    let support_dir = saved_quota_support_dir();
    let now = current_unix_seconds();
    let homes = scheduled_homes(&support_dir, true, now)
        .into_iter()
        .filter(|home| {
            (account_identifier_hash.is_none() && workspace_identifier_hash.is_none())
                || refresh_target_matches(
                    read_saved_at(&support_dir, &home.home)
                        .and_then(|saved| saved.reading)
                        .and_then(|reading| reading.identity)
                        .as_ref(),
                    account_identifier_hash,
                    workspace_identifier_hash,
                )
        })
        .collect::<Vec<_>>();
    let matching = homes.len();
    let read = read_homes(&support_dir, homes, now, |saved, _, now| {
        explicit_refresh_allowed(saved, now)
    });
    if read > 0 {
        crate::agent_status_refresh::request(&SourceKind::Codex);
    }
    CodexExplicitRefresh {
        read,
        rate_limited: matching - read,
    }
}

/// Whether a home's saved identity is one an explicit refresh names. Each
/// given hash must match; a home without a saved identity matches only a
/// refresh of every home (decided by the caller).
fn refresh_target_matches(
    identity: Option<&CodexIdentityHashes>,
    account_identifier_hash: Option<&str>,
    workspace_identifier_hash: Option<&str>,
) -> bool {
    identity.is_some_and(|identity| {
        account_identifier_hash.map_or(true, |account| identity.account_identifier_hash == account)
            && workspace_identifier_hash.map_or(true, |workspace| {
                identity.workspace_identifier_hash == workspace
            })
    })
}

struct Scheduler {
    stopped: Mutex<bool>,
    changed: Condvar,
}

fn scheduler_slot() -> MutexGuard<'static, Option<Arc<Scheduler>>> {
    static SCHEDULER: Mutex<Option<Arc<Scheduler>>> = Mutex::new(None);
    SCHEDULER.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Start the daemon's Codex quota scheduler (once).
pub fn start_codex_quota_scheduler() -> std::io::Result<()> {
    let mut slot = scheduler_slot();
    if slot.is_some() {
        return Ok(());
    }
    let scheduler = Arc::new(Scheduler {
        stopped: Mutex::new(false),
        changed: Condvar::new(),
    });
    let worker = scheduler.clone();
    thread::Builder::new()
        .name("ottto-codex-quota".to_string())
        .spawn(move || run_scheduler(&worker))?;
    *slot = Some(scheduler);
    Ok(())
}

pub(crate) fn stop_codex_quota_scheduler() {
    if let Some(scheduler) = scheduler_slot().take() {
        *scheduler
            .stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        scheduler.changed.notify_all();
    }
}

fn run_scheduler(scheduler: &Scheduler) {
    let support_dir = saved_quota_support_dir();
    let mut automatic = None::<(Instant, bool)>;
    loop {
        if *scheduler
            .stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            return;
        }
        // The same grant the collection lane polls by; re-read every 5 min.
        let enabled = match automatic {
            Some((checked, enabled)) if checked.elapsed() < SOURCE_ENABLED_RECHECK => enabled,
            _ => {
                let enabled = crate::snapshot_sync::agent_status_source_enabled(&SourceKind::Codex);
                automatic = Some((Instant::now(), enabled));
                enabled
            }
        };
        let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scheduled_round(&support_dir, enabled, current_unix_seconds())
        }))
        .unwrap_or(0);
        if read > 0 {
            // The lane rebuilds and uploads status from the new readings.
            crate::agent_status_refresh::request(&SourceKind::Codex);
        }
        let stopped = scheduler
            .stopped
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (stopped, _) = scheduler
            .changed
            .wait_timeout_while(stopped, SCHEDULER_TICK, |stopped| !*stopped)
            .unwrap_or_else(PoisonError::into_inner);
        if *stopped {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::AgentQuotaWindowFreshness;

    /// Canonical: the credential reader refuses symlinked path components
    /// (macOS `$TMPDIR` sits under the `/var` symlink).
    fn scratch(label: &str) -> PathBuf {
        crate::test_scratch::private_dir(&format!("ottto-codex-saved-quota-{label}"))
            .canonicalize()
            .expect("canonical scratch dir")
    }

    fn probe(account: &str, workspace: &str, observed_at: &str) -> CodexUsageProbe {
        CodexUsageProbe {
            quota_windows: vec![AgentQuotaWindow {
                name: "primary".to_string(),
                freshness: AgentQuotaWindowFreshness::Fresh,
                observed_at: Some(observed_at.to_string()),
                used_percent: Some(42),
                ..Default::default()
            }],
            credit_balances: vec![AgentCreditBalance {
                name: "credits".to_string(),
                freshness: AgentQuotaWindowFreshness::Fresh,
                observed_at: Some(observed_at.to_string()),
                remaining: Some(7),
                ..Default::default()
            }],
            account: Some(AgentAccountStatus {
                login_state: AgentLoginState::SignedIn,
                email: Some("never-saved".to_string()),
                plan_type: Some("pro".to_string()),
                ..unsupported_account("openai")
            }),
            identity: None,
            saved_identity: Some(CodexIdentityHashes {
                account_identifier_hash: account.to_string(),
                workspace_identifier_hash: workspace.to_string(),
                superseded_account_identifier_hash: Some("old-account".to_string()),
                superseded_organization_identifier_hash: None,
            }),
            credential_read_failed: false,
            response_completed_at: Some(observed_at.to_string()),
            reset_credit_detail_summary: Some("Codex reset details: count 2.".to_string()),
            rate_limit_pool_summary: None,
        }
    }

    fn rfc3339(at: u64) -> String {
        OffsetDateTime::from_unix_timestamp(at as i64)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    /// A home whose `auth.json` names no decodable binding, so only the auth
    /// file witness can keep a reading.
    fn opaque_home(root: &Path) -> PathBuf {
        let home = root.join("home");
        crate::test_scratch::create_private_dir(&home).unwrap();
        write_opaque_auth(&home, "first");
        home
    }

    fn write_opaque_auth(home: &Path, token: &str) {
        use std::os::unix::fs::PermissionsExt;
        let auth = home.join("auth.json");
        std::fs::write(
            &auth,
            serde_json::json!({"tokens": {"access_token": token}}).to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn saved_with(attempt_at: u64, auth: Option<AuthWitness>) -> SavedCodexQuota {
        SavedCodexQuota {
            last_attempt_at_epoch_seconds: attempt_at,
            last_attempt_auth: auth,
            ..SavedCodexQuota::new(Path::new("/unused"))
        }
    }

    #[test]
    fn schedule_intervals_are_five_minutes_in_use_and_fifteen_unused() {
        assert_eq!(refresh_interval_seconds(true), 5 * 60);
        assert_eq!(refresh_interval_seconds(false), 15 * 60);
        let auth = Some(AuthWitness {
            modified_secs: 1,
            modified_nanos: 0,
            len: 10,
        });
        let saved = saved_with(10_000, auth);
        // In use: due at 5 min, not before.
        assert!(!scheduled_read_due(
            Some(&saved),
            auth,
            true,
            10_000 + 5 * 60 - 1
        ));
        assert!(scheduled_read_due(
            Some(&saved),
            auth,
            true,
            10_000 + 5 * 60
        ));
        // Unused: due at 15 min, not before.
        assert!(!scheduled_read_due(
            Some(&saved),
            auth,
            false,
            10_000 + 15 * 60 - 1
        ));
        assert!(scheduled_read_due(
            Some(&saved),
            auth,
            false,
            10_000 + 15 * 60
        ));
        // Never read: due now.
        assert!(scheduled_read_due(None, auth, false, 10_000));
        // A clock that stepped back never holds a home forever.
        assert!(scheduled_read_due(Some(&saved), auth, false, 1_000));
    }

    #[test]
    fn a_changed_login_is_read_again_after_a_minute_only() {
        let before = Some(AuthWitness {
            modified_secs: 1,
            modified_nanos: 0,
            len: 10,
        });
        let after = Some(AuthWitness {
            modified_secs: 2,
            modified_nanos: 0,
            len: 12,
        });
        let saved = saved_with(10_000, before);
        assert!(!scheduled_read_due(Some(&saved), after, false, 10_000 + 59));
        assert!(scheduled_read_due(Some(&saved), after, false, 10_000 + 60));
        // A signed-out home (no auth file before or after) keeps the interval.
        let signed_out = saved_with(10_000, None);
        assert!(!scheduled_read_due(
            Some(&signed_out),
            None,
            false,
            10_000 + 600
        ));
    }

    #[test]
    fn a_failed_read_waits_a_full_interval() {
        let mut saved = saved_with(10_000, None);
        saved.last_failure = Some(SavedCodexFailure {
            at_epoch_seconds: 10_000,
            message: "Codex app-server quota read timed out.".to_string(),
        });
        saved.consecutive_failures = 3;
        // Never sooner than the interval: the failure adds no retry.
        assert!(!scheduled_read_due(
            Some(&saved),
            None,
            true,
            10_000 + 5 * 60 - 1
        ));
        assert!(!scheduled_read_due(
            Some(&saved),
            None,
            false,
            10_000 + 15 * 60 - 1
        ));
    }

    #[test]
    fn explicit_refresh_reads_at_most_once_a_minute() {
        assert!(explicit_refresh_allowed(None, 10_000));
        let saved = saved_with(10_000, None);
        assert!(!explicit_refresh_allowed(Some(&saved), 10_000));
        assert!(!explicit_refresh_allowed(Some(&saved), 10_059));
        assert!(explicit_refresh_allowed(Some(&saved), 10_060));
        // Through the saved file: two refreshes within a minute read once.
        let root = scratch("explicit");
        let home = opaque_home(&root);
        let mut reads = 0;
        for at in [0, 30] {
            let _ = read_and_save_at(
                &root,
                &home,
                current_unix_seconds() + at,
                explicit_refresh_allowed,
                || {
                    reads += 1;
                    Ok(probe("a", "w", &rfc3339(current_unix_seconds())))
                },
            );
        }
        assert_eq!(reads, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn saved_reading_round_trips_without_the_email() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("round-trip");
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let read = read_and_save_at(
            &root,
            &home,
            now,
            |_, _| true,
            || Ok(probe("account-a", "workspace-a", &rfc3339(now))),
        );
        assert!(matches!(read, Some(Ok(_))));
        let path = saved_path(&root, &home);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "owner-only: {mode:o}");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.contains("never-saved"), "no email on disk");
        assert!(
            !body.contains(home.to_str().unwrap()),
            "no home path on disk"
        );

        let served = serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 60).unwrap();
        let original = probe("account-a", "workspace-a", &rfc3339(now));
        assert_eq!(served.quota_windows, original.quota_windows);
        assert_eq!(served.credit_balances, original.credit_balances);
        assert_eq!(served.saved_identity, original.saved_identity);
        assert!(served.identity.is_none(), "a saved reading has no raw ids");
        assert_eq!(served.response_completed_at, original.response_completed_at);
        assert_eq!(
            served.reset_credit_detail_summary,
            original.reset_credit_detail_summary
        );
        let account = served.account.expect("provider account");
        assert_eq!(account.plan_type.as_deref(), Some("pro"));
        assert!(account.email.is_none());

        // Old readings are labelled stale, then not served at all.
        let stale = serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 31 * 60).unwrap();
        assert_eq!(
            stale.quota_windows[0].freshness,
            AgentQuotaWindowFreshness::Stale
        );
        assert_eq!(
            serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 7 * 3_600).err(),
            Some(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_reading_is_not_served_after_the_login_changes() {
        let root = scratch("login-change");
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let _ = read_and_save_at(
            &root,
            &home,
            now,
            |_, _| true,
            || Ok(probe("account-a", "workspace-a", &rfc3339(now))),
        );
        assert!(serve_saved_at(&root, &home, CodexHomeTrust::Managed, now).is_ok());
        write_opaque_auth(&home, "a-different-and-longer-login");
        assert_eq!(
            serve_saved_at(&root, &home, CodexHomeTrust::Managed, now).err(),
            Some(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_failed_read_is_served_as_that_failure_and_keeps_the_reading() {
        let root = scratch("failure");
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let _ = read_and_save_at(
            &root,
            &home,
            now,
            |_, _| true,
            || Ok(probe("account-a", "workspace-a", &rfc3339(now))),
        );
        let failure = "Codex app-server quota read timed out.".to_string();
        let _ = read_and_save_at(&root, &home, now, |_, _| true, || Err(failure.clone()));
        assert_eq!(
            serve_saved_at(&root, &home, CodexHomeTrust::Managed, now).err(),
            Some(failure)
        );
        let saved = read_saved_at(&root, &home).unwrap();
        assert!(saved.reading.is_some(), "the last good reading is kept");
        assert_eq!(saved.consecutive_failures, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_login_that_changes_during_the_read_leaves_the_reading_unsaved() {
        let root = scratch("login-race");
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let before = auth_witness(&home);
        let result = read_and_save_at(
            &root,
            &home,
            now,
            |_, _| true,
            || {
                write_opaque_auth(&home, "another-login-written-during-the-read");
                Ok(probe("account-a", "workspace-a", &rfc3339(now)))
            },
        );
        assert!(
            matches!(result, Some(Ok(_))),
            "the caller still gets its read"
        );
        let saved = read_saved_at(&root, &home).unwrap();
        assert!(saved.reading.is_none(), "no login can be named for it");
        assert_eq!(saved.last_attempt_auth, before);
        assert_eq!(
            serve_saved_at(&root, &home, CodexHomeTrust::Managed, now).err(),
            Some(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        // The changed login is read again after a minute.
        let current = auth_witness(&home);
        assert!(!scheduled_read_due(Some(&saved), current, false, now + 59));
        assert!(scheduled_read_due(Some(&saved), current, false, now + 61));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unwritable_saved_file_still_spaces_the_reads() {
        let root = scratch("unwritable");
        let home = opaque_home(&root);
        // The state directory is a file: every saved write fails.
        std::fs::write(root.join("codex-quota"), b"").unwrap();
        let now = current_unix_seconds();
        let reads = std::cell::Cell::new(0);
        let read = || {
            reads.set(reads.get() + 1);
            Ok(probe("account-a", "workspace-a", &rfc3339(now)))
        };
        let due = |saved: Option<&SavedCodexQuota>, now: u64| {
            scheduled_read_due(saved, auth_witness(&home), false, now)
        };
        assert!(read_and_save_at(&root, &home, now, due, read).is_some());
        assert!(read_saved_at(&root, &home).is_none(), "nothing was written");
        // Later ticks inside the interval do not read again.
        for tick in [15, 60, 14 * 60] {
            assert!(read_and_save_at(&root, &home, now + tick, due, read).is_none());
        }
        assert!(read_and_save_at(&root, &home, now + 15 * 60 + 1, due, read).is_some());
        assert_eq!(reads.get(), 2);
        let explicit =
            |saved: Option<&SavedCodexQuota>, now: u64| explicit_refresh_allowed(saved, now);
        assert!(read_and_save_at(&root, &home, current_unix_seconds(), explicit, read).is_none());
        assert_eq!(reads.get(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_refresh_targets_match_every_given_hash() {
        let identity = CodexIdentityHashes {
            account_identifier_hash: "account-a".to_string(),
            workspace_identifier_hash: "workspace-a".to_string(),
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
        };
        let matches =
            |account, workspace| refresh_target_matches(Some(&identity), account, workspace);
        assert!(matches(Some("account-a"), None));
        assert!(matches(Some("account-a"), Some("workspace-a")));
        assert!(matches(None, Some("workspace-a")));
        assert!(!matches(None, Some("workspace-b")));
        assert!(!matches(Some("account-b"), None));
        assert!(!matches(Some("account-a"), Some("workspace-b")));
        assert!(!refresh_target_matches(None, Some("account-a"), None));
    }

    #[test]
    fn oversized_or_foreign_saved_files_are_ignored() {
        let root = scratch("bounds");
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let _ = read_and_save_at(
            &root,
            &home,
            now,
            |_, _| true,
            || {
                let mut probe = probe("account-a", "workspace-a", &rfc3339(now));
                probe.quota_windows = vec![probe.quota_windows[0].clone(); 100];
                probe.reset_credit_detail_summary = Some("x".repeat(10_000));
                Ok(probe)
            },
        );
        let saved = read_saved_at(&root, &home).unwrap();
        let reading = saved.reading.unwrap();
        assert_eq!(reading.quota_windows.len(), SAVED_METERS_MAX);
        assert_eq!(
            reading.reset_credit_detail_summary.unwrap().chars().count(),
            SAVED_TEXT_MAX_CHARS
        );
        // Another home's file is never served for this one.
        let other = root.join("other");
        crate::test_scratch::create_private_dir(&other).unwrap();
        std::fs::create_dir_all(saved_path(&root, &other).parent().unwrap()).unwrap();
        std::fs::copy(saved_path(&root, &home), saved_path(&root, &other)).unwrap();
        assert!(read_saved_at(&root, &other).is_none());
        // A file over the size bound is ignored.
        std::fs::write(
            saved_path(&root, &home),
            vec![b' '; SAVED_QUOTA_MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert!(read_saved_at(&root, &home).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    fn session(binding: Option<(&str, &str)>, at: u64) -> ActiveSession {
        serde_json::from_value(serde_json::json!({
            "source_session_id": format!("s-{at}"),
            "source_last_activity_at": rfc3339(at),
            "account_identifier_hash": binding.map(|(a, _)| a),
            "organization_identifier_hash": binding.map(|(_, w)| w),
        }))
        .unwrap()
    }

    fn scheduled(
        ownership: CodexAccountSlotOwnershipV1,
        binding: Option<(&str, &str)>,
    ) -> ScheduledHome {
        ScheduledHome {
            home: PathBuf::from(format!("/homes/{binding:?}")),
            trust: CodexHomeTrust::Managed,
            ownership,
            binding: binding.map(|(a, w)| codex_credit_grants::binding_key(a, w)),
            process_seen_at: None,
        }
    }

    #[test]
    fn sessions_count_for_the_default_home_unless_clearly_tied_to_a_managed_one() {
        let now = 100_000;
        let homes = [
            scheduled(CodexAccountSlotOwnershipV1::Default, Some(("a", "w"))),
            scheduled(CodexAccountSlotOwnershipV1::Managed, Some(("b", "w"))),
            // Same account as the default home: not clearly tied.
            scheduled(CodexAccountSlotOwnershipV1::Managed, Some(("a", "w"))),
            scheduled(CodexAccountSlotOwnershipV1::Managed, Some(("c", "w"))),
        ];
        // Nothing recent: nothing in use.
        assert_eq!(
            homes_in_use(&homes, &[session(Some(("b", "w")), now - 31 * 60)], now),
            [false, false, false, false]
        );
        // A session of the managed-only account: that home only.
        assert_eq!(
            homes_in_use(&homes, &[session(Some(("b", "w")), now - 10 * 60)], now),
            [false, true, false, false]
        );
        // The default home's account, an unbound session, or an unknown
        // account: the default home.
        for binding in [Some(("a", "w")), None, Some(("z", "w"))] {
            assert_eq!(
                homes_in_use(&homes, &[session(binding, now - 60)], now),
                [true, false, false, false]
            );
        }
        // A running process holding a rollout ties a home outright.
        let mut with_process = homes.clone();
        with_process[3].process_seen_at = Some(now - 5 * 60);
        assert_eq!(
            homes_in_use(&with_process, &[], now),
            [false, false, false, true]
        );
        with_process[3].process_seen_at = Some(now - 31 * 60);
        assert_eq!(
            homes_in_use(&with_process, &[], now),
            [false, false, false, false]
        );
    }

    #[test]
    fn running_home_sightings_are_bounded() {
        let homes = (0..RUNNING_HOMES_MAX + 8)
            .map(|index| PathBuf::from(format!("/bounded-running-home-{index}")))
            .collect::<Vec<_>>();
        note_running_homes(homes.iter().map(PathBuf::as_path), 1);
        assert!(running_homes().len() <= RUNNING_HOMES_MAX);
        running_homes().retain(|home, _| !home.starts_with("/bounded-running-home-"));
    }
}
