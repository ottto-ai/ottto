//! Saved Codex quota per home, and the schedule that keeps it current.
//!
//! The daemon decides when a Codex home's quota is read from the provider
//! (one `codex app-server` run). A scheduler thread reads each home on its
//! schedule and saves the outcome on disk, one owner-only file per home.
//! Every status read (the companion's accounts poll, agent-status refreshes,
//! startup re-verify, the collection lane) serves that saved copy and never
//! starts `codex app-server` itself. Setup checks and an explicit refresh read
//! the provider directly and update the same copy; the checks of a setup that
//! waits for sign-in are spaced per home by `codex_setup_gate`.
//!
//! Schedule per home:
//! - in use on this Mac (a Codex process held a rollout in the home, or a
//!   session that belongs to it was written, in the last 30 min): every 5 min;
//! - otherwise every 15 min;
//! - a failed read waits the same interval before the next attempt;
//! - a changed local login (the credential names another account or
//!   workspace than at the last read) is read again after at least 1 min;
//! - an explicit refresh reads now, at most once a minute per home.
//!
//! Two homes can hold the same login (the default home and a managed slot
//! signed into the same account and workspace). They share one quota, so one
//! of them reads for both: the default home when it is one of them, else the
//! one with the lowest home key. Its interval is the in-use one when any of
//! them is in use; the others are read by themselves only once a day (their
//! own tokens stay refreshed and a dead login there is noticed), and their
//! status serves the reader's reading. Homes hold the same login only while
//! both their saved readings and their current credentials name the same
//! account and workspace, and their latest reads did not fail; anything else
//! is read on its own, as before.
//!
//! Every home is scheduled whether or not the device uploads Codex status:
//! the companion shows these readings locally.
//!
//! The scheduler sleeps until the earliest home is due, and at most a minute,
//! whether or not any app is in front: a login switched outside the daemon,
//! a new session or Codex process, or a changed setting is seen at its next
//! wake, so a switched login is read within a minute (and at least a minute
//! after the read before). A status read that finds a home not read yet, and
//! switching background refresh on, wake it at once; rounds stay at least
//! 15 s apart. To decide what is due it keeps what it derived from the
//! settings, each credential and each saved file while those files are
//! unchanged (same identity, size, times, owner and mode); the read and
//! save of a reading, and every status read, read the files themselves.
//!
//! "Background limit refresh" (the Codex accounts settings, on until the
//! owner chooses) gates the schedule for every home at once: while it is off
//! a round reads nothing, scans no processes and runs no `codex app-server`,
//! the same-login keep-alive included, and the setting is checked again under
//! the settings lock right before each read. An explicit refresh and setup
//! checks still read; saved readings are served and age as usual.
//!
//! A login is the account and workspace the home's credential names, not the
//! `auth.json` file: each provider read refreshes the token, so Codex rewrites
//! that file on every read. Only a credential that names no account falls back
//! to the file's metadata. A saved reading or failure is served only while the
//! home's login is the one it was read under, so it never moves to another
//! login. A reading carries identity hashes only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ottto_core::{
    default_support_dir, CodexHomeTrust, FileCodexAccountSlotSettingsStore,
    CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME,
};
use ottto_protocol::{
    ActiveSession, AgentAccountStatus, AgentCreditBalance, AgentLoginState, AgentQuotaWindow,
    AgentStatusConfidence, CodexAccountSlotOwnershipV1, SourceKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    chatgpt_subscription_product, codex_credential_claim_lapses_at,
    codex_credential_claimed_binding, codex_credit_grants, codex_home_slots_checked,
    codex_last_known, current_unix_seconds, default_codex_home, empty_codex_accounts_status,
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
/// A home that holds the same login as the home reading for it is still read
/// by itself this often: each read refreshes that home's own tokens, and a
/// login that died there (revoked, signed out elsewhere) shows as its own
/// failed read within a day instead of hiding behind the other home's
/// readings.
const SAME_LOGIN_KEEPALIVE_SECONDS: u64 = 24 * 60 * 60;
/// The longest the scheduler sleeps, however late the next home is due: the
/// bound on seeing a login switched outside the daemon, a new session or
/// process, or a changed setting.
const SCHEDULER_MAX_SLEEP: Duration = Duration::from_secs(60);
/// The scheduler's sleep after a round that left a home due (its read was
/// refused at the last moment, or the round failed), and the least time
/// between two rounds when something wakes it early.
const SCHEDULER_RETRY: Duration = Duration::from_secs(15);
/// A file changed this recently is not kept: a rewrite within the same tick
/// of a coarse file-system clock could leave its stamp unchanged.
const RACY_STAMP_SECONDS: u64 = 2;
/// Kept planning entries per cache (homes, saved files, settings files).
const PLANNED_ENTRIES_MAX: usize = 64;
/// A served reading older than this (two unused intervals: the schedule
/// failed to run) is labelled stale.
const SERVED_FRESH_MAX_AGE_SECONDS: u64 = 2 * UNUSED_REFRESH_SECONDS;
/// Beyond this a saved reading is not served at all (the last-known cap).
const SERVED_MAX_AGE_SECONDS: u64 = codex_last_known::LAST_KNOWN_MAX_AGE_SECS;
/// A local clock this far behind a stored time means the clock stepped back.
const CLOCK_SKEW_SECONDS: u64 = 60;

const CODEX_QUOTA_DIR: &str = "codex-quota";
const CODEX_QUOTA_STATE_DIR: &str = "codex-quota/homes";
const SAVED_QUOTA_FILE: &str = "saved-quota.json";
const SAVED_QUOTA_SCHEMA_VERSION: u16 = 1;
/// Size bounds: a file over this is ignored, meters and texts are truncated.
const SAVED_QUOTA_MAX_BYTES: u64 = 256 * 1024;
const SAVED_METERS_MAX: usize = 32;
const SAVED_TEXT_MAX_CHARS: usize = 1024;
/// Running-process sightings kept (the process scan reports at most 32).
const RUNNING_HOMES_MAX: usize = 32;
/// The schedule scans for running Codex processes itself when no collection
/// did for this long, so a home in use is seen without the Codex lane.
const PROCESS_SCAN_MIN_GAP_SECONDS: u64 = 5 * 60;

/// Served when a home has no usable saved reading yet: first start, or its
/// local login changed since the last read. Not a failed read. Every home a
/// status read shows is on the schedule, which reads it within a minute.
pub(super) const CODEX_QUOTA_NOT_READ_YET: &str =
    "Codex quota for this account has not been read since its login was last seen; the daemon reads it shortly.";

/// Served instead of [`CODEX_QUOTA_NOT_READ_YET`] while background limit
/// refresh is off: nothing reads the home until the owner asks.
pub(super) const CODEX_QUOTA_BACKGROUND_REFRESH_OFF: &str =
    "Codex quota for this account has not been read since its login was last seen, and background limit refresh is off; use Refresh limits to read it now.";

/// The failure saved for a read that panicked.
const CODEX_QUOTA_READ_PANICKED: &str = "Codex quota read failed unexpectedly.";

/// A status read that has no reading to serve: the message, and when it was
/// true (a saved failure keeps the time of the read that failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CodexQuotaFailure {
    pub(super) message: String,
    pub(super) at_epoch_seconds: u64,
}

impl CodexQuotaFailure {
    fn not_read_yet(now: u64) -> Self {
        Self {
            message: CODEX_QUOTA_NOT_READ_YET.to_string(),
            at_epoch_seconds: now,
        }
    }
}

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

/// A home's local login: the account and workspace binding its credential
/// claims, and `auth.json`'s metadata for a credential that claims none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LoginMark {
    /// [`codex_credit_grants::binding_key`] of the claimed identity hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<AuthWitness>,
}

impl LoginMark {
    /// The same login: the same claimed account and workspace. The file
    /// metadata decides only when neither side claims one (a token rewrite
    /// for the same account is not a new login).
    pub(super) fn same_login(&self, other: &Self) -> bool {
        match (&self.binding, &other.binding) {
            (Some(own), Some(other)) => own == other,
            (None, None) => self.auth == other.auth,
            _ => false,
        }
    }

    /// A login the schedule reads again soon: a positively different claimed
    /// account or workspace, or a credential file that appeared or went away.
    /// File metadata alone never is: every read rewrites `auth.json`, and a
    /// credential that names no account cannot be told apart from itself.
    fn is_new_login(&self, current: &Self) -> bool {
        match (&self.binding, &current.binding) {
            (Some(own), Some(current)) => own != current,
            _ => self.auth.is_some() != current.auth.is_some(),
        }
    }

    /// Whether the home has an `auth.json` at all.
    pub(super) fn has_credential_file(&self) -> bool {
        self.auth.is_some()
    }

    /// The same `auth.json` metadata: the file was not rewritten in between.
    pub(super) fn same_credential_file(&self, other: &Self) -> bool {
        self.auth == other.auth
    }

    #[cfg(test)]
    pub(super) fn for_test(binding: Option<&str>, auth_modified_secs: Option<u64>) -> Self {
        Self {
            binding: binding.map(str::to_string),
            auth: auth_modified_secs.map(|modified_secs| AuthWitness {
                modified_secs,
                modified_nanos: 0,
                len: 1,
            }),
        }
    }
}

pub(super) fn login_mark(home: &Path, home_trust: CodexHomeTrust) -> LoginMark {
    login_mark_lasting(home, home_trust).0
}

/// [`login_mark`], and how long it holds while `auth.json` is unchanged: a
/// claimed binding lapses when the earliest of its tokens expires, a missing
/// one stays missing. `None`: it may change without the file changing (the
/// credential could not be read, or its tokens' expiry is unknown).
fn login_mark_lasting(home: &Path, home_trust: CodexHomeTrust) -> (LoginMark, Option<Lasts>) {
    let credentials = read_codex_auth_credentials_at(home, home_trust);
    let claimed = credentials.as_ref().ok().and_then(Option::as_ref);
    let binding = claimed.and_then(codex_credential_claimed_binding);
    let lasts = match (&credentials, &binding) {
        (Err(_), _) => None,
        (Ok(_), None) => Some(Lasts::WhileUnchanged),
        (Ok(_), Some(_)) => claimed
            .and_then(codex_credential_claim_lapses_at)
            .map(Lasts::Until),
    };
    let mark = LoginMark {
        binding,
        auth: auth_witness(home),
    };
    (mark, lasts)
}

/// How long a value derived from local files holds while they are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lasts {
    WhileUnchanged,
    /// Until this local unix second (exclusive).
    Until(u64),
}

/// What a path's contents and permissions are compared by between rounds:
/// its identity, owner and mode, and for a file its size and modification
/// and status-change times. Codex and the daemon replace files by rename (a
/// new inode); any write moves the modification time and any permission or
/// owner change shows in the mode or owner. A directory's times change with
/// its entries, so only its identity, owner and mode count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathStamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
    modified_ns: i128,
    changed_ns: i128,
}

/// `None` for a path that does not exist (or cannot be looked at). Never
/// follows a final symlink.
fn path_stamp(path: &Path) -> Option<PathStamp> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    let file = !metadata.is_dir();
    let at = |secs: i64, nanos: i64| i128::from(secs) * 1_000_000_000 + i128::from(nanos);
    Some(PathStamp {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        len: if file { metadata.len() } else { 0 },
        modified_ns: if file {
            at(metadata.mtime(), metadata.mtime_nsec())
        } else {
            0
        },
        changed_ns: if file {
            at(metadata.ctime(), metadata.ctime_nsec())
        } else {
            0
        },
    })
}

impl PathStamp {
    /// Last written long enough ago that a rewrite now gets another
    /// modification time, however coarse the file-system clock (Git's
    /// "racily clean" rule).
    fn settled(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |now| now.as_nanos() as i128);
        self.modified_ns < now - i128::from(RACY_STAMP_SECONDS) * 1_000_000_000
    }
}

/// A value derived from local files, with the stamps those files had before
/// it was derived.
#[derive(Debug, Clone)]
struct Planned<V> {
    stamps: Vec<(PathBuf, Option<PathStamp>)>,
    lasts: Lasts,
    value: V,
}

impl<V> Planned<V> {
    /// Stamp `paths` (before deriving the value from them).
    fn stamps(paths: impl IntoIterator<Item = PathBuf>) -> Vec<(PathBuf, Option<PathStamp>)> {
        paths
            .into_iter()
            .map(|path| {
                let stamp = path_stamp(&path);
                (path, stamp)
            })
            .collect()
    }

    /// The entry to keep, if any: every stamped file settled and the value
    /// known to hold.
    fn keep(
        stamps: Vec<(PathBuf, Option<PathStamp>)>,
        lasts: Option<Lasts>,
        value: V,
    ) -> Option<Self> {
        let lasts = lasts?;
        stamps
            .iter()
            .all(|(_, stamp)| stamp.map_or(true, |stamp| stamp.settled()))
            .then_some(Self {
                stamps,
                lasts,
                value,
            })
    }

    /// Still holds at `now`: every path has the stamp it had.
    fn holds(&self, now: u64) -> bool {
        (match self.lasts {
            Lasts::WhileUnchanged => true,
            Lasts::Until(until) => now < until,
        }) && self
            .stamps
            .iter()
            .all(|(path, stamp)| path_stamp(path) == *stamp)
    }
}

type PlannedCache<K, V> = Mutex<BTreeMap<K, Planned<V>>>;

fn planned_cache<K, V>(
    cache: &'static OnceLock<PlannedCache<K, V>>,
) -> MutexGuard<'static, BTreeMap<K, Planned<V>>>
where
    K: Ord,
{
    cache
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The kept value for `key` while it holds at `now`, else `derive`'s, kept
/// for next time when it may be. `derive` gets the paths' stamps taken before
/// it runs, and returns the value, how long it lasts, and the paths stamped.
fn planned<K, V>(
    cache: &'static OnceLock<PlannedCache<K, V>>,
    key: &K,
    now: u64,
    derive: impl FnOnce() -> (V, Option<Lasts>, Vec<(PathBuf, Option<PathStamp>)>),
) -> V
where
    K: Ord + Clone,
    V: Clone,
{
    if let Some(kept) = planned_cache(cache).get(key) {
        if kept.holds(now) {
            return kept.value.clone();
        }
    }
    #[cfg(test)]
    tests::note_planned_derive();
    let (value, lasts, stamps) = derive();
    let kept = Planned::keep(stamps, lasts, value.clone());
    let mut entries = planned_cache(cache);
    match kept {
        Some(kept) => {
            if !entries.contains_key(key) && entries.len() >= PLANNED_ENTRIES_MAX {
                entries.clear();
            }
            entries.insert(key.clone(), kept);
        }
        None => {
            entries.remove(key);
        }
    }
    value
}

/// [`login_mark`] for deciding what the schedule reads: kept while every
/// directory from `/` to the home (the chain the credential reader checks)
/// and its `auth.json` keep their stamps and no claimed token has expired.
/// Binding a reading to its login and serving one read the file.
fn planned_login_mark(home: &Path, home_trust: CodexHomeTrust, now: u64) -> LoginMark {
    static MARKS: OnceLock<PlannedCache<(PathBuf, bool), LoginMark>> = OnceLock::new();
    let key = (
        home.to_path_buf(),
        home_trust == CodexHomeTrust::ProviderDefault,
    );
    planned(&MARKS, &key, now, || {
        let stamps = Planned::<LoginMark>::stamps(
            home.ancestors()
                .map(Path::to_path_buf)
                .chain([home.join("auth.json")]),
        );
        let (mark, lasts) = login_mark_lasting(home, home_trust);
        (mark, lasts, stamps)
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
    /// The login that attempt read: as it was right after the read, or as it
    /// was before when the account changed during the read (so the new
    /// account is read again soon).
    #[serde(default)]
    last_attempt_login: LoginMark,
    /// The last attempt's failure, while it is newer than `reading`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_failure: Option<SavedCodexFailure>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedCodexReading {
    observed_at_epoch_seconds: u64,
    /// The login right after the read.
    #[serde(default)]
    login: LoginMark,
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

/// A failed read: its time, the login it read and the collector's fixed
/// failure text (never provider text).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedCodexFailure {
    at_epoch_seconds: u64,
    message: String,
    #[serde(default)]
    login: LoginMark,
}

impl SavedCodexQuota {
    fn new(home: &Path) -> Self {
        Self {
            schema_version: SAVED_QUOTA_SCHEMA_VERSION,
            home_key: home_key(home),
            reading: None,
            last_attempt_at_epoch_seconds: 0,
            last_attempt_login: LoginMark::default(),
            last_failure: None,
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
    fn from_probe(probe: &CodexUsageProbe, observed_at: u64, login: LoginMark) -> Self {
        Self {
            observed_at_epoch_seconds: observed_at,
            login,
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

/// Saved files kept for deciding what the schedule reads.
static PLANNED_SAVED: OnceLock<PlannedCache<PathBuf, Option<SavedCodexQuota>>> = OnceLock::new();

/// [`read_saved_at`] for deciding what the schedule reads: kept while the file
/// keeps its stamp, and dropped by every write here. A read and save under
/// the home's lock, and every status read, read the file.
fn planned_saved(support_dir: &Path, home: &Path, now: u64) -> Option<SavedCodexQuota> {
    let path = saved_path(support_dir, home);
    planned(&PLANNED_SAVED, &path, now, || {
        let stamps = Planned::<Option<SavedCodexQuota>>::stamps([path.clone()]);
        let saved = read_saved_at(support_dir, home);
        (saved, Some(Lasts::WhileUnchanged), stamps)
    })
}

/// The state directories above the per-home ones, owner-only like the leaf.
fn restrict_state_dirs(support_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for dir in [CODEX_QUOTA_DIR, CODEX_QUOTA_STATE_DIR] {
        let dir = support_dir.join(dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_saved_at(support_dir: &Path, home: &Path, saved: &SavedCodexQuota) {
    let mut saved = saved.clone();
    saved.bound();
    let Ok(body) = serde_json::to_vec(&saved) else {
        return;
    };
    let written = restrict_state_dirs(support_dir).and_then(|()| {
        ottto_core::write_owner_only_cache_file_atomic(&saved_path(support_dir, home), &body)
    });
    planned_cache(&PLANNED_SAVED).remove(&saved_path(support_dir, home));
    match written {
        Ok(()) => {
            GENERATION.fetch_add(1, Ordering::SeqCst);
        }
        Err(error) => eprintln!("saved Codex quota not written: {}", error.kind()),
    }
}

/// The last attempt per saved file, kept in memory too: a file that cannot be
/// written must not make every scheduler tick read the provider again.
#[derive(Debug, Clone)]
struct Attempt {
    at: u64,
    login: LoginMark,
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
    with_attempt(support_dir, home, read_saved_at(support_dir, home))
}

/// [`saved_with_attempt`] from [`planned_saved`].
fn planned_saved_with_attempt(
    support_dir: &Path,
    home: &Path,
    now: u64,
) -> Option<SavedCodexQuota> {
    with_attempt(support_dir, home, planned_saved(support_dir, home, now))
}

fn with_attempt(
    support_dir: &Path,
    home: &Path,
    saved: Option<SavedCodexQuota>,
) -> Option<SavedCodexQuota> {
    let Some(attempt) = attempts().get(&saved_path(support_dir, home)).cloned() else {
        return saved;
    };
    let mut saved = saved.unwrap_or_else(|| SavedCodexQuota::new(home));
    if attempt.at > saved.last_attempt_at_epoch_seconds {
        saved.last_attempt_at_epoch_seconds = attempt.at;
        saved.last_attempt_login = attempt.login;
    }
    Some(saved)
}

/// Home locks kept while no read holds them; beyond this, idle ones go.
const HOME_LOCKS_IDLE_MAX: usize = 64;

/// One lock per home: provider reads of one home never overlap, and a saved
/// file's read-modify-write is never interleaved.
fn home_lock(home: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if locks.len() > HOME_LOCKS_IDLE_MAX {
        // Removed and process-only homes: nobody else holds their lock.
        locks.retain(|_, lock| Arc::strong_count(lock) > 1);
    }
    locks.entry(home_key(home)).or_default().clone()
}

/// Run `f` while no provider read of `home` runs: under the home's lock.
pub(crate) fn with_codex_home_read_lock<T>(home: &Path, f: impl FnOnce() -> T) -> T {
    let lock_for_home = home_lock(home);
    let _guard = lock(&lock_for_home);
    f()
}

fn lock(mutex: &Mutex<()>) -> MutexGuard<'_, ()> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The home's saved reading, for a status read. Never reads the provider.
/// Launch preflight may inspect the current saved proof, but must never wake
/// a provider read or perform login/model probes as a side effect.
pub(super) fn serve_saved_for_launch(
    home: &Path,
    home_trust: CodexHomeTrust,
    now: u64,
) -> Result<CodexUsageProbe, CodexQuotaFailure> {
    serve_saved_at(&saved_quota_support_dir(), home, home_trust, now)
}

pub(super) fn serve_saved(
    home: &Path,
    home_trust: CodexHomeTrust,
    now: u64,
) -> Result<CodexUsageProbe, CodexQuotaFailure> {
    serve_saved_at(&saved_quota_support_dir(), home, home_trust, now).map_err(|failure| {
        if failure.message != CODEX_QUOTA_NOT_READ_YET {
            failure
        } else if !quota_refresh_settings().background_quota_refresh_allowed() {
            CodexQuotaFailure {
                message: CODEX_QUOTA_BACKGROUND_REFRESH_OFF.to_string(),
                ..failure
            }
        } else {
            // A new login or home is read as soon as its schedule allows,
            // without waiting for the scheduler's next wake.
            wake_codex_quota_scheduler();
            failure
        }
    })
}

/// The Codex accounts settings that hold "Background limit refresh", in the
/// support dir the saved copies use (the daemon's own; a unit test's scratch
/// dir unless it chose one).
fn quota_refresh_settings() -> FileCodexAccountSlotSettingsStore {
    FileCodexAccountSlotSettingsStore::new(
        saved_quota_support_dir().join(CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME),
    )
}

/// Whether a saved time may be served at `now`: not in the future, not past
/// the last-known cap.
fn servable_at(at: u64, now: u64) -> bool {
    at <= now.saturating_add(CLOCK_SKEW_SECONDS) && now.saturating_sub(at) <= SERVED_MAX_AGE_SECONDS
}

/// A reading a status read may serve, and when it was read.
struct ServedReading {
    observed_at: u64,
    probe: CodexUsageProbe,
}

/// The home's own saved copy, or the reading of the home that reads for it
/// (the same login, confirmed on both current credentials) when that one is
/// newer or the home has none of its own to serve. The home's own failed
/// read is always served as such.
fn serve_saved_at(
    support_dir: &Path,
    home: &Path,
    home_trust: CodexHomeTrust,
    now: u64,
) -> Result<CodexUsageProbe, CodexQuotaFailure> {
    let current = login_mark(home, home_trust);
    let saved = read_saved_at(support_dir, home);
    let own = serve_saved_copy(saved.as_ref(), &current, now);
    let shared = || serve_same_login_reading(support_dir, home, saved.as_ref(), &current, now);
    match own {
        Ok(own) => Ok(match shared() {
            Some(shared) if shared.observed_at > own.observed_at => shared.probe,
            _ => own.probe,
        }),
        Err(failure) if failure.message == CODEX_QUOTA_NOT_READ_YET => {
            shared().map(|shared| shared.probe).ok_or(failure)
        }
        Err(failure) => Err(failure),
    }
}

/// The reading of the home that reads for `home`, while both homes hold the
/// same account and workspace ([`held_binding`]), that reading names them,
/// and its latest read did not fail. Never reads the provider.
fn serve_same_login_reading(
    support_dir: &Path,
    home: &Path,
    saved: Option<&SavedCodexQuota>,
    current: &LoginMark,
    now: u64,
) -> Option<ServedReading> {
    let binding = held_binding(saved, current)?;
    let (reader, reader_trust) = same_login_reader(support_dir, home)?;
    let reader_current = login_mark(&reader, reader_trust);
    let reader_saved = read_saved_at(support_dir, &reader)?;
    if held_binding(Some(&reader_saved), &reader_current).as_ref() != Some(&binding)
        || reader_saved.binding().as_ref() != Some(&binding)
        || !latest_read_succeeded(&reader_saved)
    {
        return None;
    }
    serve_saved_copy(Some(&reader_saved), &reader_current, now).ok()
}

/// The account and workspace a home holds now, from local files only: the
/// ones its credential names, or, when it names none (its id token lives an
/// hour, and only a read refreshes it), its saved reading's while its latest
/// read did not fail and `auth.json` is unchanged since that read. An
/// unchanged file still holds the login the provider validated, so this never
/// takes one login for another.
fn held_binding(saved: Option<&SavedCodexQuota>, current: &LoginMark) -> Option<String> {
    if let Some(binding) = current.binding.as_ref() {
        return Some(binding.clone());
    }
    let saved = saved.filter(|saved| latest_read_succeeded(saved))?;
    let reading = saved.reading.as_ref()?;
    (reading.login.auth.is_some() && reading.login.auth == current.auth)
        .then(|| saved.binding())
        .flatten()
}

fn serve_saved_copy(
    saved: Option<&SavedCodexQuota>,
    current: &LoginMark,
    now: u64,
) -> Result<ServedReading, CodexQuotaFailure> {
    let not_read = || Err(CodexQuotaFailure::not_read_yet(now));
    let Some(saved) = saved else {
        return not_read();
    };
    // A failed read newer than the reading is served as that failure, with
    // its own time, exactly as the read itself reported it, while the home
    // still has the login it read; the collector's last-known display handles
    // it from there.
    if let Some(failure) = saved.last_failure.as_ref() {
        if saved.reading.as_ref().map_or(true, |reading| {
            failure.at_epoch_seconds >= reading.observed_at_epoch_seconds
        }) && failure.login.same_login(current)
            && servable_at(failure.at_epoch_seconds, now)
        {
            return Err(CodexQuotaFailure {
                message: failure.message.clone(),
                at_epoch_seconds: failure.at_epoch_seconds,
            });
        }
    }
    let Some(reading) = saved.reading.as_ref() else {
        return not_read();
    };
    if !reading_matches_login(saved, reading, current) {
        return not_read();
    }
    let observed_at = reading.observed_at_epoch_seconds;
    if !servable_at(observed_at, now) {
        return not_read();
    }
    let mut probe = reading.to_probe();
    if now.saturating_sub(observed_at) > SERVED_FRESH_MAX_AGE_SECONDS {
        mark_quota_meters_stale(&mut probe.quota_windows, &mut probe.credit_balances);
    }
    Ok(ServedReading { observed_at, probe })
}

/// The home has a reading and no failed read newer than it.
fn latest_read_succeeded(saved: &SavedCodexQuota) -> bool {
    saved.reading.as_ref().is_some_and(|reading| {
        saved.last_failure.as_ref().map_or(true, |failure| {
            failure.at_epoch_seconds < reading.observed_at_epoch_seconds
        })
    })
}

/// Whether the home's current local login is the one the reading belongs to.
fn reading_matches_login(
    saved: &SavedCodexQuota,
    reading: &SavedCodexReading,
    current: &LoginMark,
) -> bool {
    match (saved.binding(), current.binding.as_ref()) {
        (Some(saved), Some(claimed)) => &saved == claimed,
        // The credential cannot name a binding (for example its access token
        // expired) or the reading had none: only an unchanged auth file keeps
        // the reading.
        _ => reading.login.auth.is_some() && reading.login.auth == current.auth,
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
        home_trust,
        current_unix_seconds(),
        admit,
        || read_codex_usage_from_provider(home, home_trust),
    )
}

/// The account and workspace binding a read validated with the provider.
fn probe_binding(probe: &CodexUsageProbe) -> Option<String> {
    let identity = probe
        .identity
        .as_ref()
        .map(CodexIdentityHashes::from)
        .or_else(|| probe.saved_identity.clone())?;
    Some(codex_credit_grants::binding_key(
        &identity.account_identifier_hash,
        &identity.workspace_identifier_hash,
    ))
}

/// Whether a read ran under one login from start to end. The read itself
/// rewrites `auth.json` (it refreshes the token), so only a positively
/// different account or workspace is a change. A credential that named none
/// before the read (an expired token) and names one after it is the same
/// login when the read validated exactly that account. A credential that
/// names none after the read is the same login unless the read validated
/// another account than the one named before it.
fn read_kept_its_login(
    before: &LoginMark,
    after: &LoginMark,
    result: &Result<CodexUsageProbe, String>,
) -> bool {
    let validated = result.as_ref().ok().and_then(probe_binding);
    match (&before.binding, &after.binding) {
        (Some(before), Some(after)) => before == after,
        (None, Some(_)) => validated == after.binding,
        (Some(before), None) => validated.map_or(true, |validated| &validated == before),
        (None, None) => true,
    }
}

/// `admit` decides at `now` (the trigger's clock), under the home's lock.
fn read_and_save_at(
    support_dir: &Path,
    home: &Path,
    home_trust: CodexHomeTrust,
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
    let before = login_mark(home, home_trust);
    // A read that panics is a failed attempt too, so the schedule does not
    // retry it on every tick.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(read))
        .unwrap_or_else(|_| Err(CODEX_QUOTA_READ_PANICKED.to_string()));
    let finished_at = read_finished_at(support_dir, now);
    let after = login_mark(home, home_trust);
    // A login that changed while the read ran leaves the reading unsaved: it
    // cannot be told which login it belongs to. The attempt then records the
    // login it started under, so a new account is read again after a minute.
    // Otherwise it records the login after the read, whose own `auth.json`
    // rewrite is not a change.
    let kept = read_kept_its_login(&before, &after, &result);
    let login = if kept { after } else { before };
    note_attempt(
        support_dir,
        home,
        Attempt {
            at: finished_at,
            login: login.clone(),
        },
    );
    let mut next = saved.unwrap_or_else(|| SavedCodexQuota::new(home));
    next.last_attempt_at_epoch_seconds = finished_at;
    next.last_attempt_login = login.clone();
    match &result {
        Ok(_) if !kept => {}
        Ok(probe) => {
            let observed_at = probe
                .response_completed_at
                .as_deref()
                .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
                .and_then(|at| u64::try_from(at.unix_timestamp()).ok())
                .filter(|at| *at <= finished_at.saturating_add(CLOCK_SKEW_SECONDS))
                .unwrap_or(finished_at);
            next.reading = Some(SavedCodexReading::from_probe(probe, observed_at, login));
            next.last_failure = None;
        }
        Err(message) => {
            next.last_failure = Some(SavedCodexFailure {
                at_epoch_seconds: finished_at,
                message: message.clone(),
                login,
            });
        }
    }
    write_saved_at(support_dir, home, &next);
    Some(result)
}

/// When a read finished: the wall clock, never before the trigger's clock.
#[cfg(not(test))]
fn read_finished_at(_support_dir: &Path, now: u64) -> u64 {
    current_unix_seconds().max(now)
}

/// As in the daemon, except under a support dir whose test pinned reads to
/// finish at the trigger's clock, so a slow run cannot shift its schedule.
#[cfg(test)]
fn read_finished_at(support_dir: &Path, now: u64) -> u64 {
    if tests::reads_finish_at_trigger_clock(support_dir) {
        now
    } else {
        current_unix_seconds().max(now)
    }
}

/// The refresh interval of a home.
pub(super) fn refresh_interval_seconds(in_use: bool) -> u64 {
    if in_use {
        IN_USE_REFRESH_SECONDS
    } else {
        UNUSED_REFRESH_SECONDS
    }
}

/// [`scheduled_read_due_every`] at a home's own 5 or 15 minutes.
#[cfg(test)]
pub(super) fn scheduled_read_due(
    saved: Option<&SavedCodexQuota>,
    current_login: &LoginMark,
    in_use: bool,
    now: u64,
) -> bool {
    scheduled_read_due_every(saved, current_login, refresh_interval_seconds(in_use), now)
}

/// Whether the schedule reads a home read every `interval_seconds` now.
/// Measured from the last attempt, so a failed read waits a full interval
/// too.
fn scheduled_read_due_every(
    saved: Option<&SavedCodexQuota>,
    current_login: &LoginMark,
    interval_seconds: u64,
    now: u64,
) -> bool {
    scheduled_read_due_at(saved, current_login, interval_seconds, now) <= now
}

/// When [`scheduled_read_due_every`] turns true while the home keeps
/// `current_login`: `now` when it is due already.
fn scheduled_read_due_at(
    saved: Option<&SavedCodexQuota>,
    current_login: &LoginMark,
    interval_seconds: u64,
    now: u64,
) -> u64 {
    let Some(saved) = saved else {
        return now;
    };
    let last = saved.last_attempt_at_epoch_seconds;
    if last == 0 || last > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return now;
    }
    let mut due_at = last.saturating_add(interval_seconds);
    if saved.last_attempt_login.is_new_login(current_login) {
        due_at = due_at.min(last.saturating_add(LOGIN_CHANGED_MIN_GAP_SECONDS));
    }
    due_at
}

/// Whether an explicit refresh may read the home now: at most once a minute
/// (or `min_gap_seconds`, if longer), counting any read.
pub(super) fn explicit_refresh_allowed(
    saved: Option<&SavedCodexQuota>,
    min_gap_seconds: u64,
    now: u64,
) -> bool {
    saved.map_or(true, |saved| {
        let last = saved.last_attempt_at_epoch_seconds;
        last > now.saturating_add(CLOCK_SKEW_SECONDS)
            || now.saturating_sub(last) >= min_gap_seconds.max(EXPLICIT_REFRESH_MIN_GAP_SECONDS)
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

/// When a process scan last ran (local unix seconds).
static PROCESS_SCANNED_AT: AtomicU64 = AtomicU64::new(0);

/// Record homes where a running Codex process holds a rollout (from a
/// process scan).
pub(super) fn note_running_homes<'a>(homes: impl Iterator<Item = &'a Path>, now: u64) {
    PROCESS_SCANNED_AT.store(now, Ordering::Relaxed);
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

/// Tests that run whole scheduler rounds start without sightings left by
/// other tests' process scans.
#[cfg(test)]
pub(super) fn forget_running_homes() {
    running_homes().clear();
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
/// slot, and recently seen process homes. Read from the stored settings on
/// every tick, so a removed slot leaves the schedule at once. The device's
/// upload grant does not matter: the companion shows these readings locally.
///
/// The home of a running daemon sign-in is left out, for the schedule and
/// the explicit refresh alike: every read rewrites `auth.json`, and the
/// sign-in decides by that file.
fn scheduled_homes(support_dir: &Path, now: u64) -> Vec<ScheduledHome> {
    let PlannedSlots { slots, signing_in } = planned_slots(now);
    let running = running_homes().clone();
    let mut homes = scheduled_homes_from(support_dir, slots, &running, now);
    if let Some(signing_in) = signing_in {
        homes.retain(|home| home_key(&home.home) != signing_in);
    }
    homes
}

/// The slots the stored settings schedule, and the [`home_key`] of a running
/// daemon sign-in's home.
#[derive(Clone)]
struct PlannedSlots {
    slots: Vec<CodexHomeSlot>,
    signing_in: Option<String>,
}

/// The stored settings' slots, kept while the settings file and every
/// directory from `/` to each managed slot's home (the chain whose privacy
/// the settings check) keep their stamps, and the default home is the same.
/// Settings that could not be read in full are not kept.
fn planned_slots(now: u64) -> PlannedSlots {
    static SLOTS: OnceLock<PlannedCache<(PathBuf, PathBuf), PlannedSlots>> = OnceLock::new();
    let settings = default_support_dir().join(CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME);
    let key = (settings.clone(), default_codex_home());
    planned(&SLOTS, &key, now, || {
        let mut stamps = Planned::<PlannedSlots>::stamps([settings]);
        let (first, _) = stored_slots();
        // The directories are known only from the settings: stamped after a
        // first look and checked again by a second one, so a change between
        // the two looks is not kept unseen.
        let chains = managed_home_chains(&first.slots);
        stamps.extend(Planned::<PlannedSlots>::stamps(chains.iter().cloned()));
        let (slots, complete) = stored_slots();
        let complete = complete && managed_home_chains(&slots.slots) == chains;
        (slots, complete.then_some(Lasts::WhileUnchanged), stamps)
    })
}

/// The stored settings' slots, and whether every settings read succeeded.
fn stored_slots() -> (PlannedSlots, bool) {
    let store = FileCodexAccountSlotSettingsStore::default();
    let status = store.load();
    let signing_in = store.active_sign_in();
    let (slots, complete) =
        codex_home_slots_checked(status.as_ref().unwrap_or(&empty_codex_accounts_status()));
    let complete = complete && status.is_ok() && signing_in.is_ok();
    let signing_in = signing_in
        .ok()
        .flatten()
        .map(|active| home_key(&active.home));
    (PlannedSlots { slots, signing_in }, complete)
}

/// Every directory from `/` to each managed slot's home.
fn managed_home_chains(slots: &[CodexHomeSlot]) -> BTreeSet<PathBuf> {
    slots
        .iter()
        .filter(|slot| slot.ownership == CodexAccountSlotOwnershipV1::Managed)
        .flat_map(|slot| slot.home.ancestors().map(Path::to_path_buf))
        .collect()
}

fn scheduled_homes_from(
    support_dir: &Path,
    slots: Vec<CodexHomeSlot>,
    running: &BTreeMap<PathBuf, u64>,
    now: u64,
) -> Vec<ScheduledHome> {
    let mut homes = slots
        .into_iter()
        .map(|slot| scheduled_home(support_dir, running, slot, now))
        .collect::<Vec<_>>();
    for (home, seen_at) in running {
        if recent(*seen_at, now) && !homes.iter().any(|known| &known.home == home) {
            homes.push(scheduled_home(
                support_dir,
                running,
                CodexHomeSlot {
                    slot_id: "process_home".to_string(),
                    ownership: CodexAccountSlotOwnershipV1::Managed,
                    home: home.clone(),
                    registered_binding: None,
                },
                now,
            ));
        }
    }
    homes
}

fn scheduled_home(
    support_dir: &Path,
    running: &BTreeMap<PathBuf, u64>,
    slot: CodexHomeSlot,
    now: u64,
) -> ScheduledHome {
    let trust = match slot.ownership {
        CodexAccountSlotOwnershipV1::Default => CodexHomeTrust::ProviderDefault,
        CodexAccountSlotOwnershipV1::Managed => CodexHomeTrust::Managed,
    };
    ScheduledHome {
        binding: planned_saved(support_dir, &slot.home, now)
            .as_ref()
            .and_then(SavedCodexQuota::binding),
        process_seen_at: running.get(&slot.home).copied(),
        home: slot.home,
        trust,
        ownership: slot.ownership,
    }
}

/// The login a home may share with another home: its saved reading's account
/// and workspace, while it still holds them ([`held_binding`]) and its latest
/// read did not fail. `None`: the home is read on its own.
/// From the kept planning copies: a status read confirms the shared login on
/// both current credentials before it serves another home's reading.
fn shareable_binding(support_dir: &Path, home: &ScheduledHome, now: u64) -> Option<String> {
    let saved = planned_saved(support_dir, &home.home, now)?;
    if !latest_read_succeeded(&saved) {
        return None;
    }
    let binding = saved.binding()?;
    let current = planned_login_mark(&home.home, home.trust, now);
    (held_binding(Some(&saved), &current).as_ref() == Some(&binding)).then_some(binding)
}

/// For each home, the index of the home that reads for it: itself, or, for
/// homes that hold the same login right now, one of them for all. That one is
/// the default home when it is among them, else the lowest home key, so it
/// stays the same from round to round.
fn same_login_readers(support_dir: &Path, homes: &[ScheduledHome], now: u64) -> Vec<usize> {
    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, home) in homes.iter().enumerate() {
        if let Some(binding) = shareable_binding(support_dir, home, now) {
            groups.entry(binding).or_default().push(index);
        }
    }
    let mut readers = (0..homes.len()).collect::<Vec<_>>();
    for members in groups.values().filter(|members| members.len() > 1) {
        let Some(reader) = members.iter().copied().min_by_key(|index| {
            let home = &homes[*index];
            (
                home.ownership != CodexAccountSlotOwnershipV1::Default,
                home_key(&home.home),
            )
        }) else {
            continue;
        };
        for member in members {
            readers[*member] = reader;
        }
    }
    readers
}

/// Homes another home reads for, and that reader with its trust.
type SameLoginReaders = BTreeMap<PathBuf, (PathBuf, CodexHomeTrust)>;

/// Support dirs kept; the daemon uses one, unit tests a few each.
const SAME_LOGIN_SUPPORT_DIRS_MAX: usize = 64;

/// The latest grouping per support dir, for status reads. A status read
/// confirms the shared login on both current credentials before it serves
/// the reader's reading, so an entry that is up to one round old never
/// serves another login.
fn same_login_state() -> MutexGuard<'static, BTreeMap<PathBuf, SameLoginReaders>> {
    static STATE: OnceLock<Mutex<BTreeMap<PathBuf, SameLoginReaders>>> = OnceLock::new();
    STATE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn publish_same_login_readers(support_dir: &Path, homes: &[ScheduledHome], readers: &[usize]) {
    let shared = homes
        .iter()
        .zip(readers)
        .enumerate()
        .filter(|(index, (_, reader))| **reader != *index)
        .map(|(_, (home, reader))| {
            let reader = &homes[*reader];
            (home.home.clone(), (reader.home.clone(), reader.trust))
        })
        .collect::<SameLoginReaders>();
    let mut state = same_login_state();
    if !state.contains_key(support_dir) && state.len() >= SAME_LOGIN_SUPPORT_DIRS_MAX {
        if let Some(evicted) = state.keys().next().cloned() {
            state.remove(&evicted);
        }
    }
    state.insert(support_dir.to_path_buf(), shared);
}

fn same_login_reader(support_dir: &Path, home: &Path) -> Option<(PathBuf, CodexHomeTrust)> {
    same_login_state().get(support_dir)?.get(home).cloned()
}

/// Read every home `due` selects with `read`, in parallel (one thread per
/// home, as the collection does). Returns how many provider reads ran.
fn read_homes(
    support_dir: &Path,
    homes: Vec<ScheduledHome>,
    now: u64,
    due: impl Fn(Option<&SavedCodexQuota>, &ScheduledHome, u64) -> bool + Sync,
    read: impl Fn(&ScheduledHome) -> Result<CodexUsageProbe, String> + Sync,
) -> usize {
    let (due, read) = (&due, &read);
    // Each read logs the reason its caller gave.
    let trigger = crate::provider_calls::current_trigger();
    thread::scope(|scope| {
        homes
            .into_iter()
            .map(|home| {
                scope.spawn(move || {
                    let read_home = || {
                        read_and_save_at(
                            support_dir,
                            &home.home,
                            home.trust,
                            now,
                            |saved, now| due(saved, &home, now),
                            || read(&home),
                        )
                        .is_some()
                    };
                    match trigger {
                        Some(trigger) => crate::provider_calls::with_trigger(trigger, read_home),
                        None => read_home(),
                    }
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(|read| *read)
            .count()
    })
}

/// What a scheduler round did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ScheduledRound {
    /// Homes read from the provider.
    read: usize,
    /// When the round after it has something to do, while nothing changes:
    /// the earliest home due, or the next process scan. `None`: nothing is
    /// scheduled (background limit refresh is off).
    next_due_at: Option<u64>,
}

/// Each home's interval this round: its own 5 or 15 minutes, the in-use one
/// for a home that reads for others when any of them is in use, and the
/// keep-alive for the homes it reads for. With the grouping.
fn round_intervals(
    support_dir: &Path,
    homes: &[ScheduledHome],
    sessions: &[ActiveSession],
    now: u64,
) -> (Vec<usize>, Vec<u64>) {
    let in_use = homes_in_use(homes, sessions, now);
    let readers = same_login_readers(support_dir, homes, now);
    let mut group_in_use = vec![false; homes.len()];
    for (index, reader) in readers.iter().enumerate() {
        group_in_use[*reader] |= in_use[index];
    }
    let intervals = (0..homes.len())
        .map(|index| {
            if readers[index] == index {
                refresh_interval_seconds(group_in_use[index])
            } else {
                SAME_LOGIN_KEEPALIVE_SECONDS
            }
        })
        .collect();
    (readers, intervals)
}

/// When the schedule reads `home` next, from the kept planning copies.
fn planned_due_at(support_dir: &Path, home: &ScheduledHome, interval: u64, now: u64) -> u64 {
    scheduled_read_due_at(
        planned_saved_with_attempt(support_dir, &home.home, now).as_ref(),
        &planned_login_mark(&home.home, home.trust, now),
        interval,
        now,
    )
}

/// One scheduler pass over `homes`: read every due one, and tell when the
/// next one is due.
/// `background_allowed` is asked right before each due read, under that
/// home's lock; `false` skips the read.
fn scheduled_round_for(
    support_dir: &Path,
    homes: Vec<ScheduledHome>,
    sessions: &[ActiveSession],
    now: u64,
    background_allowed: impl Fn() -> bool + Sync,
    read: impl Fn(&ScheduledHome) -> Result<CodexUsageProbe, String> + Sync,
) -> ScheduledRound {
    let (readers, intervals) = round_intervals(support_dir, &homes, sessions, now);
    publish_same_login_readers(support_dir, &homes, &readers);
    let interval_by_home = homes
        .iter()
        .zip(&intervals)
        .map(|(home, interval)| (home.home.clone(), *interval))
        .collect::<BTreeMap<_, _>>();
    // Only homes due by the planning copies get a read thread; each read is
    // still decided again from the files themselves under the home's lock.
    let due = homes
        .iter()
        .zip(&intervals)
        .filter(|(home, interval)| planned_due_at(support_dir, home, **interval, now) <= now)
        .map(|(home, _)| home.clone())
        .collect();
    let read = read_homes(
        support_dir,
        due,
        now,
        |saved, home, now| {
            scheduled_read_due_every(
                saved,
                &login_mark(&home.home, home.trust),
                interval_by_home
                    .get(&home.home)
                    .copied()
                    .unwrap_or(UNUSED_REFRESH_SECONDS),
                now,
            ) && background_allowed()
        },
        read,
    );
    // The reads may have changed the grouping (a failed shared read ends it).
    let (_, intervals) = round_intervals(support_dir, &homes, sessions, now);
    let next_due_at = homes
        .iter()
        .zip(&intervals)
        .map(|(home, interval)| planned_due_at(support_dir, home, *interval, now))
        .min();
    ScheduledRound { read, next_due_at }
}

/// Whether the schedule scans for running Codex processes itself: no scan
/// ran in the last 5 minutes (the Codex lane, which scans on each pass, may
/// be off: source disabled or the device unpaired).
fn process_scan_due(scanned_at: u64, now: u64) -> bool {
    scanned_at == 0
        || scanned_at > now.saturating_add(CLOCK_SKEW_SECONDS)
        || now.saturating_sub(scanned_at) >= PROCESS_SCAN_MIN_GAP_SECONDS
}

/// Scan for running Codex processes when due, so a home in use is read every
/// 5 minutes whether or not the Codex lane runs.
fn scan_running_homes_if_due(now: u64) {
    if !process_scan_due(PROCESS_SCANNED_AT.load(Ordering::Relaxed), now) {
        return;
    }
    #[cfg(not(test))]
    let running = crate::codex_process_homes::running_codex_homes();
    // Tests never see this machine's Codex processes (or read their homes).
    #[cfg(test)]
    let running = Vec::<crate::codex_process_homes::CodexProcessHome>::new();
    note_running_homes(
        running.iter().map(|process| process.auth_home.as_path()),
        now,
    );
}

/// One scheduler pass: read every due home. Returns how many were read.
/// With background limit refresh off it reads nothing and scans nothing.
#[cfg(test)]
pub(super) fn scheduled_round(support_dir: &Path, now: u64) -> usize {
    scheduled_round_due(support_dir, now).read
}

/// [`scheduled_round`], with when the next round has something to do.
fn scheduled_round_due(support_dir: &Path, now: u64) -> ScheduledRound {
    crate::codex_sign_in::end_stale_run();
    let settings = quota_refresh_settings();
    if !settings.background_quota_refresh_allowed() {
        return ScheduledRound::default();
    }
    scan_running_homes_if_due(now);
    let next_scan_at = PROCESS_SCANNED_AT
        .load(Ordering::Relaxed)
        .saturating_add(PROCESS_SCAN_MIN_GAP_SECONDS);
    let homes = scheduled_homes(support_dir, now);
    let mut round = if homes.is_empty() {
        ScheduledRound::default()
    } else {
        let sessions = crate::active_sessions::read_active_session_reconciliation(
            support_dir,
            crate::snapshots::SnapshotSource::Codex,
        )
        .map(|reconciliation| reconciliation.sessions)
        .unwrap_or_default();
        scheduled_round_for(
            support_dir,
            homes,
            &sessions,
            now,
            || settings.background_quota_refresh_allowed_locked(),
            |home| read_codex_usage_from_provider(&home.home, home.trust),
        )
    };
    round.next_due_at = Some(
        round
            .next_due_at
            .map_or(next_scan_at, |at| at.min(next_scan_at)),
    );
    round
}

/// One scheduler pass in the support dir the daemon uses.
#[cfg(test)]
pub(crate) fn scheduled_round_now(now: u64) -> usize {
    scheduled_round(&saved_quota_support_dir(), now)
}

/// How long the scheduler sleeps after a round: until the next home is due,
/// at most [`SCHEDULER_MAX_SLEEP`]; [`SCHEDULER_RETRY`] when one is still due
/// (or the round failed).
fn scheduler_sleep(next_due_at: Option<u64>, now: u64) -> Duration {
    match next_due_at {
        Some(at) if at <= now => SCHEDULER_RETRY,
        Some(at) => Duration::from_secs(at - now).min(SCHEDULER_MAX_SLEEP),
        None => SCHEDULER_MAX_SLEEP,
    }
}

/// What an explicit refresh did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CodexExplicitRefresh {
    /// Homes read from the provider now.
    pub(crate) read: usize,
    /// Homes not read: each was read within the gap.
    pub(crate) rate_limited: usize,
}

/// Explicit refresh: read every Codex home now, each at most once a minute,
/// or once per `min_gap_seconds` if longer, counting any read. Homes that
/// hold the same login are read once, by the home that reads for them.
pub(crate) fn refresh_codex_quota_now(min_gap_seconds: u64) -> CodexExplicitRefresh {
    let support_dir = saved_quota_support_dir();
    let now = current_unix_seconds();
    refresh_homes_now(
        &support_dir,
        scheduled_homes(&support_dir, now),
        min_gap_seconds,
        now,
        |home| read_codex_usage_from_provider(&home.home, home.trust),
    )
}

fn refresh_homes_now(
    support_dir: &Path,
    homes: Vec<ScheduledHome>,
    min_gap_seconds: u64,
    now: u64,
    read: impl Fn(&ScheduledHome) -> Result<CodexUsageProbe, String> + Sync,
) -> CodexExplicitRefresh {
    let readers = same_login_readers(support_dir, &homes, now);
    publish_same_login_readers(support_dir, &homes, &readers);
    let homes = homes
        .into_iter()
        .enumerate()
        .filter(|(index, _)| readers[*index] == *index)
        .map(|(_, home)| home)
        .collect::<Vec<_>>();
    let matching = homes.len();
    let read = read_homes(
        support_dir,
        homes,
        now,
        |saved, _, now| explicit_refresh_allowed(saved, min_gap_seconds, now),
        read,
    );
    if read > 0 {
        crate::agent_status_refresh::request(&SourceKind::Codex);
    }
    CodexExplicitRefresh {
        read,
        rate_limited: matching - read,
    }
}

struct Scheduler {
    state: Mutex<SchedulerState>,
    changed: Condvar,
}

#[derive(Default)]
struct SchedulerState {
    stopped: bool,
    /// Something asked for a round before the next due time.
    woken: bool,
}

impl Scheduler {
    fn state(&self) -> MutexGuard<'_, SchedulerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
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
        state: Mutex::default(),
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
        scheduler.state().stopped = true;
        scheduler.changed.notify_all();
    }
}

/// Run the scheduler's next round now rather than at its next wake (still at
/// least [`SCHEDULER_RETRY`] after the one before): a home is waiting for its
/// first reading, or background limit refresh was switched on. A round reads
/// only homes that are due, so this never reads a home sooner than its
/// schedule allows.
pub(crate) fn wake_codex_quota_scheduler() {
    let Some(scheduler) = scheduler_slot().clone() else {
        return;
    };
    scheduler.state().woken = true;
    scheduler.changed.notify_all();
}

fn run_scheduler(scheduler: &Scheduler) {
    use crate::provider_calls::Trigger;
    let support_dir = saved_quota_support_dir();
    // The first round reads every home the daemon has not read yet.
    let mut trigger = Trigger::Startup;
    loop {
        {
            let mut state = scheduler.state();
            if state.stopped {
                return;
            }
            state.woken = false;
        }
        let started = Instant::now();
        // New readings reach the upload with the lane's next timer pass; a
        // status read serves them at once.
        let next_due_at = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::provider_calls::with_trigger(trigger, || {
                scheduled_round_due(&support_dir, current_unix_seconds()).next_due_at
            })
        }))
        .unwrap_or(Some(0));
        trigger = Trigger::Schedule;
        let sleep = scheduler_sleep(next_due_at, current_unix_seconds());
        let (mut state, _) = scheduler
            .changed
            .wait_timeout_while(scheduler.state(), sleep, |state| {
                !state.stopped && !state.woken
            })
            .unwrap_or_else(PoisonError::into_inner);
        if !state.stopped && state.woken {
            // Woken early: still keep rounds this far apart.
            let rest = SCHEDULER_RETRY.saturating_sub(started.elapsed());
            state = scheduler
                .changed
                .wait_timeout_while(state, rest, |state| !state.stopped)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        if state.stopped {
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

    fn served_error(root: &Path, home: &Path, now: u64) -> Option<String> {
        serve_saved_at(root, home, CodexHomeTrust::Managed, now)
            .err()
            .map(|failure| failure.message)
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

    fn saved_with(attempt_at: u64, login: LoginMark) -> SavedCodexQuota {
        SavedCodexQuota {
            last_attempt_at_epoch_seconds: attempt_at,
            last_attempt_login: login,
            ..SavedCodexQuota::new(Path::new("/unused"))
        }
    }

    fn mark(binding: Option<&str>, modified_secs: u64) -> LoginMark {
        LoginMark {
            binding: binding.map(str::to_string),
            auth: Some(AuthWitness {
                modified_secs,
                modified_nanos: 0,
                len: 10,
            }),
        }
    }

    #[test]
    fn schedule_intervals_are_five_minutes_in_use_and_fifteen_unused() {
        assert_eq!(refresh_interval_seconds(true), 5 * 60);
        assert_eq!(refresh_interval_seconds(false), 15 * 60);
        let login = mark(Some("a:w"), 1);
        let auth = &login;
        let saved = saved_with(10_000, login.clone());
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
        let saved = saved_with(10_000, mark(Some("a:w"), 1));
        let other_account = mark(Some("b:w"), 2);
        assert!(!scheduled_read_due(
            Some(&saved),
            &other_account,
            false,
            10_000 + 59
        ));
        assert!(scheduled_read_due(
            Some(&saved),
            &other_account,
            false,
            10_000 + 60
        ));
        // A token rewrite for the same account (Codex refreshing it) is not a
        // new login: the interval holds.
        let rewritten = mark(Some("a:w"), 2);
        assert!(!scheduled_read_due(
            Some(&saved),
            &rewritten,
            false,
            10_000 + 600
        ));
        // Without a claimed account on either side, a rewritten file is not
        // a new login (every read rewrites it): the interval holds.
        let opaque = saved_with(10_000, mark(None, 1));
        assert!(!scheduled_read_due(
            Some(&opaque),
            &mark(None, 2),
            false,
            10_000 + 600
        ));
        // Nor is a credential that stops naming its account (an expired
        // token), or starts to.
        assert!(!scheduled_read_due(
            Some(&saved),
            &mark(None, 1),
            false,
            10_000 + 600
        ));
        assert!(!scheduled_read_due(
            Some(&opaque),
            &mark(Some("a:w"), 2),
            false,
            10_000 + 600
        ));
        // A credential written into a signed-out home is.
        assert!(scheduled_read_due(
            Some(&saved_with(10_000, LoginMark::default())),
            &mark(None, 2),
            false,
            10_000 + 60
        ));
        // A signed-out home (no auth file before or after) keeps the interval.
        let signed_out = saved_with(10_000, LoginMark::default());
        assert!(!scheduled_read_due(
            Some(&signed_out),
            &LoginMark::default(),
            false,
            10_000 + 600
        ));
    }

    #[test]
    fn a_failed_read_waits_a_full_interval() {
        let mut saved = saved_with(10_000, LoginMark::default());
        saved.last_failure = Some(SavedCodexFailure {
            at_epoch_seconds: 10_000,
            message: "Codex app-server quota read timed out.".to_string(),
            login: LoginMark::default(),
        });
        // Never sooner than the interval: the failure adds no retry.
        assert!(!scheduled_read_due(
            Some(&saved),
            &LoginMark::default(),
            true,
            10_000 + 5 * 60 - 1
        ));
        assert!(!scheduled_read_due(
            Some(&saved),
            &LoginMark::default(),
            false,
            10_000 + 15 * 60 - 1
        ));
    }

    #[test]
    fn explicit_refresh_reads_at_most_once_a_minute() {
        let gap = EXPLICIT_REFRESH_MIN_GAP_SECONDS;
        assert!(explicit_refresh_allowed(None, gap, 10_000));
        let saved = saved_with(10_000, LoginMark::default());
        assert!(!explicit_refresh_allowed(Some(&saved), gap, 10_000));
        assert!(!explicit_refresh_allowed(Some(&saved), gap, 10_059));
        assert!(explicit_refresh_allowed(Some(&saved), gap, 10_060));
        // A longer gap (an older app's status refresh): five minutes.
        assert!(!explicit_refresh_allowed(Some(&saved), 300, 10_299));
        assert!(explicit_refresh_allowed(Some(&saved), 300, 10_300));
        // Never shorter than the minute.
        assert!(!explicit_refresh_allowed(Some(&saved), 0, 10_059));
        // Through the saved file: two refreshes within a minute read once.
        let root = scratch("explicit");
        let home = opaque_home(&root);
        let mut reads = 0;
        for at in [0, 30] {
            let _ = read_and_save_at(
                &root,
                &home,
                CodexHomeTrust::Managed,
                current_unix_seconds() + at,
                |saved, now| explicit_refresh_allowed(saved, gap, now),
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
            CodexHomeTrust::Managed,
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
            served_error(&root, &home, now + 7 * 3_600),
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
            CodexHomeTrust::Managed,
            now,
            |_, _| true,
            || Ok(probe("account-a", "workspace-a", &rfc3339(now))),
        );
        assert!(serve_saved_at(&root, &home, CodexHomeTrust::Managed, now).is_ok());
        write_opaque_auth(&home, "a-different-and-longer-login");
        assert_eq!(
            served_error(&root, &home, now),
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
            CodexHomeTrust::Managed,
            now,
            |_, _| true,
            || Ok(probe("account-a", "workspace-a", &rfc3339(now))),
        );
        let failure = "Codex app-server quota read timed out.".to_string();
        let _ = read_and_save_at(
            &root,
            &home,
            CodexHomeTrust::Managed,
            now,
            |_, _| true,
            || Err(failure.clone()),
        );
        let saved = read_saved_at(&root, &home).unwrap();
        assert!(saved.reading.is_some(), "the last good reading is kept");
        let failed_at = saved.last_failure.as_ref().unwrap().at_epoch_seconds;
        // Served later with the failed read's own time, not as a new failure.
        assert_eq!(
            serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 600).err(),
            Some(CodexQuotaFailure {
                message: failure,
                at_epoch_seconds: failed_at,
            })
        );
        // Not past the last-known cap.
        assert_eq!(
            served_error(&root, &home, failed_at + 7 * 3_600),
            Some(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        // Never for another login.
        write_opaque_auth(&home, "a-different-and-longer-login");
        assert_eq!(
            served_error(&root, &home, now),
            Some(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// The whole schedule over four homes: a home tied to a session or a
    /// running process is read every 5 minutes, the others every 15, and a
    /// removed slot is no longer read; its sessions then count for the
    /// default home.
    #[test]
    fn a_schedule_round_reads_homes_in_use_every_five_minutes_and_drops_removed_ones() {
        let root = scratch("round");
        let homes = ["default", "busy", "process", "idle"].map(|name| {
            let home = root.join(name);
            crate::test_scratch::create_private_dir(&home).unwrap();
            write_opaque_auth(&home, name);
            home
        });
        let slot = |index: usize| CodexHomeSlot {
            slot_id: format!("slot-{index}"),
            ownership: if index == 0 {
                CodexAccountSlotOwnershipV1::Default
            } else {
                CodexAccountSlotOwnershipV1::Managed
            },
            home: homes[index].clone(),
            registered_binding: None,
        };
        let reads = Mutex::new(Vec::<String>::new());
        // A little ahead of the clock, so every attempt is stamped `at`.
        let start = current_unix_seconds() + 30;
        let round = |slots: &[usize], at: u64| {
            reads.lock().unwrap().clear();
            let running = BTreeMap::from([(homes[2].clone(), at - 60)]);
            let sessions = [session(Some(("busy", "w")), at - 60)];
            let scheduled = scheduled_homes_from(
                &root,
                slots.iter().map(|index| slot(*index)).collect(),
                &running,
                at,
            );
            scheduled_round_for(
                &root,
                scheduled,
                &sessions,
                at,
                || true,
                |home| {
                    let name = home.home.file_name().unwrap().to_str().unwrap().to_string();
                    reads.lock().unwrap().push(name.clone());
                    Ok(probe(&name, "w", &rfc3339(at)))
                },
            );
            let mut read = reads.lock().unwrap().clone();
            read.sort();
            read
        };
        let all = [0, 1, 2, 3];
        assert_eq!(round(&all, start), ["busy", "default", "idle", "process"]);
        assert!(round(&all, start + 5 * 60 - 1).is_empty());
        assert_eq!(round(&all, start + 5 * 60), ["busy", "process"]);
        assert_eq!(round(&all, start + 10 * 60), ["busy", "process"]);
        assert_eq!(
            round(&all, start + 15 * 60),
            ["busy", "default", "idle", "process"]
        );
        // "busy" is removed: never read again, and its session now counts for
        // the default home, which is read at the in-use interval.
        assert_eq!(round(&[0, 2, 3], start + 20 * 60), ["default", "process"]);
        assert!(round(&[0, 2, 3], start + 24 * 60).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    /// A read that rewrites a credential naming no account, before or after
    /// (no account id, no current id_token): the rewrite is the read's own,
    /// so the reading is kept and the next read waits the full interval.
    #[test]
    fn a_read_that_rewrites_an_unnamed_credential_keeps_its_reading() {
        let root = scratch("unnamed-rewrite");
        let _pinned = ReadsFinishAtTriggerClock::pin(&root);
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let before = login_mark(&home, CodexHomeTrust::Managed);
        assert_eq!(before.binding, None);
        let result = read_and_save_at(
            &root,
            &home,
            CodexHomeTrust::Managed,
            now,
            |_, _| true,
            || {
                write_opaque_auth(&home, "token-refreshed-by-the-read");
                Ok(probe("account-a", "workspace-a", &rfc3339(now)))
            },
        );
        assert!(matches!(result, Some(Ok(_))));
        let after = login_mark(&home, CodexHomeTrust::Managed);
        assert_eq!(after.binding, None);
        assert_ne!(after, before, "the read rewrote auth.json");
        let saved = read_saved_at(&root, &home).unwrap();
        assert!(saved.reading.is_some(), "the reading is kept");
        assert_eq!(saved.last_attempt_login, after);
        assert!(serve_saved_at(&root, &home, CodexHomeTrust::Managed, now).is_ok());
        for in_use in [true, false] {
            let interval = refresh_interval_seconds(in_use);
            assert!(!scheduled_read_due(Some(&saved), &after, in_use, now + 61));
            assert!(!scheduled_read_due(
                Some(&saved),
                &after,
                in_use,
                now + interval - 1
            ));
            assert!(scheduled_read_due(
                Some(&saved),
                &after,
                in_use,
                now + interval
            ));
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// Only a positively different account or workspace makes a read lose
    /// its login.
    #[test]
    fn only_a_different_named_account_discards_a_read() {
        let named = |binding: &str| mark(Some(binding), 1);
        let unnamed = mark(None, 2);
        let read = Ok(probe("a", "w", &rfc3339(10_000)));
        let failed = Err("Codex app-server quota read timed out.".to_string());
        assert!(read_kept_its_login(&named("a:w"), &named("a:w"), &read));
        assert!(!read_kept_its_login(&named("a:w"), &named("b:w"), &read));
        assert!(read_kept_its_login(&unnamed, &mark(None, 3), &read));
        assert!(read_kept_its_login(&unnamed, &mark(None, 3), &failed));
        assert!(read_kept_its_login(&named("a:w"), &unnamed, &read));
        assert!(read_kept_its_login(&named("a:w"), &unnamed, &failed));
        assert!(!read_kept_its_login(&named("b:w"), &unnamed, &read));
        // An expired token that the read renewed: kept only when the read
        // validated the account the renewed credential names.
        assert!(read_kept_its_login(&unnamed, &named("a:w"), &read));
        assert!(!read_kept_its_login(&unnamed, &named("b:w"), &read));
        assert!(!read_kept_its_login(&unnamed, &named("a:w"), &failed));
    }

    #[test]
    fn an_unwritable_saved_file_still_spaces_the_reads() {
        let root = scratch("unwritable");
        let _pinned = ReadsFinishAtTriggerClock::pin(&root);
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
            scheduled_read_due(
                saved,
                &login_mark(&home, CodexHomeTrust::Managed),
                false,
                now,
            )
        };
        assert!(read_and_save_at(&root, &home, CodexHomeTrust::Managed, now, due, read).is_some());
        assert!(read_saved_at(&root, &home).is_none(), "nothing was written");
        // Later ticks inside the interval do not read again.
        for tick in [15, 60, 14 * 60] {
            assert!(
                read_and_save_at(&root, &home, CodexHomeTrust::Managed, now + tick, due, read)
                    .is_none()
            );
        }
        assert!(read_and_save_at(
            &root,
            &home,
            CodexHomeTrust::Managed,
            now + 15 * 60 + 1,
            due,
            read
        )
        .is_some());
        assert_eq!(reads.get(), 2);
        let explicit = |saved: Option<&SavedCodexQuota>, now: u64| {
            explicit_refresh_allowed(saved, EXPLICIT_REFRESH_MIN_GAP_SECONDS, now)
        };
        assert!(read_and_save_at(
            &root,
            &home,
            CodexHomeTrust::Managed,
            now + 15 * 60 + 30,
            explicit,
            read
        )
        .is_none());
        assert_eq!(reads.get(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_read_that_panics_still_counts_as_an_attempt() {
        let root = scratch("panic");
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let result = read_and_save_at(
            &root,
            &home,
            CodexHomeTrust::Managed,
            now,
            |_, _| true,
            || panic!("a parser bug"),
        );
        assert!(matches!(result, Some(Err(message)) if message == CODEX_QUOTA_READ_PANICKED));
        let saved = saved_with_attempt(&root, &home).expect("attempt recorded");
        assert!(saved.last_attempt_at_epoch_seconds >= now);
        let login = login_mark(&home, CodexHomeTrust::Managed);
        assert!(!scheduled_read_due(Some(&saved), &login, true, now + 15));
        assert!(scheduled_read_due(
            Some(&saved),
            &login,
            true,
            saved.last_attempt_at_epoch_seconds + IN_USE_REFRESH_SECONDS
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn oversized_or_foreign_saved_files_are_ignored() {
        let root = scratch("bounds");
        let home = opaque_home(&root);
        let now = current_unix_seconds();
        let _ = read_and_save_at(
            &root,
            &home,
            CodexHomeTrust::Managed,
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
    fn the_schedule_scans_for_processes_when_no_scan_ran_for_five_minutes() {
        assert!(process_scan_due(0, 10_000));
        assert!(!process_scan_due(10_000, 10_000));
        assert!(!process_scan_due(10_000, 10_000 + 5 * 60 - 1));
        assert!(process_scan_due(10_000, 10_000 + 5 * 60));
        // A clock that stepped back never stops the scans.
        assert!(process_scan_due(10_000 + 3_600, 10_000));
    }

    #[test]
    fn the_next_due_time_is_when_the_due_check_turns_true() {
        let last = 1_000_000;
        let same = mark(Some("a"), 1);
        let switched = mark(Some("b"), 2);
        let cases = [
            (None, &same, 5 * 60, last, last),
            (Some(saved_with(0, same.clone())), &same, 5 * 60, last, last),
            (
                Some(saved_with(last, same.clone())),
                &same,
                5 * 60,
                last,
                last + 5 * 60,
            ),
            (
                Some(saved_with(last, same.clone())),
                &same,
                15 * 60,
                last + 5,
                last + 15 * 60,
            ),
            // A switched login: a minute after the last attempt.
            (
                Some(saved_with(last, same.clone())),
                &switched,
                15 * 60,
                last + 5,
                last + 60,
            ),
            // A clock that stepped back: due now.
            (
                Some(saved_with(last + 3_600, same.clone())),
                &same,
                5 * 60,
                last,
                last,
            ),
        ];
        for (saved, current, interval, now, due_at) in cases {
            assert_eq!(
                scheduled_read_due_at(saved.as_ref(), current, interval, now),
                due_at
            );
            for at in [due_at.saturating_sub(1).max(now), due_at, due_at + 1] {
                assert_eq!(
                    scheduled_read_due_every(saved.as_ref(), current, interval, at),
                    scheduled_read_due_at(saved.as_ref(), current, interval, at) <= at,
                    "{at}"
                );
                assert_eq!(
                    scheduled_read_due_every(saved.as_ref(), current, interval, at),
                    at >= due_at,
                    "{at}"
                );
            }
        }
    }

    #[test]
    fn the_scheduler_sleeps_until_the_next_due_time_and_at_most_a_minute() {
        let now = 1_000_000;
        assert_eq!(scheduler_sleep(Some(now + 5), now), Duration::from_secs(5));
        assert_eq!(
            scheduler_sleep(Some(now + 15 * 60), now),
            SCHEDULER_MAX_SLEEP
        );
        assert_eq!(scheduler_sleep(None, now), SCHEDULER_MAX_SLEEP);
        // Still due after the round (a read refused at the last moment, or
        // a failed round): the old tick.
        assert_eq!(scheduler_sleep(Some(now), now), SCHEDULER_RETRY);
        assert_eq!(scheduler_sleep(Some(now - 60), now), SCHEDULER_RETRY);
        assert_eq!(SCHEDULER_MAX_SLEEP.as_secs(), LOGIN_CHANGED_MIN_GAP_SECONDS);
    }

    /// A round tells when the next home is due: the in-use or unused interval
    /// after its read, and a minute after the last read once the login
    /// switched; that next round reads it.
    #[test]
    fn a_round_tells_when_the_next_home_is_due() {
        let fixture = SameLoginFixture::new("next-due", &[("default", true, "u1", "w")]);
        let start = current_unix_seconds() + 30;
        assert_eq!(
            fixture.planned_round(start, true),
            (vec!["default".to_string()], Some(start + 5 * 60))
        );
        assert_eq!(
            fixture.planned_round(start + 10, false),
            (Vec::new(), Some(start + 15 * 60))
        );
        fixture.sign_in("default", "u2", "w");
        assert_eq!(
            fixture.planned_round(start + 20, false),
            (Vec::new(), Some(start + 60))
        );
        assert_eq!(
            fixture.planned_round(start + 60, false),
            (vec!["default".to_string()], Some(start + 60 + 15 * 60))
        );
    }

    /// Set a file's modification time an hour back, as an unchanged file has.
    fn settle(path: &Path) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3_600))
            .unwrap();
    }

    /// The schedule keeps a credential's login while `auth.json` is unchanged
    /// and its tokens live; a rewrite, a permission change or a token expiry
    /// derives it again, and a file written just now is not kept.
    #[test]
    fn a_planned_login_is_kept_only_while_its_credential_is_unchanged() {
        let root = scratch("planned-login");
        let home = root.join("home");
        crate::test_scratch::create_private_dir(&home).unwrap();
        let auth = home.join("auth.json");
        let trust = CodexHomeTrust::Managed;
        let now = current_unix_seconds();
        sign_in_home_with_id_token_lifetime(&home, "u1", "w", 3_600);
        settle(&auth);
        let first = planned_login_mark(&home, trust, now);
        assert!(first.binding.is_some());
        assert_eq!(first, login_mark(&home, trust));
        let derived = planned_derives();
        assert_eq!(planned_login_mark(&home, trust, now), first);
        assert_eq!(planned_derives(), derived, "kept");
        // Past the id token's expiry: derived again.
        planned_login_mark(&home, trust, now + 3_600 + 1);
        assert_eq!(planned_derives(), derived + 1);

        // Another account, the same length: derived again, and the new one,
        // even right after the write.
        sign_in_home_with_id_token_lifetime(&home, "u2", "w", 3_600);
        let second = planned_login_mark(&home, trust, now);
        assert_ne!(second.binding, first.binding);
        assert_eq!(second, login_mark(&home, trust));
        let derived = planned_derives();
        planned_login_mark(&home, trust, now);
        assert_eq!(planned_derives(), derived + 1, "a fresh file is not kept");

        // A permission change the credential reader refuses.
        settle(&auth);
        let settled = planned_login_mark(&home, trust, now);
        assert_eq!(settled.binding, second.binding);
        assert_eq!(settled, login_mark(&home, trust));
        let derived = planned_derives();
        planned_login_mark(&home, trust, now);
        assert_eq!(planned_derives(), derived, "kept");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let refused = planned_login_mark(&home, trust, now);
        assert_eq!(refused, login_mark(&home, trust));
        assert_eq!(refused.binding, None);

        // A directory above the home that turns group-writable: the reader
        // refuses the whole chain, and so does the kept login.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
            settle(&auth);
            let kept = planned_login_mark(&home, trust, now);
            assert!(kept.binding.is_some());
            assert_eq!(kept, login_mark(&home, trust));
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
            let unsafe_parent = planned_login_mark(&home, trust, now);
            assert_eq!(unsafe_parent, login_mark(&home, trust));
            assert_eq!(unsafe_parent.binding, None);
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// The schedule keeps a saved file while it is unchanged; a write here,
    /// or any rewrite of the file, is seen at once.
    #[test]
    fn a_planned_saved_file_is_kept_only_while_unchanged() {
        let root = scratch("planned-saved");
        let home = root.join("home");
        let now = current_unix_seconds();
        let saved = |attempt_at: u64| SavedCodexQuota {
            last_attempt_at_epoch_seconds: attempt_at,
            ..SavedCodexQuota::new(&home)
        };
        write_saved_at(&root, &home, &saved(1_000_000));
        let path = saved_path(&root, &home);
        settle(&path);
        assert_eq!(planned_saved(&root, &home, now), Some(saved(1_000_000)));
        let derived = planned_derives();
        assert_eq!(planned_saved(&root, &home, now), Some(saved(1_000_000)));
        assert_eq!(planned_derives(), derived, "kept");

        write_saved_at(&root, &home, &saved(2_000_000));
        assert_eq!(planned_saved(&root, &home, now), Some(saved(2_000_000)));

        // Rewritten in place by someone else, the same size.
        settle(&path);
        assert_eq!(planned_saved(&root, &home, now), Some(saved(2_000_000)));
        let body = std::fs::read_to_string(&path).unwrap().replace(
            "\"last_attempt_at_epoch_seconds\":2000000",
            "\"last_attempt_at_epoch_seconds\":3000000",
        );
        std::fs::write(&path, body).unwrap();
        assert_eq!(planned_saved(&root, &home, now), Some(saved(3_000_000)));
        let _ = std::fs::remove_dir_all(root);
    }

    thread_local! {
        static PLANNED_DERIVES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Planning values derived from the files on this thread.
    pub(super) fn note_planned_derive() {
        PLANNED_DERIVES.with(|count| count.set(count.get() + 1));
    }

    fn planned_derives() -> usize {
        PLANNED_DERIVES.with(std::cell::Cell::get)
    }

    /// Support dirs whose reads finish at the trigger's clock.
    fn pinned_support_dirs() -> MutexGuard<'static, BTreeSet<PathBuf>> {
        static PINNED: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
        PINNED
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn reads_finish_at_trigger_clock(support_dir: &Path) -> bool {
        pinned_support_dirs().contains(support_dir)
    }

    /// Reads under a support dir finish at the trigger's clock while this
    /// lives, so a read that crosses a wall-clock second cannot shift the
    /// schedule a test checks to the second.
    struct ReadsFinishAtTriggerClock(PathBuf);

    impl ReadsFinishAtTriggerClock {
        fn pin(support_dir: &Path) -> Self {
            pinned_support_dirs().insert(support_dir.to_path_buf());
            Self(support_dir.to_path_buf())
        }
    }

    impl Drop for ReadsFinishAtTriggerClock {
        fn drop(&mut self) {
            pinned_support_dirs().remove(&self.0);
        }
    }

    /// Write a credential that names `user` in `workspace`, with an id token
    /// that expires `id_token_lifetime` seconds from now (in the past when
    /// negative) and an access token that lives 30 days.
    fn sign_in_home_with_id_token_lifetime(
        home: &Path,
        user: &str,
        workspace: &str,
        id_token_lifetime: i64,
    ) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use std::os::unix::fs::PermissionsExt;
        let jwt = |user: &str, workspace: &str, lifetime: i64| {
            let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
            let payload = URL_SAFE_NO_PAD.encode(
                serde_json::json!({
                    "iss": "https://auth.openai.com",
                    "aud": "synthetic-client",
                    "exp": OffsetDateTime::now_utc().unix_timestamp() + lifetime,
                    "https://api.openai.com/auth": {
                        "chatgpt_user_id": user,
                        "chatgpt_account_id": workspace,
                        "chatgpt_plan_type": "pro"
                    }
                })
                .to_string(),
            );
            format!("{header}.{payload}.synthetic-signature")
        };
        let auth = home.join("auth.json");
        std::fs::write(
            &auth,
            serde_json::json!({
                "tokens": {
                    "access_token": jwt(user, workspace, 30 * 86_400),
                    "id_token": jwt(user, workspace, id_token_lifetime),
                },
                "account_id": workspace,
            })
            .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A provider reading validated for `user` in `workspace`.
    fn bound_probe(user: &str, workspace: &str, observed_at: u64) -> CodexUsageProbe {
        probe(
            &ottto_core::billing_identity_hash("openai", "account", user).unwrap(),
            &ottto_core::billing_identity_hash("openai", "workspace", workspace).unwrap(),
            &rfc3339(observed_at),
        )
    }

    /// Homes on the schedule with fake provider reads that answer for each
    /// home's current login, and count. Reads finish at the round's clock.
    struct SameLoginFixture {
        root: PathBuf,
        /// (name, ownership, home)
        homes: Vec<(&'static str, CodexAccountSlotOwnershipV1, PathBuf)>,
        logins: Mutex<BTreeMap<PathBuf, (String, String)>>,
        failing: Mutex<BTreeSet<&'static str>>,
        reads: Mutex<Vec<String>>,
    }

    impl SameLoginFixture {
        fn new(label: &str, homes: &[(&'static str, bool, &str, &str)]) -> Self {
            let root = scratch(label);
            pinned_support_dirs().insert(root.clone());
            let fixture = Self {
                homes: homes
                    .iter()
                    .map(|(name, default, _, _)| {
                        let home = root.join(name);
                        crate::test_scratch::create_private_dir(&home).unwrap();
                        let ownership = if *default {
                            CodexAccountSlotOwnershipV1::Default
                        } else {
                            CodexAccountSlotOwnershipV1::Managed
                        };
                        (*name, ownership, home)
                    })
                    .collect(),
                root,
                logins: Mutex::default(),
                failing: Mutex::default(),
                reads: Mutex::default(),
            };
            for (name, _, user, workspace) in homes {
                fixture.sign_in(name, user, workspace);
            }
            fixture
        }

        fn home(&self, name: &str) -> &PathBuf {
            &self
                .homes
                .iter()
                .find(|(own, _, _)| *own == name)
                .unwrap()
                .2
        }

        fn trust(&self, name: &str) -> CodexHomeTrust {
            match self
                .homes
                .iter()
                .find(|(own, _, _)| *own == name)
                .unwrap()
                .1
            {
                CodexAccountSlotOwnershipV1::Default => CodexHomeTrust::ProviderDefault,
                CodexAccountSlotOwnershipV1::Managed => CodexHomeTrust::Managed,
            }
        }

        fn sign_in(&self, name: &str, user: &str, workspace: &str) {
            self.sign_in_with_id_token_lifetime(name, user, workspace, 30 * 86_400);
        }

        fn sign_in_with_id_token_lifetime(
            &self,
            name: &str,
            user: &str,
            workspace: &str,
            id_token_lifetime: i64,
        ) {
            let home = self.home(name).clone();
            sign_in_home_with_id_token_lifetime(&home, user, workspace, id_token_lifetime);
            self.logins
                .lock()
                .unwrap()
                .insert(home, (user.to_string(), workspace.to_string()));
        }

        fn scheduled(&self, except: &[&str], at: u64) -> Vec<ScheduledHome> {
            let slots = self
                .homes
                .iter()
                .filter(|(name, _, _)| !except.contains(name))
                .map(|(name, ownership, home)| CodexHomeSlot {
                    slot_id: name.to_string(),
                    ownership: *ownership,
                    home: home.clone(),
                    registered_binding: None,
                })
                .collect();
            scheduled_homes_from(&self.root, slots, &BTreeMap::new(), at)
        }

        fn read(&self, home: &ScheduledHome, at: u64) -> Result<CodexUsageProbe, String> {
            let name = self
                .homes
                .iter()
                .find(|(_, _, own)| own == &home.home)
                .unwrap()
                .0;
            self.reads.lock().unwrap().push(name.to_string());
            if self.failing.lock().unwrap().contains(name) {
                return Err("Codex app-server quota read timed out.".to_string());
            }
            let (user, workspace) = self.logins.lock().unwrap()[&home.home].clone();
            Ok(bound_probe(&user, &workspace, at))
        }

        fn taken_reads(&self) -> Vec<String> {
            let mut reads = std::mem::take(&mut *self.reads.lock().unwrap());
            reads.sort();
            reads
        }

        /// One scheduler round at `at`; `in_use` adds a recent session that
        /// counts for the default home.
        fn round(&self, at: u64, in_use: bool, except: &[&str]) -> Vec<String> {
            let sessions = if in_use {
                vec![session(None, at - 60)]
            } else {
                Vec::new()
            };
            scheduled_round_for(
                &self.root,
                self.scheduled(except, at),
                &sessions,
                at,
                || true,
                |home| self.read(home, at),
            );
            self.taken_reads()
        }

        /// [`Self::round`], with when the next home is due.
        fn planned_round(&self, at: u64, in_use: bool) -> (Vec<String>, Option<u64>) {
            let sessions = if in_use {
                vec![session(None, at - 60)]
            } else {
                Vec::new()
            };
            let round = scheduled_round_for(
                &self.root,
                self.scheduled(&[], at),
                &sessions,
                at,
                || true,
                |home| self.read(home, at),
            );
            let reads = self.taken_reads();
            assert_eq!(round.read, reads.len());
            (reads, round.next_due_at)
        }

        fn refresh(&self, at: u64) -> (CodexExplicitRefresh, Vec<String>) {
            let outcome = refresh_homes_now(&self.root, self.scheduled(&[], at), 0, at, |home| {
                self.read(home, at)
            });
            (outcome, self.taken_reads())
        }

        /// When the reading served for `name` was read, or its failure.
        fn served_at(&self, name: &str, at: u64) -> Result<String, String> {
            serve_saved_at(&self.root, self.home(name), self.trust(name), at)
                .map(|probe| probe.response_completed_at.unwrap())
                .map_err(|failure| failure.message)
        }

        fn served(&self, name: &str, at: u64) -> CodexUsageProbe {
            serve_saved_at(&self.root, self.home(name), self.trust(name), at).unwrap()
        }
    }

    impl Drop for SameLoginFixture {
        fn drop(&mut self) {
            pinned_support_dirs().remove(&self.root);
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// The default home and a managed slot signed into the same account and
    /// workspace share one read: the default home reads at 5 minutes while
    /// either is in use and at 15 otherwise, the slot is read by itself once
    /// a day, and its status serves the default home's reading.
    #[test]
    fn homes_with_the_same_login_are_read_once_and_share_the_reading() {
        let fixture = SameLoginFixture::new(
            "same-login",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
                ("other", false, "user-b", "workspace-a"),
            ],
        );
        let start = current_unix_seconds();
        // Nothing read yet: nothing is known to be shared.
        assert_eq!(
            fixture.round(start, false, &[]),
            ["default", "other", "twin"]
        );
        // In use: the default home reads at 5 minutes, for both.
        assert!(fixture.round(start + 5 * 60 - 1, true, &[]).is_empty());
        assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
        assert_eq!(fixture.round(start + 10 * 60, true, &[]), ["default"]);
        // The slot's card shows the default home's newer reading: windows,
        // credits and reset details.
        let served = fixture.served("twin", start + 10 * 60);
        let expected = bound_probe("user-a", "workspace-a", start + 10 * 60);
        assert_eq!(served.response_completed_at, expected.response_completed_at);
        assert_eq!(served.quota_windows, expected.quota_windows);
        assert_eq!(served.credit_balances, expected.credit_balances);
        assert_eq!(
            served.reset_credit_detail_summary,
            expected.reset_credit_detail_summary
        );
        assert_eq!(served.saved_identity, expected.saved_identity);
        // Not in use: 15 minutes since the default home's last read; the
        // other account keeps its own 15 minutes.
        assert_eq!(fixture.round(start + 15 * 60, false, &[]), ["other"]);
        assert!(fixture.round(start + 25 * 60 - 1, false, &[]).is_empty());
        assert_eq!(fixture.round(start + 25 * 60, false, &[]), ["default"]);
        // The slot only would be in use (a running Codex there): the shared
        // read is at 5 minutes again.
        let mut homes = fixture.scheduled(&[], start + 30 * 60);
        for home in &mut homes {
            if &home.home == fixture.home("twin") {
                home.process_seen_at = Some(start + 29 * 60);
            }
        }
        scheduled_round_for(
            &fixture.root,
            homes,
            &[],
            start + 30 * 60,
            || true,
            |home| fixture.read(home, start + 30 * 60),
        );
        assert_eq!(fixture.taken_reads(), ["default", "other"]);

        // Keep-alive: the slot reads by itself once a day, not before.
        let day = start + SAME_LOGIN_KEEPALIVE_SECONDS;
        assert!(!fixture
            .round(day - 60, false, &[])
            .contains(&"twin".to_string()));
        assert!(fixture.round(day, false, &[]).contains(&"twin".to_string()));
        assert!(!fixture
            .round(day + 15 * 60, false, &[])
            .contains(&"twin".to_string()));
    }

    /// The same account in another workspace is another quota: both homes
    /// keep their own schedule and their own readings.
    #[test]
    fn the_same_account_in_another_workspace_is_read_on_its_own() {
        let fixture = SameLoginFixture::new(
            "same-account-other-workspace",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("slot", false, "user-a", "workspace-b"),
            ],
        );
        let start = current_unix_seconds();
        assert_eq!(fixture.round(start, false, &[]), ["default", "slot"]);
        assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
        assert_eq!(fixture.round(start + 15 * 60, false, &[]), ["slot"]);
        assert_eq!(
            fixture.served("slot", start + 15 * 60).saved_identity,
            bound_probe("user-a", "workspace-b", start).saved_identity
        );
        let (refresh, reads) = fixture.refresh(start + 17 * 60);
        assert_eq!((refresh.read, refresh.rate_limited), (2, 0));
        assert_eq!(reads, ["default", "slot"]);
    }

    /// The slot's id token expired an hour after its own read, while its
    /// `auth.json` is unchanged since then: it still holds the login it read,
    /// so it stays shared, is served the default home's fresh reading, and is
    /// read by itself only for the keep-alive.
    #[test]
    fn a_twin_whose_id_token_expired_stays_shared_until_its_keepalive() {
        let fixture = SameLoginFixture::new(
            "same-login-expired-id-token",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
            ],
        );
        fixture.sign_in_with_id_token_lifetime("twin", "user-a", "workspace-a", -60);
        assert_eq!(
            login_mark(fixture.home("twin"), fixture.trust("twin")).binding,
            None
        );
        let start = current_unix_seconds();
        assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
        assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
        assert!(fixture.round(start + 15 * 60, false, &[]).is_empty());
        assert_eq!(fixture.round(start + 20 * 60, false, &[]), ["default"]);
        assert_eq!(fixture.round(start + 35 * 60, false, &[]), ["default"]);
        // Fresh, although the slot's own reading is 35 minutes old.
        let served = fixture.served("twin", start + 35 * 60);
        assert_eq!(served.response_completed_at, Some(rfc3339(start + 35 * 60)));
        assert!(served
            .quota_windows
            .iter()
            .all(|window| window.freshness == AgentQuotaWindowFreshness::Fresh));

        let day = start + SAME_LOGIN_KEEPALIVE_SECONDS;
        assert!(!fixture
            .round(day - 60, false, &[])
            .contains(&"twin".to_string()));
        assert!(fixture.round(day, false, &[]).contains(&"twin".to_string()));
    }

    /// The slot's `auth.json` is rewritten after its read and names no login:
    /// it may hold another one now, so it is never served the default home's
    /// reading, and it is back on its own schedule.
    #[test]
    fn a_rewritten_credential_that_names_no_login_ends_the_sharing() {
        let fixture = SameLoginFixture::new(
            "same-login-rewritten-unnamed",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
            ],
        );
        fixture.sign_in_with_id_token_lifetime("twin", "user-a", "workspace-a", -60);
        let start = current_unix_seconds();
        assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
        assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
        assert_eq!(
            fixture.served_at("twin", start + 5 * 60 + 10),
            Ok(rfc3339(start + 5 * 60))
        );

        fixture.sign_in_with_id_token_lifetime("twin", "user-a", "workspace-a", -60);
        std::fs::File::options()
            .write(true)
            .open(fixture.home("twin").join("auth.json"))
            .unwrap()
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_000_000))
            .unwrap();
        assert_eq!(
            fixture.served_at("twin", start + 5 * 60 + 30),
            Err(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        assert!(fixture.round(start + 15 * 60 - 1, false, &[]).is_empty());
        assert_eq!(fixture.round(start + 15 * 60, false, &[]), ["twin"]);
        assert_eq!(
            fixture.served_at("twin", start + 15 * 60),
            Ok(rfc3339(start + 15 * 60))
        );
    }

    /// When the default home signs into another account, the slot no longer
    /// shares its readings: at once it serves its own saved copy, and it is
    /// back on its own schedule; the default home's new login is read after a
    /// minute. No provider call is needed to notice.
    #[test]
    fn a_home_that_switches_account_stops_sharing_at_once() {
        let fixture = SameLoginFixture::new(
            "same-login-switch",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
            ],
        );
        let start = current_unix_seconds();
        assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
        assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
        assert_eq!(
            fixture.served_at("twin", start + 5 * 60 + 10),
            Ok(rfc3339(start + 5 * 60))
        );

        let switched = start + 5 * 60 + 30;
        fixture.sign_in("default", "user-c", "workspace-c");
        assert_eq!(fixture.served_at("twin", switched), Ok(rfc3339(start)));
        assert_eq!(
            fixture.served_at("default", switched),
            Err(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        assert_eq!(fixture.round(switched + 61, true, &[]), ["default"]);
        // The slot is read on its own 15 minutes again, not once a day.
        assert!(fixture.round(start + 15 * 60 - 1, false, &[]).is_empty());
        assert_eq!(fixture.round(start + 15 * 60, false, &[]), ["twin"]);
        assert_eq!(
            fixture.served_at("twin", start + 15 * 60),
            Ok(rfc3339(start + 15 * 60))
        );
    }

    /// A failed read of the home that reads for both ends the sharing: the
    /// other home reads on its own schedule and serves its own reading,
    /// never the failed home's older one.
    #[test]
    fn a_failed_shared_read_puts_the_other_home_back_on_its_own_schedule() {
        let fixture = SameLoginFixture::new(
            "same-login-failure",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
            ],
        );
        let start = current_unix_seconds();
        assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
        assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
        fixture.failing.lock().unwrap().insert("default");
        assert_eq!(fixture.round(start + 10 * 60, true, &[]), ["default"]);
        assert_eq!(
            fixture.served_at("default", start + 10 * 60),
            Err("Codex app-server quota read timed out.".to_string())
        );
        assert_eq!(
            fixture.served_at("twin", start + 10 * 60),
            Ok(rfc3339(start))
        );
        assert_eq!(
            fixture.round(start + 15 * 60, true, &[]),
            ["default", "twin"]
        );
        // A later good read of the default home shares again.
        fixture.failing.lock().unwrap().clear();
        assert_eq!(fixture.round(start + 20 * 60, true, &[]), ["default"]);
        assert_eq!(fixture.round(start + 35 * 60, false, &[]), ["default"]);
        assert_eq!(
            fixture.served_at("twin", start + 35 * 60),
            Ok(rfc3339(start + 35 * 60))
        );
    }

    /// The keep-alive read of the other home fails (its login died there):
    /// that failure is what its card shows, and it reads on its own schedule.
    #[test]
    fn a_failed_keepalive_read_is_served_and_not_hidden_by_the_shared_reading() {
        let fixture = SameLoginFixture::new(
            "same-login-keepalive-failure",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
            ],
        );
        let start = current_unix_seconds();
        assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
        fixture.failing.lock().unwrap().insert("twin");
        let day = start + SAME_LOGIN_KEEPALIVE_SECONDS;
        assert_eq!(fixture.round(day, true, &[]), ["default", "twin"]);
        assert_eq!(
            fixture.served_at("twin", day + 60),
            Err("Codex app-server quota read timed out.".to_string())
        );
        assert_eq!(fixture.round(day + 5 * 60, true, &[]), ["default"]);
        assert_eq!(fixture.round(day + 15 * 60, true, &[]), ["default", "twin"]);
    }

    /// An explicit refresh reads homes that hold the same login once, with
    /// the same once-a-minute limit.
    #[test]
    fn an_explicit_refresh_reads_a_shared_login_once() {
        let fixture = SameLoginFixture::new(
            "same-login-refresh",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
                ("other", false, "user-b", "workspace-a"),
            ],
        );
        let start = current_unix_seconds();
        assert_eq!(
            fixture.round(start, false, &[]),
            ["default", "other", "twin"]
        );
        let (first, reads) = fixture.refresh(start + 2 * 60);
        assert_eq!((first.read, first.rate_limited), (2, 0));
        assert_eq!(reads, ["default", "other"]);
        let (second, reads) = fixture.refresh(start + 2 * 60 + 30);
        assert_eq!((second.read, second.rate_limited), (0, 2));
        assert!(reads.is_empty());
        assert_eq!(
            fixture.served_at("twin", start + 2 * 60 + 30),
            Ok(rfc3339(start + 2 * 60))
        );
    }

    /// A home with a running daemon sign-in is left off the schedule (as
    /// `scheduled_homes` does): the other home reads alone on its own
    /// schedule, and the signing-in home is never served the other home's
    /// reading for a login it no longer holds.
    #[test]
    fn a_sign_in_on_one_home_ends_the_sharing_for_both() {
        let fixture = SameLoginFixture::new(
            "same-login-sign-in",
            &[
                ("default", true, "user-a", "workspace-a"),
                ("twin", false, "user-a", "workspace-a"),
            ],
        );
        let start = current_unix_seconds();
        assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
        assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);

        // A sign-in runs in the default home: the slot reads alone.
        assert!(fixture
            .round(start + 15 * 60 - 1, true, &["default"])
            .is_empty());
        assert_eq!(fixture.round(start + 15 * 60, true, &["default"]), ["twin"]);
        assert_eq!(fixture.round(start + 30 * 60, true, &["default"]), ["twin"]);

        // A sign-in runs in the slot and writes another account, before and
        // after the next round: never the default home's reading.
        assert_eq!(fixture.round(start + 31 * 60, true, &[]), ["default"]);
        assert_eq!(
            fixture.served_at("twin", start + 31 * 60),
            Ok(rfc3339(start + 31 * 60))
        );
        fixture.sign_in("twin", "user-d", "workspace-d");
        assert_eq!(
            fixture.served_at("twin", start + 31 * 60),
            Err(CODEX_QUOTA_NOT_READ_YET.to_string())
        );
        assert_eq!(fixture.round(start + 36 * 60, true, &["twin"]), ["default"]);
        assert_eq!(
            fixture.served_at("twin", start + 36 * 60),
            Err(CODEX_QUOTA_NOT_READ_YET.to_string())
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
