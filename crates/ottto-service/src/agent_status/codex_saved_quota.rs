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
//! - otherwise every 30 min;
//! - a failed read waits the same interval before the next attempt;
//! - a changed local login (the credential names another account or
//!   workspace than at the last read) is read again after at least 1 min;
//! - an explicit refresh reads now, at most once a minute per home.
//!
//! Two homes can hold the same login (the default home and a managed slot
//! signed into the same account and workspace). They share one quota, so one
//! of them reads for both: the default home when it is one of them, else the
//! one with the lowest home key. Its interval is the in-use one when any of
//! them is in use; the others are read by themselves only once a day (each
//! read lets Codex refresh that home's own login when due, and a dead login
//! there is noticed), or every 30 min while a Codex process runs in that home
//! itself, and their status serves the reader's reading. Homes hold the same login only while
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
//! `auth.json` file: each provider read lets Codex refresh the token when due,
//! and Codex then rewrites that file. Only a credential that names no account
//! falls back to the file's metadata. A saved reading or failure is served only while the
//! home's login is the one it was read under, so it never moves to another
//! login. A reading carries identity hashes only.

use crate::local_resource_diagnostics::StageWindow;
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
    CODEX_NO_ACCOUNT_FAILURE_PREFIX,
};

/// In use on this Mac: one provider read per 5 min.
pub(super) const IN_USE_REFRESH_SECONDS: u64 = 5 * 60;
/// Not in use: one provider read per 30 min.
pub(super) const UNUSED_REFRESH_SECONDS: u64 = 30 * 60;
/// A home is in use while its latest session or process sighting is this
/// recent.
pub(super) const IN_USE_WINDOW_SECONDS: u64 = 30 * 60;
/// An explicit refresh reads a home at most this often.
pub(super) const EXPLICIT_REFRESH_MIN_GAP_SECONDS: u64 = 60;
/// A changed local login is read again after at least this long.
const LOGIN_CHANGED_MIN_GAP_SECONDS: u64 = 60;
/// A home that holds the same login as the home reading for it is still read
/// by itself this often: each read lets Codex refresh that home's own tokens
/// when due, and a login that died there (revoked, signed out elsewhere) shows as its own
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
// A saved reading counts as fresh, and admits a session launch, for at most
// an hour.
const _: () = assert!(SERVED_FRESH_MAX_AGE_SECONDS <= 60 * 60);
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct LoginMark {
    /// [`codex_credit_grants::binding_key`] of the claimed identity hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<AuthWitness>,
    /// The binding the same credential names at any token age, from the same
    /// read; never saved. A carried binding needs it ([`held_binding`]).
    #[serde(skip)]
    named: Option<String>,
}

/// Compares what is saved: `named` follows from the same file.
impl PartialEq for LoginMark {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding && self.auth == other.auth
    }
}

impl Eq for LoginMark {}

impl LoginMark {
    /// The same login: the same claimed account and workspace. The file
    /// metadata decides when either side claims none (a token rewrite for the
    /// same account is not a new login, and an unchanged file is the same
    /// login whether or not its tokens still live).
    pub(super) fn same_login(&self, other: &Self) -> bool {
        match (&self.binding, &other.binding) {
            (Some(own), Some(other)) => own == other,
            _ => self.auth == other.auth,
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
            named: None,
        }
    }
}

pub(super) fn login_mark(home: &Path, home_trust: CodexHomeTrust) -> LoginMark {
    login_mark_lasting(home, home_trust).0
}

/// [`login_mark`], and how long it holds while `auth.json` is unchanged: a
/// claimed binding lapses when its access token expires, a missing one stays
/// missing. `None`: it may change without the file changing (the credential
/// could not be read, or its expiry is unknown).
fn login_mark_lasting(home: &Path, home_trust: CodexHomeTrust) -> (LoginMark, Option<Lasts>) {
    let credentials = read_codex_auth_credentials_at(home, home_trust);
    let claimed = credentials.as_ref().ok().and_then(Option::as_ref);
    let binding = claimed.and_then(|claimed| codex_credential_claimed_binding(claimed, true));
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
        named: claimed.and_then(|claimed| codex_credential_claimed_binding(claimed, false)),
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
pub(super) struct PathStamp {
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
pub(super) fn path_stamp(path: &Path) -> Option<PathStamp> {
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
    pub(super) fn settled(&self) -> bool {
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
    /// The read succeeded with no account at all (`account: null`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    provider_account_absent: bool,
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
            provider_account_absent: probe.provider_account_absent,
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
            provider_account_absent: self.provider_account_absent,
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
        crate::locked_state_dir::replace_owner_only_file_counted(
            &saved_path(support_dir, home),
            &body,
            false,
            crate::locked_state_dir::SmallFileClass::Durable,
        )
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

/// Move the saved reading of a sign-in's staging home `from` to the slot
/// home `to` its login was just published into (the same file, hard-linked),
/// so `to` serves the verified reading at once. Call under `to`'s lock.
pub(crate) fn adopt_saved_codex_reading(from: &Path, to: &Path) {
    let support_dir = saved_quota_support_dir();
    let Some(mut saved) = read_saved_at(&support_dir, from) else {
        return;
    };
    saved.home_key = home_key(to);
    write_saved_at(&support_dir, to, &saved);
    let from_path = saved_path(&support_dir, from);
    let _ = std::fs::remove_file(&from_path);
    planned_cache(&PLANNED_SAVED).remove(&from_path);
}

/// Run `f` while no provider read of `home` runs: under the home's lock.
pub(crate) fn with_codex_home_read_lock<T>(home: &Path, f: impl FnOnce() -> T) -> T {
    let lock_for_home = home_lock(home);
    let _guard = lock(&lock_for_home);
    f()
}

/// [`with_codex_home_read_lock`], waiting for the lock only until `deadline`:
/// a free lock is taken at once; one that had to be waited for, only before
/// `deadline`. `None`, with nothing run, otherwise.
pub(crate) fn with_codex_home_read_lock_until<T>(
    home: &Path,
    deadline: Instant,
    f: impl FnOnce() -> T,
) -> Option<T> {
    let lock_for_home = home_lock(home);
    let mut waited = false;
    let _guard = loop {
        let guard = match lock_for_home.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        let now = Instant::now();
        match guard {
            Some(guard) if !waited || now < deadline => break guard,
            None if now < deadline => {
                thread::sleep(crate::codex_sign_in::POLL_INTERVAL.min(deadline - now))
            }
            _ => return None,
        }
        waited = true;
    };
    Some(f())
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
/// ones its live credential names, or, when its access token has expired
/// (Codex refreshes it only when due, at a read or a session), its saved
/// reading's while its latest read did not fail, `auth.json` is unchanged
/// since that read and the credential still names that account and
/// workspace. An unchanged file still holds the login the provider
/// validated, so this never takes one login for another.
fn held_binding(saved: Option<&SavedCodexQuota>, current: &LoginMark) -> Option<String> {
    if let Some(binding) = current.binding.as_ref() {
        return Some(binding.clone());
    }
    let saved = saved.filter(|saved| latest_read_succeeded(saved))?;
    let reading = saved.reading.as_ref()?;
    let binding = saved.binding()?;
    (reading.login.auth.is_some()
        && reading.login.auth == current.auth
        && current.named.as_ref() == Some(&binding))
    .then_some(binding)
}

/// [`held_binding`] of a home now, for launch admission: from local files
/// only, never a provider read.
pub(super) fn held_launch_binding(home: &Path, home_trust: CodexHomeTrust) -> Option<String> {
    let saved = read_saved_at(&saved_quota_support_dir(), home);
    held_binding(saved.as_ref(), &login_mark(home, home_trust))
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
            // A dead login (the read named no account) lasts only until a
            // sign-in rewrites the credential file, even for the same account.
            && (!failure.message.starts_with(CODEX_NO_ACCOUNT_FAILURE_PREFIX)
                || failure.login.same_credential_file(current))
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
        // expired) or the reading had none: only an unchanged auth file that
        // still names the reading's binding, if any, keeps the reading.
        (validated, _) => {
            reading.login.auth.is_some()
                && reading.login.auth == current.auth
                && validated.map_or(true, |validated| current.named.as_ref() == Some(&validated))
        }
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
/// may rewrite `auth.json` (Codex refreshes the token when due), so only a
/// positively different account or workspace is a change. A credential that named none
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

/// Test only: a provider read of the managed `home` that `read` answers,
/// saved as [`read_provider_and_save`] saves one.
#[cfg(test)]
pub(super) fn save_read_for_test(
    home: &Path,
    read: impl FnOnce() -> Result<CodexUsageProbe, String>,
) {
    let now = current_unix_seconds();
    let support_dir = saved_quota_support_dir();
    let _ = read_and_save_at(
        &support_dir,
        home,
        CodexHomeTrust::Managed,
        now,
        |_, _| true,
        read,
    );
}

/// Test only: `body` as `home`'s saved file (bytes another release wrote),
/// with `{home_key}` replaced by the home's key.
#[cfg(test)]
pub(super) fn write_saved_bytes_for_test(home: &Path, body: &str) {
    let support_dir = saved_quota_support_dir();
    let path = saved_path(&support_dir, home);
    let body = body.replace("{home_key}", &home_key(home));
    restrict_state_dirs(&support_dir).unwrap();
    ottto_core::write_owner_only_cache_file_atomic(&path, body.as_bytes()).unwrap();
    planned_cache(&PLANNED_SAVED).remove(&path);
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

/// [`scheduled_read_due_every`] at a home's own 5 or 30 minutes.
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
/// The homes of a running daemon sign-in are left out, for the schedule and
/// the explicit refresh alike: every read rewrites `auth.json`, the sign-in
/// decides by its home's file, and the slot's home takes the new login when
/// it is accepted.
fn scheduled_homes(support_dir: &Path, now: u64) -> Vec<ScheduledHome> {
    let PlannedSlots { slots, signing_in } = planned_slots(now);
    let running = running_homes().clone();
    let mut homes = scheduled_homes_from(support_dir, slots, &running, now);
    homes.retain(|home| !signing_in.contains(&home_key(&home.home)));
    homes
}

/// The slots the stored settings schedule, and the [`home_key`]s of a
/// running daemon sign-in's homes: where `codex login` runs and the slot's.
#[derive(Clone)]
struct PlannedSlots {
    slots: Vec<CodexHomeSlot>,
    signing_in: Vec<String>,
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
        .map(|active| vec![home_key(&active.home), home_key(&active.slot_home)])
        .unwrap_or_default();
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
                CodexHomeSlot::process_home(home.clone()),
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

/// Each home's interval this round: its own 5 or 30 minutes, the in-use one
/// for a home that reads for others when any of them is in use, and the
/// keep-alive for the homes it reads for, or the unused interval while one of
/// those is itself in use. With the grouping.
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
            } else if in_use[index] {
                // Codex runs in this home on its own login (a helper, say):
                // a login that died there must show within the unused
                // interval, not a day later behind the reader's readings.
                UNUSED_REFRESH_SECONDS
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
    let _stage = StageWindow::begin("codex", "offpass_codex_quota");
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
/// counting any read. Homes that hold the same login are read once, by the
/// home that reads for them.
pub(crate) fn refresh_codex_quota_now() -> CodexExplicitRefresh {
    let support_dir = saved_quota_support_dir();
    let now = current_unix_seconds();
    refresh_homes_now(
        &support_dir,
        scheduled_homes(&support_dir, now),
        now,
        |home| read_codex_usage_from_provider(&home.home, home.trust),
    )
}

fn refresh_homes_now(
    support_dir: &Path,
    homes: Vec<ScheduledHome>,
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
        |saved, _, now| explicit_refresh_allowed(saved, now),
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
#[rustfmt::skip]
mod tests;
