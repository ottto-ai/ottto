use crate::locked_state_dir::open_private_lock_file;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(test)]
use ottto_core::claude_account_identifier_hash;
use ottto_core::{
    billing_identity_hash, compiled_release_version, default_support_dir,
    read_claude_statusline_cache, read_claude_statusline_context_cache,
    read_claude_statusline_context_history, write_owner_only_file_atomic, ClaudeConfigDirSlot,
    ClaudeSlotAccountBinding, ClaudeStatusLineContextWindowCache,
    ClaudeStatusLineContextWindowHistory, ClaudeStatusLineContextWindowSample,
    ClaudeStatusLineRateLimitCache, CodexHomeTrust, FileClaudeConfigSlotSettingsStore,
    FileCodexAccountSlotSettingsStore, MAX_CLAUDE_ACCOUNT_SLOTS,
};
use ottto_protocol::{
    AgentAccountStatus, AgentAvailableModelStatus, AgentCapabilityGap, AgentCapabilityStatus,
    AgentContextCompleteness, AgentContextPressureSample, AgentContextState, AgentContextStatus,
    AgentCreditBalance, AgentCreditBalanceStatus, AgentCreditBalanceUnit, AgentDiagnosticSeverity,
    AgentLoginState, AgentModelStatus, AgentQuotaWindow, AgentQuotaWindowFreshness,
    AgentQuotaWindowScope, AgentQuotaWindowStatus, AgentRuntimeDefaults,
    AgentStatusCollectionMethod, AgentStatusConfidence, AgentStatusDiagnostic,
    AgentStatusPlanObservation, AgentStatusSnapshot, AgentStatusState,
    ClaudeAccountAnchorCoverageV1, ClaudeAccountAnchorDescriptorV1,
    ClaudeAccountAnchorDurabilityV1, ClaudeAccountAnchorHealthV1,
    ClaudeAccountAnchorSetupBlockerV1, ClaudeAccountsStatusV1, ClaudeConfigSlotAccountProfileV1,
    ClaudeConfigSlotCollectionStateV1, ClaudeConfigSlotCollectionStatusV1,
    ClaudeConfigSlotDescriptorV1, ClaudeConfigSlotDiagnosticCodeV1, ClaudeConfigSlotDiagnosticV1,
    ClaudeConfigSlotOwnership, ClaudeConfigSlotQuotaSnapshotStateV1,
    ClaudeConfigSlotQuotaSnapshotV1, ClaudeConfigSlotUpkeepResultV1, ClaudeQuotaAccessState,
    ClaudeUnresolvedAccountDescriptorV1, ClaudeUnresolvedAccountEvidenceKind,
    CodexAccountSlotCollectionStateV1, CodexAccountSlotCollectionStatusV1,
    CodexAccountSlotDescriptorV1, CodexAccountSlotDiagnosticV1, CodexAccountSlotOwnershipV1,
    CodexAccountSlotQuotaSnapshotV1, CodexAccountSlotRelationshipV1, CodexAccountTargetCoverageV1,
    CodexAccountTargetDescriptorV1, CodexAccountTargetDurabilityV1, CodexAccountTargetHealthV1,
    CodexAccountTargetSetupBlockerV1, CodexAccountsStatusV1, CreditAmount, SourceKind,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::{
    format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime, UtcOffset,
};

mod claude_credit_pools;
mod claude_token_owner;
mod codex_credit_grants;
mod codex_last_known;
mod codex_saved_quota;
mod codex_setup_gate;
mod credit_amount_input;

use codex_saved_quota::{path_stamp, PathStamp};

#[cfg(test)]
pub(crate) use codex_saved_quota::scheduled_round_now as codex_scheduled_round_now;
pub use codex_saved_quota::start_codex_quota_scheduler;
pub(crate) use codex_saved_quota::{
    refresh_codex_quota_now, saved_codex_quota_generation, stop_codex_quota_scheduler,
    wake_codex_quota_scheduler, with_codex_home_read_lock,
};
#[cfg(test)]
pub(crate) use codex_setup_gate::SetupGateTestClock;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CODEX_APP_SERVER_TIMEOUT: Duration = Duration::from_secs(20);
const CODEX_APP_SERVER_MAX_LINE_BYTES: usize = 256 * 1024;
const CODEX_APP_SERVER_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const CODEX_APP_SERVER_MAX_MESSAGES: usize = 256;
const CODEX_APP_SERVER_CHANNEL_CAPACITY: usize = 16;
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_AVAILABLE_MODELS: usize = 250;
const CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS: u64 = 15 * 60;
const CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES: usize = 48;
const CLAUDE_OAUTH_USAGE_ENDPOINT: &str = "https://api.anthropic.com/api/oauth/usage";
const CLAUDE_OAUTH_BETA_HEADER: &str = "oauth-2025-04-20";
const CLAUDE_OAUTH_USAGE_CACHE_FILE: &str = "usage-cache.json";
const CLAUDE_OAUTH_USAGE_ACCOUNT_STATE_DIR: &str = "claude-oauth-usage/accounts";
const CLAUDE_OAUTH_USAGE_LEGACY_CACHE_FILE: &str = "claude-code-oauth-usage-cache.json";
/// Display fallback only: how long a cached payload may still be rendered (as
/// `Stale`) when the endpoint cannot be reached. Not a refresh cadence.
const CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
/// Unused-account slot: one read per ~40 min per account binding (~36/day).
/// Sparse polling is half of the recorded provider-endpoints posture
/// (identify honestly, poll sparsely, circuit-break instead of adapting). The
/// activity-based slot in `claude_credit_pools` shortens this to 5 min while
/// the binding is in use on this Mac, and a fresh local statusLine reading
/// stands in for those reads.
const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS: u64 = 40 * 60;
/// Half-width of the deterministic spread applied to the base cadence, giving
/// an effective gate in the 38-42 minute range.
const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS: u64 = 2 * 60;
/// Spacing after a successful read: 5 min to the next read of the account,
/// pass to pass. Measured from the start of the collection pass that read
/// ([`claude_spacing_anchor`]), so the daemon's next 5-min pass finds an
/// in-use account due wherever in the pass its read falls; two reads can
/// therefore be up to the anchor cap closer than 5 min. Retry-After and
/// breaker holds are stored and checked separately and are never shortened
/// by it.
const CLAUDE_OAUTH_USAGE_REFRESH_SECONDS: u64 = 5 * 60;
const CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS: u64 = 5 * 60;
/// Off-switch sentinel: while this file exists in the daemon support dir the
/// Claude OAuth usage endpoint is never contacted and quota comes from the
/// sanctioned local statusLine surface only. The name is a fixed contract with
/// the macOS Companion toggle - do not rename it.
pub(crate) const CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE: &str =
    "claude-oauth-usage-network-disabled";
const CLAUDE_OAUTH_USAGE_BREAKER_FILE: &str = "breaker.json";
const CLAUDE_OAUTH_USAGE_LEGACY_BREAKER_FILE: &str = "claude-oauth-usage-breaker.json";
const CLAUDE_CONFIG_SLOT_COLLECTION_STATE_FILE: &str = "claude-config-slot-collection-state.json";
const CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE: &str =
    ".claude-config-slot-collection-state.lock";
const CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION: u16 = 1;
const CLAUDE_QUOTA_ACCESS_CAPABILITY: &str = "claude_quota_access_state_v1";
const CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION: u16 = 1;
/// How long the breaker stays open once tripped. Long on purpose: an open
/// breaker means we believe further calls could be unwelcome or useless, and a
/// short cool-down would just re-probe the same wall.
const CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS: u64 = 24 * 60 * 60;
/// Consecutive 401/403 responses before the breaker opens. Low: an auth/scope
/// rejection that survives a retry is structural, not transient.
const CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD: u32 = 3;
/// Consecutive unreadable/unrecognised 200 bodies (or a vanished endpoint)
/// before the breaker opens.
const CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD: u32 = 3;
/// Consecutive 429s before the breaker opens. Higher than the other classes:
/// a single 429 is routine here and is already handled by the retry-after
/// backoff; this catches the sustained case that backoff never clears.
const CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD: u32 = 5;
/// First backoff after one caller's credential is rejected with 401/403. It
/// doubles for each further consecutive rejection of the same caller; once the
/// caller reaches `CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD` it holds the full
/// breaker cool-down. Other callers for the same account are not held.
const CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS: u64 = 15 * 60;
static CLAUDE_OAUTH_ACCOUNT_STATE_LOCKS: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<()>>>>> =
    OnceLock::new();
static CLAUDE_OAUTH_COLLECTION_ATTEMPT_LOCKS: OnceLock<
    Mutex<BTreeMap<String, &'static Mutex<()>>>,
> = OnceLock::new();
static CLAUDE_OAUTH_LEGACY_MIGRATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static CLAUDE_SLOT_COLLECTION_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const CLAUDE_DESKTOP_CODE_SESSION_MAX_FILES_PER_ORG: usize = 500;
const CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG: usize = 200;
const CLAUDE_DESKTOP_DUPLICATE_SESSION_OBSERVATION_MAX: usize = 64;
/// Most plan observations one Desktop pair status carries: exact pairs first,
/// then their duplicate-session observations. The backend accepts at most 20
/// plan observations per snapshot and refuses the whole upload over it.
const CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX: usize = 20;
/// The backend accepts at most this many status snapshots in one upload.
const AGENT_STATUS_UPLOAD_SNAPSHOT_MAX: usize = 10;
// Reuse the daemon's existing detected-use/session retention contract. This
// warning is a view of the same local activity evidence, not a new lifetime.
const CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS: i64 =
    crate::detected_uses::DETECTED_USE_RETENTION_DAYS * 24 * 60 * 60;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BillingIdentityHints {
    pub(crate) account_identifier_hash: Option<String>,
    pub(crate) organization_identifier_hash: Option<String>,
    pub(crate) credential_fingerprint_hash: Option<String>,
    pub(crate) billing_identity_evidence: Option<String>,
    pub(crate) billing_identity_confidence: AgentStatusConfidence,
}

#[derive(Debug, Clone)]
struct CommandOutput {
    command_found: bool,
    success: bool,
    status_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone)]
struct CodexAuthCredentials {
    access_token: Option<String>,
    id_token: Option<String>,
    account_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct CodexCredentialReadError;

#[derive(Clone)]
struct CodexUsageProbe {
    quota_windows: Vec<AgentQuotaWindow>,
    credit_balances: Vec<AgentCreditBalance>,
    account: Option<AgentAccountStatus>,
    /// Set by a provider read only; a saved reading carries `saved_identity`.
    identity: Option<CodexStrongIdentity>,
    /// The identity hashes of a saved reading, whose provider validation
    /// happened when it was read (see `codex_saved_quota`).
    saved_identity: Option<CodexIdentityHashes>,
    credential_read_failed: bool,
    /// Completion of the app-server read, distinct from quota value changes.
    response_completed_at: Option<String>,
    /// Fixed vocabulary and aggregate counts only; never provider ids/titles.
    reset_credit_detail_summary: Option<String>,
    /// Counts-only view of the non-selected rate-limit pools (design C2a).
    rate_limit_pool_summary: Option<String>,
}

/// Strong active Codex identity from one exact credential home. This type is
/// intentionally neither `Debug` nor serializable because the raw workspace
/// id is needed only to write Codex's supported workspace restriction after a
/// target-bound setup succeeds.
#[derive(Clone)]
pub(crate) struct CodexStrongIdentity {
    pub(crate) account_identifier_hash: String,
    pub(crate) workspace_identifier_hash: String,
    pub(crate) raw_workspace_id: String,
    /// What THIS SAME account and workspace hashed to before the derivation
    /// changed: the account was keyed on `chatgpt_account_id` rather than the
    /// user id, and the organization on `organizations[].id` under the
    /// `organization` kind rather than the workspace id under `workspace`.
    ///
    /// Every server that stored the old digests sees an unrelated account once
    /// the new ones arrive, because the two conflict on every field. Only this
    /// collector holds the raw values, so only it can say they are one account.
    pub(crate) superseded_account_identifier_hash: Option<String>,
    pub(crate) superseded_organization_identifier_hash: Option<String>,
}

/// The identity hashes of a provider-validated Codex reading, without the raw
/// workspace id. This is all a saved reading keeps; it grants no setup
/// authority (setup always reads the provider).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CodexIdentityHashes {
    account_identifier_hash: String,
    workspace_identifier_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    superseded_account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    superseded_organization_identifier_hash: Option<String>,
}

impl From<&CodexStrongIdentity> for CodexIdentityHashes {
    fn from(identity: &CodexStrongIdentity) -> Self {
        Self {
            account_identifier_hash: identity.account_identifier_hash.clone(),
            workspace_identifier_hash: identity.workspace_identifier_hash.clone(),
            superseded_account_identifier_hash: identity.superseded_account_identifier_hash.clone(),
            superseded_organization_identifier_hash: identity
                .superseded_organization_identifier_hash
                .clone(),
        }
    }
}

/// Where a Codex home's quota comes from in one collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexQuotaRead {
    /// The home's saved reading (`codex_saved_quota`); never starts a
    /// provider read. Every status read uses this.
    Saved,
    /// Read the provider now (one `codex app-server` run) and save the
    /// outcome. Only the refresh schedule, an explicit refresh and setup
    /// checks use this.
    Provider,
}

#[derive(Clone)]
struct CodexHomeSlot {
    slot_id: String,
    ownership: CodexAccountSlotOwnershipV1,
    home: PathBuf,
    registered_binding: Option<(String, String)>,
}

impl CodexHomeSlot {
    /// A home seen only through a running Codex process: read like an account
    /// home, but not registered.
    fn process_home(home: PathBuf) -> Self {
        Self {
            slot_id: "process_home".to_string(),
            ownership: CodexAccountSlotOwnershipV1::Managed,
            home,
            registered_binding: None,
        }
    }

    /// A registered Ottto account slot's login may be refreshed by the limits
    /// probe; the default home and a home seen only through a running Codex
    /// process (no registered binding) are a person's own logins.
    fn login_refresh(&self) -> CodexLoginRefresh {
        match (self.ownership, &self.registered_binding) {
            (CodexAccountSlotOwnershipV1::Managed, Some(_)) => CodexLoginRefresh::WhenLapsing,
            _ => CodexLoginRefresh::Never,
        }
    }
}

/// Whether the limits probe may force a refresh of a home's login: only for
/// an Ottto account slot, and then only while it lapses
/// ([`codex_probe_refresh_reason`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexLoginRefresh {
    Never,
    WhenLapsing,
}

struct CodexSlotCandidate {
    slot: CodexHomeSlot,
    snapshot: AgentStatusSnapshot,
    status: CodexAccountSlotCollectionStatusV1,
    binding: Option<(String, String)>,
    workspace_targets: Vec<CodexWorkspaceTargetEvidence>,
    quality: u8,
    auth_modified_at: Option<std::time::SystemTime>,
}

#[derive(Clone)]
struct CodexWorkspaceTargetEvidence {
    account_identifier_hash: Option<String>,
    workspace_identifier_hash: Option<String>,
    workspace_label: Option<String>,
    /// Signed-in account name from the id_token `email` claim, sanitized through
    /// `safe_display_label`. Local-control display only; never uploaded.
    account_label: Option<String>,
    /// Plan the credential claims via `chatgpt_plan_type`. It describes the
    /// workspace the credential is signed into, so it is carried only on the
    /// `is_default` evidence row; the other organizations in the same token have
    /// no claimed plan of their own.
    plan_type: Option<String>,
    is_default: bool,
    observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeOAuthUsageCache {
    schema_version: u16,
    /// Which Claude account the cached numbers belong to, as the same
    /// `billing_identity_hash` this collector uses everywhere else.
    ///
    /// The physical path is account-keyed, but every read still requires this
    /// field, the organization hash, and every embedded meter to agree exactly.
    #[serde(default)]
    account_identifier_hash: String,
    /// Exact organization paired with the account when these meters were
    /// fetched. Both hashes and every embedded meter must agree on read.
    #[serde(default)]
    organization_identifier_hash: String,
    observed_at_epoch_seconds: u64,
    next_refresh_after_epoch_seconds: u64,
    windows: Vec<AgentQuotaWindow>,
    /// Usage-credit balances parsed from the same OAuth usage response.
    /// `serde(default)` permits safe parsing of older caches before their
    /// schema and identity are rejected.
    #[serde(default)]
    credit_balances: Vec<AgentCreditBalance>,
    /// The response said this account has no account-wide weekly limit
    /// ([`claude_oauth_account_weekly_not_offered`]). Absent in older caches.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    account_weekly_not_offered: bool,
    /// The response said this account has no 5-hour session limit
    /// ([`claude_oauth_account_session_not_offered`]). Absent in older caches.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    account_session_not_offered: bool,
}

/// v4 adds organization identity and requires exact identity on every embedded
/// meter. Released v3 account-only caches cannot prove organization ownership
/// and are discarded rather than relabeled.
const CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION: u16 = 4;
const CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION: u16 = 3;
#[cfg(test)]
static CLAUDE_OAUTH_PROVIDER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// `codex app-server` runs started by this test process: the seam that proves a
/// status read never starts one.
#[cfg(test)]
static CODEX_APP_SERVER_RUNS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Tests that must never reach the provider set this: an attempted request is
/// still counted in `CLAUDE_OAUTH_PROVIDER_CALLS`, then refused locally.
#[cfg(test)]
static CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// Test-only hook run just before the final pre-request expiry check, to
/// simulate time passing (blocking I/O or sleep) inside the collection path.
#[cfg(test)]
static CLAUDE_OAUTH_BEFORE_SEND_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

/// Everything the Claude OAuth usage endpoint yields in one fetch.
#[derive(Debug, Clone, Default)]
struct ClaudeOAuthUsage {
    windows: Vec<AgentQuotaWindow>,
    credit_balances: Vec<AgentCreditBalance>,
    /// No account-wide weekly limit applies to this account (provider-stated),
    /// so a session window alone completes its account windows.
    account_weekly_not_offered: bool,
    /// No 5-hour session limit applies (provider-stated; Max plans since
    /// late 2026), so a weekly window alone completes its account windows.
    account_session_not_offered: bool,
}

/// A collection attempt plus anything the snapshot should say about *why* the
/// endpoint was or was not contacted. Diagnostics travel back to the caller
/// rather than being logged locally because they are the alerting channel:
/// snapshot diagnostics ride the agent-status upload to the backend (see
/// `AgentStatusSnapshot::redacted_for_backend`, which preserves `code` and
/// `message`), so an open breaker is visible server-side without a second
/// telemetry path.
#[derive(Debug)]
struct ClaudeOAuthUsageOutcome {
    result: Result<ClaudeOAuthUsage, String>,
    diagnostics: Vec<AgentStatusDiagnostic>,
}

/// One source scan can now produce several Claude account snapshots while
/// local source health remains one row per source.
pub(crate) struct AgentStatusCollection {
    pub snapshots: Vec<AgentStatusSnapshot>,
    pub source_health_snapshot: AgentStatusSnapshot,
    pub codex_scan_homes: Vec<PathBuf>,
    pub codex_home_bindings: Vec<CodexHomeBinding>,
}

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

/// Hash-only identity observed for an exact Codex transcript home.
pub(crate) struct CodexHomeBinding {
    pub home: PathBuf,
    pub account_identifier_hash: String,
    pub workspace_identifier_hash: String,
    pub auth_modified_at: std::time::SystemTime,
}

/// A validated exact-slot credential. Deliberately implements neither
/// `Debug` nor `Serialize`: the access token must stay in memory and never
/// become diagnostic or persistence material.
struct ResolvedClaudeSlot {
    account: AgentAccountStatus,
    account_identifier_hash: String,
    organization_identifier_hash: String,
    credential: ClaudeOAuthCredential,
}

/// One captured credential after display-safe identity stayed unchanged across
/// an exact-slot auth probe. The token is never debugged, serialized, logged,
/// persisted, or read a second time during the attempt.
struct StableClaudeSlotCredential {
    oauth_account: ClaudeCliOauthAccount,
    credential: ClaudeOAuthCredential,
}

/// Exact-slot credential material read once per attempt. This type
/// deliberately implements neither `Debug` nor `Serialize`; only safe expiry
/// metadata can be copied into authenticated local status.
struct ClaudeOAuthCredential {
    access_token: Option<String>,
    /// Presence only. The refresh token itself is never retained, logged, or
    /// exposed; upkeep needs this bit to distinguish a signed-out credential
    /// from a refreshable expired access token.
    has_refresh_token: bool,
    access_expires_at: Option<String>,
    relogin_required_at: Option<String>,
    /// `Some(true)` when the stored `scopes` list carries `user:inference`,
    /// `Some(false)` when the list lacks it, `None` when no list is stored.
    /// Claude Code itself reports `loggedIn` only for an inference-scoped
    /// token, so this is the same local evidence `claude auth status` used.
    has_inference_scope: Option<bool>,
    /// The stored `scopes` list carries `user:profile`. Claude Code's
    /// `/usage` reads plan usage (and so refreshes the login first) only for
    /// such a login.
    has_profile_scope: bool,
    /// The plan Claude Code stored with the login (`subscriptionType`), the
    /// same field `claude auth status` printed. Display metadata, not a secret.
    subscription_type: Option<String>,
}

/// Seconds before the stored access deadline at which a login no longer counts
/// as usable. Claude Code itself refreshes inside a five-minute window; the
/// daemon never refreshes, so this only stops a usage read with a token that
/// is about to lapse.
const CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS: i64 = 60;

/// What one local read of a Claude login found. `Absent` means there is no
/// stored OAuth login at all (no keychain item and no credentials file, or an
/// item without `claudeAiOauth`). `Unreadable` is every failed or malformed
/// read: callers fail closed on it and never treat it as "signed out".
enum ClaudeCredentialRead {
    Absent,
    Unreadable,
    Present(ClaudeOAuthCredential),
}

impl ClaudeCredentialRead {
    fn into_credential(self) -> Option<ClaudeOAuthCredential> {
        match self {
            Self::Present(credential) => Some(credential),
            Self::Absent | Self::Unreadable => None,
        }
    }

    fn metadata(&self) -> Option<ClaudeOAuthCredentialMetadata> {
        match self {
            Self::Present(credential) => Some(ClaudeOAuthCredentialMetadata {
                cleared_by_cli: credential.cleared_by_cli(),
                access_expires_at: credential.access_expires_at.clone(),
                refresh_token_expires_at: credential.relogin_required_at.clone(),
                has_refresh_token: credential.has_refresh_token,
                has_profile_scope: credential.has_profile_scope,
            }),
            Self::Absent | Self::Unreadable => None,
        }
    }
}

/// Login state derived from local metadata alone (the stored credential's
/// deadlines, token presence and scopes). This replaces `claude auth status`,
/// which read exactly these fields but could refresh, and so sign out, the
/// login it was asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeLocalLoginState {
    /// No stored OAuth login.
    NotSignedIn,
    /// The read failed or the stored item is malformed. Fail closed.
    Unreadable,
    /// Claude Code blanked the login after a rejected refresh.
    SignedOutByCli,
    /// No refresh token, or its absolute deadline passed.
    NeedsLogin,
    /// The access token is usable for more than the expiry margin.
    AccessValid,
    /// The access token lapsed (or lapses within the margin) while the refresh
    /// token is still alive. Only Claude Code may refresh it; Ottto waits.
    RefreshPending,
}

/// Secret-free result of one live local read, handed to the upkeep decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeLiveLogin {
    pub(crate) state: ClaudeLocalLoginState,
    pub(crate) metadata: Option<ClaudeOAuthCredentialMetadata>,
}

impl ClaudeLiveLogin {
    pub(crate) fn unreadable() -> Self {
        Self {
            state: ClaudeLocalLoginState::Unreadable,
            metadata: None,
        }
    }
}

fn claude_local_login_state(
    read: &ClaudeCredentialRead,
    now: OffsetDateTime,
) -> ClaudeLocalLoginState {
    let credential = match read {
        ClaudeCredentialRead::Absent => return ClaudeLocalLoginState::NotSignedIn,
        ClaudeCredentialRead::Unreadable => return ClaudeLocalLoginState::Unreadable,
        ClaudeCredentialRead::Present(credential) => credential,
    };
    if credential.cleared_by_cli() {
        return ClaudeLocalLoginState::SignedOutByCli;
    }
    if !credential.has_refresh_token {
        return ClaudeLocalLoginState::NeedsLogin;
    }
    let parse = |at: Option<&str>| at.and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok());
    if parse(credential.relogin_required_at.as_deref()).is_some_and(|deadline| deadline <= now) {
        return ClaudeLocalLoginState::NeedsLogin;
    }
    let Some(access_expiry) = parse(credential.access_expires_at.as_deref()) else {
        // A refresh token without a readable access deadline: the gate cannot
        // prove a spawn is safe and the status cannot say what holds.
        return ClaudeLocalLoginState::Unreadable;
    };
    if credential.access_token.is_none() || credential.has_inference_scope != Some(true) {
        return ClaudeLocalLoginState::Unreadable;
    }
    if access_expiry > now + TimeDuration::seconds(CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS) {
        ClaudeLocalLoginState::AccessValid
    } else {
        ClaudeLocalLoginState::RefreshPending
    }
}

impl ClaudeOAuthCredential {
    /// The exact shape Claude Code writes after the token endpoint rejects a
    /// refresh (`invalid_grant`): no access token, no refresh token, and an
    /// `expiresAt` of 0. Only an official login or reconnect restores it.
    fn cleared_by_cli(&self) -> bool {
        self.access_token.is_none()
            && !self.has_refresh_token
            && self.access_expires_at.as_deref().is_some_and(|at| {
                OffsetDateTime::parse(at, &Rfc3339).is_ok_and(|expiry| expiry.unix_timestamp() == 0)
            })
    }
}

/// Secret-free projection used by the background upkeep scheduler. Reading it
/// drops the access token immediately and exposes only vendor deadlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeOAuthCredentialMetadata {
    pub(crate) access_expires_at: Option<String>,
    pub(crate) refresh_token_expires_at: Option<String>,
    pub(crate) has_refresh_token: bool,
    /// Claude Code itself signed this credential out: the item is present but
    /// both token strings are empty and `expiresAt` is 0. The CLI writes this
    /// shape when the token endpoint rejects a refresh with `invalid_grant`.
    /// Only an official login or reconnect can restore it.
    pub(crate) cleared_by_cli: bool,
    /// The stored scopes include `user:profile` (no secret).
    pub(crate) has_profile_scope: bool,
}

struct ClaudeSnapshotCandidate {
    slot_id: String,
    slot_class: ClaudeSnapshotSlotClass,
    binding: ClaudeStrongBinding,
    quality: ClaudeSnapshotQuality,
    snapshot: AgentStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClaudeStrongBinding {
    account_identifier_hash: String,
    organization_identifier_hash: String,
}

impl ClaudeStrongBinding {
    fn new(account_identifier_hash: &str, organization_identifier_hash: &str) -> Option<Self> {
        (!account_identifier_hash.is_empty() && !organization_identifier_hash.is_empty()).then(
            || Self {
                account_identifier_hash: account_identifier_hash.to_string(),
                organization_identifier_hash: organization_identifier_hash.to_string(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClaudeSnapshotQuality {
    tier: u8,
    provider_observed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeSnapshotSlotClass {
    Default,
    Registered,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ClaudeSnapshotSelection {
    winning_by_binding: BTreeMap<ClaudeStrongBinding, usize>,
    preferred_anchor_by_binding: BTreeMap<ClaudeStrongBinding, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeSnapshotDisposition {
    Upload,
    ShadowDefault,
    PreserveRegisteredAnchor,
    DuplicateRegistered,
}

fn claude_candidate_is_better(
    candidate: &ClaudeSnapshotCandidate,
    current: &ClaudeSnapshotCandidate,
) -> bool {
    candidate.quality > current.quality
        || (candidate.quality == current.quality
            && match (candidate.slot_class, current.slot_class) {
                (ClaudeSnapshotSlotClass::Registered, ClaudeSnapshotSlotClass::Default) => true,
                (ClaudeSnapshotSlotClass::Default, ClaudeSnapshotSlotClass::Registered) => false,
                _ => candidate.slot_id < current.slot_id,
            })
}

/// Choose the uploading snapshot and the preferred registered anchor for each
/// exact pair.
///
/// The preferred registered anchor follows `canonical_registered_anchors`,
/// which ranks connection health (the shared credential-usability rule) before
/// meter quality. A registered slot that is not the canonical anchor for its
/// pair can neither upload nor become the preferred anchor, so one ranking
/// decides both the canonical label and which slot's limits are used. Without
/// this, an unusable slot showing complete limits (for example valid access
/// but a passed refresh deadline) could win on meter quality and label the
/// working login a duplicate. The default login still competes on meter
/// quality alone; it never changes which registered slot is canonical.
fn select_claude_snapshot_candidates(
    candidates: &[ClaudeSnapshotCandidate],
    canonical_anchors: &BTreeMap<ClaudeStrongBinding, String>,
) -> ClaudeSnapshotSelection {
    let mut selection = ClaudeSnapshotSelection::default();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.slot_class == ClaudeSnapshotSlotClass::Registered
            && canonical_anchors
                .get(&candidate.binding)
                .is_some_and(|canonical| canonical != &candidate.slot_id)
        {
            continue;
        }
        let replace_winner = selection
            .winning_by_binding
            .get(&candidate.binding)
            .map_or(true, |current| {
                claude_candidate_is_better(candidate, &candidates[*current])
            });
        if replace_winner {
            selection
                .winning_by_binding
                .insert(candidate.binding.clone(), index);
        }
        if candidate.slot_class == ClaudeSnapshotSlotClass::Registered {
            let replace_anchor = selection
                .preferred_anchor_by_binding
                .get(&candidate.binding)
                .map_or(true, |current| {
                    claude_candidate_is_better(candidate, &candidates[*current])
                });
            if replace_anchor {
                selection
                    .preferred_anchor_by_binding
                    .insert(candidate.binding.clone(), index);
            }
        }
    }
    selection
}

/// Provider quota responses do not carry account identity. Ottto normally
/// binds them to the exact slot credential that made the request. If the same
/// complete meter payload appears under different strong identities, that
/// binding is not trustworthy: a stale slot identity may be paired with a
/// credential for another account. Prefer one durable registered slot over the
/// mutable default login; if several registered slots disagree, hide them all.
fn claude_cross_binding_meter_collisions(
    candidates: &[ClaudeSnapshotCandidate],
) -> BTreeSet<String> {
    let mut by_fingerprint = BTreeMap::<String, Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let Some(fingerprint) = claude_provider_meter_fingerprint(candidate) else {
            continue;
        };
        by_fingerprint.entry(fingerprint).or_default().push(index);
    }

    let mut quarantined = BTreeSet::new();
    for group in by_fingerprint.values() {
        let bindings = group
            .iter()
            .map(|index| &candidates[*index].binding)
            .collect::<BTreeSet<_>>();
        if bindings.len() < 2 {
            continue;
        }
        let registered = group
            .iter()
            .filter(|index| candidates[**index].slot_class == ClaudeSnapshotSlotClass::Registered)
            .copied()
            .collect::<Vec<_>>();
        if registered.len() == 1 {
            let trusted = registered[0];
            for index in group {
                if *index != trusted {
                    quarantined.insert(candidates[*index].slot_id.clone());
                }
            }
        } else {
            for index in group {
                quarantined.insert(candidates[*index].slot_id.clone());
            }
        }
    }
    quarantined
}

fn claude_provider_meter_fingerprint(candidate: &ClaudeSnapshotCandidate) -> Option<String> {
    if candidate.quality.tier != 4 {
        return None;
    }
    claude_provider_meter_payload_fingerprint(
        &candidate.snapshot.quota_windows,
        &candidate.snapshot.credit_balances,
    )
}

fn claude_provider_meter_payload_fingerprint(
    quota_windows: &[AgentQuotaWindow],
    credit_balances: &[AgentCreditBalance],
) -> Option<String> {
    if quota_windows.is_empty() && credit_balances.is_empty() {
        return None;
    }
    let mut windows = quota_windows.to_vec();
    let mut window_rows = Vec::with_capacity(windows.len());
    for window in &mut windows {
        window.account_label = None;
        window.account_identifier_hash = None;
        window.organization_identifier_hash = None;
        window.observed_at = None;
        window.freshness = AgentQuotaWindowFreshness::Fresh;
        window_rows.push(serde_json::to_string(window).ok()?);
    }
    window_rows.sort();

    let mut balances = credit_balances.to_vec();
    let mut balance_rows = Vec::with_capacity(balances.len());
    for balance in &mut balances {
        balance.account_label = None;
        balance.account_identifier_hash = None;
        balance.organization_identifier_hash = None;
        balance.updated_at = None;
        // Provider read clocks only: a re-sent cached section keeps its original
        // read time, so two slots carrying the same meter differ only here.
        balance.observed_at = None;
        balance.grants_observed_at = None;
        balance.freshness = AgentQuotaWindowFreshness::Fresh;
        balance_rows.push(serde_json::to_string(balance).ok()?);
    }
    balance_rows.sort();
    serde_json::to_string(&(window_rows, balance_rows)).ok()
}

/// A retained stale meter bundle can outlive the collection cycle that first
/// paired it with the wrong account. Compare it with current complete provider
/// readings and fail closed when the exact same identity-free payload now
/// belongs to another strong account+organization binding.
fn claude_stale_cross_binding_meter_collisions(
    candidates: &[ClaudeSnapshotCandidate],
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeSet<String> {
    let current = candidates
        .iter()
        .filter_map(|candidate| {
            claude_provider_meter_fingerprint(candidate)
                .map(|fingerprint| (fingerprint, &candidate.binding))
        })
        .collect::<Vec<_>>();
    let mut quarantined = BTreeSet::new();
    for (slot_id, status) in slot_states {
        let Some(snapshot) = status
            .quota_snapshot
            .as_ref()
            .filter(|snapshot| snapshot.state == ClaudeConfigSlotQuotaSnapshotStateV1::Stale)
        else {
            continue;
        };
        let Some(binding) = status
            .account_identifier_hash
            .as_deref()
            .zip(status.organization_identifier_hash.as_deref())
            .and_then(|(account, organization)| ClaudeStrongBinding::new(account, organization))
        else {
            continue;
        };
        let Some(fingerprint) = claude_provider_meter_payload_fingerprint(
            &snapshot.quota_windows,
            &snapshot.credit_balances,
        ) else {
            continue;
        };
        if current
            .iter()
            .any(|(current_fingerprint, current_binding)| {
                current_fingerprint.as_str() == fingerprint.as_str() && *current_binding != &binding
            })
        {
            quarantined.insert(slot_id.clone());
        }
    }
    quarantined
}

fn quarantine_claude_cross_account_meters(status: &mut ClaudeConfigSlotCollectionStatusV1) {
    status.state = ClaudeConfigSlotCollectionStateV1::IdentityMismatch;
    status.last_full_quota_read_at = None;
    status.has_account_windows = false;
    status.has_scoped_limits = false;
    status.has_credit_balances = false;
    status.quota_snapshot = None;
    status
        .diagnostics
        .retain(|diagnostic| diagnostic.code != ClaudeConfigSlotDiagnosticCodeV1::IdentityMismatch);
    status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
        code: ClaudeConfigSlotDiagnosticCodeV1::IdentityMismatch,
        message: "Limits matched another account and were hidden. Reconnect this Claude login."
            .to_string(),
    });
}

fn claude_snapshot_candidate_disposition(
    index: usize,
    candidate: &ClaudeSnapshotCandidate,
    selection: &ClaudeSnapshotSelection,
) -> ClaudeSnapshotDisposition {
    if selection.winning_by_binding.get(&candidate.binding) == Some(&index) {
        return ClaudeSnapshotDisposition::Upload;
    }
    match candidate.slot_class {
        ClaudeSnapshotSlotClass::Default
            if selection
                .preferred_anchor_by_binding
                .contains_key(&candidate.binding) =>
        {
            ClaudeSnapshotDisposition::ShadowDefault
        }
        ClaudeSnapshotSlotClass::Registered
            if selection
                .preferred_anchor_by_binding
                .get(&candidate.binding)
                != Some(&index) =>
        {
            ClaudeSnapshotDisposition::DuplicateRegistered
        }
        ClaudeSnapshotSlotClass::Registered => ClaudeSnapshotDisposition::PreserveRegisteredAnchor,
        ClaudeSnapshotSlotClass::Default => ClaudeSnapshotDisposition::Upload,
    }
}

fn claude_slot_projection_quality(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> ClaudeSnapshotQuality {
    let complete = status.has_account_windows && status.has_scoped_limits;
    let fresh = status.state == ClaudeConfigSlotCollectionStateV1::Fresh;
    let tier = match (fresh, complete) {
        (true, true) => 4,
        (true, false) => 3,
        (false, true) => 2,
        (false, false) => 1,
    };
    let provider_observed_at = status
        .quota_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.observed_at.clone())
        .or_else(|| status.last_full_quota_read_at.clone())
        .or_else(|| status.observed_at.clone())
        .unwrap_or_default();
    ClaudeSnapshotQuality {
        tier,
        provider_observed_at,
    }
}

/// Whether a saved slot still holds a usable connection, decided from the
/// credential evidence rather than the collection enum alone.
///
/// Usable means the saved access deadline is still in the future, the
/// refresh deadline (when known) has not passed, and the last upkeep outcome
/// is not a sign-in requirement. Several enums are shared by very different
/// facts: `probe_failed` is both a transient provider/probe failure on a
/// valid credential and the presentation of a failed refresh (timed out,
/// missing binary, expiry unchanged) on an expired one. An expired credential
/// whose refresh failed is dead whatever enum presents it, and a slot blocked
/// on a signed-out, unreadable or unproven credential is dead however complete
/// its older limits are. A legacy saved state without an access deadline is
/// usable only when it was just collected fresh.
pub(crate) fn claude_slot_connection_usable(
    status: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) -> bool {
    if matches!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::NeedsLogin
            | ClaudeConfigSlotCollectionStateV1::RefreshDue
            | ClaudeConfigSlotCollectionStateV1::StaleAccessToken
            | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
            | ClaudeConfigSlotCollectionStateV1::IdentityUnknown
            | ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    ) || status
        .upkeep
        .as_ref()
        .is_some_and(|upkeep| upkeep.result == ClaudeConfigSlotUpkeepResultV1::NeedsLogin)
        || status
            .relogin_required_at
            .as_deref()
            .and_then(|deadline| OffsetDateTime::parse(deadline, &Rfc3339).ok())
            .is_some_and(|deadline| deadline <= now)
    {
        return false;
    }
    match status
        .access_expires_at
        .as_deref()
        .map(|deadline| OffsetDateTime::parse(deadline, &Rfc3339).ok())
    {
        Some(Some(deadline)) => deadline > now,
        Some(None) => false,
        None => status.state == ClaudeConfigSlotCollectionStateV1::Fresh,
    }
}

/// Canonical-anchor rank: connection health first, then meter quality.
///
/// A dead slot's historical complete limits must never keep the canonical
/// anchor away from a working connection for the same account (for example a
/// fresh login admitted while the provider is briefly unavailable). A slot
/// already labelled `DuplicateAccount` by an earlier selection ranks last, so
/// readers of persisted state agree with the collector's own choice.
fn claude_slot_anchor_rank(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> (u8, ClaudeSnapshotQuality) {
    let health = if status.state == ClaudeConfigSlotCollectionStateV1::DuplicateAccount {
        0
    } else if claude_slot_connection_usable(status, OffsetDateTime::now_utc()) {
        2
    } else {
        1
    };
    (health, claude_slot_projection_quality(status))
}

fn canonical_registered_anchors(
    registered_slot_ids: impl IntoIterator<Item = String>,
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeMap<ClaudeStrongBinding, String> {
    let mut canonical = BTreeMap::<ClaudeStrongBinding, String>::new();
    for slot_id in registered_slot_ids {
        let Some(status) = slot_states.get(&slot_id) else {
            continue;
        };
        let Some(binding) = status
            .account_identifier_hash
            .as_deref()
            .and_then(|account| {
                ClaudeStrongBinding::new(account, status.organization_identifier_hash.as_deref()?)
            })
        else {
            continue;
        };
        let replace = canonical.get(&binding).map_or(true, |current_slot_id| {
            let current = slot_states
                .get(current_slot_id)
                .expect("canonical registered slot remains present");
            let candidate_rank = claude_slot_anchor_rank(status);
            let current_rank = claude_slot_anchor_rank(current);
            candidate_rank > current_rank
                || (candidate_rank == current_rank && slot_id < *current_slot_id)
        });
        if replace {
            canonical.insert(binding, slot_id);
        }
    }
    canonical
}

fn canonical_anchor_health(
    canonical: &BTreeMap<ClaudeStrongBinding, String>,
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeMap<ClaudeStrongBinding, Option<ClaudeAccountAnchorHealthV1>> {
    canonical
        .iter()
        .filter_map(|(binding, slot_id)| {
            Some((
                binding.clone(),
                projected_claude_anchor_health(slot_states.get(slot_id)?),
            ))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeSlotProbeFailure {
    IdentityUnknown,
    CredentialUnavailable,
    IdentityMismatch,
    ConcurrentMutation,
    /// The stored token's owner is not proven to be an account Ottto knows:
    /// the plan families of the credential and `.claude.json` contradict, or
    /// the default home's owner check failed or found an unknown account.
    /// Unlike `ConcurrentMutation` this is not a race; it holds until the
    /// owner is proven or the home signs in again.
    OwnerUnproven,
    /// The slot's stored login could not be read, or is malformed (for
    /// example a refresh token without an access deadline). Fail closed:
    /// transient, retried on the next pass, and not evidence that the login
    /// is gone.
    ProbeFailed,
    /// Claude Code cleared this slot's tokens after its refresh was rejected
    /// (`invalid_grant`). Detected from the stored credential alone, without
    /// spawning the CLI; only a reconnect or official login restores it.
    SignedOutByCli,
}

impl ClaudeSlotProbeFailure {
    fn diagnostic_code(self) -> &'static str {
        match self {
            Self::IdentityUnknown => "claude_slot_identity_unknown",
            Self::CredentialUnavailable => "claude_slot_credential_unavailable",
            Self::IdentityMismatch => "claude_slot_identity_mismatch",
            Self::ConcurrentMutation => "claude_slot_concurrent_mutation",
            Self::OwnerUnproven => "claude_login_owner_unproven",
            Self::ProbeFailed => "claude_slot_probe_failed",
            Self::SignedOutByCli => "claude_slot_signed_out_by_cli",
        }
    }

    fn status(&self, observed_at: &str) -> ClaudeConfigSlotCollectionStatusV1 {
        let (state, code, message) = match self {
            Self::IdentityUnknown => (
                ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
                ClaudeConfigSlotDiagnosticCodeV1::IdentityUnknown,
                "This registered Claude slot has no complete strong local account and organization identity.",
            ),
            Self::CredentialUnavailable => (
                ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
                ClaudeConfigSlotDiagnosticCodeV1::CredentialUnavailable,
                "This registered Claude slot has no readable valid Claude Code credential.",
            ),
            Self::IdentityMismatch => (
                ClaudeConfigSlotCollectionStateV1::IdentityMismatch,
                ClaudeConfigSlotDiagnosticCodeV1::IdentityMismatch,
                "This registered Claude slot's credential status does not match its local account identity.",
            ),
            Self::ConcurrentMutation => (
                ClaudeConfigSlotCollectionStateV1::ConcurrentMutation,
                ClaudeConfigSlotDiagnosticCodeV1::ConcurrentMutation,
                "This registered Claude slot changed during verification; collection will retry from a stable state.",
            ),
            // No identity, as for any unknown owner; never a race.
            Self::OwnerUnproven => (
                ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
                ClaudeConfigSlotDiagnosticCodeV1::IdentityUnknown,
                "Ottto could not prove which account this Claude login belongs to; sign in again in this account's own Claude folder.",
            ),
            Self::ProbeFailed => (
                ClaudeConfigSlotCollectionStateV1::ProbeFailed,
                ClaudeConfigSlotDiagnosticCodeV1::ProbeFailed,
                "Claude Code's saved login for this slot could not be read; collection will retry.",
            ),
            Self::SignedOutByCli => (
                ClaudeConfigSlotCollectionStateV1::NeedsLogin,
                ClaudeConfigSlotDiagnosticCodeV1::NeedsLogin,
                "Claude Code signed this connection out after its sign-in was rejected; reconnect to resume.",
            ),
        };
        ClaudeConfigSlotCollectionStatusV1 {
            state,
            observed_at: Some(observed_at.to_string()),
            diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
                code,
                message: message.to_string(),
            }],
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedClaudeSlotCollectionStateV1 {
    schema_version: u16,
    slots: BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    #[serde(default)]
    unresolved_accounts: Vec<ClaudeUnresolvedAccountDescriptorV1>,
    #[serde(default)]
    anchor_transitions: Vec<ottto_protocol::ClaudeAccountAnchorTransitionV1>,
}

struct ClaudeSlotCollectionStateGuard {
    _process: std::sync::MutexGuard<'static, ()>,
    file: Option<File>,
}

struct ClaudeOAuthCollectionAttemptGuard {
    _process: std::sync::MutexGuard<'static, ()>,
    file: File,
}

impl Drop for ClaudeOAuthCollectionAttemptGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

impl Drop for ClaudeSlotCollectionStateGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if let Some(file) = &self.file {
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            }
        }
    }
}

/// The failure classes that count toward opening the breaker. Everything else
/// (transport errors, 5xx, a single 429 already covered by retry-after) is
/// transient and deliberately does not accumulate: the breaker exists to stop
/// calling when the *endpoint's answer* says stop, not when the user's Wi-Fi
/// drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeOAuthUsageFailure {
    /// 401/403 - the OAuth token is rejected or lacks the scope.
    AuthRejected,
    /// A 200 body we cannot read, a 200 body with none of the expected quota
    /// fields, or a 404/410 saying the endpoint no longer exists in this shape.
    ResponseShape,
    /// 429 that keeps coming back after the retry-after backoff.
    RateLimited,
}

impl ClaudeOAuthUsageFailure {
    fn code(self) -> &'static str {
        match self {
            Self::AuthRejected => "auth_rejected",
            Self::ResponseShape => "response_shape_changed",
            Self::RateLimited => "rate_limited",
        }
    }

    fn threshold(self) -> u32 {
        match self {
            Self::AuthRejected => CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
            Self::ResponseShape => CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD,
            Self::RateLimited => CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD,
        }
    }
}

/// Persisted breaker state for the Claude OAuth usage read.
///
/// Lives beside the usage cache in the support dir and follows the same
/// account-keying rule: counters and an open verdict belong to the account
/// whose credential produced them, so an account switch starts clean rather
/// than inheriting the previous account's rejections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ClaudeOAuthUsageBreaker {
    schema_version: u16,
    #[serde(default)]
    account_identifier_hash: String,
    #[serde(default)]
    organization_identifier_hash: String,
    /// Fingerprint of the call's own configuration (endpoint, headers, honest
    /// User-Agent, sentinel state). Changing any of them means the thing that
    /// was failing is not the thing we would call next, so the breaker resets.
    #[serde(default)]
    config_fingerprint: String,
    #[serde(default)]
    auth_failures: u32,
    #[serde(default)]
    shape_failures: u32,
    #[serde(default)]
    rate_limit_failures: u32,
    #[serde(default)]
    opened_at_epoch_seconds: u64,
    /// Cool-down expiry. `0` means the breaker has never opened; the breaker is
    /// open while `now < reopen_after_epoch_seconds`.
    #[serde(default)]
    reopen_after_epoch_seconds: u64,
    /// Which failure class opened it, for the diagnostic message.
    #[serde(default)]
    opened_by: String,
    /// Per-caller 401/403 accounting, keyed by
    /// `ClaudeOAuthUsageCaller::breaker_key`. An auth rejection is a statement
    /// about one credential, so the default login and a registered slot that
    /// read the same account never add to each other's streak or backoff.
    /// Additive: older daemons ignore it, and `auth_failures` above remains the
    /// unattributed streak written by daemons from before caller attribution.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    auth_callers: BTreeMap<String, ClaudeOAuthUsageCallerAuthState>,
    /// The most recent 401/403 for this account from any caller. Secret-free:
    /// caller key, HTTP status, and local time only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_auth_failure: Option<ClaudeOAuthUsageAuthFailureRecord>,
}

/// One caller's consecutive auth rejections and its own backoff.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ClaudeOAuthUsageCallerAuthState {
    #[serde(default)]
    consecutive_failures: u32,
    /// HTTP status of the latest rejection (401 or 403).
    #[serde(default)]
    last_status: u16,
    #[serde(default)]
    last_failure_at_epoch_seconds: u64,
    /// This caller is not sent to the provider while `now` is before this.
    #[serde(default)]
    backoff_until_epoch_seconds: u64,
    /// Access-token expiry metadata of the credential that was rejected (never
    /// the token). When the caller's current credential reports a different
    /// expiry, the credential was rotated: the hold is released and the streak
    /// starts over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_expires_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ClaudeOAuthUsageAuthFailureRecord {
    #[serde(default)]
    caller: String,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    at_epoch_seconds: u64,
}

const CLAUDE_OAUTH_USAGE_DEFAULT_CALLER_KEY: &str = "default";
const CLAUDE_OAUTH_USAGE_SLOT_CALLER_KEY_PREFIX: &str = "slot-sha256:";
/// Raw-slot-id key form written only by an unreleased build; migrated on read.
const CLAUDE_OAUTH_USAGE_RAW_SLOT_CALLER_KEY_PREFIX: &str = "slot:";

fn claude_oauth_usage_slot_caller_key(slot_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-caller:v1\0");
    hasher.update(slot_id.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!(
        "{CLAUDE_OAUTH_USAGE_SLOT_CALLER_KEY_PREFIX}{}",
        &digest[..32]
    )
}

/// The opaque form of a persisted caller key; raw `slot:<id>` keys are hashed.
fn claude_oauth_usage_opaque_caller_key(key: &str) -> String {
    match key.strip_prefix(CLAUDE_OAUTH_USAGE_RAW_SLOT_CALLER_KEY_PREFIX) {
        Some(slot_id) => claude_oauth_usage_slot_caller_key(slot_id),
        None => key.to_string(),
    }
}

/// Whether the caller's current credential is provably not the one whose
/// rejection this state records (its access expiry changed).
fn claude_oauth_usage_caller_credential_rotated(
    state: &ClaudeOAuthUsageCallerAuthState,
    credential_expires_at: Option<&str>,
) -> bool {
    matches!(
        (state.credential_expires_at.as_deref(), credential_expires_at),
        (Some(recorded), Some(current)) if recorded != current
    )
}

/// Whether a caller's streak is older than the cool-down and so no longer
/// counts toward that caller's threshold.
fn claude_oauth_usage_caller_streak_is_stale(
    state: &ClaudeOAuthUsageCallerAuthState,
    now: u64,
) -> bool {
    state.last_failure_at_epoch_seconds > 0
        && now
            >= state
                .last_failure_at_epoch_seconds
                .saturating_add(CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS)
}

impl ClaudeOAuthUsageBreaker {
    /// Rewrite any raw slot-id caller keys into their opaque form. Returns
    /// whether anything changed, so the caller can persist the migration.
    fn migrate_raw_caller_keys(&mut self) -> bool {
        let raw = |key: &str| key.starts_with(CLAUDE_OAUTH_USAGE_RAW_SLOT_CALLER_KEY_PREFIX);
        let mut changed = false;
        if self.auth_callers.keys().any(|key| raw(key)) {
            let callers = std::mem::take(&mut self.auth_callers);
            for (key, state) in callers {
                let key = claude_oauth_usage_opaque_caller_key(&key);
                match self.auth_callers.get(&key) {
                    Some(existing)
                        if existing.last_failure_at_epoch_seconds
                            >= state.last_failure_at_epoch_seconds => {}
                    _ => {
                        self.auth_callers.insert(key, state);
                    }
                }
            }
            changed = true;
        }
        if let Some(record) = self.last_auth_failure.as_mut() {
            if raw(&record.caller) {
                record.caller = claude_oauth_usage_opaque_caller_key(&record.caller);
                changed = true;
            }
        }
        changed
    }

    /// Nothing left but identity and history: the file can be removed.
    fn holds_no_state(&self) -> bool {
        self.auth_failures == 0
            && self.shape_failures == 0
            && self.rate_limit_failures == 0
            && self.opened_at_epoch_seconds == 0
            && self.reopen_after_epoch_seconds == 0
            && self.opened_by.is_empty()
            && self.auth_callers.is_empty()
    }
}

/// Parse a breaker file, migrating raw slot-id caller keys in place.
fn read_claude_oauth_usage_breaker_file_migrating(path: &Path) -> Option<ClaudeOAuthUsageBreaker> {
    let body = fs::read_to_string(path).ok()?;
    let mut breaker: ClaudeOAuthUsageBreaker = serde_json::from_str(&body).ok()?;
    if breaker.migrate_raw_caller_keys() {
        if let Ok(body) = serde_json::to_vec_pretty(&breaker) {
            let _ = write_owner_only_file_atomic(path, &body);
        }
    }
    Some(breaker)
}

/// Which local credential is asking the Claude OAuth usage endpoint.
///
/// The default `~/.claude` login (rotated by Claude Code itself) and a
/// registered slot's own login can both belong to one account. They share the
/// account's cache, refresh gate, and endpoint-level breaker classes, but auth
/// rejections and their backoff are recorded per caller.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaudeOAuthUsageCaller {
    /// The default `~/.claude` login. Mirrors the legacy root cache/breaker.
    Default,
    /// The default login for an account that a registered managed slot has
    /// proved it reads. The slot's credential is the single provider caller;
    /// the default path serves the shared account cache only.
    DefaultDeferredToSlot,
    /// A registered slot, by its local slot id.
    RegisteredSlot(String),
}

impl ClaudeOAuthUsageCaller {
    fn mirrors_legacy_default(&self) -> bool {
        matches!(self, Self::Default | Self::DefaultDeferredToSlot)
    }

    fn may_call_provider(&self) -> bool {
        !matches!(self, Self::DefaultDeferredToSlot)
    }

    /// Persisted key. The slot id stays in memory only: on disk a slot is a
    /// domain-separated opaque hash of its id.
    fn breaker_key(&self) -> String {
        match self {
            Self::Default | Self::DefaultDeferredToSlot => {
                CLAUDE_OAUTH_USAGE_DEFAULT_CALLER_KEY.to_string()
            }
            Self::RegisteredSlot(slot_id) => claude_oauth_usage_slot_caller_key(slot_id),
        }
    }

    /// Words safe to upload: never the slot id or a path.
    fn credential_kind(&self) -> &'static str {
        match self {
            Self::Default | Self::DefaultDeferredToSlot => "default Claude Code login",
            Self::RegisteredSlot(_) => "registered account slot",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ClaudeDesktopConfig {
    #[serde(rename = "lastKnownAccountUuid")]
    last_known_account_uuid: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ClaudeDesktopCodeSessionMetadata {
    #[serde(rename = "cliSessionId")]
    cli_session_id: Option<String>,
    #[serde(rename = "lastActivityAt")]
    last_activity_at: Option<Value>,
    #[serde(rename = "createdAt")]
    created_at: Option<Value>,
    /// Any `importedFrom` tag, null or malformed included, means the session
    /// was copied into this folder: not native evidence for its folder pair.
    /// The tag's value is never kept.
    #[serde(
        rename = "importedFrom",
        default,
        deserialize_with = "deserialize_field_present"
    )]
    imported: bool,
}

fn deserialize_field_present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer).map(|_| true)
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ClaudeDesktopAgentModeSessionMetadata {
    #[serde(rename = "cliSessionId")]
    cli_session_id: Option<String>,
    #[serde(rename = "lastActivityAt")]
    last_activity_at: Option<Value>,
    #[serde(rename = "createdAt")]
    created_at: Option<Value>,
    #[serde(rename = "emailAddress")]
    email_address: Option<String>,
    #[serde(rename = "accountEmail")]
    account_email: Option<String>,
    email: Option<String>,
    #[serde(rename = "accountName")]
    account_name: Option<String>,
    #[serde(rename = "organizationName")]
    organization_name: Option<String>,
    #[serde(rename = "workspaceName")]
    workspace_name: Option<String>,
    #[serde(rename = "teamName")]
    team_name: Option<String>,
    #[serde(rename = "subscriptionType")]
    subscription_type: Option<String>,
    #[serde(rename = "planType")]
    plan_type: Option<String>,
    plan: Option<String>,
}

type ClaudeDesktopMetadataEntries<T> = BTreeMap<PathBuf, (PathStamp, Option<T>)>;

/// Parsed Claude Desktop session metadata by file, kept in memory between
/// status passes so a file whose stamp is unchanged is not read again. Never
/// persisted or uploaded.
#[derive(Default)]
pub(crate) struct ClaudeDesktopMetadataCache {
    code: ClaudeDesktopMetadataEntries<ClaudeDesktopCodeSessionMetadata>,
    agent_mode: ClaudeDesktopMetadataEntries<ClaudeDesktopAgentModeSessionMetadata>,
}

#[derive(Debug, Clone, Default)]
struct ClaudeDesktopProfileBuilder {
    account_uuid: String,
    account_label: Option<String>,
    account_name: Option<String>,
    organization_label: Option<String>,
    plan_type: Option<String>,
    organization_uuids: BTreeSet<String>,
    current_organization_uuid: Option<String>,
    latest_activity_epoch_seconds: Option<i64>,
    latest_session_id: Option<String>,
    session_activity_by_id: BTreeMap<String, Option<i64>>,
    code_session_count: usize,
    agent_mode_session_count: usize,
}

/// One Desktop `<account>/<organization>` folder pair, across the Code and
/// agent-mode stores. Every folder takes part in duplicate-session ownership;
/// only an `exact` one (both names canonical UUIDs) can become a pair. Labels
/// and plan come only from the same folder pair, never from the account's
/// other folders.
#[derive(Debug, Clone, Default)]
struct ClaudeDesktopPairBuilder {
    exact: bool,
    account_label: Option<String>,
    account_name: Option<String>,
    organization_label: Option<String>,
    plan_type: Option<String>,
    /// Every session seen in the folder pair, imported copies and agent-mode
    /// sessions included: input to the duplicate-session ownership rule.
    session_activity_by_id: BTreeMap<String, Option<i64>>,
    /// Native Code sessions (no `importedFrom`) whose metadata carries a
    /// parseable activity time. Only these qualify the pair.
    native_activity_by_id: BTreeMap<String, i64>,
}

/// One Desktop folder pair: the canonical UUIDs where the names are UUIDs,
/// otherwise the names as found (a non-UUID name never equals a canonical one).
type ClaudeDesktopPairKey = (String, String);

fn claude_desktop_pair_builder<'a>(
    pair_builders: &'a mut BTreeMap<ClaudeDesktopPairKey, ClaudeDesktopPairBuilder>,
    account: &str,
    organization: &str,
) -> &'a mut ClaudeDesktopPairBuilder {
    let canonical_account = crate::claude_local_otel::canonical_uuid(account);
    let canonical_organization = crate::claude_local_otel::canonical_uuid(organization);
    let exact = canonical_account.is_some() && canonical_organization.is_some();
    pair_builders
        .entry((
            canonical_account.unwrap_or_else(|| account.to_string()),
            canonical_organization.unwrap_or_else(|| organization.to_string()),
        ))
        .or_insert_with(|| ClaudeDesktopPairBuilder {
            exact,
            ..ClaudeDesktopPairBuilder::default()
        })
}

/// One Desktop metadata scan per status pass: today's per-account observations
/// for the default snapshot, and the qualified exact folder pairs.
struct ClaudeDesktopScan {
    observations: Vec<AgentStatusPlanObservation>,
    pairs: ClaudeDesktopPairs,
}

/// Qualified exact Desktop folder pairs, newest native activity first, and the
/// duplicate sessions they own, newest first. Nothing here is uploaded until
/// `claude_desktop_pairs_snapshot` subtracts the pairs another upload covers.
#[derive(Debug, Clone, Default)]
struct ClaudeDesktopPairs {
    pairs: Vec<ClaudeDesktopPairObservation>,
    duplicate_sessions: Vec<ClaudeDesktopPairObservation>,
}

#[derive(Debug, Clone)]
struct ClaudeDesktopPairObservation {
    binding: ClaudeStrongBinding,
    observation: AgentStatusPlanObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PiRouteClassification {
    pub model_provider: Option<String>,
    pub billing_provider: Option<String>,
    pub billing_channel: Option<String>,
    pub auth_mode: Option<String>,
    pub gateway_provider: Option<String>,
    pub subscription_product: Option<String>,
    pub source_category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PiModelRoute {
    pub provider: String,
    pub model: String,
    pub thinking_level: Option<String>,
    pub classification: PiRouteClassification,
}

impl PiModelRoute {
    fn new(provider: &str, model: &str, thinking_level: Option<&str>) -> Option<Self> {
        let provider = provider.trim();
        let model = model.trim();
        if provider.is_empty() || !looks_like_safe_model_id(model) {
            return None;
        }
        Some(Self {
            provider: provider.to_string(),
            model: model.to_string(),
            thinking_level: thinking_level
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            classification: pi_route_classification(provider, model),
        })
    }
}

pub fn collect_agent_status(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    collect_agent_status_collection(source, captured_at, expires_at).source_health_snapshot
}

pub(crate) fn collect_agent_status_collection(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
) -> AgentStatusCollection {
    collect_agent_status_collection_reusing(
        source,
        captured_at,
        expires_at,
        &mut ClaudeDesktopMetadataCache::default(),
    )
}

/// [`collect_agent_status_collection`] for a caller that keeps Claude Desktop
/// session metadata between its passes.
pub(crate) fn collect_agent_status_collection_reusing(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
    desktop_metadata: &mut ClaudeDesktopMetadataCache,
) -> AgentStatusCollection {
    match source {
        SourceKind::Codex => collect_codex_status_snapshots(captured_at, expires_at),
        SourceKind::ClaudeCode => {
            collect_claude_status_snapshots(captured_at, expires_at, desktop_metadata)
        }
        SourceKind::Pi => {
            single_agent_status_collection(collect_pi_status(captured_at, expires_at))
        }
    }
}

fn single_agent_status_collection(snapshot: AgentStatusSnapshot) -> AgentStatusCollection {
    AgentStatusCollection {
        snapshots: vec![snapshot.clone()],
        source_health_snapshot: snapshot,
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    }
}

fn collect_codex_status_snapshots(
    captured_at: String,
    expires_at: String,
) -> AgentStatusCollection {
    let settings = FileCodexAccountSlotSettingsStore::default()
        .load()
        .unwrap_or_else(|_| empty_codex_accounts_status());
    let (mut status, mut candidates) =
        collect_codex_slot_candidates(settings, &captured_at, &expires_at);
    canonicalize_codex_candidates(&mut candidates);
    apply_codex_candidate_statuses(&mut status, &candidates);

    let mut codex_scan_homes: Vec<PathBuf> = candidates
        .iter()
        .map(|candidate| candidate.slot.home.clone())
        .collect();
    let mut codex_home_bindings: Vec<CodexHomeBinding> = candidates
        .iter()
        .filter_map(|candidate| {
            let (account_identifier_hash, workspace_identifier_hash) =
                candidate.binding.as_ref()?;
            Some(CodexHomeBinding {
                home: candidate.slot.home.clone(),
                account_identifier_hash: account_identifier_hash.clone(),
                workspace_identifier_hash: workspace_identifier_hash.clone(),
                auth_modified_at: candidate.auth_modified_at?,
            })
        })
        .collect();
    let mut process_bindings: BTreeMap<PathBuf, Option<(String, String, std::time::SystemTime)>> =
        codex_home_bindings
            .iter()
            .map(|binding| {
                (
                    binding.home.clone(),
                    Some((
                        binding.account_identifier_hash.clone(),
                        binding.workspace_identifier_hash.clone(),
                        binding.auth_modified_at,
                    )),
                )
            })
            .collect();
    let running_homes = crate::codex_process_homes::running_codex_homes();
    // A running Codex process holding a rollout in a home is the clearest
    // evidence that the home is in use; the quota schedule reads it often.
    codex_saved_quota::note_running_homes(
        running_homes
            .iter()
            .map(|process| process.auth_home.as_path()),
        current_unix_seconds(),
    );
    for process in running_homes {
        // The process holds a rollout in this exact home. Do not publish a
        // current status row for an unregistered home: it can contain labels.
        let process_binding = process_bindings
            .entry(process.auth_home.clone())
            .or_insert_with(|| {
                let candidate = collect_codex_home_candidate(
                    CodexHomeSlot {
                        slot_id: "process_home".to_string(),
                        ownership: CodexAccountSlotOwnershipV1::Managed,
                        home: process.auth_home.clone(),
                        registered_binding: None,
                    },
                    &captured_at,
                    &expires_at,
                    CodexQuotaRead::Saved,
                );
                candidate
                    .binding
                    .zip(candidate.auth_modified_at)
                    .map(|((account, workspace), modified)| (account, workspace, modified))
            })
            .clone();
        if !codex_scan_homes.contains(&process.auth_home) {
            codex_scan_homes.push(process.auth_home.clone());
        }
        if let Some((account_identifier_hash, workspace_identifier_hash, modified)) =
            &process_binding
        {
            let binding = CodexHomeBinding {
                home: process.auth_home,
                account_identifier_hash: account_identifier_hash.clone(),
                workspace_identifier_hash: workspace_identifier_hash.clone(),
                auth_modified_at: *modified,
            };
            if !codex_home_bindings.iter().any(|existing| {
                existing.home == binding.home
                    && existing.account_identifier_hash == binding.account_identifier_hash
                    && existing.workspace_identifier_hash == binding.workspace_identifier_hash
            }) {
                codex_home_bindings.push(binding);
            }
        }
    }

    CODEX_CLI_META
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain_listed(&codex_scan_homes.iter().cloned().collect());

    let mut snapshots = Vec::new();
    let mut winning_by_binding = BTreeMap::<(String, String), usize>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let Some(binding) = candidate.binding.clone() else {
            continue;
        };
        let replace = winning_by_binding.get(&binding).map_or(true, |current| {
            codex_candidate_is_better(candidate, &candidates[*current])
        });
        if replace {
            winning_by_binding.insert(binding, index);
        }
    }
    for index in winning_by_binding.into_values() {
        snapshots.push(candidates[index].snapshot.clone());
    }
    append_failed_default_codex_snapshot(&mut snapshots, &candidates);
    append_configured_codex_unavailable_snapshots(
        &mut snapshots,
        &candidates,
        &captured_at,
        &expires_at,
    );

    let source_health_snapshot =
        codex_source_health_snapshot(&candidates, &captured_at, &expires_at);
    if snapshots.is_empty() {
        snapshots.push(source_health_snapshot.clone());
    }
    AgentStatusCollection {
        snapshots,
        source_health_snapshot,
        codex_scan_homes,
        codex_home_bindings,
    }
}

fn append_configured_codex_unavailable_snapshots(
    snapshots: &mut Vec<AgentStatusSnapshot>,
    candidates: &[CodexSlotCandidate],
    captured_at: &str,
    expires_at: &str,
) {
    let mut represented = snapshots
        .iter()
        .filter_map(|snapshot| snapshot.account.as_ref())
        .filter_map(|account| {
            account
                .account_identifier_hash
                .clone()
                .zip(account.organization_identifier_hash.clone())
        })
        .collect::<BTreeSet<_>>();
    for candidate in candidates {
        if candidate.slot.ownership != CodexAccountSlotOwnershipV1::Managed
            || candidate.binding.is_some()
        {
            continue;
        }
        // These are previously accepted registry bindings, not live credential
        // proof. Never use this fallback for meters, transcript attribution,
        // successful checks, or labels from the failed/different live
        // identity. The binding's last reading is local display only
        // (`codex_last_known_slot_reading`); the server owns carry-forward.
        let Some((account, workspace)) = candidate
            .slot
            .registered_binding
            .as_ref()
            .filter(|(account, workspace)| !account.is_empty() && !workspace.is_empty())
        else {
            continue;
        };
        if !represented.insert((account.clone(), workspace.clone())) {
            continue;
        }
        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Degraded,
            AgentStatusCollectionMethod::ConfigFile,
            captured_at.to_string(),
            expires_at.to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::Unknown,
            provider: Some("openai".to_string()),
            billing_channel: Some("subscription".to_string()),
            account_identifier_hash: Some(account.clone()),
            organization_identifier_hash: Some(workspace.clone()),
            billing_identity_evidence: Some("provider_account_id".to_string()),
            billing_identity_confidence: AgentStatusConfidence::High,
            confidence: AgentStatusConfidence::High,
            ..unsupported_account("openai")
        });
        snapshot.capabilities = vec![
            unsupported_capability(
                "quota_windows",
                "Current limits are unavailable for this configured Codex account and workspace.",
            ),
            unsupported_capability(
                "credits",
                "Current credits are unavailable for this configured Codex account and workspace.",
            ),
        ];
        snapshot.diagnostics.push(
            AgentStatusDiagnostic::source(
                "codex_configured_account_unavailable",
                AgentDiagnosticSeverity::Warning,
                "This previously accepted Codex account and workspace remains configured; its current identity and limits could not be verified.",
            ).with_quota_binding(Some(account.clone()), Some(workspace.clone())),
        );
        snapshots.push(snapshot);
    }
}

/// Upload the default home's failed-probe snapshot when it kept the hashes of
/// its last validated account ([`keep_failed_default_codex_binding`]) and no
/// other snapshot already represents that account. Without this, a batch that
/// has any other row never carried the default account's degraded reading.
/// The candidate's binding stays empty, so transcript attribution is unchanged.
fn append_failed_default_codex_snapshot(
    snapshots: &mut Vec<AgentStatusSnapshot>,
    candidates: &[CodexSlotCandidate],
) {
    for candidate in candidates {
        if candidate.slot.ownership != CodexAccountSlotOwnershipV1::Default
            || candidate.binding.is_some()
            || !codex_probe_failed_only(&candidate.status, &candidate.snapshot)
        {
            continue;
        }
        let Some(kept) = candidate.snapshot.account.as_ref().and_then(|account| {
            account
                .account_identifier_hash
                .as_ref()
                .zip(account.organization_identifier_hash.as_ref())
        }) else {
            continue;
        };
        let represented = snapshots.iter().any(|snapshot| {
            snapshot.account.as_ref().is_some_and(|account| {
                account.account_identifier_hash.as_ref() == Some(kept.0)
                    && account.organization_identifier_hash.as_ref() == Some(kept.1)
            })
        });
        if !represented {
            snapshots.push(candidate.snapshot.clone());
        }
    }
}

/// Whether a slot's only problem is a failed usage probe: the app-server read
/// failed (`codex_usage_probe_failed`) while the login itself is not known to
/// be broken. A signed-in home then has no identity hashes
/// (`identity_unknown`); a signed-out one is `needs_login` and does not count,
/// and neither does a missing `codex` executable, which is not transient.
fn codex_probe_failed_only(
    status: &CodexAccountSlotCollectionStatusV1,
    snapshot: &AgentStatusSnapshot,
) -> bool {
    matches!(
        status.state,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
            | CodexAccountSlotCollectionStateV1::ProviderUnavailable
    ) && snapshot.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "codex_usage_probe_failed"
            && !diagnostic
                .message
                .starts_with(CODEX_CLI_NOT_FOUND_FOR_PROBE)
    })
}

/// The binding last validated at this Codex home, while the home's current
/// local credential still names that same account and workspace. Decoding the
/// credential is only a consistency check (the home has not switched
/// accounts), never authentication: the hashes are those of the earlier
/// provider-validated reading.
fn codex_home_kept_binding(codex_home: &Path, home_trust: CodexHomeTrust) -> Option<String> {
    let last = codex_credit_grants::home_binding(codex_home)?;
    let credentials = read_codex_auth_credentials_at(codex_home, home_trust)
        .ok()
        .flatten()?;
    let claimed = codex_credential_claimed_binding(&credentials)?;
    (claimed == last).then_some(last)
}

/// A default home whose usage probe failed keeps the identity hashes of its
/// last validated reading (when its credential still names that account), so
/// the degraded snapshot stays keyed to the same account, and carries that
/// account's last reading marked stale ([`codex_last_known`]) for local
/// display; the upload copy drops the reading
/// (`AgentStatusSnapshot::redacted_for_backend`). The slot's binding stays
/// empty and the account's confidence is low: kept hashes never become
/// transcript, session-attribution or live-meter authority.
fn keep_failed_default_codex_binding(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    snapshot: &mut AgentStatusSnapshot,
    now: u64,
) {
    let Some(binding) = codex_home_kept_binding(codex_home, home_trust) else {
        return;
    };
    let Some((account_hash, workspace_hash)) = binding.split_once(':') else {
        return;
    };
    let Some(account) = snapshot.account.as_mut() else {
        return;
    };
    account.account_identifier_hash = Some(account_hash.to_string());
    account.organization_identifier_hash = Some(workspace_hash.to_string());
    // Remembered, not validated in this read: low confidence keeps the kept
    // hashes out of every consumer that trusts a current login (for example
    // the current-login fallback of session attribution).
    account.confidence = AgentStatusConfidence::Low;
    if let Some((quota_windows, credit_balances)) = codex_last_known::stale_reading(&binding, now) {
        snapshot.quota_windows = quota_windows;
        snapshot.credit_balances = credit_balances;
    }
}

/// Keep a fresh, bound reading as its binding's last-known meters.
fn remember_codex_last_known_reading(
    binding: Option<&(String, String)>,
    status: &CodexAccountSlotCollectionStatusV1,
    snapshot: &AgentStatusSnapshot,
    now: u64,
) {
    let Some((account, workspace)) =
        binding.filter(|_| status.state == CodexAccountSlotCollectionStateV1::Fresh)
    else {
        return;
    };
    // Keyed on the read itself, not this collection: a saved reading served
    // again keeps its original read time, so the age cap still holds.
    let read_at = snapshot
        .quota_windows
        .iter()
        .filter_map(|window| window.observed_at.as_deref())
        .filter_map(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
        .filter_map(|at| u64::try_from(at.unix_timestamp()).ok())
        .min()
        .unwrap_or(now)
        .min(now);
    codex_last_known::record(
        &codex_credit_grants::binding_key(account, workspace),
        &snapshot.quota_windows,
        &snapshot.credit_balances,
        read_at,
    );
}

/// Local display only: the last reading of a registered slot whose probe
/// failed, marked `Stale` with its original read clocks
/// ([`codex_last_known`]), as the slot's quota snapshot. Only while the
/// home was last validated as the registered binding and its local
/// credential still names that account ([`codex_home_kept_binding`]), so a
/// sign-out or a re-login to another account carries nothing. Never part of
/// an uploaded snapshot: the server owns carry-forward.
///
/// The container's `captured_at` is the time of the failed poll. The time
/// the reading was taken is each window's and balance's own `observed_at`
/// (and `grants_observed_at`), which stay the original; a display's "as of"
/// must come from those.
///
/// The candidate keeps its failed state; [`codex_local_slot_status`] gives
/// the slot the state and hashes local clients need to decode the reading.
fn codex_last_known_slot_reading(
    slot: &CodexHomeSlot,
    captured_at: &str,
    now: u64,
) -> Option<CodexAccountSlotQuotaSnapshotV1> {
    let (account, workspace) = slot.registered_binding.as_ref()?;
    let binding = codex_credit_grants::binding_key(account, workspace);
    if codex_home_kept_binding(&slot.home, CodexHomeTrust::Managed).as_deref()
        != Some(binding.as_str())
    {
        return None;
    }
    let (quota_windows, credit_balances) = codex_last_known::stale_reading(&binding, now)?;
    Some(CodexAccountSlotQuotaSnapshotV1 {
        captured_at: captured_at.to_string(),
        quota_windows,
        credit_balances,
    })
}

fn codex_source_health_snapshot(
    candidates: &[CodexSlotCandidate],
    captured_at: &str,
    expires_at: &str,
) -> AgentStatusSnapshot {
    let mut source_health_snapshot = candidates
        .iter()
        .find(|candidate| candidate.slot.slot_id == "default")
        .map(|candidate| candidate.snapshot.clone())
        .unwrap_or_else(|| {
            not_installed_snapshot(
                SourceKind::Codex,
                "codex",
                captured_at.to_string(),
                expires_at.to_string(),
            )
        });
    // A failed usage probe is a transient read failure, retried at the next
    // poll; it is not a connection that needs local attention.
    let probe_failed_only = |candidate: &&CodexSlotCandidate| {
        codex_probe_failed_only(&candidate.status, &candidate.snapshot)
    };
    let custom_needs_attention = candidates.iter().any(|candidate| {
        candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
            && !matches!(
                candidate.status.state,
                CodexAccountSlotCollectionStateV1::Fresh
                    | CodexAccountSlotCollectionStateV1::DuplicateAccount
            )
            && !probe_failed_only(&candidate)
    });
    let usage_read_failed = candidates
        .iter()
        .any(|candidate| probe_failed_only(&candidate));
    let default_probe_failed = candidates.iter().any(|candidate| {
        candidate.slot.ownership == CodexAccountSlotOwnershipV1::Default
            && probe_failed_only(&candidate)
    });
    if !custom_needs_attention && source_health_snapshot.status != AgentStatusState::Available {
        if let Some(healthy_anchor) = candidates.iter().find(|candidate| {
            candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
                && candidate.status.state == CodexAccountSlotCollectionStateV1::Fresh
        }) {
            source_health_snapshot = healthy_anchor.snapshot.clone();
        }
    }
    // A default login whose usage probe failed is still a working login; a
    // signed-out or otherwise failed one is not, and keeps its own status.
    let current_login_available = source_health_snapshot.status == AgentStatusState::Available
        || (default_probe_failed
            && source_health_snapshot.status == AgentStatusState::Degraded
            && source_health_snapshot
                .account
                .as_ref()
                .is_some_and(|account| account.login_state == AgentLoginState::SignedIn));
    if custom_needs_attention {
        if current_login_available {
            source_health_snapshot.status = AgentStatusState::Degraded;
        }
        source_health_snapshot
            .diagnostics
            .push(AgentStatusDiagnostic::source(
                if current_login_available {
                    "codex_registered_slot_needs_attention_current_available"
                } else {
                    "codex_registered_slot_needs_attention"
                },
                AgentDiagnosticSeverity::Warning,
                "One or more durable Codex account connections need local attention; healthy accounts continue collecting independently.",
            ));
    } else if usage_read_failed && current_login_available {
        source_health_snapshot.status = AgentStatusState::Degraded;
        source_health_snapshot
            .diagnostics
            .push(AgentStatusDiagnostic::source(
                "codex_usage_read_retrying",
                AgentDiagnosticSeverity::Warning,
                "A Codex usage check failed (for example it timed out); it is retried at the next poll, and the last readings are kept, marked stale.",
            ));
    }
    source_health_snapshot
}

/// Read-only launch projection: only saved provider-verified evidence and
/// current local claims. No CLI detection/probes, provider reads, or wakeups.
pub(crate) fn session_launch_codex_accounts_status(
    mut status: CodexAccountsStatusV1,
    default_home: &Path,
) -> CodexAccountsStatusV1 {
    let captured = crate::current_rfc3339_timestamp();
    let mut candidates = Vec::new();
    for mut slot in codex_home_slots_checked(&status).0 {
        if slot.ownership == CodexAccountSlotOwnershipV1::Default {
            slot.home = default_home.into();
        }
        let trust = if slot.ownership == CodexAccountSlotOwnershipV1::Default {
            CodexHomeTrust::ProviderDefault
        } else {
            CodexHomeTrust::Managed
        };
        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Degraded,
            AgentStatusCollectionMethod::ConfigFile,
            captured.clone(),
            captured.clone(),
        );
        if session_launch_codex_identity(&slot.home, trust).is_none() {
            snapshot.status = AgentStatusState::AuthRequired;
        } else if let Ok(probe) =
            codex_saved_quota::serve_saved_for_launch(&slot.home, trust, current_unix_seconds())
        {
            if !probe.credential_read_failed {
                snapshot.account = probe.account;
                if let (Some(account), Some(identity)) =
                    (snapshot.account.as_mut(), probe.saved_identity)
                {
                    account.account_identifier_hash = Some(identity.account_identifier_hash);
                    account.organization_identifier_hash = Some(identity.workspace_identifier_hash);
                    snapshot.quota_windows = probe.quota_windows;
                    snapshot.credit_balances = probe.credit_balances;
                    snapshot.status = AgentStatusState::Available;
                }
            }
        }
        let mut collection = codex_collection_status_from_snapshot(&snapshot);
        let binding = enforce_codex_registered_binding(&slot, &mut snapshot, &mut collection);
        let quality = codex_snapshot_quality(&snapshot, &collection);
        candidates.push(CodexSlotCandidate {
            slot,
            snapshot,
            status: collection,
            binding,
            workspace_targets: Vec::new(),
            quality,
            auth_modified_at: None,
        });
    }
    canonicalize_codex_candidates(&mut candidates);
    apply_codex_candidate_statuses(&mut status, &candidates);
    status
}

pub(crate) fn annotate_codex_accounts_status(
    status: CodexAccountsStatusV1,
) -> CodexAccountsStatusV1 {
    let captured_at = crate::current_rfc3339_timestamp();
    let expires_at = captured_at.clone();
    let (mut status, mut candidates) =
        collect_codex_slot_candidates(status, &captured_at, &expires_at);
    canonicalize_codex_candidates(&mut candidates);
    apply_codex_candidate_statuses(&mut status, &candidates);
    status.target_coverage = derive_codex_account_target_coverage(&status, &candidates);
    status
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodexSlotSetupCollectionError {
    ProviderLoginPending(String),
    DurableStateUnavailable(String),
}

impl CodexSlotSetupCollectionError {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::ProviderLoginPending(message) | Self::DurableStateUnavailable(message) => message,
        }
    }
}

/// Which setup step reads a registered Codex home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexSetupRead<'a> {
    /// A check of a setup that waits for the person's sign-in. Clients repeat
    /// it every few seconds, so its provider reads are spaced per home
    /// (`codex_setup_gate`); `explicit` is a person's check.
    WaitingForLogin {
        operation_id: &'a str,
        explicit: bool,
    },
    /// A validation step. It moves the setup out of waiting, so it reads now.
    Validation,
}

pub(crate) fn collect_registered_codex_slot_for_setup(
    slot_id: &str,
    read: CodexSetupRead<'_>,
) -> Result<(CodexStrongIdentity, CodexAccountSlotCollectionStatusV1), CodexSlotSetupCollectionError>
{
    let store = FileCodexAccountSlotSettingsStore::default();
    let home = store.slot_home(slot_id).map_err(|_| {
        CodexSlotSetupCollectionError::DurableStateUnavailable(
            "Codex durable connection state is unavailable.".to_string(),
        )
    })?;
    match read {
        CodexSetupRead::WaitingForLogin {
            operation_id,
            explicit,
        } => codex_setup_gate::read_waiting_setup_home(&home, operation_id, explicit, || {
            let result = read_registered_codex_home_for_setup(&home);
            let succeeded = result.is_ok();
            (result, succeeded)
        })
        .unwrap_or_else(|deferred| {
            Err(CodexSlotSetupCollectionError::ProviderLoginPending(
                deferred.message(),
            ))
        }),
        CodexSetupRead::Validation => read_registered_codex_home_for_setup(&home),
    }
}

fn read_registered_codex_home_for_setup(
    home: &Path,
) -> Result<(CodexStrongIdentity, CodexAccountSlotCollectionStatusV1), CodexSlotSetupCollectionError>
{
    let captured_at = crate::current_rfc3339_timestamp();
    // A setup check needs a fresh provider read; it also refreshes the saved
    // copy every status read then serves.
    let (snapshot, identity, _) =
        crate::provider_calls::with_trigger(crate::provider_calls::Trigger::Setup, || {
            collect_codex_status_for_home(
                captured_at.clone(),
                captured_at,
                home,
                CodexHomeTrust::Managed,
                // `home` is an Ottto account slot's, resolved by the store.
                CodexLoginRefresh::WhenLapsing,
                CodexQuotaRead::Provider,
            )
        });
    let identity = identity.ok_or_else(|| {
        CodexSlotSetupCollectionError::ProviderLoginPending(
            "Codex sign-in has not produced a complete account and workspace identity.".to_string(),
        )
    })?;
    let status = codex_collection_status_from_snapshot(&snapshot);
    if status.state != CodexAccountSlotCollectionStateV1::Fresh
        || status.account_identifier_hash.as_deref()
            != Some(identity.account_identifier_hash.as_str())
        || status.workspace_identifier_hash.as_deref()
            != Some(identity.workspace_identifier_hash.as_str())
    {
        return Err(CodexSlotSetupCollectionError::ProviderLoginPending(
            "Codex sign-in is present, but fresh quota for its exact account and workspace is not yet available."
                .to_string(),
        ));
    }
    Ok((identity, status))
}

fn collect_codex_slot_candidates(
    status: CodexAccountsStatusV1,
    captured_at: &str,
    expires_at: &str,
) -> (CodexAccountsStatusV1, Vec<CodexSlotCandidate>) {
    let slots = codex_home_slots(&status);
    let candidates = thread::scope(|scope| {
        let handles = slots
            .into_iter()
            .map(|slot| {
                scope.spawn(move || {
                    collect_codex_home_candidate(
                        slot,
                        captured_at,
                        expires_at,
                        CodexQuotaRead::Saved,
                    )
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .collect()
    });
    (status, candidates)
}

/// The default Codex home and every accepted managed slot home.
fn codex_home_slots(status: &CodexAccountsStatusV1) -> Vec<CodexHomeSlot> {
    codex_home_slots_checked(status).0
}

/// [`codex_home_slots`], and whether every settings read it made succeeded:
/// `false` when the registered bindings or an accepted slot's home could not
/// be read, so a slot may be missing for a reason that can pass.
fn codex_home_slots_checked(status: &CodexAccountsStatusV1) -> (Vec<CodexHomeSlot>, bool) {
    let store = FileCodexAccountSlotSettingsStore::default();
    let mut slots = vec![CodexHomeSlot {
        slot_id: "default".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Default,
        home: default_codex_home(),
        registered_binding: None,
    }];
    let registered = store.registered_bindings();
    let mut complete = registered.is_ok();
    let registered = registered
        .unwrap_or_default()
        .into_iter()
        .filter(|binding| binding.accepted)
        .map(|binding| (binding.slot_id.clone(), binding))
        .collect::<BTreeMap<_, _>>();
    for descriptor in &status.managed_slots {
        if let Some(binding) = registered.get(&descriptor.slot_id) {
            let Ok(home) = store.slot_home(&descriptor.slot_id) else {
                complete = false;
                continue;
            };
            slots.push(CodexHomeSlot {
                slot_id: descriptor.slot_id.clone(),
                ownership: CodexAccountSlotOwnershipV1::Managed,
                home,
                registered_binding: Some((
                    binding.account_identifier_hash.clone(),
                    binding.workspace_identifier_hash.clone(),
                )),
            });
        }
    }
    (slots, complete)
}

/// One Codex home the daily provider reference may read: the provider
/// default home (`slot_id` `None`) or an accepted Ottto slot with the account
/// and workspace hashes it was registered with.
pub(crate) struct DailyReferenceHome {
    pub(crate) slot_id: Option<String>,
    pub(crate) home: PathBuf,
    pub(crate) trust: CodexHomeTrust,
    pub(crate) registered_pair: Option<(String, String)>,
}

/// Kind only: the path and the registered hashes stay out of formatted output.
impl std::fmt::Debug for DailyReferenceHome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DailyReferenceHome")
            .field("slot", &self.slot_id.is_some())
            .finish_non_exhaustive()
    }
}

/// The default Codex home and every accepted Ottto slot home (never a home
/// seen only through a running process), and whether every settings read
/// succeeded. Read-only: a pending slot removal is left to its owner, and an
/// unreadable registry yields the default home alone, marked incomplete.
pub(crate) fn daily_reference_homes() -> (Vec<DailyReferenceHome>, bool) {
    let default_home = || DailyReferenceHome {
        slot_id: None,
        home: default_codex_home(),
        trust: CodexHomeTrust::ProviderDefault,
        registered_pair: None,
    };
    let Ok(status) = FileCodexAccountSlotSettingsStore::default().load_for_session_launch() else {
        return (vec![default_home()], false);
    };
    let (slots, complete) = codex_home_slots_checked(&status);
    let homes = slots
        .into_iter()
        .map(|slot| match slot.ownership {
            CodexAccountSlotOwnershipV1::Default => default_home(),
            CodexAccountSlotOwnershipV1::Managed => DailyReferenceHome {
                slot_id: Some(slot.slot_id),
                home: slot.home,
                trust: CodexHomeTrust::Managed,
                registered_pair: slot.registered_binding,
            },
        })
        .collect();
    (homes, complete)
}

fn collect_codex_home_candidate(
    slot: CodexHomeSlot,
    captured_at: &str,
    expires_at: &str,
    quota_read: CodexQuotaRead,
) -> CodexSlotCandidate {
    let home_trust = match slot.ownership {
        CodexAccountSlotOwnershipV1::Default => CodexHomeTrust::ProviderDefault,
        CodexAccountSlotOwnershipV1::Managed => CodexHomeTrust::Managed,
    };
    let auth_path = slot.home.join("auth.json");
    let before = std::fs::metadata(&auth_path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let (mut snapshot, _, workspace_targets) = collect_codex_status_for_home(
        captured_at.to_string(),
        expires_at.to_string(),
        &slot.home,
        home_trust,
        slot.login_refresh(),
        quota_read,
    );
    let mut status = codex_collection_status_from_snapshot(&snapshot);
    let binding = enforce_codex_registered_binding(&slot, &mut snapshot, &mut status);
    let now = current_unix_seconds();
    remember_codex_last_known_reading(binding.as_ref(), &status, &snapshot, now);
    if binding.is_none() && codex_probe_failed_only(&status, &snapshot) {
        match slot.ownership {
            CodexAccountSlotOwnershipV1::Default => {
                keep_failed_default_codex_binding(&slot.home, home_trust, &mut snapshot, now);
            }
            CodexAccountSlotOwnershipV1::Managed => {
                status.quota_snapshot =
                    codex_last_known_slot_reading(&slot, &snapshot.captured_at, now);
            }
        }
    }
    let quality = codex_snapshot_quality(&snapshot, &status);
    let after = std::fs::metadata(&auth_path)
        .and_then(|metadata| metadata.modified())
        .ok();
    CodexSlotCandidate {
        slot,
        snapshot,
        status,
        binding,
        workspace_targets,
        quality,
        auth_modified_at: (before == after).then_some(before).flatten(),
    }
}

fn enforce_codex_registered_binding(
    slot: &CodexHomeSlot,
    snapshot: &mut AgentStatusSnapshot,
    status: &mut CodexAccountSlotCollectionStatusV1,
) -> Option<(String, String)> {
    let live_binding = status
        .account_identifier_hash
        .clone()
        .zip(status.workspace_identifier_hash.clone());
    match (&slot.registered_binding, live_binding) {
        (Some(expected), Some(live)) if expected != &live => {
            status.state = CodexAccountSlotCollectionStateV1::IdentityMismatch;
            status.quota_snapshot = None;
            status.diagnostics.push(CodexAccountSlotDiagnosticV1 {
                code: "codex_registered_identity_mismatch".to_string(),
                message:
                    "This durable Codex connection no longer matches its registered account and workspace."
                        .to_string(),
            });
            snapshot.quota_windows.clear();
            snapshot.credit_balances.clear();
            snapshot.status = AgentStatusState::Degraded;
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "codex_registered_identity_mismatch",
                AgentDiagnosticSeverity::Warning,
                "The durable Codex home changed identity; its meters were suppressed.",
            ));
            None
        }
        (_, live) => live,
    }
}

fn codex_snapshot_quality(
    snapshot: &AgentStatusSnapshot,
    status: &CodexAccountSlotCollectionStatusV1,
) -> u8 {
    let fresh_windows = snapshot
        .quota_windows
        .iter()
        .filter(|window| window.freshness == AgentQuotaWindowFreshness::Fresh)
        .count();
    if status.state == CodexAccountSlotCollectionStateV1::Fresh {
        4_u8.saturating_add(fresh_windows.min(u8::MAX as usize) as u8)
    } else if status.account_identifier_hash.is_some() && status.workspace_identifier_hash.is_some()
    {
        2
    } else {
        1
    }
}

fn codex_candidate_is_better(candidate: &CodexSlotCandidate, current: &CodexSlotCandidate) -> bool {
    candidate.quality > current.quality
        || (candidate.quality == current.quality
            && match (candidate.slot.ownership, current.slot.ownership) {
                (CodexAccountSlotOwnershipV1::Managed, CodexAccountSlotOwnershipV1::Default) => {
                    true
                }
                (CodexAccountSlotOwnershipV1::Default, CodexAccountSlotOwnershipV1::Managed) => {
                    false
                }
                _ => candidate.slot.slot_id < current.slot.slot_id,
            })
}

fn canonicalize_codex_candidates(candidates: &mut [CodexSlotCandidate]) {
    let mut canonical_managed = BTreeMap::<(String, String), usize>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.slot.ownership != CodexAccountSlotOwnershipV1::Managed {
            continue;
        }
        let Some(binding) = candidate.binding.clone() else {
            continue;
        };
        let replace = canonical_managed.get(&binding).map_or(true, |current| {
            codex_candidate_is_better(candidate, &candidates[*current])
        });
        if replace {
            canonical_managed.insert(binding, index);
        }
    }
    for (index, candidate) in candidates.iter_mut().enumerate() {
        let Some(binding) = candidate.binding.as_ref() else {
            continue;
        };
        match candidate.slot.ownership {
            CodexAccountSlotOwnershipV1::Default if canonical_managed.contains_key(binding) => {
                candidate.status.relationship =
                    Some(CodexAccountSlotRelationshipV1::ShadowedByAnchor);
            }
            CodexAccountSlotOwnershipV1::Managed
                if canonical_managed.get(binding) == Some(&index) =>
            {
                candidate.status.relationship =
                    Some(CodexAccountSlotRelationshipV1::CanonicalAnchor);
            }
            CodexAccountSlotOwnershipV1::Managed => {
                candidate.status.state = CodexAccountSlotCollectionStateV1::DuplicateAccount;
                candidate.status.relationship =
                    Some(CodexAccountSlotRelationshipV1::DuplicateAnchor);
                candidate.status.diagnostics.push(CodexAccountSlotDiagnosticV1 {
                    code: "codex_duplicate_account_workspace".to_string(),
                    message: "Another durable Codex connection already owns this exact account and workspace.".to_string(),
                });
            }
            CodexAccountSlotOwnershipV1::Default => {}
        }
    }
}

fn apply_codex_candidate_statuses(
    status: &mut CodexAccountsStatusV1,
    candidates: &[CodexSlotCandidate],
) {
    if let Some(candidate) = candidates
        .iter()
        .find(|candidate| candidate.slot.slot_id == "default")
    {
        status.default_slot.collection = codex_local_slot_status(candidate);
    }
    for descriptor in &mut status.managed_slots {
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.slot.slot_id == descriptor.slot_id)
        {
            descriptor.collection = codex_local_slot_status(candidate);
        }
    }
    // A last-known slot keeps its hashes only when no other slot, the
    // default one included, carries the same account and workspace. A local
    // client rejects the whole status when two managed slots share a binding
    // and are not one anchor plus declared duplicates, and it shows one card
    // per account from every slot of that account: an `unknown` slot there
    // would hide the meters another slot of the account read fresh.
    let mut slots_by_binding = BTreeMap::<(String, String), usize>::new();
    if let Some(binding) = codex_slot_status_binding(&status.default_slot.collection) {
        *slots_by_binding.entry(binding).or_default() += 1;
    }
    for descriptor in &status.managed_slots {
        if let Some(binding) = codex_slot_status_binding(&descriptor.collection) {
            *slots_by_binding.entry(binding).or_default() += 1;
        }
    }
    for descriptor in &mut status.managed_slots {
        if descriptor.collection.state != CodexAccountSlotCollectionStateV1::Unknown {
            continue;
        }
        let shared = codex_slot_status_binding(&descriptor.collection)
            .is_some_and(|binding| slots_by_binding.get(&binding).copied().unwrap_or(0) > 1);
        if !shared {
            continue;
        }
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.slot.slot_id == descriptor.slot_id)
        {
            descriptor.collection = candidate.status.clone();
            descriptor.collection.quota_snapshot = None;
        }
    }
}

fn codex_slot_status_binding(
    status: &CodexAccountSlotCollectionStatusV1,
) -> Option<(String, String)> {
    status
        .account_identifier_hash
        .clone()
        .zip(status.workspace_identifier_hash.clone())
}

/// The slot status as local clients read it.
///
/// Shipped clients decode a slot's `quota_snapshot` only on state `unknown`,
/// `fresh` or `duplicate_account`, only with both identity hashes, and only
/// when every meter carries those hashes; one slot outside that rule fails
/// the whole Codex accounts status. A failed read that shows its last-known
/// reading ([`codex_last_known_slot_reading`]) is therefore sent as
/// `unknown` with the registered hashes, which
/// [`codex_last_known_slot_reading`] has already matched against the home's
/// local credential. Any other snapshot outside the rule is not sent.
///
/// Wire shape only: the candidate's own state, binding and health are
/// unchanged, and `unknown` gives a client no authority over the slot.
/// Shipped clients decode this shape but do not show the reading of an
/// `unknown` slot; the slot also gives way to any other slot of the same
/// account ([`apply_codex_candidate_statuses`]).
fn codex_local_slot_status(candidate: &CodexSlotCandidate) -> CodexAccountSlotCollectionStatusV1 {
    let mut status = candidate.status.clone();
    if status.quota_snapshot.is_none() || codex_slot_quota_snapshot_is_admitted(&status) {
        return status;
    }
    if candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
        && candidate.binding.is_none()
        && codex_probe_failed_only(&candidate.status, &candidate.snapshot)
    {
        if let Some((account, workspace)) = candidate.slot.registered_binding.clone() {
            let mut last_known = status.clone();
            last_known.state = CodexAccountSlotCollectionStateV1::Unknown;
            last_known.account_identifier_hash = Some(account);
            last_known.workspace_identifier_hash = Some(workspace);
            if codex_slot_quota_snapshot_is_admitted(&last_known) {
                return last_known;
            }
        }
    }
    status.quota_snapshot = None;
    status
}

/// Whether local clients admit this status's `quota_snapshot`.
fn codex_slot_quota_snapshot_is_admitted(status: &CodexAccountSlotCollectionStatusV1) -> bool {
    let Some(snapshot) = status.quota_snapshot.as_ref() else {
        return true;
    };
    if !matches!(
        status.state,
        CodexAccountSlotCollectionStateV1::Unknown
            | CodexAccountSlotCollectionStateV1::Fresh
            | CodexAccountSlotCollectionStateV1::DuplicateAccount
    ) {
        return false;
    }
    let (Some(account), Some(workspace)) = (
        status.account_identifier_hash.as_deref(),
        status.workspace_identifier_hash.as_deref(),
    ) else {
        return false;
    };
    snapshot.quota_windows.iter().all(|window| {
        window.account_identifier_hash.as_deref() == Some(account)
            && window.organization_identifier_hash.as_deref() == Some(workspace)
    }) && snapshot.credit_balances.iter().all(|balance| {
        balance.account_identifier_hash.as_deref() == Some(account)
            && balance.organization_identifier_hash.as_deref() == Some(workspace)
    })
}

/// Shown when the credential does not claim an email for the account.
const CODEX_GENERIC_ACCOUNT_LABEL: &str = "Codex account";

fn derive_codex_account_target_coverage(
    status: &CodexAccountsStatusV1,
    candidates: &[CodexSlotCandidate],
) -> CodexAccountTargetCoverageV1 {
    let mut by_target = BTreeMap::<String, CodexAccountTargetDescriptorV1>::new();

    // OpenAI has TWO unrelated workspace namespaces, and only one of them carries
    // subscriptions:
    //
    // - `platform.openai.com` organizations govern API keys. They are what the
    //   id_token's `organizations[]` claim lists.
    // - `chatgpt.com` workspaces carry ChatGPT/Codex subscriptions. The signed-in
    //   one is `chatgpt_account_id`, which is what a durable slot registers and
    //   what `forced_chatgpt_workspace_id` pins.
    //
    // Only the second is a subscription. The two id spaces differ even when the
    // names match: preparing a target from an `organizations[].id` and then signing
    // into the same-named ChatGPT workspace returns `identity_mismatch`.
    //
    // The default organization is the one this credential is pointed at, so its
    // TITLE is a usable name for the workspace the credential is signed into, and
    // its hash is aliased onto the binding so the row does not render twice. That
    // is a naming convenience only - the binding hash stays the identity.
    let mut workspace_alias = BTreeMap::<String, String>::new();
    for candidate in candidates {
        let Some((_, binding_workspace_hash)) = candidate
            .binding
            .as_ref()
            .or(candidate.slot.registered_binding.as_ref())
        else {
            continue;
        };
        for evidence in candidate
            .workspace_targets
            .iter()
            .filter(|evidence| evidence.is_default)
        {
            let Some(observed) = evidence.workspace_identifier_hash.as_deref() else {
                continue;
            };
            if observed == binding_workspace_hash {
                continue;
            }
            workspace_alias.insert(observed.to_string(), binding_workspace_hash.clone());
        }
    }
    let canonical_workspace_hash = |hash: Option<&str>| -> Option<String> {
        let hash = hash?;
        Some(
            workspace_alias
                .get(hash)
                .cloned()
                .unwrap_or_else(|| hash.to_string()),
        )
    };

    // Both Codex accounts otherwise render as the same generic string, which makes
    // two connected identities impossible to tell apart. The id_token already
    // carries the signed-in email, and this status is local-control only - it is
    // never uploaded - so the account can name itself on this Mac.
    let mut account_labels = BTreeMap::<String, String>::new();
    for candidate in candidates {
        for evidence in &candidate.workspace_targets {
            if let (Some(account_hash), Some(label)) = (
                evidence.account_identifier_hash.as_deref(),
                evidence.account_label.as_deref(),
            ) {
                account_labels
                    .entry(account_hash.to_string())
                    .or_insert_with(|| label.to_string());
            }
        }
    }
    let account_label_for = |account_hash: Option<&str>| -> Option<String> {
        account_labels.get(account_hash?).cloned()
    };

    // A credential's `chatgpt_plan_type` describes the workspace it is signed
    // into, so it is keyed by the target that credential binds - never spread
    // across the account's other workspaces, whose plans the token never claims.
    let mut plan_by_workspace = BTreeMap::<String, String>::new();
    for candidate in candidates {
        let Some((_, binding_workspace_hash)) = candidate
            .binding
            .as_ref()
            .or(candidate.slot.registered_binding.as_ref())
        else {
            continue;
        };
        for evidence in candidate
            .workspace_targets
            .iter()
            .filter(|evidence| evidence.is_default)
        {
            if let Some(plan) = evidence.plan_type.as_deref() {
                plan_by_workspace
                    .entry(binding_workspace_hash.clone())
                    .or_insert_with(|| plan.to_string());
            }
        }
    }
    for candidate in candidates {
        if let Some(plan) = candidate.snapshot.account.as_ref().and_then(|account| {
            account
                .plan_type
                .as_deref()
                .and_then(|plan| safe_display_label(Some(plan)))
        }) {
            if let Some((_, binding_workspace_hash)) = candidate
                .binding
                .as_ref()
                .or(candidate.slot.registered_binding.as_ref())
            {
                plan_by_workspace
                    .entry(binding_workspace_hash.clone())
                    .or_insert(plan);
            }
        }
    }
    let plan_for = |workspace_hash: Option<&str>| -> Option<String> {
        plan_by_workspace.get(workspace_hash?).cloned()
    };

    for candidate in candidates.iter().filter(|candidate| {
        candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
            && candidate.status.relationship
                != Some(CodexAccountSlotRelationshipV1::DuplicateAnchor)
    }) {
        let Some((account_hash, workspace_hash)) = candidate.slot.registered_binding.as_ref()
        else {
            continue;
        };
        upsert_codex_account_target(
            &mut by_target,
            codex_account_target_descriptor(
                CodexAccountTargetIdentity {
                    account_identifier_hash: Some(account_hash.clone()),
                    workspace_identifier_hash: Some(workspace_hash.clone()),
                    workspace_label: None,
                    account_label: account_label_for(Some(account_hash.as_str())),
                    plan_type: plan_for(Some(workspace_hash.as_str())),
                },
                CodexAccountTargetDurabilityV1::Durable,
                false,
                Some(projected_codex_target_health(candidate.status.state)),
                candidate.status.observed_at.clone(),
            ),
        );
    }

    for candidate in candidates {
        let from_default_home = candidate.slot.ownership == CodexAccountSlotOwnershipV1::Default;
        // Non-default organizations are platform orgs this credential is NOT
        // signed into. They are not subscriptions, they are frequently not even
        // sign-in-able - one observed live is absent from the ChatGPT workspace
        // picker entirely - and offering them as connectable targets sends the
        // owner through a login that can only end in `identity_mismatch`.
        //
        // Other ChatGPT workspaces are not enumerable: the id_token names only the
        // signed-in one, and `account/read` returns type, email, and plan with no
        // workspace list. So there is no honest target row to emit for them, and
        // connecting another workspace has to be an unbound flow that lets the
        // provider's own picker decide.
        for evidence in candidate
            .workspace_targets
            .iter()
            .filter(|evidence| evidence.is_default)
        {
            let workspace_hash =
                canonical_workspace_hash(evidence.workspace_identifier_hash.as_deref());
            let is_current = from_default_home
                && candidate.binding.as_ref().map_or(
                    evidence.is_default,
                    |(_, binding_workspace_hash)| {
                        workspace_hash.as_deref() == Some(binding_workspace_hash.as_str())
                    },
                );
            upsert_codex_account_target(
                &mut by_target,
                codex_account_target_descriptor(
                    CodexAccountTargetIdentity {
                        account_label: evidence.account_label.clone().or_else(|| {
                            account_label_for(evidence.account_identifier_hash.as_deref())
                        }),
                        plan_type: evidence
                            .plan_type
                            .clone()
                            .or_else(|| plan_for(workspace_hash.as_deref())),
                        account_identifier_hash: evidence.account_identifier_hash.clone(),
                        workspace_identifier_hash: workspace_hash,
                        workspace_label: evidence.workspace_label.clone(),
                    },
                    if is_current {
                        CodexAccountTargetDurabilityV1::Current
                    } else {
                        CodexAccountTargetDurabilityV1::ObservedOnly
                    },
                    is_current,
                    is_current.then_some(projected_codex_target_health(candidate.status.state)),
                    Some(evidence.observed_at.clone()),
                ),
            );
        }
    }

    if let Some(default) = candidates
        .iter()
        .find(|candidate| candidate.slot.ownership == CodexAccountSlotOwnershipV1::Default)
    {
        if let Some((account_hash, workspace_hash)) = default.binding.as_ref() {
            upsert_codex_account_target(
                &mut by_target,
                codex_account_target_descriptor(
                    CodexAccountTargetIdentity {
                        account_identifier_hash: Some(account_hash.clone()),
                        workspace_identifier_hash: Some(workspace_hash.clone()),
                        workspace_label: None,
                        account_label: account_label_for(Some(account_hash.as_str())),
                        plan_type: plan_for(Some(workspace_hash.as_str())),
                    },
                    CodexAccountTargetDurabilityV1::Current,
                    true,
                    Some(projected_codex_target_health(default.status.state)),
                    default.status.observed_at.clone(),
                ),
            );
        }
    }

    let mut targets = by_target.into_values().collect::<Vec<_>>();
    for target in &mut targets {
        if target.account_identifier_hash.is_none() || target.workspace_identifier_hash.is_none() {
            target
                .setup_blockers
                .push(CodexAccountTargetSetupBlockerV1::IdentityUnconfirmed);
        }
        let reuses_setup_slot = status
            .setup_operation
            .expected_account_identifier_hash
            .as_deref()
            .zip(
                status
                    .setup_operation
                    .expected_workspace_identifier_hash
                    .as_deref(),
            )
            .is_some_and(|(account_hash, workspace_hash)| {
                target.account_identifier_hash.as_deref() == Some(account_hash)
                    && target.workspace_identifier_hash.as_deref() == Some(workspace_hash)
            });
        if target.durability != CodexAccountTargetDurabilityV1::Durable
            && status.capacity.remaining_slots == 0
            && !reuses_setup_slot
        {
            target
                .setup_blockers
                .push(CodexAccountTargetSetupBlockerV1::CapacityReached);
        }
        target.connectable = target.durability != CodexAccountTargetDurabilityV1::Durable
            && target.setup_blockers.is_empty();
    }
    targets.sort_by(|left, right| {
        right
            .is_current
            .cmp(&left.is_current)
            .then_with(|| {
                (right.durability == CodexAccountTargetDurabilityV1::Durable)
                    .cmp(&(left.durability == CodexAccountTargetDurabilityV1::Durable))
            })
            .then_with(|| left.workspace_label.cmp(&right.workspace_label))
            .then_with(|| left.target_id.cmp(&right.target_id))
    });

    let bounded_count = |predicate: fn(&CodexAccountTargetDescriptorV1) -> bool| {
        u8::try_from(targets.iter().filter(|target| predicate(target)).count()).unwrap_or(u8::MAX)
    };
    CodexAccountTargetCoverageV1 {
        observed_targets: u8::try_from(targets.len()).unwrap_or(u8::MAX),
        durable_targets: bounded_count(|target| {
            target.durability == CodexAccountTargetDurabilityV1::Durable
        }),
        current_targets: bounded_count(|target| target.is_current),
        connectable_targets: bounded_count(|target| target.connectable),
        blocked_targets: bounded_count(|target| !target.setup_blockers.is_empty()),
        targets,
    }
}

/// How one Codex target names itself. `account_label` distinguishes two connected
/// Codex identities and falls back to the generic string when the credential did
/// not claim an email.
struct CodexAccountTargetIdentity {
    account_identifier_hash: Option<String>,
    workspace_identifier_hash: Option<String>,
    workspace_label: Option<String>,
    account_label: Option<String>,
    plan_type: Option<String>,
}

fn codex_account_target_descriptor(
    identity: CodexAccountTargetIdentity,
    durability: CodexAccountTargetDurabilityV1,
    is_current: bool,
    health: Option<CodexAccountTargetHealthV1>,
    observed_at: Option<String>,
) -> CodexAccountTargetDescriptorV1 {
    let CodexAccountTargetIdentity {
        account_identifier_hash,
        workspace_identifier_hash,
        workspace_label,
        account_label,
        plan_type,
    } = identity;
    let target_id = codex_account_target_id(
        account_identifier_hash.as_deref(),
        workspace_identifier_hash.as_deref(),
        workspace_label.as_deref(),
    );
    CodexAccountTargetDescriptorV1 {
        target_id,
        account_identifier_hash,
        workspace_identifier_hash,
        account_label: account_label.unwrap_or_else(|| CODEX_GENERIC_ACCOUNT_LABEL.to_string()),
        workspace_label,
        subscription_product: plan_type.map(chatgpt_subscription_product),
        durability,
        is_current,
        connectable: false,
        health,
        setup_blockers: Vec::new(),
        observed_at,
    }
}

fn codex_account_target_id(
    account_identifier_hash: Option<&str>,
    workspace_identifier_hash: Option<&str>,
    workspace_label: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:codex-account-target:v1\0");
    digest.update(account_identifier_hash.unwrap_or_default().as_bytes());
    digest.update(b"\0");
    digest.update(workspace_identifier_hash.unwrap_or_default().as_bytes());
    digest.update(b"\0");
    if workspace_identifier_hash.is_none() {
        digest.update(
            workspace_label
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_bytes(),
        );
    }
    format!("codex_account_target_{:.32x}", digest.finalize())
}

fn upsert_codex_account_target(
    targets: &mut BTreeMap<String, CodexAccountTargetDescriptorV1>,
    incoming: CodexAccountTargetDescriptorV1,
) {
    let Some(existing) = targets.get_mut(&incoming.target_id) else {
        targets.insert(incoming.target_id.clone(), incoming);
        return;
    };
    existing.is_current |= incoming.is_current;
    existing.account_identifier_hash = existing
        .account_identifier_hash
        .take()
        .or(incoming.account_identifier_hash);
    existing.workspace_identifier_hash = existing
        .workspace_identifier_hash
        .take()
        .or(incoming.workspace_identifier_hash);
    existing.workspace_label = existing.workspace_label.take().or(incoming.workspace_label);
    if existing.account_label == CODEX_GENERIC_ACCOUNT_LABEL
        && incoming.account_label != CODEX_GENERIC_ACCOUNT_LABEL
    {
        existing.account_label = incoming.account_label;
    }
    existing.subscription_product = existing
        .subscription_product
        .take()
        .or(incoming.subscription_product);
    existing.observed_at = existing.observed_at.take().or(incoming.observed_at);
    match (existing.durability, incoming.durability) {
        (CodexAccountTargetDurabilityV1::Durable, _) => {}
        (_, CodexAccountTargetDurabilityV1::Durable) => {
            existing.durability = CodexAccountTargetDurabilityV1::Durable;
            existing.health = incoming.health;
        }
        (CodexAccountTargetDurabilityV1::Current, _) => {}
        (_, CodexAccountTargetDurabilityV1::Current) => {
            existing.durability = CodexAccountTargetDurabilityV1::Current;
            existing.health = incoming.health.or(existing.health);
        }
        _ => {
            existing.health = existing.health.or(incoming.health);
        }
    }
}

fn projected_codex_target_health(
    state: CodexAccountSlotCollectionStateV1,
) -> CodexAccountTargetHealthV1 {
    match state {
        CodexAccountSlotCollectionStateV1::Fresh => CodexAccountTargetHealthV1::Healthy,
        CodexAccountSlotCollectionStateV1::Unverified => CodexAccountTargetHealthV1::Unverified,
        CodexAccountSlotCollectionStateV1::NeedsLogin => CodexAccountTargetHealthV1::NeedsLogin,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
        | CodexAccountSlotCollectionStateV1::Unknown => CodexAccountTargetHealthV1::IdentityUnknown,
        CodexAccountSlotCollectionStateV1::IdentityMismatch => {
            CodexAccountTargetHealthV1::IdentityMismatch
        }
        CodexAccountSlotCollectionStateV1::ProviderUnavailable => {
            CodexAccountTargetHealthV1::ProviderUnavailable
        }
        CodexAccountSlotCollectionStateV1::DuplicateAccount => {
            CodexAccountTargetHealthV1::DuplicateAccount
        }
    }
}

fn codex_collection_status_from_snapshot(
    snapshot: &AgentStatusSnapshot,
) -> CodexAccountSlotCollectionStatusV1 {
    let account = snapshot.account.as_ref();
    let identity = account.and_then(|account| {
        account
            .account_identifier_hash
            .clone()
            .zip(account.organization_identifier_hash.clone())
    });
    let (account_identifier_hash, workspace_identifier_hash) = identity
        .clone()
        .map_or((None, None), |(account, workspace)| {
            (Some(account), Some(workspace))
        });
    let has_fresh_quota = snapshot
        .quota_windows
        .iter()
        .any(|window| window.freshness == AgentQuotaWindowFreshness::Fresh);
    let state = if snapshot.status == AgentStatusState::AuthRequired
        || account.is_some_and(|account| account.login_state == AgentLoginState::SignedOut)
    {
        CodexAccountSlotCollectionStateV1::NeedsLogin
    } else if account.is_some_and(|account| account.login_state == AgentLoginState::SignedIn)
        && (account_identifier_hash.is_none() || workspace_identifier_hash.is_none())
    {
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    } else if account_identifier_hash.is_some()
        && workspace_identifier_hash.is_some()
        && has_fresh_quota
    {
        CodexAccountSlotCollectionStateV1::Fresh
    } else {
        CodexAccountSlotCollectionStateV1::ProviderUnavailable
    };
    let diagnostics = match state {
        CodexAccountSlotCollectionStateV1::NeedsLogin => vec![CodexAccountSlotDiagnosticV1 {
            code: "codex_account_needs_login".to_string(),
            message: "Codex must be signed in again for this durable connection.".to_string(),
        }],
        CodexAccountSlotCollectionStateV1::IdentityUnknown => vec![CodexAccountSlotDiagnosticV1 {
            code: "codex_identity_unknown".to_string(),
            message: "Codex did not provide a complete active user and workspace identity."
                .to_string(),
        }],
        CodexAccountSlotCollectionStateV1::ProviderUnavailable => {
            vec![CodexAccountSlotDiagnosticV1 {
                code: "codex_quota_unavailable".to_string(),
                message: "Codex quota is temporarily unavailable for this connection.".to_string(),
            }]
        }
        _ => Vec::new(),
    };
    CodexAccountSlotCollectionStatusV1 {
        state,
        account_identifier_hash,
        workspace_identifier_hash,
        plan_type: account.and_then(|account| account.plan_type.clone()),
        observed_at: Some(snapshot.captured_at.clone()),
        quota_snapshot: (state == CodexAccountSlotCollectionStateV1::Fresh && has_fresh_quota)
            .then(|| CodexAccountSlotQuotaSnapshotV1 {
                captured_at: snapshot.captured_at.clone(),
                quota_windows: snapshot.quota_windows.clone(),
                credit_balances: snapshot.credit_balances.clone(),
            }),
        relationship: None,
        diagnostics,
    }
}

fn empty_codex_accounts_status() -> CodexAccountsStatusV1 {
    CodexAccountsStatusV1 {
        schema_version: ottto_protocol::CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
        setup_operation: Default::default(),
        default_slot: CodexAccountSlotDescriptorV1 {
            slot_id: "default".to_string(),
            ownership: CodexAccountSlotOwnershipV1::Default,
            collection: Default::default(),
        },
        managed_slots: Vec::new(),
        target_coverage: CodexAccountTargetCoverageV1::default(),
        capacity: ottto_protocol::CodexAccountCapacityV1 {
            max_slots: ottto_core::MAX_CODEX_ACCOUNT_SLOTS,
            used_slots: 1,
            remaining_slots: ottto_core::MAX_CODEX_ACCOUNT_SLOTS.saturating_sub(1),
        },
        daemon_sign_in_supported: None,
        background_quota_refresh: None,
    }
}

#[cfg(test)]
pub fn parse_codex_status_fallback(
    text: &str,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    let account = parse_codex_account_text(text).unwrap_or_else(|| unsupported_account("openai"));
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::ManualFallback,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(account);
    snapshot.model = parse_codex_text_model(text);
    snapshot.quota_windows = parse_codex_text_quota_windows(text);
    snapshot.context = parse_codex_text_context(text);
    snapshot
}

const CLI_META_MAX_AGE: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
struct CliMeta<F> {
    loaded_at: Instant,
    facts: F,
}

type CliFacts<K, F, const N: usize> = crate::transcript_acquisition::StampedFacts<
    K,
    CliMeta<F>,
    [crate::transcript_acquisition::SourceStamp; N],
>;

#[derive(Clone)]
struct CodexCliMeta {
    // No account, email, plan or identity is retained from CLI text.
    login: AgentLoginState,
    models: AgentModelStatus,
}

static CODEX_CLI_META: OnceLock<Mutex<CliFacts<PathBuf, CodexCliMeta, 3>>> = OnceLock::new();
static CLAUDE_CLI_META: OnceLock<Mutex<CliFacts<PathBuf, (), 1>>> = OnceLock::new();

fn cli_meta<K: Ord + Clone, F: Clone, E, const N: usize>(
    cache: &Mutex<CliFacts<K, F, N>>,
    key: K,
    capture: impl FnMut() -> std::io::Result<[crate::transcript_acquisition::SourceStamp; N]>,
    load: impl FnOnce() -> Result<F, E>,
    now: Instant,
    bypass: bool,
) -> Result<F, E> {
    // Move this key out while loading: never hold the shared lock over a CLI
    // spawn, file metadata lookup or parsing. Concurrent misses may both read.
    let mut local = CliFacts::default();
    {
        let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((stamp, facts)) = cache.kept.remove(&key) {
            if !bypass && now.saturating_duration_since(facts.loaded_at) < CLI_META_MAX_AGE {
                local.kept.insert(key.clone(), (stamp, facts));
            }
        }
    }
    let result = local.reuse_or_load(key.clone(), capture, || {
        load().map(|facts| CliMeta {
            loaded_at: now,
            facts,
        })
    });
    if let Some(kept) = local.kept.remove(&key) {
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .kept
            .insert(key, kept);
    }
    result.map(|entry| entry.facts)
}

fn cli_binary_stamp(binary: &str) -> std::io::Result<crate::transcript_acquisition::SourceStamp> {
    let path = crate::command_env::executable_path(binary)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let stamp = crate::transcript_acquisition::SourceStamp::capture_file(&path.canonicalize()?)?;
    match stamp {
        crate::transcript_acquisition::SourceStamp::File(_) => Ok(stamp),
        _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
    }
}

fn codex_cli_meta(
    home: &Path,
    allow_legacy_oauth: bool,
    reuse_login: bool,
) -> (
    Result<AgentLoginState, CommandOutput>,
    AgentModelStatus,
    Option<AgentAccountStatus>,
) {
    use crate::transcript_acquisition::SourceStamp;
    let mut fresh = None;
    let mut fresh_login_account = None;
    let result = cli_meta(
        CODEX_CLI_META.get_or_init(Default::default),
        home.to_path_buf(),
        || {
            let binary = cli_binary_stamp("codex")?;
            let auth = SourceStamp::capture_file(&home.join("auth.json"))?;
            // Absent auth must never suppress a login probe (keyring homes).
            if matches!(auth, SourceStamp::Absent) {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
            }
            Ok([
                binary,
                auth,
                SourceStamp::capture_file(&home.join("config.toml"))?,
            ])
        },
        || {
            let login = run_codex_home_command(
                home,
                &["login", "status"],
                COMMAND_TIMEOUT,
                allow_legacy_oauth,
            );
            let models = run_codex_home_command(
                home,
                &["debug", "models", "--bundled"],
                COMMAND_TIMEOUT,
                allow_legacy_oauth,
            );
            // Codex prints `login status` to stderr. Admit that text only where
            // this pass's complete auth read overrides every field it fills;
            // other homes keep their stdout-only account surface.
            let login_text = if reuse_login {
                command_output_text(&login)
            } else {
                login.stdout.clone()
            };
            let parsed_account = parse_codex_account_text(&login_text);
            let parsed_login = parsed_account
                .as_ref()
                .map(|account| account.login_state.clone());
            let parsed_models = collect_codex_model_status_from_output(&models);
            let valid = login.command_found
                && login.success
                && login.status_code == Some(0)
                && parsed_login.is_some()
                && models.command_found
                && models.success
                && models.status_code == Some(0)
                && !parsed_models.available_models.is_empty();
            if valid {
                // The fresh fallback is used this pass only, never kept in facts.
                fresh_login_account = parsed_account;
                Ok(CodexCliMeta {
                    login: parsed_login.unwrap(),
                    models: parsed_models,
                })
            } else {
                fresh = Some((login, parsed_account, parsed_models));
                Err(())
            }
        },
        Instant::now(),
        !reuse_login
            || crate::provider_calls::current_trigger()
                == Some(crate::provider_calls::Trigger::Setup),
    );
    match result {
        Ok(meta) => (Ok(meta.login), meta.models, fresh_login_account),
        Err(()) => {
            let (output, parsed, models) = fresh.expect("loader returned uncached outputs");
            let fresh_account = if output.command_found && output.success {
                parsed
            } else {
                None
            };
            let login = fresh_account
                .as_ref()
                .map(|account| account.login_state.clone())
                .ok_or(output);
            (login, models, fresh_account)
        }
    }
}

fn claude_version_detected() -> bool {
    cli_meta(
        CLAUDE_CLI_META.get_or_init(Default::default),
        PathBuf::from("claude"),
        || Ok([cli_binary_stamp("claude")?]),
        || {
            let output = run_command_capture("claude", &["--version"], COMMAND_TIMEOUT);
            if output.command_found && output.success {
                Ok(())
            } else {
                Err(())
            }
        },
        Instant::now(),
        false,
    )
    .is_ok()
}

fn collect_codex_status_for_home(
    captured_at: String,
    expires_at: String,
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    login_refresh: CodexLoginRefresh,
    quota_read: CodexQuotaRead,
) -> (
    AgentStatusSnapshot,
    Option<CodexStrongIdentity>,
    Vec<CodexWorkspaceTargetEvidence>,
) {
    let allow_legacy_oauth = home_trust == CodexHomeTrust::ProviderDefault;
    if !executable_exists("codex")
        && !ottto_core::read_codex_config_file_secure(codex_home, home_trust)
            .is_ok_and(|body| body.is_some())
    {
        return (
            not_installed_snapshot(SourceKind::Codex, "codex", captured_at, expires_at),
            None,
            Vec::new(),
        );
    }

    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unknown,
        provider: Some("openai".to_string()),
        confidence: AgentStatusConfidence::Unknown,
        ..unsupported_account("openai")
    });

    let auth_account = read_codex_auth_account_at(codex_home, home_trust);
    // Reuse login metadata only when this pass's fresh auth read covers every
    // variable field the CLI fallback can fill. Incomplete/unreadable auth must
    // run the CLI fresh; the full parsed account is never cached.
    let reuse_login = auth_account
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .is_some_and(|account| {
            account.email.is_some()
                && account.plan_type.is_some()
                && account.subscription_product.is_some()
                && account.billing_channel.is_some()
        });
    let (login, mut model_status, fresh_login_account) =
        codex_cli_meta(codex_home, allow_legacy_oauth, reuse_login);
    match login {
        Ok(login_state) => {
            snapshot.collection_method = AgentStatusCollectionMethod::CliText;
            snapshot.status = AgentStatusState::Available;
            if let Some(account) = &mut snapshot.account {
                if login_state == AgentLoginState::SignedIn {
                    account.billing_channel = Some("subscription".to_string());
                }
                account.login_state = login_state;
                account.auth_method = Some("oauth".to_string());
                account.confidence = AgentStatusConfidence::Medium;
            }
        }
        Err(login) if login.command_found => {
            snapshot.collection_method = AgentStatusCollectionMethod::CliText;
            if !login.success {
                snapshot.diagnostics.push(command_diagnostic(
                    "codex_login_status_failed",
                    "codex login status did not return a usable status.",
                    &login,
                ));
                if matches!(
                    login.status_code,
                    Some(1) | Some(2) | Some(64) | Some(65) | Some(66) | Some(67)
                ) {
                    snapshot.status = AgentStatusState::AuthRequired;
                    if let Some(account) = &mut snapshot.account {
                        account.login_state = AgentLoginState::SignedOut;
                        account.confidence = AgentStatusConfidence::Medium;
                    }
                }
            }
        }
        Err(_) => {}
    }
    if let Some(account) = fresh_login_account {
        snapshot.account = Some(account);
    }
    match auth_account {
        Ok(Some(auth_account)) => {
            snapshot.status = AgentStatusState::Available;
            snapshot.account = Some(merge_codex_accounts(snapshot.account.take(), auth_account));
        }
        Ok(None) => {}
        Err(_) => append_codex_credential_read_failed_diagnostic(&mut snapshot),
    }

    apply_codex_config_model(
        &mut model_status,
        read_codex_config_model_at(codex_home, home_trust),
        &mut snapshot.collection_method,
    );
    snapshot.model = Some(model_status);
    let mut quota_capability = unsupported_capability(
        "quota_windows",
        "Codex usage windows were not available from the local account probe.",
    );
    let mut credits_capability = unsupported_capability(
        "credits",
        "Codex credit balance was not available from the local account probe.",
    );
    let mut strong_identity = None;
    let mut probe_failed = false;
    match collect_codex_usage_for_home(codex_home, home_trust, login_refresh, quota_read) {
        Ok(usage) => {
            if usage.credential_read_failed {
                append_codex_credential_read_failed_diagnostic(&mut snapshot);
            }
            if let Some(account) = usage.account {
                snapshot.account = Some(merge_codex_accounts(snapshot.account.take(), account));
            }
            let identity_hashes = usage
                .identity
                .as_ref()
                .map(CodexIdentityHashes::from)
                .or(usage.saved_identity);
            strong_identity = usage.identity;
            if let Some(identity) = identity_hashes.as_ref() {
                if let Some(account) = snapshot.account.as_mut() {
                    account.account_identifier_hash =
                        Some(identity.account_identifier_hash.clone());
                    account.organization_identifier_hash =
                        Some(identity.workspace_identifier_hash.clone());
                    account.superseded_account_identifier_hash =
                        identity.superseded_account_identifier_hash.clone();
                    account.superseded_organization_identifier_hash =
                        identity.superseded_organization_identifier_hash.clone();
                    account.billing_identity_evidence = billing_identity_evidence_for(
                        &account.account_identifier_hash,
                        &account.organization_identifier_hash,
                        &None,
                    );
                    account.billing_identity_confidence = AgentStatusConfidence::High;
                    account.confidence = AgentStatusConfidence::High;
                }
            }
            let quota_is_bound = snapshot.account.as_ref().is_some_and(|account| {
                account.account_identifier_hash.is_some()
                    && account.organization_identifier_hash.is_some()
            });
            if let Some(diagnostic) = codex_app_server_success_diagnostic(
                usage.response_completed_at.clone(),
                identity_hashes.as_ref(),
                !usage.quota_windows.is_empty() || !usage.credit_balances.is_empty(),
            ) {
                snapshot.diagnostics.push(diagnostic);
            }
            if let Some(summary) = usage.rate_limit_pool_summary {
                if let Some(mut diagnostic) = codex_app_server_success_diagnostic(
                    usage.response_completed_at.clone(),
                    identity_hashes.as_ref(),
                    true,
                ) {
                    diagnostic.code = "codex_rate_limit_pools_observed".to_string();
                    diagnostic.message = summary;
                    snapshot.diagnostics.push(diagnostic);
                }
            }
            if let Some(summary) = usage.reset_credit_detail_summary {
                if let Some(mut diagnostic) = codex_app_server_success_diagnostic(
                    usage.response_completed_at,
                    identity_hashes.as_ref(),
                    true,
                ) {
                    diagnostic.code = "codex_reset_credit_details_observed".to_string();
                    diagnostic.message = summary;
                    snapshot.diagnostics.push(diagnostic);
                }
            }
            if quota_is_bound && !usage.quota_windows.is_empty() {
                snapshot.collection_method = AgentStatusCollectionMethod::AppServer;
                snapshot.quota_windows = usage.quota_windows;
                quota_capability = supported_capability(
                    "quota_windows",
                    "Collected from the local Codex app-server rate-limit endpoint.",
                );
            } else {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            }
            if quota_is_bound && !usage.credit_balances.is_empty() {
                snapshot.credit_balances = usage.credit_balances;
                credits_capability = supported_capability(
                    "credits",
                    "Collected from the local Codex app-server rate-limit endpoint.",
                );
            }
        }
        Err(failure) if failure.message == codex_saved_quota::CODEX_QUOTA_NOT_READ_YET => {
            // No usable saved reading yet (first start, or the local login
            // changed): the schedule reads it shortly. Not a failed read.
            snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "codex_quota_not_read_yet",
                AgentDiagnosticSeverity::Info,
                failure.message,
            ));
        }
        Err(failure)
            if failure.message == codex_saved_quota::CODEX_QUOTA_BACKGROUND_REFRESH_OFF =>
        {
            // The same, while background limit refresh is off: nothing reads
            // it until the owner asks. Not a failed read.
            snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "codex_quota_background_refresh_off",
                AgentDiagnosticSeverity::Info,
                failure.message,
            ));
        }
        Err(failure) => {
            probe_failed = !failure.message.starts_with(CODEX_CLI_NOT_FOUND_FOR_PROBE);
            snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            snapshot.diagnostics.push(
                AgentStatusDiagnostic::source(
                    "codex_usage_probe_failed",
                    AgentDiagnosticSeverity::Warning,
                    failure.message,
                )
                // When the read failed, not when it is served.
                .with_observed_at(rfc3339_from_unix_seconds(failure.at_epoch_seconds))
                .with_quota_binding(
                    snapshot
                        .account
                        .as_ref()
                        .and_then(|account| account.account_identifier_hash.clone()),
                    snapshot
                        .account
                        .as_ref()
                        .and_then(|account| account.organization_identifier_hash.clone()),
                ),
            );
        }
    }
    snapshot.context = Some(unsupported_context(
        "codex_cli_v1",
        "codex_active_context_not_collected",
        None,
    ));
    snapshot.capabilities = vec![
        supported_capability("account_status", "Detected with Codex CLI/config probes."),
        quota_capability,
        credits_capability,
        unsupported_capability(
            "active_context",
            "Codex active session context requires the app-server status channel.",
        ),
    ];
    if snapshot.status == AgentStatusState::Degraded
        && snapshot
            .account
            .as_ref()
            .is_some_and(|account| account.login_state == AgentLoginState::SignedIn)
    {
        snapshot.status = AgentStatusState::Available;
    }
    // A failed usage read is a degraded reading even when the login works;
    // `codex_usage_probe_failed` is its stable code.
    if probe_failed && snapshot.status == AgentStatusState::Available {
        snapshot.status = AgentStatusState::Degraded;
    }
    append_current_plan_observation(&mut snapshot);
    let workspace_targets =
        append_codex_workspace_observations_at(&mut snapshot, codex_home, home_trust);
    stamp_codex_meter_identity(&mut snapshot);
    snapshot.runtime_defaults =
        build_codex_runtime_defaults_at(&snapshot.captured_at, codex_home, home_trust);
    (snapshot, strong_identity, workspace_targets)
}

fn collect_codex_usage_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    login_refresh: CodexLoginRefresh,
    quota_read: CodexQuotaRead,
) -> Result<CodexUsageProbe, codex_saved_quota::CodexQuotaFailure> {
    match quota_read {
        CodexQuotaRead::Saved => {
            codex_saved_quota::serve_saved(codex_home, home_trust, current_unix_seconds())
        }
        CodexQuotaRead::Provider => codex_saved_quota::read_provider_and_save(
            codex_home,
            home_trust,
            login_refresh,
            |_, _| true,
        )
        .unwrap_or_else(|| Err(codex_saved_quota::CODEX_QUOTA_NOT_READ_YET.to_string()))
        .map_err(|message| codex_saved_quota::CodexQuotaFailure {
            message,
            at_epoch_seconds: current_unix_seconds(),
        }),
    }
}

/// One provider read of a Codex home's quota from its local app-server.
/// Callers go through [`codex_saved_quota::read_provider_and_save`], which
/// saves the outcome.
fn read_codex_usage_from_provider(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    login_refresh: CodexLoginRefresh,
) -> Result<CodexUsageProbe, String> {
    collect_codex_app_server_usage_for_home(codex_home, home_trust, login_refresh)
}

fn stamp_codex_meter_identity(snapshot: &mut AgentStatusSnapshot) {
    let Some(account) = snapshot.account.as_ref() else {
        return;
    };
    let Some((account_identifier_hash, organization_identifier_hash)) = account
        .account_identifier_hash
        .clone()
        .zip(account.organization_identifier_hash.clone())
    else {
        snapshot.quota_windows.clear();
        snapshot.credit_balances.clear();
        return;
    };
    for window in &mut snapshot.quota_windows {
        window.account_identifier_hash = Some(account_identifier_hash.clone());
        window.organization_identifier_hash = Some(organization_identifier_hash.clone());
    }
    for balance in &mut snapshot.credit_balances {
        balance.account_identifier_hash = Some(account_identifier_hash.clone());
        balance.organization_identifier_hash = Some(organization_identifier_hash.clone());
    }
}

fn append_codex_credential_read_failed_diagnostic(snapshot: &mut AgentStatusSnapshot) {
    if snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_credential_read_failed")
    {
        return;
    }
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "codex_credential_read_failed",
        AgentDiagnosticSeverity::Warning,
        "Codex credentials could not be read safely; account-bound meters were suppressed.",
    ));
}

/// Assemble display-safe Codex runtime defaults from `~/.codex/config.toml` for
/// the agent-status upload. The backend overwrites `machine_id` from the stored
/// snapshot, so it is left unset here.
fn build_codex_runtime_defaults_at(
    captured_at: &str,
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Option<AgentRuntimeDefaults> {
    let body = ottto_core::read_codex_config_file_secure(codex_home, home_trust).ok()??;
    let raw = std::str::from_utf8(&body).ok()?;
    let defaults = crate::snapshots::parse_codex_config_defaults(raw)?;
    let fast_mode_enabled = defaults.display_fast_mode();
    Some(AgentRuntimeDefaults {
        captured_at: Some(captured_at.to_string()),
        provenance: Some("config_file".to_string()),
        machine_id: None,
        model: defaults.model,
        service_tier: defaults.service_tier,
        speed_mode: None,
        fast_mode_enabled,
        priority_enabled: None,
        reasoning_effort: defaults.reasoning_effort,
        reasoning_effort_by_model: BTreeMap::new(),
        approval_policy: defaults.approval_policy,
        sandbox_mode: None,
        selector_context: defaults.selector_context,
        selector_sources: defaults.selector_sources,
    })
}

/// macOS enterprise/MDM policy settings for Claude Code. Highest precedence in
/// Claude Code's own chain and not overridable by a developer, so it is applied
/// last.
const CLAUDE_MANAGED_SETTINGS_PATH: &str =
    "/Library/Application Support/ClaudeCode/managed-settings.json";

/// Claude Code settings files, lowest precedence first.
///
/// Claude Code's own order is user settings, then project settings, then local
/// project settings, then managed settings on top. Project-scoped
/// `.claude/settings*.json` files are intentionally out of scope here: the daemon
/// has no single project cwd, and a checked-out repository's settings are not a
/// machine default. `~/.claude/settings.local.json` is included because the
/// local MCP inventory already treats it as an override of `~/.claude/settings.json`.
fn claude_settings_paths() -> Vec<(String, PathBuf)> {
    vec![
        (
            "claude_code.settings".to_string(),
            home_path(".claude/settings.json"),
        ),
        (
            "claude_code.settings_local".to_string(),
            home_path(".claude/settings.local.json"),
        ),
        (
            "claude_code.managed_settings".to_string(),
            PathBuf::from(CLAUDE_MANAGED_SETTINGS_PATH),
        ),
    ]
}

/// Claude Code runtime defaults plus the honest marker for what we found.
struct ClaudeRuntimeDefaultsCapture {
    defaults: Option<AgentRuntimeDefaults>,
    capability: AgentCapabilityGap,
    diagnostic: Option<AgentStatusDiagnostic>,
}

/// Assemble display-safe Claude Code runtime defaults from the local settings
/// chain for the agent-status upload. The backend overwrites `machine_id` from
/// the stored snapshot, so it is left unset here.
fn build_claude_runtime_defaults(captured_at: &str) -> ClaudeRuntimeDefaultsCapture {
    claude_runtime_defaults_from_paths(captured_at, &claude_settings_paths())
}

fn claude_runtime_defaults_from_paths(
    captured_at: &str,
    paths: &[(String, PathBuf)],
) -> ClaudeRuntimeDefaultsCapture {
    let scopes: Vec<crate::snapshots::ClaudeSettingsScope<'_>> = paths
        .iter()
        .map(|(label, path)| crate::snapshots::ClaudeSettingsScope {
            label: label.as_str(),
            path: path.as_path(),
        })
        .collect();
    match crate::snapshots::load_claude_settings_defaults(&scopes) {
        crate::snapshots::ClaudeConfigDefaultsOutcome::Configured(defaults) => {
            ClaudeRuntimeDefaultsCapture {
                defaults: Some(AgentRuntimeDefaults {
                    captured_at: Some(captured_at.to_string()),
                    provenance: Some("config_file".to_string()),
                    machine_id: None,
                    model: defaults.model,
                    // Claude Code has no config-file service tier or speed mode;
                    // Fast is the only tier-shaped default it persists.
                    service_tier: None,
                    speed_mode: None,
                    fast_mode_enabled: defaults.fast_mode_enabled,
                    priority_enabled: None,
                    // The saved model's `/effort` (or the legacy top-level
                    // `effortLevel`), plus every model's saved effort. Reported
                    // exactly as configured; absent means absent.
                    reasoning_effort: defaults.reasoning_effort,
                    reasoning_effort_by_model: defaults.reasoning_effort_by_model,
                    approval_policy: defaults.approval_policy,
                    sandbox_mode: defaults.sandbox_mode,
                    selector_context: defaults.selector_context,
                    selector_sources: defaults.selector_sources,
                }),
                capability: supported_capability(
                    "runtime_defaults",
                    "Read display-safe Claude Code defaults from the local settings chain.",
                ),
                diagnostic: None,
            }
        }
        crate::snapshots::ClaudeConfigDefaultsOutcome::Unreadable => ClaudeRuntimeDefaultsCapture {
            defaults: None,
            capability: unsupported_capability(
                "runtime_defaults",
                "No readable Claude Code settings file was found on this Mac.",
            ),
            diagnostic: Some(AgentStatusDiagnostic::source(
                "claude_runtime_defaults_unreadable",
                AgentDiagnosticSeverity::Info,
                "No Claude Code settings file in the local chain could be read and parsed.",
            )),
        },
    }
}

fn apply_claude_statusline_context_provenance(
    snapshot: &mut AgentStatusSnapshot,
    full_oauth_quota_collected: bool,
) {
    // Context is an augmentation, not quota provenance. Keep the strong
    // full-meter proof when OAuth usage already supplied quota; otherwise
    // statusLine remains the honest partial source marker.
    if !full_oauth_quota_collected {
        snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
    }
}

/// A signed-in default login whose `.claude.json` identity could not be
/// trusted: keep the plan stored with the credential, claim no identity.
fn claude_signed_in_account_without_identity(
    credential_plan: Option<String>,
) -> AgentAccountStatus {
    let mut auth = serde_json::Map::new();
    auth.insert("loggedIn".to_string(), Value::Bool(true));
    auth.insert("authMethod".to_string(), Value::from("claude.ai"));
    auth.insert("apiProvider".to_string(), Value::from("firstParty"));
    if let Some(plan) = credential_plan {
        auth.insert("subscriptionType".to_string(), Value::from(plan));
    }
    parse_claude_auth_json(&Value::Object(auth))
}

/// A non-OAuth way the default Claude Code login authenticates. Claude Code
/// gives these precedence over the stored OAuth login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeAlternativeAuth {
    Bedrock,
    Vertex,
    ApiKey,
}

impl ClaudeAlternativeAuth {
    fn auth_method(self) -> &'static str {
        match self {
            Self::Bedrock => "bedrock",
            Self::Vertex => "vertex",
            Self::ApiKey => "api_key",
        }
    }

    fn api_provider(self) -> &'static str {
        match self {
            Self::Bedrock => "bedrock",
            Self::Vertex => "vertex",
            Self::ApiKey => "anthropic",
        }
    }

    /// How Claude Code usage is billed on this route.
    fn billing_channel(self) -> &'static str {
        match self {
            Self::Bedrock => "amazon_bedrock",
            Self::Vertex => "google_vertex",
            Self::ApiKey => "direct_api",
        }
    }
}

/// Whether a Claude login authenticates without OAuth, following Claude
/// Code 2.1.288's own rules (read statically from its source):
///
/// - Settings layers are applied low to high (`user`, `project`, `local`,
///   `flag`, `policy`); the highest layer that defines a value wins, and the
///   settings `env` overrides the process environment. `paths` must be ordered
///   lowest precedence first. `ambient` is the daemon's own environment,
///   consulted last.
/// - `CLAUDE_CODE_USE_BEDROCK` / `CLAUDE_CODE_USE_VERTEX` route all inference.
/// - `ANTHROPIC_AUTH_TOKEN` and `apiKeyHelper` are used ahead of OAuth.
/// - `ANTHROPIC_API_KEY` is used in an interactive session only once the user
///   approved it (its last 20 characters are in `.claude.json`
///   `customApiKeyResponses.approved`); otherwise only when no OAuth login is
///   usable. A Max user who declined the key stays on the subscription.
///
/// Only presence (and, for the API key, the approval suffix compared in
/// memory) is read; no value is kept.
fn claude_alternative_auth(
    paths: &[(String, PathBuf)],
    ambient: &dyn Fn(&str) -> Option<String>,
    oauth_usable: bool,
    approved_api_key_suffixes: &[String],
    stored_console_key: bool,
) -> Option<ClaudeAlternativeAuth> {
    // Highest precedence first.
    let layers = paths
        .iter()
        .rev()
        .filter_map(|(_, path)| {
            fs::read_to_string(path)
                .ok()
                .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        })
        .collect::<Vec<_>>();
    claude_alternative_auth_layers(
        &layers,
        ambient,
        oauth_usable,
        approved_api_key_suffixes,
        stored_console_key,
    )
}

/// The same precedence evaluator for a caller that has already read and
/// validated all layers (highest precedence first).
pub(crate) fn claude_alternative_auth_layers(
    layers: &[Value],
    ambient: &dyn Fn(&str) -> Option<String>,
    oauth_usable: bool,
    approved_api_key_suffixes: &[String],
    stored_console_key: bool,
) -> Option<ClaudeAlternativeAuth> {
    let present = |value: &Value| match value {
        Value::String(text) => !text.trim().is_empty(),
        Value::Null => false,
        _ => true,
    };
    let truthy = |value: Option<String>| {
        value.is_some_and(|text| {
            let text = text.trim().to_ascii_lowercase();
            !text.is_empty() && text != "0" && text != "false"
        })
    };
    let env_value = |key: &str| {
        layers
            .iter()
            .find_map(|layer| {
                layer
                    .get("env")
                    .and_then(|env| env.get(key))
                    .map(|value| match value {
                        Value::String(text) => text.clone(),
                        Value::Null => String::new(),
                        other => other.to_string(),
                    })
            })
            .or_else(|| ambient(key))
    };
    if truthy(env_value("CLAUDE_CODE_USE_BEDROCK")) {
        return Some(ClaudeAlternativeAuth::Bedrock);
    }
    if truthy(env_value("CLAUDE_CODE_USE_VERTEX")) {
        return Some(ClaudeAlternativeAuth::Vertex);
    }
    let auth_token =
        env_value("ANTHROPIC_AUTH_TOKEN").is_some_and(|value| !value.trim().is_empty());
    let api_key_helper = layers
        .iter()
        .find_map(|layer| layer.get("apiKeyHelper"))
        .is_some_and(present);
    if auth_token || api_key_helper {
        return Some(ClaudeAlternativeAuth::ApiKey);
    }
    let api_key_active = env_value("ANTHROPIC_API_KEY").is_some_and(|key| {
        let key = key.trim();
        !key.is_empty()
            && (!oauth_usable || {
                let suffix = key
                    .char_indices()
                    .rev()
                    .nth(19)
                    .map_or(key, |(index, _)| &key[index..]);
                approved_api_key_suffixes
                    .iter()
                    .any(|approved| approved == suffix)
            })
    });
    // A Console API key saved by `/login` ("/login managed key": the
    // `Claude Code` keychain item or `.claude.json` `primaryApiKey`). Counted
    // only when no OAuth login is usable, so a subscription stays one.
    (api_key_active || (stored_console_key && !oauth_usable))
        .then_some(ClaudeAlternativeAuth::ApiKey)
}

/// Whether a Console API key saved by `/login` is present for this login:
/// its `Claude Code` keychain item (`Claude Code-<hash>` for a registered
/// config dir, the same suffix as the OAuth item; presence only, read
/// without `-w`) or `.claude.json` `primaryApiKey`. No key value is kept.
fn claude_stored_console_key_present(slot: &ClaudeConfigDirSlot) -> bool {
    let in_config = fs::read_to_string(slot.identity_path(&home_dir()))
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .and_then(|value| {
            value
                .get("primaryApiKey")
                .and_then(Value::as_str)
                .map(|key| !key.trim().is_empty())
        })
        .unwrap_or(false);
    if in_config {
        return true;
    }
    if crate::command_env::executable_path("security").is_none() {
        return false;
    }
    let Some(account) = effective_user_account_name() else {
        return false;
    };
    run_command_capture(
        "security",
        &[
            "find-generic-password",
            "-a",
            &account,
            "-s",
            &slot
                .service_name()
                .replacen("Claude Code-credentials", "Claude Code", 1),
        ],
        COMMAND_TIMEOUT,
    )
    .success
}

/// `.claude.json` `customApiKeyResponses.approved`: suffixes of API keys the
/// user accepted in Claude Code.
fn claude_approved_api_key_suffixes(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .and_then(|value| {
            value
                .get("customApiKeyResponses")?
                .get("approved")?
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
        })
        .unwrap_or_default()
}

fn claude_default_alternative_auth_now(oauth_usable: bool) -> Option<ClaudeAlternativeAuth> {
    claude_alternative_auth_for_slot(
        &ClaudeConfigDirSlot::Default,
        &|key| std::env::var(key).ok(),
        oauth_usable,
        false,
    )
}

/// [`claude_alternative_auth`] for one login, read from that login's own
/// settings, `.claude.json` approvals and stored Console key. `ambient` is the
/// environment the Claude Code process for this login runs with.
///
/// `print_mode`: a `claude -p` run. Claude Code 2.1.288 (`Rb`: when the
/// session is non-interactive, `ANTHROPIC_API_KEY` is returned before the
/// `customApiKeyResponses` approval check) then uses any `ANTHROPIC_API_KEY`,
/// approved or not.
fn claude_alternative_auth_for_slot(
    slot: &ClaudeConfigDirSlot,
    ambient: &dyn Fn(&str) -> Option<String>,
    oauth_usable: bool,
    print_mode: bool,
) -> Option<ClaudeAlternativeAuth> {
    claude_alternative_auth(
        &claude_settings_paths_for_slot(slot),
        ambient,
        // The approval rule applies only while an OAuth login is usable.
        oauth_usable && !print_mode,
        &claude_approved_api_key_suffixes(&slot.identity_path(&home_dir())),
        !oauth_usable && claude_stored_console_key_present(slot),
    )
}

/// Claude Code's settings files for one login, lowest precedence first.
fn claude_settings_paths_for_slot(slot: &ClaudeConfigDirSlot) -> Vec<(String, PathBuf)> {
    match slot.config_dir() {
        None => claude_settings_paths(),
        Some(config_dir) => vec![
            (
                "claude_code.settings".to_string(),
                PathBuf::from(config_dir).join("settings.json"),
            ),
            (
                "claude_code.settings_local".to_string(),
                PathBuf::from(config_dir).join("settings.local.json"),
            ),
            (
                "claude_code.managed_settings".to_string(),
                PathBuf::from(CLAUDE_MANAGED_SETTINGS_PATH),
            ),
        ],
    }
}

/// A plan-usage snapshot younger than this is reused by `/usage`, which then
/// refreshes nothing.
const CLAUDE_USAGE_CACHE_REUSE_MS: i64 = 60_000;

/// Why the background refresher must not run `claude -p /usage` for this
/// login now. Claude Code 2.1.288's `/usage` returns without awaiting a token
/// refresh when:
///
/// - the stored scopes lack `user:profile`;
/// - `.claude.json` `oauthAccount.billingType` is `usage_based`;
/// - another credential takes precedence over the OAuth login (Bedrock,
///   Vertex, an auth token, `apiKeyHelper`, or an approved API key). Judged by
///   the same helper the status uses, with the refresher's own environment
///   (it starts Claude Code with a cleared environment, so only the login's
///   settings files count) and print-mode precedence: any `ANTHROPIC_API_KEY`
///   in those settings counts, approved or not;
/// - its plan-usage snapshot is under 60 seconds old (a later pass runs).
pub(crate) fn claude_refresher_skip_reason(
    slot: &ClaudeConfigDirSlot,
    live: &ClaudeLiveLogin,
    now: OffsetDateTime,
) -> Option<&'static str> {
    if !live
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.has_profile_scope)
    {
        return Some("no_profile_scope");
    }
    let config = fs::read_to_string(slot.identity_path(&home_dir()))
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok());
    let config = config.as_ref();
    if config.and_then(|value| value.get("oauthAccount")?.get("billingType")?.as_str())
        == Some("usage_based")
    {
        return Some("usage_billing");
    }
    if claude_alternative_auth_for_slot(slot, &|_| None, true, true).is_some() {
        return Some("other_auth");
    }
    let fetched_at_ms = config
        .and_then(|value| {
            claude_credit_pools::claude_cached_usage_fetched_at_ms(
                value.get("cachedUsageUtilization")?,
            )
        })
        .and_then(|ms| i64::try_from(ms).ok());
    let now_ms = i64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
    if fetched_at_ms.is_some_and(|fetched| {
        let age = now_ms - fetched;
        (0..CLAUDE_USAGE_CACHE_REUSE_MS).contains(&age)
    }) {
        return Some("usage_cached");
    }
    None
}

/// `slot_owned_bindings` names exact account+organization bindings that a
/// registered managed slot has proved it reads (see
/// `claude_slot_owned_usage_bindings`). For those, the default login is not a
/// second provider caller: it serves the shared account cache only.
/// Snapshot diagnostic for the default login's lifetime warning.
const CLAUDE_RELOGIN_APPROACHING_CODE: &str = "claude_relogin_approaching";

/// Warning: the default home's token belongs to a known account other than
/// the one its `.claude.json` names (Claude Desktop and the terminal signed
/// in as different accounts there).
const CLAUDE_DEFAULT_HOME_SPLIT_LOGIN_CODE: &str = "claude_default_home_split_login";
/// A Claude home's owner check (the default home or a registered slot): the
/// binding `.claude.json` names, and the stored token's owner once proven.
struct ClaudeTokenOwner {
    cached: Option<(String, String)>,
    proven: Option<claude_token_owner::ProvenOwner>,
}

impl ClaudeTokenOwner {
    fn proven_binding(&self) -> Option<(String, String)> {
        self.proven
            .as_ref()
            .map(|owner| (owner.account_hash.clone(), owner.organization_hash.clone()))
    }

    /// Proven to be exactly `expected`, account and organization.
    fn proves(&self, expected: &ClaudeSlotAccountBinding) -> bool {
        self.proven.as_ref().is_some_and(|owner| {
            owner.account_hash == expected.account_identifier_hash
                && owner.organization_hash == expected.organization_identifier_hash
        })
    }

    /// Proven and known, but not the account `.claude.json` names.
    fn split_login(&self) -> bool {
        self.proven.is_some() && self.proven_binding() != self.cached
    }

    /// Information only: the default home counts as the token owner's account.
    fn split_login_diagnostic(&self) -> Option<AgentStatusDiagnostic> {
        self.split_login().then(|| AgentStatusDiagnostic::source(
            CLAUDE_DEFAULT_HOME_SPLIT_LOGIN_CODE,
            AgentDiagnosticSeverity::Warning,
            "Claude Desktop and the terminal use different accounts in the default Claude folder; it counts as the terminal login's account.",
        ))
    }

    /// The binding the default slot is verified against when it is not the
    /// one `.claude.json` names: none while unproven, the owner's on a split.
    fn binding_override(&self) -> Option<Option<(String, String)>> {
        match &self.proven {
            None => Some(None),
            Some(_) if self.split_login() => Some(self.proven_binding()),
            Some(_) => None,
        }
    }
}

/// The proven owner of a home's stored token (`home` is `"default"` or the
/// slot id). A valid token may be sent when `calls_allowed` (the background
/// gates of `claude_owner_call_allowed`, or false for remembered verdicts
/// only). A lapsed token waiting for Claude Code's refresh is never sent: it
/// keeps the verdict remembered for that same token. Any other login state
/// has nothing to prove.
fn prove_claude_token_owner(
    home: &str,
    login_state: &ClaudeLocalLoginState,
    access_token: Option<&str>,
    calls_allowed: bool,
) -> Option<claude_token_owner::ProvenOwner> {
    let may_call = match login_state {
        ClaudeLocalLoginState::AccessValid => calls_allowed,
        ClaudeLocalLoginState::RefreshPending => false,
        _ => return None,
    };
    claude_token_owner::proven_owner(home, access_token?, may_call)
}

/// Prove the default home's token owner, only where the local files disagree:
/// a locally valid token whose plan contradicts `.claude.json`. A lapsed token
/// waiting for Claude Code's refresh is never sent; it keeps the verdict
/// remembered for that same token. Elsewhere (`None`) the default home keeps
/// its usual path. The owner is the cached account: the credential's plan is
/// stale and is dropped. The owner is another known account (a registered
/// slot with the same hashes): `stable` takes that account's own
/// `.claude.json`, so labels and plan facts come only from an account Ottto
/// knows. Anything else stays unproven and the caller fails closed.
fn resolve_claude_default_home_owner(
    login_state: &ClaudeLocalLoginState,
    stable: &mut StableClaudeSlotCredential,
    known_identities: &[ClaudeCliOauthAccount],
) -> Option<ClaudeTokenOwner> {
    let refresh_pending = *login_state == ClaudeLocalLoginState::RefreshPending;
    if !matches!(
        login_state,
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending
    ) || !claude_local_plan_facts_contradict(
        stable.credential.subscription_type.as_deref(),
        stable.oauth_account.organization_type.as_deref(),
    ) {
        return None;
    }
    let cached = claude_strong_oauth_identity_hashes(&stable.oauth_account);
    let owner = prove_claude_token_owner(
        "default",
        login_state,
        stable.credential.access_token.as_deref(),
        claude_owner_call_allowed(),
    );
    if refresh_pending && owner.is_none() {
        return None;
    }
    let mut resolved = ClaudeTokenOwner {
        cached,
        proven: owner,
    };
    if resolved.split_login() {
        let owner = resolved.proven_binding();
        match known_identities
            .iter()
            .find(|known| claude_strong_oauth_identity_hashes(known) == owner)
        {
            Some(known) => stable.oauth_account = known.clone(),
            None => resolved.proven = None,
        }
    } else if resolved.proven.is_some() {
        stable.credential.subscription_type = None;
    }
    Some(resolved)
}

/// The owner check's hashes on a home's local status.
fn apply_claude_token_owner(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    owner: Option<&ClaudeTokenOwner>,
) {
    let Some(owner) = owner else {
        return;
    };
    (status.cached_account_hash, status.cached_organization_hash) = owner.cached.clone().unzip();
    (
        status.token_owner_account_hash,
        status.token_owner_organization_hash,
    ) = owner.proven_binding().unzip();
    status.owner_proven_at = owner.proven.as_ref().map(|owner| owner.proven_at.clone());
}

/// Also returns this pass's exact Claude Desktop folder pairs, read in the same
/// single scan as the default snapshot's Desktop readings, and the default
/// home's owner check.
fn collect_claude_status(
    captured_at: String,
    expires_at: String,
    slot_owned_bindings: &BTreeSet<ClaudeStrongBinding>,
    keep_signed_in: bool,
    known_identities: &[ClaudeCliOauthAccount],
    desktop_metadata: &mut ClaudeDesktopMetadataCache,
) -> (
    AgentStatusSnapshot,
    ClaudeDesktopPairs,
    Option<ClaudeTokenOwner>,
) {
    // Presence is decided by the canonical detector, which requires the `claude`
    // binary. A lone `~/.claude/settings.json` — which Ottto's own relay-base
    // patch writes during onboarding — must NOT read as "installed", or a Mac
    // that never had Claude reports it as present and then fails verification
    // with "claude is not installed or not executable".
    let claude_desktop_root = claude_desktop_support_dir();
    let claude_cli_present =
        crate::agent_configs::detection::source_present_locally(&SourceKind::ClaudeCode);
    if !claude_cli_present && !claude_desktop_metadata_present(&claude_desktop_root) {
        return (
            not_installed_snapshot(SourceKind::ClaudeCode, "claude", captured_at, expires_at),
            ClaudeDesktopPairs::default(),
            None,
        );
    }
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    // Login state comes from local metadata only: `.claude.json` (before),
    // the stored credential, `.claude.json` (after). `claude auth status`
    // printed exactly these fields but could refresh, and so sign out, the
    // default login on every pass.
    let local = read_claude_slot_locally(&ClaudeConfigDirSlot::Default);
    let mut login_state = local.state;
    let default_live = local.live_login();
    // "Keep my Claude accounts signed in": the default login gets the same
    // single waiting background refresh as registered slots.
    let refresh = if claude_oauth_usage_network_disabled() {
        crate::claude_refresher::RefreshDecision::NotNeeded
    } else {
        crate::claude_refresher::maybe_refresh(
            "default",
            &ClaudeConfigDirSlot::Default,
            &default_live,
            keep_signed_in,
        )
    };
    if login_state == ClaudeLocalLoginState::RefreshPending
        && refresh == crate::claude_refresher::RefreshDecision::FailedWaitingForSignIn
    {
        // The background refresh could not advance this credential: ask for
        // sign-in (the app's "Sign in again" gate), no retry until it changes.
        login_state = ClaudeLocalLoginState::NeedsLogin;
    }
    if let Some(warning) = claude_relogin_warning(
        default_live
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.refresh_token_expires_at.as_deref()),
        OffsetDateTime::now_utc(),
    ) {
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            CLAUDE_RELOGIN_APPROACHING_CODE,
            AgentDiagnosticSeverity::Warning,
            warning,
        ));
    }
    let credential_plan = match &local.credential {
        ClaudeCredentialRead::Present(credential) => credential.subscription_type.clone(),
        ClaudeCredentialRead::Absent | ClaudeCredentialRead::Unreadable => None,
    };
    let mut stable_default_credential = stable_claude_slot_credential(
        local.initial_oauth_account,
        local.credential.into_credential(),
        local.final_oauth_account,
    );
    // `.claude.json` is only a display cache here: another writer (a Claude
    // Desktop session) may have written it for a different account than the
    // stored token's. Where the two disagree, the token's proven owner decides.
    let default_owner = stable_default_credential.as_mut().ok().and_then(|stable| {
        resolve_claude_default_home_owner(&login_state, stable, known_identities)
    });
    if let Some(owner) = &default_owner {
        snapshot.diagnostics.extend(owner.split_login_diagnostic());
        if owner.proven.is_none() {
            stable_default_credential = Err(ClaudeSlotProbeFailure::OwnerUnproven);
        }
    }
    // Claude Code uses a configured Bedrock/Vertex route or API key ahead of
    // the stored OAuth login, so it is evaluated first.
    let alternative = claude_default_alternative_auth_now(matches!(
        login_state,
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending
    ));
    match login_state {
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending => {
            snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
            let mut refined_seat_plan = None;
            let mut refined_max_plan = None;
            let account = match stable_default_credential.as_ref() {
                Ok(stable) => {
                    match claude_account_from_local_metadata(
                        &stable.oauth_account,
                        &stable.credential,
                    ) {
                        Ok(mut account) => {
                            match require_claude_auth_identity_agreement(
                                &account,
                                &stable.oauth_account,
                            ) {
                                Ok(()) => {
                                    let refined = refine_claude_local_plan_metadata(
                                        &mut account,
                                        &stable.oauth_account,
                                    );
                                    refined_seat_plan = refined.seat_plan;
                                    refined_max_plan = refined.max_plan;
                                    // Positive account + organization identity is
                                    // required before local metadata can stamp
                                    // full-meter identity.
                                    stamp_claude_cli_account_identity(
                                        &mut account,
                                        &stable.oauth_account,
                                    );
                                }
                                Err(failure) => snapshot
                                    .diagnostics
                                    .push(default_claude_identity_diagnostic(failure)),
                            }
                            account
                        }
                        Err(failure) => {
                            snapshot
                                .diagnostics
                                .push(default_claude_identity_diagnostic(failure));
                            claude_signed_in_account_without_identity(
                                (failure != ClaudeSlotProbeFailure::OwnerUnproven)
                                    .then(|| credential_plan.clone())
                                    .flatten(),
                            )
                        }
                    }
                }
                Err(failure) => {
                    snapshot
                        .diagnostics
                        .push(default_claude_identity_diagnostic(*failure));
                    // An unproven owner gets no plan either: the stored plan
                    // may be another account's.
                    claude_signed_in_account_without_identity(
                        (*failure != ClaudeSlotProbeFailure::OwnerUnproven)
                            .then(|| credential_plan.clone())
                            .flatten(),
                    )
                }
            };
            let mut account = account;
            if let Some(alternative) = alternative {
                // The OAuth login still supplies identity, plan and
                // subscription usage; Claude Code itself authenticates, and
                // bills its own usage, the other way.
                account.auth_method = Some(alternative.auth_method().to_string());
                account.billing_channel = Some(alternative.billing_channel().to_string());
            }
            snapshot.account = Some(account);
            snapshot.status = AgentStatusState::Available;
            if let Some(seat_plan) = refined_seat_plan {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_team_seat_tier_detected",
                    AgentDiagnosticSeverity::Info,
                    format!(
                        "Claude Team seat tier resolved to {seat_plan} from local Claude Code account metadata."
                    ),
                ));
            }
            if let Some(max_plan) = refined_max_plan.and_then(|plan| claude_plan_name(Some(plan))) {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_max_rate_limit_tier_detected",
                    AgentDiagnosticSeverity::Info,
                    format!(
                        "Claude plan tier resolved to {max_plan} from local Claude Code account metadata."
                    ),
                ));
            }
        }
        _ if alternative.is_some() => {
            // No usable OAuth login, but Claude Code authenticates another way:
            // signed in, with no subscription identity or usage.
            let alternative = alternative.expect("checked");
            let mut auth = serde_json::Map::new();
            auth.insert("loggedIn".to_string(), Value::Bool(true));
            auth.insert(
                "authMethod".to_string(),
                Value::from(alternative.auth_method()),
            );
            auth.insert(
                "apiProvider".to_string(),
                Value::from(alternative.api_provider()),
            );
            snapshot.account = Some(parse_claude_auth_json(&Value::Object(auth)));
            snapshot.status = AgentStatusState::Available;
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(
                    ClaudeSlotProbeFailure::IdentityUnknown,
                ));
        }
        ClaudeLocalLoginState::Unreadable => {
            // Fail closed: a failed or malformed read is not "signed out".
            snapshot.account = Some(unsupported_account("anthropic"));
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(
                    ClaudeSlotProbeFailure::ProbeFailed,
                ));
        }
        ClaudeLocalLoginState::NotSignedIn
        | ClaudeLocalLoginState::NeedsLogin
        | ClaudeLocalLoginState::SignedOutByCli => {
            snapshot.account = Some(unsupported_account("anthropic"));
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(
                    ClaudeSlotProbeFailure::CredentialUnavailable,
                ));
        }
    }
    let version_detected = claude_version_detected();
    snapshot.model = Some(AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: Some("anthropic".to_string()),
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    });
    let mut quota_capability = unsupported_capability(
        "quota_windows",
        "Claude Code rate-limit windows have not been observed from local OAuth usage or statusLine yet.",
    );
    // Resolved once, before any statusLine read: the statusLine cache is shared
    // by every Claude Code surface on this machine and names no account, so
    // serving it needs both the account that owns the credential now and the set
    // of other Claude accounts that could have written it. Desktop observations
    // are computed here rather than at their append site further down so the
    // gate and the snapshot agree and the session buckets are only scanned once.
    // The same resolution also scopes the OAuth usage read and stamps its
    // served windows, so cache scope, statusLine gate, and wire identity can
    // never disagree.
    let strong_oauth_identity = match (
        stable_default_credential.as_ref().ok(),
        snapshot.account.as_ref(),
    ) {
        (Some(stable), Some(account))
            if require_claude_auth_identity_agreement(account, &stable.oauth_account).is_ok() =>
        {
            claude_strong_oauth_identity_hashes(&stable.oauth_account)
        }
        _ => None,
    };
    let claude_account_identifier_hash = strong_oauth_identity
        .as_ref()
        .map(|(account_hash, _)| account_hash.clone())
        .unwrap_or_default();
    let ClaudeDesktopScan {
        observations: desktop_plan_observations,
        pairs: desktop_pairs,
    } = claude_desktop_scan_from_root(
        &claude_desktop_root,
        &snapshot.captured_at,
        desktop_metadata,
    );
    let observable_account_identifier_hashes =
        claude_account_identifier_hashes_from_observations(&desktop_plan_observations);
    let apply_statusline_quota = |snapshot: &mut AgentStatusSnapshot,
                                  quota_capability: &mut AgentCapabilityGap|
     -> bool {
        match collect_claude_statusline_quota_windows(
            &claude_account_identifier_hash,
            &observable_account_identifier_hashes,
        ) {
            Ok(ClaudeStatusLineQuota::Windows(windows)) if !windows.is_empty() => {
                snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                snapshot.diagnostics.push(claude_quota_check_diagnostic(
                        "claude_statusline_read_succeeded",
                        "The supported local statusLine cache was read successfully; its quota windows retain their original observation times.",
                        current_unix_seconds(),
                    ).with_quota_binding(windows[0].account_identifier_hash.clone(), windows[0].organization_identifier_hash.clone()));
                snapshot.quota_windows = windows;
                *quota_capability = supported_capability(
                    "quota_windows",
                    "Collected from Claude Code's local statusLine rate_limits payload.",
                );
                true
            }
            Ok(ClaudeStatusLineQuota::Unattributable(reason)) => {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                *quota_capability = unsupported_capability("quota_windows", reason.detail());
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    reason.code(),
                    AgentDiagnosticSeverity::Warning,
                    reason.detail(),
                ));
                false
            }
            Ok(_) => {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                false
            }
            Err(message) => {
                snapshot.quota_windows = vec![unsupported_quota_window("usage")];
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_statusline_cache_unavailable",
                    AgentDiagnosticSeverity::Warning,
                    message,
                ));
                false
            }
        }
    };
    if let (Some(stable), Some((account_hash, organization_hash)), Some(account)) = (
        stable_default_credential.as_ref().ok(),
        strong_oauth_identity.as_ref(),
        snapshot.account.as_mut(),
    ) {
        account.account_identifier_hash = Some(account_hash.clone());
        account.organization_identifier_hash = Some(organization_hash.clone());
        if account.account_id.is_none() {
            account.account_id = stable.oauth_account.account_uuid.clone();
        }
        if account.organization_id.is_none() {
            account.organization_id = stable.oauth_account.organization_uuid.clone();
        }
        account.billing_identity_evidence = billing_identity_evidence_for(
            &account.account_identifier_hash,
            &account.organization_identifier_hash,
            &account.credential_fingerprint_hash,
        );
    }
    let oauth_outcome = match (
        strong_oauth_identity.as_ref(),
        stable_default_credential.as_ref().ok(),
    ) {
        (Some((account_hash, organization_hash)), Some(stable)) => {
            let caller = if ClaudeStrongBinding::new(account_hash, organization_hash)
                .is_some_and(|binding| slot_owned_bindings.contains(&binding))
            {
                ClaudeOAuthUsageCaller::DefaultDeferredToSlot
            } else {
                ClaudeOAuthUsageCaller::Default
            };
            collect_claude_oauth_usage_with_credential(
                account_hash,
                organization_hash,
                stable.credential.access_token.clone(),
                stable.credential.access_expires_at.clone(),
                &caller,
                current_unix_seconds,
            )
        }
        _ => {
            claude_oauth_end_caller_run(&ClaudeOAuthUsageCaller::Default);
            ClaudeOAuthUsageOutcome::from(Err(
                "Claude OAuth usage requires strong matching local account and organization identity."
                    .to_string(),
            ))
        }
    };
    // Pushed before the quota branch below so the reason the endpoint was or
    // was not called rides the snapshot regardless of which source ends up
    // serving quota. These diagnostics are the alert channel for the circuit
    // breaker: they travel to the backend with the agent-status upload.
    snapshot.diagnostics.extend(oauth_outcome.diagnostics);
    let mut full_oauth_quota_collected = false;
    let mut account_weekly_not_offered = false;
    let mut account_session_not_offered = false;
    match oauth_outcome.result {
        Ok(usage) if !usage.windows.is_empty() => {
            full_oauth_quota_collected = true;
            account_weekly_not_offered = usage.account_weekly_not_offered;
            account_session_not_offered = usage.account_session_not_offered;
            snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
            snapshot.quota_windows = usage.windows;
            snapshot.credit_balances = usage.credit_balances;
            // StatusLine may be newer than the locally cached OAuth answer.
            // Only a source-proven exact account/workspace pair can replace
            // that pair's meter; scoped windows/credits stay independently dated.
            if let Ok(ClaudeStatusLineQuota::Windows(windows)) =
                collect_claude_statusline_quota_windows(
                    &claude_account_identifier_hash,
                    &observable_account_identifier_hashes,
                )
            {
                if prefer_newer_exact_claude_statusline_windows(
                    &mut snapshot.quota_windows,
                    windows,
                ) {
                    snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
                    snapshot.diagnostics.push(claude_quota_check_diagnostic(
                        "claude_statusline_newer_exact_binding_selected",
                        "Newer local statusLine readings replaced the matching account/workspace OAuth meters; other meters retain their own observation times.",
                        current_unix_seconds(),
                    ).with_quota_binding(Some(claude_account_identifier_hash.clone()), strong_oauth_identity.as_ref().map(|(_, organization)| organization.clone())));
                }
            }
            quota_capability = supported_capability(
                "quota_windows",
                "Collected from Claude Code's local OAuth usage endpoint.",
            );
        }
        Ok(_) => {
            apply_statusline_quota(&mut snapshot, &mut quota_capability);
        }
        Err(message) => {
            if !apply_statusline_quota(&mut snapshot, &mut quota_capability) {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_oauth_usage_unavailable",
                    AgentDiagnosticSeverity::Warning,
                    message,
                ));
            }
        }
    }
    let mut context_capability = unsupported_capability(
        "active_context",
        "Claude Code active context has not been observed from statusLine yet.",
    );
    match collect_claude_statusline_context_status() {
        Ok(context) => {
            if context.status == AgentContextState::Available {
                apply_claude_statusline_context_provenance(
                    &mut snapshot,
                    full_oauth_quota_collected,
                );
                context_capability = match context.completeness {
                    Some(AgentContextCompleteness::FullPressure) => supported_capability(
                        "active_context",
                        "Collected live context pressure from Claude Code's local statusLine context_window payload.",
                    ),
                    Some(AgentContextCompleteness::WindowSizeOnly) => supported_capability(
                        "active_context",
                        "Collected Claude Code context-window size from statusLine; live pressure fields have not been reported yet.",
                    ),
                    _ => supported_capability(
                        "active_context",
                        "Collected Claude Code's local statusLine context_window payload.",
                    ),
                };
            }
            snapshot.context = Some(context);
        }
        Err(message) => {
            snapshot.context = Some(AgentContextStatus {
                status: AgentContextState::Unknown,
                active_tokens: None,
                max_tokens: None,
                used_percent: None,
                remaining_tokens: None,
                source: Some("claude_statusline_context_window".to_string()),
                recent_samples: Vec::new(),
                observed_at: None,
                completeness: Some(AgentContextCompleteness::Unknown),
                reason: Some("statusline_context_cache_unreadable".to_string()),
                posture: None,
            });
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "claude_statusline_context_cache_unavailable",
                AgentDiagnosticSeverity::Warning,
                message,
            ));
        }
    }
    // Machine-local posture summary over recent sessions, derived by the
    // snapshot scan and cached (see `context_posture`). Independent of the
    // statusLine live-context channel: posture history is still served when
    // live pressure is unavailable, and vice versa.
    if let Some(context) = snapshot.context.as_mut() {
        context.posture = crate::context_posture::claude_context_posture_summary(
            &default_support_dir(),
            OffsetDateTime::now_utc(),
        );
    }
    let runtime_defaults = build_claude_runtime_defaults(&snapshot.captured_at);
    snapshot.runtime_defaults = runtime_defaults.defaults;
    snapshot.capabilities = vec![
        supported_capability(
            "account_status",
            "Read from local Claude Code login metadata (stored credential deadlines and .claude.json); no Claude command runs.",
        ),
        quota_capability,
        context_capability,
        runtime_defaults.capability,
    ];
    if account_weekly_not_offered {
        snapshot
            .capabilities
            .push(claude_account_weekly_not_offered_capability());
    }
    if account_session_not_offered {
        snapshot
            .capabilities
            .push(claude_account_session_not_offered_capability());
    }
    if let Some(diagnostic) = runtime_defaults.diagnostic {
        snapshot.diagnostics.push(diagnostic);
    }
    if version_detected {
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_version_detected",
            AgentDiagnosticSeverity::Info,
            "Claude Code CLI version detected.",
        ));
    }
    append_current_plan_observation(&mut snapshot);
    let desktop_observation_count =
        append_claude_desktop_plan_observations(&mut snapshot, desktop_plan_observations);
    if desktop_observation_count > 0 {
        if snapshot.status == AgentStatusState::Degraded {
            snapshot.status = AgentStatusState::Available;
        }
        snapshot.capabilities.push(supported_capability(
            "desktop_identity",
            "Read display-safe Claude Desktop account and session-bucket metadata.",
        ));
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_desktop_profile_detected",
            AgentDiagnosticSeverity::Info,
            "Claude Desktop Code account/session bucket metadata was detected.",
        ));
    }
    (snapshot, desktop_pairs, default_owner)
}

/// The registered-slot settings for one collection pass. A failed read is
/// retried once (a reader can land between a writer's two atomic renames of
/// the settings file and its sidecar) and then logged: such a pass must not
/// look like a machine without registered slots.
fn load_claude_slot_settings_for_pass(
) -> Result<ClaudeAccountsStatusV1, ottto_core::ClaudeConfigSlotSettingsError> {
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .load()
        .or_else(|_| {
            std::thread::sleep(Duration::from_millis(100));
            store.load()
        })
        .inspect_err(|_| eprintln!("claude_status registered_slots=unavailable"))
}

/// A failing registered-slot settings read keeps the last saved slot states
/// and withholds default uploads for slot-owned accounts for at most this
/// long, or this many consecutive passes.
const CLAUDE_SETTINGS_FAILURE_BOUND: Duration = Duration::from_secs(60 * 60);
const CLAUDE_SETTINGS_FAILURE_BOUND_PASSES: u32 = 6;

/// Whether a run of failed settings reads (first failure at `since`, `passes`
/// consecutive failed passes) has outlasted the bound. Pure.
fn claude_settings_failure_outlasted(since: Instant, passes: u32, now: Instant) -> bool {
    now.saturating_duration_since(since) >= CLAUDE_SETTINGS_FAILURE_BOUND
        || passes >= CLAUDE_SETTINGS_FAILURE_BOUND_PASSES
}

/// Record this pass's settings read and say whether the failure run has
/// outlasted the bound. A successful read resets it.
fn claude_settings_failure_bound_exceeded(failed: bool) -> bool {
    static RUN: OnceLock<Mutex<Option<(Instant, u32)>>> = OnceLock::new();
    let mut run = RUN
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !failed {
        *run = None;
        return false;
    }
    let (since, passes) = run.get_or_insert((Instant::now(), 0));
    *passes += 1;
    claude_settings_failure_outlasted(*since, *passes, Instant::now())
}

fn collect_claude_status_snapshots(
    captured_at: String,
    expires_at: String,
    desktop_metadata: &mut ClaudeDesktopMetadataCache,
) -> AgentStatusCollection {
    // Every caller that does not reach the usage collector during this pass
    // has its passive sign-in run ended when the pass ends, whatever made it
    // skip (an identity gate, upkeep, a failed settings load, capacity, a
    // missing binary, a later `continue`).
    let _pass = ClaudeOAuthCollectionPass::begin();
    let settings = load_claude_slot_settings_for_pass().map(annotate_claude_accounts_status);
    let settings_failure_outlasted = claude_settings_failure_bound_exceeded(settings.is_err());
    if settings_failure_outlasted {
        eprintln!("claude_status registered_slots=unavailable_past_bound saved_slot_states=stale");
    }
    // Each slot's own `.claude.json`, read once for this pass: the usage
    // bindings below and the accounts the default home's owner may be.
    let slot_accounts: BTreeMap<String, ClaudeCliOauthAccount> = settings
        .as_ref()
        .map(ordered_claude_slot_descriptors)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|descriptor| {
            let slot = claude_config_slot_for_descriptor(&descriptor)?;
            let account = read_claude_cli_oauth_account(&slot.identity_path(&home_dir()))?;
            Some((descriptor.slot_id, account))
        })
        .collect();
    let slot_owned_bindings = settings
        .as_ref()
        .map(|status| {
            claude_slot_owned_usage_bindings(
                status,
                |descriptor| {
                    let (account, organization) = slot_accounts
                        .get(&descriptor.slot_id)
                        .and_then(claude_strong_oauth_identity_hashes)?;
                    ClaudeStrongBinding::new(&account, &organization)
                },
                |slot_id| crate::claude_browser_auth::collection_suppression(slot_id).is_some(),
                |binding, slot_id| {
                    read_claude_oauth_usage_breaker_with_legacy_migration(
                        &binding.account_identifier_hash,
                        &binding.organization_identifier_hash,
                        &claude_oauth_usage_config_fingerprint(),
                        false,
                    )
                    .is_some_and(|breaker| {
                        claude_oauth_usage_caller_auth_hold(
                            &breaker,
                            &ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.to_string()),
                            current_unix_seconds(),
                            None,
                        )
                        .is_some()
                    })
                },
            )
        })
        .unwrap_or_default();
    let upkeep_consent = settings.as_ref().is_ok_and(|status| {
        status.consent == ottto_protocol::ClaudeAccountUpkeepConsentState::Granted
    });
    let known_identities: Vec<ClaudeCliOauthAccount> = slot_accounts.into_values().collect();
    let (mut default_snapshot, desktop_pairs, default_owner) = collect_claude_status(
        captured_at.clone(),
        expires_at.clone(),
        &slot_owned_bindings,
        upkeep_consent,
        &known_identities,
        desktop_metadata,
    );
    let mut candidates = Vec::new();
    let mut descriptors = settings
        .as_ref()
        .map(ordered_claude_slot_descriptors)
        .unwrap_or_else(|_| {
            vec![ClaudeConfigDirSlot::Default
                .descriptor("default", ClaudeConfigSlotOwnership::External)]
        });
    if descriptors.is_empty() {
        descriptors.push(
            ClaudeConfigDirSlot::Default.descriptor("default", ClaudeConfigSlotOwnership::External),
        );
    }

    let mut slot_states = BTreeMap::new();
    let mut default_state = prepare_default_claude_slot_status(
        &mut default_snapshot,
        crate::command_env::claude_default_login_executable_path(&home_dir()).is_some(),
    );
    if let Some(warning) = default_snapshot
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == CLAUDE_RELOGIN_APPROACHING_CODE)
    {
        default_state
            .diagnostics
            .push(ClaudeConfigSlotDiagnosticV1 {
                code: ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
                message: warning.message.clone(),
            });
    }
    remember_claude_slot_account_profile(
        &mut default_state,
        default_snapshot.account.as_ref(),
        &captured_at,
    );
    match default_owner
        .as_ref()
        .and_then(ClaudeTokenOwner::binding_override)
    {
        Some(binding) => retain_verified_claude_binding("default", binding, &mut default_state),
        None => retain_verified_claude_slot_binding(
            "default",
            &ClaudeConfigDirSlot::Default,
            &mut default_state,
        ),
    }
    apply_claude_token_owner(&mut default_state, default_owner.as_ref());
    apply_claude_quota_access_state(&mut default_snapshot, &default_state);
    slot_states.insert("default".to_string(), default_state.clone());
    if claude_slot_status_carries_meters(&default_state) {
        if let Some(quality) = claude_snapshot_candidate_rank(&default_snapshot) {
            if let Some(binding) = default_snapshot.account.as_ref().and_then(|account| {
                ClaudeStrongBinding::new(
                    account.account_identifier_hash.as_deref()?,
                    account.organization_identifier_hash.as_deref()?,
                )
            }) {
                candidates.push(ClaudeSnapshotCandidate {
                    slot_id: "default".to_string(),
                    slot_class: ClaudeSnapshotSlotClass::Default,
                    binding,
                    quality,
                    snapshot: default_snapshot.clone(),
                });
            }
        }
    }

    let mut blocked_worker_receipt_descriptors = BTreeMap::new();
    let mut custom_descriptors = descriptors
        .into_iter()
        .filter(|descriptor| descriptor.slot_id != "default")
        .collect::<Vec<_>>();
    custom_descriptors.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let (custom_descriptors, overflow_descriptors) =
        bounded_claude_custom_descriptors(custom_descriptors);
    for descriptor in overflow_descriptors {
        slot_states.insert(descriptor.slot_id, capacity_exceeded_status(&captured_at));
    }
    let previous_states = read_persisted_claude_slot_collection_state();
    for descriptor in custom_descriptors {
        match crate::claude_browser_auth::collection_suppression(&descriptor.slot_id) {
            Some(
                crate::claude_browser_auth::ClaudeCollectionSuppression::HideProvisionalTarget,
            ) => {
                claude_oauth_end_slot_run(&descriptor.slot_id);
                continue;
            }
            Some(
                crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveCanonicalReconnect
                | crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveWhileStateUnavailable,
            ) => {
                claude_oauth_end_slot_run(&descriptor.slot_id);
                slot_states.insert(descriptor.slot_id.clone(), descriptor.collection.clone());
                continue;
            }
            None => {}
        }
        let previous = previous_states.slots.get(&descriptor.slot_id);
        let step = collect_registered_claude_slot_step(
            &descriptor,
            previous,
            upkeep_consent,
            &captured_at,
            &expires_at,
        );
        match step {
            ClaudeSlotCollectionStep::PreGateRefused(status)
            | ClaudeSlotCollectionStep::Stopped(status)
            | ClaudeSlotCollectionStep::UsageFailed(status) => {
                slot_states.insert(descriptor.slot_id, status);
            }
            ClaudeSlotCollectionStep::UpkeepBlocked { status, paused } => {
                if status.state == ClaudeConfigSlotCollectionStateV1::RefreshDue && !paused {
                    blocked_worker_receipt_descriptors
                        .insert(descriptor.slot_id.clone(), descriptor.clone());
                }
                slot_states.insert(descriptor.slot_id, status);
            }
            ClaudeSlotCollectionStep::Collected {
                mut snapshot,
                status,
                account_identifier_hash,
                organization_identifier_hash,
            } => {
                apply_claude_quota_access_state(&mut snapshot, &status);
                if claude_slot_status_carries_meters(&status) {
                    let quality = claude_snapshot_candidate_rank(&snapshot)
                        .expect("validated custom meter snapshot is rankable");
                    candidates.push(ClaudeSnapshotCandidate {
                        slot_id: descriptor.slot_id.clone(),
                        slot_class: ClaudeSnapshotSlotClass::Registered,
                        binding: ClaudeStrongBinding {
                            account_identifier_hash,
                            organization_identifier_hash,
                        },
                        quality,
                        snapshot,
                    });
                }
                slot_states.insert(descriptor.slot_id, status);
            }
        }
    }
    let approvals = claude_slot_approvals();
    for (slot_id, status) in &mut slot_states {
        inherit_claude_slot_account_profile(status, previous_states.slots.get(slot_id));
        if slot_id != "default" {
            apply_claude_slot_approval_notice(status, approvals.get(slot_id));
        }
    }
    let mut quarantined_slots = claude_cross_binding_meter_collisions(&candidates);
    for slot_id in &quarantined_slots {
        if let Some(status) = slot_states.get_mut(slot_id) {
            quarantine_claude_cross_account_meters(status);
        }
        if slot_id == "default" {
            default_snapshot.quota_windows.clear();
            default_snapshot.credit_balances.clear();
        }
    }
    candidates.retain(|candidate| !quarantined_slots.contains(&candidate.slot_id));
    let stale_collisions = claude_stale_cross_binding_meter_collisions(&candidates, &slot_states);
    for slot_id in &stale_collisions {
        if let Some(status) = slot_states.get_mut(slot_id) {
            quarantine_claude_cross_account_meters(status);
        }
        if slot_id == "default" {
            default_snapshot.quota_windows.clear();
            default_snapshot.credit_balances.clear();
        }
    }
    quarantined_slots.extend(stale_collisions);
    candidates.retain(|candidate| !quarantined_slots.contains(&candidate.slot_id));
    if let Some(status) = slot_states.get("default") {
        default_state = status.clone();
    }

    let mut registered_slot_ids = settings
        .as_ref()
        .map(|status| {
            status
                .managed_slots
                .iter()
                .chain(status.external_slots.iter())
                .map(|slot| slot.slot_id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    registered_slot_ids.sort();
    let canonical_anchors = canonical_registered_anchors(registered_slot_ids.clone(), &slot_states);
    let anchor_health_by_binding = canonical_anchor_health(&canonical_anchors, &slot_states);
    // Past the bound, saved ownership no longer withholds the default upload.
    let mut registered_owned = if settings_failure_outlasted {
        BTreeSet::new()
    } else {
        claude_registered_owned_bindings(
            settings.is_ok(),
            &registered_slot_ids,
            &slot_states,
            &previous_states.slots,
        )
    };
    registered_owned.extend(slot_owned_bindings.iter().cloned());
    let selection = select_claude_snapshot_candidates(&candidates, &canonical_anchors);
    let winning_accounts = selection
        .winning_by_binding
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let dispositions = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            claude_snapshot_candidate_disposition(index, candidate, &selection)
        })
        .collect::<Vec<_>>();
    for (binding, slot_id) in &canonical_anchors {
        if let Some(status) = slot_states.get_mut(slot_id) {
            status.relationship =
                Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::CanonicalAnchor);
        }
        for duplicate_slot_id in &registered_slot_ids {
            if duplicate_slot_id == slot_id {
                continue;
            }
            let duplicate_matches = slot_states.get(duplicate_slot_id).is_some_and(|status| {
                status.account_identifier_hash.as_deref()
                    == Some(binding.account_identifier_hash.as_str())
                    && status.organization_identifier_hash.as_deref()
                        == Some(binding.organization_identifier_hash.as_str())
            });
            if duplicate_matches {
                if let Some(status) = slot_states.get_mut(duplicate_slot_id) {
                    status.state = ClaudeConfigSlotCollectionStateV1::DuplicateAccount;
                    status.relationship =
                        Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::DuplicateAnchor);
                }
            }
        }
    }
    if let Some(default_status) = slot_states.get_mut("default") {
        if default_status
            .account_identifier_hash
            .as_deref()
            .and_then(|account| {
                ClaudeStrongBinding::new(
                    account,
                    default_status.organization_identifier_hash.as_deref()?,
                )
            })
            .is_some_and(|binding| canonical_anchors.contains_key(&binding))
        {
            default_status.relationship =
                Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor);
        }
    }
    let mut snapshots = Vec::with_capacity(selection.winning_by_binding.len());
    // Slot id and binding of each candidate upload, in `snapshots` order.
    let mut uploaded_slots = Vec::with_capacity(selection.winning_by_binding.len());
    for (index, candidate) in candidates.into_iter().enumerate() {
        match dispositions[index] {
            ClaudeSnapshotDisposition::Upload => {
                if claude_default_upload_withheld(&candidate, &registered_owned, &canonical_anchors)
                {
                    // A registered slot owns this account but produced no
                    // anchor this pass (its settings read failed or it dropped
                    // out). Upload nothing for it rather than a default-only
                    // snapshot; the backend keeps the last anchored one.
                    eprintln!(
                        "claude_status default_upload=withheld reason=slot_owned_without_anchor"
                    );
                    continue;
                }
                uploaded_slots.push((candidate.slot_id.clone(), candidate.binding.clone()));
                snapshots.push(claude_uploaded_candidate_snapshot(
                    candidate,
                    &anchor_health_by_binding,
                    &canonical_anchors,
                    &slot_states,
                    &registered_owned,
                ));
            }
            ClaudeSnapshotDisposition::ShadowDefault => {
                if let Some(status) = slot_states.get_mut(&candidate.slot_id) {
                    status.relationship =
                        Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor);
                }
            }
            ClaudeSnapshotDisposition::DuplicateRegistered => {
                if let Some(status) = slot_states.get_mut(&candidate.slot_id) {
                    status.state = ClaudeConfigSlotCollectionStateV1::DuplicateAccount;
                    status.relationship =
                        Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::DuplicateAnchor);
                }
            }
            ClaudeSnapshotDisposition::PreserveRegisteredAnchor => {
                // A healthier default may temporarily supply the uploaded
                // meters. Keep the best registered anchor's exact collection,
                // upkeep, and reconnect state intact for continuity.
            }
        }
    }
    let default_binding = default_snapshot.account.as_ref().and_then(|account| {
        ClaudeStrongBinding::new(
            account.account_identifier_hash.as_deref()?,
            account.organization_identifier_hash.as_deref()?,
        )
    });
    if let Some(index) = claude_runtime_defaults_carrier(
        &snapshots,
        &uploaded_slots,
        default_snapshot.runtime_defaults.is_some(),
        default_binding.as_ref(),
    ) {
        snapshots[index].runtime_defaults = default_snapshot.runtime_defaults.clone();
    }
    snapshots.extend(degraded_claude_slot_snapshots(
        &slot_states,
        &canonical_anchors,
        &winning_accounts,
        &captured_at,
        &expires_at,
    ));
    append_claude_desktop_pairs_snapshot(&mut snapshots, &desktop_pairs, &captured_at, &expires_at);
    let unresolved_accounts = derive_unresolved_claude_accounts(
        &default_snapshot,
        &desktop_pairs,
        &snapshots,
        &slot_states,
        OffsetDateTime::parse(&captured_at, &Rfc3339).unwrap_or_else(|_| OffsetDateTime::now_utc()),
    );
    // Without the registered set this pass saw only the default login: keep
    // the last persisted slot states rather than overwrite them with it.
    if settings.is_ok() {
        let _ = persist_claude_slot_collection_states(
            &slot_states,
            &unresolved_accounts,
            &blocked_worker_receipt_descriptors,
        );
    } else if settings_failure_outlasted {
        // Past the bound the saved registered-slot states are stale: a fresh
        // one becomes a transient read failure (no repair asked).
        let _ = persist_claude_slot_collection_states(
            &claude_stale_saved_slot_states(&previous_states.slots),
            &unresolved_accounts,
            &BTreeMap::new(),
        );
    }

    let mut source_health_snapshot = default_snapshot.clone();
    let mut custom_slot_states = slot_states
        .iter()
        .filter(|(slot_id, _)| slot_id.as_str() != "default")
        .map(|(_, status)| status);
    let has_healthy_custom_account = custom_slot_states
        .clone()
        .any(|status| status.state == ClaudeConfigSlotCollectionStateV1::Fresh);
    let has_actionable_custom_slot =
        custom_slot_states.any(|status| claude_custom_slot_needs_attention(&status.state));
    let default_has_full_meter_evidence = default_snapshot
        .quota_windows
        .iter()
        .any(|window| window.organization_identifier_hash.is_some())
        || !default_snapshot.credit_balances.is_empty();
    let default_full_meter_needs_attention = claude_default_full_meter_needs_attention(
        default_has_full_meter_evidence,
        &default_state.state,
    );
    if has_actionable_custom_slot || default_full_meter_needs_attention {
        let current_login_available = source_health_snapshot.status == AgentStatusState::Available;
        if current_login_available {
            source_health_snapshot.status = AgentStatusState::Degraded;
        }
        source_health_snapshot
            .diagnostics
            .push(AgentStatusDiagnostic::source(
                if current_login_available {
                    "claude_registered_slot_needs_attention_current_available"
                } else {
                    "claude_registered_slot_needs_attention"
                },
                AgentDiagnosticSeverity::Warning,
                "One or more registered Claude account slots need local attention; healthy accounts continue collecting independently.",
            ));
    } else if has_healthy_custom_account {
        source_health_snapshot.status = AgentStatusState::Available;
    }
    // Usage checks that are paused for an account (an auth hold or an open
    // breaker, or a provider that stopped answering) are not a repair the
    // operator makes, so they never degrade `status` above. They still must
    // not leave the source looking fully healthy: the local source-health
    // copy carries one plain-words diagnostic that `ottto apps` turns into an
    // attention grade. Only this machine-local copy is touched; the uploaded
    // snapshots are unchanged.
    let now_epoch = current_unix_seconds();
    if let Some(diagnostic) = claude_usage_checks_paused_diagnostic(&claude_paused_usage_accounts(
        &slot_states,
        &default_snapshot,
        |account, organization| {
            read_claude_oauth_usage_breaker_with_legacy_migration(
                account,
                organization,
                &claude_oauth_usage_config_fingerprint(),
                false,
            )
        },
        now_epoch,
    )) {
        source_health_snapshot.diagnostics.push(diagnostic);
    }
    append_registered_claude_plan_observations(&mut source_health_snapshot, &snapshots);

    AgentStatusCollection {
        snapshots,
        source_health_snapshot,
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    }
}

/// Whether one registered Claude slot's collection state is something the
/// operator has to act on.
///
/// "Needs attention" is reserved for a repair the operator can actually make in
/// Ottto. Two families of state are not that:
///
/// - A duplicate registration resolves to an account another registered slot
///   already owns, so its meters come from that owner and nothing is expired,
///   mismatched, or waiting on a login. Codex has always treated its own
///   `DuplicateAccount` this way; Claude counting it as actionable degraded a
///   fully healthy source and told the operator their durable connections
///   needed repair while every slot was fresh and metered.
/// - A transient read failure means the meters could not be read right now.
///   `projected_claude_quota_access_state` already classifies these
///   `TemporarilyUnavailable`, the credential is untouched, background upkeep
///   keeps running, and the failed-verification re-verify backoff clears them
///   without the operator doing anything. Their approved copy names no action
///   ("Ottto could not read current limits", "Staged"), unlike `NeedsLogin`,
///   `StaleAccessToken`, `ReloginApproaching` and `IdentityMismatch`, which
///   all tell the operator to sign in again and so stay actionable here.
/// - `ConcurrentMutation` is a race: Claude Code rewrote the login's account
///   metadata between two reads of one pass. The slot keeps its last verified
///   account (`retain_verified_claude_binding`), the quota projection is
///   `TemporarilyUnavailable`, and the next pass retries from a stable read.
///   It is not proof of another account or of a lost login, so it never asks
///   the operator to act.
fn claude_custom_slot_needs_attention(state: &ClaudeConfigSlotCollectionStateV1) -> bool {
    !matches!(
        state,
        ClaudeConfigSlotCollectionStateV1::Fresh
            | ClaudeConfigSlotCollectionStateV1::Unverified
            | ClaudeConfigSlotCollectionStateV1::DuplicateAccount
            | ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
            | ClaudeConfigSlotCollectionStateV1::ProbeFailed
            | ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
            | ClaudeConfigSlotCollectionStateV1::CollectionInProgress
            | ClaudeConfigSlotCollectionStateV1::RefreshDue
    )
}

/// The default slot's own path to the same warning. It carried its own
/// `!= Fresh` comparison, so a default slot whose provider read failed raised
/// the unactionable warning even once the custom-slot predicate stopped. Both
/// branches ask the same question.
fn claude_default_full_meter_needs_attention(
    has_full_meter_evidence: bool,
    state: &ClaudeConfigSlotCollectionStateV1,
) -> bool {
    has_full_meter_evidence && claude_custom_slot_needs_attention(state)
}

/// Machine-local diagnostic code on the Claude source-health copy when usage
/// checks are paused for at least one connected account. `ottto apps` reads it
/// to grade the source as needing attention. It is never uploaded.
pub(crate) const CLAUDE_USAGE_CHECKS_PAUSED_DIAGNOSTIC_CODE: &str = "claude_usage_checks_paused";

/// One connected Claude account whose usage checks are paused right now.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudePausedUsageAccount {
    /// The provider rejected this account's sign-in (auth hold or open
    /// breaker), as opposed to the provider not answering.
    after_sign_in_rejection: bool,
    /// When Ottto may automatically check this account again, if known.
    next_check_epoch_seconds: Option<u64>,
}

/// A slot diagnostic that proves the provider rejected this slot's sign-in
/// and the slot is now held back. Matches both the raw producer text and the
/// sanitized slot-state copy of the circuit-open alert.
fn claude_diagnostic_is_auth_pause(diagnostic: &AgentStatusDiagnostic) -> bool {
    match diagnostic.code.as_str() {
        "claude_oauth_usage_auth_rejected" | "claude_oauth_usage_auth_backoff" => true,
        "claude_oauth_usage_circuit_open" => diagnostic.message.contains("auth"),
        _ => false,
    }
}

/// When the breaker next lets any caller for this account ask the provider.
/// An account-wide auth verdict gates every caller; otherwise the earliest
/// live per-caller hold is the next possible automatic check.
fn claude_breaker_auth_pause_until(breaker: &ClaudeOAuthUsageBreaker, now: u64) -> Option<u64> {
    if breaker.opened_by == "auth_rejected" && now < breaker.reopen_after_epoch_seconds {
        return Some(breaker.reopen_after_epoch_seconds);
    }
    breaker
        .auth_callers
        .values()
        .map(|state| state.backoff_until_epoch_seconds)
        .filter(|until| now < *until)
        .min()
}

/// Connected Claude accounts whose usage checks are paused.
///
/// An account is served, and so not paused, only while some slot for it is
/// `Fresh` through an ELIGIBLE provider caller: that caller has no live auth
/// hold, the account has no open auth breaker, and the slot carries no
/// sign-in-rejection or breaker-suppression evidence. `Fresh` alone is not
/// proof: the default login marks account-attributed status-line fallback
/// readings `Fresh`, and a held slot can look `Fresh` while the shared cache
/// is young. An eligible caller reusing its own young cache still counts as
/// serving, because it will ask the provider on its normal cadence.
///
/// An unserved account counts when some non-duplicate slot for it is held
/// back after a sign-in rejection (slot diagnostics, the default login's own
/// diagnostics, or a live breaker hold) or is `provider_unavailable` with only
/// stale readings. Slots whose state already raises the registered-slot
/// attention path are left to that path, so the same account is never
/// reported twice.
fn claude_paused_usage_accounts(
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    default_snapshot: &AgentStatusSnapshot,
    breaker_for: impl Fn(&str, &str) -> Option<ClaudeOAuthUsageBreaker>,
    now: u64,
) -> Vec<ClaudePausedUsageAccount> {
    #[derive(Default)]
    struct AccountEvidence {
        breaker: Option<ClaudeOAuthUsageBreaker>,
        served: bool,
        auth_paused: bool,
        provider_stale: bool,
    }
    let default_binding = default_snapshot.account.as_ref().and_then(|account| {
        Some((
            account.account_identifier_hash.clone()?,
            account.organization_identifier_hash.clone()?,
        ))
    });
    let default_auth_paused = default_snapshot
        .diagnostics
        .iter()
        .any(claude_diagnostic_is_auth_pause);
    let mut accounts: BTreeMap<(String, String), AccountEvidence> = BTreeMap::new();
    for (slot_id, status) in slot_states {
        let (Some(account), Some(organization)) = (
            status
                .account_identifier_hash
                .as_deref()
                .filter(|value| !value.is_empty()),
            status
                .organization_identifier_hash
                .as_deref()
                .filter(|value| !value.is_empty()),
        ) else {
            continue;
        };
        let key = (account.to_string(), organization.to_string());
        let is_default = slot_id == "default";
        let entry = accounts
            .entry(key.clone())
            .or_insert_with(|| AccountEvidence {
                breaker: breaker_for(account, organization),
                ..Default::default()
            });
        let caller = if is_default {
            ClaudeOAuthUsageCaller::Default
        } else {
            ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.clone())
        };
        // The same rotation-aware hold the collector applies: a credential
        // whose access expiry differs from the rejected one is not held.
        let (account_auth_open, caller_held) =
            entry.breaker.as_ref().map_or((false, false), |breaker| {
                (
                    breaker.opened_by == "auth_rejected"
                        && now < breaker.reopen_after_epoch_seconds,
                    claude_oauth_usage_caller_auth_hold(
                        breaker,
                        &caller,
                        now,
                        status.access_expires_at.as_deref(),
                    )
                    .is_some(),
                )
            });
        let slot_auth_evidence = status
            .quota_check_diagnostics
            .iter()
            .any(claude_diagnostic_is_auth_pause)
            || (is_default && default_auth_paused && default_binding.as_ref() == Some(&key));
        let slot_suppressed = status
            .quota_check_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "claude_oauth_usage_check_suppressed");
        if status.state == ClaudeConfigSlotCollectionStateV1::Fresh {
            if !account_auth_open && !caller_held && !slot_auth_evidence && !slot_suppressed {
                entry.served = true;
            } else if account_auth_open || caller_held || slot_auth_evidence {
                // Fresh-looking readings from a held caller (status-line
                // fallback or a young shared cache) are not service.
                entry.auth_paused = true;
            }
            continue;
        }
        if status.state == ClaudeConfigSlotCollectionStateV1::DuplicateAccount
            || status.relationship
                == Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::DuplicateAnchor)
            || claude_custom_slot_needs_attention(&status.state)
        {
            continue;
        }
        entry.auth_paused |= slot_auth_evidence || caller_held || account_auth_open;
        entry.provider_stale |= status.state
            == ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
            && status.quota_snapshot.as_ref().is_some_and(|snapshot| {
                snapshot.state == ClaudeConfigSlotQuotaSnapshotStateV1::Stale
            });
    }
    accounts
        .into_values()
        .filter(|evidence| !evidence.served && (evidence.auth_paused || evidence.provider_stale))
        .map(|evidence| {
            let held_until = evidence
                .breaker
                .as_ref()
                .and_then(|breaker| claude_breaker_auth_pause_until(breaker, now));
            ClaudePausedUsageAccount {
                after_sign_in_rejection: evidence.auth_paused || held_until.is_some(),
                next_check_epoch_seconds: held_until,
            }
        })
        .collect()
}

/// One plain-words diagnostic for every paused account. It names accounts
/// only, never asks the operator to sign in again, and never implies Ottto
/// will check sooner than its own schedule. It avoids "quota" and "limit"
/// wording so no consumer mistakes it for a used-up plan.
fn claude_usage_checks_paused_diagnostic(
    paused: &[ClaudePausedUsageAccount],
) -> Option<AgentStatusDiagnostic> {
    if paused.is_empty() {
        return None;
    }
    let accounts = if paused.len() == 1 {
        "one account".to_string()
    } else {
        format!("{} accounts", paused.len())
    };
    let reason = if paused.iter().all(|account| account.after_sign_in_rejection) {
        "after the provider rejected sign-in"
    } else if paused.iter().any(|account| account.after_sign_in_rejection) {
        "after the provider rejected sign-in or stopped answering"
    } else {
        "while the provider is not answering"
    };
    let next_check = paused
        .iter()
        .filter_map(|account| account.next_check_epoch_seconds)
        .min()
        .and_then(rfc3339_from_unix_seconds);
    let next = match next_check {
        Some(at) => format!("next automatic check {at}"),
        None => "Ottto checks again automatically".to_string(),
    };
    Some(AgentStatusDiagnostic::source(
        CLAUDE_USAGE_CHECKS_PAUSED_DIAGNOSTIC_CODE,
        AgentDiagnosticSeverity::Warning,
        format!(
            "Claude usage checks paused for {accounts} {reason}; {next}. Last readings stay shown until then."
        ),
    ))
}

fn apply_claude_anchor_continuity(
    snapshot: &mut AgentStatusSnapshot,
    durability: ClaudeAccountAnchorDurabilityV1,
    health: Option<ClaudeAccountAnchorHealthV1>,
) {
    let Some(account) = snapshot.account.as_mut() else {
        return;
    };
    if account
        .account_identifier_hash
        .as_deref()
        .map_or(true, str::is_empty)
        || account
            .organization_identifier_hash
            .as_deref()
            .map_or(true, str::is_empty)
    {
        return;
    }
    account.claude_anchor_durability = Some(durability);
    account.claude_anchor_health = health;
}

/// Final presentation of one uploaded Claude candidate: the canonical saved
/// anchor's durability and health for the same exact pair, plus that anchor's
/// closed local worker receipt when another slot supplies the meters.
fn claude_uploaded_candidate_snapshot(
    mut candidate: ClaudeSnapshotCandidate,
    anchor_health_by_binding: &BTreeMap<ClaudeStrongBinding, Option<ClaudeAccountAnchorHealthV1>>,
    canonical_anchors: &BTreeMap<ClaudeStrongBinding, String>,
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    registered_owned: &BTreeSet<ClaudeStrongBinding>,
) -> AgentStatusSnapshot {
    if candidate.slot_class == ClaudeSnapshotSlotClass::Default {
        strip_slot_owned_plan_observations(
            &mut candidate.snapshot.plan_observations,
            &candidate.binding,
            registered_owned,
        );
    }
    let (durability, health) = anchor_health_by_binding
        .get(&candidate.binding)
        .map(|health| (ClaudeAccountAnchorDurabilityV1::Anchored, *health))
        .unwrap_or((ClaudeAccountAnchorDurabilityV1::DefaultOnly, None));
    apply_claude_anchor_continuity(&mut candidate.snapshot, durability, health);
    append_canonical_anchor_worker_receipts(
        &mut candidate.snapshot,
        &candidate.slot_id,
        &candidate.binding,
        canonical_anchors,
        slot_states,
    );
    candidate.snapshot
}

/// Accounts owned by a registered slot: the bindings of the registered slots
/// this pass and in the last persisted state. When the registered set could
/// not be read this pass, every non-default slot in the last persisted state.
fn claude_registered_owned_bindings(
    registered_set_known: bool,
    registered_slot_ids: &[String],
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    previous: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeSet<ClaudeStrongBinding> {
    let binding = |status: &ClaudeConfigSlotCollectionStatusV1| {
        ClaudeStrongBinding::new(
            status.account_identifier_hash.as_deref()?,
            status.organization_identifier_hash.as_deref()?,
        )
    };
    let slot_ids: Vec<&String> = if registered_set_known {
        registered_slot_ids.iter().collect()
    } else {
        previous
            .keys()
            .filter(|slot_id| slot_id.as_str() != "default")
            .collect()
    };
    slot_ids
        .into_iter()
        .flat_map(|slot_id| {
            [
                slot_states.get(slot_id).and_then(binding),
                previous.get(slot_id).and_then(binding),
            ]
        })
        .flatten()
        .collect()
}

/// The saved registered-slot states, with every fresh one marked a transient
/// read failure.
fn claude_stale_saved_slot_states(
    previous: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeMap<String, ClaudeConfigSlotCollectionStatusV1> {
    previous
        .iter()
        .filter(|(slot_id, _)| slot_id.as_str() != "default")
        .map(|(slot_id, status)| {
            let mut status = status.clone();
            if status.state == ClaudeConfigSlotCollectionStateV1::Fresh {
                status.state = ClaudeConfigSlotCollectionStateV1::ProbeFailed;
            }
            (slot_id.clone(), status)
        })
        .collect()
}

/// Which uploaded candidate snapshot should carry this Mac's Claude Code
/// settings (`runtime_defaults`), if any.
///
/// Only the default login's snapshot is built with them, and when the Claude
/// accounts are registered slots the default login is usually not uploaded,
/// so its settings would never reach the server. They are machine-level and
/// the server keeps one log per machine and install, so exactly one upload
/// carries a copy, and none when one already does (the default login itself
/// uploaded) or this pass built none. The carrier is the upload for the
/// default login's account, otherwise the lowest slot id, so every pass with
/// the same uploads picks the same one. `uploaded_slots[i]` is the slot id and
/// binding of `snapshots[i]`.
fn claude_runtime_defaults_carrier(
    snapshots: &[AgentStatusSnapshot],
    uploaded_slots: &[(String, ClaudeStrongBinding)],
    defaults_built: bool,
    default_binding: Option<&ClaudeStrongBinding>,
) -> Option<usize> {
    if !defaults_built
        || snapshots
            .iter()
            .any(|snapshot| snapshot.runtime_defaults.is_some())
    {
        return None;
    }
    uploaded_slots
        .iter()
        .enumerate()
        .min_by_key(|(_, (slot_id, binding))| (Some(binding) != default_binding, slot_id))
        .map(|(index, _)| index)
}

/// A default-login candidate for an account a registered slot owns uploads
/// only while that account's registered anchor is present this pass.
fn claude_default_upload_withheld(
    candidate: &ClaudeSnapshotCandidate,
    registered_owned: &BTreeSet<ClaudeStrongBinding>,
    canonical_anchors: &BTreeMap<ClaudeStrongBinding, String>,
) -> bool {
    candidate.slot_class == ClaudeSnapshotSlotClass::Default
        && registered_owned.contains(&candidate.binding)
        && !canonical_anchors.contains_key(&candidate.binding)
}

/// The default login's upload never speaks for another account a registered
/// slot owns: its plan observations for such an account (for example Claude
/// Desktop session buckets marked current) are dropped. An observation with
/// only an account hash is matched on the account.
fn strip_slot_owned_plan_observations(
    observations: &mut Vec<AgentStatusPlanObservation>,
    candidate: &ClaudeStrongBinding,
    registered_owned: &BTreeSet<ClaudeStrongBinding>,
) {
    let matches = |observation: &AgentStatusPlanObservation, binding: &ClaudeStrongBinding| {
        observation.account_identifier_hash.as_deref()
            == Some(binding.account_identifier_hash.as_str())
            && observation
                .organization_identifier_hash
                .as_deref()
                .map_or(true, |organization| {
                    organization == binding.organization_identifier_hash
                })
    };
    observations.retain(|observation| {
        matches(observation, candidate)
            || !registered_owned
                .iter()
                .any(|owned| owned != candidate && matches(observation, owned))
    });
}

/// Carry the canonical registered anchor's closed local worker receipt onto
/// the snapshot that uploads that same exact account/workspace pair.
///
/// When the default slot supplies a binding's meters, its anchor has no meters
/// and is neither uploaded nor turned into a degraded snapshot, so the anchor's
/// `claude_slot_worker_*` receipt was only ever persisted locally. That hid the
/// outcome exactly where the anchor is blocked and the default is not (for
/// example the CLI's current account). Only exact-binding, closed worker codes
/// with their original local completion clocks travel; provider-check codes,
/// collection-state codes and every other anchor diagnostic stay with the
/// anchor. This is presentation of an existing local fact, not a quota check.
fn append_canonical_anchor_worker_receipts(
    snapshot: &mut AgentStatusSnapshot,
    candidate_slot_id: &str,
    binding: &ClaudeStrongBinding,
    canonical_anchors: &BTreeMap<ClaudeStrongBinding, String>,
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) {
    let Some(anchor_slot_id) = canonical_anchors.get(binding) else {
        return;
    };
    if anchor_slot_id == candidate_slot_id {
        return;
    }
    let Some(anchor) = slot_states.get(anchor_slot_id) else {
        return;
    };
    let snapshot_matches = snapshot.account.as_ref().is_some_and(|account| {
        account.account_identifier_hash.as_deref() == Some(binding.account_identifier_hash.as_str())
            && account.organization_identifier_hash.as_deref()
                == Some(binding.organization_identifier_hash.as_str())
    });
    if !snapshot_matches
        || anchor.account_identifier_hash.as_deref()
            != Some(binding.account_identifier_hash.as_str())
        || anchor.organization_identifier_hash.as_deref()
            != Some(binding.organization_identifier_hash.as_str())
    {
        return;
    }
    for receipt in safe_claude_slot_check_diagnostics(
        &anchor.quota_check_diagnostics,
        &binding.account_identifier_hash,
        &binding.organization_identifier_hash,
    ) {
        if claude_worker_diagnostic_message(&receipt.code).is_none()
            || snapshot
                .diagnostics
                .iter()
                .any(|existing| claude_worker_diagnostic_message(&existing.code).is_some())
        {
            continue;
        }
        snapshot.diagnostics.push(receipt);
    }
}

#[cfg(test)]
fn claude_default_snapshot_is_uploadable(snapshot: &AgentStatusSnapshot) -> bool {
    claude_snapshot_candidate_rank(snapshot).is_some()
}

fn claude_snapshot_candidate_rank(snapshot: &AgentStatusSnapshot) -> Option<ClaudeSnapshotQuality> {
    if snapshot.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ClaudeSlotProbeFailure::ConcurrentMutation.diagnostic_code()
            || diagnostic.code == ClaudeSlotProbeFailure::OwnerUnproven.diagnostic_code()
    }) {
        return None;
    }
    if let Some((account_hash, organization_hash)) = snapshot.account.as_ref().and_then(|account| {
        Some((
            account.account_identifier_hash.as_deref()?,
            account.organization_identifier_hash.as_deref()?,
        ))
    }) {
        let exact_oauth_meters = !snapshot.quota_windows.is_empty()
            && snapshot.quota_windows.iter().all(|window| {
                window.account_identifier_hash.as_deref() == Some(account_hash)
                    && window.organization_identifier_hash.as_deref() == Some(organization_hash)
            })
            && snapshot.credit_balances.iter().all(|balance| {
                balance.account_identifier_hash.as_deref() == Some(account_hash)
                    && balance.organization_identifier_hash.as_deref() == Some(organization_hash)
            });
        if exact_oauth_meters {
            let fresh = snapshot
                .quota_windows
                .iter()
                .all(|window| window.freshness == AgentQuotaWindowFreshness::Fresh)
                && snapshot
                    .credit_balances
                    .iter()
                    .all(|balance| balance.freshness == AgentQuotaWindowFreshness::Fresh);
            let complete = claude_snapshot_has_account_windows(snapshot)
                && snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Model
                        || window.model.is_some()
                        || window.group.is_some()
                });
            return Some(ClaudeSnapshotQuality {
                tier: match (fresh, complete) {
                    (true, true) => 4,
                    (true, false) => 3,
                    (false, true) => 2,
                    (false, false) => 1,
                },
                provider_observed_at: coherent_claude_provider_observed_at(snapshot),
            });
        }
    }
    if snapshot.collection_method != AgentStatusCollectionMethod::StatusLine
        || !snapshot.credit_balances.is_empty()
        || snapshot.quota_windows.is_empty()
    {
        return None;
    }
    let attributed_account = snapshot.quota_windows[0]
        .account_identifier_hash
        .as_deref()
        .filter(|hash| !hash.is_empty());
    let attributed_account = attributed_account?;
    snapshot
        .quota_windows
        .iter()
        .all(|window| {
            window.account_identifier_hash.as_deref() == Some(attributed_account)
                && window.organization_identifier_hash.is_none()
        })
        .then(|| ClaudeSnapshotQuality {
            tier: if snapshot
                .quota_windows
                .iter()
                .all(|window| window.freshness == AgentQuotaWindowFreshness::Fresh)
            {
                3
            } else {
                1
            },
            provider_observed_at: coherent_claude_provider_observed_at(snapshot),
        })
}

fn coherent_claude_provider_observed_at(snapshot: &AgentStatusSnapshot) -> String {
    snapshot
        .quota_windows
        .iter()
        .filter_map(|window| window.observed_at.as_deref())
        .chain(
            snapshot
                .credit_balances
                .iter()
                .filter_map(|balance| balance.updated_at.as_deref()),
        )
        .min()
        .unwrap_or(snapshot.captured_at.as_str())
        .to_string()
}

fn bounded_claude_custom_descriptors(
    mut descriptors: Vec<ClaudeConfigSlotDescriptorV1>,
) -> (
    Vec<ClaudeConfigSlotDescriptorV1>,
    Vec<ClaudeConfigSlotDescriptorV1>,
) {
    let overflow = descriptors.split_off(
        descriptors
            .len()
            .min(MAX_CLAUDE_ACCOUNT_SLOTS.saturating_sub(1)),
    );
    (descriptors, overflow)
}

/// Exact bindings whose usage the default login must not request itself,
/// because a registered managed slot is the single caller for them.
///
/// A slot qualifies only when everything below is proved; otherwise the
/// binding is absent and the default login keeps calling as before:
/// - it is a managed (Ottto-owned) slot inside this pass's collection bound,
///   not provisional and not suppressed, so it is collected this pass;
/// - its last pass was the binding's canonical anchor and ended `Fresh` or
///   `ReloginApproaching`, i.e. its own credential read this account;
/// - its config directory's identity file still names that same account and
///   organization right now;
/// - its own credential is not in a live auth hold. A held slot can still
///   look `Fresh` while the shared cache is young, but it would not refresh
///   the account, so the default login keeps calling.
fn claude_slot_owned_usage_bindings(
    status: &ClaudeAccountsStatusV1,
    current_binding: impl Fn(&ClaudeConfigSlotDescriptorV1) -> Option<ClaudeStrongBinding>,
    suppressed: impl Fn(&str) -> bool,
    slot_auth_held: impl Fn(&ClaudeStrongBinding, &str) -> bool,
) -> BTreeSet<ClaudeStrongBinding> {
    let mut custom = ordered_claude_slot_descriptors(status)
        .into_iter()
        .filter(|descriptor| descriptor.slot_id != "default")
        .collect::<Vec<_>>();
    custom.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let (collected, _) = bounded_claude_custom_descriptors(custom);
    let managed = status
        .managed_slots
        .iter()
        .map(|descriptor| descriptor.slot_id.as_str())
        .collect::<BTreeSet<_>>();
    collected
        .iter()
        .filter(|descriptor| {
            descriptor.ownership == ClaudeConfigSlotOwnership::Managed
                && managed.contains(descriptor.slot_id.as_str())
                && !suppressed(&descriptor.slot_id)
                && descriptor.collection.relationship
                    == Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::CanonicalAnchor)
                && matches!(
                    descriptor.collection.state,
                    ClaudeConfigSlotCollectionStateV1::Fresh
                        | ClaudeConfigSlotCollectionStateV1::ReloginApproaching
                )
        })
        .filter_map(|descriptor| {
            let persisted = ClaudeStrongBinding::new(
                descriptor.collection.account_identifier_hash.as_deref()?,
                descriptor
                    .collection
                    .organization_identifier_hash
                    .as_deref()?,
            )?;
            (current_binding(descriptor)? == persisted
                && !slot_auth_held(&persisted, &descriptor.slot_id))
            .then_some(persisted)
        })
        .collect()
}

fn ordered_claude_slot_descriptors(
    status: &ClaudeAccountsStatusV1,
) -> Vec<ClaudeConfigSlotDescriptorV1> {
    let mut custom = status
        .managed_slots
        .iter()
        .chain(status.external_slots.iter())
        .filter(|descriptor| {
            !crate::claude_browser_auth::is_provisional_target_slot(&descriptor.slot_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    custom.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let mut descriptors = Vec::with_capacity(1 + custom.len());
    descriptors.push(status.default_slot.clone());
    descriptors.extend(custom);
    descriptors
}

/// Where one registered slot's collection stopped. The bulk pass and the
/// single-slot refresh share the pipeline and differ only in what they do with
/// the result (coverage and candidates there, one persisted state here).
#[allow(
    clippy::large_enum_variant,
    reason = "moved once to the caller; never stored"
)]
enum ClaudeSlotCollectionStep {
    /// The pre-collection gate refused: no upkeep, read, usage call or refresh.
    PreGateRefused(ClaudeConfigSlotCollectionStatusV1),
    /// Upkeep held collection back, either blocked or paused on a Claude refresh.
    UpkeepBlocked {
        status: ClaudeConfigSlotCollectionStatusV1,
        paused: bool,
    },
    /// Resolution failed, or the post-resolution gate refused the login.
    Stopped(ClaudeConfigSlotCollectionStatusV1),
    /// The usage call ran and produced no snapshot.
    UsageFailed(ClaudeConfigSlotCollectionStatusV1),
    Collected {
        snapshot: AgentStatusSnapshot,
        status: ClaudeConfigSlotCollectionStatusV1,
        account_identifier_hash: String,
        organization_identifier_hash: String,
    },
}

/// Gate, read, upkeep, resolve, gate again and call usage for one registered
/// slot. A slot that stops before the usage call has its passive sign-in run
/// ended here.
fn collect_registered_claude_slot_step(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    upkeep_consent: bool,
    captured_at: &str,
    expires_at: &str,
) -> ClaudeSlotCollectionStep {
    let slot_id = descriptor.slot_id.as_str();
    let expected_binding = match claude_slot_pre_collection_gate(descriptor, previous, captured_at)
    {
        Ok(expected) => expected,
        Err(status) => {
            claude_oauth_end_slot_run(slot_id);
            return ClaudeSlotCollectionStep::PreGateRefused(status);
        }
    };
    #[cfg(test)]
    claude_slot_after_pre_gate_hook();
    // One live local read per slot per pass (identity, stored credential,
    // identity), shared by the owner rule, the upkeep decision and the
    // resolution below. Never a `claude` spawn.
    let network_enabled = !claude_oauth_usage_network_disabled();
    let local = read_registered_claude_slot_locally(descriptor);
    // Another account signed in to this slot, or one that cannot be shown to
    // be the approved account: no upkeep, CLI, usage call, candidate or
    // refresh for it until the approved account is back. The one exception:
    // an unproven lapsed token may refresh itself, so its fresh token can be
    // proven.
    let mut owner = None;
    if let Some(expected) = &expected_binding {
        let calls_allowed = claude_owner_call_allowed();
        let refusal = match claude_slot_owner_rule(slot_id, expected, local.as_ref(), calls_allowed)
        {
            ClaudeSlotOwnerRule::Named => None,
            ClaudeSlotOwnerRule::Proven(proven) => {
                owner = Some(proven);
                None
            }
            ClaudeSlotOwnerRule::Other(plan) => Some(claude_slot_binding_mismatch_status(
                expected,
                plan.as_deref(),
                previous,
                captured_at,
            )),
            ClaudeSlotOwnerRule::Unproven => {
                // A lapsed token is never sent for proof, and its verdict is
                // not remembered (as after a restart): start the slot's own
                // background refresh, when due, so the pass its completion
                // wakes proves the fresh token. Nothing is collected here.
                if let Some(local) = local.as_ref().filter(|local| {
                    let strong = |oauth: &Option<ClaudeCliOauthAccount>| {
                        oauth.as_ref().and_then(claude_strong_oauth_identity_hashes)
                    };
                    calls_allowed
                        && local.state == ClaudeLocalLoginState::RefreshPending
                        && strong(&local.initial_oauth_account)
                            == strong(&local.final_oauth_account)
                }) {
                    registered_slot_refresh(
                        descriptor,
                        &local.live_login(),
                        upkeep_consent,
                        network_enabled,
                    );
                }
                Some(claude_slot_approval_blocked_status(
                    expected,
                    ClaudeSlotProbeFailure::OwnerUnproven,
                    claude_slot_owner_unproven_message,
                    previous,
                    captured_at,
                ))
            }
            ClaudeSlotOwnerRule::Unknown => Some(claude_slot_approval_blocked_status(
                expected,
                ClaudeSlotProbeFailure::IdentityUnknown,
                claude_slot_unknown_login_message,
                previous,
                captured_at,
            )),
        };
        if let Some(status) = refusal {
            claude_oauth_end_slot_run(slot_id);
            return ClaudeSlotCollectionStep::PreGateRefused(status);
        }
    }
    let local = local.filter(|_| network_enabled);
    let live = local
        .as_ref()
        .map_or_else(ClaudeLiveLogin::unreadable, ClaudeSlotLocalRead::live_login);
    // "Keep my Claude accounts signed in": start (or follow) the one
    // background refresh for this login when it is due.
    let refresh = registered_slot_refresh(descriptor, &live, upkeep_consent, network_enabled);
    let upkeep = crate::claude_upkeep::observe_registered_slot_upkeep(
        descriptor,
        upkeep_consent,
        network_enabled,
        &live,
        refresh,
    );
    if !upkeep.proceed_with_collection {
        claude_oauth_end_slot_run(slot_id);
        let result_observed_at = upkeep.result_observed_at.clone();
        let paused = upkeep.paused_awaiting_claude_refresh;
        let mut status = if paused {
            paused_claude_refresh_status(slot_id, captured_at, upkeep.status)
        } else {
            blocked_claude_upkeep_status(slot_id, captured_at, upkeep.status)
        };
        retain_registered_claude_slot_binding(descriptor, owner.as_ref(), &mut status);
        append_claude_upkeep_result_receipt(&mut status, descriptor, result_observed_at);
        apply_claude_token_owner(&mut status, owner.as_ref());
        return ClaudeSlotCollectionStep::UpkeepBlocked { status, paused };
    }
    let resolved = match local {
        Some(local) => resolve_registered_claude_slot_from_local(local, owner.as_ref()),
        None => Err(ClaudeSlotProbeFailure::IdentityUnknown),
    };
    let mut resolved = match resolved {
        Ok(resolved) => resolved,
        Err(failure) => {
            claude_oauth_end_slot_run(slot_id);
            let mut status = registered_claude_failure_status(
                descriptor,
                owner.as_ref(),
                failure,
                captured_at,
                upkeep.status,
            );
            apply_claude_token_owner(&mut status, owner.as_ref());
            return ClaudeSlotCollectionStep::Stopped(status);
        }
    };
    if let Err(status) = claude_slot_post_resolution_gate(
        descriptor,
        expected_binding,
        &resolved,
        previous,
        captured_at,
    ) {
        claude_oauth_end_slot_run(slot_id);
        return ClaudeSlotCollectionStep::Stopped(status);
    }
    let account_hash = resolved.account_identifier_hash.clone();
    let organization_hash = resolved.organization_identifier_hash.clone();
    let access_token = resolved.credential.access_token.take();
    let credential_available = access_token.is_some();
    let outcome = collect_claude_oauth_usage_with_credential(
        &account_hash,
        &organization_hash,
        access_token,
        resolved.credential.access_expires_at.clone(),
        &ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.to_string()),
        current_unix_seconds,
    );
    match custom_claude_snapshot_from_usage(
        resolved,
        outcome,
        credential_available,
        captured_at.to_string(),
        expires_at.to_string(),
    ) {
        Ok((snapshot, mut status)) => {
            apply_claude_upkeep_observation(&mut status, upkeep.status);
            apply_claude_token_owner(&mut status, owner.as_ref());
            ClaudeSlotCollectionStep::Collected {
                snapshot,
                status,
                account_identifier_hash: account_hash,
                organization_identifier_hash: organization_hash,
            }
        }
        Err(mut status) => {
            retain_exact_claude_slot_binding(&mut status, &account_hash, &organization_hash);
            apply_claude_upkeep_observation(&mut status, upkeep.status);
            apply_claude_token_owner(&mut status, owner.as_ref());
            ClaudeSlotCollectionStep::UsageFailed(status)
        }
    }
}

/// Refresh exactly one registered custom slot for the connection workflow.
/// This intentionally does not collect the default slot, statusLine, or any
/// sibling custom slot and never uploads a backend snapshot.
pub(crate) fn collect_registered_claude_slot_status(
    slot_id: &str,
    captured_at: String,
    expires_at: String,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let settings = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map(annotate_claude_accounts_status)
        .ok();
    let upkeep_consent = settings.as_ref().is_some_and(|status| {
        status.consent == ottto_protocol::ClaudeAccountUpkeepConsentState::Granted
    });
    let descriptor = settings.and_then(|status| {
        status
            .managed_slots
            .into_iter()
            .chain(status.external_slots)
            .find(|descriptor| descriptor.slot_id == slot_id)
    });
    let Some(descriptor) = descriptor else {
        claude_oauth_end_slot_run(slot_id);
        return ClaudeSlotProbeFailure::IdentityUnknown.status(&captured_at);
    };
    match crate::claude_browser_auth::collection_suppression(slot_id) {
        Some(crate::claude_browser_auth::ClaudeCollectionSuppression::HideProvisionalTarget) => {
            claude_oauth_end_slot_run(slot_id);
            return ClaudeSlotProbeFailure::IdentityUnknown.status(&captured_at);
        }
        Some(
            crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveCanonicalReconnect
            | crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveWhileStateUnavailable,
        ) => {
            claude_oauth_end_slot_run(slot_id);
            return descriptor.collection;
        }
        None => {}
    }
    let previous_states = read_persisted_claude_slot_collection_state();
    let previous = previous_states.slots.get(slot_id);
    let step = collect_registered_claude_slot_step(
        &descriptor,
        previous,
        upkeep_consent,
        &captured_at,
        &expires_at,
    );
    match step {
        ClaudeSlotCollectionStep::PreGateRefused(mut status) => {
            apply_claude_slot_approval_notice(&mut status, claude_slot_approvals().get(slot_id));
            let _ = persist_one_claude_slot_collection_state(slot_id, &status);
            status
        }
        ClaudeSlotCollectionStep::UpkeepBlocked { status, .. }
        | ClaudeSlotCollectionStep::Stopped(status) => {
            let _ = persist_one_claude_slot_collection_state(slot_id, &status);
            status
        }
        ClaudeSlotCollectionStep::UsageFailed(mut status)
        | ClaudeSlotCollectionStep::Collected { mut status, .. } => {
            inherit_claude_slot_account_profile(&mut status, previous);
            apply_claude_slot_approval_notice(&mut status, claude_slot_approvals().get(slot_id));
            let _ = persist_one_claude_slot_collection_state(slot_id, &status);
            status
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeLocalIdentityFailure {
    IdentityUnknown,
    CredentialUnavailable,
    IdentityMismatch,
    ConcurrentMutation,
}

pub(crate) struct ClaudeLocalIdentityProof {
    pub(crate) account_identifier_hash: String,
    pub(crate) organization_identifier_hash: String,
    pub(crate) collection: ClaudeConfigSlotCollectionStatusV1,
}

/// Secret-free witness for one exact Claude authentication namespace. The
/// digest covers provider-owned identity bytes plus credential material in
/// memory, but persists neither. Browser-auth recovery requires this witness
/// to differ from the pre-login baseline before accepting a ceremony.
pub(crate) fn claude_auth_ceremony_witness(config_dir: &str) -> Result<String, ()> {
    ottto_core::validate_managed_claude_auth_root(config_dir).map_err(|_| ())?;
    let slot = ClaudeConfigDirSlot::registered(config_dir.to_string()).map_err(|_| ())?;
    let mut digest = Sha256::new();
    digest.update(b"ottto:claude-auth-ceremony-witness:v1\0");
    match std::fs::read(slot.identity_path(&home_dir())) {
        Ok(body) => {
            digest.update(b"identity\0");
            digest.update(Sha256::digest(body));
        }
        Err(_) => digest.update(b"identity-absent\0"),
    }
    match read_claude_oauth_credential_for_slot(&slot) {
        Some(credential) => {
            digest.update(b"credential\0");
            if let Some(token) = credential.access_token.as_deref() {
                digest.update(Sha256::digest(token.as_bytes()));
            } else {
                digest.update(b"access-absent\0");
            }
            digest.update([u8::from(credential.has_refresh_token)]);
            if let Some(expires) = credential.access_expires_at.as_deref() {
                digest.update(expires.as_bytes());
            }
            if let Some(deadline) = credential.relogin_required_at.as_deref() {
                digest.update(deadline.as_bytes());
            }
        }
        None => digest.update(b"credential-absent\0"),
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Prove only the provider-owned local identity for one exact root. This does
/// not consult upkeep consent, call the usage endpoint, read quota, persist a
/// slot, or upload anything. Generic browser-auth roots remain provisional
/// until the caller atomically admits this strong composite.
pub(crate) fn verify_claude_local_identity(
    slot_id: &str,
    config_dir: &str,
    observed_at: &str,
) -> Result<ClaudeLocalIdentityProof, ClaudeLocalIdentityFailure> {
    let descriptor = ClaudeConfigDirSlot::registered(config_dir.to_string())
        .map_err(|_| ClaudeLocalIdentityFailure::IdentityUnknown)?
        .descriptor(slot_id.to_string(), ClaudeConfigSlotOwnership::Managed);
    let resolved = resolve_registered_claude_slot(descriptor).map_err(|failure| match failure {
        ClaudeSlotProbeFailure::IdentityUnknown => ClaudeLocalIdentityFailure::IdentityUnknown,
        ClaudeSlotProbeFailure::CredentialUnavailable => {
            ClaudeLocalIdentityFailure::CredentialUnavailable
        }
        ClaudeSlotProbeFailure::IdentityMismatch | ClaudeSlotProbeFailure::OwnerUnproven => {
            ClaudeLocalIdentityFailure::IdentityMismatch
        }
        ClaudeSlotProbeFailure::ConcurrentMutation => {
            ClaudeLocalIdentityFailure::ConcurrentMutation
        }
        // Identity proof needs a successful status read; keep the connect
        // flow's existing answer for a failed one.
        ClaudeSlotProbeFailure::ProbeFailed | ClaudeSlotProbeFailure::SignedOutByCli => {
            ClaudeLocalIdentityFailure::CredentialUnavailable
        }
    })?;
    let mut collection = fresh_slot_status(
        observed_at,
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
        false,
        false,
        false,
    );
    apply_credential_metadata(&mut collection, &resolved.credential);
    remember_claude_slot_account_profile(&mut collection, Some(&resolved.account), observed_at);
    Ok(ClaudeLocalIdentityProof {
        account_identifier_hash: resolved.account_identifier_hash,
        organization_identifier_hash: resolved.organization_identifier_hash,
        collection,
    })
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum ClaudeWorkerDiagnostic {
    Observed(ClaudeConfigSlotUpkeepResultV1),
    IdentityFailed(ClaudeLocalIdentityFailure),
    ReconciliationRefused,
    Reconciled,
}

#[cfg(test)]
impl ClaudeWorkerDiagnostic {
    fn code(self) -> &'static str {
        use ClaudeConfigSlotUpkeepResultV1 as R;
        match self {
            Self::Observed(R::NotRequired) => "claude_slot_worker_not_required",
            Self::Observed(R::RefreshDue) => "claude_slot_worker_refresh_due",
            Self::Observed(R::Refreshed) => "claude_slot_worker_refreshed",
            Self::Observed(R::UpkeepNotConsented) => "claude_slot_worker_upkeep_not_consented",
            Self::Observed(R::CollectionPaused) => "claude_slot_worker_collection_paused",
            Self::Observed(R::UpkeepDisabled) => "claude_slot_worker_upkeep_disabled",
            Self::Observed(R::Backoff) => "claude_slot_worker_backoff",
            Self::Observed(R::MissingBinary) => "claude_slot_worker_missing_binary",
            Self::Observed(R::SpawnFailed) => "claude_slot_worker_spawn_failed",
            Self::Observed(R::TimedOut) => "claude_slot_worker_timed_out",
            Self::Observed(R::NonzeroExit) => "claude_slot_worker_nonzero_exit",
            Self::Observed(R::CredentialUnreadable) => "claude_slot_worker_credential_unreadable",
            Self::Observed(R::ExpiryUnchanged) => "claude_slot_worker_expiry_unchanged",
            Self::Observed(R::ProbeFailed) => "claude_slot_worker_probe_failed",
            Self::Observed(R::ReloginApproaching) => "claude_slot_worker_relogin_approaching",
            Self::Observed(R::NeedsLogin) => "claude_slot_worker_needs_login",
            Self::Observed(R::InProgress) => "claude_slot_worker_in_progress",
            Self::IdentityFailed(ClaudeLocalIdentityFailure::IdentityUnknown) => {
                "claude_slot_worker_identity_unknown"
            }
            Self::IdentityFailed(ClaudeLocalIdentityFailure::CredentialUnavailable) => {
                "claude_slot_worker_identity_credential_unavailable"
            }
            Self::IdentityFailed(ClaudeLocalIdentityFailure::IdentityMismatch) => {
                "claude_slot_worker_identity_mismatch"
            }
            Self::IdentityFailed(ClaudeLocalIdentityFailure::ConcurrentMutation) => {
                "claude_slot_worker_identity_concurrent_mutation"
            }
            Self::ReconciliationRefused => "claude_slot_worker_reconciliation_refused",
            Self::Reconciled => "claude_slot_worker_metadata_reconciled",
        }
    }
}

fn claude_worker_diagnostic_message(code: &str) -> Option<&'static str> {
    Some(match code {
        "claude_slot_worker_not_required" | "claude_slot_worker_relogin_approaching" => "The local worker observed valid access metadata; this does not establish saved-pair reconciliation or a quota check.",
        "claude_slot_worker_refresh_due" | "claude_slot_worker_refreshed" | "claude_slot_worker_upkeep_not_consented" | "claude_slot_worker_collection_paused" | "claude_slot_worker_upkeep_disabled" | "claude_slot_worker_backoff" | "claude_slot_worker_missing_binary" | "claude_slot_worker_spawn_failed" | "claude_slot_worker_timed_out" | "claude_slot_worker_nonzero_exit" | "claude_slot_worker_credential_unreadable" | "claude_slot_worker_expiry_unchanged" | "claude_slot_worker_probe_failed" | "claude_slot_worker_needs_login" | "claude_slot_worker_in_progress" => "The local worker returned this upkeep outcome; no quota provider check, vendor-command attempt, or current limits observation is implied.",
        "claude_slot_worker_identity_unknown" => "The local worker observed valid access metadata, but its exact-root identity was unknown; saved metadata was not reconciled.",
        "claude_slot_worker_identity_credential_unavailable" => "The local worker observed valid access metadata, but the exact-root identity verifier found no usable credential; saved metadata was not reconciled.",
        "claude_slot_worker_identity_mismatch" => "The local worker observed valid access metadata, but the exact-root identity verifier found conflicting identities; saved metadata was not reconciled.",
        "claude_slot_worker_identity_concurrent_mutation" => "The local worker observed valid access metadata, but the exact-root identity changed during verification; saved metadata was not reconciled.",
        "claude_slot_worker_reconciliation_refused" => "The local worker observed valid access metadata, but the same-fence proof or observation clocks did not permit saved metadata reconciliation.",
        "claude_slot_worker_metadata_reconciled" => "The local worker reconciled verified same-root, same-pair access metadata; quota/check clocks and saved limits state were not refreshed.",
        _ => return None,
    })
}

#[cfg(test)]
fn append_claude_worker_diagnostic(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    diagnostic: ClaudeWorkerDiagnostic,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<()> {
    let completed = bounded_claude_collection_timestamp(Some(completed_at), now)?;
    if status.quota_check_diagnostics.iter().any(|entry| {
        claude_worker_diagnostic_message(&entry.code).is_some()
            && bounded_claude_collection_timestamp(entry.observed_at.as_deref(), now)
                .is_some_and(|at| at > completed)
    }) {
        return None;
    }
    let account = status.account_identifier_hash.as_ref()?.clone();
    let organization = status.organization_identifier_hash.as_ref()?.clone();
    if account.is_empty() || organization.is_empty() {
        return None;
    }
    let code = diagnostic.code();
    status
        .quota_check_diagnostics
        .retain(|entry| claude_worker_diagnostic_message(&entry.code).is_none());
    status.quota_check_diagnostics.push(
        AgentStatusDiagnostic::source(
            code,
            AgentDiagnosticSeverity::Info,
            claude_worker_diagnostic_message(code)?,
        )
        .with_observed_at(Some(completed_at.to_string()))
        .with_quota_binding(Some(account), Some(organization)),
    );
    Some(())
}

#[cfg(test)]
fn claude_worker_receipt_status(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    diagnostic: ClaudeWorkerDiagnostic,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<ClaudeConfigSlotCollectionStatusV1> {
    let fence = crate::claude_upkeep::preclaim_descriptor(queued)?;
    if crate::claude_upkeep::preclaim_descriptor(current).as_ref() != Some(&fence) {
        return None;
    }
    let completed = bounded_claude_collection_timestamp(Some(completed_at), now)?;
    if current
        .collection
        .observed_at
        .as_deref()
        .is_some_and(|at| bounded_claude_collection_timestamp(Some(at), completed).is_none())
    {
        return None;
    }
    let mut status = current.collection.clone();
    append_claude_worker_diagnostic(&mut status, diagnostic, completed_at, now)?;
    Some(status)
}

#[cfg(test)]
pub(crate) fn record_registered_claude_worker_observation(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    result: ClaudeConfigSlotUpkeepResultV1,
) {
    record_registered_claude_worker_diagnostic(
        descriptor,
        ClaudeWorkerDiagnostic::Observed(result),
    );
}

#[cfg(test)]
fn record_registered_claude_worker_diagnostic(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    diagnostic: ClaudeWorkerDiagnostic,
) {
    let completed_at = crate::current_rfc3339_timestamp();
    // A refused/unavailable publication remains unknown. Never recreate a
    // removed slot or override consent/suppression merely to expose a reason.
    let _ = FileClaudeConfigSlotSettingsStore::default().with_locked_status(|registry| {
        if !crate::claude_upkeep::registered_slot_publication_allowed(
            registry,
            descriptor,
            &default_support_dir(),
        ) {
            return;
        }
        let Some(current) = registry
            .managed_slots
            .iter()
            .chain(&registry.external_slots)
            .find(|slot| slot.slot_id == descriptor.slot_id)
        else {
            return;
        };
        let _ = persist_one_claude_slot_collection_state_with(&descriptor.slot_id, |previous| {
            let mut current = current.clone();
            current.collection = previous?.clone();
            claude_worker_receipt_status(
                descriptor,
                &current,
                diagnostic,
                &completed_at,
                OffsetDateTime::now_utc(),
            )
        });
    });
}

/// A worker can find already-valid access after a login/refresh while the
/// foreground still gates on the old saved deadline. Reconcile only through
/// the existing exact-root identity verifier and collection-state owner.
#[cfg(test)]
pub(crate) fn reconcile_registered_claude_valid_access(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> bool {
    let now = OffsetDateTime::now_utc();
    if !valid_access_reconciliation_due(descriptor, upkeep, now) {
        record_registered_claude_worker_observation(descriptor, upkeep.result);
        return false;
    }
    let Ok(registry) = FileClaudeConfigSlotSettingsStore::default().load() else {
        return false;
    };
    if !crate::claude_upkeep::registered_slot_publication_allowed(
        &registry,
        descriptor,
        &default_support_dir(),
    ) {
        return false;
    }
    let Some(config_dir) = descriptor.config_dir.as_deref() else {
        return false;
    };
    let observed_at = crate::current_rfc3339_timestamp();
    let proof = match verify_claude_local_identity(&descriptor.slot_id, config_dir, &observed_at) {
        Ok(proof) => proof,
        Err(reason) => {
            record_registered_claude_worker_diagnostic(
                descriptor,
                ClaudeWorkerDiagnostic::IdentityFailed(reason),
            );
            return false;
        }
    };
    let completed_at = crate::current_rfc3339_timestamp();
    FileClaudeConfigSlotSettingsStore::default()
        .with_locked_status(|registry| {
            if !crate::claude_upkeep::registered_slot_publication_allowed(
                registry,
                descriptor,
                &default_support_dir(),
            ) {
                return false;
            }
            let Some(current) = registry
                .managed_slots
                .iter()
                .chain(&registry.external_slots)
                .find(|slot| slot.slot_id == descriptor.slot_id)
            else {
                return false;
            };
            // Compare the collection fence under its existing transaction lock,
            // not against an annotation that a concurrent collector can replace.
            let mut metadata_reconciled = false;
            persist_one_claude_slot_collection_state_with(&descriptor.slot_id, |previous| {
                let mut current = current.clone();
                current.collection = previous?.clone();
                if let Some(status) = reconciled_valid_access_status_with_worker_receipt(
                    descriptor,
                    &current,
                    upkeep,
                    &proof,
                    &completed_at,
                    OffsetDateTime::now_utc(),
                ) {
                    metadata_reconciled = true;
                    Some(status)
                } else {
                    claude_worker_receipt_status(
                        descriptor,
                        &current,
                        ClaudeWorkerDiagnostic::ReconciliationRefused,
                        &completed_at,
                        OffsetDateTime::now_utc(),
                    )
                }
            })
            .map(|changed| changed && metadata_reconciled)
            .unwrap_or(false)
        })
        .unwrap_or(false)
}

#[cfg(test)]
fn valid_access_reconciliation_due(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
    now: OffsetDateTime,
) -> bool {
    matches!(
        upkeep.result,
        ClaudeConfigSlotUpkeepResultV1::NotRequired
            | ClaudeConfigSlotUpkeepResultV1::ReloginApproaching
    ) && upkeep.attempted_at.is_none()
        && descriptor
            .collection
            .access_expires_at
            .as_deref()
            .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .is_some_and(|expiry| expiry <= now)
        && upkeep
            .due_access_expires_at
            .as_deref()
            .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .is_some_and(|expiry| expiry > now)
}

#[cfg(test)]
fn reconciled_valid_access_status(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
    proof: &ClaudeLocalIdentityProof,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<ClaudeConfigSlotCollectionStatusV1> {
    let fence = crate::claude_upkeep::preclaim_descriptor(queued)?;
    let completed = bounded_claude_collection_timestamp(Some(completed_at), now)?;
    if crate::claude_upkeep::preclaim_descriptor(current).as_ref() != Some(&fence)
        || !valid_access_reconciliation_due(queued, upkeep, now)
        || bounded_claude_collection_timestamp(proof.collection.observed_at.as_deref(), completed)
            .is_none()
        || current
            .collection
            .observed_at
            .as_deref()
            .is_some_and(|at| bounded_claude_collection_timestamp(Some(at), completed).is_none())
        || current.collection.account_identifier_hash.as_deref()
            != Some(proof.account_identifier_hash.as_str())
        || current.collection.organization_identifier_hash.as_deref()
            != Some(proof.organization_identifier_hash.as_str())
        || proof.collection.access_expires_at != upkeep.due_access_expires_at
        || proof.collection.relogin_required_at != upkeep.refresh_token_expires_at
    {
        return None;
    }
    // This is a real local identity observation, not a quota read or an upkeep
    // command. Preserve every meter/check clock and unavailable state until the
    // ordinary collector obtains its own exact-pair outcome.
    let mut status = current.collection.clone();
    status.observed_at = Some(completed_at.to_string());
    status.access_expires_at = proof.collection.access_expires_at.clone();
    status.relogin_required_at = proof.collection.relogin_required_at.clone();
    status.upkeep = Some(upkeep.clone());
    Some(status)
}

#[cfg(test)]
fn reconciled_valid_access_status_with_worker_receipt(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
    proof: &ClaudeLocalIdentityProof,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<ClaudeConfigSlotCollectionStatusV1> {
    let mut status =
        reconciled_valid_access_status(queued, current, upkeep, proof, completed_at, now)?;
    // A superseded diagnostic must never become a new access-recovery gate.
    // Keep a newer local receipt while accepting the original metadata proof.
    let _ = append_claude_worker_diagnostic(
        &mut status,
        ClaudeWorkerDiagnostic::Reconciled,
        completed_at,
        now,
    );
    Some(status)
}

/// One local observation of an exact slot: its `.claude.json` identity, the
/// stored credential, then the identity again (a change between the two reads
/// is a concurrent login). Never spawns `claude`.
struct ClaudeSlotLocalRead {
    initial_oauth_account: Option<ClaudeCliOauthAccount>,
    credential: ClaudeCredentialRead,
    final_oauth_account: Option<ClaudeCliOauthAccount>,
    state: ClaudeLocalLoginState,
}

impl ClaudeSlotLocalRead {
    fn live_login(&self) -> ClaudeLiveLogin {
        ClaudeLiveLogin {
            state: self.state,
            metadata: self.credential.metadata(),
        }
    }

    /// The owner check of this read's own stored token, the bytes the usage
    /// call sends, against `cached`, the pair `.claude.json` names.
    fn token_owner(
        &self,
        slot_id: &str,
        cached: Option<(String, String)>,
        calls_allowed: bool,
    ) -> ClaudeTokenOwner {
        let token = match &self.credential {
            ClaudeCredentialRead::Present(credential) => credential.access_token.as_deref(),
            ClaudeCredentialRead::Absent | ClaudeCredentialRead::Unreadable => None,
        };
        ClaudeTokenOwner {
            cached,
            proven: prove_claude_token_owner(slot_id, &self.state, token, calls_allowed),
        }
    }
}

fn read_claude_slot_locally(slot: &ClaudeConfigDirSlot) -> ClaudeSlotLocalRead {
    let identity_path = slot.identity_path(&home_dir());
    let initial_oauth_account = read_claude_cli_oauth_account(&identity_path);
    let credential = read_claude_oauth_credential_state_for_slot(slot);
    let final_oauth_account = read_claude_cli_oauth_account(&identity_path);
    let state = claude_local_login_state(&credential, OffsetDateTime::now_utc());
    ClaudeSlotLocalRead {
        initial_oauth_account,
        credential,
        final_oauth_account,
        state,
    }
}

fn registered_slot_refresh(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    live: &ClaudeLiveLogin,
    consent: bool,
    network_enabled: bool,
) -> crate::claude_refresher::RefreshDecision {
    match claude_config_slot_for_descriptor(descriptor).filter(|slot| slot.config_dir().is_some()) {
        Some(slot) if network_enabled => {
            crate::claude_refresher::maybe_refresh(&descriptor.slot_id, &slot, live, consent)
        }
        _ => crate::claude_refresher::RefreshDecision::NotNeeded,
    }
}

/// The background gates every owner-profile call shares ("Background limit
/// refresh" included).
fn claude_owner_call_allowed() -> bool {
    !claude_oauth_usage_network_disabled()
        && !claude_pass_saved_only()
        && !claude_background_read_withheld()
}

fn read_registered_claude_slot_locally(
    descriptor: &ClaudeConfigSlotDescriptorV1,
) -> Option<ClaudeSlotLocalRead> {
    claude_config_slot_for_descriptor(descriptor)
        .filter(|slot| slot.config_dir().is_some())
        .map(|slot| read_claude_slot_locally(&slot))
}

fn resolve_registered_claude_slot(
    descriptor: ClaudeConfigSlotDescriptorV1,
) -> Result<ResolvedClaudeSlot, ClaudeSlotProbeFailure> {
    let local = read_registered_claude_slot_locally(&descriptor)
        .ok_or(ClaudeSlotProbeFailure::IdentityUnknown)?;
    // Reconnect's identity check follows collection's owner rule.
    let owner = match FileClaudeConfigSlotSettingsStore::default()
        .expected_slot_binding(&descriptor.slot_id)
    {
        Ok(Some(expected)) => match claude_slot_owner_rule(
            &descriptor.slot_id,
            &expected,
            Some(&local),
            claude_owner_call_allowed(),
        ) {
            ClaudeSlotOwnerRule::Proven(owner) => Some(owner),
            _ => None,
        },
        _ => None,
    };
    resolve_registered_claude_slot_from_local(local, owner.as_ref())
}

/// A registered slot's owner rule, from one local read of it (`.claude.json`
/// and the stored token, the bytes its usage call sends). Where the file names
/// another account than the approved one, the stored token decides; with
/// `calls_allowed` false only remembered verdicts count.
enum ClaudeSlotOwnerRule {
    /// `.claude.json` names the approved account.
    Named,
    /// It names another account, and the stored token is proven to be the
    /// approved account and organization.
    Proven(ClaudeTokenOwner),
    /// The stored token is proven to be another account (with the plan the
    /// file names, for wording).
    Other(Option<String>),
    /// It names another account, and the token's owner is not proven: no
    /// read, no token, a lapsed token without a verdict, or a failed check.
    Unproven,
    /// The file is missing, unreadable or without strong ids.
    Unknown,
}

fn claude_slot_owner_rule(
    slot_id: &str,
    expected: &ClaudeSlotAccountBinding,
    local: Option<&ClaudeSlotLocalRead>,
    calls_allowed: bool,
) -> ClaudeSlotOwnerRule {
    let Some((local, oauth)) =
        local.and_then(|local| Some((local, local.initial_oauth_account.as_ref()?)))
    else {
        return ClaudeSlotOwnerRule::Unknown;
    };
    let Some((cached, binding)) = claude_strong_oauth_identity_hashes(oauth).and_then(|cached| {
        let binding = ClaudeSlotAccountBinding::new(&cached.0, &cached.1)?;
        Some((cached, binding))
    }) else {
        return ClaudeSlotOwnerRule::Unknown;
    };
    if binding == *expected {
        return ClaudeSlotOwnerRule::Named;
    }
    let owner = local.token_owner(slot_id, Some(cached), calls_allowed);
    if owner.proves(expected) {
        ClaudeSlotOwnerRule::Proven(owner)
    } else if owner.proven.is_some() {
        ClaudeSlotOwnerRule::Other(claude_oauth_plan_type_for_label(oauth))
    } else {
        ClaudeSlotOwnerRule::Unproven
    }
}

/// Resolve a registered slot from local metadata alone. `claude auth status`
/// added no independent evidence: it printed the stored token's presence and
/// scopes, the plan stored with the token, and the `.claude.json` account. The
/// same fields are read here directly, so no Claude command runs and nothing
/// can refresh (or sign out) the login.
///
/// `owner` proves the stored token is the approved account that a stale
/// `.claude.json` does not name: nothing comes from that file, and the
/// credential's plan is dropped as for the default home's proven owner.
/// Labels then come only from that account's own last profile.
fn resolve_registered_claude_slot_from_local(
    local: ClaudeSlotLocalRead,
    owner: Option<&ClaudeTokenOwner>,
) -> Result<ResolvedClaudeSlot, ClaudeSlotProbeFailure> {
    match local.state {
        ClaudeLocalLoginState::SignedOutByCli => {
            return Err(ClaudeSlotProbeFailure::SignedOutByCli)
        }
        ClaudeLocalLoginState::NotSignedIn | ClaudeLocalLoginState::NeedsLogin => {
            return Err(ClaudeSlotProbeFailure::CredentialUnavailable)
        }
        // Fail closed and transient: a failed or malformed read is not
        // evidence that the login is gone.
        ClaudeLocalLoginState::Unreadable => return Err(ClaudeSlotProbeFailure::ProbeFailed),
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending => {}
    }
    let mut stable = stable_claude_slot_credential(
        local.initial_oauth_account,
        local.credential.into_credential(),
        local.final_oauth_account,
    )?;
    let (mut account, (account_identifier_hash, organization_identifier_hash)) =
        match owner.and_then(ClaudeTokenOwner::proven_binding) {
            Some(binding) => {
                stable.credential.subscription_type = None;
                let account = claude_account_from_local_metadata(
                    &ClaudeCliOauthAccount::default(),
                    &stable.credential,
                )?;
                (account, binding)
            }
            None => {
                let mut account =
                    claude_account_from_local_metadata(&stable.oauth_account, &stable.credential)?;
                require_claude_auth_identity_agreement(&account, &stable.oauth_account)?;
                refine_claude_local_plan_metadata(&mut account, &stable.oauth_account);
                let binding = claude_strong_oauth_identity_hashes(&stable.oauth_account)
                    .ok_or(ClaudeSlotProbeFailure::IdentityUnknown)?;
                if !stamp_claude_cli_account_identity(&mut account, &stable.oauth_account) {
                    return Err(ClaudeSlotProbeFailure::IdentityMismatch);
                }
                (account, binding)
            }
        };
    account.account_identifier_hash = Some(account_identifier_hash.clone());
    account.organization_identifier_hash = Some(organization_identifier_hash.clone());
    account.billing_identity_evidence = billing_identity_evidence_for(
        &account.account_identifier_hash,
        &account.organization_identifier_hash,
        &account.credential_fingerprint_hash,
    );
    Ok(ResolvedClaudeSlot {
        account,
        account_identifier_hash,
        organization_identifier_hash,
        credential: stable.credential,
    })
}

/// Build the signed-in Claude account from local metadata: email, organization
/// and organization name from `.claude.json` `oauthAccount`, the plan from the
/// stored credential's `subscriptionType`. This is the same field set
/// `claude auth status --json` printed, and it goes through the same parser so
/// plan normalization and billing channel stay identical.
///
/// Two present plan facts that contradict each other (the credential says one
/// plan, `.claude.json` names another organization type) mean the two files
/// may come from different logins: `OwnerUnproven`. The credential's plan is
/// cached metadata, never identity.
fn claude_account_from_local_metadata(
    oauth: &ClaudeCliOauthAccount,
    credential: &ClaudeOAuthCredential,
) -> Result<AgentAccountStatus, ClaudeSlotProbeFailure> {
    if claude_local_plan_facts_contradict(
        credential.subscription_type.as_deref(),
        oauth.organization_type.as_deref(),
    ) {
        return Err(ClaudeSlotProbeFailure::OwnerUnproven);
    }
    let mut auth = serde_json::Map::new();
    auth.insert("loggedIn".to_string(), Value::Bool(true));
    auth.insert("authMethod".to_string(), Value::from("claude.ai"));
    auth.insert("apiProvider".to_string(), Value::from("firstParty"));
    for (key, value) in [
        ("email", oauth.email_address.as_deref()),
        ("orgId", oauth.organization_uuid.as_deref()),
        ("orgName", oauth.organization_name.as_deref()),
        ("subscriptionType", credential.subscription_type.as_deref()),
    ] {
        if let Some(value) = value {
            auth.insert(key.to_string(), Value::from(value));
        }
    }
    Ok(parse_claude_auth_json(&Value::Object(auth)))
}

/// Only plan families both files can name are compared; an unknown value on
/// either side is never a contradiction.
fn claude_local_plan_facts_contradict(
    subscription_type: Option<&str>,
    organization_type: Option<&str>,
) -> bool {
    const KNOWN: &[&str] = &["pro", "max", "team", "enterprise"];
    let family = |value: &str| {
        let normalized = normalize_plan_type(value.to_string());
        let family = normalized
            .strip_prefix("claude_")
            .unwrap_or(&normalized)
            .to_string();
        KNOWN.contains(&family.as_str()).then_some(family)
    };
    match (
        subscription_type.and_then(family),
        organization_type.and_then(family),
    ) {
        (Some(left), Some(right)) => left != right,
        _ => false,
    }
}

#[expect(clippy::result_large_err, reason = "Err is the full slot status")]
fn custom_claude_snapshot_from_usage(
    resolved: ResolvedClaudeSlot,
    outcome: ClaudeOAuthUsageOutcome,
    credential_available: bool,
    captured_at: String,
    expires_at: String,
) -> Result<
    (AgentStatusSnapshot, ClaudeConfigSlotCollectionStatusV1),
    ClaudeConfigSlotCollectionStatusV1,
> {
    let ClaudeOAuthUsageOutcome {
        result,
        diagnostics,
    } = outcome;
    let usage = match result {
        Ok(usage) if !usage.windows.is_empty() => usage,
        _ => {
            let collection_paused = diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "claude_oauth_usage_network_disabled");
            let collection_in_progress = diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "claude_oauth_usage_collection_in_progress");
            let mut status = if collection_paused {
                collection_paused_status(
                    &captured_at,
                    &resolved.account_identifier_hash,
                    &resolved.organization_identifier_hash,
                )
            } else if collection_in_progress {
                collection_in_progress_status(
                    &captured_at,
                    &resolved.account_identifier_hash,
                    &resolved.organization_identifier_hash,
                )
            } else if credential_available {
                provider_unavailable_status(
                    &captured_at,
                    &resolved.account_identifier_hash,
                    &resolved.organization_identifier_hash,
                )
            } else {
                ClaudeSlotProbeFailure::CredentialUnavailable.status(&captured_at)
            };
            apply_credential_metadata(&mut status, &resolved.credential);
            remember_claude_slot_account_profile(
                &mut status,
                Some(&resolved.account),
                &captured_at,
            );
            status.quota_check_diagnostics = safe_claude_slot_check_diagnostics(
                &diagnostics,
                &resolved.account_identifier_hash,
                &resolved.organization_identifier_hash,
            );
            return Err(status);
        }
    };
    if !claude_usage_has_exact_identity(
        &usage,
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
    ) {
        return Err(ClaudeSlotProbeFailure::IdentityMismatch.status(&captured_at));
    }
    // Credit sections carry their own per-section freshness (each from its own
    // read time); the slot's state is its meters', as in
    // `local_claude_quota_snapshot`. A section read on alternate slots goes
    // Stale while the windows are fresh, which is not a failed read.
    let stale = usage
        .windows
        .iter()
        .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh);
    let account_weekly_not_offered = usage.account_weekly_not_offered;
    let account_session_not_offered = usage.account_session_not_offered;
    let has_account_windows = claude_has_account_windows(
        &usage.windows,
        account_weekly_not_offered,
        account_session_not_offered,
    );
    let has_scoped_limits = usage.windows.iter().any(|window| {
        window.scope == AgentQuotaWindowScope::Model
            || window.model.is_some()
            || window.group.is_some()
    });
    let has_credit_balances = !usage.credit_balances.is_empty();
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        captured_at.clone(),
        expires_at,
    );
    snapshot.account = Some(resolved.account);
    snapshot.model = Some(AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: Some("anthropic".to_string()),
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    });
    snapshot.quota_windows = usage.windows;
    snapshot.credit_balances = usage.credit_balances;
    snapshot.capabilities = vec![
        supported_capability(
            "account_status",
            "Validated from the exact registered Claude Code slot.",
        ),
        supported_capability(
            "quota_windows",
            "Collected from Claude Code's local OAuth usage endpoint.",
        ),
    ];
    if account_weekly_not_offered {
        snapshot
            .capabilities
            .push(claude_account_weekly_not_offered_capability());
    }
    if account_session_not_offered {
        snapshot
            .capabilities
            .push(claude_account_session_not_offered_capability());
    }
    snapshot.diagnostics = diagnostics;
    append_current_plan_observation(&mut snapshot);
    let mut state = if stale {
        provider_unavailable_status(
            &captured_at,
            &resolved.account_identifier_hash,
            &resolved.organization_identifier_hash,
        )
    } else {
        fresh_slot_status(
            &captured_at,
            &resolved.account_identifier_hash,
            &resolved.organization_identifier_hash,
            has_account_windows,
            has_scoped_limits,
            has_credit_balances,
        )
    };
    state.quota_snapshot = Some(local_claude_quota_snapshot(
        &snapshot.captured_at,
        &snapshot.quota_windows,
        &snapshot.credit_balances,
        has_account_windows,
        has_scoped_limits,
    ));
    apply_credential_metadata(&mut state, &resolved.credential);
    remember_claude_slot_account_profile(&mut state, snapshot.account.as_ref(), &captured_at);
    state.quota_check_diagnostics = safe_claude_slot_check_diagnostics(
        &snapshot.diagnostics,
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
    );
    Ok((snapshot, state))
}

const CLAUDE_CACHE_REUSED_MESSAGE: &str =
    "Locally cached quota evidence was reused; no provider check was made.";
/// Retain a canonical clock only on a bound cache-reuse or rate-limited outcome. Its deadline
/// was still ahead at the producer's check time; consumers compare it with now.
fn safe_claude_cache_retry_after(diagnostic: &AgentStatusDiagnostic) -> Option<String> {
    let deadline = diagnostic
        .retry_after
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())?;
    let observed = diagnostic
        .observed_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())?;
    if deadline <= observed {
        return None;
    }
    u64::try_from(deadline.unix_timestamp())
        .ok()
        .and_then(rfc3339_from_unix_seconds)
}

/// Persist only known producer outcomes, never provider errors, slot paths or
/// caller-supplied messages. Both hashes must already match the proven slot.
fn safe_claude_slot_check_diagnostics(
    diagnostics: &[AgentStatusDiagnostic],
    account: &str,
    organization: &str,
) -> Vec<AgentStatusDiagnostic> {
    let mut result = Vec::new();
    for diagnostic in diagnostics {
        if account.is_empty()
            || organization.is_empty()
            || diagnostic.account_identifier_hash.as_deref() != Some(account)
            || diagnostic.organization_identifier_hash.as_deref() != Some(organization)
            || result
                .iter()
                .any(|existing: &AgentStatusDiagnostic| existing.code == diagnostic.code)
        {
            continue;
        }
        let message = match diagnostic.code.as_str() {
            "claude_oauth_usage_check_failed" => "The exact-account quota provider request failed.",
            "claude_oauth_usage_check_suppressed" => "A local hold (quota breaker, credential backoff or this account's read slot) suppressed the provider request; no provider check was made.",
            "claude_oauth_usage_cache_reused" => CLAUDE_CACHE_REUSED_MESSAGE,
            "claude_oauth_usage_check_succeeded" => "A supported exact-account quota response was collected successfully.",
            "claude_oauth_usage_network_disabled" => "Quota network collection is disabled on this machine.",
            "claude_oauth_usage_collection_in_progress" => "Quota collection is already in progress; no duplicate provider check was made.",
            CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE => CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE,
            CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE => {
                if diagnostic.message.contains(" saved-resets read") {
                    CLAUDE_OAUTH_USAGE_RATE_LIMITED_SAVED_RESETS_MESSAGE
                } else {
                    CLAUDE_OAUTH_USAGE_RATE_LIMITED_USAGE_MESSAGE
                }
            }
            // Our own typed auth classification; only the HTTP status is kept.
            "claude_oauth_usage_auth_rejected" => {
                if diagnostic.message.contains(" with HTTP 401 ") {
                    "The quota provider rejected this exact slot's credential with HTTP 401; it backs off before retrying."
                } else if diagnostic.message.contains(" with HTTP 403 ") {
                    "The quota provider rejected this exact slot's credential with HTTP 403; it backs off before retrying."
                } else {
                    "The quota provider rejected this exact slot's credential; it backs off before retrying."
                }
            }
            "claude_oauth_usage_auth_backoff" => "This exact slot's credential is backing off after a provider rejection; no provider check was made.",
            "claude_slot_upkeep_credential_unreadable" | "claude_slot_upkeep_probe_failed" | "claude_slot_upkeep_spawn_failed" => "The exact-slot local upkeep result was observed at this time; no quota provider check or vendor-command attempt is implied.",
            "claude_oauth_usage_circuit_open" => {
                // These classifications come from the existing typed breaker,
                // not an arbitrary transport error or credential string.
                if diagnostic.message == "The local quota circuit is open after authentication rejection."
                    || diagnostic.message.starts_with("Stopped calling the Claude OAuth usage endpoint after auth rejected;") {
                    "The local quota circuit is open after authentication rejection."
                } else if diagnostic.message == "The local quota circuit is open after unsupported response shape."
                    || diagnostic.message.starts_with("Stopped calling the Claude OAuth usage endpoint after response shape;") {
                    "The local quota circuit is open after unsupported response shape."
                } else {
                    "The local quota circuit is open after repeated failures."
                }
            }
            code if claude_worker_diagnostic_message(code).is_some() => {
                claude_worker_diagnostic_message(code).expect("matched closed local worker code")
            }
            _ => continue,
        };
        let clock = bounded_claude_collection_timestamp(
            diagnostic.observed_at.as_deref(),
            OffsetDateTime::now_utc(),
        )
        .and(diagnostic.observed_at.clone());
        if claude_worker_diagnostic_message(&diagnostic.code).is_some() && clock.is_none() {
            continue;
        }
        let mut safe =
            AgentStatusDiagnostic::source(&diagnostic.code, diagnostic.severity.clone(), message)
                .with_observed_at(clock)
                .with_quota_binding(Some(account.to_string()), Some(organization.to_string()));
        if matches!(
            diagnostic.code.as_str(),
            "claude_oauth_usage_cache_reused" | CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE
        ) && safe.observed_at.is_some()
        {
            safe.retry_after = safe_claude_cache_retry_after(diagnostic);
        }
        result.push(safe);
    }
    result
}

fn local_claude_quota_snapshot(
    captured_at: &str,
    quota_windows: &[AgentQuotaWindow],
    credit_balances: &[AgentCreditBalance],
    has_account_windows: bool,
    has_scoped_limits: bool,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    // Credit sections carry their own per-section freshness (each from its own
    // read time); the snapshot's state is its meters'.
    let stale = quota_windows
        .iter()
        .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh);
    let state = if stale {
        ClaudeConfigSlotQuotaSnapshotStateV1::Stale
    } else if !has_account_windows || !has_scoped_limits {
        ClaudeConfigSlotQuotaSnapshotStateV1::Partial
    } else {
        ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
    };
    let observed_at = quota_windows
        .iter()
        .filter_map(|window| window.observed_at.as_deref())
        .chain(
            credit_balances
                .iter()
                .filter_map(|balance| balance.updated_at.as_deref()),
        )
        .min()
        .map(ToString::to_string);
    ClaudeConfigSlotQuotaSnapshotV1 {
        state,
        captured_at: captured_at.to_string(),
        observed_at,
        quota_windows: quota_windows.to_vec(),
        credit_balances: credit_balances.to_vec(),
    }
}

fn stale_local_claude_quota_snapshot(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    let mut snapshot = snapshot.clone();
    snapshot.state = ClaudeConfigSlotQuotaSnapshotStateV1::Stale;
    for balance in &mut snapshot.credit_balances {
        // A reader-blind row kept from an older daemon (complete, 0) is shown
        // in its §11.10 shape, never as no resets.
        claude_credit_pools::claude_mark_reader_unavailable(balance);
    }
    mark_quota_meters_stale(&mut snapshot.quota_windows, &mut snapshot.credit_balances);
    snapshot
}

/// Mark a kept reading's meters `Stale`. Only freshness changes: read clocks
/// (`observed_at`, `grants_observed_at`) and values stay as read.
fn mark_quota_meters_stale(
    quota_windows: &mut [AgentQuotaWindow],
    credit_balances: &mut [AgentCreditBalance],
) {
    for window in quota_windows {
        window.freshness = AgentQuotaWindowFreshness::Stale;
    }
    for balance in credit_balances {
        balance.freshness = AgentQuotaWindowFreshness::Stale;
    }
}

fn local_claude_quota_snapshot_within_retention(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
    now: OffsetDateTime,
) -> bool {
    let represented_at = snapshot
        .observed_at
        .as_deref()
        .unwrap_or(snapshot.captured_at.as_str());
    let Ok(represented_at) = OffsetDateTime::parse(represented_at, &Rfc3339) else {
        return false;
    };
    let age_seconds = now.unix_timestamp() - represented_at.unix_timestamp();
    (0..=CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS as i64).contains(&age_seconds)
}

fn local_claude_quota_snapshot_is_fresh_for_account(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: OffsetDateTime,
) -> bool {
    // Credit sections carry their own per-section freshness (each from its own
    // read time); the snapshot's freshness is its meters'.
    if snapshot.state != ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
        || snapshot
            .quota_windows
            .iter()
            .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh)
    {
        return false;
    }
    let represented_at = snapshot
        .observed_at
        .as_deref()
        .unwrap_or(snapshot.captured_at.as_str());
    let Ok(represented_at) = OffsetDateTime::parse(represented_at, &Rfc3339) else {
        return false;
    };
    let age_seconds = now.unix_timestamp() - represented_at.unix_timestamp();
    // The same gate the cache serve path labels with.
    let gate = claude_oauth_usage_serve_gate_seconds(
        account_identifier_hash,
        organization_identifier_hash,
        u64::try_from(now.unix_timestamp()).unwrap_or_default(),
    );
    (0..=i64::try_from(gate).unwrap_or(i64::MAX)).contains(&age_seconds)
}

/// A retained full snapshot reused as fresh: its meters are fresh, but each
/// credit section is relabelled from its own read time (the label taken at
/// capture can be past that section's own limit by now).
fn claude_retained_snapshot_relabelled(
    snapshot: &ClaudeConfigSlotQuotaSnapshotV1,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: OffsetDateTime,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    let mut snapshot = snapshot.clone();
    let now = u64::try_from(now.unix_timestamp()).unwrap_or_default();
    let represented_at = snapshot
        .observed_at
        .as_deref()
        .unwrap_or(snapshot.captured_at.as_str());
    let stored_read_at = OffsetDateTime::parse(represented_at, &Rfc3339)
        .ok()
        .and_then(|instant| u64::try_from(instant.unix_timestamp()).ok())
        .unwrap_or(now);
    claude_credit_pools::label_credit_freshness(
        &mut snapshot.credit_balances,
        claude_oauth_usage_serve_gate_seconds(
            account_identifier_hash,
            organization_identifier_hash,
            now,
        ),
        stored_read_at,
        now,
    );
    snapshot
}

fn claude_usage_has_exact_identity(
    usage: &ClaudeOAuthUsage,
    account_hash: &str,
    organization_hash: &str,
) -> bool {
    !usage.windows.is_empty()
        && usage.windows.iter().all(|window| {
            window.account_identifier_hash.as_deref() == Some(account_hash)
                && window.organization_identifier_hash.as_deref() == Some(organization_hash)
        })
        && usage.credit_balances.iter().all(|balance| {
            balance.account_identifier_hash.as_deref() == Some(account_hash)
                && balance.organization_identifier_hash.as_deref() == Some(organization_hash)
        })
}

fn ensure_claude_quota_access_capability(snapshot: &mut AgentStatusSnapshot) {
    if snapshot
        .capabilities
        .iter()
        .any(|capability| capability.capability == CLAUDE_QUOTA_ACCESS_CAPABILITY)
    {
        return;
    }
    snapshot.capabilities.push(supported_capability(
        CLAUDE_QUOTA_ACCESS_CAPABILITY,
        "This daemon reports exact-slot Claude quota access state for strongly bound accounts.",
    ));
}

fn projected_claude_quota_access_state(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<ClaudeQuotaAccessState> {
    let strongly_bound = status
        .account_identifier_hash
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        && status
            .organization_identifier_hash
            .as_deref()
            .is_some_and(|value| !value.is_empty());
    if !strongly_bound {
        return None;
    }
    if status
        .upkeep
        .as_ref()
        .is_some_and(|upkeep| upkeep.result == ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled)
    {
        return Some(ClaudeQuotaAccessState::Paused);
    }
    if status
        .upkeep
        .as_ref()
        .is_some_and(|upkeep| upkeep.result == ClaudeConfigSlotUpkeepResultV1::MissingBinary)
    {
        return Some(ClaudeQuotaAccessState::AttentionRequired);
    }
    match status.state {
        ClaudeConfigSlotCollectionStateV1::Fresh => {
            Some(if status.has_account_windows && status.has_scoped_limits {
                ClaudeQuotaAccessState::Full
            } else {
                ClaudeQuotaAccessState::Partial
            })
        }
        ClaudeConfigSlotCollectionStateV1::RefreshDue
        | ClaudeConfigSlotCollectionStateV1::StaleAccessToken => Some(
            claude_blocked_refresh_worker_escalation(status, OffsetDateTime::now_utc())
                .unwrap_or(ClaudeQuotaAccessState::TemporarilyUnavailable),
        ),
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        | ClaudeConfigSlotCollectionStateV1::CollectionInProgress
        | ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
        | ClaudeConfigSlotCollectionStateV1::ProbeFailed
        | ClaudeConfigSlotCollectionStateV1::ReloginApproaching => {
            Some(ClaudeQuotaAccessState::TemporarilyUnavailable)
        }
        ClaudeConfigSlotCollectionStateV1::NeedsLogin => {
            Some(ClaudeQuotaAccessState::ReconnectRequired)
        }
        ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
            if status.upkeep.as_ref().is_some_and(|upkeep| {
                upkeep.result == ClaudeConfigSlotUpkeepResultV1::NeedsLogin
            }) =>
        {
            Some(ClaudeQuotaAccessState::ReconnectRequired)
        }
        ClaudeConfigSlotCollectionStateV1::CollectionPaused
        | ClaudeConfigSlotCollectionStateV1::UpkeepNotConsented => {
            Some(ClaudeQuotaAccessState::Paused)
        }
        ClaudeConfigSlotCollectionStateV1::IdentityUnknown
        | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
        | ClaudeConfigSlotCollectionStateV1::IdentityMismatch => {
            Some(ClaudeQuotaAccessState::AttentionRequired)
        }
        ClaudeConfigSlotCollectionStateV1::Unverified
        | ClaudeConfigSlotCollectionStateV1::DuplicateAccount
        | ClaudeConfigSlotCollectionStateV1::CapacityExceeded => None,
    }
}

/// Worker outcomes that mean the latest refresh pass for a blocked saved
/// anchor did not take, as opposed to a pending, paused or successful pass.
/// `backoff` is included because it only follows a failed attempt for the same
/// credential expiry; omitting it would make the projection flap between runs.
const CLAUDE_BLOCKED_REFRESH_FAILURE_WORKER_CODES: &[&str] = &[
    "claude_slot_worker_expiry_unchanged",
    "claude_slot_worker_nonzero_exit",
    "claude_slot_worker_timed_out",
    "claude_slot_worker_spawn_failed",
    "claude_slot_worker_credential_unreadable",
    "claude_slot_worker_probe_failed",
    "claude_slot_worker_backoff",
    "claude_slot_worker_reconciliation_refused",
    "claude_slot_worker_identity_unknown",
    "claude_slot_worker_identity_credential_unavailable",
    "claude_slot_worker_identity_mismatch",
];

/// How long a blocked saved anchor's access may stay expired, with an exact
/// failed worker receipt, before it stops being presented as temporary.
const CLAUDE_BLOCKED_REFRESH_ESCALATION_SECONDS: i64 = 24 * 60 * 60;

/// Truthful access state for a saved anchor that collection skips because its
/// saved access deadline has expired.
///
/// The fenced local worker receipt is the only current evidence about that
/// anchor's real credential. A worker that read a signed-out or expired refresh
/// grant reports `needs_login`: the saved connection needs sign-in again, not
/// patience. A refresh that keeps failing for a day is an attention state that
/// names its worker reason instead of an indefinitely "temporary" one. Any
/// newer worker pass (refresh, reconciliation) replaces the receipt, so this
/// never sticks after the credential recovers. Meters and quota clocks are
/// untouched; this classifies saved-connection health only.
fn claude_blocked_refresh_worker_escalation(
    status: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) -> Option<ClaudeQuotaAccessState> {
    let receipt = latest_exact_claude_worker_receipt_code(status, now)?;
    if receipt == "claude_slot_worker_needs_login" {
        return Some(ClaudeQuotaAccessState::ReconnectRequired);
    }
    let expired_long_ago = bounded_claude_collection_timestamp(
        status.access_expires_at.as_deref(),
        now - TimeDuration::seconds(CLAUDE_BLOCKED_REFRESH_ESCALATION_SECONDS),
    )
    .is_some();
    (expired_long_ago && CLAUDE_BLOCKED_REFRESH_FAILURE_WORKER_CODES.contains(&receipt.as_str()))
        .then_some(ClaudeQuotaAccessState::AttentionRequired)
}

/// Code of the newest exact-binding local worker receipt on one saved slot,
/// bounded by `now`. Forged, foreign-pair and future receipts are ignored.
fn latest_exact_claude_worker_receipt_code(
    status: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) -> Option<String> {
    let account = status.account_identifier_hash.as_deref()?;
    let organization = status.organization_identifier_hash.as_deref()?;
    safe_claude_slot_check_diagnostics(&status.quota_check_diagnostics, account, organization)
        .into_iter()
        .filter(|entry| claude_worker_diagnostic_message(&entry.code).is_some())
        .filter_map(|entry| {
            bounded_claude_collection_timestamp(entry.observed_at.as_deref(), now)
                .map(|clock| (entry.code, clock))
        })
        .max_by_key(|(_, clock)| *clock)
        .map(|(code, _)| code)
}

/// Saved state for a blocked slot whose newest exact worker pass read a
/// credential that needs a new sign-in.
///
/// The worker's pre-claim `needs_login` describes the slot's actual
/// credential, but its witness is keyed by that credential's expiry (for a
/// signed-out credential, often the epoch), so the foreground's exact saved
/// deadline match never adopts it and the slot stayed `refresh_due`. That
/// hid both reconnect-required health and the companion's "Sign in again".
/// The receipt is already fenced to this registration, pair and saved
/// deadlines with its original clock, and any newer worker pass replaces it.
/// Only the presented state changes: the saved upkeep result stays
/// `refresh_due`, so collection keeps queuing the worker and a valid
/// credential after sign-in reconciles through the existing worker path.
fn apply_claude_worker_needs_login_state(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) {
    if !matches!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::RefreshDue
            | ClaudeConfigSlotCollectionStateV1::StaleAccessToken
    ) || latest_exact_claude_worker_receipt_code(status, now).as_deref()
        != Some("claude_slot_worker_needs_login")
    {
        return;
    }
    let (state, code, message) =
        upkeep_state_diagnostic(ClaudeConfigSlotUpkeepResultV1::NeedsLogin);
    status.state = state;
    status.diagnostics = vec![ClaudeConfigSlotDiagnosticV1 {
        code,
        message: message.to_string(),
    }];
}

fn claude_slot_status_carries_meters(status: &ClaudeConfigSlotCollectionStatusV1) -> bool {
    matches!(
        projected_claude_quota_access_state(status),
        None | Some(ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial)
    )
}

fn apply_claude_quota_access_state(
    snapshot: &mut AgentStatusSnapshot,
    status: &ClaudeConfigSlotCollectionStatusV1,
) {
    ensure_claude_quota_access_capability(snapshot);
    let Some(projected) = projected_claude_quota_access_state(status) else {
        return;
    };
    let account_matches = snapshot.account.as_ref().is_some_and(|account| {
        account.account_identifier_hash.as_deref() == status.account_identifier_hash.as_deref()
            && account.organization_identifier_hash.as_deref()
                == status.organization_identifier_hash.as_deref()
    });
    if account_matches {
        snapshot
            .account
            .as_mut()
            .expect("matching Claude account must exist")
            .claude_quota_access_state = Some(projected);
    }
}

fn exact_claude_slot_account_profile(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<&ClaudeConfigSlotAccountProfileV1> {
    let profile = status.account_profile.as_ref()?;
    (status.account_identifier_hash.as_deref() == Some(profile.account_identifier_hash.as_str())
        && status.organization_identifier_hash.as_deref()
            == Some(profile.organization_identifier_hash.as_str())
        && !profile.account_identifier_hash.is_empty()
        && !profile.organization_identifier_hash.is_empty()
        && bounded_claude_collection_timestamp(
            Some(&profile.captured_at),
            OffsetDateTime::now_utc(),
        )
        .is_some())
    .then_some(profile)
}

fn remember_claude_slot_account_profile(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    account: Option<&AgentAccountStatus>,
    captured_at: &str,
) {
    let Some(account) = account.filter(|account| {
        account.login_state == AgentLoginState::SignedIn
            && account.account_identifier_hash == status.account_identifier_hash
            && account.organization_identifier_hash == status.organization_identifier_hash
    }) else {
        return;
    };
    let Some(binding) = account
        .account_identifier_hash
        .as_deref()
        .zip(account.organization_identifier_hash.as_deref())
        .and_then(|(account, organization)| ClaudeStrongBinding::new(account, organization))
    else {
        return;
    };
    if account.email.is_none()
        && account.organization_label.is_none()
        && account.plan_type.is_none()
        && account.subscription_product.is_none()
    {
        return;
    }
    status.account_profile = Some(ClaudeConfigSlotAccountProfileV1 {
        account_identifier_hash: binding.account_identifier_hash,
        organization_identifier_hash: binding.organization_identifier_hash,
        captured_at: captured_at.to_string(),
        email: account.email.clone(),
        organization_label: account.organization_label.clone(),
        plan_type: account.plan_type.clone(),
        subscription_product: account.subscription_product.clone(),
    });
}

fn inherit_claude_slot_account_profile(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
) {
    let previous = previous
        .filter(|previous| {
            previous.account_identifier_hash == status.account_identifier_hash
                && previous.organization_identifier_hash == status.organization_identifier_hash
        })
        .and_then(exact_claude_slot_account_profile)
        .cloned();
    let Some(mut current) = exact_claude_slot_account_profile(status).cloned() else {
        status.account_profile = previous;
        return;
    };
    let Some(previous) = previous else {
        return;
    };
    // Plan and product describe one tier. A newly reported different tier
    // wins; never complete it with a label from the previous tier.
    let tier_compatible = (current.plan_type.is_none() && current.subscription_product.is_none())
        || (current.plan_type.is_some()
            && current.plan_type == previous.plan_type
            && (current.subscription_product.is_none()
                || current.subscription_product == previous.subscription_product))
        || (current.subscription_product.is_some()
            && current.subscription_product == previous.subscription_product
            && (current.plan_type.is_none() || current.plan_type == previous.plan_type));
    let mut retained = false;
    let mut fill_missing = |current: &mut Option<String>, previous: &Option<String>| {
        if current.is_none() && previous.is_some() {
            *current = previous.clone();
            retained = true;
        }
    };
    fill_missing(&mut current.email, &previous.email);
    fill_missing(
        &mut current.organization_label,
        &previous.organization_label,
    );
    if tier_compatible {
        fill_missing(&mut current.plan_type, &previous.plan_type);
        fill_missing(
            &mut current.subscription_product,
            &previous.subscription_product,
        );
    }
    if retained {
        // One conservative profile clock: retained old fields do not acquire
        // the later auth-response time. This is never quota/check freshness.
        let previous_at = OffsetDateTime::parse(&previous.captured_at, &Rfc3339)
            .expect("exact profile clock was validated");
        let current_at = OffsetDateTime::parse(&current.captured_at, &Rfc3339)
            .expect("exact profile clock was validated");
        if previous_at < current_at {
            current.captured_at = previous.captured_at;
        }
    }
    status.account_profile = Some(current);
}

fn retain_exact_claude_slot_binding(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    account_hash: &str,
    organization_hash: &str,
) {
    if account_hash.is_empty() || organization_hash.is_empty() {
        return;
    }
    status.account_identifier_hash = Some(account_hash.to_string());
    status.organization_identifier_hash = Some(organization_hash.to_string());
    status.display_label = Some(format!(
        "Claude account {}",
        &account_hash[..account_hash.len().min(8)]
    ));
}

fn claude_config_slot_for_descriptor(
    descriptor: &ClaudeConfigSlotDescriptorV1,
) -> Option<ClaudeConfigDirSlot> {
    match descriptor.config_dir.as_ref() {
        Some(config_dir) => ClaudeConfigDirSlot::registered(config_dir.clone()).ok(),
        None if descriptor.slot_id == "default" => Some(ClaudeConfigDirSlot::Default),
        None => None,
    }
}

fn clear_claude_slot_binding(status: &mut ClaudeConfigSlotCollectionStatusV1) {
    status.account_identifier_hash = None;
    status.organization_identifier_hash = None;
    status.display_label = None;
    status.account_profile = None;
    status.last_full_quota_read_at = None;
    status.has_account_windows = false;
    status.has_scoped_limits = false;
    status.has_credit_balances = false;
    status.quota_snapshot = None;
    status.quota_check_diagnostics.clear();
}

fn retain_verified_claude_slot_binding(
    slot_id: &str,
    slot: &ClaudeConfigDirSlot,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    let current_binding = read_claude_cli_oauth_account(&slot.identity_path(&home_dir()))
        .as_ref()
        .and_then(claude_strong_oauth_identity_hashes);
    retain_verified_claude_binding(slot_id, current_binding, status);
}

/// [`retain_verified_claude_slot_binding`] for a registered slot, against the
/// stored token's proven owner where it outranks a stale `.claude.json`.
fn retain_registered_claude_slot_binding(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    owner: Option<&ClaudeTokenOwner>,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    match (owner, claude_config_slot_for_descriptor(descriptor)) {
        (Some(owner), _) => {
            retain_verified_claude_binding(&descriptor.slot_id, owner.proven_binding(), status);
        }
        (None, Some(slot)) => {
            retain_verified_claude_slot_binding(&descriptor.slot_id, &slot, status)
        }
        (None, None) => clear_claude_slot_binding(status),
    }
}

/// Whether [`retain_verified_claude_binding`] kept the slot's last verified
/// account, or why it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeBindingRetention {
    /// The current login is the last verified account; it was kept.
    Retained,
    /// The current login is proven to be a different account.
    OtherOwner,
    /// No last verified account, or the current login names none.
    OwnerUnknown,
}

/// [`retain_verified_claude_slot_binding`] against a binding the caller
/// already resolved (the default home's proven token owner).
///
/// A `ConcurrentMutation` is a benign retry only while the slot keeps its last
/// verified account. When the account file now names a different owner (A
/// read first, B read last) the race is reported as `IdentityMismatch`, and
/// with no provable owner as `IdentityUnknown`; B is never adopted. Every
/// consumer (attention, setup check, companion) then keys on the state alone.
fn retain_verified_claude_binding(
    slot_id: &str,
    current_binding: Option<(String, String)>,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    let retention = retain_or_clear_verified_claude_binding(slot_id, current_binding, status);
    if status.state != ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
        || retention == ClaudeBindingRetention::Retained
    {
        return;
    }
    let failure = if retention == ClaudeBindingRetention::OtherOwner {
        ClaudeSlotProbeFailure::IdentityMismatch
    } else {
        ClaudeSlotProbeFailure::IdentityUnknown
    };
    let replacement = failure.status(status.observed_at.as_deref().unwrap_or_default());
    status.state = replacement.state;
    // Swap only the race diagnostic; upkeep diagnostics already on the
    // status stay.
    status.diagnostics.retain(|diagnostic| {
        diagnostic.code != ClaudeConfigSlotDiagnosticCodeV1::ConcurrentMutation
    });
    let mut diagnostics = replacement.diagnostics;
    diagnostics.append(&mut status.diagnostics);
    status.diagnostics = diagnostics;
}

fn retain_or_clear_verified_claude_binding(
    slot_id: &str,
    current_binding: Option<(String, String)>,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) -> ClaudeBindingRetention {
    let Some(previous) = read_persisted_claude_slot_collection_state()
        .slots
        .get(slot_id)
        .cloned()
    else {
        if status
            .account_identifier_hash
            .as_deref()
            .zip(status.organization_identifier_hash.as_deref())
            != current_binding
                .as_ref()
                .map(|(account, organization)| (account.as_str(), organization.as_str()))
        {
            clear_claude_slot_binding(status);
        }
        return if claude_slot_status_binding(status).is_some() {
            ClaudeBindingRetention::Retained
        } else {
            ClaudeBindingRetention::OwnerUnknown
        };
    };
    let (Some(previous_account), Some(previous_organization)) = (
        previous.account_identifier_hash.as_deref(),
        previous.organization_identifier_hash.as_deref(),
    ) else {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OwnerUnknown;
    };
    let Some((current_account, current_organization)) = current_binding else {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OwnerUnknown;
    };
    if current_account != previous_account || current_organization != previous_organization {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OtherOwner;
    }
    if status
        .account_identifier_hash
        .as_deref()
        .is_some_and(|account| account != current_account)
        || status
            .organization_identifier_hash
            .as_deref()
            .is_some_and(|organization| organization != current_organization)
    {
        clear_claude_slot_binding(status);
        return ClaudeBindingRetention::OtherOwner;
    }
    retain_exact_claude_slot_binding(status, &current_account, &current_organization);
    inherit_claude_slot_account_profile(status, Some(&previous));
    retain_previous_complete_claude_read(status, previous);
    ClaudeBindingRetention::Retained
}

/// Keep the same account's last complete reading, marked stale, when the
/// current pass produced none. Callers prove `previous` is the same binding.
fn retain_previous_complete_claude_read(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    previous: ClaudeConfigSlotCollectionStatusV1,
) {
    let current_has_complete_read = status.last_full_quota_read_at.is_some()
        && status.has_account_windows
        && status.has_scoped_limits;
    if !current_has_complete_read
        && previous.last_full_quota_read_at.is_some()
        && previous.has_account_windows
        && previous.has_scoped_limits
    {
        status.last_full_quota_read_at = previous.last_full_quota_read_at;
        status.has_account_windows = true;
        status.has_scoped_limits = true;
        status.has_credit_balances = previous.has_credit_balances;
        status.quota_snapshot = previous
            .quota_snapshot
            .filter(|snapshot| {
                local_claude_quota_snapshot_within_retention(snapshot, OffsetDateTime::now_utc())
            })
            .map(|snapshot| stale_local_claude_quota_snapshot(&snapshot));
    }
}

/// A registered slot's strong local identity as last recorded by collection.
fn claude_slot_status_binding(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<ClaudeSlotAccountBinding> {
    ClaudeSlotAccountBinding::new(
        status.account_identifier_hash.as_deref()?,
        status.organization_identifier_hash.as_deref()?,
    )
}

/// The account+organization this registered slot is approved to collect for,
/// back-filling the approval once for slots registered before approvals were
/// persisted (see `ensure_approved_slot_binding`). `Ok(None)` leaves the slot
/// ungated, which is exactly the behaviour before approvals existed. When the
/// back-fill cannot be persisted, the binding it would have recorded is still
/// enforced for this pass; `Err` means the approval could not be determined
/// at all, and callers then refuse to collect rather than run ungated.
fn claude_slot_expected_binding(
    slot_id: &str,
    observed: Option<&ClaudeSlotAccountBinding>,
) -> Result<Option<ClaudeSlotAccountBinding>, ()> {
    if slot_id == "default" {
        return Ok(None);
    }
    let store = FileClaudeConfigSlotSettingsStore::default();
    store
        .ensure_approved_slot_binding(
            ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
            slot_id,
            observed,
        )
        .or_else(|_| store.prospective_approved_slot_binding(slot_id, observed))
        .map_err(|_| ())
}

/// Collection is refused for one pass when the approval is undeterminable.
/// The slot keeps its last verified pair so its card stays on that account.
fn claude_slot_approval_unavailable_status(
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = ClaudeSlotProbeFailure::ConcurrentMutation.status(captured_at);
    if let Some(binding) = previous.and_then(claude_slot_status_binding) {
        retain_exact_claude_slot_binding(
            &mut status,
            &binding.account_identifier_hash,
            &binding.organization_identifier_hash,
        );
    }
    status
}

/// Whether this registered slot's current Claude login is not provably the
/// account it is approved for, under collection's owner rule with remembered
/// verdicts only (never a provider call): another account, an unproven owner,
/// or an account file that is missing, unreadable or without strong ids.
/// Read-only; used by the upkeep worker's final spawn and publication fences
/// so a refresh never runs for another or an unknown login. An unreadable
/// approval also refuses.
pub(crate) fn claude_slot_login_unapproved(descriptor: &ClaudeConfigSlotDescriptorV1) -> bool {
    match FileClaudeConfigSlotSettingsStore::default().expected_slot_binding(&descriptor.slot_id) {
        Ok(None) => false,
        Ok(Some(expected)) => !matches!(
            claude_slot_owner_rule(
                &descriptor.slot_id,
                &expected,
                read_registered_claude_slot_locally(descriptor).as_ref(),
                false,
            ),
            ClaudeSlotOwnerRule::Named | ClaudeSlotOwnerRule::Proven(_)
        ),
        Err(_) => true,
    }
}

/// Plan type for local wording only, from `.claude.json` alone. Mirrors the
/// collector's Max 5x/20x and Team seat refinements without an auth status.
fn claude_oauth_plan_type_for_label(oauth: &ClaudeCliOauthAccount) -> Option<String> {
    let organization_type = normalize_plan_type(oauth.organization_type.clone()?);
    let base = organization_type
        .strip_prefix("claude_")
        .unwrap_or(&organization_type)
        .to_string();
    let tier = |value: &Option<String>| value.clone().map(normalize_plan_type).unwrap_or_default();
    let organization_tier = tier(&oauth.organization_rate_limit_tier);
    let user_tier = tier(&oauth.user_rate_limit_tier);
    let refined = match base.as_str() {
        "max" => [&organization_tier, &user_tier]
            .into_iter()
            .find_map(|tier| {
                if tier.ends_with("max_5x") {
                    Some("max_5x")
                } else if tier.ends_with("max_20x") {
                    Some("max_20x")
                } else {
                    None
                }
            })
            .map(str::to_string),
        "team" => {
            let seat = tier(&oauth.seat_tier);
            if seat.contains("premium") || user_tier.ends_with("max_5x") {
                Some("team_premium".to_string())
            } else if seat.contains("standard") {
                Some("team_standard".to_string())
            } else {
                None
            }
        }
        _ => None,
    };
    Some(refined.unwrap_or(base)).filter(|plan| !plan.is_empty())
}

/// "Claude Ultra", "Claude Team Premium", ... for a local message.
fn claude_plan_label(plan_type: Option<&str>) -> Option<String> {
    claude_plan_name(plan_type).map(|name| format!("Claude {name}"))
}

/// "Ultra", "Team Premium", ... Plan ids keep their old names: `max_5x` is
/// Max, `max_20x` is Ultra, and a bare `max` (tier unknown) is either.
fn claude_plan_name(plan_type: Option<&str>) -> Option<String> {
    let plan = normalize_plan_type(plan_type?.to_string());
    let plan = plan.strip_prefix("claude_").unwrap_or(&plan);
    let label = match plan {
        "" => return None,
        "max_20x" => "Ultra".to_string(),
        "max_5x" => "Max".to_string(),
        "max" => "Max or Ultra".to_string(),
        other => other
            .split('_')
            .filter(|word| !word.is_empty())
            .map(|word| {
                let mut chars = word.chars();
                chars.next().map_or_else(String::new, |first| {
                    first.to_uppercase().collect::<String>() + chars.as_str()
                })
            })
            .collect::<Vec<_>>()
            .join(" "),
    };
    Some(label)
}

/// Local-only explanation naming the plans of both logins. It never names an
/// email and is never uploaded: degraded projections carry codes only.
fn claude_slot_binding_mismatch_message(
    approved_plan: Option<&str>,
    signed_in_plan: Option<&str>,
) -> String {
    let approved = claude_plan_label(approved_plan)
        .map(|label| format!("the {label} account"))
        .unwrap_or_else(|| "the account it was set up with".to_string());
    let signed_in = claude_plan_label(signed_in_plan)
        .map(|label| format!("a different {label} account"))
        .unwrap_or_else(|| "a different Claude account".to_string());
    format!(
        "Claude Code in this connection is now signed in to {signed_in}. This connection is for {approved}, so Ottto paused limit reading, uploads and token refresh here and assigned nothing to the other account. Sign in again with {approved} to resume."
    )
}

/// Collection status for a slot whose current login is not the account it is
/// approved for. It keeps the approved pair, profile and that account's own
/// last complete reading (stale), so local and degraded projections stay on
/// the approved account; nothing from the other login is kept.
fn claude_slot_binding_mismatch_status(
    expected: &ClaudeSlotAccountBinding,
    signed_in_plan: Option<&str>,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    claude_slot_approval_blocked_status(
        expected,
        ClaudeSlotProbeFailure::IdentityMismatch,
        |approved_plan| claude_slot_binding_mismatch_message(approved_plan, signed_in_plan),
        previous,
        captured_at,
    )
}

/// Local message when a bound slot's Claude account file cannot be read.
fn claude_slot_unknown_login_message(approved_plan: Option<&str>) -> String {
    let approved = claude_plan_label(approved_plan)
        .map(|label| format!("the {label} account"))
        .unwrap_or_else(|| "the account it was set up with".to_string());
    format!(
        "Claude Code's account file for this connection is missing or unreadable, so Ottto cannot confirm it is still signed in to {approved}. Ottto paused limit reading, uploads and token refresh here. Sign in again with {approved} to resume."
    )
}

/// Status for a bound slot that must not be collected or refreshed this
/// pass. It keeps the approved pair, profile and that account's own last
/// complete reading (stale), so local and degraded projections stay on the
/// approved account; nothing from any other login is kept.
fn claude_slot_approval_blocked_status(
    expected: &ClaudeSlotAccountBinding,
    failure: ClaudeSlotProbeFailure,
    message: impl FnOnce(Option<&str>) -> String,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let previous = previous
        .filter(|previous| claude_slot_status_binding(previous).as_ref() == Some(expected))
        .cloned();
    let approved_plan = previous
        .as_ref()
        .and_then(exact_claude_slot_account_profile)
        .and_then(|profile| profile.plan_type.clone());
    let mut status = failure.status(captured_at);
    if let Some(diagnostic) = status.diagnostics.first_mut() {
        diagnostic.message = message(approved_plan.as_deref());
    }
    retain_exact_claude_slot_binding(
        &mut status,
        &expected.account_identifier_hash,
        &expected.organization_identifier_hash,
    );
    if let Some(previous) = previous {
        inherit_claude_slot_account_profile(&mut status, Some(&previous));
        retain_previous_complete_claude_read(&mut status, previous);
    }
    status
}

/// Gate before upkeep, any CLI spawn or usage call: refuse when the slot's
/// approval is undeterminable. `Ok` carries the expected binding (when the
/// slot has one) for the owner rule and the post-resolution check.
#[expect(clippy::result_large_err, reason = "Err is the full slot status")]
fn claude_slot_pre_collection_gate(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> Result<Option<ClaudeSlotAccountBinding>, ClaudeConfigSlotCollectionStatusV1> {
    let observed = previous.and_then(claude_slot_status_binding);
    claude_slot_expected_binding(&descriptor.slot_id, observed.as_ref())
        .map_err(|()| claude_slot_approval_unavailable_status(previous, captured_at))
}

/// Local message when another account's `.claude.json` sits in a slot whose
/// stored sign-in cannot be checked yet.
fn claude_slot_owner_unproven_message(approved_plan: Option<&str>) -> String {
    let approved = claude_plan_label(approved_plan)
        .map(|label| format!("the {label} account"))
        .unwrap_or_else(|| "the account it was set up with".to_string());
    format!(
        "Claude Code's account file for this connection names a different account, and Ottto could not yet confirm that its saved sign-in is still {approved}. Ottto paused limit reading and uploads here until it can; reconnect if this does not clear."
    )
}

/// Local wording for a slot whose approval was observed, not verified.
fn claude_slot_observed_approval_notice(approved_plan: Option<&str>) -> String {
    match claude_plan_label(approved_plan) {
        Some(label) => format!(
            "Approved from the current Claude login ({label}). If this is the wrong account, sign in again with the right one."
        ),
        None => "Approved from the current Claude login. If this is the wrong account, sign in again with the right one.".to_string(),
    }
}

/// Mark registered slots whose approval was back-filled from an observed
/// login (trust on first use). The notice is local-only and clears as soon
/// as a verified setup or reconnect approves the slot.
fn apply_claude_slot_approval_notice(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    approval: Option<&ottto_core::ClaudeSlotApproval>,
) {
    status.approval_notice = approval
        .filter(|approval| {
            approval.source == ottto_core::ClaudeSlotApprovalSource::Observed
                && claude_slot_status_binding(status).as_ref() == Some(&approval.binding)
        })
        .map(|_| {
            claude_slot_observed_approval_notice(
                exact_claude_slot_account_profile(status)
                    .and_then(|profile| profile.plan_type.as_deref()),
            )
        });
}

fn claude_slot_approvals() -> BTreeMap<String, ottto_core::ClaudeSlotApproval> {
    FileClaudeConfigSlotSettingsStore::default()
        .slot_approvals()
        .unwrap_or_default()
}

/// Gate after the exact slot resolved, before its usage call. A slot without
/// any approval records this first verified identity (trust on first use).
#[expect(clippy::result_large_err, reason = "Err is the full slot status")]
fn claude_slot_post_resolution_gate(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    expected: Option<ClaudeSlotAccountBinding>,
    resolved: &ResolvedClaudeSlot,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    captured_at: &str,
) -> Result<(), ClaudeConfigSlotCollectionStatusV1> {
    let current = ClaudeSlotAccountBinding::new(
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
    );
    let expected = match expected {
        Some(expected) => Some(expected),
        None => claude_slot_expected_binding(&descriptor.slot_id, current.as_ref())
            .map_err(|()| claude_slot_approval_unavailable_status(previous, captured_at))?,
    };
    match (expected, current) {
        (Some(expected), Some(current)) if expected != current => {
            Err(claude_slot_binding_mismatch_status(
                &expected,
                resolved.account.plan_type.as_deref(),
                previous,
                captured_at,
            ))
        }
        _ => Ok(()),
    }
}

fn degraded_claude_slot_snapshot(
    status: &ClaudeConfigSlotCollectionStatusV1,
    durability: ClaudeAccountAnchorDurabilityV1,
    anchor_health: Option<ClaudeAccountAnchorHealthV1>,
    captured_at: &str,
    expires_at: &str,
) -> Option<AgentStatusSnapshot> {
    let access_state = projected_claude_quota_access_state(status)?;
    if matches!(
        access_state,
        ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial
    ) {
        return None;
    }
    let account_hash = status.account_identifier_hash.as_ref()?.clone();
    let organization_hash = status.organization_identifier_hash.as_ref()?.clone();
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CliJson,
        captured_at.to_string(),
        expires_at.to_string(),
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: if access_state == ClaudeQuotaAccessState::ReconnectRequired {
            AgentLoginState::SignedOut
        } else {
            AgentLoginState::Unknown
        },
        provider: Some("anthropic".to_string()),
        auth_method: Some("oauth".to_string()),
        billing_channel: Some("subscription".to_string()),
        account_identifier_hash: Some(account_hash),
        organization_identifier_hash: Some(organization_hash),
        billing_identity_evidence: Some("provider_account_id".to_string()),
        claude_quota_access_state: Some(access_state),
        claude_anchor_durability: Some(durability),
        claude_anchor_health: anchor_health,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
        ..unsupported_account("anthropic")
    });
    if let Some(profile) = exact_claude_slot_account_profile(status) {
        let account = snapshot.account.as_mut().expect("degraded account exists");
        account.email = profile.email.clone();
        account.organization_label = profile.organization_label.clone();
        account.plan_type = profile.plan_type.clone();
        account.subscription_product = profile.subscription_product.clone();
    }
    if let Some(local) = status.quota_snapshot.as_ref().filter(|local| {
        local_claude_quota_snapshot_within_retention(local, OffsetDateTime::now_utc())
    }) {
        snapshot.quota_windows = local
            .quota_windows
            .iter()
            .cloned()
            .map(|mut window| {
                window.freshness = AgentQuotaWindowFreshness::Stale;
                window
            })
            .collect();
        snapshot.credit_balances = local
            .credit_balances
            .iter()
            .cloned()
            .map(|mut balance| {
                balance.freshness = AgentQuotaWindowFreshness::Stale;
                balance
            })
            .collect();
    }
    ensure_claude_quota_access_capability(&mut snapshot);
    let (code, message) = match access_state {
        ClaudeQuotaAccessState::TemporarilyUnavailable => (
            "claude_quota_temporarily_unavailable",
            "Full Claude quota collection is temporarily unavailable for this registered account and will retry automatically.",
        ),
        ClaudeQuotaAccessState::ReconnectRequired => (
            "claude_quota_reconnect_required",
            "This registered Claude account requires customer-owned official Claude Code login before full quota collection can resume.",
        ),
        ClaudeQuotaAccessState::Paused => (
            "claude_quota_collection_paused",
            "Full Claude quota collection is paused for this registered account.",
        ),
        ClaudeQuotaAccessState::AttentionRequired => (
            "claude_quota_attention_required",
            "This registered Claude account needs local attention before full quota collection can resume.",
        ),
        ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial => unreachable!(),
    };
    snapshot.diagnostics.push(
        AgentStatusDiagnostic::source(code, AgentDiagnosticSeverity::Warning, message)
            .with_quota_binding(
                status.account_identifier_hash.clone(),
                status.organization_identifier_hash.clone(),
            ),
    );
    snapshot
        .diagnostics
        .extend(safe_claude_slot_check_diagnostics(
            &status.quota_check_diagnostics,
            status.account_identifier_hash.as_deref()?,
            status.organization_identifier_hash.as_deref()?,
        ));
    // Enum-derived codes describe local collection/upkeep state only. Their
    // clocks are intentionally absent: slot captured_at is not a provider check.
    let state_code = serde_json::to_value(&status.state)
        .ok()?
        .as_str()?
        .to_string();
    snapshot.diagnostics.push(
        AgentStatusDiagnostic::source(
            format!("claude_slot_collection_{state_code}"),
            AgentDiagnosticSeverity::Warning,
            "The exact registered slot reported this local collection state.",
        )
        .with_quota_binding(
            status.account_identifier_hash.clone(),
            status.organization_identifier_hash.clone(),
        ),
    );
    for diagnostic in &status.diagnostics {
        let code = serde_json::to_value(diagnostic.code)
            .ok()?
            .as_str()?
            .to_string();
        let code = format!("claude_slot_collection_{code}");
        if !snapshot.diagnostics.iter().any(|item| item.code == code) {
            snapshot.diagnostics.push(
                AgentStatusDiagnostic::source(
                    code,
                    AgentDiagnosticSeverity::Warning,
                    "The exact registered slot reported this local collection state.",
                )
                .with_quota_binding(
                    status.account_identifier_hash.clone(),
                    status.organization_identifier_hash.clone(),
                ),
            );
        }
    }
    if let Some(upkeep) = &status.upkeep {
        let result = serde_json::to_value(upkeep.result)
            .ok()?
            .as_str()?
            .to_string();
        let result_code = format!("claude_slot_upkeep_{result}");
        if !snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == result_code)
        {
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            result_code, AgentDiagnosticSeverity::Info,
            "The exact registered slot reported this local credential-upkeep result; it is not a quota provider check.",
        ).with_quota_binding(status.account_identifier_hash.clone(), status.organization_identifier_hash.clone()));
        }
        if bounded_claude_collection_timestamp(
            upkeep.attempted_at.as_deref(),
            OffsetDateTime::now_utc(),
        )
        .is_some()
        {
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "claude_slot_upkeep_attempt_started", AgentDiagnosticSeverity::Info,
                "The last recorded local credential-upkeep attempt started at this time; completion time is unavailable.",
            ).with_observed_at(upkeep.attempted_at.clone()).with_quota_binding(status.account_identifier_hash.clone(), status.organization_identifier_hash.clone()));
        }
    }
    Some(snapshot)
}

fn claude_quota_access_priority(snapshot: &AgentStatusSnapshot) -> u8 {
    match snapshot
        .account
        .as_ref()
        .and_then(|account| account.claude_quota_access_state)
    {
        Some(ClaudeQuotaAccessState::ReconnectRequired) => 4,
        Some(ClaudeQuotaAccessState::AttentionRequired) => 3,
        Some(ClaudeQuotaAccessState::Paused) => 2,
        Some(ClaudeQuotaAccessState::TemporarilyUnavailable) => 1,
        _ => 0,
    }
}

fn degraded_claude_slot_snapshots(
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    canonical_anchors: &BTreeMap<ClaudeStrongBinding, String>,
    winning_bindings: &BTreeSet<ClaudeStrongBinding>,
    captured_at: &str,
    expires_at: &str,
) -> Vec<AgentStatusSnapshot> {
    let mut degraded_by_binding = BTreeMap::<ClaudeStrongBinding, AgentStatusSnapshot>::new();
    for (slot_id, status) in slot_states {
        let Some(binding) = status
            .account_identifier_hash
            .as_deref()
            .and_then(|account| {
                ClaudeStrongBinding::new(account, status.organization_identifier_hash.as_deref()?)
            })
        else {
            continue;
        };
        let canonical_slot_id = canonical_anchors.get(&binding);
        if canonical_slot_id.is_some_and(|canonical| canonical != slot_id) {
            continue;
        }
        let (durability, anchor_health) = canonical_slot_id
            .and_then(|canonical| slot_states.get(canonical))
            .map(|anchor| {
                (
                    ClaudeAccountAnchorDurabilityV1::Anchored,
                    projected_claude_anchor_health(anchor),
                )
            })
            .unwrap_or((ClaudeAccountAnchorDurabilityV1::DefaultOnly, None));
        let Some(snapshot) = degraded_claude_slot_snapshot(
            status,
            durability,
            anchor_health,
            captured_at,
            expires_at,
        ) else {
            continue;
        };
        if winning_bindings.contains(&binding) {
            continue;
        }
        match degraded_by_binding.get(&binding) {
            Some(previous)
                if claude_quota_access_priority(previous)
                    >= claude_quota_access_priority(&snapshot) => {}
            _ => {
                degraded_by_binding.insert(binding, snapshot);
            }
        }
    }
    degraded_by_binding.into_values().collect()
}

fn claude_default_slot_collection_status(
    snapshot: &AgentStatusSnapshot,
) -> ClaudeConfigSlotCollectionStatusV1 {
    for failure in [
        ClaudeSlotProbeFailure::CredentialUnavailable,
        ClaudeSlotProbeFailure::ProbeFailed,
        ClaudeSlotProbeFailure::ConcurrentMutation,
        ClaudeSlotProbeFailure::OwnerUnproven,
        ClaudeSlotProbeFailure::IdentityMismatch,
        ClaudeSlotProbeFailure::IdentityUnknown,
    ] {
        if snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == failure.diagnostic_code())
        {
            return failure.status(&snapshot.captured_at);
        }
    }
    if snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "claude_auth_status_failed")
    {
        return ClaudeSlotProbeFailure::CredentialUnavailable.status(&snapshot.captured_at);
    }
    let hashes = snapshot.account.as_ref().and_then(|account| {
        Some((
            account.account_identifier_hash.as_deref()?,
            account.organization_identifier_hash.as_deref()?,
        ))
    });
    match hashes {
        Some((account_hash, organization_hash))
            if snapshot.collection_method == AgentStatusCollectionMethod::StatusLine
                && !snapshot.quota_windows.is_empty()
                && snapshot.credit_balances.is_empty()
                && snapshot.quota_windows.iter().all(|window| {
                    window.account_identifier_hash.as_deref() == Some(account_hash)
                        && window.organization_identifier_hash.is_none()
                }) =>
        {
            fresh_slot_status(
                &snapshot.captured_at,
                account_hash,
                organization_hash,
                snapshot
                    .quota_windows
                    .iter()
                    .any(|window| window.name == "session")
                    && snapshot
                        .quota_windows
                        .iter()
                        .any(|window| window.name == "weekly"),
                false,
                false,
            )
        }
        Some((account_hash, organization_hash))
            if !snapshot.quota_windows.is_empty()
                && snapshot.quota_windows.iter().all(|window| {
                    window.account_identifier_hash.as_deref() == Some(account_hash)
                        && window.organization_identifier_hash.as_deref() == Some(organization_hash)
                        && window.freshness == AgentQuotaWindowFreshness::Fresh
                })
                // Credit sections keep their own freshness; the state is the meters'.
                && snapshot.credit_balances.iter().all(|balance| {
                    balance.account_identifier_hash.as_deref() == Some(account_hash)
                        && balance.organization_identifier_hash.as_deref()
                            == Some(organization_hash)
                }) =>
        {
            let mut status = fresh_slot_status(
                &snapshot.captured_at,
                account_hash,
                organization_hash,
                claude_snapshot_has_account_windows(snapshot),
                snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Model
                        || window.model.is_some()
                        || window.group.is_some()
                }),
                !snapshot.credit_balances.is_empty(),
            );
            status.quota_snapshot = Some(local_claude_quota_snapshot(
                &snapshot.captured_at,
                &snapshot.quota_windows,
                &snapshot.credit_balances,
                status.has_account_windows,
                status.has_scoped_limits,
            ));
            status
        }
        Some((account_hash, organization_hash)) => {
            let mut status =
                provider_unavailable_status(&snapshot.captured_at, account_hash, organization_hash);
            let exact_values = !snapshot.quota_windows.is_empty()
                && snapshot.quota_windows.iter().all(|window| {
                    window.account_identifier_hash.as_deref() == Some(account_hash)
                        && window.organization_identifier_hash.as_deref() == Some(organization_hash)
                })
                && snapshot.credit_balances.iter().all(|balance| {
                    balance.account_identifier_hash.as_deref() == Some(account_hash)
                        && balance.organization_identifier_hash.as_deref()
                            == Some(organization_hash)
                });
            if exact_values {
                status.has_account_windows = claude_snapshot_has_account_windows(snapshot);
                status.has_scoped_limits = snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Model
                        || window.model.is_some()
                        || window.group.is_some()
                });
                status.has_credit_balances = !snapshot.credit_balances.is_empty();
                status.quota_snapshot = Some(local_claude_quota_snapshot(
                    &snapshot.captured_at,
                    &snapshot.quota_windows,
                    &snapshot.credit_balances,
                    status.has_account_windows,
                    status.has_scoped_limits,
                ));
            }
            status
        }
        None if snapshot
            .account
            .as_ref()
            .is_some_and(|account| account.login_state != AgentLoginState::SignedIn) =>
        {
            ClaudeSlotProbeFailure::CredentialUnavailable.status(&snapshot.captured_at)
        }
        None => ClaudeSlotProbeFailure::IdentityUnknown.status(&snapshot.captured_at),
    }
}

fn apply_credential_metadata(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    credential: &ClaudeOAuthCredential,
) {
    status.access_expires_at = credential.access_expires_at.clone();
    status.relogin_required_at = credential.relogin_required_at.clone();
}

fn blocked_claude_upkeep_status(
    slot_id: &str,
    observed_at: &str,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = read_persisted_claude_slot_collection_state()
        .slots
        .get(slot_id)
        .cloned()
        .unwrap_or_default();
    status.observed_at = Some(observed_at.to_string());
    if upkeep.due_access_expires_at.is_some() {
        status.access_expires_at = upkeep.due_access_expires_at.clone();
    }
    if upkeep.refresh_token_expires_at.is_some() {
        status.relogin_required_at = upkeep.refresh_token_expires_at.clone();
    }
    let (state, code, message) = upkeep_state_diagnostic(upkeep.result);
    status.state = state;
    status.quota_snapshot = status
        .quota_snapshot
        .as_ref()
        .map(stale_local_claude_quota_snapshot);
    status.diagnostics = vec![ClaudeConfigSlotDiagnosticV1 {
        code,
        message: message.to_string(),
    }];
    status.upkeep = Some(upkeep);
    status
}

/// A registered slot whose access login lapsed while its refresh grant is
/// alive. Ottto does not refresh it (that can sign the account out), so the
/// last reading stays, marked stale, until Claude Code refreshes the login or
/// the user signs in again; the next pass resumes on its own.
///
/// No new wire values: the quiet default is collection `refresh_due` with
/// upkeep `upkeep_disabled` (quota access `paused`), never
/// `stale_access_token`, which tells the app the provider ended the session.
fn paused_claude_refresh_status(
    slot_id: &str,
    observed_at: &str,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = read_persisted_claude_slot_collection_state()
        .slots
        .get(slot_id)
        .cloned()
        .unwrap_or_default();
    status.observed_at = Some(observed_at.to_string());
    if upkeep.due_access_expires_at.is_some() {
        status.access_expires_at = upkeep.due_access_expires_at.clone();
    }
    if upkeep.refresh_token_expires_at.is_some() {
        status.relogin_required_at = upkeep.refresh_token_expires_at.clone();
    }
    let expired_at = upkeep
        .due_access_expires_at
        .clone()
        .unwrap_or_else(|| "an unknown time".to_string());
    let refreshing = upkeep.result == ClaudeConfigSlotUpkeepResultV1::InProgress;
    let message = if refreshing {
        format!(
            "This sign-in expired at {expired_at}; Ottto is refreshing it in the background now. The last reading is shown with its age until the refresh finishes."
        )
    } else {
        format!(
            "Claude Code has not refreshed this sign-in since it expired at {expired_at}. \"Keep my Claude accounts signed in\" is off, so Ottto does not refresh it. The last reading is shown with its age. Sign in again, or turn the setting on, to resume now."
        )
    };
    let (state, code) = (
        ClaudeConfigSlotCollectionStateV1::RefreshDue,
        ClaudeConfigSlotDiagnosticCodeV1::RefreshDue,
    );
    status.state = state;
    status.quota_snapshot = status
        .quota_snapshot
        .as_ref()
        .map(stale_local_claude_quota_snapshot);
    status.diagnostics = vec![ClaudeConfigSlotDiagnosticV1 { code, message }];
    // Old background-worker receipts describe a refresher that no longer
    // runs; they must not escalate or explain this state.
    status
        .quota_check_diagnostics
        .retain(|diagnostic| !diagnostic.code.starts_with("claude_slot_worker_"));
    apply_claude_upkeep_observation(&mut status, upkeep);
    status
}

fn apply_claude_upkeep_observation(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) {
    let relogin_warning = claude_relogin_warning(
        upkeep.refresh_token_expires_at.as_deref(),
        OffsetDateTime::now_utc(),
    );
    let deadline_approaching = relogin_warning.is_some();
    match upkeep.result {
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching => {
            status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
                code: ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
                message: relogin_warning.clone().unwrap_or_else(|| {
                    "This Claude login reaches its absolute refresh deadline within 3 days; sign in again before then.".to_string()
                }),
            });
        }
        ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented => {
            status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
                code: ClaudeConfigSlotDiagnosticCodeV1::UpkeepNotConsented,
                message: "Background Claude login upkeep is not consented; valid credentials remain readable until they expire.".to_string(),
            });
        }
        _ => {}
    }
    if deadline_approaching && upkeep.result != ClaudeConfigSlotUpkeepResultV1::ReloginApproaching {
        status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
            message: relogin_warning.unwrap_or_default(),
        });
    }
    status.upkeep = Some(upkeep);
}

/// The login lifetime warning, from the stored `refreshTokenExpiresAt` (about
/// 28 days after a browser sign-in): 3 days before, then 1 day before. No new
/// wire value: the existing `relogin_approaching` diagnostic carries it.
fn claude_relogin_warning(
    refresh_token_expires_at: Option<&str>,
    now: OffsetDateTime,
) -> Option<String> {
    let deadline = OffsetDateTime::parse(refresh_token_expires_at?, &Rfc3339).ok()?;
    if deadline <= now {
        return None;
    }
    let left = deadline - now;
    if left <= TimeDuration::days(1) {
        Some(
            "This Claude login ends within 1 day; sign in again to keep its limits current."
                .to_string(),
        )
    } else if left <= TimeDuration::days(3) {
        Some(
            "This Claude login ends within 3 days; sign in again to keep its limits current."
                .to_string(),
        )
    } else {
        None
    }
}

fn append_claude_upkeep_result_receipt(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    descriptor: &ClaudeConfigSlotDescriptorV1,
    observed_at: Option<String>,
) {
    if status.account_identifier_hash != descriptor.collection.account_identifier_hash
        || status.organization_identifier_hash != descriptor.collection.organization_identifier_hash
    {
        return;
    }
    let Some(clock) = observed_at.filter(|at| {
        bounded_claude_collection_timestamp(Some(at), OffsetDateTime::now_utc()).is_some()
    }) else {
        return;
    };
    let Some(upkeep) = &status.upkeep else {
        return;
    };
    let suffix = match upkeep.result {
        ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable => "credential_unreadable",
        ClaudeConfigSlotUpkeepResultV1::ProbeFailed => "probe_failed",
        ClaudeConfigSlotUpkeepResultV1::SpawnFailed => "spawn_failed",
        _ => return,
    };
    let diagnostic = AgentStatusDiagnostic::source(format!("claude_slot_upkeep_{suffix}"), AgentDiagnosticSeverity::Info,
        "The exact-slot local upkeep result was observed at this time; no quota provider check or vendor-command attempt is implied.")
        .with_observed_at(Some(clock)).with_quota_binding(status.account_identifier_hash.clone(), status.organization_identifier_hash.clone());
    status.quota_check_diagnostics.retain(|existing| {
        existing.code != diagnostic.code
            || existing.account_identifier_hash != diagnostic.account_identifier_hash
            || existing.organization_identifier_hash != diagnostic.organization_identifier_hash
    });
    status
        .quota_check_diagnostics
        .extend(safe_claude_slot_check_diagnostics(
            &[diagnostic],
            status
                .account_identifier_hash
                .as_deref()
                .unwrap_or_default(),
            status
                .organization_identifier_hash
                .as_deref()
                .unwrap_or_default(),
        ));
}

/// The registered-slot `ConcurrentMutation` outcome exactly as collection
/// stops with it, for the setup-check tests in `control`.
#[cfg(test)]
pub(crate) fn registered_claude_race_status_for_test(
    slot_id: &str,
    config_dir: &str,
    observed_at: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let descriptor = ClaudeConfigDirSlot::registered(config_dir.to_string())
        .expect("registered slot")
        .descriptor(slot_id.to_string(), ClaudeConfigSlotOwnership::Managed);
    registered_claude_failure_status(
        &descriptor,
        None,
        ClaudeSlotProbeFailure::ConcurrentMutation,
        observed_at,
        ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::NotRequired,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    )
}

fn registered_claude_failure_status(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    owner: Option<&ClaudeTokenOwner>,
    failure: ClaudeSlotProbeFailure,
    observed_at: &str,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let mut status = failure.status(observed_at);
    retain_registered_claude_slot_binding(descriptor, owner, &mut status);
    // A cleared credential's old deadlines are not last-known-good; leaving
    // them out sends the next pass to the live (spawn-free) metadata check.
    if failure != ClaudeSlotProbeFailure::SignedOutByCli {
        retain_last_known_claude_deadlines(&mut status, descriptor, &upkeep);
    }
    apply_claude_upkeep_observation(&mut status, upkeep);
    status
}

/// Keep the last-known, still-unexpired access deadline (and its paired
/// refresh deadline) on a failed probe. Persisting the failure without them
/// made the next upkeep pass read "no deadline" as "credential unreadable"
/// and stop there. An already-past deadline is not carried: upkeep then
/// re-reads the slot's own metadata and routes a truly expired login to the
/// refresh worker.
fn retain_last_known_claude_deadlines(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    descriptor: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) {
    let now = OffsetDateTime::now_utc();
    let unexpired = |at: Option<&str>| {
        at.and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .is_some_and(|expiry| expiry > now)
    };
    let (access, relogin) = if unexpired(upkeep.due_access_expires_at.as_deref()) {
        (
            upkeep.due_access_expires_at.clone(),
            upkeep.refresh_token_expires_at.clone(),
        )
    } else if unexpired(descriptor.collection.access_expires_at.as_deref()) {
        (
            descriptor.collection.access_expires_at.clone(),
            descriptor.collection.relogin_required_at.clone(),
        )
    } else {
        return;
    };
    status.access_expires_at = access;
    status.relogin_required_at = relogin;
}

fn upkeep_state_diagnostic(
    result: ClaudeConfigSlotUpkeepResultV1,
) -> (
    ClaudeConfigSlotCollectionStateV1,
    ClaudeConfigSlotDiagnosticCodeV1,
    &'static str,
) {
    match result {
        ClaudeConfigSlotUpkeepResultV1::CollectionPaused => (
            ClaudeConfigSlotCollectionStateV1::CollectionPaused,
            ClaudeConfigSlotDiagnosticCodeV1::CollectionPaused,
            "Claude subscription usage collection and background upkeep are paused by the machine off-switch.",
        ),
        ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented => (
            ClaudeConfigSlotCollectionStateV1::UpkeepNotConsented,
            ClaudeConfigSlotDiagnosticCodeV1::UpkeepNotConsented,
            "This expired Claude slot cannot run background upkeep until machine-level consent is granted.",
        ),
        ClaudeConfigSlotUpkeepResultV1::NeedsLogin => (
            ClaudeConfigSlotCollectionStateV1::NeedsLogin,
            ClaudeConfigSlotDiagnosticCodeV1::NeedsLogin,
            "This Claude slot reached its absolute refresh deadline and needs official Claude Code login again.",
        ),
        ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled => (
            ClaudeConfigSlotCollectionStateV1::ProbeFailed,
            ClaudeConfigSlotDiagnosticCodeV1::UpkeepDisabled,
            "Background Claude upkeep is stopped by the operational kill-switch; consent and account data are unchanged.",
        ),
        ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable => (
            ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
            ClaudeConfigSlotDiagnosticCodeV1::CredentialUnavailable,
            "This registered Claude slot has no readable credential metadata.",
        ),
        ClaudeConfigSlotUpkeepResultV1::Backoff => (
            ClaudeConfigSlotCollectionStateV1::StaleAccessToken,
            ClaudeConfigSlotDiagnosticCodeV1::StaleAccessToken,
            "This expired Claude slot is waiting for its durable upkeep retry deadline; no duplicate command was started.",
        ),
        ClaudeConfigSlotUpkeepResultV1::RefreshDue => (
            ClaudeConfigSlotCollectionStateV1::RefreshDue,
            ClaudeConfigSlotDiagnosticCodeV1::RefreshDue,
            "This expired Claude slot is queued for background upkeep; no vendor-command attempt has been claimed yet.",
        ),
        ClaudeConfigSlotUpkeepResultV1::InProgress => (
            ClaudeConfigSlotCollectionStateV1::RefreshDue,
            ClaudeConfigSlotDiagnosticCodeV1::RefreshDue,
            "This expired Claude slot has one background upkeep attempt in progress.",
        ),
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching => (
            ClaudeConfigSlotCollectionStateV1::ReloginApproaching,
            ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
            "This Claude login reaches its absolute refresh deadline within 3 days.",
        ),
        _ => (
            ClaudeConfigSlotCollectionStateV1::ProbeFailed,
            ClaudeConfigSlotDiagnosticCodeV1::ProbeFailed,
            "Claude Code background upkeep did not prove that this expired credential advanced; cached readings remain honestly stale.",
        ),
    }
}

/// Classify before suppressing display warnings: these diagnostics also carry
/// the internal failure state, including transient unreadable credentials.
/// Desktop authenticates its own Code sessions; its bundled binary alone does
/// not make an unusable default login actionable. Registered slots never pass
/// through this default-only display preparation.
fn prepare_default_claude_slot_status(
    snapshot: &mut AgentStatusSnapshot,
    claude_cli_installed: bool,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let status = claude_default_slot_collection_status(snapshot);
    if !claude_cli_installed {
        snapshot.diagnostics.retain(|diagnostic| {
            diagnostic.code != ClaudeSlotProbeFailure::CredentialUnavailable.diagnostic_code()
                && diagnostic.code != ClaudeSlotProbeFailure::ProbeFailed.diagnostic_code()
        });
    }
    status
}

fn default_claude_identity_diagnostic(failure: ClaudeSlotProbeFailure) -> AgentStatusDiagnostic {
    let status = failure.status("");
    AgentStatusDiagnostic::source(
        failure.diagnostic_code(),
        AgentDiagnosticSeverity::Warning,
        status
            .diagnostics
            .first()
            .map(|diagnostic| diagnostic.message.clone())
            .unwrap_or_else(|| "Claude slot identity could not be verified.".to_string()),
    )
}

fn fresh_slot_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
    has_account_windows: bool,
    has_scoped_limits: bool,
    has_credit_balances: bool,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::Fresh,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        last_full_quota_read_at: (has_account_windows && has_scoped_limits)
            .then(|| observed_at.to_string()),
        has_account_windows,
        has_scoped_limits,
        has_credit_balances,
        diagnostics: Vec::new(),
        ..Default::default()
    }
}

fn provider_unavailable_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::ProviderUnavailable,
            message: "Full Claude usage is temporarily unavailable for this exact account slot."
                .to_string(),
        }],
        ..Default::default()
    }
}

fn collection_paused_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::CollectionPaused,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::CollectionPaused,
            message: "Claude subscription usage collection is paused by the machine off-switch."
                .to_string(),
        }],
        ..Default::default()
    }
}

fn collection_in_progress_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: &str,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::CollectionInProgress,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::CollectionInProgress,
            message: "Another task is already reading this exact Claude account; no duplicate request was started."
                .to_string(),
        }],
        ..Default::default()
    }
}

#[cfg(test)]
fn duplicate_account_status(
    observed_at: &str,
    account_hash: &str,
    organization_hash: Option<&str>,
) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::DuplicateAccount,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: organization_hash.map(ToString::to_string),
        observed_at: Some(observed_at.to_string()),
        display_label: Some(format!(
            "Claude account {}",
            &account_hash[..account_hash.len().min(8)]
        )),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::DuplicateAccount,
            message: "This registered slot resolves to an account already collected by an earlier valid slot."
                .to_string(),
        }],
        relationship: Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::DuplicateAnchor),
        ..Default::default()
    }
}

fn capacity_exceeded_status(observed_at: &str) -> ClaudeConfigSlotCollectionStatusV1 {
    ClaudeConfigSlotCollectionStatusV1 {
        state: ClaudeConfigSlotCollectionStateV1::CapacityExceeded,
        observed_at: Some(observed_at.to_string()),
        diagnostics: vec![ClaudeConfigSlotDiagnosticV1 {
            code: ClaudeConfigSlotDiagnosticCodeV1::CapacityExceeded,
            message: "This slot is beyond the ten-account collection capacity and remains local."
                .to_string(),
        }],
        ..Default::default()
    }
}

fn claude_slot_collection_state_path() -> PathBuf {
    default_support_dir().join(CLAUDE_CONFIG_SLOT_COLLECTION_STATE_FILE)
}

#[cfg(test)]
pub(crate) fn publish_blocked_claude_slot_for_test(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    candidate: &ClaudeConfigSlotCollectionStatusV1,
) -> std::io::Result<Option<ClaudeConfigSlotCollectionStatusV1>> {
    persist_claude_slot_collection_states(
        &BTreeMap::from([(descriptor.slot_id.clone(), candidate.clone())]),
        &[],
        &BTreeMap::from([(descriptor.slot_id.clone(), descriptor.clone())]),
    )?;
    Ok(read_persisted_claude_slot_collection_state()
        .slots
        .remove(&descriptor.slot_id))
}

fn persist_claude_slot_collection_states(
    slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    unresolved_accounts: &[ClaudeUnresolvedAccountDescriptorV1],
    blocked_descriptors: &BTreeMap<String, ClaudeConfigSlotDescriptorV1>,
) -> std::io::Result<()> {
    if blocked_descriptors.is_empty() {
        return persist_claude_slot_collection_states_with_registry(
            slots,
            unresolved_accounts,
            blocked_descriptors,
            None,
        );
    }
    // Same lock order as worker publication: registration before collection.
    // Do not fall back to an unfenced retention write if registration is unavailable.
    FileClaudeConfigSlotSettingsStore::default()
        .with_locked_status(|registry| {
            persist_claude_slot_collection_states_with_registry(
                slots,
                unresolved_accounts,
                blocked_descriptors,
                Some(registry),
            )
        })
        .map_err(|_| {
            std::io::Error::other("Claude registration unavailable for blocked receipt retention")
        })?
}

fn persist_claude_slot_collection_states_with_registry(
    slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    unresolved_accounts: &[ClaudeUnresolvedAccountDescriptorV1],
    blocked_descriptors: &BTreeMap<String, ClaudeConfigSlotDescriptorV1>,
    registry: Option<&ottto_protocol::ClaudeAccountsStatusV1>,
) -> std::io::Result<()> {
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    for (slot_id, candidate) in slots {
        let previous = persisted.slots.get(slot_id).cloned();
        let mut candidate = candidate.clone();
        if let (Some(queued), Some(registry), Some(previous)) = (
            blocked_descriptors.get(slot_id),
            registry,
            previous.as_ref(),
        ) {
            if crate::claude_upkeep::registered_slot_publication_allowed(
                registry,
                queued,
                &default_support_dir(),
            ) {
                if let Some(current) = registry
                    .managed_slots
                    .iter()
                    .chain(&registry.external_slots)
                    .find(|slot| slot.slot_id == *slot_id)
                {
                    let mut current = current.clone();
                    current.collection = previous.clone();
                    retain_claude_worker_receipt_for_blocked_candidate(
                        queued,
                        &current,
                        &mut candidate,
                        OffsetDateTime::now_utc(),
                    );
                }
            }
        }
        merge_claude_slot_collection_state(&mut persisted.slots, slot_id, &candidate);
        if persisted.slots.get(slot_id) != previous.as_ref() {
            record_claude_anchor_transitions(
                &mut persisted.anchor_transitions,
                slot_id,
                previous.as_ref(),
                persisted
                    .slots
                    .get(slot_id)
                    .expect("merged slot remains present"),
            );
        }
    }
    persisted.unresolved_accounts = unresolved_accounts.to_vec();
    // The unresolved candidates were derived before this transaction lock was
    // acquired. An exact check may have persisted newer full proof in the
    // meantime, so subtract against the merged lock-time state rather than
    // trusting the scheduled collector's stale view. Restrict the proof to
    // slots that are still registered so an orphaned best-effort state file
    // entry cannot suppress a real unresolved account after slot removal.
    let current_slot_ids = registry
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| FileClaudeConfigSlotSettingsStore::default().load())
        .map(|status| {
            std::iter::once(status.default_slot.slot_id)
                .chain(status.managed_slots.into_iter().map(|slot| slot.slot_id))
                .chain(status.external_slots.into_iter().map(|slot| slot.slot_id))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_else(|_| slots.keys().cloned().collect());
    let resolved_full_bindings = persisted
        .slots
        .iter()
        .filter(|(slot_id, state)| {
            current_slot_ids.contains(*slot_id)
                && state.last_full_quota_read_at.is_some()
                && state.has_account_windows
                && state.has_scoped_limits
        })
        .filter_map(|(_, state)| {
            ClaudeStrongBinding::new(
                state.account_identifier_hash.as_deref()?,
                state.organization_identifier_hash.as_deref()?,
            )
        })
        .collect::<BTreeSet<_>>();
    persisted.unresolved_accounts.retain(|unresolved| {
        let Some(account_hash) = unresolved.account_identifier_hash.as_deref() else {
            return true;
        };
        if let Some(organization_hash) = unresolved.organization_identifier_hash.as_deref() {
            return ClaudeStrongBinding::new(account_hash, organization_hash)
                .map_or(true, |binding| !resolved_full_bindings.contains(&binding));
        }
        resolved_full_bindings
            .iter()
            .filter(|binding| binding.account_identifier_hash == account_hash)
            .count()
            != 1
    });
    write_persisted_claude_slot_collection_state(&persisted)
}

fn write_persisted_claude_slot_collection_state(
    state: &PersistedClaudeSlotCollectionStateV1,
) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic(&claude_slot_collection_state_path(), &body)
}

pub(crate) fn persist_one_claude_slot_collection_state(
    slot_id: &str,
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> std::io::Result<()> {
    persist_one_claude_slot_collection_state_with(slot_id, |_| Some(status.clone())).map(|_| ())
}

/// Keep ordinary collection and conditional metadata reconciliation on one
/// locked merge/transition/write owner. A refused update never creates a slot.
fn persist_one_claude_slot_collection_state_with(
    slot_id: &str,
    update: impl FnOnce(
        Option<&ClaudeConfigSlotCollectionStatusV1>,
    ) -> Option<ClaudeConfigSlotCollectionStatusV1>,
) -> std::io::Result<bool> {
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    let previous = persisted.slots.get(slot_id).cloned();
    let Some(status) = update(previous.as_ref()) else {
        return Ok(false);
    };
    merge_claude_slot_collection_state(&mut persisted.slots, slot_id, &status);
    if persisted.slots.get(slot_id) != previous.as_ref() {
        record_claude_anchor_transitions(
            &mut persisted.anchor_transitions,
            slot_id,
            previous.as_ref(),
            persisted
                .slots
                .get(slot_id)
                .expect("merged slot remains present"),
        );
    }
    if let Some(merged) = persisted.slots.get(slot_id).filter(|merged| {
        merged.last_full_quota_read_at.is_some()
            && merged.has_account_windows
            && merged.has_scoped_limits
    }) {
        if let (Some(account_hash), Some(organization_hash)) = (
            merged.account_identifier_hash.as_deref(),
            merged.organization_identifier_hash.as_deref(),
        ) {
            let exact_binding_count = persisted
                .slots
                .values()
                .filter(|state| {
                    state.account_identifier_hash.as_deref() == Some(account_hash)
                        && state.organization_identifier_hash.as_deref() == Some(organization_hash)
                        && state.last_full_quota_read_at.is_some()
                        && state.has_account_windows
                        && state.has_scoped_limits
                })
                .count();
            persisted.unresolved_accounts.retain(|unresolved| {
                if unresolved.account_identifier_hash.as_deref() != Some(account_hash) {
                    return true;
                }
                match unresolved.organization_identifier_hash.as_deref() {
                    Some(organization) => organization != organization_hash,
                    None => exact_binding_count != 1,
                }
            });
        }
    }
    let changed = persisted.slots.get(slot_id) != previous.as_ref();
    write_persisted_claude_slot_collection_state(&persisted).map(|_| changed)
}

fn read_persisted_claude_slot_collection_state() -> PersistedClaudeSlotCollectionStateV1 {
    fs::read(claude_slot_collection_state_path())
        .ok()
        .and_then(|body| serde_json::from_slice::<PersistedClaudeSlotCollectionStateV1>(&body).ok())
        .filter(|state| state.schema_version == CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION)
        .unwrap_or_else(|| PersistedClaudeSlotCollectionStateV1 {
            schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
            slots: BTreeMap::new(),
            unresolved_accounts: Vec::new(),
            anchor_transitions: Vec::new(),
        })
}

fn record_claude_anchor_transitions(
    transitions: &mut Vec<ottto_protocol::ClaudeAccountAnchorTransitionV1>,
    slot_id: &str,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    current: &ClaudeConfigSlotCollectionStatusV1,
) {
    use ottto_protocol::ClaudeAccountAnchorTransitionKindV1 as Kind;
    let previous_binding = previous.and_then(|status| {
        ClaudeStrongBinding::new(
            status.account_identifier_hash.as_deref()?,
            status.organization_identifier_hash.as_deref()?,
        )
    });
    let current_binding = ClaudeStrongBinding::new(
        current
            .account_identifier_hash
            .as_deref()
            .unwrap_or_default(),
        current
            .organization_identifier_hash
            .as_deref()
            .unwrap_or_default(),
    );
    let mut kinds = Vec::new();
    if slot_id == "default"
        && previous_binding.is_some()
        && current_binding.is_some()
        && previous_binding != current_binding
    {
        kinds.push(Kind::DefaultIdentityChanged);
    }
    if slot_id != "default" && previous_binding.is_some() && previous_binding == current_binding {
        kinds.push(Kind::AnchorRemainedBound);
    }
    if previous.is_some_and(|status| status.has_account_windows && status.has_scoped_limits)
        && matches!(
            current.state,
            ClaudeConfigSlotCollectionStateV1::NeedsLogin
                | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
        )
    {
        kinds.push(Kind::AnchorGrantDisappeared);
    }
    let previous_deadline = previous
        .and_then(|status| status.upkeep.as_ref())
        .and_then(|upkeep| upkeep.due_access_expires_at.as_deref());
    let current_deadline = current
        .upkeep
        .as_ref()
        .and_then(|upkeep| upkeep.due_access_expires_at.as_deref());
    if matches!((previous_deadline, current_deadline), (Some(before), Some(after)) if after > before)
    {
        kinds.push(Kind::RefreshDeadlineAdvanced);
    }
    if previous.is_some_and(|status| {
        matches!(
            status.state,
            ClaudeConfigSlotCollectionStateV1::NeedsLogin
                | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
        )
    }) && current.state == ClaudeConfigSlotCollectionStateV1::Fresh
    {
        kinds.push(Kind::OfficialReconnectCompleted);
    }
    if slot_id == "default"
        && current.relationship
            == Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor)
        && previous.and_then(|status| status.relationship)
            != Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor)
    {
        kinds.push(Kind::DefaultShadowObserved);
    }
    for kind in kinds {
        let transition = ottto_protocol::ClaudeAccountAnchorTransitionV1 {
            kind,
            slot_id: Some(slot_id.to_string()),
            observed_at: current.observed_at.clone(),
        };
        if transitions.last() != Some(&transition) {
            transitions.push(transition);
        }
    }
    const MAX_TRANSITIONS: usize = 64;
    if transitions.len() > MAX_TRANSITIONS {
        transitions.drain(..transitions.len() - MAX_TRANSITIONS);
    }
}

fn merge_claude_slot_collection_state(
    slots: &mut BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    slot_id: &str,
    candidate: &ClaudeConfigSlotCollectionStatusV1,
) {
    let now = OffsetDateTime::now_utc();
    let mut candidate = candidate.clone();
    apply_claude_worker_needs_login_state(&mut candidate, now);
    merge_claude_slot_collection_state_at(slots, slot_id, &candidate, now);
}

fn retain_claude_worker_receipt_for_blocked_candidate(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    candidate: &mut ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) {
    if candidate.state != ClaudeConfigSlotCollectionStateV1::RefreshDue
        || bounded_claude_collection_timestamp(candidate.observed_at.as_deref(), now).is_none()
    {
        return;
    }
    let Some(fence) = crate::claude_upkeep::preclaim_descriptor(queued) else {
        return;
    };
    let candidate_descriptor = ClaudeConfigSlotDescriptorV1 {
        collection: candidate.clone(),
        ..current.clone()
    };
    if crate::claude_upkeep::preclaim_descriptor(current).as_ref() != Some(&fence)
        || crate::claude_upkeep::preclaim_descriptor(&candidate_descriptor).as_ref() != Some(&fence)
    {
        return;
    }
    let account = fence
        .collection
        .account_identifier_hash
        .as_deref()
        .expect("strong fence");
    let organization = fence
        .collection
        .organization_identifier_hash
        .as_deref()
        .expect("strong fence");
    let latest = |status: &ClaudeConfigSlotCollectionStatusV1| {
        safe_claude_slot_check_diagnostics(&status.quota_check_diagnostics, account, organization)
            .into_iter()
            .filter(|entry| claude_worker_diagnostic_message(&entry.code).is_some())
            .filter_map(|entry| {
                bounded_claude_collection_timestamp(entry.observed_at.as_deref(), now)
                    .map(|clock| (entry, clock))
            })
            .max_by_key(|(_, clock)| *clock)
    };
    let Some((receipt, clock)) = latest(&current.collection) else {
        return;
    };
    // A saved enum can remain Fresh after its deadline expires. Only a
    // collection observation newer than this actual local receipt supersedes
    // it; the blocked candidate/map already proves the expired-access branch.
    if bounded_claude_collection_timestamp(current.collection.observed_at.as_deref(), clock)
        .is_none()
    {
        return;
    }
    if latest(candidate).is_some_and(|(_, candidate_clock)| candidate_clock >= clock) {
        return;
    }
    // Only an actually blocked, same immutable registration/deadline candidate
    // can inherit this lock-time receipt. Real provider/fresh writes replace it.
    candidate
        .quota_check_diagnostics
        .retain(|entry| claude_worker_diagnostic_message(&entry.code).is_none());
    candidate.quota_check_diagnostics.push(receipt);
}

fn bounded_claude_collection_timestamp(
    value: Option<&str>,
    upper_bound: OffsetDateTime,
) -> Option<OffsetDateTime> {
    value
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .filter(|timestamp| *timestamp <= upper_bound)
}

fn merge_claude_slot_collection_state_at(
    slots: &mut BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    slot_id: &str,
    candidate: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) {
    let candidate_observed =
        bounded_claude_collection_timestamp(candidate.observed_at.as_deref(), now);
    let replace = slots.get(slot_id).map_or(true, |existing| {
        let existing_observed =
            bounded_claude_collection_timestamp(existing.observed_at.as_deref(), now);
        match (candidate_observed, existing_observed) {
            (Some(candidate), Some(existing)) => candidate >= existing,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => candidate.observed_at.is_none(),
        }
    });
    if replace {
        let mut candidate = candidate.clone();
        inherit_claude_slot_account_profile(&mut candidate, slots.get(slot_id));
        let candidate_full_proof_is_bounded = candidate_observed.is_some()
            && candidate
                .last_full_quota_read_at
                .as_deref()
                .map_or(true, |value| {
                    bounded_claude_collection_timestamp(
                        Some(value),
                        candidate_observed.expect("checked above"),
                    )
                    .is_some()
                });
        if !candidate_full_proof_is_bounded {
            candidate.last_full_quota_read_at = None;
            candidate.has_account_windows = false;
            candidate.has_scoped_limits = false;
            candidate.has_credit_balances = false;
            candidate.quota_snapshot = None;
        }
        let may_retain_last_full = matches!(
            candidate.state,
            ClaudeConfigSlotCollectionStateV1::Fresh
                | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
                | ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
                | ClaudeConfigSlotCollectionStateV1::CollectionPaused
                | ClaudeConfigSlotCollectionStateV1::CollectionInProgress
                | ClaudeConfigSlotCollectionStateV1::RefreshDue
                | ClaudeConfigSlotCollectionStateV1::UpkeepNotConsented
                | ClaudeConfigSlotCollectionStateV1::StaleAccessToken
                | ClaudeConfigSlotCollectionStateV1::ProbeFailed
                | ClaudeConfigSlotCollectionStateV1::ReloginApproaching
                | ClaudeConfigSlotCollectionStateV1::NeedsLogin
        );
        if candidate.last_full_quota_read_at.is_none() && may_retain_last_full {
            if let Some(existing) = slots.get(slot_id).filter(|existing| {
                let inheritance_upper_bound = candidate_observed.unwrap_or(now);
                existing.account_identifier_hash == candidate.account_identifier_hash
                    && existing.organization_identifier_hash
                        == candidate.organization_identifier_hash
                    && existing.last_full_quota_read_at.is_some()
                    && bounded_claude_collection_timestamp(
                        existing.observed_at.as_deref(),
                        inheritance_upper_bound,
                    )
                    .is_some()
                    && bounded_claude_collection_timestamp(
                        existing.last_full_quota_read_at.as_deref(),
                        inheritance_upper_bound,
                    )
                    .is_some()
            }) {
                let candidate_is_fresh_partial_observation =
                    candidate.state == ClaudeConfigSlotCollectionStateV1::Fresh;
                candidate.last_full_quota_read_at = existing.last_full_quota_read_at.clone();
                candidate.has_account_windows = existing.has_account_windows;
                candidate.has_scoped_limits = existing.has_scoped_limits;
                candidate.has_credit_balances = existing.has_credit_balances;
                // A fresh partial exact read may carry a non-empty snapshot (for
                // example, account windows without scoped limits). Keep the last
                // bounded full snapshot as one coherent meter bundle instead of
                // pairing inherited full-proof flags with the partial snapshot.
                if candidate_is_fresh_partial_observation || candidate.quota_snapshot.is_none() {
                    candidate.quota_snapshot = existing
                        .quota_snapshot
                        .as_ref()
                        .filter(|snapshot| {
                            local_claude_quota_snapshot_within_retention(
                                snapshot,
                                candidate_observed.unwrap_or(now),
                            )
                        })
                        .map(|snapshot| {
                            let remains_fresh = candidate_is_fresh_partial_observation
                                && candidate.account_identifier_hash.as_deref().is_some_and(
                                    |account_hash| {
                                        local_claude_quota_snapshot_is_fresh_for_account(
                                            snapshot,
                                            account_hash,
                                            candidate
                                                .organization_identifier_hash
                                                .as_deref()
                                                .expect(
                                                "retained full snapshot has strong organization",
                                            ),
                                            now,
                                        )
                                    },
                                );
                            if remains_fresh {
                                claude_retained_snapshot_relabelled(
                                    snapshot,
                                    candidate
                                        .account_identifier_hash
                                        .as_deref()
                                        .unwrap_or_default(),
                                    candidate
                                        .organization_identifier_hash
                                        .as_deref()
                                        .unwrap_or_default(),
                                    now,
                                )
                            } else {
                                stale_local_claude_quota_snapshot(snapshot)
                            }
                        });
                }
            }
        }
        slots.insert(slot_id.to_string(), candidate);
    }
}

fn claude_slot_collection_state_guard() -> std::io::Result<ClaudeSlotCollectionStateGuard> {
    use std::os::fd::AsRawFd;
    let process = CLAUDE_SLOT_COLLECTION_STATE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(default_support_dir())?;
    let file = open_private_lock_file(
        &default_support_dir().join(CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE),
    )?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ClaudeSlotCollectionStateGuard {
        _process: process,
        file: Some(file),
    })
}

fn derive_claude_account_anchor_coverage(
    status: &ClaudeAccountsStatusV1,
) -> ClaudeAccountAnchorCoverageV1 {
    let mut by_binding = BTreeMap::<ClaudeStrongBinding, ClaudeAccountAnchorDescriptorV1>::new();
    let mut registered = status
        .managed_slots
        .iter()
        .chain(status.external_slots.iter())
        .collect::<Vec<_>>();
    registered.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let registered_states = registered
        .iter()
        .map(|slot| (slot.slot_id.clone(), slot.collection.clone()))
        .collect::<BTreeMap<_, _>>();
    let canonical = canonical_registered_anchors(
        registered.iter().map(|slot| slot.slot_id.clone()),
        &registered_states,
    );
    for (binding, slot_id) in canonical {
        let slot = registered
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .expect("canonical registered slot remains present");
        by_binding.insert(
            binding.clone(),
            ClaudeAccountAnchorDescriptorV1 {
                target_id: Some(claude_anchor_target_id(&binding)),
                account_identifier_hash: binding.account_identifier_hash,
                organization_identifier_hash: Some(binding.organization_identifier_hash),
                durability: ClaudeAccountAnchorDurabilityV1::Anchored,
                health: projected_claude_anchor_health(&slot.collection),
                setup_blockers: Vec::new(),
                observed_at: slot.collection.observed_at.clone(),
            },
        );
    }

    if let Some(binding) = status
        .default_slot
        .collection
        .account_identifier_hash
        .as_deref()
        .and_then(|account| {
            ClaudeStrongBinding::new(
                account,
                status
                    .default_slot
                    .collection
                    .organization_identifier_hash
                    .as_deref()?,
            )
        })
    {
        by_binding
            .entry(binding.clone())
            .or_insert_with(|| ClaudeAccountAnchorDescriptorV1 {
                target_id: Some(claude_anchor_target_id(&binding)),
                account_identifier_hash: binding.account_identifier_hash,
                organization_identifier_hash: Some(binding.organization_identifier_hash),
                durability: ClaudeAccountAnchorDurabilityV1::DefaultOnly,
                health: None,
                setup_blockers: Vec::new(),
                observed_at: status.default_slot.collection.observed_at.clone(),
            });
    }

    let mut ambiguous = Vec::new();
    for unresolved in &status.unresolved_accounts {
        if unresolved.organization_identifier_hash.is_some() {
            continue;
        }
        let Some(account_hash) = unresolved
            .account_identifier_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
        else {
            continue;
        };
        let matching_bindings = by_binding
            .keys()
            .filter(|binding| binding.account_identifier_hash == account_hash)
            .count();
        if matching_bindings != 1 {
            ambiguous.push(ClaudeAccountAnchorDescriptorV1 {
                target_id: None,
                account_identifier_hash: account_hash.to_string(),
                organization_identifier_hash: None,
                durability: ClaudeAccountAnchorDurabilityV1::Unresolved,
                health: None,
                setup_blockers: vec![ClaudeAccountAnchorSetupBlockerV1::AmbiguousIdentity],
                observed_at: unresolved.observed_at.clone(),
            });
        }
    }

    // An exact Desktop folder pair without full limits is a connect target of
    // its own. Its binding never replaces an anchored or default row.
    for unresolved in &status.unresolved_accounts {
        let Some(binding) = unresolved
            .account_identifier_hash
            .as_deref()
            .and_then(|account| {
                ClaudeStrongBinding::new(
                    account,
                    unresolved.organization_identifier_hash.as_deref()?,
                )
            })
        else {
            continue;
        };
        by_binding
            .entry(binding.clone())
            .or_insert_with(|| ClaudeAccountAnchorDescriptorV1 {
                target_id: Some(claude_anchor_target_id(&binding)),
                account_identifier_hash: binding.account_identifier_hash.clone(),
                organization_identifier_hash: Some(binding.organization_identifier_hash.clone()),
                durability: ClaudeAccountAnchorDurabilityV1::Unresolved,
                health: None,
                setup_blockers: Vec::new(),
                observed_at: unresolved.observed_at.clone(),
            });
    }

    if status.capacity.remaining_slots == 0 {
        for account in by_binding.values_mut().chain(ambiguous.iter_mut()) {
            if account.durability != ClaudeAccountAnchorDurabilityV1::Anchored {
                account
                    .setup_blockers
                    .push(ClaudeAccountAnchorSetupBlockerV1::CapacityReached);
            }
        }
    }

    let mut accounts = by_binding.into_values().collect::<Vec<_>>();
    accounts.extend(ambiguous);
    let bounded_count = |predicate: fn(&ClaudeAccountAnchorDescriptorV1) -> bool| {
        u8::try_from(accounts.iter().filter(|account| predicate(account)).count())
            .unwrap_or(u8::MAX)
    };
    ClaudeAccountAnchorCoverageV1 {
        observed_accounts: u8::try_from(accounts.len()).unwrap_or(u8::MAX),
        anchored_accounts: bounded_count(|account| {
            account.durability == ClaudeAccountAnchorDurabilityV1::Anchored
        }),
        default_only_accounts: bounded_count(|account| {
            account.durability == ClaudeAccountAnchorDurabilityV1::DefaultOnly
        }),
        unresolved_accounts: bounded_count(|account| {
            account.durability == ClaudeAccountAnchorDurabilityV1::Unresolved
        }),
        capacity_blocked_accounts: bounded_count(|account| {
            account
                .setup_blockers
                .contains(&ClaudeAccountAnchorSetupBlockerV1::CapacityReached)
        }),
        ambiguous_identity_accounts: bounded_count(|account| {
            account
                .setup_blockers
                .contains(&ClaudeAccountAnchorSetupBlockerV1::AmbiguousIdentity)
        }),
        accounts,
    }
}

fn claude_anchor_target_id(binding: &ClaudeStrongBinding) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:claude-anchor-target:v1\0");
    digest.update(binding.account_identifier_hash.as_bytes());
    digest.update(b"\0");
    digest.update(binding.organization_identifier_hash.as_bytes());
    format!("claude_anchor_target_{:.32x}", digest.finalize())
}

fn projected_claude_anchor_health(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<ClaudeAccountAnchorHealthV1> {
    match projected_claude_quota_access_state(status)? {
        ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial => {
            Some(ClaudeAccountAnchorHealthV1::Healthy)
        }
        ClaudeQuotaAccessState::TemporarilyUnavailable => {
            Some(ClaudeAccountAnchorHealthV1::TemporarilyUnavailable)
        }
        ClaudeQuotaAccessState::ReconnectRequired => {
            Some(ClaudeAccountAnchorHealthV1::ReconnectRequired)
        }
        ClaudeQuotaAccessState::Paused => Some(ClaudeAccountAnchorHealthV1::Paused),
        ClaudeQuotaAccessState::AttentionRequired => {
            Some(ClaudeAccountAnchorHealthV1::AttentionRequired)
        }
    }
}

pub(crate) fn annotate_claude_accounts_status(
    mut status: ClaudeAccountsStatusV1,
) -> ClaudeAccountsStatusV1 {
    let persisted = read_persisted_claude_slot_collection_state();
    for descriptor in std::iter::once(&mut status.default_slot)
        .chain(status.managed_slots.iter_mut())
        .chain(status.external_slots.iter_mut())
    {
        if let Some(collection) = persisted.slots.get(&descriptor.slot_id) {
            descriptor.collection = collection.clone();
            if descriptor
                .collection
                .quota_snapshot
                .as_ref()
                .is_some_and(|snapshot| {
                    !local_claude_quota_snapshot_within_retention(
                        snapshot,
                        OffsetDateTime::now_utc(),
                    )
                })
            {
                descriptor.collection.quota_snapshot = None;
            }
        }
    }
    status.unresolved_accounts = persisted.unresolved_accounts;
    status.anchor_transitions = persisted.anchor_transitions;
    status.anchor_coverage = derive_claude_account_anchor_coverage(&status);
    status
}

pub(crate) fn prune_claude_slot_collection_state(slot_id: &str) -> std::io::Result<()> {
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    persisted.slots.remove(slot_id);
    write_persisted_claude_slot_collection_state(&persisted)
}

/// Desktop evidence for Claude accounts without full limits on this Mac.
///
/// Each qualified exact Desktop folder pair is its own row (with its
/// organization hash, so it is a connect target) unless that exact pair has
/// full limits. An account with no qualified pair keeps the account-only row.
fn derive_unresolved_claude_accounts(
    desktop_snapshot: &AgentStatusSnapshot,
    desktop_pairs: &ClaudeDesktopPairs,
    full_snapshots: &[AgentStatusSnapshot],
    current_slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    now: OffsetDateTime,
) -> Vec<ClaudeUnresolvedAccountDescriptorV1> {
    let mut full_accounts = full_snapshots
        .iter()
        .filter(|snapshot| {
            claude_has_account_windows(
                &fresh_quota_windows(&snapshot.quota_windows),
                claude_snapshot_account_weekly_not_offered(snapshot),
                claude_snapshot_account_session_not_offered(snapshot),
            ) && snapshot.quota_windows.iter().any(|window| {
                (window.scope == AgentQuotaWindowScope::Model
                    || window.model.is_some()
                    || window.group.is_some())
                    && window.freshness == AgentQuotaWindowFreshness::Fresh
            })
        })
        .filter_map(|snapshot| snapshot.account.as_ref())
        .filter_map(|account| {
            Some((
                account.account_identifier_hash.clone()?,
                account.organization_identifier_hash.clone(),
            ))
        })
        .collect::<Vec<_>>();
    full_accounts.extend(
        read_persisted_claude_slot_collection_state()
            .slots
            .into_iter()
            .filter(|(slot_id, _)| current_slots.contains_key(slot_id))
            .map(|(_, state)| state)
            .filter(|state| {
                state.last_full_quota_read_at.is_some()
                    && state.has_account_windows
                    && state.has_scoped_limits
            })
            .filter_map(|state| {
                Some((
                    state.account_identifier_hash?,
                    state.organization_identifier_hash,
                ))
            }),
    );
    let resolved = full_accounts
        .iter()
        .map(|(account, _)| account.clone())
        .collect::<BTreeSet<_>>();
    let resolved_bindings = full_accounts
        .iter()
        .filter_map(|(account, organization)| {
            ClaudeStrongBinding::new(account, organization.as_deref()?)
        })
        .collect::<BTreeSet<_>>();
    let recent = |observed_at: &str| {
        OffsetDateTime::parse(observed_at, &Rfc3339).is_ok_and(|observed| {
            now.unix_timestamp() - observed.unix_timestamp()
                <= CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS
        })
    };
    let mut descriptors = desktop_pairs
        .pairs
        .iter()
        .filter(|pair| !resolved_bindings.contains(&pair.binding))
        .filter_map(|pair| {
            let observed_at = pair.observation.observed_at.clone()?;
            recent(&observed_at).then(|| {
                let ClaudeStrongBinding {
                    account_identifier_hash,
                    organization_identifier_hash,
                } = pair.binding.clone();
                ClaudeUnresolvedAccountDescriptorV1 {
                    unresolved_id: format!(
                        "claude-unresolved-{}",
                        &format!(
                            "{:x}",
                            Sha256::digest(
                                format!(
                                    "unresolved:{account_identifier_hash}:{organization_identifier_hash}"
                                )
                                .as_bytes()
                            )
                        )[..16]
                    ),
                    account_identifier_hash: Some(account_identifier_hash),
                    organization_identifier_hash: Some(organization_identifier_hash),
                    account_label: pair.observation.account_label.clone(),
                    organization_label: pair.observation.organization_label.clone(),
                    observed_at: Some(observed_at),
                    evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
                }
            })
        })
        .take(CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX)
        .collect::<Vec<_>>();
    // Only an emitted pair row stands in for its account's account-only row;
    // a stale, resolved or capped-out pair must not hide recent evidence.
    let pair_accounts = descriptors
        .iter()
        .filter_map(|descriptor| descriptor.account_identifier_hash.clone())
        .collect::<BTreeSet<_>>();
    let mut by_hash = BTreeMap::<String, String>::new();
    for observation in &desktop_snapshot.plan_observations {
        if observation.evidence_method.as_deref() != Some("claude_desktop_session_bucket")
            || observation.billing_identity_confidence != AgentStatusConfidence::High
        {
            continue;
        }
        let Some(account_hash) = observation.account_identifier_hash.as_ref() else {
            continue;
        };
        if account_hash.is_empty()
            || resolved.contains(account_hash)
            || pair_accounts.contains(account_hash)
        {
            continue;
        }
        let Some(observed_at) = observation.observed_at.clone() else {
            continue;
        };
        let Ok(observed_time) = OffsetDateTime::parse(&observed_at, &Rfc3339) else {
            continue;
        };
        if now.unix_timestamp() - observed_time.unix_timestamp()
            > CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS
        {
            continue;
        }
        by_hash
            .entry(account_hash.clone())
            .and_modify(|current| {
                if observed_at > *current {
                    *current = observed_at.clone();
                }
            })
            .or_insert(observed_at);
    }
    descriptors.extend(by_hash.into_iter().map(|(account_hash, observed_at)| {
        let unresolved_id = format!(
            "claude-unresolved-{}",
            &format!(
                "{:x}",
                Sha256::digest(format!("unresolved:{account_hash}").as_bytes())
            )[..16]
        );
        ClaudeUnresolvedAccountDescriptorV1 {
            unresolved_id,
            account_identifier_hash: Some(account_hash),
            organization_identifier_hash: None,
            account_label: None,
            organization_label: None,
            observed_at: Some(observed_at),
            evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
        }
    }));
    descriptors
}

/// Takes the observations rather than recomputing them: the statusLine
/// attribution gate above needs the same set, and scanning the Desktop session
/// buckets twice per status tick would be pure waste.
fn append_claude_desktop_plan_observations(
    snapshot: &mut AgentStatusSnapshot,
    observations: Vec<AgentStatusPlanObservation>,
) -> usize {
    let count = observations.len();
    snapshot.plan_observations.extend(observations);
    count
}

fn claude_desktop_support_dir() -> PathBuf {
    home_path("Library/Application Support/Claude")
}

fn claude_cli_config_path() -> PathBuf {
    ClaudeConfigDirSlot::Default.identity_path(&home_dir())
}

/// Which Claude account this Mac uses by default right now: the Claude Desktop
/// app's last known account plus the default config dir's OAuth account and
/// organization. Opaque, local-only, and cheap enough to re-read while the sync
/// loop waits; it changes only when the user switches accounts.
pub(crate) fn claude_default_account_fingerprint() -> Option<String> {
    let desktop_account =
        read_claude_desktop_config(&claude_desktop_support_dir()).last_known_account_uuid;
    let cli_account = read_claude_cli_oauth_account(&claude_cli_config_path());
    let (cli_account_uuid, cli_organization_uuid) = cli_account
        .map(|account| (account.account_uuid, account.organization_uuid))
        .unwrap_or_default();
    if desktop_account.is_none() && cli_account_uuid.is_none() {
        return None;
    }
    Some(format!(
        "desktop={};cli={};org={}",
        desktop_account.unwrap_or_default(),
        cli_account_uuid.unwrap_or_default(),
        cli_organization_uuid.unwrap_or_default()
    ))
}

fn claude_desktop_metadata_present(root: &Path) -> bool {
    root.join("config.json").is_file()
        || root.join("claude-code-sessions").is_dir()
        || root.join("local-agent-mode-sessions").is_dir()
}

#[cfg(test)]
fn claude_desktop_plan_observations_from_root(
    root: &Path,
    observed_at: &str,
) -> Vec<AgentStatusPlanObservation> {
    claude_desktop_scan_from_root(
        root,
        observed_at,
        &mut ClaudeDesktopMetadataCache::default(),
    )
    .observations
}

fn claude_desktop_scan_from_root(
    root: &Path,
    observed_at: &str,
    metadata_cache: &mut ClaudeDesktopMetadataCache,
) -> ClaudeDesktopScan {
    let config = read_claude_desktop_config(root);
    let last_known_account_uuid = config
        .last_known_account_uuid
        .as_deref()
        .and_then(safe_local_identifier)
        .map(ToString::to_string);
    let mut builders: BTreeMap<String, ClaudeDesktopProfileBuilder> = BTreeMap::new();
    let mut pair_builders: BTreeMap<ClaudeDesktopPairKey, ClaudeDesktopPairBuilder> =
        BTreeMap::new();

    // Entries move from the previous pass into this one as files are read,
    // so files no longer selected drop out.
    let mut previous = std::mem::take(metadata_cache);
    collect_claude_desktop_code_sessions(
        &root.join("claude-code-sessions"),
        last_known_account_uuid.as_deref(),
        &mut builders,
        &mut pair_builders,
        (&mut previous.code, &mut metadata_cache.code),
    );
    collect_claude_desktop_agent_mode_sessions(
        &root.join("local-agent-mode-sessions"),
        &mut builders,
        &mut pair_builders,
        (&mut previous.agent_mode, &mut metadata_cache.agent_mode),
    );
    let pairs = claude_desktop_qualified_pairs(pair_builders);

    let builders = builders
        .into_values()
        .filter(|builder| {
            builder.code_session_count > 0
                || last_known_account_uuid.as_deref() == Some(builder.account_uuid.as_str())
        })
        .collect::<Vec<_>>();
    let duplicate_session_owners = claude_desktop_unambiguous_duplicate_session_owners(&builders);
    let mut observations = Vec::new();

    for builder in &builders {
        let mut profile = builder.clone();
        if let Some(session_id) = profile.latest_session_id.as_deref() {
            if let Some(owner) = duplicate_session_owners.get(session_id) {
                let owner_matches = owner
                    .as_ref()
                    .is_some_and(|(account_uuid, _)| account_uuid == &profile.account_uuid);
                if !owner_matches {
                    // The same resumed Desktop session may remain in an older
                    // account bucket. Never emit an exact session binding for
                    // the losing (or tied/ambiguous) bucket.
                    profile.latest_session_id = None;
                }
            }
        }
        if let Some(observation) = claude_desktop_builder_plan_observation(
            profile,
            observed_at,
            last_known_account_uuid.as_deref(),
        ) {
            observations.push(observation);
        }
    }

    let mut resolved_duplicate_sessions = duplicate_session_owners
        .into_iter()
        .filter_map(|(session_id, owner)| {
            owner.map(|(account_uuid, activity)| (session_id, account_uuid, activity))
        })
        .collect::<Vec<_>>();
    resolved_duplicate_sessions
        .sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    for (session_id, account_uuid, activity) in resolved_duplicate_sessions
        .into_iter()
        .take(CLAUDE_DESKTOP_DUPLICATE_SESSION_OBSERVATION_MAX)
    {
        let Some(builder) = builders
            .iter()
            .find(|builder| builder.account_uuid == account_uuid)
        else {
            continue;
        };
        if builder.latest_session_id.as_deref() == Some(session_id.as_str()) {
            continue;
        }
        let mut session_builder = builder.clone();
        session_builder.latest_session_id = Some(session_id);
        session_builder.latest_activity_epoch_seconds = activity;
        if let Some(observation) = claude_desktop_builder_plan_observation(
            session_builder,
            observed_at,
            last_known_account_uuid.as_deref(),
        ) {
            observations.push(observation);
        }
    }

    ClaudeDesktopScan {
        observations,
        pairs,
    }
}

/// Returns only duplicated Desktop session IDs. A session is attributed when
/// exactly one account bucket has the newest timestamp; equal or missing
/// timestamps fail closed so account cards never guess.
fn claude_desktop_unambiguous_duplicate_session_owners(
    builders: &[ClaudeDesktopProfileBuilder],
) -> BTreeMap<String, Option<(String, Option<i64>)>> {
    claude_desktop_duplicate_session_owners(builders.iter().map(|builder| {
        (
            builder.account_uuid.clone(),
            &builder.session_activity_by_id,
        )
    }))
}

/// The same rule over any bucket key: Desktop account buckets for the
/// per-account readings, exact account/organization folders for pairs.
fn claude_desktop_duplicate_session_owners<'a, K: Clone + PartialEq>(
    buckets: impl IntoIterator<Item = (K, &'a BTreeMap<String, Option<i64>>)>,
) -> BTreeMap<String, Option<(K, Option<i64>)>> {
    let mut candidates: BTreeMap<String, Vec<(K, Option<i64>)>> = BTreeMap::new();
    for (key, sessions) in buckets {
        for (session_id, activity) in sessions {
            candidates
                .entry(session_id.clone())
                .or_default()
                .push((key.clone(), *activity));
        }
    }

    candidates
        .into_iter()
        .filter(|(_, candidates)| candidates.len() > 1)
        .map(|(session_id, candidates)| {
            if candidates.iter().any(|(_, activity)| activity.is_none()) {
                return (session_id, None);
            }
            let newest = candidates
                .iter()
                .filter_map(|(_, activity)| *activity)
                .max();
            let winners = newest.map_or_else(Vec::new, |newest| {
                candidates
                    .into_iter()
                    .filter(|(_, activity)| *activity == Some(newest))
                    .collect::<Vec<_>>()
            });
            let owner = (winners.len() == 1).then(|| winners[0].clone());
            (session_id, owner)
        })
        .collect()
}

fn read_claude_desktop_config(root: &Path) -> ClaudeDesktopConfig {
    let path = root.join("config.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<ClaudeDesktopConfig>(&body).ok())
        .unwrap_or_default()
}

fn collect_claude_desktop_code_sessions(
    root: &Path,
    last_known_account_uuid: Option<&str>,
    builders: &mut BTreeMap<String, ClaudeDesktopProfileBuilder>,
    pair_builders: &mut BTreeMap<ClaudeDesktopPairKey, ClaudeDesktopPairBuilder>,
    (previous, current): ClaudeDesktopMetadataPass<'_, ClaudeDesktopCodeSessionMetadata>,
) {
    let Ok(accounts) = fs::read_dir(root) else {
        return;
    };
    for account in accounts.flatten() {
        let Ok(file_type) = account.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(account_uuid) = account
            .file_name()
            .to_str()
            .and_then(safe_local_identifier)
            .map(ToString::to_string)
        else {
            continue;
        };
        let Ok(orgs) = fs::read_dir(account.path()) else {
            continue;
        };
        for org in orgs.flatten() {
            let Ok(file_type) = org.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let Some(org_uuid) = org
                .file_name()
                .to_str()
                .and_then(safe_local_identifier)
                .map(ToString::to_string)
            else {
                continue;
            };
            let builder = builders.entry(account_uuid.clone()).or_insert_with(|| {
                ClaudeDesktopProfileBuilder {
                    account_uuid: account_uuid.clone(),
                    ..Default::default()
                }
            });
            builder.organization_uuids.insert(org_uuid.clone());
            let Ok(files) = fs::read_dir(org.path()) else {
                continue;
            };
            for file in files
                .flatten()
                .filter(|entry| looks_like_local_json_file(entry.path().as_path()))
                .take(CLAUDE_DESKTOP_CODE_SESSION_MAX_FILES_PER_ORG)
            {
                let metadata = claude_desktop_session_metadata(file.path(), previous, current);
                let metadata_activity = metadata.as_ref().and_then(|metadata| {
                    timestamp_value_epoch_seconds(metadata.last_activity_at.as_ref())
                        .or_else(|| timestamp_value_epoch_seconds(metadata.created_at.as_ref()))
                });
                let activity =
                    metadata_activity.or_else(|| file_modified_epoch_seconds(&file.path()));
                let imported = metadata.as_ref().is_some_and(|metadata| metadata.imported);
                let session_id = metadata
                    .and_then(|metadata| metadata.cli_session_id)
                    .and_then(|value| safe_local_identifier(&value).map(ToString::to_string));
                if let Some(session_id) = session_id.as_deref() {
                    claude_desktop_pair_builder(pair_builders, &account_uuid, &org_uuid)
                        .record_session(session_id, activity, metadata_activity, imported);
                }
                let builder = builders.get_mut(&account_uuid).expect("builder exists");
                builder.code_session_count += 1;
                if builder.record_activity(activity, session_id)
                    && last_known_account_uuid == Some(account_uuid.as_str())
                {
                    builder.current_organization_uuid = Some(org_uuid.clone());
                }
            }
        }
    }
}

fn collect_claude_desktop_agent_mode_sessions(
    root: &Path,
    builders: &mut BTreeMap<String, ClaudeDesktopProfileBuilder>,
    pair_builders: &mut BTreeMap<ClaudeDesktopPairKey, ClaudeDesktopPairBuilder>,
    (previous, current): ClaudeDesktopMetadataPass<'_, ClaudeDesktopAgentModeSessionMetadata>,
) {
    let Ok(accounts) = fs::read_dir(root) else {
        return;
    };
    for account in accounts.flatten() {
        let Ok(file_type) = account.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(account_uuid) = account
            .file_name()
            .to_str()
            .and_then(safe_local_identifier)
            .map(ToString::to_string)
        else {
            continue;
        };
        let Ok(orgs) = fs::read_dir(account.path()) else {
            continue;
        };
        for org in orgs.flatten() {
            let Ok(file_type) = org.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let Some(org_uuid) = org
                .file_name()
                .to_str()
                .and_then(safe_local_identifier)
                .map(ToString::to_string)
            else {
                continue;
            };
            let builder = builders.entry(account_uuid.clone()).or_insert_with(|| {
                ClaudeDesktopProfileBuilder {
                    account_uuid: account_uuid.clone(),
                    ..Default::default()
                }
            });
            builder.organization_uuids.insert(org_uuid.clone());
            let Ok(files) = fs::read_dir(org.path()) else {
                continue;
            };
            for file in files
                .flatten()
                .filter(|entry| looks_like_local_json_file(entry.path().as_path()))
                .take(CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG)
            {
                let Some(metadata) =
                    claude_desktop_session_metadata(file.path(), previous, current)
                else {
                    continue;
                };
                let activity = timestamp_value_epoch_seconds(metadata.last_activity_at.as_ref())
                    .or_else(|| timestamp_value_epoch_seconds(metadata.created_at.as_ref()))
                    .or_else(|| file_modified_epoch_seconds(&file.path()));
                let session_id = metadata
                    .cli_session_id
                    .as_deref()
                    .and_then(safe_local_identifier)
                    .map(ToString::to_string);
                // Agent-mode sessions compete for duplicate-session ownership
                // and label their own folder pair, but never qualify one.
                let pair = claude_desktop_pair_builder(pair_builders, &account_uuid, &org_uuid);
                if let Some(session_id) = session_id.as_deref() {
                    pair.record_session(session_id, activity, None, true);
                }
                pair.record_agent_mode_metadata(&metadata);
                let builder = builders.get_mut(&account_uuid).expect("builder exists");
                builder.agent_mode_session_count += 1;
                builder.record_activity(activity, session_id);
                builder.account_label = builder.account_label.clone().or_else(|| {
                    first_non_empty([
                        metadata.email_address.as_deref(),
                        metadata.account_email.as_deref(),
                        metadata.email.as_deref(),
                    ])
                    .map(ToString::to_string)
                });
                builder.account_name = builder
                    .account_name
                    .clone()
                    .or_else(|| safe_display_label(metadata.account_name.as_deref()));
                builder.organization_label = builder.organization_label.clone().or_else(|| {
                    first_non_empty([
                        metadata.organization_name.as_deref(),
                        metadata.workspace_name.as_deref(),
                        metadata.team_name.as_deref(),
                    ])
                    .and_then(|value| safe_display_label(Some(value)))
                });
                builder.plan_type = builder.plan_type.clone().or_else(|| {
                    first_non_empty([
                        metadata.subscription_type.as_deref(),
                        metadata.plan_type.as_deref(),
                        metadata.plan.as_deref(),
                    ])
                    .map(|value| normalize_plan_type(value.to_string()))
                });
            }
        }
    }
}

fn claude_desktop_builder_plan_observation(
    builder: ClaudeDesktopProfileBuilder,
    _observed_at: &str,
    last_known_account_uuid: Option<&str>,
) -> Option<AgentStatusPlanObservation> {
    let account_identifier_hash =
        billing_identity_hash("anthropic", "account", &builder.account_uuid);
    // An organization is attached only when the pairing is unambiguous: the
    // current organization when the Desktop config names this account as
    // current, or the single organization the session store holds for it.
    // Picking `iter().next()` off a multi-org set fabricated pairings for
    // non-current accounts (a personal account hash next to an employer org
    // hash), which the backend then minted as a brand-new billing identity.
    // Fail closed: omit the organization rather than guess.
    let organization_id = builder.current_organization_uuid.or_else(|| {
        if builder.organization_uuids.len() == 1 {
            builder.organization_uuids.iter().next().cloned()
        } else {
            None
        }
    });
    let organization_identifier_hash = organization_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "organization", value));
    let billing_identity_evidence = billing_identity_evidence_for(
        &account_identifier_hash,
        &organization_identifier_hash,
        &None,
    );
    if account_identifier_hash.is_none() && organization_identifier_hash.is_none() {
        return None;
    }
    let plan_type = builder.plan_type;
    let subscription_product = plan_type.clone().map(claude_desktop_subscription_product);
    let is_current = last_known_account_uuid == Some(builder.account_uuid.as_str());
    let activity_observed_at = builder
        .latest_activity_epoch_seconds
        .and_then(|seconds| u64::try_from(seconds).ok())
        .and_then(rfc3339_from_unix_seconds);
    Some(AgentStatusPlanObservation {
        desktop_recent_at: None,
        observed_at: activity_observed_at,
        evidence_method: Some("claude_desktop_session_bucket".to_string()),
        source_session_id: builder.latest_session_id,
        provider: Some("anthropic".to_string()),
        billing_provider: Some("anthropic".to_string()),
        model_provider: Some("anthropic".to_string()),
        billing_channel: Some("subscription".to_string()),
        auth_mode: Some("claude_desktop".to_string()),
        gateway_provider: None,
        subscription_product,
        plan_type,
        account_label: builder
            .account_label
            .or(builder.account_name)
            .or_else(|| is_current.then(|| "Claude Desktop".to_string())),
        account_id: Some(builder.account_uuid),
        organization_label: builder.organization_label,
        organization_id,
        account_identifier_hash,
        organization_identifier_hash,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: if is_current {
            AgentStatusConfidence::High
        } else {
            AgentStatusConfidence::Medium
        },
        is_current: Some(is_current),
    })
}

fn claude_desktop_subscription_product(plan: String) -> String {
    if plan.starts_with("claude_") {
        plan
    } else {
        format!("claude_{plan}")
    }
}

/// Qualify each exact Desktop folder pair and describe it.
///
/// A pair qualifies only with at least one native (never imported) Code
/// session that carries a parseable activity time and that this folder owns:
/// a session copied into several folders counts only for the folder with its
/// unambiguously newest activity, and a tie or a missing time counts for none.
/// Ownership is decided over every Desktop folder pair the scan saw, Code and
/// agent-mode, UUID-named or not, so no copy the per-account rule sees is
/// ignored here. Imported-only and ambiguous copied evidence therefore never
/// makes a pair. `observed_at` is the newest qualifying native activity, and
/// the pair's session is that activity's session. No organization is ever
/// chosen for an account: every folder speaks only for itself.
fn claude_desktop_qualified_pairs(
    pair_builders: BTreeMap<ClaudeDesktopPairKey, ClaudeDesktopPairBuilder>,
) -> ClaudeDesktopPairs {
    let owners = claude_desktop_duplicate_session_owners(
        pair_builders
            .iter()
            .map(|(key, pair)| (key.clone(), &pair.session_activity_by_id)),
    );
    let owns = |key: &ClaudeDesktopPairKey, session_id: &str| match owners.get(session_id) {
        None => true,
        Some(owner) => owner.as_ref().is_some_and(|(owner, _)| owner == key),
    };
    let mut qualified = pair_builders
        .into_iter()
        .filter(|(_, pair)| pair.exact)
        .filter_map(|(key, pair)| {
            let newest = pair
                .native_activity_by_id
                .iter()
                .filter(|(session_id, _)| owns(&key, session_id.as_str()))
                .map(|(session_id, activity)| (*activity, session_id.clone()))
                .max()?;
            Some((key, newest, pair))
        })
        .collect::<Vec<_>>();
    // Newest first; equal activity falls back to the pair so every pass with
    // the same folders orders them the same way.
    qualified.sort_by(
        |(left_key, (left_activity, _), _), (right_key, (right_activity, _), _)| {
            right_activity
                .cmp(left_activity)
                .then_with(|| left_key.cmp(right_key))
        },
    );
    let mut pairs = Vec::with_capacity(qualified.len());
    let mut index_by_key = BTreeMap::new();
    for (key, (activity, session_id), pair) in qualified {
        if let Some(observation) =
            claude_desktop_pair_observation(&key, &pair, activity, session_id)
        {
            index_by_key.insert(key, pairs.len());
            pairs.push(observation);
        }
    }

    let mut owned_duplicates = owners
        .into_iter()
        .filter_map(|(session_id, owner)| {
            let (key, activity) = owner?;
            Some((session_id, *index_by_key.get(&key)?, activity?))
        })
        .collect::<Vec<_>>();
    owned_duplicates.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    let duplicate_sessions = owned_duplicates
        .into_iter()
        .filter_map(|(session_id, index, activity)| {
            let pair: &ClaudeDesktopPairObservation = &pairs[index];
            if pair.observation.source_session_id.as_deref() == Some(session_id.as_str()) {
                return None;
            }
            let mut duplicate = pair.clone();
            duplicate.observation.source_session_id = Some(session_id);
            duplicate.observation.observed_at = u64::try_from(activity)
                .ok()
                .and_then(rfc3339_from_unix_seconds);
            Some(duplicate)
        })
        .take(CLAUDE_DESKTOP_DUPLICATE_SESSION_OBSERVATION_MAX)
        .collect();
    ClaudeDesktopPairs {
        pairs,
        duplicate_sessions,
    }
}

/// One exact Desktop folder pair as a plan observation: raw canonical account
/// and organization UUIDs with their hashes, so the backend can rebuild the
/// same pair the session evidence carries. Plan and labels only when that
/// folder's own agent-mode metadata states them.
///
/// Never `is_current`: the backend turns a current observation into a current
/// account row keyed by the same account and organization as a login's
/// metered row, so a meterless Desktop reading would replace those meters
/// whenever the login is not uploaded. A non-current reading still carries
/// the exact pair.
fn claude_desktop_pair_observation(
    (account_id, organization_id): &ClaudeDesktopPairKey,
    pair: &ClaudeDesktopPairBuilder,
    activity: i64,
    session_id: String,
) -> Option<ClaudeDesktopPairObservation> {
    let account_identifier_hash = billing_identity_hash("anthropic", "account", account_id)?;
    let organization_identifier_hash =
        billing_identity_hash("anthropic", "organization", organization_id)?;
    let binding =
        ClaudeStrongBinding::new(&account_identifier_hash, &organization_identifier_hash)?;
    let account_identifier_hash = Some(account_identifier_hash);
    let organization_identifier_hash = Some(organization_identifier_hash);
    let billing_identity_evidence = billing_identity_evidence_for(
        &account_identifier_hash,
        &organization_identifier_hash,
        &None,
    );
    Some(ClaudeDesktopPairObservation {
        binding,
        observation: AgentStatusPlanObservation {
            desktop_recent_at: None,
            observed_at: u64::try_from(activity)
                .ok()
                .and_then(rfc3339_from_unix_seconds),
            evidence_method: Some("claude_desktop_session_bucket".to_string()),
            source_session_id: Some(session_id),
            provider: Some("anthropic".to_string()),
            billing_provider: Some("anthropic".to_string()),
            model_provider: Some("anthropic".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("claude_desktop".to_string()),
            gateway_provider: None,
            subscription_product: pair
                .plan_type
                .clone()
                .map(claude_desktop_subscription_product),
            plan_type: pair.plan_type.clone(),
            account_label: pair
                .account_label
                .clone()
                .or_else(|| pair.account_name.clone()),
            account_id: Some(account_id.clone()),
            organization_label: pair.organization_label.clone(),
            organization_id: Some(organization_id.clone()),
            account_identifier_hash,
            organization_identifier_hash,
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence,
            billing_identity_confidence: AgentStatusConfidence::High,
            confidence: AgentStatusConfidence::Medium,
            is_current: Some(false),
        },
    })
}

/// The Claude Desktop pair status for this pass: one `claude_code` snapshot
/// whose plan observations are the exact Desktop folder pairs that no other
/// upload of this pass already carries (its strong account binding, or a plan
/// observation with both hashes). On a Mac without an uploadable Claude Code
/// login that is every pair; beside uploaded logins it is only the rest.
///
/// It has no root account, so it never stands in for a login or its meters,
/// and it reports usage as unsupported. Pairs come newest first within the
/// backend's per-snapshot observation limit; the duplicate sessions they own
/// fill what is left, and anything left out is disclosed.
fn claude_desktop_pairs_snapshot(
    desktop: &ClaudeDesktopPairs,
    uploads: &[AgentStatusSnapshot],
    captured_at: &str,
    expires_at: &str,
) -> Option<AgentStatusSnapshot> {
    let exact_binding = |account: Option<&String>, organization: Option<&String>| {
        ClaudeStrongBinding::new(account?.as_str(), organization?.as_str())
    };
    let mut covered = BTreeSet::new();
    let mut uploaded_sessions = BTreeSet::new();
    for snapshot in uploads {
        if let Some(account) = snapshot.account.as_ref() {
            covered.extend(exact_binding(
                account.account_identifier_hash.as_ref(),
                account.organization_identifier_hash.as_ref(),
            ));
        }
        for observation in &snapshot.plan_observations {
            covered.extend(exact_binding(
                observation.account_identifier_hash.as_ref(),
                observation.organization_identifier_hash.as_ref(),
            ));
            uploaded_sessions.extend(observation.source_session_id.clone());
        }
    }
    let uncovered = desktop
        .pairs
        .iter()
        .filter(|pair| !covered.contains(&pair.binding))
        .collect::<Vec<_>>();
    if uncovered.is_empty() {
        return None;
    }
    let mut plan_observations = Vec::with_capacity(CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX);
    let mut emitted = BTreeSet::new();
    for pair in uncovered.iter().take(CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX) {
        plan_observations.push(pair.observation.clone());
        emitted.insert(&pair.binding);
    }
    let left_out_pairs = uncovered.len() - plan_observations.len();
    let duplicates = desktop
        .duplicate_sessions
        .iter()
        .filter(|duplicate| {
            emitted.contains(&duplicate.binding)
                && duplicate
                    .observation
                    .source_session_id
                    .as_ref()
                    .is_some_and(|session_id| !uploaded_sessions.contains(session_id))
        })
        .collect::<Vec<_>>();
    let room = CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX - plan_observations.len();
    let left_out_duplicates = duplicates.len().saturating_sub(room);
    plan_observations.extend(
        duplicates
            .into_iter()
            .take(room)
            .map(|duplicate| duplicate.observation.clone()),
    );

    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at.to_string(),
        expires_at.to_string(),
    );
    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
    snapshot.capabilities = vec![
        supported_capability(
            "desktop_identity",
            "Read display-safe Claude Desktop account/organization session-folder metadata.",
        ),
        unsupported_capability(
            "quota_windows",
            "Claude Desktop session folders carry no usage limits; a Claude Code login for the account is needed to show them.",
        ),
    ];
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "claude_desktop_profile_detected",
        AgentDiagnosticSeverity::Info,
        "Claude Desktop Code account/session bucket metadata was detected.",
    ));
    snapshot.diagnostics.push(if uploads.is_empty() {
        AgentStatusDiagnostic::source(
            "claude_desktop_only_no_cli_login",
            AgentDiagnosticSeverity::Info,
            "No Claude Code login on this Mac can be uploaded; Claude Desktop account/organization folders are reported without limits.",
        )
    } else {
        AgentStatusDiagnostic::source(
            "claude_desktop_uncovered_pairs",
            AgentDiagnosticSeverity::Info,
            "Claude Desktop account/organization folders that no uploaded Claude Code login covers are reported without limits.",
        )
    });
    if left_out_pairs + left_out_duplicates > 0 {
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_desktop_pairs_truncated",
            AgentDiagnosticSeverity::Warning,
            format!(
                "{left_out_pairs} Claude Desktop folder pair(s) and {left_out_duplicates} duplicate-session reading(s) were left out to stay within the upload limit; the newest were kept."
            ),
        ));
    }
    snapshot.plan_observations = plan_observations;
    Some(snapshot)
}

/// Append this pass's Desktop pair status to the Claude uploads, after every
/// login and degraded snapshot so coverage is computed from what actually
/// uploads. The uploads already present are never changed.
///
/// The backend keeps a login's metered current row when this status arrives:
/// an account-less, meterless status no longer takes the profile of its newest
/// linked observation, so the current-row cleanup cannot delete this Mac's
/// metered row for that profile. Pair connect targets are local and do not
/// depend on this.
fn append_claude_desktop_pairs_snapshot(
    snapshots: &mut Vec<AgentStatusSnapshot>,
    desktop: &ClaudeDesktopPairs,
    captured_at: &str,
    expires_at: &str,
) {
    let Some(snapshot) = claude_desktop_pairs_snapshot(desktop, snapshots, captured_at, expires_at)
    else {
        return;
    };
    // One more snapshot past the backend's per-upload limit would refuse every
    // Claude upload of the pass, the metered ones included.
    if snapshots.len() < AGENT_STATUS_UPLOAD_SNAPSHOT_MAX {
        snapshots.push(snapshot);
    } else {
        eprintln!("claude_status desktop_pairs=withheld reason=upload_snapshot_limit");
    }
}

impl ClaudeDesktopPairBuilder {
    fn record_session(
        &mut self,
        session_id: &str,
        activity: Option<i64>,
        metadata_activity: Option<i64>,
        imported: bool,
    ) {
        let recorded = self
            .session_activity_by_id
            .entry(session_id.to_string())
            .or_insert(activity);
        if activity.is_some_and(|next| recorded.map_or(true, |current| next > current)) {
            *recorded = activity;
        }
        if let (false, Some(activity)) = (imported, metadata_activity) {
            let native = self
                .native_activity_by_id
                .entry(session_id.to_string())
                .or_insert(activity);
            *native = (*native).max(activity);
        }
    }

    fn record_agent_mode_metadata(&mut self, metadata: &ClaudeDesktopAgentModeSessionMetadata) {
        self.account_label = self.account_label.take().or_else(|| {
            first_non_empty([
                metadata.email_address.as_deref(),
                metadata.account_email.as_deref(),
                metadata.email.as_deref(),
            ])
            .map(ToString::to_string)
        });
        self.account_name = self
            .account_name
            .take()
            .or_else(|| safe_display_label(metadata.account_name.as_deref()));
        self.organization_label = self.organization_label.take().or_else(|| {
            first_non_empty([
                metadata.organization_name.as_deref(),
                metadata.workspace_name.as_deref(),
                metadata.team_name.as_deref(),
            ])
            .and_then(|value| safe_display_label(Some(value)))
        });
        self.plan_type = self.plan_type.take().or_else(|| {
            first_non_empty([
                metadata.subscription_type.as_deref(),
                metadata.plan_type.as_deref(),
                metadata.plan.as_deref(),
            ])
            .map(|value| normalize_plan_type(value.to_string()))
        });
    }
}

impl ClaudeDesktopProfileBuilder {
    fn record_activity(&mut self, activity: Option<i64>, session_id: Option<String>) -> bool {
        if let Some(session_id) = session_id.as_ref() {
            let current = self
                .session_activity_by_id
                .get(session_id)
                .copied()
                .flatten();
            if activity.is_some_and(|next| current.map_or(true, |current| next > current))
                || !self.session_activity_by_id.contains_key(session_id)
            {
                self.session_activity_by_id
                    .insert(session_id.clone(), activity);
            }
        }
        let should_replace = match (activity, self.latest_activity_epoch_seconds) {
            (Some(next), Some(current)) => next >= current,
            (Some(_), None) => true,
            (None, _) => self.latest_session_id.is_none(),
        };
        if should_replace {
            self.latest_activity_epoch_seconds = activity.or(self.latest_activity_epoch_seconds);
            if session_id.is_some() {
                self.latest_session_id = session_id;
            }
        }
        should_replace
    }
}

/// The previous pass's entries and this pass's, for one Desktop file kind.
type ClaudeDesktopMetadataPass<'a, T> = (
    &'a mut ClaudeDesktopMetadataEntries<T>,
    &'a mut ClaudeDesktopMetadataEntries<T>,
);

/// One Desktop session file's metadata: the previous pass's parse, failures
/// included, while the file's stamp is unchanged, else a fresh read. A file
/// written too recently for a rewrite to change its stamp is not kept.
fn claude_desktop_session_metadata<T: for<'de> Deserialize<'de> + Clone>(
    path: PathBuf,
    previous: &mut ClaudeDesktopMetadataEntries<T>,
    current: &mut ClaudeDesktopMetadataEntries<T>,
) -> Option<T> {
    let Some(stamp) = path_stamp(&path) else {
        return read_json_file(&path);
    };
    let metadata = match previous.remove(&path) {
        Some((kept, metadata)) if kept == stamp => metadata,
        _ => read_json_file(&path),
    };
    if stamp.settled() {
        current.insert(path, (stamp, metadata.clone()));
    }
    metadata
}

#[cfg(test)]
thread_local! {
    /// Desktop session JSON reads on this thread: (attempts, bytes read).
    static CLAUDE_DESKTOP_JSON_READ_RECEIPT: std::cell::Cell<(usize, u64)> =
        const { std::cell::Cell::new((0, 0)) };
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    #[cfg(test)]
    CLAUDE_DESKTOP_JSON_READ_RECEIPT.with(|receipt| {
        let (attempts, bytes) = receipt.get();
        receipt.set((attempts + 1, bytes));
    });
    let body = fs::read_to_string(path).ok()?;
    #[cfg(test)]
    CLAUDE_DESKTOP_JSON_READ_RECEIPT.with(|receipt| {
        let (attempts, bytes) = receipt.get();
        receipt.set((attempts, bytes + body.len() as u64));
    });
    serde_json::from_str(&body).ok()
}

fn looks_like_local_json_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("local_") && name.ends_with(".json")
}

fn safe_local_identifier(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        Some(value)
    } else {
        None
    }
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn safe_display_label(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains('/')
        || value.contains('\\')
        || value.to_ascii_lowercase().contains("token")
        || value.to_ascii_lowercase().contains("secret")
    {
        return None;
    }
    Some(value.to_string())
}

fn timestamp_value_epoch_seconds(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(seconds) = value.as_i64() {
        return Some(normalize_unix_epoch_seconds(seconds));
    }
    if let Some(seconds) = value.as_u64().and_then(|value| i64::try_from(value).ok()) {
        return Some(normalize_unix_epoch_seconds(seconds));
    }
    if let Some(seconds) = value.as_f64() {
        if seconds.is_finite() {
            return Some(normalize_unix_epoch_seconds(seconds.round() as i64));
        }
    }
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(seconds) = text.parse::<i64>() {
        return Some(normalize_unix_epoch_seconds(seconds));
    }
    if let Ok(seconds) = text.parse::<f64>() {
        if seconds.is_finite() {
            return Some(normalize_unix_epoch_seconds(seconds.round() as i64));
        }
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|value| value.unix_timestamp())
}

fn normalize_unix_epoch_seconds(mut value: i64) -> i64 {
    // Claude Desktop currently stores JavaScript millisecond epochs, while
    // older fixtures and some builds use seconds. Reduce higher-precision
    // integer epochs until they are in the Unix-seconds range.
    while value.unsigned_abs() >= 10_000_000_000 {
        value /= 1_000;
    }
    value
}

fn file_modified_epoch_seconds(path: &Path) -> Option<i64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let duration = modified
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?;
    i64::try_from(duration.as_secs()).ok()
}

/// What the statusLine rate-limit cache can offer the currently-resolved
/// account. `NotObserved` (nothing usable on disk) and `Unattributable`
/// (something on disk that is not provably ours) are deliberately distinct:
/// they read identically on the surface but mean opposite things about whether
/// collection is working.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaudeStatusLineQuota {
    Windows(Vec<AgentQuotaWindow>),
    NotObserved,
    Unattributable(ClaudeStatusLineUnattributable),
}

/// Why a cached statusLine sample may not be served as the current account's
/// quota. Each variant is a distinct thing an operator can act on, so they stay
/// separate rather than collapsing into "unavailable".
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaudeStatusLineUnattributable {
    /// Written while a different Claude Code credential was signed in -- the
    /// `/login` switch case, the same defect `ClaudeOAuthUsageCache` fixes.
    CredentialReplaced,
    /// A second Claude account is observable on this machine, so no statusLine
    /// sample can be tied to one of them.
    MultipleAccounts,
    /// Nothing on this machine names the account that wrote the sample, or the
    /// account reading it.
    AccountUnknown,
}

impl ClaudeStatusLineUnattributable {
    fn code(&self) -> &'static str {
        match self {
            Self::CredentialReplaced => "claude_statusline_cache_credential_replaced",
            Self::MultipleAccounts => "claude_statusline_cache_multiple_accounts",
            Self::AccountUnknown => "claude_statusline_cache_account_unknown",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            Self::CredentialReplaced => {
                "Claude Code statusLine quota is not currently observable for this account: the cached sample was written while a different Claude account was signed in."
            }
            Self::MultipleAccounts => {
                "Claude Code statusLine quota is not currently observable for this account: more than one Claude account is present on this machine, and statusLine samples carry no account identity."
            }
            Self::AccountUnknown => {
                "Claude Code statusLine quota is not currently observable for this account: the local Claude account could not be identified."
            }
        }
    }
}

/// Read the statusLine rate-limit cache, but only serve it as `account`'s quota
/// when it can actually be proven to be `account`'s.
///
/// `statusLine` is a Claude *Code* mechanism, not a Claude Desktop one. It is
/// configured once in `~/.claude/settings.json` and invoked by whichever Claude
/// Code surface renders -- the terminal CLI and the Claude Desktop app's "Code"
/// tab pipe to the same Ottto wrapper and overwrite the same machine-global
/// file. The payload names no account. So unlike `ClaudeOAuthUsageCache`, where
/// the daemon fetched the numbers itself and the writer's account key IS proof,
/// here the key records only which credential was visible at write time. Taken
/// alone it would launder a wrong attribution into a confident one: during the
/// live 2026-07-26 repro the CLI credential was the work Team account both when
/// the sample was written and when it was read, while the numbers belonged to
/// the personal Max account rendering in Desktop.
///
/// Proof therefore needs both halves:
///
/// 1. the sample was written under the credential that owns the machine now, and
/// 2. no *other* Claude account is observable on the machine at all.
///
/// Desktop plan observations already carry `account_identifier_hash` derived
/// without any decrypt, which is what makes (2) answerable today; the caller
/// passes them through `claude_account_identifier_hashes_from_observations`.
/// When either half fails the caller falls through to the typed unsupported
/// window rather than rendering another account's numbers.
fn collect_claude_statusline_quota_windows(
    account_identifier_hash: &str,
    observable_account_identifier_hashes: &[String],
) -> Result<ClaudeStatusLineQuota, String> {
    let cache = read_claude_statusline_cache(&default_support_dir())
        .map_err(|_| "Claude Code statusLine cache could not be read safely.".to_string())?;
    let Some(cache) = cache else {
        return Ok(ClaudeStatusLineQuota::NotObserved);
    };
    let now = current_unix_seconds();
    if cache.observed_at_epoch_seconds > now.saturating_add(60)
        || now.saturating_sub(cache.observed_at_epoch_seconds)
            > CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
    {
        return Ok(ClaudeStatusLineQuota::NotObserved);
    }
    if let Some(reason) = claude_statusline_attribution_failure(
        &cache.observed_under_account_identifier_hash,
        &cache.observed_under_account_method,
        account_identifier_hash,
        observable_account_identifier_hashes,
    ) {
        // Refusing to attribute is not an error -- the cache is intact, it just
        // is not ours to serve.
        return Ok(ClaudeStatusLineQuota::Unattributable(reason));
    }

    Ok(ClaudeStatusLineQuota::Windows(
        claude_statusline_quota_windows_from_cache(cache, now),
    ))
}

/// Every Claude account this machine can show us, as billing identity hashes.
/// Anything in here other than the signed-in account is another writer of the
/// shared statusLine cache.
fn claude_account_identifier_hashes_from_observations(
    observations: &[AgentStatusPlanObservation],
) -> Vec<String> {
    observations
        .iter()
        .filter_map(|observation| observation.account_identifier_hash.as_deref())
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// `None` when the sample provably belongs to the account that owns the local
/// Claude Code credential now, with resolution method taken into account.
///
/// SAFETY INVARIANT: A sample is served ONLY under an account proven for that
/// render. When resolution fails, behavior must be identical to today's fail-closed:
/// unattributable error, typed diagnostic, `unsupported_quota_window("usage")`.
///
/// Resolution method gates the proof requirements:
/// - session_store: Desktop session store proved which account owns this session,
///   so we serve it even when multiple accounts are observable (the whole point
///   of the store join is to break that tie).
/// - config_dir: CLI credential holders' sessions; serve if the stamped hash
///   matches the current credential, even with multiple accounts observable (CLI
///   credential is proof of ownership).
/// - ambiguous: Multiple Desktop store matches that could not be resolved; refuse.
/// - unknown: Unable to resolve; refuse.
/// - v2 cache (no method field): unresolved origin; refuse.
fn claude_statusline_attribution_failure(
    observed_under_account_identifier_hash: &str,
    observed_under_account_method: &str,
    account_identifier_hash: &str,
    _observable_account_identifier_hashes: &[String],
) -> Option<ClaudeStatusLineUnattributable> {
    // Empty hash always means unknown, regardless of method
    if observed_under_account_identifier_hash.is_empty() {
        return Some(ClaudeStatusLineUnattributable::AccountUnknown);
    }
    if account_identifier_hash.is_empty() {
        return Some(ClaudeStatusLineUnattributable::AccountUnknown);
    }

    match observed_under_account_method {
        "session_store" => {
            // Desktop session store proved which account owns this session.
            // Serve it, even if multiple accounts are observable.
            // The store join is itself the proof.
            None
        }
        "config_dir" => {
            // CLI credential: only serve if the stamped hash matches the current holder.
            if observed_under_account_identifier_hash == account_identifier_hash {
                None
            } else {
                Some(ClaudeStatusLineUnattributable::CredentialReplaced)
            }
        }
        "ambiguous" => {
            // Multiple Desktop store matches; cannot resolve.
            Some(ClaudeStatusLineUnattributable::MultipleAccounts)
        }
        _ => {
            // "unknown" or missing/empty method (v2 cache) -> unresolved
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        }
    }
}

fn collect_claude_statusline_context_status() -> Result<AgentContextStatus, String> {
    let support_dir = default_support_dir();
    let cache = read_claude_statusline_context_cache(&support_dir).map_err(|_| {
        "Claude Code statusLine context cache could not be read safely.".to_string()
    })?;
    let history = read_claude_statusline_context_history(&support_dir)
        .ok()
        .flatten();
    let Some(cache) = cache else {
        return Ok(claude_statusline_context_unavailable(
            "statusline_context_not_observed",
            None,
        ));
    };
    let now = current_unix_seconds();
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    if cache.observed_at_epoch_seconds > now.saturating_add(60)
        || now.saturating_sub(cache.observed_at_epoch_seconds)
            > CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
    {
        return Ok(claude_statusline_context_unavailable(
            "statusline_context_cache_stale",
            observed_at,
        ));
    }

    Ok(claude_statusline_context_from_cache(cache, history))
}

#[cfg(test)]
fn collect_claude_oauth_usage_with_access_token(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    caller: &ClaudeOAuthUsageCaller,
) -> ClaudeOAuthUsageOutcome {
    collect_claude_oauth_usage_with_credential(
        account_identifier_hash,
        organization_identifier_hash,
        access_token,
        None,
        caller,
        current_unix_seconds,
    )
}

/// `credential_expires_at` is the access-token expiry metadata of the same
/// credential, used only to notice rotation; it is never the token. `clock`
/// is the wall clock (`current_unix_seconds`) outside fixed-instant tests.
fn collect_claude_oauth_usage_with_credential(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    credential_expires_at: Option<String>,
    caller: &ClaudeOAuthUsageCaller,
    clock: fn() -> u64,
) -> ClaudeOAuthUsageOutcome {
    let mut outcome = collect_claude_oauth_usage_unstamped(
        account_identifier_hash,
        organization_identifier_hash,
        access_token,
        credential_expires_at.as_deref(),
        caller,
        clock,
    );
    if let Ok(usage) = &mut outcome.result {
        claude_oauth_stamp_account_identity(
            usage,
            account_identifier_hash,
            Some(organization_identifier_hash),
        );
    }
    for diagnostic in &mut outcome.diagnostics {
        diagnostic.account_identifier_hash = Some(account_identifier_hash.to_string());
        diagnostic.organization_identifier_hash = Some(organization_identifier_hash.to_string());
    }
    outcome
}

fn claude_oauth_stamp_account_identity(
    usage: &mut ClaudeOAuthUsage,
    account_identifier_hash: &str,
    organization_identifier_hash: Option<&str>,
) {
    let account =
        (!account_identifier_hash.is_empty()).then(|| account_identifier_hash.to_string());
    let organization = organization_identifier_hash
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string);
    for window in &mut usage.windows {
        window.account_identifier_hash = account.clone();
        window.organization_identifier_hash = organization.clone();
    }
    for balance in &mut usage.credit_balances {
        balance.account_identifier_hash = account.clone();
        balance.organization_identifier_hash = organization.clone();
    }
}

/// Whether an access deadline (RFC 3339) is at or within the expiry margin
/// of `now` (unix seconds). An absent or unparseable deadline is not
/// "expired" here; the local login state already failed those closed.
fn claude_access_token_locally_expired(credential_expires_at: Option<&str>, now: u64) -> bool {
    credential_expires_at
        .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
        .is_some_and(|expiry| {
            let now = i64::try_from(now).unwrap_or(i64::MAX);
            expiry.unix_timestamp() <= now.saturating_add(CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS)
        })
}

fn collect_claude_oauth_usage_unstamped(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    credential_expires_at: Option<&str>,
    caller: &ClaudeOAuthUsageCaller,
    clock: fn() -> u64,
) -> ClaudeOAuthUsageOutcome {
    let now = clock();
    let mirror_legacy_default = caller.mirrors_legacy_default();
    // Every pass is evidence of where this caller's login is signed in; a
    // passive reading must have been fetched inside that continuous run.
    claude_oauth_pass_reached_collector(caller);
    let caller_bound_since = claude_credit_pools::claude_observe_caller_binding(
        &mut CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        &caller.breaker_key(),
        &claude_oauth_binding_key(account_identifier_hash, organization_identifier_hash),
        now,
    );

    // Off-switch first, ahead of the cache. Existing account-scoped cache files
    // are retained and continue aging honestly; no endpoint data is served and
    // the network resumes without destroying the last known local evidence.
    if claude_oauth_usage_network_disabled() {
        return ClaudeOAuthUsageOutcome {
            result: Err(
                "Claude OAuth usage endpoint is switched off on this machine.".to_string(),
            ),
            diagnostics: vec![AgentStatusDiagnostic::source(
                "claude_oauth_usage_network_disabled",
                AgentDiagnosticSeverity::Info,
                "Claude subscription quota is read from Claude Code's local statusLine only: the Claude OAuth usage network read is switched off on this machine.",
            )],
        };
    }

    // A registered managed slot owns this exact account and proved last pass
    // that it reads it. Its credential is the one provider caller; the default
    // login only serves the shared per-account cache that slot keeps current.
    if !caller.may_call_provider() {
        let deferred = AgentStatusDiagnostic::source(
            "claude_oauth_usage_deferred_to_registered_slot",
            AgentDiagnosticSeverity::Info,
            "This Claude account's quota is read through its registered account slot; the default Claude Code login made no provider request.",
        );
        let cache = read_claude_oauth_usage_cache_with_legacy_migration(
            account_identifier_hash,
            organization_identifier_hash,
            mirror_legacy_default,
        );
        if mirror_legacy_default {
            if let Some(cache) = &cache {
                let _ = write_legacy_claude_oauth_usage_cache(cache);
            }
        }
        if let Some(cache) = cache.filter(|cache| {
            !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
        }) {
            return ClaudeOAuthUsageOutcome {
                result: Ok(claude_oauth_usage_from_cache(cache, now)),
                diagnostics: vec![deferred],
            }
            .with_check_outcome(
                "claude_oauth_usage_cache_reused",
                "A locally cached quota reading kept by the registered account slot was reused; no provider check was made.",
                now,
            );
        }
        return ClaudeOAuthUsageOutcome {
            result: Err(
                "Claude OAuth usage for this account is read by its registered account slot."
                    .to_string(),
            ),
            diagnostics: vec![deferred],
        };
    }

    let Some(_collection_attempt) =
        try_claude_oauth_collection_attempt(account_identifier_hash, organization_identifier_hash)
    else {
        if let Some(cache) = read_claude_oauth_usage_cache_with_legacy_migration(
            account_identifier_hash,
            organization_identifier_hash,
            mirror_legacy_default,
        )
        .filter(|cache| {
            !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
        }) {
            return ClaudeOAuthUsageOutcome::from(Ok(claude_oauth_usage_from_cache(cache, now)))
                .with_check_outcome("claude_oauth_usage_cache_reused", "A locally cached quota reading was reused while collection is in progress; no duplicate provider check was made.", now);
        }
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude usage collection is already in progress for this account.".to_string()),
            diagnostics: vec![AgentStatusDiagnostic::source(
                "claude_oauth_usage_collection_in_progress",
                AgentDiagnosticSeverity::Info,
                "Another daemon task is already reading this exact Claude account; no duplicate provider request was started.",
            )],
        };
    };

    let config_fingerprint = claude_oauth_usage_config_fingerprint();
    let breaker = read_claude_oauth_usage_breaker_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        &config_fingerprint,
        mirror_legacy_default,
    );
    if mirror_legacy_default {
        if let Some(breaker) = &breaker {
            let _ = write_legacy_claude_oauth_usage_breaker(breaker);
        }
    }
    let caller_auth_hold = breaker
        .as_ref()
        .and_then(|breaker| {
            claude_oauth_usage_caller_auth_hold(breaker, caller, now, credential_expires_at)
        })
        .cloned();
    // The future cache gate alone also covers ordinary refresh. Require the
    // matching-account rate-limit receipt and no competing auth/circuit hold
    // before naming a Retry-After reason. This changes disclosure only.
    let rate_limit_retry_evidenced = breaker.as_ref().is_some_and(|breaker| {
        breaker.rate_limit_failures > 0
            && breaker.auth_failures == 0
            && !claude_oauth_usage_breaker_is_open(breaker, now)
    }) && caller_auth_hold.is_none()
        && access_token.is_some()
        && !claude_access_token_locally_expired(credential_expires_at, now);
    let breaker_rate_limited = breaker
        .as_ref()
        .is_some_and(|breaker| breaker.rate_limit_failures > 0);
    let open_breaker = breaker.filter(|breaker| claude_oauth_usage_breaker_is_open(breaker, now));

    // Read cadence: one read per binding per slot. The
    // slot follows the account's recent activity; due slots alternate the
    // plain and saved-reset reads.
    let account_state_dir =
        claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash);
    let mut read_schedule = claude_credit_pools::read_claude_read_schedule(&account_state_dir);
    let (latest_activity_at, feed_fresh_at) =
        claude_oauth_activity(account_identifier_hash, organization_identifier_hash);
    // The scan lists a session only while its activity advances: keep every
    // sighting, even when this pass serves the stored reading.
    if read_schedule.observe_activity(latest_activity_at) {
        let _ = claude_credit_pools::write_claude_read_schedule(&account_state_dir, &read_schedule);
    }
    let mut slot_seconds = claude_oauth_usage_slot_seconds(
        &read_schedule,
        latest_activity_at,
        feed_fresh_at,
        account_identifier_hash,
        organization_identifier_hash,
        now,
    );
    // In use: Claude Code's own statusLine is the free source. While it is
    // fresh for exactly this binding, the provider is read only at the
    // unused-account gate (for the meters the statusLine does not carry);
    // the collection prefers the newer statusLine windows when it serves.
    // Only the default login's collection merges the statusLine.
    if slot_seconds == claude_credit_pools::ACTIVE_SLOT_SECONDS
        && matches!(caller, ClaudeOAuthUsageCaller::Default)
        && claude_statusline_fresh_for_binding(
            account_identifier_hash,
            organization_identifier_hash,
            now,
        )
    {
        slot_seconds = claude_oauth_usage_fresh_age_seconds(
            account_identifier_hash,
            organization_identifier_hash,
        );
    }
    let mut last_reading_at = None;
    let mut previous_credit_balances = Vec::new();

    // A saved-reset reading that was not usable (or had no windows) moved
    // this binding's next read to its next slot.
    let held = claude_credit_pools::claude_read_held(&mut read_schedule, slot_seconds, now);
    if held.cleared {
        let _ = claude_credit_pools::write_claude_read_schedule(&account_state_dir, &read_schedule);
    }

    let mut exact_stale_fallback = None;
    let mut explicit_refresh_due = false;
    if let Some(cache) = read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        mirror_legacy_default,
    ) {
        if mirror_legacy_default {
            let _ = write_legacy_claude_oauth_usage_cache(&cache);
        }
        // The last stored reading: its sections are re-sent by a read that
        // does not carry them.
        previous_credit_balances = cache.credit_balances.clone();
        if !cache.windows.is_empty() {
            last_reading_at = Some(cache.observed_at_epoch_seconds);
        }
        let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
        // An explicit refresh reads now, past the slot and the plain spacing
        // after a successful read, but never inside a Retry-After hold: the
        // spacing must be exactly the success floor and no rate limit may be
        // on record, in the breaker or in this run's own 429 record. Every
        // later hold and breaker check still applies.
        explicit_refresh_due = claude_explicit_refresh_requested(
            account_identifier_hash,
            organization_identifier_hash,
            cache.observed_at_epoch_seconds,
            now,
        ) && (now >= cache.next_refresh_after_epoch_seconds
            || (!breaker_rate_limited
                && !claude_rate_limit_held(
                    account_identifier_hash,
                    organization_identifier_hash,
                    now,
                )
                && cache.next_refresh_after_epoch_seconds
                    <= cache
                        .observed_at_epoch_seconds
                        .saturating_add(CLAUDE_OAUTH_USAGE_REFRESH_SECONDS)));
        if explicit_refresh_due {
            note_claude_explicit_refresh_attempt(
                account_identifier_hash,
                organization_identifier_hash,
                now,
            );
        }
        // A window that reset after this reading gets one read shortly after
        // the reset instead of waiting out the slot.
        let reset_read_due = claude_credit_pools::claude_reset_read_due(
            &cache.windows,
            cache.observed_at_epoch_seconds,
            cache.next_refresh_after_epoch_seconds,
            claude_credit_pools::claude_reset_read_delay_seconds(
                account_identifier_hash,
                organization_identifier_hash,
            ),
            now,
        );
        if !cache.windows.is_empty()
            && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            && !reset_read_due
            && !explicit_refresh_due
            && !claude_credit_pools::claude_reading_due(
                Some(cache.observed_at_epoch_seconds),
                cache.next_refresh_after_epoch_seconds,
                slot_seconds,
                now,
            )
        {
            let retry_after = (rate_limit_retry_evidenced
                && claude_credit_pools::claude_slot_elapsed(cache_age, slot_seconds)
                && now < cache.next_refresh_after_epoch_seconds)
                .then(|| rfc3339_from_unix_seconds(cache.next_refresh_after_epoch_seconds))
                .flatten();
            let mut outcome =
                ClaudeOAuthUsageOutcome::from(Ok(claude_oauth_usage_from_cache(cache, now)))
                    .with_check_outcome(
                        "claude_oauth_usage_cache_reused",
                        CLAUDE_CACHE_REUSED_MESSAGE,
                        now,
                    );
            if let Some(diagnostic) = outcome.diagnostics.last_mut() {
                diagnostic.retry_after = retry_after;
            }
            return outcome;
        }
        if now < cache.next_refresh_after_epoch_seconds && !explicit_refresh_due {
            // A stored reading without windows under the hold: the saved-reset
            // section of a windowless variant read, served for this slot.
            if held.active && cache.windows.is_empty() {
                return claude_oauth_read_held_outcome(
                    Ok(claude_oauth_usage_from_cache(cache, now)),
                    now,
                );
            }
            return ClaudeOAuthUsageOutcome::from(Err(
                "Claude OAuth usage endpoint is rate limited.".to_string(),
            ));
        }
        if !cache.windows.is_empty() && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS {
            exact_stale_fallback = Some(cache);
        }
    } else if claude_explicit_refresh_requested(
        account_identifier_hash,
        organization_identifier_hash,
        0,
        now,
    ) {
        // Nothing stored yet: an explicit refresh may read it now.
        explicit_refresh_due = true;
        note_claude_explicit_refresh_attempt(
            account_identifier_hash,
            organization_identifier_hash,
            now,
        );
    }

    // The hold applies even without a stored reading to serve; a servable
    // stale reading is served.
    if held.active {
        return claude_oauth_read_held_outcome(
            match exact_stale_fallback {
                Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
                None => {
                    Err("Claude usage for this account is read again at its next slot.".to_string())
                }
            },
            now,
        );
    }

    // Passive input (active-account freshness): Claude Code's own
    // plain reading for exactly this binding, newer than ours and inside the
    // slot, stands in for a plain slot's call. Parsed by the same plain-body
    // parser; no provider request.

    // The slot's read is chosen first (same endpoint, same slot: the
    // saved-reset variant replaces the plain read in its slot, never adds a
    // call). A passive body can only stand in for a plain slot, so it never
    // displaces a saved-reset slot.
    let usage_read =
        claude_credit_pools::claude_usage_read_kind(&read_schedule, &previous_credit_balances, now);
    let passive_config = if usage_read == claude_credit_pools::ClaudeUsageRead::Plain {
        claude_oauth_passive_config(
            caller,
            account_identifier_hash,
            organization_identifier_hash,
        )
    } else {
        claude_credit_pools::ClaudePassiveConfig::default()
    };
    if let Some(passive) = passive_config.reading.filter(|passive| {
        claude_credit_pools::claude_passive_reading_usable(
            passive.fetched_at,
            last_reading_at,
            Some(caller_bound_since),
            slot_seconds,
            now,
        )
    }) {
        if let Ok(usage) = claude_oauth_usage_record_reading(
            ClaudeOAuthReading {
                account_identifier_hash,
                organization_identifier_hash,
                body: &passive.body,
                read: claude_credit_pools::ClaudeUsageRead::Plain,
                observed_at_epoch_seconds: passive.fetched_at,
                previous_credit_balances: &previous_credit_balances,
                latest_activity_at,
                now,
                mirror_legacy_default,
            },
            &mut read_schedule,
        ) {
            return ClaudeOAuthUsageOutcome::from(Ok(usage)).with_check_outcome(
                "claude_oauth_usage_cache_reused",
                "A newer local quota reading that Claude Code made for this exact account was reused; no provider request was made.",
                now,
            );
        }
    }

    let Some(token) = access_token else {
        if let Some(cache) = exact_stale_fallback {
            return ClaudeOAuthUsageOutcome {
                result: Ok(claude_oauth_usage_from_cache(cache, now)),
                diagnostics: open_breaker
                    .as_ref()
                    .map(|breaker| claude_oauth_usage_circuit_open_diagnostic(breaker, now))
                    .into_iter()
                    .collect(),
            }
            .with_check_outcome(
                "claude_oauth_usage_cache_reused",
                "A prior local quota reading was reused; no provider request was made.",
                now,
            );
        }
        if let Some(breaker) = open_breaker {
            return ClaudeOAuthUsageOutcome {
                result: Err("Claude OAuth usage endpoint is not being called.".to_string()),
                diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
            }
            .with_check_outcome(
                "claude_oauth_usage_check_suppressed",
                "The local quota breaker suppressed this provider request.",
                now,
            );
        }
        return ClaudeOAuthUsageOutcome::from(Err(
            "Claude OAuth credentials were not available locally.".to_string(),
        ));
    };
    // Never send an access token that is expired by the local clock: the
    // request could only be rejected (adding a per-caller hold), and only
    // Claude Code itself may refresh the login. The daemon never uses the
    // refresh token.
    // A fresh clock sample: cache, breaker and lock reads above can block, and
    // the Mac can sleep, after `now` was taken.
    if claude_access_token_locally_expired(credential_expires_at, clock()) {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude Code has not refreshed this login since its access token expired."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome {
            result,
            diagnostics: Vec::new(),
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "This Claude login's access token has expired locally and Claude Code has not refreshed it yet; no provider request was made, and any served readings are last-known local readings.",
            now,
        );
    }
    if let Some(breaker) = open_breaker {
        if let Some(cache) = exact_stale_fallback {
            return ClaudeOAuthUsageOutcome {
                result: Ok(claude_oauth_usage_from_cache(cache, now)),
                diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
            }.with_check_outcome("claude_oauth_usage_check_suppressed", "The local quota breaker suppressed this provider request; last-known local readings were reused.", now);
        }
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude OAuth usage endpoint is not being called.".to_string()),
            diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "The local quota breaker suppressed this provider request.",
            now,
        );
    }
    // This caller's own credential was rejected recently. Hold only this
    // caller; another credential for the same account is unaffected.
    if let Some(hold) = caller_auth_hold {
        let held = claude_oauth_usage_caller_auth_hold_diagnostic(caller, &hold, now);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude OAuth usage is backing off after this credential was rejected.".to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome {
            result,
            diagnostics: vec![held],
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "The local quota breaker suppressed this provider request after this credential was rejected.",
            now,
        );
    }
    #[cfg(test)]
    if let Some(hook) = *CLAUDE_OAUTH_BEFORE_SEND_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        hook();
    }
    // Last check, with a clock read immediately before the request.
    if claude_access_token_locally_expired(credential_expires_at, clock()) {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude Code has not refreshed this login since its access token expired."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome {
            result,
            diagnostics: Vec::new(),
        }
        .with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "This Claude login's access token has expired locally and Claude Code has not refreshed it yet; no provider request was made, and any served readings are last-known local readings.",
            clock(),
        );
    }
    if claude_transient_failure_held(account_identifier_hash, organization_identifier_hash, now) {
        let result = match read_claude_oauth_usage_cache_with_legacy_migration(
            account_identifier_hash,
            organization_identifier_hash,
            mirror_legacy_default,
        )
        .filter(|cache| {
            !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
        }) {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "The latest Claude OAuth quota request failed; it is retried after a minute."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "The latest Claude OAuth quota request failed moments ago; no provider request was made, and any served readings are last-known local readings.",
            clock(),
        );
    }
    // "Background limit refresh" off: the daemon's own passes read no
    // account, the default login included. Only an explicit refresh and setup
    // checks call the provider; stored readings are served and age as usual.
    if !explicit_refresh_due && claude_background_read_withheld() {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE.to_string()),
        };
        return ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
            "claude_oauth_usage_check_suppressed",
            "Background limit refresh is off: no provider request was made, and any served readings are last-known local readings.",
            now,
        );
    }
    // A status read for the app serves the stored reading: only the daemon's
    // own passes, an explicit refresh and setup checks call the provider. The
    // daemon's next pass reads a due account.
    if claude_pass_saved_only() && !explicit_refresh_due {
        drop(token);
        let result = match exact_stale_fallback {
            Some(cache) => Ok(claude_oauth_usage_from_cache(cache, now)),
            None => Err(
                "Claude quota for this account has no stored reading yet; the daemon reads it shortly."
                    .to_string(),
            ),
        };
        return ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
            "claude_oauth_usage_cache_reused",
            "A status read served the stored quota reading; the daemon's own schedule makes the provider requests.",
            now,
        );
    }
    let authorization = format!("Bearer {token}");
    let user_agent = ottto_user_agent();
    // Same endpoint, same slot: the saved-reset variant replaces the plain
    // read in its slot, never adds a call.
    let endpoint = format!("{CLAUDE_OAUTH_USAGE_ENDPOINT}{}", usage_read.query());
    #[cfg(test)]
    CLAUDE_OAUTH_PROVIDER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    #[cfg(test)]
    if CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.load(std::sync::atomic::Ordering::SeqCst) {
        return ClaudeOAuthUsageOutcome::from(Err(
            "This test forbids Claude OAuth provider requests.".to_string(),
        ));
    }
    // A test response stands in for the provider's response text.
    #[cfg(test)]
    let injected = CLAUDE_OAUTH_TEST_RESPONSE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .map(|respond| respond(&endpoint).map(|body| body.to_string()));
    #[cfg(not(test))]
    let injected: Option<Result<String, u16>> = None;
    let call_started = Instant::now();
    let record_call = |result: crate::provider_calls::CallResult| {
        use crate::provider_calls::{CallKind, Provider, ProviderCall, Trigger};
        let trigger = if explicit_refresh_due {
            claude_explicit_refresh_request().trigger
        } else {
            crate::provider_calls::trigger_or(Trigger::Schedule)
        };
        crate::provider_calls::record(ProviderCall::observed(
            Provider::Anthropic,
            CallKind::ClaudeOauthUsage,
            trigger,
            Some(account_identifier_hash),
            result,
            call_started.elapsed(),
        ));
    };
    let response = match injected {
        Some(Ok(body)) => {
            record_call(crate::provider_calls::CallResult::Ok);
            let value =
                credit_amount_input::decode(&body, credit_amount_input::CreditBody::ClaudeUsage)
                    .unwrap_or_default();
            return claude_oauth_usage_after_response(
                ClaudeOAuthReading {
                    account_identifier_hash,
                    organization_identifier_hash,
                    body: &value,
                    read: usage_read,
                    observed_at_epoch_seconds: clock(),
                    previous_credit_balances: &previous_credit_balances,
                    latest_activity_at,
                    now,
                    mirror_legacy_default,
                },
                caller,
                &config_fingerprint,
                slot_seconds,
                &mut read_schedule,
            );
        }
        Some(Err(status)) => match ureq::Response::new(status, "injected", "") {
            Ok(response) => Err(ureq::Error::Status(status, response)),
            Err(error) => Err(error),
        },
        None => crate::retry_tls::agent()
            .get(&endpoint)
            .set("Accept", "application/json")
            .set("Content-Type", "application/json")
            .set("Authorization", &authorization)
            .set("anthropic-beta", CLAUDE_OAUTH_BETA_HEADER)
            .set("User-Agent", &user_agent)
            .timeout(COMMAND_TIMEOUT)
            .call(),
    };
    record_call(crate::provider_calls::http_result(&response));
    let response = match response {
        Ok(response) => response,
        // The provider rejected the saved-reset variant itself (not auth, not
        // a rate limit): variant state, never an endpoint-breaker strike, and
        // never retried on the next pass.
        Err(ureq::Error::Status(status, _))
            if usage_read == claude_credit_pools::ClaudeUsageRead::SavedResets
                && claude_credit_pools::claude_saved_resets_variant_rejected(status) =>
        {
            return claude_oauth_saved_resets_variant_unusable(
                account_identifier_hash,
                organization_identifier_hash,
                mirror_legacy_default,
                slot_seconds,
                &mut read_schedule,
                now,
            );
        }
        Err(ureq::Error::Status(429, response)) => {
            let retry_after = claude_oauth_retry_after_epoch_seconds(&response, now);
            set_claude_binding_time(
                &mut claude_rate_limit_holds(),
                account_identifier_hash,
                organization_identifier_hash,
                retry_after,
            );
            // A cache belonging to another account is not merely skipped here:
            // `unwrap_or` replaces it with an empty cache for the current
            // account, so the write below also clears the stale payload off
            // disk instead of leaving it to be reconsidered next tick.
            let mut cache = read_claude_oauth_usage_cache_with_legacy_migration(
                account_identifier_hash,
                organization_identifier_hash,
                mirror_legacy_default,
            )
            .unwrap_or(ClaudeOAuthUsageCache {
                schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                account_identifier_hash: account_identifier_hash.to_string(),
                organization_identifier_hash: organization_identifier_hash.to_string(),
                observed_at_epoch_seconds: now,
                next_refresh_after_epoch_seconds: retry_after,
                windows: Vec::new(),
                credit_balances: Vec::new(),
                account_weekly_not_offered: false,
                account_session_not_offered: false,
            });
            cache.next_refresh_after_epoch_seconds = retry_after;
            let _ = write_claude_oauth_usage_cache(&cache);
            if mirror_legacy_default {
                let _ = write_legacy_claude_oauth_usage_cache(&cache);
            }
            // The retry-after backoff above still handles the transient case
            // unchanged; the breaker only fires once 429s outlive it.
            let mut diagnostics = record_claude_oauth_usage_failure_with_legacy(
                ClaudeOAuthUsageFailure::RateLimited,
                account_identifier_hash,
                organization_identifier_hash,
                &config_fingerprint,
                now,
                mirror_legacy_default,
            );
            diagnostics.push(claude_quota_check_diagnostic("claude_oauth_usage_check_failed", "The latest Claude OAuth quota request failed with rate limiting; any served readings remain locally cached evidence.", clock()));
            diagnostics.push(claude_oauth_usage_rate_limited_diagnostic(
                usage_read,
                retry_after,
                now,
            ));
            if !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            {
                return ClaudeOAuthUsageOutcome {
                    result: Ok(claude_oauth_usage_from_cache(cache, now)),
                    diagnostics,
                };
            }
            return ClaudeOAuthUsageOutcome {
                result: Err("Claude OAuth usage endpoint is rate limited.".to_string()),
                diagnostics,
            };
        }
        Err(error) => {
            let mut diagnostics = match claude_oauth_usage_failure_class(&error) {
                Some(ClaudeOAuthUsageFailure::AuthRejected) => {
                    let status = match &error {
                        ureq::Error::Status(status, _) => *status,
                        ureq::Error::Transport(_) => 0,
                    };
                    record_claude_oauth_usage_auth_failure(
                        caller,
                        status,
                        account_identifier_hash,
                        organization_identifier_hash,
                        &config_fingerprint,
                        now,
                        credential_expires_at,
                    )
                }
                Some(failure) => record_claude_oauth_usage_failure_with_legacy(
                    failure,
                    account_identifier_hash,
                    organization_identifier_hash,
                    &config_fingerprint,
                    now,
                    mirror_legacy_default,
                ),
                None => {
                    set_claude_binding_time(
                        &mut claude_transient_failures(),
                        account_identifier_hash,
                        organization_identifier_hash,
                        clock(),
                    );
                    Vec::new()
                }
            };
            diagnostics.push(claude_quota_check_diagnostic("claude_oauth_usage_check_failed", "The latest Claude OAuth quota request failed; any served readings remain locally cached evidence.", clock()));
            if let Some(cache) = read_claude_oauth_usage_cache_with_legacy_migration(
                account_identifier_hash,
                organization_identifier_hash,
                mirror_legacy_default,
            ) {
                if !cache.windows.is_empty()
                    && now.saturating_sub(cache.observed_at_epoch_seconds)
                        <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
                {
                    return ClaudeOAuthUsageOutcome {
                        result: Ok(claude_oauth_usage_from_cache(cache, now)),
                        diagnostics,
                    };
                }
            }
            return ClaudeOAuthUsageOutcome {
                result: Err(claude_oauth_usage_error(error)),
                diagnostics,
            };
        }
    };
    let Some(value) = response.into_string().ok().and_then(|body| {
        credit_amount_input::decode(&body, credit_amount_input::CreditBody::ClaudeUsage)
    }) else {
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude OAuth usage endpoint returned an unreadable response.".to_string()),
            diagnostics: record_claude_oauth_usage_failure_with_legacy(
                ClaudeOAuthUsageFailure::ResponseShape,
                account_identifier_hash,
                organization_identifier_hash,
                &config_fingerprint,
                now,
                mirror_legacy_default,
            ),
        }
        .with_check_outcome(
            "claude_oauth_usage_check_failed",
            "The latest Claude OAuth response could not be read as quota data.",
            clock(),
        );
    };
    // This is the local successful response time, never a provider-supplied
    // timestamp. Cache reuse preserves it rather than stamping a later upload.
    claude_oauth_usage_after_response(
        ClaudeOAuthReading {
            account_identifier_hash,
            organization_identifier_hash,
            body: &value,
            read: usage_read,
            observed_at_epoch_seconds: clock(),
            previous_credit_balances: &previous_credit_balances,
            latest_activity_at,
            now,
            mirror_legacy_default,
        },
        caller,
        &config_fingerprint,
        slot_seconds,
        &mut read_schedule,
    )
}

/// Test-only: runs between a registered slot's pre-collection gate and its
/// resolution read, to change the slot's login in between.
#[cfg(test)]
type ClaudeSlotTestHook = Box<dyn Fn() + Send>;
#[cfg(test)]
static CLAUDE_SLOT_AFTER_PRE_GATE_HOOK: Mutex<Option<ClaudeSlotTestHook>> = Mutex::new(None);

#[cfg(test)]
fn claude_slot_after_pre_gate_hook() {
    if let Some(hook) = CLAUDE_SLOT_AFTER_PRE_GATE_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        hook();
    }
}

/// Test-only stand-in for the provider, consulted after every pre-request
/// gate has run: answers the request URL with a 200 body (`Ok`) or an HTTP
/// status (`Err`) that goes through the real response arms.
#[cfg(test)]
type ClaudeOAuthTestResponder = fn(&str) -> Result<Value, u16>;
#[cfg(test)]
static CLAUDE_OAUTH_TEST_RESPONSE: Mutex<Option<ClaudeOAuthTestResponder>> = Mutex::new(None);

const CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE: &str =
    "claude_saved_reset_variant_unrecognized";
/// Fixed, value-free text: the same words reach the slot status and upload.
const CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE: &str = "Claude's saved-reset reading had no recognizable saved-reset section; this account uses the plain reading for 24 hours.";

/// Local status only: the upload drops it (`ottto_protocol`).
const CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE: &str =
    ottto_protocol::CLAUDE_OAUTH_USAGE_RATE_LIMITED_DIAGNOSTIC_CODE;
/// Fixed, value-free slot-status text per read; the time is in `retry_after`.
const CLAUDE_OAUTH_USAGE_RATE_LIMITED_USAGE_MESSAGE: &str =
    "Claude asked Ottto to wait before the next usage read; Ottto checks again after the retry time.";
const CLAUDE_OAUTH_USAGE_RATE_LIMITED_SAVED_RESETS_MESSAGE: &str =
    "Claude asked Ottto to wait before the next saved-resets read; Ottto checks again after the retry time.";

/// A 429 on the Claude usage read: which read Claude asked Ottto to hold and
/// until when ("Claude asked Ottto to wait until HH:MM UTC"), with the same
/// deadline in `retry_after`. Reporting only: the Retry-After backoff, the
/// breaker and the calls made are unchanged.
fn claude_oauth_usage_rate_limited_diagnostic(
    read: claude_credit_pools::ClaudeUsageRead,
    retry_after: u64,
    now: u64,
) -> AgentStatusDiagnostic {
    let until = i64::try_from(retry_after)
        .ok()
        .and_then(|at| OffsetDateTime::from_unix_timestamp(at).ok())
        .map_or_else(
            || "later".to_string(),
            |at| format!("{:02}:{:02} UTC", at.hour(), at.minute()),
        );
    let mut diagnostic = claude_quota_check_diagnostic(
        CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE,
        &format!(
            "Claude asked Ottto to wait until {until} before the next {} read.",
            read.label()
        ),
        now,
    );
    diagnostic.retry_after = rfc3339_from_unix_seconds(retry_after);
    diagnostic
}

/// Handle one 200 response body.
///
/// The saved-reset variant is self-checked (owner decision): a body without a
/// recognizable `cedar_ember` adds a code-only diagnostic, sends no
/// saved-reset balance (the last observed one is re-sent), and pauses the
/// variant for this binding for 24 h. That pause is variant state, never a
/// strike on the endpoint breaker. A variant body that also lacks windows is
/// handled like a rejected variant
/// ([`claude_oauth_saved_resets_variant_unusable`]).
fn claude_oauth_usage_after_response(
    reading: ClaudeOAuthReading<'_>,
    caller: &ClaudeOAuthUsageCaller,
    config_fingerprint: &str,
    slot_seconds: u64,
    read_schedule: &mut claude_credit_pools::ClaudeReadSchedule,
) -> ClaudeOAuthUsageOutcome {
    let account_identifier_hash = reading.account_identifier_hash;
    let organization_identifier_hash = reading.organization_identifier_hash;
    let now = reading.now;
    let mirror_legacy_default = reading.mirror_legacy_default;
    let variant_recognized = (reading.read == claude_credit_pools::ClaudeUsageRead::SavedResets)
        .then(|| claude_credit_pools::claude_saved_resets_recognized(reading.body));
    if let Some(recognized) = variant_recognized {
        read_schedule.after_saved_resets_variant(recognized, now);
    }
    let unrecognized = (variant_recognized == Some(false)).then(|| {
        claude_quota_check_diagnostic(
            CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE,
            CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE,
            now,
        )
    });
    let read = reading.read;
    let usage = match claude_oauth_usage_record_reading(reading, read_schedule) {
        Ok(usage) => usage,
        // The saved-reset variant without windows is variant state, never an
        // endpoint shape failure: a recognizable saved-reset section is kept,
        // anything else pauses the variant.
        Err(_) if read == claude_credit_pools::ClaudeUsageRead::SavedResets => {
            if unrecognized.is_none() {
                return claude_oauth_saved_resets_without_windows(
                    reading,
                    slot_seconds,
                    read_schedule,
                );
            }
            return claude_oauth_saved_resets_variant_unusable(
                account_identifier_hash,
                organization_identifier_hash,
                mirror_legacy_default,
                slot_seconds,
                read_schedule,
                now,
            );
        }
        // A plain 200 that carries none of the expected quota fields is a
        // shape change, not an empty account: every plan this endpoint answers
        // for reports at least one window.
        Err(usage) => {
            return ClaudeOAuthUsageOutcome {
                result: Ok(usage),
                diagnostics: record_claude_oauth_usage_failure_with_legacy(
                    ClaudeOAuthUsageFailure::ResponseShape,
                    account_identifier_hash,
                    organization_identifier_hash,
                    config_fingerprint,
                    now,
                    mirror_legacy_default,
                ),
            }
            .with_check_outcome(
                "claude_oauth_usage_check_failed",
                "The latest Claude OAuth response contained no supported quota windows.",
                current_unix_seconds(),
            );
        }
    };
    // One clean answer clears the accumulated failure counters: the thresholds
    // below are about *consecutive* failures. Another caller's own auth
    // streak survives: this answer says nothing about that credential.
    clear_claude_oauth_usage_breaker_after_success(
        caller,
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        now,
    );
    ClaudeOAuthUsageOutcome {
        result: Ok(usage),
        diagnostics: unrecognized.into_iter().collect(),
    }
    .with_check_outcome(
        "claude_oauth_usage_check_succeeded",
        "A supported Claude OAuth quota response was collected successfully.",
        current_unix_seconds(),
    )
}

/// The binding is held until its next slot after a saved-reset reading that
/// was not usable (or had no windows): no provider request in this slot.
fn claude_oauth_read_held_outcome(
    result: Result<ClaudeOAuthUsage, String>,
    now: u64,
) -> ClaudeOAuthUsageOutcome {
    ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
        "claude_oauth_usage_check_suppressed",
        "The last Claude saved-reset reading was not usable; no provider request is made before this account's next slot.",
        now,
    )
}

/// The saved-reset variant answered with a recognizable saved-reset section
/// but no windows. Not a shape failure, so no breaker strike: the fresh
/// saved-reset section is kept, the stored windows and other sections are
/// served unchanged, and the binding's next read moves out by one slot (no
/// second call in this slot, with or without a stored reading).
fn claude_oauth_saved_resets_without_windows(
    reading: ClaudeOAuthReading<'_>,
    slot_seconds: u64,
    read_schedule: &mut claude_credit_pools::ClaudeReadSchedule,
) -> ClaudeOAuthUsageOutcome {
    let account_identifier_hash = reading.account_identifier_hash;
    let organization_identifier_hash = reading.organization_identifier_hash;
    let now = reading.now;
    let next_read = now.saturating_add(slot_seconds);
    let observed_at =
        rfc3339_from_unix_seconds(reading.observed_at_epoch_seconds).unwrap_or_default();
    let credit_read = claude_credit_pools::claude_credit_read(
        reading.body,
        claude_credit_pools::ClaudeUsageRead::SavedResets,
        &observed_at,
    );
    let stored = read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        reading.mirror_legacy_default,
    );
    let mut usage = ClaudeOAuthUsage {
        windows: Vec::new(),
        credit_balances: claude_credit_pools::claude_merge_credit_sections(
            &claude_oauth_binding_key(account_identifier_hash, organization_identifier_hash),
            stored
                .as_ref()
                .map_or(reading.previous_credit_balances, |cache| {
                    cache.credit_balances.as_slice()
                }),
            &credit_read,
        ),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    };
    claude_oauth_stamp_account_identity(
        &mut usage,
        account_identifier_hash,
        Some(organization_identifier_hash),
    );
    read_schedule.after_reading(
        claude_credit_pools::ClaudeUsageRead::SavedResets,
        reading.observed_at_epoch_seconds,
        reading.latest_activity_at,
        now,
    );
    read_schedule.next_read_not_before = Some(next_read);
    let _ = claude_credit_pools::write_claude_read_schedule(
        &claude_oauth_usage_account_state_dir(
            account_identifier_hash,
            organization_identifier_hash,
        ),
        read_schedule,
    );
    let mut cache = stored.unwrap_or(ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account_identifier_hash.to_string(),
        organization_identifier_hash: organization_identifier_hash.to_string(),
        observed_at_epoch_seconds: now,
        next_refresh_after_epoch_seconds: next_read,
        windows: Vec::new(),
        credit_balances: Vec::new(),
        account_weekly_not_offered: false,
        account_session_not_offered: false,
    });
    cache.credit_balances = usage.credit_balances;
    cache.next_refresh_after_epoch_seconds = next_read;
    let _ = write_claude_oauth_usage_cache(&cache);
    if reading.mirror_legacy_default {
        let _ = write_legacy_claude_oauth_usage_cache(&cache);
    }
    // Without a stored reading, the cache holds just this saved-reset section
    // (no windows), served as such.
    let result = if now.saturating_sub(cache.observed_at_epoch_seconds)
        <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
    {
        Ok(claude_oauth_usage_from_cache(cache, now))
    } else {
        Err("Claude's saved-reset reading carried no quota windows.".to_string())
    };
    ClaudeOAuthUsageOutcome::from(result).with_check_outcome(
        "claude_oauth_usage_cache_reused",
        "The latest Claude saved-reset reading carried no quota windows; its saved-reset section was kept and the stored windows were reused.",
        current_unix_seconds(),
    )
}

/// The saved-reset variant gave this binding nothing usable this slot: a 200
/// without windows or a recognizable `cedar_ember`, or a 4xx rejection other
/// than auth or rate limiting. Variant state only, never an endpoint-breaker
/// strike:
/// - the variant pauses for 24 h for this binding (every slot reads plain);
/// - the code-only diagnostic is added;
/// - the stored reading is served unchanged, so no section flips off;
/// - the binding's next read moves out by one slot: no second call in this
///   slot, and no retry on every pass.
fn claude_oauth_saved_resets_variant_unusable(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    mirror_legacy_default: bool,
    slot_seconds: u64,
    read_schedule: &mut claude_credit_pools::ClaudeReadSchedule,
    now: u64,
) -> ClaudeOAuthUsageOutcome {
    read_schedule.after_saved_resets_variant(false, now);
    // No call before the next slot, with or without a stored reading.
    read_schedule.next_read_not_before = Some(now.saturating_add(slot_seconds));
    let _ = claude_credit_pools::write_claude_read_schedule(
        &claude_oauth_usage_account_state_dir(
            account_identifier_hash,
            organization_identifier_hash,
        ),
        read_schedule,
    );
    let diagnostics = vec![claude_quota_check_diagnostic(
        CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE,
        CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE,
        now,
    )];
    let stored = read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        mirror_legacy_default,
    );
    let result = match stored {
        Some(mut cache) => {
            cache.next_refresh_after_epoch_seconds = now.saturating_add(slot_seconds);
            let _ = write_claude_oauth_usage_cache(&cache);
            if mirror_legacy_default {
                let _ = write_legacy_claude_oauth_usage_cache(&cache);
            }
            if !cache.windows.is_empty()
                && now.saturating_sub(cache.observed_at_epoch_seconds)
                    <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            {
                Ok(claude_oauth_usage_from_cache(cache, now))
            } else {
                Err("Claude's saved-reset reading was not usable.".to_string())
            }
        }
        None => Err("Claude's saved-reset reading was not usable.".to_string()),
    };
    ClaudeOAuthUsageOutcome {
        result,
        diagnostics,
    }
    .with_check_outcome(
        "claude_oauth_usage_check_failed",
        "The latest Claude saved-reset reading was not usable; the stored reading was kept.",
        current_unix_seconds(),
    )
}

/// Per caller: the binding its login was seen on, pass after pass. In memory
/// only, so a restart starts every run afresh.
static CLAUDE_OAUTH_CALLER_BINDINGS: Mutex<
    BTreeMap<String, claude_credit_pools::ClaudeCallerBinding>,
> = Mutex::new(BTreeMap::new());

/// Callers that reached the usage collector during the open full collection
/// pass(es), with the number of open passes.
static CLAUDE_OAUTH_PASS_CALLERS: Mutex<(usize, BTreeSet<String>)> =
    Mutex::new((0, BTreeSet::new()));

/// One full collection pass (`collect_claude_status_snapshots`). When the last
/// open pass ends, every caller run not seen at the collector during it ends.
///
/// Overlapping passes share one reached set (their union), and the sweep runs
/// when the last of them ends: a caller reached by one overlapping pass but
/// skipped by another keeps its run here. The skipping pass's explicit run-end
/// on that skip return, and the 15 min run gap, still apply, so the sweep is
/// defense in depth for that case rather than the only guard.
struct ClaudeOAuthCollectionPass;

impl ClaudeOAuthCollectionPass {
    fn begin() -> Self {
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

fn claude_oauth_pass_reached_collector(caller: &ClaudeOAuthUsageCaller) {
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
fn claude_oauth_end_caller_run(caller: &ClaudeOAuthUsageCaller) {
    claude_credit_pools::claude_end_caller_binding(
        &mut CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        &caller.breaker_key(),
    );
}

fn claude_oauth_end_slot_run(slot_id: &str) {
    claude_oauth_end_caller_run(&ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.to_string()));
}

/// One usable OAuth usage body: a provider response, or a passive reading
/// Claude Code made for the same binding.
#[derive(Clone, Copy)]
struct ClaudeOAuthReading<'a> {
    account_identifier_hash: &'a str,
    organization_identifier_hash: &'a str,
    body: &'a Value,
    read: claude_credit_pools::ClaudeUsageRead,
    /// When the body was read: the local response time, or the passive
    /// reading's own fetch time.
    observed_at_epoch_seconds: u64,
    previous_credit_balances: &'a [AgentCreditBalance],
    latest_activity_at: Option<u64>,
    now: u64,
    mirror_legacy_default: bool,
}

/// Parse, merge and store one reading. `Err` carries the unstored parse when
/// the body has no supported quota window (a shape change).
fn claude_oauth_usage_record_reading(
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
    if reading.mirror_legacy_default {
        let _ = write_legacy_claude_oauth_usage_cache(&cache);
    }
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
fn claude_oauth_caller_identity_path(caller: &ClaudeOAuthUsageCaller) -> Option<PathBuf> {
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
fn claude_oauth_passive_config(
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
fn claude_oauth_activity(
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
fn claude_oauth_usage_slot_seconds(
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
fn claude_oauth_usage_serve_gate_seconds(
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
fn claude_statusline_fresh_for_binding(
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
const CLAUDE_EXPLICIT_REFRESH_TTL_SECONDS: u64 = 2 * 60;
const CLAUDE_EXPLICIT_REFRESH_MIN_GAP_SECONDS: u64 = 60;

/// The last explicit refresh request: when it was made (0: never) and why,
/// for the provider-call log of the reads it causes on the lane thread.
struct ClaudeExplicitRefreshRequest {
    at: u64,
    trigger: crate::provider_calls::Trigger,
}

fn claude_explicit_refresh_request() -> std::sync::MutexGuard<'static, ClaudeExplicitRefreshRequest>
{
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
/// minute old. The caller's trigger (an older app's status refresh) labels
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
fn claude_explicit_refresh_requested(
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
struct ClaudeBindingTime {
    account_identifier_hash: String,
    organization_identifier_hash: String,
    at: u64,
}

const CLAUDE_BINDING_TIMES_MAX: usize = 64;

fn claude_binding_time(
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

fn set_claude_binding_time(
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
fn claude_explicit_refresh_attempts() -> std::sync::MutexGuard<'static, Vec<ClaudeBindingTime>> {
    static ATTEMPTS: Mutex<Vec<ClaudeBindingTime>> = Mutex::new(Vec::new());
    ATTEMPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn note_claude_explicit_refresh_attempt(
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
fn claude_rate_limit_holds() -> std::sync::MutexGuard<'static, Vec<ClaudeBindingTime>> {
    static HOLDS: Mutex<Vec<ClaudeBindingTime>> = Mutex::new(Vec::new());
    HOLDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn claude_rate_limit_held(
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
struct ClaudePass {
    /// An app's status request: serve stored readings. Only an explicit
    /// refresh reads the provider in such a pass.
    saved_only: bool,
    /// When the pass started (unix seconds).
    started_at: u64,
}

thread_local! {
    static CLAUDE_PASS: std::cell::Cell<Option<ClaudePass>> = const { std::cell::Cell::new(None) };
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

const CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE: &str =
    "Claude quota for this account has no stored reading, and background limit refresh is off; use Refresh limits to read it now.";

/// Whether this read is a background one that "Background limit refresh"
/// (the Claude upkeep consent) withholds: it runs in a collection pass of the
/// status lane (the daemon's schedule, or an app's status request) while the
/// switch is off, and its caller is not a setup check. Reads outside a pass
/// (setup and account checks, a standalone collection) and an explicit
/// refresh, which the caller checks first, are never withheld. Unreadable
/// settings count as off, as for the sign-in renewal.
fn claude_background_read_withheld() -> bool {
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
const CLAUDE_PASS_ANCHOR_MAX_SECONDS: u64 = 2 * 60;

/// Where the spacing after a successful read is measured from: the start of
/// the collection pass that read, so the next pass 5 min later finds the
/// account due wherever in that pass the read falls; `now` outside a pass.
fn claude_spacing_anchor(now: u64) -> u64 {
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
const CLAUDE_TRANSIENT_FAILURE_RETRY_SECONDS: u64 = 60;

fn claude_transient_failures() -> std::sync::MutexGuard<'static, Vec<ClaudeBindingTime>> {
    static FAILURES: Mutex<Vec<ClaudeBindingTime>> = Mutex::new(Vec::new());
    FAILURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn claude_transient_failure_held(
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
    fn with_check_outcome(mut self, code: &str, detail: &str, now: u64) -> Self {
        self.diagnostics
            .push(claude_quota_check_diagnostic(code, detail, now));
        self
    }
}

fn claude_quota_check_diagnostic(code: &str, detail: &str, now: u64) -> AgentStatusDiagnostic {
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
fn claude_oauth_usage_fresh_age_seconds(
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

/// Whether the off-switch sentinel is present in the daemon support dir.
///
/// Absent means enabled, which keeps the default behaviour unchanged.
pub(crate) fn claude_oauth_usage_network_disabled() -> bool {
    default_support_dir()
        .join(CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE)
        .is_file()
}

fn claude_oauth_binding_key(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-strong-binding:v1\0");
    hasher.update(account_identifier_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(organization_identifier_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn claude_oauth_usage_account_state_dir(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> PathBuf {
    let component = if account_identifier_hash.is_empty() || organization_identifier_hash.is_empty()
    {
        "unresolved".to_string()
    } else {
        claude_oauth_binding_key(account_identifier_hash, organization_identifier_hash)
    };
    default_support_dir()
        .join(CLAUDE_OAUTH_USAGE_ACCOUNT_STATE_DIR)
        .join(component)
}

fn claude_oauth_usage_breaker_path(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> PathBuf {
    claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash)
        .join(CLAUDE_OAUTH_USAGE_BREAKER_FILE)
}

fn claude_oauth_usage_legacy_breaker_path() -> PathBuf {
    default_support_dir().join(CLAUDE_OAUTH_USAGE_LEGACY_BREAKER_FILE)
}

fn claude_oauth_account_state_lock(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Arc<Mutex<()>> {
    let mut locks = CLAUDE_OAUTH_ACCOUNT_STATE_LOCKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks
        .entry(claude_oauth_binding_key(
            account_identifier_hash,
            organization_identifier_hash,
        ))
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn try_claude_oauth_collection_attempt(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<ClaudeOAuthCollectionAttemptGuard> {
    use std::os::fd::AsRawFd;
    let process_lock = {
        let mut locks = CLAUDE_OAUTH_COLLECTION_ATTEMPT_LOCKS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *locks
            .entry(claude_oauth_binding_key(
                account_identifier_hash,
                organization_identifier_hash,
            ))
            .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
    };
    let process = match process_lock.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return None,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
    };
    let account_root =
        claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash);
    if fs::create_dir_all(&account_root).is_err() {
        return None;
    }
    let file = open_private_lock_file(&account_root.join(".collection-attempt.lock")).ok()?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    Some(ClaudeOAuthCollectionAttemptGuard {
        _process: process,
        file,
    })
}

/// Fingerprint of everything about the call that could make a past failure
/// irrelevant: the endpoint, the beta header, the User-Agent we identify with,
/// and whether the off-switch is engaged. When any of them changes - a daemon
/// upgrade, or the user toggling the sentinel off and back on - the breaker
/// resets rather than holding a verdict about a call we no longer make.
fn claude_oauth_usage_config_fingerprint() -> String {
    claude_oauth_usage_config_fingerprint_for(
        CLAUDE_OAUTH_USAGE_ENDPOINT,
        CLAUDE_OAUTH_BETA_HEADER,
        &ottto_user_agent(),
        claude_oauth_usage_network_disabled(),
    )
}

fn claude_oauth_usage_config_fingerprint_for(
    endpoint: &str,
    beta_header: &str,
    user_agent: &str,
    network_disabled: bool,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:claude-oauth-usage-config:");
    hasher.update(endpoint.as_bytes());
    hasher.update(b"\0");
    hasher.update(beta_header.as_bytes());
    hasher.update(b"\0");
    hasher.update(user_agent.as_bytes());
    hasher.update(b"\0");
    hasher.update(if network_disabled { "off" } else { "on" }.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

#[cfg(test)]
fn read_claude_oauth_usage_breaker(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
) -> Option<ClaudeOAuthUsageBreaker> {
    read_claude_oauth_usage_breaker_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        true,
    )
}

fn read_claude_oauth_usage_breaker_with_legacy_migration(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    allow_legacy_migration: bool,
) -> Option<ClaudeOAuthUsageBreaker> {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        allow_legacy_migration,
    )
}

fn read_claude_oauth_usage_breaker_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    allow_legacy_migration: bool,
) -> Option<ClaudeOAuthUsageBreaker> {
    if allow_legacy_migration {
        migrate_legacy_claude_oauth_usage_breaker_locked(
            account_identifier_hash,
            organization_identifier_hash,
            config_fingerprint,
        );
    }
    if allow_legacy_migration {
        let _ = read_claude_oauth_usage_breaker_file_migrating(
            &claude_oauth_usage_legacy_breaker_path(),
        );
    }
    let breaker = read_claude_oauth_usage_breaker_file_migrating(
        &claude_oauth_usage_breaker_path(account_identifier_hash, organization_identifier_hash),
    )?;
    if breaker.schema_version != CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION
        || breaker.account_identifier_hash != account_identifier_hash
        || breaker.organization_identifier_hash != organization_identifier_hash
        || breaker.config_fingerprint != config_fingerprint
    {
        return None;
    }
    Some(breaker)
}

fn write_claude_oauth_usage_breaker_locked(
    breaker: &ClaudeOAuthUsageBreaker,
) -> std::io::Result<()> {
    let path = claude_oauth_usage_breaker_path(
        &breaker.account_identifier_hash,
        &breaker.organization_identifier_hash,
    );
    let body = serde_json::to_vec_pretty(breaker).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic(&path, &body)
}

fn write_legacy_claude_oauth_usage_breaker(
    breaker: &ClaudeOAuthUsageBreaker,
) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(breaker).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic(&claude_oauth_usage_legacy_breaker_path(), &body)
}

#[cfg(test)]
fn clear_claude_oauth_usage_breaker(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) {
    clear_claude_oauth_usage_breaker_with_legacy(
        account_identifier_hash,
        organization_identifier_hash,
        false,
    );
}

#[cfg(test)]
fn clear_claude_oauth_usage_breaker_with_legacy(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    mirror_legacy_default: bool,
) {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = fs::remove_file(claude_oauth_usage_breaker_path(
        account_identifier_hash,
        organization_identifier_hash,
    ));
    if mirror_legacy_default {
        let _ = fs::remove_file(claude_oauth_usage_legacy_breaker_path());
    }
}

/// Clear an auth-class open breaker once consented upkeep has replaced the
/// credential whose rejections opened it.
///
/// The breaker's own rule is that a changed call configuration resets it,
/// because the thing that was failing is not the thing we would call next. An
/// expired access token is exactly that: those 401s came from a credential
/// that no longer exists, and holding the full cool-down against a fresh one
/// leaves a healthy account's limits dark for up to a day. Only the auth class
/// is cleared - an unreadable response shape or a sustained 429 is a statement
/// about the endpoint rather than about our token, and keeps its cool-down.
///
/// Auth state is per caller, so only the refreshed slot's own streak and
/// backoff are retired; the default login's rejections, if any, were earned by
/// a different credential and stay. An account-wide auth verdict written by a
/// daemon from before caller attribution has only its auth fields cleared.
#[cfg(test)]
pub(crate) fn clear_claude_oauth_usage_auth_breaker(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    slot_id: &str,
) {
    let caller_key = ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.to_string()).breaker_key();
    let retire = |path: &Path| {
        let Some(mut breaker) =
            read_claude_oauth_usage_breaker_file_migrating(path).filter(|breaker| {
                breaker.account_identifier_hash == account_identifier_hash
                    && breaker.organization_identifier_hash == organization_identifier_hash
            })
        else {
            return;
        };
        let mut changed = breaker.auth_callers.remove(&caller_key).is_some();
        // A pre-attribution account-wide auth verdict: clear only its auth
        // fields. Other callers' attributed holds were earned by credentials
        // this refresh did not touch, and stay.
        if breaker.opened_by == ClaudeOAuthUsageFailure::AuthRejected.code() {
            breaker.auth_failures = 0;
            breaker.opened_by.clear();
            breaker.opened_at_epoch_seconds = 0;
            breaker.reopen_after_epoch_seconds = 0;
            changed = true;
        }
        if !changed {
            return;
        }
        if breaker.holds_no_state() {
            let _ = fs::remove_file(path);
            return;
        }
        if let Ok(body) = serde_json::to_vec_pretty(&breaker) {
            let _ = write_owner_only_file_atomic(path, &body);
        }
    };
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retire(&claude_oauth_usage_breaker_path(
        account_identifier_hash,
        organization_identifier_hash,
    ));
    retire(&claude_oauth_usage_legacy_breaker_path());
}

fn migrate_legacy_claude_oauth_usage_breaker_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
) {
    let target =
        claude_oauth_usage_breaker_path(account_identifier_hash, organization_identifier_hash);
    if target.exists() {
        return;
    }
    let _migration = CLAUDE_OAUTH_LEGACY_MIGRATION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if target.exists() {
        return;
    }
    let legacy = claude_oauth_usage_legacy_breaker_path();
    let Some(mut breaker) = fs::read_to_string(&legacy)
        .ok()
        .and_then(|body| serde_json::from_str::<ClaudeOAuthUsageBreaker>(&body).ok())
        .filter(|breaker| {
            breaker.schema_version == CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION
                && breaker.account_identifier_hash == account_identifier_hash
                && breaker.organization_identifier_hash == organization_identifier_hash
                && breaker.config_fingerprint == config_fingerprint
        })
    else {
        return;
    };
    breaker.migrate_raw_caller_keys();
    if write_claude_oauth_usage_breaker_locked(&breaker).is_ok() {
        let _ = fs::remove_file(legacy);
    }
}

fn claude_oauth_usage_breaker_is_open(breaker: &ClaudeOAuthUsageBreaker, now: u64) -> bool {
    // Reset by expiry: once the cool-down passes the breaker is closed again
    // and the next tick re-probes with the counters it carries.
    now < breaker.reopen_after_epoch_seconds
}

/// Fold one failure into the persisted breaker state. Pure so the thresholds
/// and the cool-down can be exercised without touching disk or the network.
fn claude_oauth_usage_breaker_after_failure(
    previous: Option<ClaudeOAuthUsageBreaker>,
    failure: ClaudeOAuthUsageFailure,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) -> ClaudeOAuthUsageBreaker {
    let mut breaker = previous.unwrap_or_default();
    breaker.schema_version = CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION;
    breaker.account_identifier_hash = account_identifier_hash.to_string();
    breaker.organization_identifier_hash = organization_identifier_hash.to_string();
    breaker.config_fingerprint = config_fingerprint.to_string();
    let counter = match failure {
        ClaudeOAuthUsageFailure::AuthRejected => &mut breaker.auth_failures,
        ClaudeOAuthUsageFailure::ResponseShape => &mut breaker.shape_failures,
        ClaudeOAuthUsageFailure::RateLimited => &mut breaker.rate_limit_failures,
    };
    *counter = counter.saturating_add(1);
    if *counter >= failure.threshold() && !claude_oauth_usage_breaker_is_open(&breaker, now) {
        breaker.opened_at_epoch_seconds = now;
        breaker.reopen_after_epoch_seconds = now + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS;
        breaker.opened_by = failure.code().to_string();
    }
    breaker
}

#[cfg(test)]
fn record_claude_oauth_usage_failure(
    failure: ClaudeOAuthUsageFailure,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) -> Vec<AgentStatusDiagnostic> {
    record_claude_oauth_usage_failure_with_legacy(
        failure,
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        now,
        false,
    )
}

fn record_claude_oauth_usage_failure_with_legacy(
    failure: ClaudeOAuthUsageFailure,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
    mirror_legacy_default: bool,
) -> Vec<AgentStatusDiagnostic> {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        mirror_legacy_default,
    );
    let was_open = previous
        .as_ref()
        .is_some_and(|breaker| claude_oauth_usage_breaker_is_open(breaker, now));
    let breaker = claude_oauth_usage_breaker_after_failure(
        previous,
        failure,
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        now,
    );
    let _ = write_claude_oauth_usage_breaker_locked(&breaker);
    if mirror_legacy_default {
        let _ = write_legacy_claude_oauth_usage_breaker(&breaker);
    }
    if !was_open && claude_oauth_usage_breaker_is_open(&breaker, now) {
        return vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)];
    }
    Vec::new()
}

/// The backoff one caller holds after `consecutive_failures` rejections in a
/// row: 15 minutes, then doubling, then the full breaker cool-down once the
/// caller reaches the auth threshold. Bounded by that cool-down.
fn claude_oauth_usage_auth_backoff_seconds(consecutive_failures: u32) -> u64 {
    if consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        return CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS;
    }
    let doublings = consecutive_failures.saturating_sub(1).min(16);
    CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS
        .saturating_mul(1u64 << doublings)
        .min(CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS)
}

/// This caller's auth state while it is held back, if it is. A rotated
/// credential (different access expiry) is not held by its predecessor's
/// rejections. `None` for the current expiry means unknown: the hold stands.
fn claude_oauth_usage_caller_auth_hold<'a>(
    breaker: &'a ClaudeOAuthUsageBreaker,
    caller: &ClaudeOAuthUsageCaller,
    now: u64,
    credential_expires_at: Option<&str>,
) -> Option<&'a ClaudeOAuthUsageCallerAuthState> {
    breaker
        .auth_callers
        .get(&caller.breaker_key())
        .filter(|state| now < state.backoff_until_epoch_seconds)
        .filter(|state| !claude_oauth_usage_caller_credential_rotated(state, credential_expires_at))
}

/// Fold one 401/403 from one caller into the persisted breaker. Pure so the
/// per-caller streak, backoff, and attribution fields can be tested directly.
///
/// The account-wide counters and open verdict are untouched: one credential's
/// rejection must not stop a different credential for the same account. A
/// caller whose streak is older than the cool-down starts a new streak.
#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
fn claude_oauth_usage_breaker_after_auth_failure(
    previous: Option<ClaudeOAuthUsageBreaker>,
    caller: &ClaudeOAuthUsageCaller,
    status: u16,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
    credential_expires_at: Option<&str>,
) -> ClaudeOAuthUsageBreaker {
    let mut breaker = previous.unwrap_or_default();
    breaker.schema_version = CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION;
    breaker.account_identifier_hash = account_identifier_hash.to_string();
    breaker.organization_identifier_hash = organization_identifier_hash.to_string();
    breaker.config_fingerprint = config_fingerprint.to_string();
    let key = caller.breaker_key();
    let state = breaker.auth_callers.entry(key.clone()).or_default();
    if claude_oauth_usage_caller_streak_is_stale(state, now)
        || claude_oauth_usage_caller_credential_rotated(state, credential_expires_at)
    {
        *state = ClaudeOAuthUsageCallerAuthState::default();
    }
    state.credential_expires_at = credential_expires_at.map(ToString::to_string);
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    state.last_status = status;
    state.last_failure_at_epoch_seconds = now;
    state.backoff_until_epoch_seconds = now.saturating_add(
        claude_oauth_usage_auth_backoff_seconds(state.consecutive_failures),
    );
    breaker.last_auth_failure = Some(ClaudeOAuthUsageAuthFailureRecord {
        caller: key,
        status,
        at_epoch_seconds: now,
    });
    breaker
}

fn record_claude_oauth_usage_auth_failure(
    caller: &ClaudeOAuthUsageCaller,
    status: u16,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
    credential_expires_at: Option<&str>,
) -> Vec<AgentStatusDiagnostic> {
    let mirror_legacy_default = caller.mirrors_legacy_default();
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        mirror_legacy_default,
    );
    let was_open = previous
        .as_ref()
        .and_then(|breaker| {
            claude_oauth_usage_caller_auth_hold(breaker, caller, now, credential_expires_at)
        })
        .is_some_and(|state| {
            state.consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD
        });
    let breaker = claude_oauth_usage_breaker_after_auth_failure(
        previous,
        caller,
        status,
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        now,
        credential_expires_at,
    );
    let _ = write_claude_oauth_usage_breaker_locked(&breaker);
    if mirror_legacy_default {
        let _ = write_legacy_claude_oauth_usage_breaker(&breaker);
    }
    let state = breaker
        .auth_callers
        .get(&caller.breaker_key())
        .cloned()
        .unwrap_or_default();
    let mut diagnostics = vec![AgentStatusDiagnostic::source(
        "claude_oauth_usage_auth_rejected",
        AgentDiagnosticSeverity::Warning,
        format!(
            "The Claude OAuth usage endpoint rejected the {} credential with HTTP {status} at {}; that credential is not retried until {}.",
            caller.credential_kind(),
            rfc3339_from_unix_seconds(now).unwrap_or_default(),
            rfc3339_from_unix_seconds(state.backoff_until_epoch_seconds).unwrap_or_default(),
        ),
    )
    .with_observed_at(rfc3339_from_unix_seconds(now))];
    if !was_open && state.consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        diagnostics.push(claude_oauth_usage_caller_auth_hold_diagnostic(
            caller, &state, now,
        ));
    }
    diagnostics
}

/// Why this caller made no provider request. Once the caller reached the auth
/// threshold this is the existing circuit-open alert, worded exactly as the
/// account-wide one so every consumer that already reads it keeps working.
fn claude_oauth_usage_caller_auth_hold_diagnostic(
    caller: &ClaudeOAuthUsageCaller,
    state: &ClaudeOAuthUsageCallerAuthState,
    now: u64,
) -> AgentStatusDiagnostic {
    let remaining_minutes = state.backoff_until_epoch_seconds.saturating_sub(now) / 60;
    if state.consecutive_failures >= CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
        return AgentStatusDiagnostic::source(
            "claude_oauth_usage_circuit_open",
            AgentDiagnosticSeverity::Warning,
            format!(
                "Stopped calling the Claude OAuth usage endpoint after auth rejected; quota falls back to Claude Code's local statusLine for the next {remaining_minutes} minute(s)."
            ),
        );
    }
    AgentStatusDiagnostic::source(
        "claude_oauth_usage_auth_backoff",
        AgentDiagnosticSeverity::Info,
        format!(
            "The {} credential was rejected with HTTP {} at {}; it is not retried for the next {remaining_minutes} minute(s).",
            caller.credential_kind(),
            state.last_status,
            rfc3339_from_unix_seconds(state.last_failure_at_epoch_seconds).unwrap_or_default(),
        ),
    )
    .with_observed_at(rfc3339_from_unix_seconds(now))
}

/// A clean answer from `caller`: reset the account-wide counters and this
/// caller's auth streak. Other callers' non-stale streaks are kept, held or
/// not, because this answer was earned by a different credential. With nothing left to keep, the
/// files are removed exactly as before caller attribution.
fn clear_claude_oauth_usage_breaker_after_success(
    caller: &ClaudeOAuthUsageCaller,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    config_fingerprint: &str,
    now: u64,
) {
    let mirror_legacy_default = caller.mirrors_legacy_default();
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = read_claude_oauth_usage_breaker_locked(
        account_identifier_hash,
        organization_identifier_hash,
        config_fingerprint,
        mirror_legacy_default,
    );
    let caller_key = caller.breaker_key();
    // Another caller's streak survives this success, held or not: it ends only
    // on that caller's own success, its credential refresh, or staleness.
    let held_others = previous
        .as_ref()
        .map(|breaker| {
            breaker
                .auth_callers
                .iter()
                .filter(|(key, state)| {
                    **key != caller_key && !claude_oauth_usage_caller_streak_is_stale(state, now)
                })
                .map(|(key, state)| (key.clone(), state.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    if !mirror_legacy_default {
        retire_success_from_legacy_breaker_locked(
            &caller_key,
            account_identifier_hash,
            organization_identifier_hash,
            now,
        );
    }
    if held_others.is_empty() {
        let _ = fs::remove_file(claude_oauth_usage_breaker_path(
            account_identifier_hash,
            organization_identifier_hash,
        ));
        if mirror_legacy_default {
            let _ = fs::remove_file(claude_oauth_usage_legacy_breaker_path());
        }
        return;
    }
    let retained = ClaudeOAuthUsageBreaker {
        schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
        account_identifier_hash: account_identifier_hash.to_string(),
        organization_identifier_hash: organization_identifier_hash.to_string(),
        config_fingerprint: config_fingerprint.to_string(),
        auth_callers: held_others,
        last_auth_failure: previous.and_then(|breaker| breaker.last_auth_failure),
        ..Default::default()
    };
    let _ = write_claude_oauth_usage_breaker_locked(&retained);
    if mirror_legacy_default {
        let _ = write_legacy_claude_oauth_usage_breaker(&retained);
    }
}

/// Apply a non-default caller's success to the legacy root breaker too.
///
/// The default collection mirrors the whole account breaker, other callers'
/// streaks included, into the legacy file, and later migrates that file back
/// whenever the account file is absent. Without this, a slot's success that
/// deleted the account file would be undone by that migration. Only a legacy
/// file for this exact account and organization is touched: the success
/// resets its account-wide counters and this caller's entry, drops stale
/// streaks, and keeps unrelated callers' state. Runs under the account lock,
/// which is the lock the default path holds when it writes this legacy file.
fn retire_success_from_legacy_breaker_locked(
    caller_key: &str,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    now: u64,
) {
    let path = claude_oauth_usage_legacy_breaker_path();
    let Some(previous) = read_claude_oauth_usage_breaker_file_migrating(&path).filter(|breaker| {
        breaker.account_identifier_hash == account_identifier_hash
            && breaker.organization_identifier_hash == organization_identifier_hash
    }) else {
        return;
    };
    let mut retired = ClaudeOAuthUsageBreaker {
        schema_version: previous.schema_version,
        account_identifier_hash: previous.account_identifier_hash.clone(),
        organization_identifier_hash: previous.organization_identifier_hash.clone(),
        config_fingerprint: previous.config_fingerprint.clone(),
        auth_callers: previous.auth_callers.clone(),
        last_auth_failure: previous.last_auth_failure.clone(),
        ..Default::default()
    };
    retired.auth_callers.remove(caller_key);
    retired
        .auth_callers
        .retain(|_, state| !claude_oauth_usage_caller_streak_is_stale(state, now));
    if retired == previous {
        return;
    }
    if retired.holds_no_state() {
        let _ = fs::remove_file(&path);
        return;
    }
    let _ = write_legacy_claude_oauth_usage_breaker(&retired);
}

/// The alert itself. Snapshot diagnostics are uploaded with the agent-status
/// snapshot, so this reaches the backend on the next sync without a separate
/// telemetry channel.
fn claude_oauth_usage_circuit_open_diagnostic(
    breaker: &ClaudeOAuthUsageBreaker,
    now: u64,
) -> AgentStatusDiagnostic {
    let reason = if breaker.opened_by.is_empty() {
        "repeated failures".to_string()
    } else {
        breaker.opened_by.replace('_', " ")
    };
    let remaining_minutes = breaker.reopen_after_epoch_seconds.saturating_sub(now) / 60;
    AgentStatusDiagnostic::source(
        "claude_oauth_usage_circuit_open",
        AgentDiagnosticSeverity::Warning,
        format!(
            "Stopped calling the Claude OAuth usage endpoint after {reason}; quota falls back to Claude Code's local statusLine for the next {remaining_minutes} minute(s)."
        ),
    )
}

/// Which failure class, if any, a transport-level error counts as. `None` means
/// transient: transport errors and server-side 5xx say nothing about whether we
/// should keep calling.
fn claude_oauth_usage_failure_class(error: &ureq::Error) -> Option<ClaudeOAuthUsageFailure> {
    match error {
        ureq::Error::Status(401 | 403, _) => Some(ClaudeOAuthUsageFailure::AuthRejected),
        // The endpoint answering "gone" is a shape change by another name.
        ureq::Error::Status(404 | 410, _) => Some(ClaudeOAuthUsageFailure::ResponseShape),
        _ => None,
    }
}

fn read_claude_oauth_credential_for_slot(
    slot: &ClaudeConfigDirSlot,
) -> Option<ClaudeOAuthCredential> {
    read_claude_oauth_credential_state_for_slot(slot).into_credential()
}

#[cfg(test)]
pub(crate) fn read_claude_oauth_credential_metadata_for_slot(
    slot: &ClaudeConfigDirSlot,
) -> Option<ClaudeOAuthCredentialMetadata> {
    read_claude_oauth_credential_state_for_slot(slot).metadata()
}

/// Read one exact slot's stored Claude login: the keychain item first, then
/// the credentials-file fallback. Only `security` exit 44 (item not found)
/// falls through to the file; every other keychain outcome (no `security`
/// tool on the search path, locked keychain, timeout, spawn failure,
/// unparseable JSON) is `Unreadable`: the login cannot be confirmed either
/// way, never "signed out".
///
/// The item is read with `security find-generic-password -w`, so the secret
/// passes through a pipe into daemon memory. It is parsed here and dropped;
/// only the access token travels on, to the usage request.
fn read_claude_oauth_credential_state_for_slot(slot: &ClaudeConfigDirSlot) -> ClaudeCredentialRead {
    match read_claude_oauth_credential_from_keychain(slot) {
        ClaudeKeychainRead::Found(payload) => parse_claude_oauth_credential_read(&payload),
        ClaudeKeychainRead::NotFound => read_claude_oauth_credential_from_credentials_file(slot),
        ClaudeKeychainRead::Failed => ClaudeCredentialRead::Unreadable,
    }
}

/// Exact-slot login state from one fresh local read. Never spawns `claude`.
pub(crate) fn read_claude_live_login_for_slot(slot: &ClaudeConfigDirSlot) -> ClaudeLiveLogin {
    let read = read_claude_oauth_credential_state_for_slot(slot);
    ClaudeLiveLogin {
        state: claude_local_login_state(&read, OffsetDateTime::now_utc()),
        metadata: read.metadata(),
    }
}

/// The stored credential's modification marker, for the refresher's log: the
/// keychain item's `mdat` attribute (read without `-w`, so no secret is
/// printed), or the credentials file's mtime. Never the item's contents.
pub(crate) fn claude_credential_modified_marker(slot: &ClaudeConfigDirSlot) -> Option<String> {
    if crate::command_env::executable_path("security").is_some() {
        if let Some(account) = effective_user_account_name() {
            let service = slot.service_name();
            let output = run_command_capture(
                "security",
                &["find-generic-password", "-a", &account, "-s", &service],
                COMMAND_TIMEOUT,
            );
            if output.success {
                return output
                    .stdout
                    .lines()
                    .chain(output.stderr.lines())
                    .find(|line| line.trim_start().starts_with("\"mdat\""))
                    .map(|line| line.trim().to_string());
            }
        }
    }
    std::fs::metadata(slot.credentials_path(&home_dir()))
        .and_then(|metadata| metadata.modified())
        .ok()
        .map(|modified| format!("{modified:?}"))
}

/// Spawn-gate view of one exact slot's stored credential: token presence and
/// the raw access deadline only.
pub(crate) fn read_claude_spawn_gate_credential(
    slot: &ClaudeConfigDirSlot,
) -> crate::claude_spawn_gate::ClaudeGateCredential {
    claude_gate_credential(
        &read_claude_oauth_credential_state_for_slot(slot),
        OffsetDateTime::now_utc(),
    )
}

/// The spawn gate's view, derived from the one login classifier
/// ([`claude_local_login_state`]) so the status, the gate and the refresher
/// always agree. A missing or unparseable access deadline, a missing access
/// token or inference scope, or a failed read is `Unreadable` there and
/// `ReadFailed` here: no spawn, no refresh.
fn claude_gate_credential(
    read: &ClaudeCredentialRead,
    now: OffsetDateTime,
) -> crate::claude_spawn_gate::ClaudeGateCredential {
    use crate::claude_spawn_gate::ClaudeGateCredential;
    match claude_local_login_state(read, now) {
        ClaudeLocalLoginState::NotSignedIn => ClaudeGateCredential::Absent,
        ClaudeLocalLoginState::Unreadable => ClaudeGateCredential::ReadFailed,
        // Nothing left to refresh, so nothing a short run could lose.
        ClaudeLocalLoginState::SignedOutByCli | ClaudeLocalLoginState::NeedsLogin => {
            ClaudeGateCredential::Present {
                has_refresh_token: false,
                access_expires_at: None,
            }
        }
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending => {
            ClaudeGateCredential::Present {
                has_refresh_token: true,
                access_expires_at: read.metadata().and_then(|metadata| {
                    OffsetDateTime::parse(metadata.access_expires_at.as_deref()?, &Rfc3339).ok()
                }),
            }
        }
    }
}

enum ClaudeKeychainRead {
    Found(String),
    NotFound,
    Failed,
}

/// `security` exits 44 (`errSecItemNotFound`) when the item does not exist.
const SECURITY_ITEM_NOT_FOUND_EXIT_CODE: i32 = 44;

fn read_claude_oauth_credential_from_keychain(slot: &ClaudeConfigDirSlot) -> ClaudeKeychainRead {
    read_claude_oauth_credential_from_keychain_with_timeout(slot, COMMAND_TIMEOUT)
}

fn read_claude_oauth_credential_from_keychain_with_timeout(
    slot: &ClaudeConfigDirSlot,
    timeout: Duration,
) -> ClaudeKeychainRead {
    if crate::command_env::executable_path("security").is_none() {
        // Without the keychain tool the stored login cannot be confirmed
        // either way: fail closed, never "no login".
        return ClaudeKeychainRead::Failed;
    }
    let Some(account) = effective_user_account_name() else {
        return ClaudeKeychainRead::Failed;
    };
    let Some(arguments) = claude_oauth_keychain_lookup_arguments(slot, &account) else {
        return ClaudeKeychainRead::Failed;
    };
    let argument_refs: Vec<_> = arguments.iter().map(String::as_str).collect();
    let output = run_command_capture("security", &argument_refs, timeout);
    if output.success {
        return ClaudeKeychainRead::Found(output.stdout);
    }
    if output.command_found && output.status_code == Some(SECURITY_ITEM_NOT_FOUND_EXIT_CODE) {
        return ClaudeKeychainRead::NotFound;
    }
    ClaudeKeychainRead::Failed
}

struct EffectiveUserIdentity {
    account_name: String,
    home_dir: PathBuf,
}

fn effective_user_account_name() -> Option<String> {
    effective_user_identity().map(|identity| identity.account_name)
}

#[cfg(unix)]
fn effective_user_identity() -> Option<EffectiveUserIdentity> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    // LaunchAgents are not guaranteed to inherit USER. Resolve the account
    // that owns this daemon from its effective uid instead of trusting ambient
    // environment state when selecting a same-service Keychain item.
    let uid = unsafe { libc::geteuid() };
    let size_hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_size = usize::try_from(size_hint)
        .ok()
        .filter(|size| (1_024..=1_048_576).contains(size))
        .unwrap_or(16_384);

    for _ in 0..3 {
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_size];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_size = buffer_size.checked_mul(2)?.min(1_048_576);
            continue;
        }
        if status != 0 || result.is_null() {
            return None;
        }
        let passwd = unsafe { passwd.assume_init() };
        if passwd.pw_name.is_null() || passwd.pw_dir.is_null() {
            return None;
        }
        let account = unsafe { CStr::from_ptr(passwd.pw_name) }
            .to_str()
            .ok()?
            .to_string();
        let home_dir = PathBuf::from(unsafe { CStr::from_ptr(passwd.pw_dir) }.to_str().ok()?);
        #[cfg(test)]
        let home_dir = std::env::var_os("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS")
            .map(PathBuf::from)
            .unwrap_or(home_dir);
        if account.is_empty() || !home_dir.is_absolute() {
            return None;
        }
        return Some(EffectiveUserIdentity {
            account_name: account,
            home_dir,
        });
    }
    None
}

#[cfg(not(unix))]
fn effective_user_identity() -> Option<EffectiveUserIdentity> {
    let account_name = std::env::var("USER")
        .ok()
        .filter(|account| !account.is_empty() && !account.contains('\0'))?;
    let home_dir = PathBuf::from(std::env::var_os("HOME")?);
    home_dir.is_absolute().then_some(EffectiveUserIdentity {
        account_name,
        home_dir,
    })
}

fn claude_oauth_keychain_lookup_arguments(
    slot: &ClaudeConfigDirSlot,
    account: &str,
) -> Option<Vec<String>> {
    if account.is_empty() || account.contains('\0') {
        return None;
    }
    Some(vec![
        "find-generic-password".to_string(),
        "-a".to_string(),
        account.to_string(),
        "-s".to_string(),
        slot.service_name(),
        "-w".to_string(),
    ])
}

fn read_claude_oauth_credential_from_credentials_file(
    slot: &ClaudeConfigDirSlot,
) -> ClaudeCredentialRead {
    let path = slot.credentials_path(&home_dir());
    match fs::read_to_string(path) {
        Ok(body) => parse_claude_oauth_credential_read(&body),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ClaudeCredentialRead::Absent,
        Err(_) => ClaudeCredentialRead::Unreadable,
    }
}

/// A stored payload that is not JSON, or whose `claudeAiOauth` is not an
/// object, is `Unreadable`. A JSON object without `claudeAiOauth` (for example
/// an item that holds only MCP server logins) carries no Claude login.
fn parse_claude_oauth_credential_read(payload: &str) -> ClaudeCredentialRead {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return ClaudeCredentialRead::Unreadable;
    };
    if !value.is_object() {
        return ClaudeCredentialRead::Unreadable;
    }
    match value.get("claudeAiOauth") {
        None | Some(Value::Null) => ClaudeCredentialRead::Absent,
        Some(oauth) if oauth.is_object() => parse_claude_oauth_credential_value(oauth).map_or(
            ClaudeCredentialRead::Unreadable,
            ClaudeCredentialRead::Present,
        ),
        Some(_) => ClaudeCredentialRead::Unreadable,
    }
}

#[cfg(test)]
fn parse_claude_oauth_access_token(payload: &str) -> Option<String> {
    parse_claude_oauth_credential(payload)?.access_token
}

#[cfg(test)]
fn parse_claude_oauth_credential(payload: &str) -> Option<ClaudeOAuthCredential> {
    let value: Value = serde_json::from_str(payload).ok()?;
    parse_claude_oauth_credential_value(value.get("claudeAiOauth")?)
}

fn parse_claude_oauth_credential_value(oauth: &Value) -> Option<ClaudeOAuthCredential> {
    let access_token = oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToString::to_string);
    let has_refresh_token = oauth
        .get("refreshToken")
        .and_then(Value::as_str)
        .is_some_and(|token| !token.trim().is_empty());
    let timestamp = |field: &str| {
        oauth
            .get(field)
            .and_then(Value::as_i64)
            .and_then(rfc3339_from_epoch_millis)
    };
    let has_inference_scope = oauth.get("scopes").and_then(Value::as_array).map(|scopes| {
        scopes
            .iter()
            .filter_map(Value::as_str)
            .any(|scope| scope.trim() == CLAUDE_INFERENCE_SCOPE)
    });
    let has_profile_scope = oauth
        .get("scopes")
        .and_then(Value::as_array)
        .is_some_and(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .any(|scope| scope.trim() == CLAUDE_PROFILE_SCOPE)
        });
    let subscription_type = oauth
        .get("subscriptionType")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    Some(ClaudeOAuthCredential {
        access_token,
        has_refresh_token,
        access_expires_at: timestamp("expiresAt"),
        relogin_required_at: timestamp("refreshTokenExpiresAt"),
        has_inference_scope,
        has_profile_scope,
        subscription_type,
    })
}

/// The OAuth scope Claude Code requires before it reports a login as signed in.
const CLAUDE_INFERENCE_SCOPE: &str = "user:inference";
/// The OAuth scope Claude Code's `/usage` needs before it reads plan usage.
const CLAUDE_PROFILE_SCOPE: &str = "user:profile";

fn rfc3339_from_epoch_millis(epoch_millis: i64) -> Option<String> {
    let seconds = epoch_millis.div_euclid(1_000);
    let nanos = u32::try_from(epoch_millis.rem_euclid(1_000)).ok()? * 1_000_000;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .replace_nanosecond(nanos)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn claude_oauth_usage_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(401 | 403, _) => {
            "Claude OAuth usage endpoint rejected the local Claude Code session.".to_string()
        }
        ureq::Error::Status(429, _) => "Claude OAuth usage endpoint is rate limited.".to_string(),
        ureq::Error::Status(status, _) => {
            format!("Claude OAuth usage endpoint returned HTTP {status}.")
        }
        ureq::Error::Transport(_) => "Claude OAuth usage endpoint was unreachable.".to_string(),
    }
}

fn claude_oauth_usage_cache_path(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> PathBuf {
    claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash)
        .join(CLAUDE_OAUTH_USAGE_CACHE_FILE)
}

fn claude_oauth_usage_legacy_cache_path() -> PathBuf {
    default_support_dir().join(CLAUDE_OAUTH_USAGE_LEGACY_CACHE_FILE)
}

/// Identify the Claude account that currently owns the local Claude Code
/// credential, as a `billing_identity_hash`. Callers resolve it from
/// `read_claude_cli_oauth_account`; an account-less config yields an empty
/// hash.
///
/// Deliberately NOT a hash of the access token: the token rotates on refresh
/// while the account does not, so a token fingerprint would discard a valid
/// same-account cache on every rotation -- extra fetches against an endpoint
/// that rate-limits, and no cache left to fall back on when it answers 429.
/// `oauthAccount` is rewritten by Claude Code itself on every profile refresh,
/// so it tracks the credential without inheriting its rotation.
#[cfg(test)]
fn claude_oauth_account_identifier_hash_for(account: &ClaudeCliOauthAccount) -> String {
    // Same preference order the subscription grouping uses: provider account
    // id, then organization, then email. It lives in `ottto-core` because the
    // CLI's statusLine writer stamps the same hash and the two must agree
    // exactly -- a divergence would read as "foreign cache" and quota would
    // silently vanish rather than fail loudly.
    claude_account_identifier_hash(
        account.account_uuid.as_deref(),
        account.organization_uuid.as_deref(),
        account.email_address.as_deref(),
    )
}

/// Multi-account collection never assigns full meters through organization or
/// email fallback. Both provider UUIDs must be present and independently
/// hashed before a window or credit can leave the machine.
fn claude_strong_oauth_identity_hashes(
    account: &ClaudeCliOauthAccount,
) -> Option<(String, String)> {
    let account_hash = account
        .account_uuid
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "account", value))?;
    let organization_hash = account
        .organization_uuid
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "organization", value))?;
    Some((account_hash, organization_hash))
}

fn stable_claude_slot_credential(
    initial_oauth_account: Option<ClaudeCliOauthAccount>,
    initial_credential: Option<ClaudeOAuthCredential>,
    final_oauth_account: Option<ClaudeCliOauthAccount>,
) -> Result<StableClaudeSlotCredential, ClaudeSlotProbeFailure> {
    let (Some(initial_oauth_account), Some(final_oauth_account)) =
        (initial_oauth_account, final_oauth_account)
    else {
        return Err(ClaudeSlotProbeFailure::IdentityUnknown);
    };
    if initial_oauth_account != final_oauth_account {
        return Err(ClaudeSlotProbeFailure::ConcurrentMutation);
    }
    Ok(StableClaudeSlotCredential {
        oauth_account: initial_oauth_account,
        credential: initial_credential.unwrap_or(ClaudeOAuthCredential {
            access_token: None,
            has_refresh_token: false,
            access_expires_at: None,
            relogin_required_at: None,
            has_inference_scope: None,
            has_profile_scope: false,
            subscription_type: None,
        }),
    })
}

#[cfg(test)]
fn read_claude_oauth_usage_cache(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> Option<ClaudeOAuthUsageCache> {
    read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        true,
    )
}

fn read_claude_oauth_usage_cache_with_legacy_migration(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    allow_legacy_migration: bool,
) -> Option<ClaudeOAuthUsageCache> {
    let lock =
        claude_oauth_account_state_lock(account_identifier_hash, organization_identifier_hash);
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read_claude_oauth_usage_cache_locked(
        account_identifier_hash,
        organization_identifier_hash,
        allow_legacy_migration,
    )
}

fn read_claude_oauth_usage_cache_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    allow_legacy_migration: bool,
) -> Option<ClaudeOAuthUsageCache> {
    if allow_legacy_migration {
        migrate_legacy_claude_oauth_usage_cache_locked(
            account_identifier_hash,
            organization_identifier_hash,
        );
    }
    let path = claude_oauth_usage_cache_path(account_identifier_hash, organization_identifier_hash);
    let body = fs::read_to_string(path).ok()?;
    let cache: ClaudeOAuthUsageCache = serde_json::from_str(&body).ok()?;
    if cache.schema_version != CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION {
        // Older cache layouts (v1: windows only; v2: no account identity) are
        // discarded so the next tick refetches under a known account.
        return None;
    }
    if !claude_oauth_usage_cache_belongs_to_identity(
        &cache,
        account_identifier_hash,
        organization_identifier_hash,
    ) {
        return None;
    }
    Some(cache)
}

/// Whether a cached OAuth usage payload may be served for the exact account
/// and organization that currently own the credential.
///
/// Exact match, both directions. Account-only matches and caches whose embedded
/// meters are unattributed or differently attributed are rejected. Empty
/// v4 caches may retain per-identity retry timing, but cannot produce a row.
fn claude_oauth_usage_cache_belongs_to_identity(
    cache: &ClaudeOAuthUsageCache,
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> bool {
    cache.account_identifier_hash == account_identifier_hash
        && cache.organization_identifier_hash == organization_identifier_hash
        && !account_identifier_hash.is_empty()
        && !organization_identifier_hash.is_empty()
        && cache.windows.iter().all(|window| {
            window.account_identifier_hash.as_deref() == Some(account_identifier_hash)
                && window.organization_identifier_hash.as_deref()
                    == Some(organization_identifier_hash)
        })
        && cache.credit_balances.iter().all(|balance| {
            balance.account_identifier_hash.as_deref() == Some(account_identifier_hash)
                && balance.organization_identifier_hash.as_deref()
                    == Some(organization_identifier_hash)
        })
}

fn write_claude_oauth_usage_cache(cache: &ClaudeOAuthUsageCache) -> std::io::Result<()> {
    let lock = claude_oauth_account_state_lock(
        &cache.account_identifier_hash,
        &cache.organization_identifier_hash,
    );
    let _transaction = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    write_claude_oauth_usage_cache_locked(cache)
}

fn write_claude_oauth_usage_cache_locked(cache: &ClaudeOAuthUsageCache) -> std::io::Result<()> {
    let path = claude_oauth_usage_cache_path(
        &cache.account_identifier_hash,
        &cache.organization_identifier_hash,
    );
    let body = serde_json::to_vec_pretty(cache).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic(&path, &body)
}

fn write_legacy_claude_oauth_usage_cache(cache: &ClaudeOAuthUsageCache) -> std::io::Result<()> {
    let mut legacy_cache = cache.clone();
    legacy_cache.schema_version = CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION;
    let body = serde_json::to_vec_pretty(&legacy_cache).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic(&claude_oauth_usage_legacy_cache_path(), &body)
}

fn migrate_legacy_claude_oauth_usage_cache_locked(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) {
    let target =
        claude_oauth_usage_cache_path(account_identifier_hash, organization_identifier_hash);
    if target.exists() {
        return;
    }
    let _migration = CLAUDE_OAUTH_LEGACY_MIGRATION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if target.exists() {
        return;
    }
    let legacy = claude_oauth_usage_legacy_cache_path();
    let Some(mut cache) = fs::read_to_string(&legacy)
        .ok()
        .and_then(|body| serde_json::from_str::<ClaudeOAuthUsageCache>(&body).ok())
        .filter(|cache| {
            matches!(
                cache.schema_version,
                CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION
                    | CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION
            ) && !cache.windows.is_empty()
                && claude_oauth_usage_cache_belongs_to_identity(
                    cache,
                    account_identifier_hash,
                    organization_identifier_hash,
                )
        })
    else {
        return;
    };
    cache.schema_version = CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION;
    if write_claude_oauth_usage_cache_locked(&cache).is_ok() {
        let _ = fs::remove_file(legacy);
    }
}

fn claude_oauth_retry_after_epoch_seconds(response: &ureq::Response, now: u64) -> u64 {
    response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS)
        .saturating_add(now)
}

pub(crate) fn ottto_user_agent() -> String {
    // Honest identification: Ottto reads the user's own aggregate usage and
    // says so. Never present a claude-* client identity from an
    // Ottto-originated request (recorded provider-endpoints posture,
    // 2026-07-26). Shared by every Ottto-originated provider read, so one
    // identity change moves them all together.
    // compiled_release_version(), not CARGO_PKG_VERSION: the
    // crate manifest carries the 0.1.0 placeholder and real release versions
    // are injected via OTTTO_RELEASE_VERSION at package time.
    format!(
        "ottto/{} (subscription-usage-reader; +https://ottto.net)",
        compiled_release_version()
    )
}

fn claude_oauth_quota_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    if let Some(window) = claude_oauth_quota_window("session", value.get("five_hour"), 5 * 60 * 60)
    {
        windows.push(window);
    }
    if let Some(window) =
        claude_oauth_quota_window("weekly", value.get("seven_day"), 7 * 24 * 60 * 60)
    {
        windows.push(window);
    }
    windows.extend(claude_oauth_scoped_limit_windows(value));
    windows
}

/// Whether the body says the account has no account-wide weekly limit (some
/// Team plans): `seven_day` is present and null, and `limits[]` lists no
/// account-wide weekly entry. A missing key or a missing `limits[]` proves
/// nothing, so the weekly window stays expected.
fn claude_oauth_account_weekly_not_offered(value: &Value) -> bool {
    let Some(limits) = value.get("limits").and_then(Value::as_array) else {
        return false;
    };
    value.get("seven_day").is_some_and(Value::is_null)
        && !limits.is_empty()
        && !limits.iter().any(|entry| {
            let account_scoped = entry
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .map_or(true, Value::is_null);
            entry.get("kind").and_then(Value::as_str) == Some("weekly_all")
                || account_scoped && entry.get("group").and_then(Value::as_str) == Some("weekly")
        })
}

/// Whether the body says the account has no 5-hour session limit (Max plans
/// since late 2026): `five_hour` is present and null, and `limits[]` lists no
/// account-wide session entry. A missing key or a missing `limits[]` proves
/// nothing, so the session window stays expected.
fn claude_oauth_account_session_not_offered(value: &Value) -> bool {
    let Some(limits) = value.get("limits").and_then(Value::as_array) else {
        return false;
    };
    value.get("five_hour").is_some_and(Value::is_null)
        && !limits.is_empty()
        && !limits.iter().any(|entry| {
            let account_scoped = entry
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .map_or(true, Value::is_null);
            account_scoped
                && (entry.get("kind").and_then(Value::as_str) == Some("session")
                    || entry.get("group").and_then(Value::as_str) == Some("session"))
        })
}

/// Capability a Claude snapshot carries when Claude said the account has no
/// account-wide weekly limit, so completeness checks over the snapshot expect
/// only its session window.
const CLAUDE_ACCOUNT_WEEKLY_NOT_OFFERED_CAPABILITY: &str = "account_weekly_window";

fn claude_account_weekly_not_offered_capability() -> AgentCapabilityGap {
    unsupported_capability(
        CLAUDE_ACCOUNT_WEEKLY_NOT_OFFERED_CAPABILITY,
        "Claude reports no account-wide weekly limit for this account.",
    )
}

fn claude_snapshot_account_weekly_not_offered(snapshot: &AgentStatusSnapshot) -> bool {
    claude_snapshot_capability_unsupported(snapshot, CLAUDE_ACCOUNT_WEEKLY_NOT_OFFERED_CAPABILITY)
}

/// Capability a Claude snapshot carries when Claude said the account has no
/// 5-hour session limit, so completeness checks expect only its weekly window.
const CLAUDE_ACCOUNT_SESSION_NOT_OFFERED_CAPABILITY: &str = "account_session_window";

fn claude_account_session_not_offered_capability() -> AgentCapabilityGap {
    unsupported_capability(
        CLAUDE_ACCOUNT_SESSION_NOT_OFFERED_CAPABILITY,
        "Claude reports no 5-hour session limit for this account.",
    )
}

fn claude_snapshot_account_session_not_offered(snapshot: &AgentStatusSnapshot) -> bool {
    claude_snapshot_capability_unsupported(snapshot, CLAUDE_ACCOUNT_SESSION_NOT_OFFERED_CAPABILITY)
}

fn claude_snapshot_capability_unsupported(snapshot: &AgentStatusSnapshot, name: &str) -> bool {
    snapshot.capabilities.iter().any(|capability| {
        capability.capability == name && capability.status == AgentCapabilityStatus::Unsupported
    })
}

fn claude_snapshot_has_account_windows(snapshot: &AgentStatusSnapshot) -> bool {
    claude_has_account_windows(
        &snapshot.quota_windows,
        claude_snapshot_account_weekly_not_offered(snapshot),
        claude_snapshot_account_session_not_offered(snapshot),
    )
}

fn fresh_quota_windows(windows: &[AgentQuotaWindow]) -> Vec<AgentQuotaWindow> {
    windows
        .iter()
        .filter(|window| window.freshness == AgentQuotaWindowFreshness::Fresh)
        .cloned()
        .collect()
}

/// Every account-wide window the account has: the session and weekly windows,
/// minus any Claude said the account does not have, and at least one of them.
fn claude_has_account_windows(
    windows: &[AgentQuotaWindow],
    account_weekly_not_offered: bool,
    account_session_not_offered: bool,
) -> bool {
    let has = |name: &str| {
        windows
            .iter()
            .any(|window| window.scope == AgentQuotaWindowScope::Account && window.name == name)
    };
    (has("session") || has("weekly"))
        && (account_session_not_offered || has("session"))
        && (account_weekly_not_offered || has("weekly"))
}

/// Per-model scoped limits from the `limits[]` array (e.g. `weekly_scoped`
/// for one model at 98% while the account-level `seven_day` shows 82%).
/// Entries without a model scope duplicate `five_hour`/`seven_day` account
/// windows (`session`, `weekly_all`) and are skipped.
fn claude_oauth_scoped_limit_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    let Some(limits) = value.get("limits").and_then(Value::as_array) else {
        return Vec::new();
    };
    limits
        .iter()
        .filter_map(|entry| {
            let model = entry
                .get("scope")
                .and_then(|scope| scope.get("model"))
                .and_then(|model| {
                    model
                        .get("display_name")
                        .or_else(|| model.get("id"))
                        .and_then(Value::as_str)
                })
                .map(str::trim)
                .filter(|name| !name.is_empty())?;
            let used_percent = json_u8(entry, &["percent"]);
            let resets_at = json_timestamp_rfc3339(entry, &["resets_at", "reset_at"]);
            if used_percent.is_none() && resets_at.is_none() {
                return None;
            }
            let name = entry
                .get("kind")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|kind| !kind.is_empty())
                .unwrap_or("scoped")
                .to_string();
            Some(AgentQuotaWindow {
                name,
                scope: AgentQuotaWindowScope::Model,
                status: used_percent
                    .map(percent_quota_status)
                    .unwrap_or(AgentQuotaWindowStatus::Unknown),
                freshness: AgentQuotaWindowFreshness::Fresh,
                model: Some(model.to_string()),
                resets_at,
                used_percent,
                left_percent: used_percent.map(|used| 100_u8.saturating_sub(used)),
                group: json_trimmed_string(entry, "group"),
                severity: json_trimmed_string(entry, "severity"),
                is_active: entry.get("is_active").and_then(Value::as_bool),
                ..Default::default()
            })
        })
        .collect()
}

/// Usage-credit balances from the OAuth usage response. The newer `spend`
/// object is authoritative; the older `extra_usage` shape is the fallback.
/// Disabled accounts emit nothing (no credit chrome downstream), and a missing
/// or unrecognized shape fails soft to an empty list so quota windows are
/// never hidden by credit parsing.
fn claude_oauth_credit_balances(value: &Value) -> Vec<AgentCreditBalance> {
    claude_oauth_credit_balances_and_refusals(value).0
}

/// The usage-credit balances plus the model's field refusals (a disabled
/// reason that is not a reason code), for the adapter's diagnostics.
fn claude_oauth_credit_balances_and_refusals(
    value: &Value,
) -> (
    Vec<AgentCreditBalance>,
    Vec<crate::quota_credit_model::CreditModelDiagnostic>,
) {
    let mut refusals = Vec::new();
    let balance =
        claude_oauth_spend_credit_balance(value.get("spend"), &mut refusals).or_else(|| {
            claude_oauth_extra_usage_credit_balance(value.get("extra_usage"), &mut refusals)
        });
    (balance.into_iter().collect(), refusals)
}

fn claude_oauth_spend_credit_balance(
    spend: Option<&Value>,
    refusals: &mut Vec<crate::quota_credit_model::CreditModelDiagnostic>,
) -> Option<AgentCreditBalance> {
    let spend = spend?;
    let enabled = spend.get("enabled").and_then(Value::as_bool)?;
    if !enabled {
        return Some(claude_credit_pools::claude_disabled_usage_credits(
            spend, refusals,
        ));
    }
    let used = claude_oauth_money_cents(spend.get("used"));
    let quota = claude_oauth_money_cents(spend.get("cap"))
        .or_else(|| claude_oauth_money_cents(spend.get("limit")));
    let remaining =
        claude_oauth_money_cents(spend.get("balance")).or_else(|| match (quota, used) {
            (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
            _ => None,
        });
    let used_percent = json_u8(spend, &["percent"]).or_else(|| match (used, quota) {
        (Some(used), Some(quota)) if quota > 0 => {
            Some(((used.saturating_mul(100)) / quota).min(100) as u8)
        }
        _ => None,
    });
    let severity = spend.get("severity").and_then(Value::as_str).unwrap_or("");
    Some(AgentCreditBalance {
        name: claude_credit_pools::CLAUDE_USAGE_CREDITS_NAME.to_string(),
        status: if used.is_none() && quota.is_none() && remaining.is_none() {
            AgentCreditBalanceStatus::Unknown
        } else {
            claude_oauth_credit_status(severity, used, quota, remaining)
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining: remaining.and_then(CreditAmount::whole),
        used: used.and_then(CreditAmount::whole),
        quota: quota.and_then(CreditAmount::whole),
        currency: claude_oauth_money_currency(spend.get("used"))
            .or_else(|| json_trimmed_string(spend, "currency")),
        resets_at: json_timestamp_rfc3339(spend, &["resets_at", "reset_at"]),
        used_percent,
        enabled: Some(true),
        ..Default::default()
    })
}

fn claude_oauth_extra_usage_credit_balance(
    extra: Option<&Value>,
    refusals: &mut Vec<crate::quota_credit_model::CreditModelDiagnostic>,
) -> Option<AgentCreditBalance> {
    let extra = extra?;
    let enabled = extra.get("is_enabled").and_then(Value::as_bool)?;
    if !enabled {
        return Some(claude_credit_pools::claude_disabled_usage_credits(
            extra, refusals,
        ));
    }
    // Latent, deliberately untouched: real `extra_usage` bare numbers are minor
    // units (`monthly_limit 1000` beside `spend.limit.amount_minor 1000`,
    // `decimal_places: 2`), so this fallback would read them x100. It is never
    // reached on observed data: every plain body since July 2026 carries
    // `spend`, which wins above.
    let quota = claude_oauth_money_cents(extra.get("monthly_limit"));
    let used = claude_oauth_money_cents(extra.get("used_credits"));
    let remaining = match (quota, used) {
        (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
        _ => None,
    };
    // The client uses an explicitly null monthly_limit for unlimited usage;
    // an omitted or malformed limit remains unknown.
    let unlimited = extra.get("monthly_limit").is_some_and(Value::is_null);
    let used_percent = json_u8(extra, &["utilization"]);
    Some(AgentCreditBalance {
        name: claude_credit_pools::CLAUDE_USAGE_CREDITS_NAME.to_string(),
        status: if unlimited {
            AgentCreditBalanceStatus::Unlimited
        } else {
            claude_oauth_credit_status("", used, quota, remaining)
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining: remaining
            .filter(|_| !unlimited)
            .and_then(CreditAmount::whole),
        used: used.and_then(CreditAmount::whole),
        quota: quota.and_then(CreditAmount::whole),
        currency: json_trimmed_string(extra, "currency"),
        resets_at: None,
        used_percent,
        enabled: Some(true),
        unlimited: unlimited.then_some(true),
        ..Default::default()
    })
}

fn claude_oauth_credit_status(
    severity: &str,
    used: Option<u64>,
    quota: Option<u64>,
    remaining: Option<u64>,
) -> AgentCreditBalanceStatus {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => return AgentCreditBalanceStatus::Exhausted,
        "warning" => return AgentCreditBalanceStatus::Low,
        "normal" => return AgentCreditBalanceStatus::Ok,
        _ => {}
    }
    match (used, quota, remaining) {
        (_, _, Some(0)) => AgentCreditBalanceStatus::Exhausted,
        (Some(used), Some(quota), _) if quota > 0 && used >= quota => {
            AgentCreditBalanceStatus::Exhausted
        }
        (Some(used), Some(quota), _) if quota > 0 && used.saturating_mul(10) >= quota * 9 => {
            AgentCreditBalanceStatus::Low
        }
        (Some(_), _, _) | (_, Some(_), _) => AgentCreditBalanceStatus::Ok,
        _ => AgentCreditBalanceStatus::Unknown,
    }
}

/// Normalize a provider money value to integer minor units (cents).
///
/// Accepts either the structured shape `{"amount_minor": 321, "currency":
/// "USD", "exponent": 2}` (exponent 0..=6) or a bare non-negative number of
/// whole dollars: an integer, or a decimal lexeme kept by the provider decode
/// ([`credit_amount_input::decode`]). Both scale through the one exact scaler,
/// rounding half-even; a float that bypassed that decode is refused.
fn claude_oauth_money_cents(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if let Some(object) = value.as_object() {
        let amount_minor = object.get("amount_minor").and_then(Value::as_u64)?;
        let exponent = object.get("exponent").and_then(Value::as_u64).unwrap_or(2);
        if exponent > 6 {
            return None;
        }
        return ottto_protocol::scale_minor(amount_minor, 2 - exponent as i64);
    }
    credit_amount_input::scaled(value, 2)
}

fn claude_oauth_money_currency(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_object)
        .and_then(|object| object.get("currency"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|currency| !currency.is_empty())
        .map(ToString::to_string)
}

fn json_trimmed_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}

fn claude_oauth_quota_window(
    name: &str,
    value: Option<&Value>,
    window_seconds: u64,
) -> Option<AgentQuotaWindow> {
    let value = value?;
    let used_percent = json_u8(value, &["utilization", "used_percentage", "used_percent"]);
    let resets_at = json_timestamp_rfc3339(value, &["resets_at", "reset_at"]);
    if used_percent.is_none() && resets_at.is_none() {
        return None;
    }
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let started_at = resets_at
        .as_deref()
        .and_then(|reset| rfc3339_minus_seconds(reset, window_seconds));
    Some(AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Account,
        status: used_percent
            .map(percent_quota_status)
            .unwrap_or(AgentQuotaWindowStatus::Unknown),
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds: Some(window_seconds),
        started_at_basis: started_at.as_ref().map(|_| "assumed_duration".to_string()),
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        limit_cents: claude_oauth_money_cents(value.get("limit_dollars")),
        used_cents: claude_oauth_money_cents(value.get("used_dollars")),
        remaining_cents: claude_oauth_money_cents(value.get("remaining_dollars")),
        ..Default::default()
    })
}

fn claude_oauth_usage_from_cache(cache: ClaudeOAuthUsageCache, now: u64) -> ClaudeOAuthUsage {
    let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
    // The refresh slot, seeded from the account the cache belongs to: a
    // payload served as fresh must not be labelled stale. A shorter active
    // slot never labels a reading stale sooner than the default gate.
    let gate = claude_oauth_usage_serve_gate_seconds(
        &cache.account_identifier_hash,
        &cache.organization_identifier_hash,
        now,
    );
    let cache_is_stale = cache_age > gate;
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    ClaudeOAuthUsage {
        windows: cache
            .windows
            .into_iter()
            .map(|mut window| {
                window.observed_at = observed_at.clone();
                if cache_is_stale {
                    window.status = AgentQuotaWindowStatus::Unknown;
                    window.freshness = AgentQuotaWindowFreshness::Stale;
                } else {
                    window.freshness = AgentQuotaWindowFreshness::Fresh;
                }
                window
            })
            .collect(),
        // Each credit section by its own read time: a newer windows or
        // passive read never relabels an older section Fresh.
        credit_balances: {
            let mut credits = cache.credit_balances;
            claude_credit_pools::label_credit_freshness(
                &mut credits,
                gate,
                cache.observed_at_epoch_seconds,
                now,
            );
            credits
        },
        account_weekly_not_offered: cache.account_weekly_not_offered,
        account_session_not_offered: cache.account_session_not_offered,
    }
}

fn claude_statusline_quota_windows_from_cache(
    cache: ClaudeStatusLineRateLimitCache,
    now: u64,
) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
    let cache_is_stale = cache_age > CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS;
    let observed_at = rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds);
    // The v2 cache records which account's credential was active when the CLI
    // writer observed these numbers, and the serve gate above only lets a
    // same-account cache through -- so the stamp is the writer's observation,
    // not a serve-time guess. An empty hash (unidentifiable writer) stays
    // absent rather than inventing an identity.
    let account_identifier_hash = (!cache.observed_under_account_identifier_hash.is_empty())
        .then(|| cache.observed_under_account_identifier_hash.clone());
    for window in cache.windows {
        if window.resets_at_epoch_seconds <= now {
            continue;
        }
        let Some(resets_at) = rfc3339_from_unix_seconds(window.resets_at_epoch_seconds) else {
            continue;
        };
        let (name, window_seconds) = match window.name.as_str() {
            "five_hour" => ("session", Some(5 * 60 * 60)),
            "seven_day" => ("weekly", Some(7 * 24 * 60 * 60)),
            _ => continue,
        };
        windows.push(AgentQuotaWindow {
            name: name.to_string(),
            scope: AgentQuotaWindowScope::Account,
            status: if cache_is_stale {
                AgentQuotaWindowStatus::Stale
            } else {
                percent_quota_status(window.used_percent)
            },
            freshness: if cache_is_stale {
                AgentQuotaWindowFreshness::Stale
            } else {
                AgentQuotaWindowFreshness::Fresh
            },
            observed_at: observed_at.clone(),
            model: None,
            account_label: None,
            account_identifier_hash: account_identifier_hash.clone(),
            organization_identifier_hash: cache.observed_under_organization_identifier_hash.clone(),
            window_seconds,
            started_at: None,
            resets_at: Some(resets_at),
            quota: None,
            remaining: None,
            used_percent: Some(window.used_percent),
            left_percent: Some(100u8.saturating_sub(window.used_percent)),
            ..Default::default()
        });
    }
    windows
}

/// OAuth usage resets carry microseconds; statusLine resets are whole epoch
/// seconds from response headers. Two resets within this tolerance name the
/// same window; distinct Claude windows are hours apart.
const CLAUDE_STATUSLINE_RESET_MATCH_TOLERANCE_SECONDS: i64 = 1;

fn claude_statusline_same_instant(left: OffsetDateTime, right: OffsetDateTime) -> bool {
    (left - right).abs() <= TimeDuration::seconds(CLAUDE_STATUSLINE_RESET_MATCH_TOLERANCE_SECONDS)
}

/// Replace only a percentage-only meter whose clocks, exact binding and reset
/// prove the statusLine reading newer. Money-bearing readings remain intact;
/// unreported OAuth meters remain in the original vector.
fn prefer_newer_exact_claude_statusline_windows(
    oauth_windows: &mut [AgentQuotaWindow],
    statusline_windows: Vec<AgentQuotaWindow>,
) -> bool {
    let mut replaced = false;
    for newer in statusline_windows {
        if newer.used_percent.is_none() && newer.left_percent.is_none() {
            continue;
        }
        let Some(account) = newer
            .account_identifier_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
        else {
            continue;
        };
        let Some(organization) = newer
            .organization_identifier_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
        else {
            continue;
        };
        let Some(new_time) = newer
            .observed_at
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        else {
            continue;
        };
        if new_time.unix_timestamp() > current_unix_seconds() as i64 + 60 {
            continue;
        }
        for older in oauth_windows.iter_mut() {
            if older.account_identifier_hash.as_deref() != Some(account)
                || older.organization_identifier_hash.as_deref() != Some(organization)
                || older.name != newer.name
                || older.scope != newer.scope
                || older.window_seconds != newer.window_seconds
                || older.model != newer.model
                || older.group != newer.group
                || older.limit_id != newer.limit_id
            {
                continue;
            }
            // A statusLine percentage cannot represent independently dated
            // OAuth dollars/totals. Retain the whole reading rather than erase
            // coverage or copy old monetary evidence onto a newer clock.
            if older.limit_cents.is_some()
                || older.used_cents.is_some()
                || older.remaining_cents.is_some()
                || older.quota.is_some()
                || older.remaining.is_some()
            {
                continue;
            }
            let Some(old_reset) = older
                .resets_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            else {
                continue;
            };
            let Some(new_reset) = newer
                .resets_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            else {
                continue;
            };
            // Preserve same-reset tolerance. A later cycle wins only after the
            // old one ended, with a nominal start containing the new reading.
            // All account/org/meter and money gates above still apply.
            let same_cycle = claude_statusline_same_instant(old_reset, new_reset);
            let rolled_over = !same_cycle
                && new_reset > old_reset
                && old_reset <= new_time
                && newer
                    .window_seconds
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .filter(|seconds| *seconds > 0)
                    .is_some_and(|seconds| new_reset - TimeDuration::seconds(seconds) <= new_time);
            if (!same_cycle && !rolled_over) || new_reset <= new_time {
                continue;
            }
            // A start is a period boundary, not a reading clock. It can survive
            // only when the same verified reset/duration derives that boundary.
            if let Some(start) = older.started_at.as_deref().filter(|_| same_cycle) {
                let start = OffsetDateTime::parse(start, &Rfc3339).ok();
                let derived = newer
                    .window_seconds
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .map(|seconds| new_reset - TimeDuration::seconds(seconds));
                match (start, derived) {
                    (Some(start), Some(derived))
                        if claude_statusline_same_instant(start, derived) => {}
                    _ => continue,
                }
            }
            let Some(old_time) = older
                .observed_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            else {
                continue;
            };
            if new_time > old_time {
                let mut selected = newer.clone();
                if same_cycle {
                    selected.started_at = older.started_at.clone().or(selected.started_at);
                    selected.started_at_basis =
                        older.started_at_basis.clone().or(selected.started_at_basis);
                } else {
                    selected.started_at = newer.window_seconds.and_then(|seconds| {
                        rfc3339_minus_seconds(newer.resets_at.as_deref()?, seconds)
                    });
                    selected.started_at_basis = selected
                        .started_at
                        .as_ref()
                        .map(|_| "assumed_duration".to_string());
                }
                *older = selected;
                replaced = true;
            }
        }
    }
    replaced
}

fn claude_statusline_context_from_cache(
    cache: ClaudeStatusLineContextWindowCache,
    history: Option<ClaudeStatusLineContextWindowHistory>,
) -> AgentContextStatus {
    let zero_sentinel = claude_statusline_context_is_zero_sentinel(
        cache.active_tokens,
        cache.max_tokens,
        cache.used_percent,
        cache.remaining_tokens,
    );
    let active_tokens = if zero_sentinel {
        None
    } else {
        cache.active_tokens
    };
    let remaining_tokens = if zero_sentinel {
        None
    } else {
        cache.remaining_tokens
    };
    let has_pressure =
        active_tokens.is_some() || cache.used_percent.is_some() || remaining_tokens.is_some();
    let (status, completeness, reason) = if has_pressure {
        (
            AgentContextState::Available,
            AgentContextCompleteness::FullPressure,
            "full_pressure_observed",
        )
    } else if cache.max_tokens.is_some() {
        (
            AgentContextState::Available,
            AgentContextCompleteness::WindowSizeOnly,
            "context_window_size_only",
        )
    } else {
        (
            AgentContextState::Unsupported,
            AgentContextCompleteness::Unavailable,
            "statusline_context_empty",
        )
    };
    AgentContextStatus {
        status,
        active_tokens,
        max_tokens: cache.max_tokens,
        used_percent: cache.used_percent,
        remaining_tokens,
        source: Some("claude_statusline_context_window".to_string()),
        recent_samples: claude_statusline_recent_context_samples(&cache, history),
        observed_at: rfc3339_from_unix_seconds(cache.observed_at_epoch_seconds),
        completeness: Some(completeness),
        reason: Some(reason.to_string()),
        posture: None,
    }
}

fn claude_statusline_recent_context_samples(
    cache: &ClaudeStatusLineContextWindowCache,
    history: Option<ClaudeStatusLineContextWindowHistory>,
) -> Vec<AgentContextPressureSample> {
    let now = current_unix_seconds();
    let mut samples = history.map(|history| history.samples).unwrap_or_default();
    samples.push(ClaudeStatusLineContextWindowSample {
        observed_at_epoch_seconds: cache.observed_at_epoch_seconds,
        active_tokens: cache.active_tokens,
        max_tokens: cache.max_tokens,
        used_percent: cache.used_percent,
        remaining_tokens: cache.remaining_tokens,
    });
    samples.retain(|sample| {
        sample.observed_at_epoch_seconds <= now.saturating_add(60)
            && now.saturating_sub(sample.observed_at_epoch_seconds)
                <= CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS
            && !claude_statusline_context_is_zero_sentinel(
                sample.active_tokens,
                sample.max_tokens,
                sample.used_percent,
                sample.remaining_tokens,
            )
            && (sample.active_tokens.is_some()
                || sample.used_percent.is_some()
                || sample.remaining_tokens.is_some())
    });
    samples.sort_by_key(|sample| sample.observed_at_epoch_seconds);
    samples.dedup_by_key(|sample| sample.observed_at_epoch_seconds);
    if samples.len() > CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES {
        let remove_count = samples.len() - CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES;
        samples.drain(0..remove_count);
    }
    samples
        .into_iter()
        .filter_map(|sample| {
            Some(AgentContextPressureSample {
                at: rfc3339_from_unix_seconds(sample.observed_at_epoch_seconds)?,
                active_tokens: sample.active_tokens,
                max_tokens: sample.max_tokens,
                used_percent: sample.used_percent,
                remaining_tokens: sample.remaining_tokens,
            })
        })
        .collect()
}

fn claude_statusline_context_is_zero_sentinel(
    active_tokens: Option<u64>,
    max_tokens: Option<u64>,
    used_percent: Option<u8>,
    remaining_tokens: Option<u64>,
) -> bool {
    let remaining_is_unreported = match (max_tokens, remaining_tokens) {
        (Some(_), None) => true,
        (Some(max), Some(remaining)) => remaining == max,
        _ => false,
    };
    used_percent.is_none() && matches!(active_tokens, None | Some(0)) && remaining_is_unreported
}

fn claude_statusline_context_unavailable(
    reason: &str,
    observed_at: Option<String>,
) -> AgentContextStatus {
    unsupported_context("claude_statusline_context_window", reason, observed_at)
}

fn current_unix_seconds() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}

fn rfc3339_from_unix_seconds(seconds: u64) -> Option<String> {
    let timestamp = i64::try_from(seconds).ok()?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn percent_quota_status(used_percent: u8) -> AgentQuotaWindowStatus {
    if used_percent >= 100 {
        AgentQuotaWindowStatus::Exhausted
    } else if used_percent >= 90 {
        AgentQuotaWindowStatus::NearLimit
    } else {
        AgentQuotaWindowStatus::Ok
    }
}

fn collect_pi_status(captured_at: String, expires_at: String) -> AgentStatusSnapshot {
    if !crate::agent_configs::detection::source_present_locally(&SourceKind::Pi) {
        return not_installed_snapshot(SourceKind::Pi, "pi", captured_at, expires_at);
    }
    let mut snapshot = base_snapshot(
        SourceKind::Pi,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unknown,
        provider: None,
        email: read_pi_safe_auth_metadata()
            .and_then(|metadata| first_json_string(&metadata, &["email"])),
        confidence: AgentStatusConfidence::Low,
        ..unsupported_account("")
    });
    let settings = read_pi_agent_settings();
    let auth = read_pi_agent_auth();
    let list_models = if settings.is_none() {
        Some(run_command_capture(
            "pi",
            &["--list-models"],
            COMMAND_TIMEOUT,
        ))
    } else {
        None
    };
    snapshot.model = Some(collect_pi_model_status(
        settings.as_ref(),
        list_models.as_ref(),
        auth.as_ref(),
    ));
    if settings.is_some() {
        snapshot.collection_method = AgentStatusCollectionMethod::ConfigFile;
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "pi_agent_settings_detected",
            AgentDiagnosticSeverity::Info,
            "Pi model route read from Pi's agent settings.json.",
        ));
    }
    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
    snapshot.context = Some(unsupported_context(
        "pi_cli_v1",
        "pi_active_context_not_collected",
        None,
    ));
    snapshot.capabilities = vec![
        supported_capability(
            "model_list",
            "Collected from Pi's agent settings.json enabledModels, falling back to pi --list-models.",
        ),
        unsupported_capability(
            "account_plan",
            "Pi does not publish display-safe plan metadata in v1.",
        ),
        unsupported_capability(
            "quota_windows",
            "Pi does not publish display-safe quota-window metadata in v1.",
        ),
        unsupported_capability(
            "active_context",
            "Pi does not publish active context metadata in v1.",
        ),
    ];
    append_pi_route_plan_observations(&mut snapshot);
    append_current_plan_observation(&mut snapshot);
    snapshot
}

fn append_current_plan_observation(snapshot: &mut AgentStatusSnapshot) {
    let Some(account) = snapshot.account.as_ref() else {
        return;
    };
    let is_current = account.login_state == AgentLoginState::SignedIn
        && matches!(
            account.confidence,
            AgentStatusConfidence::High | AgentStatusConfidence::Medium
        );
    let Some(observation) = plan_observation_from_snapshot_account(snapshot, is_current) else {
        return;
    };
    snapshot.plan_observations.push(observation);
}

/// Describe `snapshot`'s own account as a plan observation, stamped with that
/// snapshot's provenance (capture time, collection method, model provider).
fn plan_observation_from_snapshot_account(
    snapshot: &AgentStatusSnapshot,
    is_current: bool,
) -> Option<AgentStatusPlanObservation> {
    let account = snapshot.account.as_ref()?;
    if account.subscription_product.is_none()
        && account.plan_type.is_none()
        && account.account_id.is_none()
        && account.account_identifier_hash.is_none()
        && account.organization_identifier_hash.is_none()
        && account.credential_fingerprint_hash.is_none()
        && account.email.is_none()
        && account.organization_id.is_none()
        && account.organization_label.is_none()
    {
        return None;
    }
    Some(AgentStatusPlanObservation {
        desktop_recent_at: None,
        observed_at: Some(snapshot.captured_at.clone()),
        evidence_method: Some(collection_method_key(&snapshot.collection_method).to_string()),
        source_session_id: None,
        provider: account.provider.clone(),
        billing_provider: account.provider.clone(),
        model_provider: snapshot
            .model
            .as_ref()
            .and_then(|model| model.provider.clone()),
        billing_channel: account.billing_channel.clone(),
        auth_mode: account.auth_method.clone(),
        gateway_provider: None,
        subscription_product: account.subscription_product.clone(),
        plan_type: account.plan_type.clone(),
        account_label: account.email.clone(),
        account_id: account.account_id.clone(),
        organization_label: account.organization_label.clone(),
        organization_id: account.organization_id.clone(),
        account_identifier_hash: account.account_identifier_hash.clone(),
        organization_identifier_hash: account.organization_identifier_hash.clone(),
        superseded_account_identifier_hash: account.superseded_account_identifier_hash.clone(),
        superseded_organization_identifier_hash: account
            .superseded_organization_identifier_hash
            .clone(),
        credential_fingerprint_hash: account.credential_fingerprint_hash.clone(),
        billing_identity_evidence: account.billing_identity_evidence.clone(),
        billing_identity_confidence: account.billing_identity_confidence.clone(),
        confidence: account.confidence.clone(),
        is_current: Some(is_current),
    })
}

/// Most Claude accounts worth describing in one source-health snapshot. Slot
/// capacity is already bounded well below this; the cap only keeps a corrupt
/// registry from growing the payload without limit.
const CLAUDE_PLAN_OBSERVATION_ACCOUNT_LIMIT: usize = 20;

/// Carry every collected Claude account's product into the source-health
/// snapshot.
///
/// That snapshot is the default slot's, so on its own it names the product of
/// exactly one account: whichever one the CLI is signed into now. Each
/// registered slot collects its own account, and only that slot's snapshot
/// knows its product. Without this the app still lists the other accounts — a
/// Claude Desktop session bucket supplies the email — but has no product to
/// title them with, so they read as a bare email or as the source's own name
/// ("Claude Code") instead of "Claude Max 20x".
///
/// Only the product observation is added here. Identity, meters and health for
/// those accounts keep flowing through the Claude accounts control surface,
/// which owns them.
fn append_registered_claude_plan_observations(
    source_health_snapshot: &mut AgentStatusSnapshot,
    snapshots: &[AgentStatusSnapshot],
) {
    let current_identity = source_health_snapshot
        .account
        .as_ref()
        .and_then(claude_plan_identity_from_account);
    let mut described = source_health_snapshot
        .plan_observations
        .iter()
        .filter(|observation| {
            observation.subscription_product.is_some() || observation.plan_type.is_some()
        })
        .filter_map(claude_plan_identity_from_observation)
        .collect::<BTreeSet<_>>();
    for snapshot in snapshots.iter().take(CLAUDE_PLAN_OBSERVATION_ACCOUNT_LIMIT) {
        let Some(account) = snapshot.account.as_ref() else {
            continue;
        };
        if account.subscription_product.is_none() && account.plan_type.is_none() {
            continue;
        }
        let Some(identity) = claude_plan_identity_from_account(account) else {
            continue;
        };
        if !described.insert(identity.clone()) {
            continue;
        }
        let is_current = current_identity.as_ref() == Some(&identity);
        if let Some(observation) = plan_observation_from_snapshot_account(snapshot, is_current) {
            source_health_snapshot.plan_observations.push(observation);
        }
    }
}

/// The account+organization pair an observation describes. Both halves are
/// required: an account hash alone cannot tell two organizations of the same
/// login apart, which is exactly what a Team seat alongside a personal
/// organization produces.
fn claude_plan_identity_from_observation(
    observation: &AgentStatusPlanObservation,
) -> Option<(String, String)> {
    claude_plan_identity(
        observation.account_identifier_hash.as_deref(),
        observation.organization_identifier_hash.as_deref(),
    )
}

fn claude_plan_identity_from_account(account: &AgentAccountStatus) -> Option<(String, String)> {
    claude_plan_identity(
        account.account_identifier_hash.as_deref(),
        account.organization_identifier_hash.as_deref(),
    )
}

fn claude_plan_identity(
    account_identifier_hash: Option<&str>,
    organization_identifier_hash: Option<&str>,
) -> Option<(String, String)> {
    let account = account_identifier_hash.filter(|hash| !hash.is_empty())?;
    let organization = organization_identifier_hash.filter(|hash| !hash.is_empty())?;
    Some((account.to_string(), organization.to_string()))
}

fn append_pi_route_plan_observations(snapshot: &mut AgentStatusSnapshot) {
    let Some(model) = &snapshot.model else {
        return;
    };
    let observed_at = snapshot.captured_at.clone();
    for detail in model.available_model_details.iter().take(20) {
        if detail.subscription_product.is_none()
            && detail.account_identifier_hash.is_none()
            && detail.organization_identifier_hash.is_none()
            && detail.credential_fingerprint_hash.is_none()
        {
            continue;
        }
        snapshot.plan_observations.push(AgentStatusPlanObservation {
            desktop_recent_at: None,
            observed_at: Some(observed_at.clone()),
            evidence_method: Some("pi_route_metadata".to_string()),
            source_session_id: None,
            provider: detail.provider.clone(),
            billing_provider: detail.billing_provider.clone(),
            model_provider: detail.model_provider.clone(),
            billing_channel: detail.billing_channel.clone(),
            auth_mode: detail.auth_mode.clone(),
            gateway_provider: detail.gateway_provider.clone(),
            subscription_product: detail.subscription_product.clone(),
            plan_type: None,
            account_label: None,
            account_id: None,
            organization_label: None,
            organization_id: None,
            account_identifier_hash: detail.account_identifier_hash.clone(),
            organization_identifier_hash: detail.organization_identifier_hash.clone(),
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: detail.credential_fingerprint_hash.clone(),
            billing_identity_evidence: detail.billing_identity_evidence.clone(),
            billing_identity_confidence: detail.billing_identity_confidence.clone(),
            confidence: if detail.billing_identity_confidence == AgentStatusConfidence::Unknown {
                AgentStatusConfidence::Low
            } else {
                detail.billing_identity_confidence.clone()
            },
            is_current: Some(true),
        });
    }
}

fn append_codex_workspace_observations_at(
    snapshot: &mut AgentStatusSnapshot,
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Vec<CodexWorkspaceTargetEvidence> {
    let credentials = match read_codex_auth_credentials_at(codex_home, home_trust) {
        Ok(Some(credentials)) => credentials,
        Ok(None) => return Vec::new(),
        Err(_) => {
            append_codex_credential_read_failed_diagnostic(snapshot);
            return Vec::new();
        }
    };
    let Some(token) = credentials.id_token.as_deref() else {
        return Vec::new();
    };
    // Only workspace TARGETS come out of the ID token. The token's
    // `organizations[]` claim lists platform.openai.com organizations, which
    // govern API keys; ChatGPT/Codex subscriptions live in chatgpt.com
    // workspaces keyed by `chatgpt_account_id`, and the two id spaces differ
    // even where the names match. A platform organization therefore cannot
    // witness a subscription, so it no longer contributes a plan observation:
    // one carrying a plan name used to be uploaded as
    // `billing_channel: "subscription"` with no account identifier at all,
    // which the backend materialized into its own priced subscription row keyed
    // on the account label -- a plan the operator does not pay for, added to the
    // monthly total. The signed-in workspace's real plan still arrives through
    // the app-server probe, which reads the subscription rather than inferring
    // it.
    codex_workspace_target_evidence_from_id_token(token, &snapshot.captured_at).unwrap_or_default()
}

fn collection_method_key(method: &AgentStatusCollectionMethod) -> &'static str {
    match method {
        AgentStatusCollectionMethod::AppServer => "app_server",
        AgentStatusCollectionMethod::CliJson => "cli_json",
        AgentStatusCollectionMethod::CliText => "cli_text",
        AgentStatusCollectionMethod::ConfigFile => "config_file",
        AgentStatusCollectionMethod::StatusLine => "status_line",
        AgentStatusCollectionMethod::CommandProbe => "command_probe",
        AgentStatusCollectionMethod::ManualFallback => "manual_fallback",
        AgentStatusCollectionMethod::Unsupported => "unsupported",
    }
}

fn billing_identity_evidence_for(
    account_hash: &Option<String>,
    organization_hash: &Option<String>,
    credential_hash: &Option<String>,
) -> Option<String> {
    if credential_hash.is_some() {
        Some("credential_fingerprint".to_string())
    } else if account_hash.is_some() {
        Some("provider_account_id".to_string())
    } else if organization_hash.is_some() {
        Some("organization_identifier".to_string())
    } else {
        None
    }
}

fn base_snapshot(
    source: SourceKind,
    status: AgentStatusState,
    collection_method: AgentStatusCollectionMethod,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    AgentStatusSnapshot {
        source,
        status,
        collection_method,
        captured_at,
        expires_at,
        account: None,
        model: None,
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
        context: None,
        capabilities: Vec::new(),
        plan_observations: Vec::new(),
        diagnostics: Vec::new(),
        runtime_defaults: None,
    }
}

fn not_installed_snapshot(
    source: SourceKind,
    binary: &str,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    let mut snapshot = base_snapshot(
        source,
        AgentStatusState::NotInstalled,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unsupported,
        provider: None,
        confidence: AgentStatusConfidence::High,
        ..unsupported_account("")
    });
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        "agent_cli_not_found",
        AgentDiagnosticSeverity::Warning,
        format!("{binary} was not found on PATH or in known local metadata."),
    ));
    snapshot
}

fn parse_codex_account_text(text: &str) -> Option<AgentAccountStatus> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("not logged in")
        || lower.contains("not signed in")
        || lower.contains("logged out")
        || lower.contains("sign in")
    {
        return Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedOut,
            provider: Some("openai".to_string()),
            auth_method: Some("oauth".to_string()),
            confidence: AgentStatusConfidence::Medium,
            ..unsupported_account("openai")
        });
    }
    let email = extract_email(text);
    let plan_type = extract_plan_type(text, &["plus", "pro", "team", "enterprise", "free"]);
    if email.is_none()
        && plan_type.is_none()
        && !lower.contains("logged in")
        && !lower.contains("signed in")
    {
        return None;
    }
    Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(|plan| format!("chatgpt_{plan}")),
        billing_channel: Some("subscription".to_string()),
        confidence: AgentStatusConfidence::Medium,
        ..unsupported_account("openai")
    })
}

fn read_codex_auth_account_at(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<Option<AgentAccountStatus>, CodexCredentialReadError> {
    let Some(credentials) = read_codex_auth_credentials_at(codex_home, home_trust)? else {
        return Ok(None);
    };
    let Some(token) = credentials.id_token.as_deref() else {
        return Ok(None);
    };
    Ok(parse_codex_id_token_account(token))
}

fn read_codex_auth_credentials_at(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<Option<CodexAuthCredentials>, CodexCredentialReadError> {
    let Some(body) = ottto_core::read_codex_auth_file_secure(codex_home, home_trust)
        .map_err(|_| CodexCredentialReadError)?
    else {
        return Ok(None);
    };
    let json: Value = serde_json::from_slice(&body).map_err(|_| CodexCredentialReadError)?;
    let access_token = json
        .get("tokens")
        .and_then(|tokens| tokens.get("access_token"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let id_token = json
        .get("tokens")
        .and_then(|tokens| tokens.get("id_token"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let account_id = first_json_string(&json, &["account_id", "chatgpt_account_id"])
        .or_else(|| {
            json.get("tokens")
                .and_then(|tokens| first_json_string(tokens, &["account_id", "chatgpt_account_id"]))
        })
        .or_else(|| id_token.as_deref().and_then(codex_account_id_from_id_token));
    if access_token.is_none() && id_token.is_none() {
        return Ok(None);
    }
    Ok(Some(CodexAuthCredentials {
        access_token,
        id_token,
        account_id,
    }))
}

fn codex_account_id_from_id_token(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id", "chatgpt_user_id"]))
        .or_else(|| first_json_string(&claims, &["chatgpt_account_id", "chatgpt_user_id"]))
}

fn parse_codex_id_token_account(token: &str) -> Option<AgentAccountStatus> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    let plan_type = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_plan_type"]))
        .map(normalize_plan_type)
        .filter(|value| !value.is_empty());
    // `chatgpt_user_id` is the stable user. `chatgpt_account_id` is the
    // currently selected ChatGPT workspace/account and is the value Codex's
    // supported `forced_chatgpt_workspace_id` restriction consumes. Treating
    // the latter as the user collapses two workspaces into two fake users.
    let account_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
        .or_else(|| first_json_string(&claims, &["sub"]));
    let workspace_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id"]))
        .or_else(|| first_json_string(&claims, &["chatgpt_account_id"]));
    let email = first_json_string(&claims, &["email"]);
    // The same claim object that carries `chatgpt_plan_type` also carries the
    // real subscription period and the time that period evidence was checked.
    // Read them here rather than deriving anything: the backend contract is
    // "reported or absent".
    let subscription_period_start = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_active_start")
    });
    let subscription_period_end = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_active_until")
    });
    let subscription_period_last_checked_at = auth_claim.and_then(|value| {
        subscription_period_timestamp(value, "chatgpt_subscription_last_checked")
    });
    // Deliberately unchanged: a period with no plan, account, email, or
    // organization is not a useful account row, so it does not by itself
    // resurrect one.
    if plan_type.is_none() && account_id.is_none() && email.is_none() && workspace_id.is_none() {
        return None;
    }
    Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email,
        account_id,
        organization_id: workspace_id,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(chatgpt_subscription_product),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start,
        subscription_period_end,
        subscription_period_last_checked_at,
        billing_identity_confidence: AgentStatusConfidence::Low,
        confidence: AgentStatusConfidence::Low,
        ..unsupported_account("openai")
    })
}

/// The user and workspace ids a local Codex credential claims: the access
/// token's, agreeing with the stored account id and, when present, the id
/// token. Decoding a JWT never authenticates it; this names what the
/// credential says, nothing more.
fn codex_credential_claimed_ids(credentials: &CodexAuthCredentials) -> Option<(String, String)> {
    let ids = codex_jwt_claimed_ids(&structurally_valid_live_codex_jwt_claims(
        credentials.access_token.as_deref()?,
    )?)?;
    if credentials.account_id.as_deref() != Some(ids.1.as_str()) {
        return None;
    }
    if let Some(id_token) = credentials.id_token.as_deref() {
        if codex_jwt_claimed_ids(&structurally_valid_live_codex_jwt_claims(id_token)?)? != ids {
            return None;
        }
    }
    Some(ids)
}

/// The user and workspace ids a decoded Codex JWT names: the auth claim's
/// user id (else `sub`) and its workspace (ChatGPT account) id.
pub(crate) fn codex_jwt_claimed_ids(claims: &Value) -> Option<(String, String)> {
    let auth_claim = claims.get("https://api.openai.com/auth");
    let account_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
        .or_else(|| first_json_string(claims, &["sub"]))?;
    let workspace_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id"]))
        .or_else(|| first_json_string(claims, &["chatgpt_account_id"]))?;
    Some((account_id, workspace_id))
}

/// When the binding a credential claims ([`codex_credential_claimed_binding`])
/// lapses: the earliest expiry of the tokens it is checked against. `None`
/// when a token's expiry cannot be read.
fn codex_credential_claim_lapses_at(credentials: &CodexAuthCredentials) -> Option<u64> {
    [
        credentials.access_token.as_deref(),
        credentials.id_token.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(|token| {
        structurally_valid_live_codex_jwt_claims(token)?
            .get("exp")?
            .as_i64()
            .and_then(|expires_at| u64::try_from(expires_at).ok())
    })
    .try_fold(u64::MAX, |earliest, expires_at| {
        Some(earliest.min(expires_at?))
    })
    .filter(|earliest| *earliest != u64::MAX)
}

/// The account identifier hash the credential claims (not validated), for
/// the provider-call log.
fn codex_credential_claimed_account_hash(credentials: &CodexAuthCredentials) -> Option<String> {
    let (account_id, _) = codex_credential_claimed_ids(credentials)?;
    billing_identity_hash("openai", "account", &account_id)
}

/// The account identifier hash a home's credential claims, for the
/// provider-call log. `None` when it names none or cannot be read (and, in
/// unit tests, for any home outside the scratch dir).
pub(crate) fn codex_home_claimed_account_hash(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Option<String> {
    if !crate::provider_calls::readable_for_account(codex_home) {
        return None;
    }
    let credentials = read_codex_auth_credentials_at(codex_home, home_trust).ok()??;
    codex_credential_claimed_account_hash(&credentials)
}

/// The account the default Codex home's credential claims, for the
/// provider-call log of reads that use `~/.codex` itself.
pub(crate) fn default_codex_home_claimed_account_hash() -> Option<String> {
    codex_home_claimed_account_hash(&default_codex_home(), CodexHomeTrust::ProviderDefault)
}

/// The account a Codex CLI run started with the daemon's environment signs
/// in as (its `CODEX_HOME`, else `~/.codex`), for the provider-call log.
pub(crate) fn codex_cli_home_claimed_account_hash() -> Option<String> {
    let home = std::env::var_os("CODEX_HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from);
    match home {
        Some(home) => codex_home_claimed_account_hash(&home, CodexHomeTrust::ProviderDefault),
        None => default_codex_home_claimed_account_hash(),
    }
}

/// The user a Codex access token claims (not validated), hashed like
/// [`codex_credential_claimed_account_hash`], for the provider-call log of a
/// request made with exactly that token.
pub(crate) fn codex_access_token_claimed_account_hash(access_token: &str) -> Option<String> {
    let claims = structurally_valid_live_codex_jwt_claims(access_token)?;
    let account_id = claims
        .get("https://api.openai.com/auth")
        .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
        .or_else(|| first_json_string(&claims, &["sub"]))?;
    billing_identity_hash("openai", "account", &account_id)
}

/// The binding key ([`codex_credit_grants::binding_key`]) a local Codex
/// credential claims. Only a key to compare with an earlier provider-validated
/// binding; it is never an identity and grants no authority.
fn codex_credential_claimed_binding(credentials: &CodexAuthCredentials) -> Option<String> {
    let (account_id, raw_workspace_id) = codex_credential_claimed_ids(credentials)?;
    Some(codex_credit_grants::binding_key(
        &billing_identity_hash("openai", "account", &account_id)?,
        &billing_identity_hash("openai", "workspace", &raw_workspace_id)?,
    ))
}

fn validated_codex_identity(
    credentials: &CodexAuthCredentials,
    provider_account: Option<&Value>,
    rate_limits: Option<&Value>,
    provider_authenticated_active_credential: bool,
) -> Option<CodexStrongIdentity> {
    // Decoding a JWT never authenticates it. This flag is supplied only after
    // the provider has successfully used the active access token for the same
    // quota response. App-server does that after account/read refreshes the
    // credential; the default-only legacy fallback does it when the provider
    // accepts the access token and workspace header for its quota response.
    if !provider_authenticated_active_credential {
        return None;
    }
    let (account_id, raw_workspace_id) = codex_credential_claimed_ids(credentials)?;
    let claims = structurally_valid_live_codex_jwt_claims(credentials.access_token.as_deref()?)?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    if let Some(provider_account) = provider_account {
        let active = provider_account.get("account")?;
        if active.get("type").and_then(Value::as_str) != Some("chatgpt") {
            return None;
        }
        let claim_email = codex_access_token_email(&claims)?;
        let active_email = first_json_string(active, &["email"])?;
        if claim_email != active_email {
            return None;
        }
        let claim_plan = auth_claim
            .and_then(|value| first_json_string(value, &["chatgpt_plan_type"]))
            .map(normalize_plan_type)?;
        let active_plan =
            first_json_string(active, &["planType", "plan_type"]).map(normalize_plan_type)?;
        if claim_plan != active_plan {
            return None;
        }
        if rate_limits
            .into_iter()
            .flat_map(codex_app_server_rate_limit_snapshots)
            .filter_map(|(_, snapshot)| first_json_string(snapshot, &["planType", "plan_type"]))
            .map(normalize_plan_type)
            .any(|plan| plan != active_plan)
        {
            return None;
        }
    }
    let superseded_account_identifier_hash =
        billing_identity_hash("openai", "account", &raw_workspace_id);
    let superseded_organization_identifier_hash = credentials
        .id_token
        .as_deref()
        .and_then(structurally_valid_live_codex_jwt_claims)
        .as_ref()
        .and_then(|id_claims| id_claims.get("https://api.openai.com/auth"))
        .map(codex_organizations)
        .and_then(|organizations| {
            organizations
                .into_iter()
                .find(|organization| organization.is_default)
                .and_then(|organization| organization.id)
        })
        .and_then(|organization_id| {
            billing_identity_hash("openai", "organization", &organization_id)
        });
    Some(CodexStrongIdentity {
        account_identifier_hash: billing_identity_hash("openai", "account", &account_id)?,
        workspace_identifier_hash: billing_identity_hash("openai", "workspace", &raw_workspace_id)?,
        raw_workspace_id,
        superseded_account_identifier_hash,
        superseded_organization_identifier_hash,
    })
}

fn codex_access_token_email(claims: &Value) -> Option<String> {
    claims
        .get("email")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            claims
                .get("https://api.openai.com/profile")
                .and_then(|profile| profile.get("email"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .map(|value| value.trim().to_string())
}

fn structurally_valid_live_codex_jwt_claims(token: &str) -> Option<Value> {
    let claims = structurally_valid_codex_jwt_claims(token)?;
    let expires_at = claims.get("exp").and_then(Value::as_i64)?;
    (expires_at > OffsetDateTime::now_utc().unix_timestamp()).then_some(claims)
}

/// The claims of a Codex JWT whose shape, algorithm, issuer and audience are
/// plausible. Expiry is not checked here. Decoding never authenticates a
/// token; it only names what the token says.
pub(crate) fn structurally_valid_codex_jwt_claims(token: &str) -> Option<Value> {
    let mut segments = token.split('.');
    let header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    if segments.next().is_some() || signature.is_empty() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header
        .get("alg")
        .and_then(Value::as_str)
        .map_or(true, |alg| alg == "none")
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    if first_json_string(&claims, &["iss"]).as_deref() != Some("https://auth.openai.com") {
        return None;
    }
    let has_audience = claims.get("aud").is_some_and(|audience| match audience {
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => values
            .iter()
            .any(|value| value.as_str().is_some_and(|value| !value.trim().is_empty())),
        _ => false,
    });
    if !has_audience {
        return None;
    }
    Some(claims)
}

fn codex_app_server_account(value: &Value) -> Option<AgentAccountStatus> {
    let account = value.get("account")?;
    if account.get("type").and_then(Value::as_str) != Some("chatgpt") {
        return None;
    }
    let plan_type = first_json_string(account, &["planType", "plan_type"])
        .map(normalize_plan_type)
        .filter(|value| !value.is_empty());
    Some(AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("openai".to_string()),
        auth_method: Some("oauth".to_string()),
        email: first_json_string(account, &["email"]),
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(chatgpt_subscription_product),
        billing_channel: Some("subscription".to_string()),
        confidence: AgentStatusConfidence::High,
        ..unsupported_account("openai")
    })
}

/// Sanity window for a reported subscription-period boundary, in Unix seconds.
///
/// The claim's wire type is not guaranteed, so a millisecond-encoded value is a
/// real possibility. It lands far outside this window and therefore reads as
/// "not reported" rather than as a year-57000 renewal date.
const SUBSCRIPTION_PERIOD_MIN_UNIX_SECONDS: i64 = 1_420_070_400; // 2015-01-01T00:00:00Z
const SUBSCRIPTION_PERIOD_MAX_UNIX_SECONDS: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

/// Read one subscription-period boundary from a provider auth claim.
///
/// Format-tolerant by design: epoch seconds (number or numeric string) and
/// RFC3339 strings are both accepted and normalized to an offset-bearing UTC
/// RFC3339 timestamp. Anything unparseable, or outside the sanity window,
/// returns `None`. No failure path substitutes `now`.
fn subscription_period_timestamp(value: &Value, key: &str) -> Option<String> {
    let parsed = OffsetDateTime::parse(&json_timestamp_rfc3339(value, &[key])?, &Rfc3339).ok()?;
    if !(SUBSCRIPTION_PERIOD_MIN_UNIX_SECONDS..=SUBSCRIPTION_PERIOD_MAX_UNIX_SECONDS)
        .contains(&parsed.unix_timestamp())
    {
        return None;
    }
    // An offset-bearing input is converted, not reinterpreted: the instant is
    // preserved and every emitted boundary reads as UTC.
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

fn collect_codex_app_server_usage_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    login_refresh: CodexLoginRefresh,
) -> Result<CodexUsageProbe, String> {
    let now = current_unix_seconds();
    let needs_details =
        |account: &Value, rate_limits: &Value, credentials: Option<&CodexAuthCredentials>| {
            let binding = credentials
                .and_then(|credentials| {
                    validated_codex_identity(credentials, Some(account), Some(rate_limits), true)
                })
                .map(|identity| codex_credit_binding(&identity));
            codex_credit_grants::routine_read_needs_details(binding.as_deref(), rate_limits, now)
        };
    let started = Instant::now();
    let observation = match call_codex_app_server_rate_limits_for_home(
        codex_home,
        home_trust,
        login_refresh,
        &needs_details,
    ) {
        Ok(observation) => observation,
        Err(message) => {
            eprintln!(
                "{}",
                codex_probe_failure_log_line(
                    &message,
                    codex_home,
                    started.elapsed(),
                    current_unix_seconds(),
                )
            );
            // No reading at all: the detail back-off still applies to the
            // account last validated at this home.
            codex_credit_grants::record_session_failure(codex_home, now);
            return Err(message);
        }
    };
    let probe = codex_usage_probe_from_app_server_observation(observation);
    if let Some(identity) = probe.identity.as_ref() {
        codex_credit_grants::remember_home_binding(codex_home, &codex_credit_binding(identity));
    }
    Ok(probe)
}

/// One log line per failed app-server probe: wall-clock time, the session
/// stage, the error kind, the JSON-RPC error code, a digest of the Codex home
/// and the elapsed time.
/// Built from the fixed producer text only; no path, account or provider text.
fn codex_probe_failure_log_line(
    message: &str,
    codex_home: &Path,
    elapsed: Duration,
    now: u64,
) -> String {
    let (stage, kind) = codex_probe_failure_stage_and_kind(message);
    // The JSON-RPC error code from `codex_app_server_rpc_failure`, digits only.
    let code = message
        .split_once("RPC failed with code ")
        .and_then(|(_, rest)| rest.trim_end_matches('.').parse::<i64>().ok())
        .map_or_else(|| "none".to_string(), |code| code.to_string());
    let mut digest = Sha256::new();
    digest.update(b"ottto:codex-home-log:v1\0");
    digest.update(codex_home.as_os_str().as_encoded_bytes());
    let home = format!("{:x}", digest.finalize());
    format!(
        "codex usage probe failed: at={} stage={stage} kind={kind} code={code} home={} elapsed_ms={}",
        rfc3339_from_unix_seconds(now).unwrap_or_else(|| "unknown".to_string()),
        &home[..12],
        elapsed.as_millis()
    )
}

/// `(stage, kind)` of a failed app-server probe, from its fixed producer text
/// (`codex_app_server_rpc_failure`, `codex_app_server_end_failure` and the
/// session's own messages).
fn codex_probe_failure_stage_and_kind(message: &str) -> (&'static str, &'static str) {
    let kind = if message.contains("timed out") {
        "timeout"
    } else if message.contains("RPC failed") {
        "rpc_error"
    } else if message.contains("stdout closed") {
        "stdout_closed"
    } else if message.contains("stdout read failed") {
        "read_failed"
    } else if message.contains("exceeded") {
        "output_bound"
    } else if message.contains("not found")
        || message.contains("could not be started")
        || message.contains("was unavailable")
    {
        "start"
    } else if message.contains("request") && message.contains("failed") {
        "request_failed"
    } else {
        "other"
    };
    let stage = message
        .split(|character: char| !character.is_ascii_alphanumeric())
        .find_map(|word| match word {
            "initialize" => Some("initialize"),
            "account" => Some("account"),
            "quota" => Some("quota"),
            _ => None,
        })
        .unwrap_or(if kind == "start" { "start" } else { "session" });
    (stage, kind)
}

fn codex_credit_binding(identity: &CodexStrongIdentity) -> String {
    codex_credit_grants::binding_key(
        &identity.account_identifier_hash,
        &identity.workspace_identifier_hash,
    )
}

fn codex_usage_probe_from_app_server_observation(
    observation: CodexAppServerObservation,
) -> CodexUsageProbe {
    let identity = observation
        .refreshed_credentials
        .as_ref()
        .and_then(|credentials| {
            validated_codex_identity(
                credentials,
                Some(&observation.account),
                Some(&observation.rate_limits),
                true,
            )
        });
    let mut quota_windows = codex_app_server_quota_windows(&observation.rate_limits);
    for window in &mut quota_windows {
        window.observed_at = observation.response_completed_at.clone();
    }
    let now = current_unix_seconds();
    let binding = identity.as_ref().map(codex_credit_binding);
    let mut credit_balances = codex_app_server_credit_balances(&observation.rate_limits);
    let model_diagnostics = codex_credit_grants::attach_reset_bank_grants(
        &mut credit_balances,
        &observation.rate_limits,
        codex_credit_grants::CodexCreditRead {
            binding: binding.as_deref(),
            details_requested: observation.details_requested,
            details_answered: observation.details_answered,
            observed_at: observation.response_completed_at.as_deref(),
            now,
        },
    );
    codex_credit_grants::stamp_read_clock(
        &mut credit_balances,
        observation.response_completed_at.as_deref(),
    );
    let reset_credit_detail_summary = if observation.details_requested {
        codex_reset_credit_detail_summary(&observation.rate_limits)
    } else {
        codex_credit_grants::routine_reset_credit_summary(&observation.rate_limits)
    }
    .map(|summary| summary + &codex_credit_grants::model_diagnostics_suffix(&model_diagnostics));
    CodexUsageProbe {
        quota_windows,
        credit_balances,
        account: codex_app_server_account(&observation.account),
        identity,
        saved_identity: None,
        credential_read_failed: observation.credential_read_failed,
        response_completed_at: observation.response_completed_at,
        reset_credit_detail_summary,
        rate_limit_pool_summary: Some(codex_credit_grants::rate_limit_pools_summary(
            &observation.rate_limits,
            now,
        )),
    }
}

/// V1 acquisition evidence from the existing read. Summarize at most 20 rows,
/// without grant ids, titles, descriptions, timestamps or invented semantics.
fn codex_reset_credit_detail_summary(value: &Value) -> Option<String> {
    let credits = value.get("rateLimitResetCredits")?.as_object()?;
    let count = codex_credit_grants::available_count(value)
        .filter(|n| *n <= 10_000)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unreported".to_string());
    let Some(rows) = credits.get("credits").and_then(Value::as_array) else {
        return Some(format!(
            "Codex reset details: count {count}; list unobserved."
        ));
    };
    let mut states = [0usize; 4];
    let mut expiry_present = 0;
    for row in rows.iter().take(20) {
        let bucket = match row.get("status").and_then(Value::as_str) {
            Some("available") => 0,
            Some("redeeming") => 1,
            Some("redeemed") => 2,
            _ => 3,
        };
        states[bucket] += 1;
        if row.get("expiresAt").is_some_and(|v| !v.is_null()) {
            expiry_present += 1;
        }
    }
    Some(format!("Codex reset details: count {count}; list rows {}; sampled {}; available {}, redeeming {}, redeemed {}, unknown {}; expiry present {}.",
        rows.len(), rows.len().min(20), states[0], states[1], states[2], states[3], expiry_present))
}

struct CodexAppServerObservation {
    account: Value,
    rate_limits: Value,
    refreshed_credentials: Option<CodexAuthCredentials>,
    credential_read_failed: bool,
    response_completed_at: Option<String>,
    /// A detailed (reset-credit list) read was sent in this session.
    details_requested: bool,
    /// That detailed read answered with a result.
    details_answered: bool,
}

fn codex_app_server_success_diagnostic(
    response_completed_at: Option<String>,
    identity: Option<&CodexIdentityHashes>,
    has_usage: bool,
) -> Option<AgentStatusDiagnostic> {
    let identity = identity.filter(|_| has_usage)?;
    let completed_at = response_completed_at?;
    bounded_claude_collection_timestamp(Some(&completed_at), OffsetDateTime::now_utc())?;
    Some(
        AgentStatusDiagnostic::source(
            "codex_app_server_usage_response",
            AgentDiagnosticSeverity::Info,
            "Codex app-server account and quota read completed successfully; this clock records the read, not when quota last changed.",
        )
        .with_observed_at(Some(completed_at))
        .with_quota_binding(
            Some(identity.account_identifier_hash.clone()),
            Some(identity.workspace_identifier_hash.clone()),
        ),
    )
}

/// Decides, after the routine reading, whether to send the detailed read in
/// the same session: `(account result, rate-limit result, refreshed
/// credentials)`.
type CodexNeedsDetails<'a> = &'a dyn Fn(&Value, &Value, Option<&CodexAuthCredentials>) -> bool;

/// No `codex` executable: not a transient read failure (see
/// [`codex_probe_failed_only`]).
const CODEX_CLI_NOT_FOUND_FOR_PROBE: &str =
    "Codex CLI was not found for app-server rate-limit collection.";

/// Fixed producer text only; never persist provider error messages or data.
fn codex_app_server_rpc_failure(phase: &str, error: &Value) -> String {
    match error.get("code").and_then(Value::as_i64) {
        Some(code) => format!("Codex app-server {phase} RPC failed with code {code}."),
        None => format!("Codex app-server {phase} RPC failed without a numeric code."),
    }
}

/// Observe child termination before our cleanup; never report our own kill signal.
fn codex_app_server_end_failure(
    phase: &str,
    disconnected: bool,
    initialize_error: Option<&str>,
    child: &mut crate::local_resource_diagnostics::cli_children::MeasuredChild,
) -> String {
    if let Some(message) = initialize_error {
        return message.to_string();
    }
    if !disconnected {
        return format!("Codex app-server {phase} read timed out.");
    }
    let status = child.try_wait().ok().flatten();
    if let Some(status) = status {
        if let Some(code) = status.code() {
            return format!(
                "Codex app-server stdout closed during {phase}; child exited with code {code}."
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return format!("Codex app-server stdout closed during {phase}; child terminated by signal {signal}.");
            }
        }
    }
    format!("Codex app-server stdout closed during {phase}; child termination was not observed before cleanup.")
}

/// What one `codex app-server` run asked of the provider, for the
/// provider-call log.
#[derive(Debug, Default)]
struct CodexAppServerRun {
    spawned: bool,
    /// Whether the session asked for the detailed rate-limits read.
    detail_read_sent: bool,
    /// Whether the CLI rejected the routine read's parameter itself; that
    /// read never reached the provider, and the detailed read replaced it.
    routine_read_rejected: bool,
    timed_out: bool,
}

/// Provider requests a started `codex app-server` quota session counts at
/// least, sent whether or not they were answered: the token refresh and the
/// rate-limits read.
const CODEX_APP_SERVER_MIN_REQUESTS: u32 = 2;

/// Bound on one `codex app-server` quota session: [`CODEX_APP_SERVER_TIMEOUT`],
/// or a test's scaled bound.
fn codex_app_server_timeout() -> Duration {
    #[cfg(test)]
    if let Some(timeouts) = codex_app_server_test_timeouts() {
        return timeouts.session;
    }
    CODEX_APP_SERVER_TIMEOUT
}

/// Scaled app-server bounds for tests only; production constants are never
/// changed.
#[cfg(test)]
#[derive(Clone, Copy)]
struct CodexAppServerTestTimeouts {
    session: Duration,
    detail_min: Duration,
    detail_max: Duration,
}

#[cfg(test)]
thread_local! {
    static CODEX_APP_SERVER_TEST_TIMEOUTS: std::cell::Cell<Option<CodexAppServerTestTimeouts>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn codex_app_server_test_timeouts() -> Option<CodexAppServerTestTimeouts> {
    CODEX_APP_SERVER_TEST_TIMEOUTS.with(std::cell::Cell::get)
}

/// Runs `run` with the session bound and the detailed read's budget bounds
/// scaled down. The session runs on the calling thread, so the override
/// reaches it and no other test.
#[cfg(test)]
fn with_codex_app_server_test_timeouts<T>(
    session: Duration,
    detail_min: Duration,
    detail_max: Duration,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CODEX_APP_SERVER_TEST_TIMEOUTS.with(|timeouts| timeouts.set(None));
        }
    }
    CODEX_APP_SERVER_TEST_TIMEOUTS.with(|timeouts| {
        timeouts.set(Some(CodexAppServerTestTimeouts {
            session,
            detail_min,
            detail_max,
        }))
    });
    let _reset = Reset;
    run()
}

/// One `codex app-server` quota session for `codex_home`, logged as one
/// provider-call line when the CLI started.
fn call_codex_app_server_rate_limits_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    login_refresh: CodexLoginRefresh,
    needs_details: CodexNeedsDetails<'_>,
) -> Result<CodexAppServerObservation, String> {
    use crate::provider_calls::{CallKind, CallResult, Provider, ProviderCall, Trigger};
    let account_before = codex_home_claimed_account_hash(codex_home, home_trust);
    let started = Instant::now();
    let mut run = CodexAppServerRun::default();
    let result = run_codex_app_server_rate_limits_for_home(
        codex_home,
        home_trust,
        login_refresh,
        needs_details,
        &mut run,
    );
    if run.spawned {
        let result_class = match &result {
            Ok(_) => CallResult::Ok,
            Err(_) if run.timed_out => CallResult::Timeout,
            Err(message) if message.contains("RPC failed") => CallResult::Error("rpc_error"),
            Err(message) if message.contains("stdout closed") => CallResult::Error("exited"),
            Err(message) if message.contains("exceeded its") => CallResult::Error("output_bound"),
            Err(_) => CallResult::Error("error"),
        };
        let account =
            account_before.or_else(|| codex_home_claimed_account_hash(codex_home, home_trust));
        crate::provider_calls::record(ProviderCall::subprocess(
            Provider::Openai,
            CallKind::CodexAppServerQuota,
            crate::provider_calls::trigger_or(Trigger::Other),
            account.as_deref(),
            result_class,
            started.elapsed(),
            CODEX_APP_SERVER_MIN_REQUESTS
                + u32::from(run.detail_read_sent && !run.routine_read_rejected),
        ));
    }
    result
}

/// How far ahead of its lapse the probe refreshes an account home's login: the
/// longest gap between two reads of a home, so the claimed workspace does not
/// lapse before the next read. A lapse alone does not bring that read forward.
const CODEX_MANAGED_LOGIN_REFRESH_AHEAD_SECONDS: u64 = codex_saved_quota::UNUSED_REFRESH_SECONDS;

/// Why the probe forces a token refresh in `account/read`, or `None` to leave
/// the login as it is. Only an Ottto account slot's home
/// ([`CodexLoginRefresh::WhenLapsing`]) is refreshed, and only when its
/// claimed binding has lapsed, lapses within
/// [`CODEX_MANAGED_LOGIN_REFRESH_AHEAD_SECONDS`] or has no readable expiry:
/// Codex does not persist a refresh of its own for that, so the workspace
/// would stay unconfirmed. The default home, and a home seen only through a
/// running Codex process, hold a person's own login and are never refreshed
/// here.
fn codex_probe_refresh_reason(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    login_refresh: CodexLoginRefresh,
    now: u64,
) -> Option<&'static str> {
    if login_refresh == CodexLoginRefresh::Never || home_trust != CodexHomeTrust::Managed {
        return None;
    }
    let credentials = match read_codex_auth_credentials_at(codex_home, home_trust) {
        Ok(Some(credentials)) => credentials,
        Ok(None) => return None,
        Err(_) => return Some("unreadable"),
    };
    match codex_credential_claim_lapses_at(&credentials) {
        None => Some("lapsed_or_unknown"),
        Some(lapses_at)
            if lapses_at <= now.saturating_add(CODEX_MANAGED_LOGIN_REFRESH_AHEAD_SECONDS) =>
        {
            Some("lapses_soon")
        }
        Some(_) => None,
    }
}

fn run_codex_app_server_rate_limits_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    login_refresh: CodexLoginRefresh,
    needs_details: CodexNeedsDetails<'_>,
    run: &mut CodexAppServerRun,
) -> Result<CodexAppServerObservation, String> {
    #[cfg(test)]
    CODEX_APP_SERVER_RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let Some(program_path) = crate::command_env::executable_path("codex") else {
        return Err(CODEX_CLI_NOT_FOUND_FOR_PROBE.to_string());
    };
    let Some(identity) = effective_user_identity() else {
        return Err("Codex app-server user identity was unavailable.".to_string());
    };
    let mut command = Command::new(program_path);
    // Turn off Codex's startup installers, which write into the account's home:
    // the bundled system-skill install and the curated plugin sync. A CLI that
    // lacks either key warns and keeps its default.
    command
        .args([
            "-c",
            "skills.bundled.enabled=false",
            "-c",
            "features.plugins=false",
            "app-server",
            "--stdio",
        ])
        .env_clear();
    command
        .env("HOME", &identity.home_dir)
        .env("USER", identity.account_name)
        .env("CODEX_HOME", codex_home)
        .env("CODEX_SQLITE_HOME", codex_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for locale_key in ["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = std::env::var_os(locale_key) {
            command.env(locale_key, value);
        }
    }
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    let mut child = crate::local_resource_diagnostics::cli_children::spawn(&mut command)
        .map_err(|_| "Codex app-server could not be started.".to_string())?;
    run.spawned = true;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Codex app-server stdout was unavailable.".to_string())?;
    let (sender, receiver) =
        mpsc::sync_channel::<Result<Value, String>>(CODEX_APP_SERVER_CHANNEL_CAPACITY);
    thread::spawn(move || {
        read_bounded_codex_app_server_stdout(BufReader::new(stdout), sender);
    });

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Codex app-server stdin was unavailable.".to_string())?;
    let initialize = serde_json::json!({
        "method": "initialize",
        "id": 1,
        "params": {
            "clientInfo": {
                "name": "ottto_local_platform",
                "title": "Ottto Local Platform",
                "version": compiled_release_version()
            },
            "capabilities": {
                "experimentalApi": true,
                "optOutNotificationMethods": ["account/rateLimits/updated"]
            }
        }
    });
    let initialized = serde_json::json!({"method": "initialized"});
    let refresh_reason = codex_probe_refresh_reason(
        codex_home,
        home_trust,
        login_refresh,
        current_unix_seconds(),
    );
    if let Some(reason) = refresh_reason {
        eprintln!("codex usage probe: forcing account home login refresh reason={reason}");
    }
    let account = serde_json::json!({
        "method": "account/read",
        "id": "ottto_account",
        "params": {"refreshToken": refresh_reason.is_some()}
    });
    // Every poll reads usage and the count first; the reset-credit list
    // follows in this session only when the cadence asks for it.
    let read = codex_credit_grants::CodexRateLimitsRead::Routine.request("ottto_rate_limits");
    let detail_read = codex_credit_grants::CodexRateLimitsRead::Detailed
        .request(codex_credit_grants::DETAIL_READ_ID);
    let write_result = (|| -> Result<(), String> {
        for message in [initialize, initialized, account] {
            serde_json::to_writer(&mut stdin, &message)
                .map_err(|_| "Codex app-server request serialization failed.".to_string())?;
            stdin
                .write_all(b"\n")
                .map_err(|_| "Codex app-server request write failed.".to_string())?;
        }
        stdin
            .flush()
            .map_err(|_| "Codex app-server request flush failed.".to_string())
    })();
    if let Err(message) = write_result {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err(message);
    }

    let start = Instant::now();
    let mut deadline = start + codex_app_server_timeout();
    let mut initialize_error = None;
    let mut initialize_completed = false;
    let mut disconnected = false;
    let mut account_result = None;
    let mut rate_limits_result: Option<(Value, Option<String>)> = None;
    let mut detail_result: Option<(Value, Option<String>)> = None;
    let mut rate_limits_requested = false;
    // The detailed read sent after the routine one in this session.
    let mut detail_requested = false;
    let mut detail_failed = false;
    let mut credentials: Option<(Option<CodexAuthCredentials>, bool)> = None;
    let read_credentials = || match read_codex_auth_credentials_at(codex_home, home_trust) {
        Ok(credentials) => (credentials, false),
        Err(_) => (None, true),
    };
    // `Ok(true)`: settled; `Ok(false)`: timed out or the server went away.
    let outcome: Result<bool, String> = loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            run.timed_out = true;
            break Ok(false);
        };
        let message = match receiver.recv_timeout(remaining.min(Duration::from_millis(250))) {
            // Output bounds still end the session; a routine reading taken
            // before the detailed read stands (the attempt counts as failed).
            Ok(Err(_)) if detail_requested && rate_limits_result.is_some() => break Ok(true),
            Ok(Err(message)) => break Err(message),
            Ok(Ok(message)) => message,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                disconnected = true;
                break Ok(false);
            }
        };
        if message.get("id").and_then(Value::as_i64) == Some(1) {
            if let Some(error) = message.get("error") {
                initialize_error = Some(codex_app_server_rpc_failure("initialize", error));
            } else if message.get("result").is_some() {
                initialize_completed = true;
            }
        }
        // An earlier initialize rejection is the likelier cause of a later
        // RPC failure.
        let rpc_failure = |phase: &str, error: &Value| {
            initialize_error
                .clone()
                .unwrap_or_else(|| codex_app_server_rpc_failure(phase, error))
        };
        let response_id = message.get("id").and_then(Value::as_str);
        let error = message.get("error");
        let arrived_at = || rfc3339_from_unix_seconds(current_unix_seconds());
        let mut send_details = false;
        match (response_id, error) {
            (Some("ottto_account"), Some(error)) => {
                break Err(rpc_failure("account", error));
            }
            (Some("ottto_account"), None) => account_result = message.get("result").cloned(),
            (Some("ottto_rate_limits"), Some(error))
                if !detail_requested && codex_credit_grants::routine_param_rejected(error) =>
            {
                // A server that does not accept the routine parameter still
                // answers the plain read it always accepted.
                send_details = true;
                run.routine_read_rejected = true;
            }
            (Some("ottto_rate_limits"), Some(error)) => {
                break Err(rpc_failure("quota", error));
            }
            (Some("ottto_rate_limits"), None) if rate_limits_result.is_none() => {
                rate_limits_result = message
                    .get("result")
                    .cloned()
                    .map(|result| (result, arrived_at()));
            }
            (Some(codex_credit_grants::DETAIL_READ_ID), Some(error)) => {
                if rate_limits_result.is_none() {
                    break Err(rpc_failure("quota", error));
                }
                detail_failed = true;
            }
            (Some(codex_credit_grants::DETAIL_READ_ID), None) => {
                detail_result = message
                    .get("result")
                    .cloned()
                    .map(|result| (result, arrived_at()));
            }
            _ => {}
        }
        if account_result.is_some() && !rate_limits_requested {
            if write_codex_app_server_message(&mut stdin, &read).is_err() {
                break Err("Codex app-server quota request failed.".to_string());
            }
            rate_limits_requested = true;
        }
        if !send_details && !detail_requested {
            if let (Some(account), Some((rate_limits, _))) =
                (account_result.as_ref(), rate_limits_result.as_ref())
            {
                let (refreshed, _) = credentials.get_or_insert_with(read_credentials);
                if !needs_details(account, rate_limits, refreshed.as_ref()) {
                    break Ok(true);
                }
                send_details = true;
            }
        }
        if send_details {
            detail_requested = true;
            let now = Instant::now();
            deadline = now
                + codex_credit_grants::detail_read_budget(deadline.saturating_duration_since(now));
            if write_codex_app_server_message(&mut stdin, &detail_read).is_err() {
                if rate_limits_result.is_some() {
                    // The routine reading stands; the attempt counts as failed.
                    break Ok(true);
                }
                break Err("Codex app-server quota request failed.".to_string());
            }
            run.detail_read_sent = true;
            continue;
        }
        if detail_requested
            && account_result.is_some()
            && (detail_result.is_some() || (detail_failed && rate_limits_result.is_some()))
        {
            break Ok(true);
        }
    };
    // A detailed read that did not answer in time leaves the routine reading.
    let settled = match outcome {
        Ok(settled) => settled || (detail_requested && rate_limits_result.is_some()),
        Err(message) => {
            drop(stdin);
            let _ = child.kill();
            let _ = child.wait();
            return Err(message);
        }
    };
    let phase = if account_result.is_some() {
        "quota"
    } else if initialize_completed {
        "account"
    } else {
        "initialize"
    };
    let details_answered = detail_result.is_some();
    let (Some(account), Some((rate_limits, response_completed_at)), true) = (
        account_result,
        detail_result.or(rate_limits_result),
        settled,
    ) else {
        // Observe the child's own end before our cleanup kill.
        let message = codex_app_server_end_failure(
            phase,
            disconnected,
            initialize_error.as_deref(),
            &mut child,
        );
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err(message);
    };
    let (refreshed_credentials, credential_read_failed) =
        credentials.unwrap_or_else(read_credentials);
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    Ok(CodexAppServerObservation {
        account,
        rate_limits,
        refreshed_credentials,
        credential_read_failed,
        response_completed_at,
        details_requested: detail_requested,
        details_answered,
    })
}

fn write_codex_app_server_message(stdin: &mut impl Write, message: &Value) -> Result<(), ()> {
    serde_json::to_writer(&mut *stdin, message).map_err(|_| ())?;
    stdin.write_all(b"\n").map_err(|_| ())?;
    stdin.flush().map_err(|_| ())
}

fn read_bounded_codex_app_server_stdout<R: BufRead>(
    mut reader: R,
    sender: mpsc::SyncSender<Result<Value, String>>,
) {
    let mut total_bytes = 0_usize;
    let mut message_count = 0_usize;
    loop {
        let mut line = Vec::new();
        let read = match reader
            .by_ref()
            .take((CODEX_APP_SERVER_MAX_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
        {
            Ok(read) => read,
            Err(_) => {
                let _ = sender.send(Err("Codex app-server stdout read failed.".to_string()));
                return;
            }
        };
        if read == 0 {
            return;
        }
        total_bytes = total_bytes.saturating_add(read);
        if read > CODEX_APP_SERVER_MAX_LINE_BYTES || total_bytes > CODEX_APP_SERVER_MAX_TOTAL_BYTES
        {
            let _ = sender.send(Err(
                "Codex app-server output exceeded its byte limit.".to_string()
            ));
            return;
        }
        let Ok(line) = std::str::from_utf8(&line) else {
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        message_count = message_count.saturating_add(1);
        if message_count > CODEX_APP_SERVER_MAX_MESSAGES {
            let _ = sender.send(Err(
                "Codex app-server output exceeded its message limit.".to_string()
            ));
            return;
        }
        if let Some(value) =
            credit_amount_input::decode(line, credit_amount_input::CreditBody::CodexMessage)
        {
            if sender.send(Ok(value)).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
fn call_codex_app_server_rate_limits() -> Result<Value, String> {
    call_codex_app_server_rate_limits_for_home(
        &default_codex_home(),
        CodexHomeTrust::ProviderDefault,
        CodexLoginRefresh::Never,
        &|_, _, _| false,
    )
    .map(|observation| observation.rate_limits)
}

fn codex_app_server_quota_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    for (limit_id, rate_limit) in codex_app_server_rate_limit_snapshots(value) {
        let Some(fields) = rate_limit.as_object() else {
            continue;
        };
        let mut window_fields = fields
            .iter()
            .filter(|(_, candidate)| {
                candidate.get("usedPercent").is_some()
                    || candidate.get("used_percent").is_some()
                    || candidate.get("windowDurationMins").is_some()
                    || candidate.get("window_duration_mins").is_some()
            })
            .collect::<Vec<_>>();
        window_fields.sort_by_key(|(field, _)| match field.as_str() {
            "primary" => (0_u8, field.as_str()),
            "secondary" => (1_u8, field.as_str()),
            _ => (2_u8, field.as_str()),
        });
        for (field, raw_window) in window_fields {
            let window_seconds =
                json_u64(raw_window, &["windowDurationMins", "window_duration_mins"])
                    .map(|minutes| minutes.saturating_mul(60));
            let name = codex_usage_window_key(
                &limit_id,
                field,
                window_seconds,
                json_timestamp_rfc3339(raw_window, &["resetsAt", "resets_at"]).is_some(),
            );
            if let Some(window) =
                codex_app_server_quota_window(&name, &limit_id, raw_window, rate_limit)
            {
                windows.push(window);
            }
        }
    }
    windows
}

fn codex_app_server_rate_limit_snapshots(value: &Value) -> Vec<(String, &Value)> {
    // `rateLimits` is the app server's effective subscription snapshot.  The
    // sibling `rateLimitsByLimitId` map may also contain inactive/model-specific
    // pools whose reset boundaries advance on every read.  Treating that map as
    // the primary source fabricated extra customer quotas and, because the
    // effective snapshot was then skipped, could also hide its credit balance.
    // Keep the map only as a compatibility fallback for app-server versions
    // that do not provide a usable effective snapshot.
    if let Some(snapshot) = value
        .get("rateLimits")
        .filter(|snapshot| codex_rate_limit_snapshot_has_usage(snapshot))
    {
        return vec![(
            first_json_string(snapshot, &["limitId", "limit_id"])
                .unwrap_or_else(|| "codex".to_string()),
            snapshot,
        )];
    }
    if let Some(by_limit_id) = value.get("rateLimitsByLimitId").and_then(Value::as_object) {
        let mut snapshots = by_limit_id
            .iter()
            .filter(|(_, snapshot)| codex_rate_limit_snapshot_has_usage(snapshot))
            .map(|(limit_id, snapshot)| (limit_id.clone(), snapshot))
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.0.cmp(&right.0));
        if !snapshots.is_empty() {
            return snapshots;
        }
    }
    Vec::new()
}

fn codex_rate_limit_snapshot_has_usage(value: &Value) -> bool {
    ["primary", "secondary"].iter().any(|field| {
        value.get(field).is_some_and(|window| {
            codex_app_server_quota_window(field, "codex", window, value).is_some()
        })
    }) || value
        .get("credits")
        .is_some_and(|credits| codex_credit_balance_from_credits_snapshot(credits, value).is_some())
        || codex_monthly_credit_limit_from_snapshot(value).is_some()
}

fn codex_app_server_quota_window(
    name: &str,
    limit_id: &str,
    value: &Value,
    snapshot: &Value,
) -> Option<AgentQuotaWindow> {
    let used_percent = json_u8(value, &["usedPercent", "used_percent"]);
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let resets_at = json_timestamp_rfc3339(value, &["resetsAt", "resets_at"]);
    let window_seconds = json_u64(value, &["windowDurationMins", "window_duration_mins"])
        .map(|minutes| minutes.saturating_mul(60));
    let started_at = resets_at
        .as_deref()
        .zip(window_seconds)
        .and_then(|(reset, seconds)| rfc3339_minus_seconds(reset, seconds));
    if used_percent.is_none() && resets_at.is_none() && window_seconds.is_none() {
        return None;
    }
    let spend_control_reached =
        json_bool(snapshot, &["spendControlReached", "spend_control_reached"]);
    let rate_limit_reached_type = codex_rate_limit_reached_type(snapshot);
    Some(AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Account,
        status: match (
            spend_control_reached,
            rate_limit_reached_type.as_deref(),
            left_percent,
        ) {
            (Some(true), _, _) | (_, Some(_), _) => AgentQuotaWindowStatus::Exhausted,
            (_, _, Some(0)) => AgentQuotaWindowStatus::Exhausted,
            (_, _, Some(value)) if value <= 20 => AgentQuotaWindowStatus::NearLimit,
            (_, _, Some(_)) => AgentQuotaWindowStatus::Ok,
            _ => AgentQuotaWindowStatus::Unknown,
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds,
        started_at_basis: started_at.as_ref().map(|_| "provider_duration".to_string()),
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        spend_control_reached,
        rate_limit_reached_type,
        limit_id: Some(limit_id.to_string()),
        ..Default::default()
    })
}

fn codex_rate_limit_reached_type(container: &Value) -> Option<String> {
    let value = first_json_string(
        container,
        &["rateLimitReachedType", "rate_limit_reached_type"],
    )?;
    match value.as_str() {
        "rateLimitReached" | "rate_limit_reached" => Some("rateLimitReached".to_string()),
        "workspaceOwnerCreditsDepleted" | "workspace_owner_credits_depleted" => {
            Some("workspaceOwnerCreditsDepleted".to_string())
        }
        "workspaceMemberCreditsDepleted" | "workspace_member_credits_depleted" => {
            Some("workspaceMemberCreditsDepleted".to_string())
        }
        "workspaceOwnerUsageLimitReached" | "workspace_owner_usage_limit_reached" => {
            Some("workspaceOwnerUsageLimitReached".to_string())
        }
        "workspaceMemberUsageLimitReached" | "workspace_member_usage_limit_reached" => {
            Some("workspaceMemberUsageLimitReached".to_string())
        }
        _ => None,
    }
}

fn codex_app_server_credit_balances(value: &Value) -> Vec<AgentCreditBalance> {
    let mut balances = BTreeMap::<String, AgentCreditBalance>::new();
    for (limit_id, rate_limit) in codex_app_server_rate_limit_snapshots(value) {
        if let Some(credits) = rate_limit.get("credits") {
            if let Some(mut balance) =
                codex_credit_balance_from_credits_snapshot(credits, rate_limit)
            {
                balance.limit_id = Some(limit_id.clone());
                if limit_id != "codex" {
                    balance.name = format!("{limit_id}_{}", balance.name);
                }
                balances.insert(balance.name.clone(), balance);
            }
        }
        if let Some(mut balance) = codex_monthly_credit_limit_from_snapshot(rate_limit) {
            balance.limit_id = Some(limit_id.clone());
            if limit_id != "codex" {
                balance.name = format!("{limit_id}_{}", balance.name);
            }
            balances.insert(balance.name.clone(), balance);
        }
    }
    if let Some(remaining) = codex_credit_grants::available_count(value) {
        let remaining = CreditAmount::whole(remaining);
        let balance = AgentCreditBalance {
            name: codex_credit_grants::RESET_BANK.to_string(),
            status: crate::quota_credit_model::status_for_remaining(remaining),
            freshness: AgentQuotaWindowFreshness::Fresh,
            unit: AgentCreditBalanceUnit::Resets,
            account_label: None,
            remaining,
            used: None,
            quota: None,
            unlimited: Some(false),
            updated_at: None,
            ..Default::default()
        };
        balances.insert(balance.name.clone(), balance);
    }
    let mut balances = balances.into_values().collect::<Vec<_>>();
    codex_credit_grants::stamp_codex_balance_kinds(&mut balances);
    balances
}

/// Parse Codex's effective workspace monthly credit limit.
///
/// The app-server surface calls this `individualLimit`; the snake_case
/// `individual_limit` spelling is also accepted. It is a recurring budget, not
/// the earned reset bank and not the sparse `credits.balance`, so it gets a
/// stable, separate identity downstream.
fn codex_monthly_credit_limit_from_snapshot(container: &Value) -> Option<AgentCreditBalance> {
    let individual_limit = container
        .get("individualLimit")
        .or_else(|| container.get("individual_limit"))?;
    if individual_limit.is_null() {
        return None;
    }

    let quota = credit_amount_input::amount_at(individual_limit, &["limit"]);
    let used = credit_amount_input::amount_at(individual_limit, &["used"]);
    let remaining = match (quota, used) {
        (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
        _ => None,
    };
    let remaining_percent = json_u8(individual_limit, &["remainingPercent", "remaining_percent"]);
    let used_percent = remaining_percent.map(|value| 100_u8.saturating_sub(value));
    let resets_at = json_timestamp_rfc3339(individual_limit, &["resetsAt", "resets_at"]);
    if quota.is_none() && used.is_none() && remaining_percent.is_none() && resets_at.is_none() {
        return None;
    }

    let spend_control_reached =
        json_bool(container, &["spend_control_reached", "spendControlReached"]);
    let rate_limit_reached_type = codex_rate_limit_reached_type(container);
    let limit_id = first_json_string(container, &["limit_id", "limitId"]);
    let status = if spend_control_reached == Some(true)
        || remaining == Some(CreditAmount::ZERO)
        || remaining_percent == Some(0)
    {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining_percent.is_some_and(|value| value <= 20) {
        AgentCreditBalanceStatus::Low
    } else {
        AgentCreditBalanceStatus::Ok
    };

    Some(AgentCreditBalance {
        name: codex_credit_grants::WORKSPACE_MONTHLY_CREDITS.to_string(),
        status,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Credits,
        account_label: None,
        remaining,
        used,
        quota,
        unlimited: Some(false),
        updated_at: None,
        resets_at,
        used_percent,
        enabled: Some(true),
        spend_control_reached,
        rate_limit_reached_type,
        limit_id,
        ..Default::default()
    })
}

fn codex_credit_balance_from_credits_snapshot(
    credits: &Value,
    container: &Value,
) -> Option<AgentCreditBalance> {
    let remaining = credit_amount_input::amount_at(credits, &["balance", "remaining", "credits"]);
    let unlimited = json_bool(credits, &["unlimited"]);
    let has_credits_claim = json_bool(credits, &["hasCredits", "has_credits"]);
    let has_credits = has_credits_claim.unwrap_or(false);
    // `credits` sits beside `primary`/`secondary` on the rate-limit snapshot; the
    // sibling `spend_control_reached`, `rate_limit_reached_type`, and `limit_id`
    // fields (e.g. `limitId: "codex"`) live on that container and carry the
    // spend-cap contract.
    let spend_control_reached =
        json_bool(container, &["spend_control_reached", "spendControlReached"]);
    let rate_limit_reached_type = codex_rate_limit_reached_type(container);
    let limit_id = first_json_string(container, &["limit_id", "limitId"]);
    if remaining.is_none()
        && unlimited.is_none()
        && !has_credits
        && spend_control_reached != Some(true)
    {
        return None;
    }
    if codex_credits_do_not_apply(
        has_credits_claim,
        unlimited,
        remaining,
        spend_control_reached,
    ) {
        return None;
    }
    // A reached spend control means the account is spend-capped even if a nominal
    // credit figure remains, so treat it as exhausted regardless of the balance.
    let status = if spend_control_reached == Some(true) {
        AgentCreditBalanceStatus::Exhausted
    } else {
        codex_credit_balance_status(remaining, unlimited, has_credits)
    };
    Some(AgentCreditBalance {
        name: codex_credit_grants::PLAN_CREDITS.to_string(),
        status,
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Credits,
        account_label: None,
        remaining,
        used: None,
        quota: None,
        unlimited,
        updated_at: None,
        spend_control_reached,
        rate_limit_reached_type,
        limit_id,
        ..Default::default()
    })
}

/// `hasCredits: false` is the provider stating that the credits program does not
/// apply to this account, not that the balance ran out. A nominal `balance: "0"`
/// rides along with that claim, so mapping it through the balance rules invents a
/// red "0 left / exhausted" meter for a concept the account does not have. Suppress
/// the row only when the provider explicitly disowns credits and nothing positive
/// is being reported: an absent claim keeps the old behaviour, an `unlimited` grant
/// or a reached spend control still has something true to say, and a positive
/// balance is never hidden even when the two signals disagree.
fn codex_credits_do_not_apply(
    has_credits_claim: Option<bool>,
    unlimited: Option<bool>,
    remaining: Option<CreditAmount>,
    spend_control_reached: Option<bool>,
) -> bool {
    has_credits_claim == Some(false)
        && unlimited != Some(true)
        && spend_control_reached != Some(true)
        && remaining.map_or(true, CreditAmount::is_zero)
}

/// At or below this exact balance (five credits), Codex credits are low.
const CODEX_LOW_CREDITS: CreditAmount = CreditAmount::from_micros(5_000_000);

fn codex_credit_balance_status(
    remaining: Option<CreditAmount>,
    unlimited: Option<bool>,
    has_credits: bool,
) -> AgentCreditBalanceStatus {
    if unlimited == Some(true) {
        AgentCreditBalanceStatus::Unlimited
    } else if remaining.is_some_and(CreditAmount::is_zero) {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining.is_some_and(|value| value <= CODEX_LOW_CREDITS) {
        AgentCreditBalanceStatus::Low
    } else if remaining.is_some() || has_credits {
        AgentCreditBalanceStatus::Ok
    } else {
        AgentCreditBalanceStatus::Unknown
    }
}

fn codex_usage_window_key(
    limit_id: &str,
    window_key: &str,
    window_seconds: Option<u64>,
    has_reset: bool,
) -> String {
    let semantic = match window_seconds {
        Some(18_000) => "five_hour".to_string(),
        Some(604_800) => "weekly".to_string(),
        Some(seconds) if seconds % 60 == 0 => format!("unknown_{}m", seconds / 60),
        Some(seconds) => format!("unknown_{seconds}s"),
        None => "unknown_duration".to_string(),
    };
    let reset_semantic = if has_reset {
        "reset_known"
    } else {
        "reset_unknown"
    };
    format!(
        "{}_{}_{}_{}",
        codex_bucket_component(limit_id),
        codex_bucket_component(window_key),
        semantic,
        reset_semantic
    )
}

/// Reversibly encode one provider bucket-key component. Underscore is reserved
/// as the escape marker and separator, so unlike lossy punctuation replacement
/// this cannot make two distinct provider identifiers share one emitted name.
fn codex_bucket_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "_{byte:02x}");
        }
    }
    encoded
}

#[derive(Debug, Clone)]
struct CodexOrganization {
    id: Option<String>,
    label: Option<String>,
    is_default: bool,
    plan_type: Option<String>,
}

fn codex_workspace_target_evidence_from_id_token(
    token: &str,
    observed_at: &str,
) -> Option<Vec<CodexWorkspaceTargetEvidence>> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let auth_claim = claims.get("https://api.openai.com/auth")?;
    let account_identifier_hash = first_json_string(auth_claim, &["chatgpt_user_id", "user_id"])
        .or_else(|| first_json_string(&claims, &["sub"]))
        .as_deref()
        .and_then(|value| billing_identity_hash("openai", "account", value));
    let account_label = safe_display_label(first_json_string(&claims, &["email"]).as_deref());
    let claimed_plan_type = safe_display_label(
        first_json_string(auth_claim, &["chatgpt_plan_type", "plan_type"]).as_deref(),
    );
    Some(
        codex_organizations(auth_claim)
            .into_iter()
            .map(|organization| CodexWorkspaceTargetEvidence {
                account_identifier_hash: account_identifier_hash.clone(),
                workspace_identifier_hash: organization
                    .id
                    .as_deref()
                    .and_then(|value| billing_identity_hash("openai", "workspace", value)),
                workspace_label: safe_display_label(organization.label.as_deref()),
                account_label: account_label.clone(),
                plan_type: organization
                    .plan_type
                    .clone()
                    .and_then(|plan| safe_display_label(Some(plan.as_str())))
                    .or_else(|| {
                        organization
                            .is_default
                            .then(|| claimed_plan_type.clone())
                            .flatten()
                    }),
                is_default: organization.is_default,
                observed_at: observed_at.to_string(),
            })
            .collect(),
    )
}

fn codex_organizations(value: &Value) -> Vec<CodexOrganization> {
    let Some(organizations) = value.get("organizations").and_then(Value::as_array) else {
        return Vec::new();
    };
    organizations
        .iter()
        .filter_map(|organization| {
            let id = first_json_string(organization, &["id"]);
            let label = first_json_string(organization, &["title", "name", "label"]);
            if id.is_none() && label.is_none() {
                return None;
            }
            Some(CodexOrganization {
                id,
                label,
                is_default: organization
                    .get("is_default")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                plan_type: first_json_string(
                    organization,
                    &[
                        "chatgpt_plan_type",
                        "plan_type",
                        "planType",
                        "subscription_plan",
                        "subscriptionPlan",
                        "tier",
                    ],
                )
                .map(normalize_plan_type)
                .filter(|value| !value.is_empty()),
            })
        })
        .collect()
}

fn merge_codex_accounts(
    existing: Option<AgentAccountStatus>,
    auth_account: AgentAccountStatus,
) -> AgentAccountStatus {
    let Some(existing) = existing else {
        return auth_account;
    };
    AgentAccountStatus {
        login_state: auth_account.login_state,
        provider: auth_account.provider.or(existing.provider),
        auth_method: auth_account.auth_method.or(existing.auth_method),
        email: auth_account.email.or(existing.email),
        account_id: auth_account.account_id.or(existing.account_id),
        organization_id: auth_account.organization_id.or(existing.organization_id),
        organization_label: auth_account
            .organization_label
            .or(existing.organization_label),
        plan_type: auth_account.plan_type.or(existing.plan_type),
        subscription_product: auth_account
            .subscription_product
            .or(existing.subscription_product),
        billing_channel: auth_account.billing_channel.or(existing.billing_channel),
        // This struct is rebuilt field-by-field, so a field added upstream and
        // not carried here is dropped silently on every merged Codex account.
        subscription_period_start: auth_account
            .subscription_period_start
            .or(existing.subscription_period_start),
        subscription_period_end: auth_account
            .subscription_period_end
            .or(existing.subscription_period_end),
        subscription_period_last_checked_at: auth_account
            .subscription_period_last_checked_at
            .or(existing.subscription_period_last_checked_at),
        account_identifier_hash: auth_account
            .account_identifier_hash
            .or(existing.account_identifier_hash),
        organization_identifier_hash: auth_account
            .organization_identifier_hash
            .or(existing.organization_identifier_hash),
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: auth_account
            .credential_fingerprint_hash
            .or(existing.credential_fingerprint_hash),
        billing_identity_evidence: auth_account
            .billing_identity_evidence
            .or(existing.billing_identity_evidence),
        claude_quota_access_state: auth_account
            .claude_quota_access_state
            .or(existing.claude_quota_access_state),
        claude_anchor_durability: auth_account
            .claude_anchor_durability
            .or(existing.claude_anchor_durability),
        claude_anchor_health: auth_account
            .claude_anchor_health
            .or(existing.claude_anchor_health),
        billing_identity_confidence: if auth_account.billing_identity_confidence
            != AgentStatusConfidence::Unknown
        {
            auth_account.billing_identity_confidence
        } else {
            existing.billing_identity_confidence
        },
        confidence: auth_account.confidence,
    }
}

fn normalize_plan_type(value: String) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(|c: char| c.is_whitespace() || c == '-' || c == '/', "_")
}

fn chatgpt_subscription_product(plan_type: String) -> String {
    if plan_type.starts_with("chatgpt_") {
        plan_type
    } else {
        format!("chatgpt_{plan_type}")
    }
}

fn parse_claude_auth_json(value: &Value) -> AgentAccountStatus {
    let login_state = match first_json_string(
        value,
        &["status", "state", "login_state", "logged_in", "loggedIn"],
    )
    .as_deref()
    {
        Some("authenticated") | Some("signed_in") | Some("logged_in") | Some("true") => {
            AgentLoginState::SignedIn
        }
        Some("signed_out") | Some("logged_out") | Some("unauthenticated") | Some("false") => {
            AgentLoginState::SignedOut
        }
        _ => {
            if first_json_string(value, &["email", "account_email", "accountEmail"]).is_some() {
                AgentLoginState::SignedIn
            } else {
                AgentLoginState::Unknown
            }
        }
    };
    let plan_type = first_json_string(
        value,
        &[
            "subscription_type",
            "subscriptionType",
            "plan_type",
            "planType",
            "plan",
            "tier",
        ],
    )
    .map(normalize_plan_type);
    let api_provider = first_json_string(value, &["api_provider", "apiProvider"]);
    let organization_id = first_json_string(
        value,
        &["organization_id", "organizationId", "org_id", "orgId"],
    )
    .or_else(|| nested_json_string(value, &["organization", "org"], &["id"]));
    let organization_label = first_json_string(
        value,
        &[
            "organization_label",
            "organizationLabel",
            "organization_name",
            "organizationName",
            "org_name",
            "orgName",
        ],
    )
    .or_else(|| nested_json_string(value, &["organization", "org"], &["name", "label"]));
    let account_id = first_json_string(value, &["account_id", "accountId", "user_id", "userId"]);
    let account_identifier_hash = account_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "account", value));
    let organization_identifier_hash = organization_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "organization", value));
    let billing_identity_evidence = billing_identity_evidence_for(
        &account_identifier_hash,
        &organization_identifier_hash,
        &None,
    );
    AgentAccountStatus {
        login_state,
        provider: Some("anthropic".to_string()),
        auth_method: first_json_string(
            value,
            &[
                "auth_method",
                "authMethod",
                "auth_type",
                "authType",
                "method",
            ],
        )
        .or(Some("oauth".to_string())),
        email: first_json_string(value, &["email", "account_email", "accountEmail"]),
        account_id,
        organization_id,
        organization_label,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.clone().map(|plan| {
            if plan.starts_with("claude_") {
                plan
            } else {
                format!("claude_{plan}")
            }
        }),
        billing_channel: Some(claude_billing_channel(
            api_provider.as_deref(),
            plan_type.as_deref(),
        )),
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash,
        organization_identifier_hash,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence,
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    }
}

fn claude_billing_channel(api_provider: Option<&str>, plan_type: Option<&str>) -> String {
    match api_provider.map(|value| normalize_plan_type(value.to_string())) {
        Some(provider) if provider.contains("bedrock") => "amazon_bedrock".to_string(),
        Some(provider) if provider.contains("vertex") => "google_vertex".to_string(),
        Some(provider) if provider.contains("first_party") || provider.contains("firstparty") => {
            "subscription".to_string()
        }
        Some(provider) if provider.contains("anthropic") && plan_type.is_none() => {
            "direct_api".to_string()
        }
        _ if plan_type.is_some() => "subscription".to_string(),
        _ => "subscription".to_string(),
    }
}

/// Display-safe account metadata Claude Code itself persists to
/// `~/.claude.json` under `oauthAccount` after each profile refresh. The file
/// holds no tokens or secrets; it is the same class of local app state as the
/// Claude Desktop config and statusLine caches this collector already reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ClaudeCliOauthAccount {
    account_uuid: Option<String>,
    email_address: Option<String>,
    organization_uuid: Option<String>,
    /// Display only; replaces the `orgName` that `claude auth status` printed.
    organization_name: Option<String>,
    organization_type: Option<String>,
    seat_tier: Option<String>,
    organization_rate_limit_tier: Option<String>,
    user_rate_limit_tier: Option<String>,
}

/// Full-meter collection requires a signed-in account whose email and
/// organization UUID are both present and equal to the exact slot's local
/// account metadata before the account UUID from that identity file may become
/// strong meter identity. The account is now built from that same local
/// metadata (as `claude auth status` itself did), so this check keeps its old
/// requirement that both fields exist. Absence of contradiction is not
/// identity evidence.
fn require_claude_auth_identity_agreement(
    account: &AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Result<(), ClaudeSlotProbeFailure> {
    if account.login_state != AgentLoginState::SignedIn {
        return Err(ClaudeSlotProbeFailure::CredentialUnavailable);
    }
    let (Some(auth_email), Some(auth_organization)) =
        (account.email.as_deref(), account.organization_id.as_deref())
    else {
        return Err(ClaudeSlotProbeFailure::IdentityUnknown);
    };
    let (Some(local_email), Some(local_organization)) = (
        oauth.email_address.as_deref(),
        oauth.organization_uuid.as_deref(),
    ) else {
        return Err(ClaudeSlotProbeFailure::IdentityUnknown);
    };
    if !auth_email.trim().eq_ignore_ascii_case(local_email.trim())
        || !auth_organization
            .trim()
            .eq_ignore_ascii_case(local_organization.trim())
    {
        return Err(ClaudeSlotProbeFailure::IdentityMismatch);
    }
    Ok(())
}

/// Local claims only: compare with the accepted slot binding, never adopt.
/// Use the established local login classifier before granting launch or
/// nickname authority. The exact passwd home is used for file fallback.
/// No provider executable is invoked. Test reads are scratch-only and never
/// consult the real Keychain, including on the native CI lane.
pub(crate) fn session_launch_claude_login_state(
    slot: &ClaudeConfigDirSlot,
    home: &Path,
) -> ClaudeLocalLoginState {
    let read_file = || {
        let path = slot.credentials_path(home);
        if !crate::provider_calls::readable_for_account(&path) {
            return ClaudeCredentialRead::Unreadable;
        }
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ClaudeCredentialRead::Absent
            }
            Err(_) => return ClaudeCredentialRead::Unreadable,
        };
        let Ok(metadata) = file.metadata() else {
            return ClaudeCredentialRead::Unreadable;
        };
        if !metadata.is_file()
            || metadata.len() > 1024 * 1024
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return ClaudeCredentialRead::Unreadable;
        }
        let mut body = String::new();
        if file
            .take(1024 * 1024 + 1)
            .read_to_string(&mut body)
            .is_err()
            || body.len() > 1024 * 1024
        {
            return ClaudeCredentialRead::Unreadable;
        }
        parse_claude_oauth_credential_read(&body)
    };
    #[cfg(all(target_os = "macos", not(test)))]
    let read =
        match read_claude_oauth_credential_from_keychain_with_timeout(slot, Duration::from_secs(2))
        {
            ClaudeKeychainRead::Found(payload) => parse_claude_oauth_credential_read(&payload),
            ClaudeKeychainRead::NotFound => read_file(),
            ClaudeKeychainRead::Failed => ClaudeCredentialRead::Unreadable,
        };
    #[cfg(any(not(target_os = "macos"), test))]
    let read = read_file();
    claude_local_login_state(&read, OffsetDateTime::now_utc())
}

pub(crate) fn session_launch_claude_identity(
    slot: &ClaudeConfigDirSlot,
    home: &Path,
) -> Option<(String, String)> {
    let identity = read_claude_cli_oauth_account(&slot.identity_path(home))?;
    Some((
        billing_identity_hash("anthropic", "account", identity.account_uuid.as_deref()?)?,
        billing_identity_hash(
            "anthropic",
            "organization",
            identity.organization_uuid.as_deref()?,
        )?,
    ))
}

/// Match Codex's explicit-mode precedence. ChatGPT login can retain an
/// exchanged API key; explicit API/unknown modes cannot inherit stale OAuth.
pub(crate) fn session_launch_codex_api_key_route(home: &Path, trust: CodexHomeTrust) -> bool {
    let Some(value) = ottto_core::read_codex_auth_file_secure(home, trust)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return false;
    };
    if let Some(mode) = value.get("auth_mode").filter(|mode| !mode.is_null()) {
        return mode.as_str() != Some("chatgpt");
    }
    // Legacy inference is used only without an explicit mode.
    [
        "OPENAI_API_KEY",
        "personal_access_token",
        "bedrock_api_key",
        "bedrock_access_keys",
    ]
    .iter()
    .any(|key| value.get(key).is_some_and(|value| !value.is_null()))
}

/// Accepted registered Codex slots (never a process-only home), login cause.
pub(crate) fn registered_codex_creator_slots() -> Vec<(String, String, usize)> {
    let Ok(status) = FileCodexAccountSlotSettingsStore::default().load() else {
        return Vec::new();
    };
    let env_api_key = ["OPENAI_API_KEY", "CODEX_API_KEY"]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()));
    let slots = codex_home_slots(&status).into_iter();
    slots
        .filter_map(|slot| {
            let (account, workspace) = slot.registered_binding?;
            let cause = codex_slot_login_cause(&slot.home, env_api_key);
            Some((account, workspace, cause))
        })
        .collect()
}

/// Named only with forced ChatGPT config, `chatgpt` auth mode and no API key
/// there or in the env; unreadable refuses. Only these fields are decoded.
pub(crate) fn codex_slot_login_cause(home: &Path, env_api_key: bool) -> usize {
    use crate::codex_scan_diagnostics::*;
    #[derive(Deserialize)]
    struct SavedLogin {
        auth_mode: Option<String>,
        #[serde(rename = "OPENAI_API_KEY", default)]
        api_key: Option<serde::de::IgnoredAny>,
    }
    let config = ottto_core::read_codex_config_file_secure(home, CodexHomeTrust::Managed);
    let forced = config.ok().flatten().and_then(|body| {
        let config: toml_edit::DocumentMut = String::from_utf8(body).ok()?.parse().ok()?;
        Some(config.get("forced_login_method")?.as_str()? == "chatgpt")
    });
    let auth = ottto_core::read_codex_auth_file_secure(home, CodexHomeTrust::Managed);
    let saved = auth.ok().flatten();
    let saved = saved.and_then(|auth| serde_json::from_slice::<SavedLogin>(&auth).ok());
    match saved.filter(|saved| saved.auth_mode.as_deref() == Some("chatgpt")) {
        _ if forced != Some(true) => CREATOR_NOT_FORCED_CHATGPT,
        None => CREATOR_MODE_UNREADABLE,
        Some(saved) if saved.api_key.is_some() || env_api_key => CREATOR_API_KEY,
        Some(_) => CREATOR_NAMED,
    }
}

pub(crate) fn session_launch_codex_identity(
    home: &Path,
    trust: CodexHomeTrust,
) -> Option<(String, String)> {
    if session_launch_codex_api_key_route(home, trust) {
        return None;
    }
    let credential = read_codex_auth_credentials_at(home, trust).ok()??;
    let (account, workspace) = codex_credential_claimed_ids(&credential)?;
    Some((
        billing_identity_hash("openai", "account", &account)?,
        billing_identity_hash("openai", "workspace", &workspace)?,
    ))
}

fn read_claude_cli_oauth_account(path: &Path) -> Option<ClaudeCliOauthAccount> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    parse_claude_cli_oauth_account(&value)
}

fn parse_claude_cli_oauth_account(value: &Value) -> Option<ClaudeCliOauthAccount> {
    let account = value.get("oauthAccount")?;
    if !account.is_object() {
        return None;
    }
    let field = |key: &str| {
        account
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    Some(ClaudeCliOauthAccount {
        account_uuid: field("accountUuid"),
        email_address: field("emailAddress"),
        organization_uuid: field("organizationUuid"),
        organization_name: field("organizationName"),
        organization_type: field("organizationType"),
        seat_tier: field("seatTier"),
        organization_rate_limit_tier: field("organizationRateLimitTier"),
        user_rate_limit_tier: field("userRateLimitTier"),
    })
}

/// Identity guard shared by every consumer of `~/.claude.json` account
/// metadata: the file can lag behind `claude auth status` after an account
/// switch, so metadata is only trusted when neither the email nor the
/// organization contradicts the auth-status identity. A field absent on
/// either side is not a mismatch — only two present-and-different values
/// refuse.
fn claude_cli_oauth_identity_mismatch(
    account: &AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> bool {
    let mismatch = |ours: &Option<String>, theirs: &Option<String>| match (ours, theirs) {
        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b.trim()),
        _ => false,
    };
    mismatch(&account.email, &oauth.email_address)
        || mismatch(&account.organization_id, &oauth.organization_uuid)
}

/// Stamp the Claude account identity from the local Claude Code account
/// metadata (`~/.claude.json` `oauthAccount`) onto the auth-status account.
/// `claude auth status --json` names the organization but not the account
/// uuid, so without this the CLI plan observation reaches the backend with an
/// organization hash only while the quota windows from the very same
/// `oauthAccount` carry the account hash — plan and quota evidence then
/// resolve at different ranks and cannot deterministically converge.
///
/// Same identity guard as the seat/tier refinements above: stale metadata
/// from a different account must never be stamped, and a present auth-status
/// account id that disagrees with `accountUuid` also refuses. Uses the exact
/// `billing_identity_hash("anthropic", "account", …)` the quota path stamps,
/// never a second hashing implementation.
fn stamp_claude_cli_account_identity(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> bool {
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return false;
    }
    let Some(account_uuid) = oauth.account_uuid.as_deref() else {
        return false;
    };
    if let Some(existing) = account.account_id.as_deref() {
        if !existing.eq_ignore_ascii_case(account_uuid.trim()) {
            return false;
        }
    }
    let Some(account_identifier_hash) = billing_identity_hash("anthropic", "account", account_uuid)
    else {
        return false;
    };
    if account.account_id.is_none() {
        account.account_id = Some(account_uuid.to_string());
    }
    if account.account_identifier_hash.is_none() {
        account.account_identifier_hash = Some(account_identifier_hash);
    }
    account.billing_identity_evidence = billing_identity_evidence_for(
        &account.account_identifier_hash,
        &account.organization_identifier_hash,
        &account.credential_fingerprint_hash,
    );
    true
}

/// Outcome of the local-metadata plan refinements, one field per rule.
#[derive(Debug, Default, PartialEq, Eq)]
struct RefinedClaudeLocalPlan {
    seat_plan: Option<&'static str>,
    max_plan: Option<&'static str>,
}

/// Apply every local-metadata plan refinement to a freshly parsed Claude
/// account.
///
/// The stored `subscriptionType` (what `claude auth status` printed) is a bare
/// `team` for every seat tier and a bare `max` for BOTH Max tiers, so the only
/// disambiguator is the rate-limit / seat metadata in the slot's own
/// `.claude.json`. Every collector must run these refinements, not just the
/// default slot:
/// a registered (`CLAUDE_CONFIG_DIR`) slot left unrefined ships a bare plan,
/// and the backend then prices the conservative lower bound — a Max 20x
/// account reads as Max 5x ($100 instead of $200), a Team Premium seat as
/// Team Standard ($25 instead of $125).
///
/// Callers must have already established identity agreement between `account`
/// and `oauth`; each rule additionally re-checks identity itself.
fn refine_claude_local_plan_metadata(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> RefinedClaudeLocalPlan {
    // Mutually exclusive by plan_type gate (`team` vs `max`).
    RefinedClaudeLocalPlan {
        seat_plan: refine_claude_team_seat_plan(account, oauth),
        max_plan: refine_claude_max_rate_limit_plan(account, oauth),
    }
}

/// Refine a generic Claude `team` plan into `team_premium` / `team_standard`
/// when the local Claude Code account metadata carries an explicit seat-tier
/// signal. Mirrors the Claude Max 5x/20x rule: explicit collector evidence
/// only, never a guess — an unrecognized or absent signal leaves the generic
/// `team` plan untouched. Premium detection accepts either a literal
/// `seatTier` value or the `*_max_5x` rate-limit tier, which is the signal
/// Claude Code's own internals use to identify a premium Team seat.
fn refine_claude_team_seat_plan(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Option<&'static str> {
    if account.plan_type.as_deref() != Some("team") {
        return None;
    }
    // Identity guard: `~/.claude.json` can lag behind `claude auth status`
    // after an account switch. Refuse to mix metadata across accounts.
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return None;
    }
    if let Some(organization_type) = oauth.organization_type.as_deref() {
        if normalize_plan_type(organization_type.to_string()) != "claude_team" {
            return None;
        }
    }
    let seat_tier = oauth
        .seat_tier
        .clone()
        .map(normalize_plan_type)
        .unwrap_or_default();
    // Only the user-level rate-limit tier can prove a per-seat tier: Team
    // orgs mix Standard and Premium seats, so the org-wide tier says nothing
    // about THIS seat.
    let rate_limit_tier = oauth
        .user_rate_limit_tier
        .clone()
        .map(normalize_plan_type)
        .unwrap_or_default();
    let seat_plan = if seat_tier.contains("premium") || rate_limit_tier.ends_with("max_5x") {
        "team_premium"
    } else if seat_tier.contains("standard") {
        "team_standard"
    } else {
        return None;
    };
    account.plan_type = Some(seat_plan.to_string());
    account.subscription_product = Some(format!("claude_{seat_plan}"));
    Some(seat_plan)
}

/// Refine a generic Claude `max` plan into `max_5x` / `max_20x` when the local
/// Claude Code account metadata carries an explicit rate-limit tier. Mirrors
/// `refine_claude_team_seat_plan`: explicit collector evidence only, never a
/// guess — `claude auth status` reports bare `max` for BOTH Max tiers, so an
/// absent or unrecognized signal leaves the generic plan untouched (the
/// backend prices that as the conservative lower bound). Max is an individual
/// plan, so the organization-level rate-limit tier speaks for the account;
/// the user-level tier is accepted as a same-shaped fallback.
fn refine_claude_max_rate_limit_plan(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Option<&'static str> {
    if account.plan_type.as_deref() != Some("max") {
        return None;
    }
    // Identity guard: `~/.claude.json` can lag behind `claude auth status`
    // after an account switch. Refuse to mix metadata across accounts.
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return None;
    }
    if let Some(organization_type) = oauth.organization_type.as_deref() {
        if normalize_plan_type(organization_type.to_string()) != "claude_max" {
            return None;
        }
    }
    let tier_signal = |value: &Option<String>| -> Option<&'static str> {
        let normalized = value.clone().map(normalize_plan_type)?;
        if normalized.ends_with("max_5x") {
            Some("max_5x")
        } else if normalized.ends_with("max_20x") {
            Some("max_20x")
        } else {
            None
        }
    };
    let refined = tier_signal(&oauth.organization_rate_limit_tier)
        .or_else(|| tier_signal(&oauth.user_rate_limit_tier))?;
    account.plan_type = Some(refined.to_string());
    account.subscription_product = Some(format!("claude_{refined}"));
    Some(refined)
}

#[cfg(test)]
fn parse_codex_text_model(text: &str) -> Option<AgentModelStatus> {
    let model = text.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if lower.contains("model") {
            line.split(':')
                .nth(1)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value
                        .trim_matches(|c: char| c == '"' || c == '\'' || c == '`')
                        .to_string()
                })
        } else {
            None
        }
    });
    model.map(|active_model| AgentModelStatus {
        active_model: Some(active_model.clone()),
        default_model: Some(active_model),
        provider: Some("openai".to_string()),
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    })
}

#[cfg(test)]
fn parse_codex_text_quota_windows(text: &str) -> Vec<AgentQuotaWindow> {
    let mut windows = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("quota") && !lower.contains("limit") && !lower.contains("remaining") {
            continue;
        }
        let left_percent = extract_percent_before(&lower, &["left", "remaining"]);
        let used_percent = extract_percent_before(&lower, &["used"]);
        if left_percent.is_some() || used_percent.is_some() {
            let left =
                left_percent.or_else(|| used_percent.map(|used| 100_u8.saturating_sub(used)));
            windows.push(AgentQuotaWindow {
                name: "usage".to_string(),
                scope: AgentQuotaWindowScope::Source,
                status: match left {
                    Some(0) => AgentQuotaWindowStatus::Exhausted,
                    Some(value) if value <= 20 => AgentQuotaWindowStatus::NearLimit,
                    Some(_) => AgentQuotaWindowStatus::Ok,
                    None => AgentQuotaWindowStatus::Unknown,
                },
                freshness: AgentQuotaWindowFreshness::Fresh,
                model: None,
                account_label: None,
                window_seconds: None,
                started_at: None,
                resets_at: None,
                quota: None,
                remaining: None,
                used_percent,
                left_percent: left,
                ..Default::default()
            });
        }
    }
    windows
}

#[cfg(test)]
fn parse_codex_text_context(text: &str) -> Option<AgentContextStatus> {
    let context_line = text
        .lines()
        .map(str::to_ascii_lowercase)
        .find(|line| line.contains("context"))?;
    let used_percent = extract_percent_before(&context_line, &["used", "context"]);
    Some(AgentContextStatus {
        status: AgentContextState::Available,
        active_tokens: None,
        max_tokens: None,
        used_percent,
        remaining_tokens: None,
        source: Some("codex_status_text".to_string()),
        recent_samples: Vec::new(),
        observed_at: None,
        completeness: Some(AgentContextCompleteness::FullPressure),
        reason: Some("codex_status_text_observed".to_string()),
        posture: None,
    })
}

fn collect_model_status_from_output(output: &CommandOutput, provider: &str) -> AgentModelStatus {
    let mut models = BTreeSet::new();
    if output.command_found && output.success {
        if let Ok(json) = serde_json::from_str::<Value>(&output.stdout) {
            collect_model_names_from_json(&json, &mut models);
        } else {
            for line in output.stdout.lines() {
                let trimmed = line.trim().trim_matches(|c: char| {
                    c == '-' || c == '*' || c == '"' || c == '\'' || c == '`' || c.is_whitespace()
                });
                if looks_like_model_name(trimmed) {
                    models.insert(trimmed.to_string());
                }
            }
        }
    }
    AgentModelStatus {
        active_model: models.iter().next().cloned(),
        default_model: models.iter().next().cloned(),
        provider: Some(provider.to_string()),
        available_models: models.into_iter().take(MAX_AVAILABLE_MODELS).collect(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    }
}

fn collect_codex_model_status_from_output(output: &CommandOutput) -> AgentModelStatus {
    if !output.command_found || !output.success {
        return collect_model_status_from_output(output, "openai");
    }
    let Ok(json) = serde_json::from_str::<Value>(&output.stdout) else {
        return collect_model_status_from_output(output, "openai");
    };
    let Some(models) = json.get("models").and_then(Value::as_array) else {
        return collect_model_status_from_output(output, "openai");
    };

    let mut details = Vec::new();
    let mut seen = BTreeSet::new();
    for model in models {
        let Some(model) = model.as_object() else {
            continue;
        };
        let id = ["slug", "id", "model", "name"]
            .iter()
            .find_map(|key| model.get(*key).and_then(Value::as_str))
            .map(str::trim)
            .filter(|value| looks_like_model_name(value) && looks_like_safe_model_id(value));
        let Some(id) = id else {
            continue;
        };
        if id.chars().any(char::is_whitespace) || !seen.insert(id.to_string()) {
            continue;
        }
        let context_window_tokens = model
            .get("context_window")
            .or_else(|| model.get("max_context_window"))
            .and_then(Value::as_u64);
        let max_output_tokens = model
            .get("max_output_tokens")
            .or_else(|| model.get("max_output"))
            .and_then(Value::as_u64);
        let supports_thinking = model
            .get("supported_reasoning_levels")
            .and_then(Value::as_array)
            .map(|levels| !levels.is_empty())
            .or_else(|| {
                model
                    .get("supports_reasoning_summaries")
                    .and_then(Value::as_bool)
            });
        let supports_images = model
            .get("input_modalities")
            .and_then(Value::as_array)
            .map(|modalities| {
                modalities
                    .iter()
                    .any(|value| value.as_str() == Some("image"))
            })
            .or_else(|| {
                model
                    .get("supports_image_detail_original")
                    .and_then(Value::as_bool)
            });
        details.push(AgentAvailableModelStatus {
            id: id.to_string(),
            provider: Some("openai".to_string()),
            model_provider: Some("openai".to_string()),
            // The bundled-model list identifies the model provider, not the
            // account's actual billing route (subscription, API, or gateway).
            billing_provider: None,
            billing_channel: None,
            auth_mode: None,
            gateway_provider: None,
            subscription_product: None,
            source_category: None,
            account_identifier_hash: None,
            organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: None,
            billing_identity_confidence: AgentStatusConfidence::Unknown,
            context_window_tokens,
            max_output_tokens,
            supports_thinking,
            supports_images,
        });
        if details.len() >= MAX_AVAILABLE_MODELS {
            break;
        }
    }

    if details.is_empty() {
        return collect_model_status_from_output(output, "openai");
    }
    let default_model = details.first().map(|detail| detail.id.clone());
    let context_window_tokens = details
        .first()
        .and_then(|detail| detail.context_window_tokens);
    AgentModelStatus {
        active_model: default_model.clone(),
        default_model,
        provider: Some("openai".to_string()),
        available_models: details.iter().map(|detail| detail.id.clone()).collect(),
        available_model_details: details,
        context_window_tokens,
    }
}

pub(crate) fn read_pi_smoke_routes() -> Vec<PiModelRoute> {
    if let Some(settings) = read_pi_agent_settings() {
        if let Some(route) = collect_default_pi_smoke_route_from_settings(&settings) {
            return vec![route];
        }
    }
    Vec::new()
}

fn apply_codex_config_model(
    model_status: &mut AgentModelStatus,
    config_model: Option<String>,
    collection_method: &mut AgentStatusCollectionMethod,
) {
    let Some(config_model) = config_model else {
        return;
    };
    let config_model = config_model.trim();
    if config_model.is_empty() {
        return;
    }
    let config_model = config_model.to_string();
    let only_config_available = model_status.available_models.is_empty();
    model_status.active_model = Some(config_model.clone());
    model_status.default_model = Some(config_model.clone());
    if !model_status
        .available_models
        .iter()
        .any(|model| model == &config_model)
    {
        let mut available_models = Vec::with_capacity(model_status.available_models.len() + 1);
        available_models.push(config_model.clone());
        available_models.extend(
            model_status
                .available_models
                .iter()
                .filter(|model| model.trim() != config_model.as_str())
                .take(MAX_AVAILABLE_MODELS.saturating_sub(1))
                .cloned(),
        );
        model_status.available_models = available_models;
    }
    model_status.context_window_tokens = model_status
        .available_model_details
        .iter()
        .find(|detail| detail.id == config_model)
        .and_then(|detail| detail.context_window_tokens);
    if only_config_available && *collection_method == AgentStatusCollectionMethod::CommandProbe {
        *collection_method = AgentStatusCollectionMethod::ConfigFile;
    }
}

fn collect_pi_model_status(
    settings: Option<&Value>,
    list_models: Option<&CommandOutput>,
    auth: Option<&Value>,
) -> AgentModelStatus {
    if let Some(settings) = settings {
        let status = collect_pi_model_status_from_settings(settings, auth);
        if !status.available_models.is_empty() || status.default_model.is_some() {
            return status;
        }
    }
    if let Some(output) = list_models {
        return collect_pi_model_status_from_output(output, auth);
    }
    AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: None,
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    }
}

fn collect_pi_model_status_from_settings(
    settings: &Value,
    auth: Option<&Value>,
) -> AgentModelStatus {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let mut routes = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(enabled_models) = settings
        .get("enabledModels")
        .or_else(|| settings.get("enabled_models"))
    {
        collect_pi_enabled_model_routes(
            enabled_models,
            default_provider.as_deref(),
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    if let (Some(provider), Some(model)) = (default_provider.as_deref(), default_model.as_deref()) {
        push_pi_model_route(
            provider,
            model,
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    let details: Vec<AgentAvailableModelStatus> = routes
        .iter()
        .map(|route| {
            let identity = pi_identity_hints_for_route(auth, route);
            pi_model_detail_from_route(route, None, None, None, None, Some(&identity))
        })
        .collect();
    let providers: BTreeSet<&str> = details
        .iter()
        .filter_map(|detail| detail.provider.as_deref())
        .collect();
    AgentModelStatus {
        active_model: default_model.clone(),
        default_model,
        provider: match providers.len() {
            0 => default_provider,
            1 => providers
                .iter()
                .next()
                .map(|provider| (*provider).to_string()),
            _ => Some("multi_provider".to_string()),
        },
        available_models: details
            .iter()
            .map(|detail| detail.id.clone())
            .take(MAX_AVAILABLE_MODELS)
            .collect(),
        available_model_details: details.into_iter().take(MAX_AVAILABLE_MODELS).collect(),
        context_window_tokens: None,
    }
}

#[cfg(test)]
fn collect_pi_routes_from_settings(settings: &Value) -> Vec<PiModelRoute> {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let mut routes = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(enabled_models) = settings
        .get("enabledModels")
        .or_else(|| settings.get("enabled_models"))
    {
        collect_pi_enabled_model_routes(
            enabled_models,
            default_provider.as_deref(),
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    if let (Some(provider), Some(model)) = (default_provider.as_deref(), default_model.as_deref()) {
        push_pi_model_route(
            provider,
            model,
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    routes
}

fn collect_default_pi_smoke_route_from_settings(settings: &Value) -> Option<PiModelRoute> {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let provider = default_provider.as_deref()?;
    let model = default_model.as_deref()?;
    PiModelRoute::new(provider, model, default_thinking.as_deref())
}

fn collect_pi_enabled_model_routes(
    value: &Value,
    default_provider: Option<&str>,
    default_thinking: Option<&str>,
    seen: &mut BTreeSet<(Option<String>, String)>,
    routes: &mut Vec<PiModelRoute>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_pi_enabled_model_routes(
                    item,
                    default_provider,
                    default_thinking,
                    seen,
                    routes,
                );
            }
        }
        Value::Object(map) => {
            if let Some(enabled) = map.get("enabled").and_then(Value::as_bool) {
                if !enabled {
                    return;
                }
            }
            let provider = first_json_string(
                value,
                &["provider", "defaultProvider", "provider_id", "providerId"],
            )
            .or_else(|| default_provider.map(ToString::to_string));
            let model = first_json_string(value, &["model", "id", "model_id", "modelId", "name"]);
            if let (Some(provider), Some(model)) = (provider.as_deref(), model.as_deref()) {
                let thinking = first_json_string(
                    value,
                    &["thinkingLevel", "thinking_level", "defaultThinkingLevel"],
                )
                .or_else(|| default_thinking.map(ToString::to_string));
                push_pi_model_route(provider, model, thinking.as_deref(), seen, routes);
                return;
            }
            for nested in map.values() {
                collect_pi_enabled_model_routes(
                    nested,
                    default_provider,
                    default_thinking,
                    seen,
                    routes,
                );
            }
        }
        Value::String(route) => {
            if let Some((provider, model, route_thinking)) =
                parse_pi_route_string(route, default_provider)
            {
                let thinking = route_thinking.as_deref().or(default_thinking);
                push_pi_model_route(&provider, &model, thinking, seen, routes);
            }
        }
        _ => {}
    }
}

fn parse_pi_route_string(
    route: &str,
    default_provider: Option<&str>,
) -> Option<(String, String, Option<String>)> {
    let trimmed = route.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (route_body, thinking_level) = parse_pi_route_thinking_suffix(trimmed);
    for separator in ["/", ":"] {
        if let Some((provider, model)) = route_body.split_once(separator) {
            if looks_like_safe_model_id(model) && !provider.trim().is_empty() {
                return Some((
                    provider.trim().to_string(),
                    model.trim().to_string(),
                    thinking_level,
                ));
            }
        }
    }
    default_provider
        .filter(|_| looks_like_safe_model_id(route_body))
        .map(|provider| (provider.to_string(), route_body.to_string(), thinking_level))
}

fn parse_pi_route_thinking_suffix(route: &str) -> (&str, Option<String>) {
    let Some((body, suffix)) = route.rsplit_once(':') else {
        return (route, None);
    };
    let suffix = suffix.trim();
    if !body.contains('/') || !looks_like_pi_thinking_level(suffix) {
        return (route, None);
    }
    (body.trim(), Some(suffix.to_ascii_lowercase()))
}

fn looks_like_pi_thinking_level(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "none" | "off" | "low" | "medium" | "high" | "xhigh"
    )
}

fn push_pi_model_route(
    provider: &str,
    model: &str,
    thinking_level: Option<&str>,
    seen: &mut BTreeSet<(Option<String>, String)>,
    routes: &mut Vec<PiModelRoute>,
) {
    let Some(route) = PiModelRoute::new(provider, model, thinking_level) else {
        return;
    };
    let key = (Some(route.provider.clone()), route.model.clone());
    if !seen.insert(key) {
        return;
    }
    routes.push(route);
}

fn pi_model_detail_from_route(
    route: &PiModelRoute,
    context_window_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    supports_thinking: Option<bool>,
    supports_images: Option<bool>,
    billing_identity: Option<&BillingIdentityHints>,
) -> AgentAvailableModelStatus {
    let identity = billing_identity.cloned().unwrap_or_default();
    AgentAvailableModelStatus {
        id: route.model.clone(),
        provider: Some(route.provider.clone()),
        model_provider: route.classification.model_provider.clone(),
        billing_provider: route.classification.billing_provider.clone(),
        billing_channel: route.classification.billing_channel.clone(),
        auth_mode: route.classification.auth_mode.clone(),
        gateway_provider: route.classification.gateway_provider.clone(),
        subscription_product: route.classification.subscription_product.clone(),
        source_category: route.classification.source_category.clone(),
        account_identifier_hash: identity.account_identifier_hash,
        organization_identifier_hash: identity.organization_identifier_hash,
        credential_fingerprint_hash: identity.credential_fingerprint_hash,
        billing_identity_evidence: identity.billing_identity_evidence,
        billing_identity_confidence: identity.billing_identity_confidence,
        context_window_tokens,
        max_output_tokens,
        supports_thinking: supports_thinking.or_else(|| {
            route
                .thinking_level
                .as_deref()
                .map(|value| value != "none" && value != "off")
        }),
        supports_images,
    }
}

fn collect_pi_model_status_from_output(
    output: &CommandOutput,
    auth: Option<&Value>,
) -> AgentModelStatus {
    let mut details = Vec::new();
    let mut seen = BTreeSet::new();
    if output.command_found && output.success {
        let text = command_output_text(output);
        for line in text.lines() {
            let Some(detail) = parse_pi_model_table_line(line, auth) else {
                continue;
            };
            if seen.insert((detail.provider.clone(), detail.id.clone())) {
                details.push(detail);
            }
            if details.len() >= MAX_AVAILABLE_MODELS {
                break;
            }
        }
    }
    let available_models = details.iter().map(|detail| detail.id.clone()).collect();
    let providers: BTreeSet<&str> = details
        .iter()
        .filter_map(|detail| detail.provider.as_deref())
        .collect();
    AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: match providers.len() {
            0 => None,
            1 => providers
                .iter()
                .next()
                .map(|provider| (*provider).to_string()),
            _ => Some("multi_provider".to_string()),
        },
        available_models,
        available_model_details: details,
        context_window_tokens: None,
    }
}

fn parse_pi_model_table_line(
    line: &str,
    auth: Option<&Value>,
) -> Option<AgentAvailableModelStatus> {
    let mut parts = line.split_whitespace();
    let provider = parts.next()?;
    let model = parts.next()?;
    if provider == "provider" || model == "model" {
        return None;
    }
    let context = parts.next();
    let max_output = parts.next();
    let thinking = parts.next();
    let images = parts.next();
    if provider.is_empty() || model.is_empty() || !looks_like_safe_model_id(model) {
        return None;
    }
    let route = PiModelRoute::new(provider, model, None)?;
    let identity = pi_identity_hints_for_route(auth, &route);
    Some(pi_model_detail_from_route(
        &route,
        context.and_then(parse_pi_token_count),
        max_output.and_then(parse_pi_token_count),
        thinking.and_then(parse_yes_no),
        images.and_then(parse_yes_no),
        Some(&identity),
    ))
}

fn command_output_text(output: &CommandOutput) -> String {
    match (
        output.stdout.trim().is_empty(),
        output.stderr.trim().is_empty(),
    ) {
        (true, true) => String::new(),
        (false, true) => output.stdout.clone(),
        (true, false) => output.stderr.clone(),
        (false, false) => format!("{}\n{}", output.stdout, output.stderr),
    }
}

fn parse_yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

fn parse_pi_token_count(value: &str) -> Option<u64> {
    let trimmed = value.trim().replace(',', "");
    if trimmed.is_empty() {
        return None;
    }
    let (number, multiplier) = match trimmed.chars().last()? {
        'K' | 'k' => (&trimmed[..trimmed.len() - 1], 1_000_f64),
        'M' | 'm' => (&trimmed[..trimmed.len() - 1], 1_000_000_f64),
        _ => (trimmed.as_str(), 1_f64),
    };
    number
        .parse::<f64>()
        .ok()
        .map(|value| (value * multiplier).round() as u64)
}

fn pi_route_classification(provider: &str, model: &str) -> PiRouteClassification {
    let provider = normalize_pi_provider(provider);
    let model_key = model.to_ascii_lowercase();
    match provider.as_str() {
        "openai-codex" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("chatgpt".to_string()),
            source_category: Some("chatgpt_openai_subscription".to_string()),
        },
        "openai" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("openai_api_key".to_string()),
        },
        "google-vertex" => PiRouteClassification {
            model_provider: Some("google".to_string()),
            billing_provider: Some("google".to_string()),
            billing_channel: Some("google_vertex".to_string()),
            auth_mode: Some("service_account".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("google_cloud_vertex".to_string()),
        },
        "google" | "google-gemini" => PiRouteClassification {
            model_provider: Some("google".to_string()),
            billing_provider: Some("google".to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("google_gemini_api_key".to_string()),
        },
        "amazon-bedrock" | "aws-bedrock" => {
            let model_provider = infer_pi_model_provider_from_model(&model_key)
                .unwrap_or_else(|| "amazon".to_string());
            PiRouteClassification {
                model_provider: Some(model_provider.clone()),
                billing_provider: Some(model_provider),
                billing_channel: Some("amazon_bedrock".to_string()),
                auth_mode: Some("service_account".to_string()),
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("aws_bedrock".to_string()),
            }
        }
        "azure-openai-responses" | "azure-openai" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("azure_openai".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("azure_openai".to_string()),
        },
        "cloudflare-ai-gateway" | "cloudflare-workers-ai" => {
            gateway_classification("cloudflare", &model_key)
        }
        "openrouter" => gateway_classification("openrouter", &model_key),
        "vercel-ai-gateway" => gateway_classification("vercel_ai_gateway", &model_key),
        "github-copilot" => PiRouteClassification {
            model_provider: infer_pi_model_provider_from_model(&model_key),
            billing_provider: Some("github".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("github_copilot".to_string()),
            source_category: Some("unknown".to_string()),
        },
        "anthropic" | "claude" | "claude-code" => PiRouteClassification {
            model_provider: Some("anthropic".to_string()),
            billing_provider: Some("anthropic".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("claude".to_string()),
            source_category: Some("unknown".to_string()),
        },
        other => PiRouteClassification {
            model_provider: infer_pi_model_provider_from_model(&model_key),
            billing_provider: Some(other.to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("unknown".to_string()),
        },
    }
}

fn gateway_classification(gateway_provider: &str, model_key: &str) -> PiRouteClassification {
    PiRouteClassification {
        model_provider: infer_pi_model_provider_from_model(model_key),
        billing_provider: Some(gateway_provider.to_string()),
        billing_channel: Some("gateway".to_string()),
        auth_mode: Some("api_key".to_string()),
        gateway_provider: Some(gateway_provider.to_string()),
        subscription_product: None,
        source_category: Some("gateway".to_string()),
    }
}

fn normalize_pi_provider(provider: &str) -> String {
    provider
        .trim()
        .to_ascii_lowercase()
        .replace('_', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
}

fn infer_pi_model_provider_from_model(model_key: &str) -> Option<String> {
    let model_key = model_key.trim().to_ascii_lowercase();
    if model_key.is_empty() {
        return None;
    }
    if model_key.contains("anthropic.") || model_key.contains("claude") {
        return Some("anthropic".to_string());
    }
    if model_key.starts_with("openai.")
        || model_key.starts_with("gpt-")
        || model_key.starts_with("o1")
        || model_key.starts_with("o3")
        || model_key.starts_with("o4")
    {
        return Some("openai".to_string());
    }
    if model_key.starts_with("google.")
        || model_key.starts_with("gemini")
        || model_key.contains(".gemini")
    {
        return Some("google".to_string());
    }
    if model_key.starts_with("meta.") || model_key.contains("llama") {
        return Some("meta".to_string());
    }
    if model_key.starts_with("mistral.") || model_key.contains("mistral") {
        return Some("mistral".to_string());
    }
    if model_key.starts_with("xai.") || model_key.contains("grok") {
        return Some("xai".to_string());
    }
    if let Some((prefix, _)) = model_key.split_once('.') {
        if !matches!(prefix, "global" | "us" | "eu" | "apac") {
            return Some(prefix.to_string());
        }
    }
    None
}

fn collect_model_names_from_json(value: &Value, models: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if matches!(key.as_str(), "id" | "model" | "name" | "slug") {
                    if let Some(model) =
                        nested.as_str().filter(|value| looks_like_model_name(value))
                    {
                        models.insert(model.to_string());
                    }
                }
                collect_model_names_from_json(nested, models);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_model_names_from_json(item, models);
            }
        }
        Value::String(value) if looks_like_model_name(value) => {
            models.insert(value.clone());
        }
        _ => {}
    }
}

fn looks_like_model_name(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 2 || value.len() > 128 || value.contains('/') || value.contains('\\') {
        return false;
    }
    if is_codex_automatic_review_model_label(value) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    lower.contains("gpt")
        || lower.contains("claude")
        || lower.contains("gemini")
        || lower.contains("o3")
        || lower.contains("o4")
        || lower.contains("o5")
        || lower.contains("model")
}

fn is_codex_automatic_review_model_label(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let tokens = lower
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    tokens.contains(&"automatic")
        && tokens.contains(&"approval")
        && tokens.contains(&"review")
        && tokens.contains(&"codex")
}

fn looks_like_safe_model_id(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 2 || value.len() > 128 || value.contains('\\') {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    !lower.contains("/users/")
        && !lower.contains("/home/")
        && !lower.contains("/.codex")
        && !lower.contains("/.claude")
        && !lower.contains("/.pi/")
}

fn read_codex_config_model_at(codex_home: &Path, home_trust: CodexHomeTrust) -> Option<String> {
    let body = ottto_core::read_codex_config_file_secure(codex_home, home_trust).ok()??;
    let body = std::str::from_utf8(&body).ok()?;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains('=') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key != "model" && key != "default_model" {
            continue;
        }
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if looks_like_model_name(value) {
            return Some(value.to_string());
        }
    }
    None
}

fn read_pi_safe_auth_metadata() -> Option<Value> {
    for path in [
        pi_agent_auth_path(),
        home_path(".pi/auth.json"),
        home_path(".pi/profile.json"),
        home_path(".pi/config.json"),
    ] {
        if let Ok(body) = fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<Value>(&body) {
                return Some(strip_secret_json(json));
            }
        }
    }
    None
}

pub(crate) fn read_pi_agent_auth() -> Option<Value> {
    let body = fs::read_to_string(pi_agent_auth_path()).ok()?;
    serde_json::from_str::<Value>(&body).ok()
}

fn read_pi_agent_settings() -> Option<Value> {
    let body = fs::read_to_string(pi_agent_settings_path()).ok()?;
    serde_json::from_str::<Value>(&body)
        .ok()
        .map(strip_secret_json)
}

/// Pi's agent directory, resolved as Pi itself does: a non-empty
/// `PI_CODING_AGENT_DIR`, taken as written (no trim) with a leading `~`
/// expanded against `home`, else `~/.pi/agent`. The scanner, the status
/// reader and the Verify census all use this one rule.
pub(crate) fn pi_agent_dir(home: &Path) -> PathBuf {
    pi_agent_dir_from(home, std::env::var_os("PI_CODING_AGENT_DIR"))
}

/// Where Pi writes its sessions: `sessions` under its agent directory.
pub(crate) fn pi_sessions_dir(home: &Path) -> PathBuf {
    pi_agent_dir(home).join("sessions")
}

fn pi_agent_dir_from(home: &Path, value: Option<std::ffi::OsString>) -> PathBuf {
    match value.filter(|value| !value.is_empty()).map(PathBuf::from) {
        Some(dir) => match dir.strip_prefix("~") {
            Ok(rest) if rest.as_os_str().is_empty() => home.to_path_buf(),
            Ok(rest) => home.join(rest),
            Err(_) => dir,
        },
        None => home.join(".pi").join("agent"),
    }
}

fn pi_agent_auth_path() -> PathBuf {
    pi_agent_dir(&home_dir()).join("auth.json")
}

fn pi_agent_settings_path() -> PathBuf {
    pi_agent_dir(&home_dir()).join("settings.json")
}

fn pi_auth_entry<'a>(auth: &'a Value, provider: &str) -> Option<&'a Value> {
    let Value::Object(map) = auth else {
        return None;
    };
    let provider_lower = provider.trim().to_ascii_lowercase();
    let mut aliases = vec![provider_lower.clone(), provider_lower.replace('-', "_")];
    aliases.push(
        match provider_lower.as_str() {
            "openai-codex" | "openai_codex" => "openai",
            "google-vertex" | "google_vertex" | "vertex" => "google",
            "anthropic-api" | "anthropic_api" => "anthropic",
            other => other,
        }
        .to_string(),
    );
    aliases.iter().find_map(|alias| map.get(alias.as_str()))
}

fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn openai_codex_account_id_from_auth_entry(entry: &Value) -> Option<String> {
    first_json_string(
        entry,
        &[
            "accountId",
            "account_id",
            "chatgpt_account_id",
            "chatgptAccountId",
        ],
    )
    .or_else(|| {
        for key in [
            "accessToken",
            "access_token",
            "idToken",
            "id_token",
            "token",
        ] {
            let token = first_json_string(entry, &[key])?;
            let claims = jwt_claims(&token)?;
            let auth_claim = claims.get("https://api.openai.com/auth");
            if let Some(account_id) = auth_claim.and_then(|value| {
                first_json_string(value, &["chatgpt_account_id", "chatgpt_user_id", "user_id"])
            }) {
                return Some(account_id);
            }
            if let Some(subject) = first_json_string(&claims, &["sub"]) {
                return Some(subject);
            }
        }
        None
    })
}

pub(crate) fn pi_identity_hints_for_route(
    auth: Option<&Value>,
    route: &PiModelRoute,
) -> BillingIdentityHints {
    let Some(entry) = auth.and_then(|auth| pi_auth_entry(auth, &route.provider)) else {
        return BillingIdentityHints::default();
    };
    let provider_for_hash = route
        .classification
        .billing_provider
        .as_deref()
        .unwrap_or(route.provider.as_str());
    let auth_type = first_json_string(entry, &["type", "auth_type", "authType", "auth_method"])
        .map(normalize_plan_type);

    let mut account_identifier_hash = None;
    let mut organization_identifier_hash = None;
    let mut credential_fingerprint_hash = None;
    let mut evidence = None;

    if route.provider.eq_ignore_ascii_case("openai-codex")
        || route.provider.eq_ignore_ascii_case("openai_codex")
    {
        account_identifier_hash = openai_codex_account_id_from_auth_entry(entry)
            .as_deref()
            .and_then(|value| billing_identity_hash("openai", "account", value));
    }

    if matches!(
        route.classification.billing_channel.as_deref(),
        Some("google_vertex")
    ) {
        organization_identifier_hash = first_json_string(
            entry,
            &[
                "projectId",
                "project_id",
                "quota_project_id",
                "quotaProjectId",
                "billing_project",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash("google_vertex", "project", value));
        credential_fingerprint_hash = first_json_string(
            entry,
            &[
                "client_email",
                "clientEmail",
                "service_account",
                "serviceAccount",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash("google_vertex", "service_account", value));
        if organization_identifier_hash.is_some() {
            evidence = Some("cloud_project_id".to_string());
        }
    }

    if route.classification.auth_mode.as_deref() == Some("api_key")
        || auth_type.as_deref() == Some("api_key")
    {
        credential_fingerprint_hash = first_json_string(
            entry,
            &[
                "key",
                "api_key",
                "apiKey",
                "access_key",
                "accessKey",
                "secret_access_key",
                "secretAccessKey",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash(provider_for_hash, "credential", value));
    }

    if evidence.is_none() {
        evidence = billing_identity_evidence_for(
            &account_identifier_hash,
            &organization_identifier_hash,
            &credential_fingerprint_hash,
        );
    }
    let billing_identity_confidence = if evidence.is_some() {
        AgentStatusConfidence::High
    } else {
        AgentStatusConfidence::Unknown
    };
    BillingIdentityHints {
        account_identifier_hash,
        organization_identifier_hash,
        credential_fingerprint_hash,
        billing_identity_evidence: evidence,
        billing_identity_confidence,
    }
}

fn strip_secret_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter_map(|(key, nested)| {
                    let lower = key.to_ascii_lowercase();
                    if lower.contains("token")
                        || lower.contains("secret")
                        || lower.contains("password")
                        || lower.contains("key")
                        || lower.contains("cookie")
                    {
                        None
                    } else {
                        Some((key, strip_secret_json(nested)))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(strip_secret_json).collect()),
        other => other,
    }
}

fn first_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(nested) = map.get(*key) {
                    match nested {
                        Value::String(value) if !value.trim().is_empty() => {
                            return Some(value.trim().to_string())
                        }
                        Value::Bool(value) => return Some(value.to_string()),
                        Value::Number(value) => return Some(value.to_string()),
                        _ => {}
                    }
                }
            }
            for nested in map.values() {
                if let Some(value) = first_json_string(nested, keys) {
                    return Some(value);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|item| first_json_string(item, keys)),
        _ => None,
    }
}

fn json_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(number) = nested.as_u64() {
            return Some(number);
        }
        if let Some(number) = nested.as_i64().and_then(|value| u64::try_from(value).ok()) {
            return Some(number);
        }
        if let Some(number) = nested.as_f64() {
            if number.is_finite() && number >= 0.0 {
                return Some(number.round() as u64);
            }
        }
        if let Some(text) = nested.as_str() {
            if let Ok(number) = text.trim().parse::<u64>() {
                return Some(number);
            }
            if let Ok(number) = text.trim().parse::<f64>() {
                if number.is_finite() && number >= 0.0 {
                    return Some(number.round() as u64);
                }
            }
        }
    }
    None
}

fn json_u8(value: &Value, keys: &[&str]) -> Option<u8> {
    json_u64(value, keys).map(|value| value.min(100) as u8)
}

fn json_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(boolean) = nested.as_bool() {
            return Some(boolean);
        }
        if let Some(text) = nested.as_str() {
            match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => return Some(true),
                "false" | "0" | "no" => return Some(false),
                _ => {}
            }
        }
    }
    None
}

fn rfc3339_minus_seconds(timestamp: &str, seconds: u64) -> Option<String> {
    let parsed = OffsetDateTime::parse(timestamp, &Rfc3339).ok()?;
    let duration = TimeDuration::seconds(i64::try_from(seconds).ok()?);
    (parsed - duration).format(&Rfc3339).ok()
}

fn json_timestamp_rfc3339(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(nested) = value.get(*key) else {
            continue;
        };
        if let Some(text) = nested
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if let Ok(parsed) = OffsetDateTime::parse(text, &Rfc3339) {
                return parsed.format(&Rfc3339).ok();
            }
            if let Ok(seconds) = text.parse::<i64>() {
                return OffsetDateTime::from_unix_timestamp(seconds)
                    .ok()
                    .and_then(|value| value.format(&Rfc3339).ok());
            }
            if let Ok(seconds) = text.parse::<f64>() {
                if seconds.is_finite() {
                    return OffsetDateTime::from_unix_timestamp(seconds.round() as i64)
                        .ok()
                        .and_then(|value| value.format(&Rfc3339).ok());
                }
            }
        }
        if let Some(seconds) = nested.as_i64() {
            return OffsetDateTime::from_unix_timestamp(seconds)
                .ok()
                .and_then(|value| value.format(&Rfc3339).ok());
        }
        if let Some(seconds) = nested.as_u64().and_then(|value| i64::try_from(value).ok()) {
            return OffsetDateTime::from_unix_timestamp(seconds)
                .ok()
                .and_then(|value| value.format(&Rfc3339).ok());
        }
        if let Some(seconds) = nested.as_f64() {
            if seconds.is_finite() {
                return OffsetDateTime::from_unix_timestamp(seconds.round() as i64)
                    .ok()
                    .and_then(|value| value.format(&Rfc3339).ok());
            }
        }
    }
    None
}

fn nested_json_string(value: &Value, object_keys: &[&str], value_keys: &[&str]) -> Option<String> {
    let Value::Object(map) = value else {
        return None;
    };
    for key in object_keys {
        if let Some(nested) = map.get(*key) {
            if let Some(value) = first_json_string(nested, value_keys) {
                return Some(value);
            }
        }
    }
    None
}

fn unsupported_account(provider: &str) -> AgentAccountStatus {
    AgentAccountStatus {
        login_state: AgentLoginState::Unsupported,
        provider: Some(provider.to_string()),
        auth_method: None,
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: None,
        subscription_product: None,
        billing_channel: None,
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash: None,
        organization_identifier_hash: None,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::Unknown,
        confidence: AgentStatusConfidence::Unknown,
    }
}

fn unsupported_quota_window(name: &str) -> AgentQuotaWindow {
    AgentQuotaWindow {
        name: name.to_string(),
        scope: AgentQuotaWindowScope::Source,
        status: AgentQuotaWindowStatus::Unsupported,
        freshness: AgentQuotaWindowFreshness::Unsupported,
        model: None,
        account_label: None,
        window_seconds: None,
        started_at: None,
        resets_at: None,
        quota: None,
        remaining: None,
        used_percent: None,
        left_percent: None,
        ..Default::default()
    }
}

fn unsupported_context(
    source: &str,
    reason: &str,
    observed_at: Option<String>,
) -> AgentContextStatus {
    AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some(source.to_string()),
        recent_samples: Vec::new(),
        observed_at,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some(reason.to_string()),
        posture: None,
    }
}

fn supported_capability(capability: &str, detail: &str) -> AgentCapabilityGap {
    AgentCapabilityGap {
        capability: capability.to_string(),
        status: AgentCapabilityStatus::Supported,
        detail: Some(detail.to_string()),
    }
}

fn unsupported_capability(capability: &str, detail: &str) -> AgentCapabilityGap {
    AgentCapabilityGap {
        capability: capability.to_string(),
        status: AgentCapabilityStatus::Unsupported,
        detail: Some(detail.to_string()),
    }
}

fn command_diagnostic(code: &str, message: &str, output: &CommandOutput) -> AgentStatusDiagnostic {
    let status = output
        .status_code
        .map(|code| format!(" exit {code}"))
        .unwrap_or_default();
    let stderr_hint = if output.stderr.trim().is_empty() {
        String::new()
    } else {
        " stderr redacted".to_string()
    };
    AgentStatusDiagnostic::source(
        code,
        AgentDiagnosticSeverity::Warning,
        format!("{message}{status}.{stderr_hint}"),
    )
}

fn extract_email(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|token| {
            token.trim_matches(|c: char| {
                c == '<' || c == '>' || c == ',' || c == ';' || c == ':' || c == '"' || c == '\''
            })
        })
        .find(|token| {
            let parts: Vec<&str> = token.split('@').collect();
            parts.len() == 2
                && !parts[0].is_empty()
                && parts[1].contains('.')
                && !token.contains('/')
        })
        .map(ToString::to_string)
}

fn extract_plan_type(text: &str, candidates: &[&str]) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    candidates
        .iter()
        .find(|candidate| lower.contains(**candidate))
        .map(|candidate| candidate.to_string())
}

#[cfg(test)]
fn extract_percent_before(text: &str, markers: &[&str]) -> Option<u8> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let mut start = index;
            while start > 0 && bytes[start - 1].is_ascii_digit() {
                start -= 1;
            }
            if start < index {
                if let Ok(value) = text[start..index].parse::<u8>() {
                    let context_start = start.saturating_sub(24);
                    let context_end = (index + 24).min(text.len());
                    let context = &text[context_start..context_end];
                    if markers.iter().any(|marker| context.contains(marker)) {
                        return Some(value.min(100));
                    }
                }
            }
        }
        index += 1;
    }
    None
}

fn run_command_capture(program: &str, args: &[&str], timeout: Duration) -> CommandOutput {
    run_command_capture_with_exact_env(program, args, timeout)
}

fn run_codex_home_command(
    codex_home: &Path,
    args: &[&str],
    timeout: Duration,
    allow_ambient_environment: bool,
) -> CommandOutput {
    let Some(mut command) =
        resolved_codex_home_command(codex_home, args, allow_ambient_environment)
    else {
        return CommandOutput {
            command_found: false,
            success: false,
            status_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_prepared_command_capture(command, timeout)
}

/// `codex login` for one managed home, with the same binary, PATH and clean
/// environment as the home's quota reads. `None` when Codex is not found.
pub(crate) fn codex_login_command(codex_home: &Path) -> Option<Command> {
    resolved_codex_home_command(codex_home, &["login"], false)
}

/// Resolve Codex once and run it with one exact credential home. Ambient
/// provider credentials are deliberately excluded so a managed slot cannot
/// silently fall back to the default account or an API key.
fn resolved_codex_home_command(
    codex_home: &Path,
    args: &[&str],
    _allow_ambient_environment: bool,
) -> Option<Command> {
    let identity = effective_user_identity()?;
    let program_path = crate::command_env::executable_path("codex")?;
    let mut command = Command::new(program_path);
    command.args(args).env_clear();
    command
        .env("HOME", &identity.home_dir)
        .env("USER", identity.account_name)
        .env("CODEX_HOME", codex_home)
        .env("CODEX_SQLITE_HOME", codex_home);
    for locale_key in ["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = std::env::var_os(locale_key) {
            command.env(locale_key, value);
        }
    }
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    Some(command)
}

/// Resolve Claude once and apply the single shared sanitized exact-slot
/// environment used by the browser sign-in and the background refresher. No
/// provider or token-shaped ambient variables survive `env_clear`.
pub(crate) fn resolved_claude_slot_command(
    slot: &ClaudeConfigDirSlot,
    args: &[&str],
) -> Option<Command> {
    let identity = effective_user_identity()?;
    let program_path = crate::command_env::claude_executable_path(&identity.home_dir)?;
    let mut command = Command::new(program_path);
    command
        .args(args)
        .env_clear()
        .env("HOME", &identity.home_dir)
        .env("USER", identity.account_name);
    for locale_key in ["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = std::env::var_os(locale_key) {
            command.env(locale_key, value);
        }
    }
    if let Some(path_env) = crate::command_env::claude_path_env(&identity.home_dir) {
        command.env("PATH", path_env);
    }
    match slot.config_dir() {
        Some(config_dir) => {
            command.env("CLAUDE_CONFIG_DIR", config_dir);
        }
        None => {
            command.env_remove("CLAUDE_CONFIG_DIR");
        }
    }
    Some(command)
}

fn run_command_capture_with_exact_env(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> CommandOutput {
    let Some(program_path) = crate::command_env::executable_path(program) else {
        return CommandOutput {
            command_found: false,
            success: false,
            status_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    };
    let mut command = Command::new(program_path);
    command.args(args);
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_prepared_command_capture(command, timeout)
}

fn run_prepared_command_capture(mut command: Command, timeout: Duration) -> CommandOutput {
    let start = Instant::now();
    let mut child = match crate::local_resource_diagnostics::cli_children::spawn(&mut command) {
        Ok(child) => child,
        Err(_) => {
            return CommandOutput {
                command_found: false,
                success: false,
                status_code: None,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
    };

    let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
    let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: status.success(),
                    status_code: status.code(),
                    stdout,
                    stderr,
                };
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                let _ = child.kill();
                let stdout = collect_pipe_reader(stdout_reader, PIPE_DRAIN_TIMEOUT);
                let stderr = collect_pipe_reader(stderr_reader, PIPE_DRAIN_TIMEOUT);
                return CommandOutput {
                    command_found: true,
                    success: false,
                    status_code: None,
                    stdout,
                    stderr,
                };
            }
        }
    }
}

fn spawn_pipe_reader<R>(mut pipe: R) -> mpsc::Receiver<String>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut output = String::new();
        let _ = pipe.read_to_string(&mut output);
        let _ = sender.send(output);
    });
    receiver
}

fn collect_pipe_reader(reader: Option<mpsc::Receiver<String>>, timeout: Duration) -> String {
    reader
        .and_then(|receiver| receiver.recv_timeout(timeout).ok())
        .unwrap_or_default()
}

fn executable_exists(program: &str) -> bool {
    crate::command_env::executable_path(program).is_some()
}

fn default_codex_home() -> PathBuf {
    home_path(".codex")
}

fn home_path(relative: &str) -> PathBuf {
    home_dir().join(relative)
}

pub(crate) fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

/// Local display supplement only: never contributes billing/account evidence.
pub(crate) fn claude_session_registrations() -> crate::claude_session_registrations::Registrations {
    #[cfg(not(test))]
    {
        crate::claude_session_registrations::collect(&home_path(".claude/sessions"))
    }
    // Ordinary unit tests must not acquire the operator's provider state.
    #[cfg(test)]
    crate::claude_session_registrations::Registrations::default()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod usage_checks_paused_tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;
    const ACCOUNT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ACCOUNT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ORG: &str = "oooooooooooooooooooooooooooooooo";

    fn stale_quota() -> ClaudeConfigSlotQuotaSnapshotV1 {
        ClaudeConfigSlotQuotaSnapshotV1 {
            state: ClaudeConfigSlotQuotaSnapshotStateV1::Stale,
            captured_at: "2026-10-03T05:04:35Z".to_string(),
            observed_at: Some("2026-10-03T05:04:35Z".to_string()),
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
        }
    }

    fn paused_slot(account: &str) -> ClaudeConfigSlotCollectionStatusV1 {
        let mut status = provider_unavailable_status("2026-10-03T06:46:48Z", account, ORG);
        status.quota_snapshot = Some(stale_quota());
        status.quota_check_diagnostics = vec![AgentStatusDiagnostic::source(
            "claude_oauth_usage_circuit_open",
            AgentDiagnosticSeverity::Warning,
            "The local quota circuit is open after authentication rejection.",
        )];
        status
    }

    fn healthy_slot(account: &str) -> ClaudeConfigSlotCollectionStatusV1 {
        fresh_slot_status("2026-10-03T06:30:56Z", account, ORG, true, true, false)
    }

    fn current_login() -> AgentStatusSnapshot {
        base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::ConfigFile,
            "2026-10-03T06:46:07Z".to_string(),
            "2026-10-03T06:51:07Z".to_string(),
        )
    }

    fn auth_breaker(reopen_after: u64) -> ClaudeOAuthUsageBreaker {
        ClaudeOAuthUsageBreaker {
            schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
            account_identifier_hash: ACCOUNT_A.to_string(),
            organization_identifier_hash: ORG.to_string(),
            opened_by: "auth_rejected".to_string(),
            reopen_after_epoch_seconds: reopen_after,
            ..Default::default()
        }
    }

    fn no_breaker(_: &str, _: &str) -> Option<ClaudeOAuthUsageBreaker> {
        None
    }

    #[test]
    fn paused_account_reports_plain_words_with_next_check() {
        let slots = BTreeMap::from([
            ("slot-paused".to_string(), paused_slot(ACCOUNT_A)),
            ("slot-healthy".to_string(), healthy_slot(ACCOUNT_B)),
        ]);
        let reopen = NOW + 3_600;
        let paused = claude_paused_usage_accounts(
            &slots,
            &current_login(),
            |account, _| (account == ACCOUNT_A).then(|| auth_breaker(reopen)),
            NOW,
        );
        assert_eq!(
            paused,
            vec![ClaudePausedUsageAccount {
                after_sign_in_rejection: true,
                next_check_epoch_seconds: Some(reopen),
            }]
        );
        let diagnostic = claude_usage_checks_paused_diagnostic(&paused).expect("diagnostic");
        assert_eq!(diagnostic.code, CLAUDE_USAGE_CHECKS_PAUSED_DIAGNOSTIC_CODE);
        assert_eq!(diagnostic.severity, AgentDiagnosticSeverity::Warning);
        let expected_at = rfc3339_from_unix_seconds(reopen).expect("time");
        assert_eq!(
            diagnostic.message,
            format!(
                "Claude usage checks paused for one account after the provider rejected sign-in; next automatic check {expected_at}. Last readings stay shown until then."
            )
        );
        let lowered = diagnostic.message.to_ascii_lowercase();
        for forbidden in [
            "sign in again",
            "log in",
            "login",
            "reconnect",
            "quota",
            "limit",
        ] {
            assert!(!lowered.contains(forbidden), "{forbidden}: {lowered}");
        }
        assert!(diagnostic.account_identifier_hash.is_none());
    }

    fn held(backoff_until: u64) -> ClaudeOAuthUsageCallerAuthState {
        ClaudeOAuthUsageCallerAuthState {
            consecutive_failures: 1,
            last_status: 401,
            last_failure_at_epoch_seconds: NOW - 60,
            backoff_until_epoch_seconds: backoff_until,
            credential_expires_at: None,
        }
    }

    fn caller_hold_breaker(caller_key: String, backoff_until: u64) -> ClaudeOAuthUsageBreaker {
        let mut breaker = auth_breaker(0);
        breaker.opened_by = String::new();
        breaker.auth_callers.insert(caller_key, held(backoff_until));
        breaker
    }

    #[test]
    fn account_genuinely_served_by_a_second_credential_is_not_paused() {
        // The held slot's own caller is backing off, but a different, eligible
        // credential for the same account is reading it.
        let slots = BTreeMap::from([
            ("slot-held".to_string(), paused_slot(ACCOUNT_A)),
            ("slot-fresh".to_string(), healthy_slot(ACCOUNT_A)),
        ]);
        let paused = claude_paused_usage_accounts(
            &slots,
            &current_login(),
            |_, _| {
                Some(caller_hold_breaker(
                    claude_oauth_usage_slot_caller_key("slot-held"),
                    NOW + 900,
                ))
            },
            NOW,
        );
        assert!(paused.is_empty());
    }

    #[test]
    fn young_shared_cache_on_a_held_slot_is_paused() {
        // A held slot can look Fresh while the shared per-account cache is
        // young; its caller cannot refresh it, so it does not serve the account.
        let slots = BTreeMap::from([("slot-held".to_string(), healthy_slot(ACCOUNT_A))]);
        let paused = claude_paused_usage_accounts(
            &slots,
            &current_login(),
            |_, _| {
                Some(caller_hold_breaker(
                    claude_oauth_usage_slot_caller_key("slot-held"),
                    NOW + 900,
                ))
            },
            NOW,
        );
        assert_eq!(
            paused,
            vec![ClaudePausedUsageAccount {
                after_sign_in_rejection: true,
                next_check_epoch_seconds: Some(NOW + 900),
            }]
        );
        // Once the hold has expired the same slot serves the account again.
        let paused = claude_paused_usage_accounts(
            &slots,
            &current_login(),
            |_, _| {
                Some(caller_hold_breaker(
                    claude_oauth_usage_slot_caller_key("slot-held"),
                    NOW - 1,
                ))
            },
            NOW,
        );
        assert!(paused.is_empty());
    }

    #[test]
    fn provider_unavailable_with_stale_readings_counts_without_auth_evidence() {
        let mut slot = provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_A, ORG);
        slot.quota_snapshot = Some(stale_quota());
        let slots = BTreeMap::from([("slot-a".to_string(), slot.clone())]);
        let paused = claude_paused_usage_accounts(&slots, &current_login(), no_breaker, NOW);
        assert_eq!(
            paused,
            vec![ClaudePausedUsageAccount {
                after_sign_in_rejection: false,
                next_check_epoch_seconds: None,
            }]
        );
        let message = claude_usage_checks_paused_diagnostic(&paused)
            .expect("diagnostic")
            .message;
        assert_eq!(
            message,
            "Claude usage checks paused for one account while the provider is not answering; Ottto checks again automatically. Last readings stay shown until then."
        );

        // Provider unavailable but readings not yet stale: not paused.
        slot.quota_snapshot = None;
        let slots = BTreeMap::from([("slot-a".to_string(), slot)]);
        assert!(claude_paused_usage_accounts(&slots, &current_login(), no_breaker, NOW).is_empty());
    }

    #[test]
    fn per_caller_hold_gives_the_earliest_next_check() {
        let mut breaker = auth_breaker(0);
        breaker.opened_by = String::new();
        breaker.auth_callers.insert(
            "default".to_string(),
            ClaudeOAuthUsageCallerAuthState {
                consecutive_failures: 1,
                last_status: 401,
                last_failure_at_epoch_seconds: NOW - 60,
                backoff_until_epoch_seconds: NOW + 900,
                credential_expires_at: None,
            },
        );
        breaker.auth_callers.insert(
            "slot-sha256:expired".to_string(),
            ClaudeOAuthUsageCallerAuthState {
                backoff_until_epoch_seconds: NOW - 1,
                ..Default::default()
            },
        );
        assert_eq!(
            claude_breaker_auth_pause_until(&breaker, NOW),
            Some(NOW + 900)
        );
        // An expired account-wide verdict does not count.
        let expired = auth_breaker(NOW - 1);
        assert_eq!(claude_breaker_auth_pause_until(&expired, NOW), None);
    }

    #[test]
    fn default_login_auth_pause_is_attributed_to_its_account() {
        let mut default_slot = provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_A, ORG);
        default_slot.quota_snapshot = None;
        let mut snapshot = current_login();
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            provider: None,
            auth_method: None,
            email: None,
            account_id: None,
            organization_id: None,
            organization_label: None,
            plan_type: None,
            subscription_product: None,
            billing_channel: None,
            subscription_period_start: None,
            subscription_period_end: None,
            subscription_period_last_checked_at: None,
            account_identifier_hash: Some(ACCOUNT_A.to_string()),
            organization_identifier_hash: Some(ORG.to_string()),
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: None,
            claude_quota_access_state: None,
            claude_anchor_durability: None,
            claude_anchor_health: None,
            billing_identity_confidence: AgentStatusConfidence::default(),
            confidence: AgentStatusConfidence::default(),
        });
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_oauth_usage_circuit_open",
            AgentDiagnosticSeverity::Warning,
            "Stopped calling the Claude OAuth usage endpoint after auth rejected; quota falls back to Claude Code's local statusLine for the next 1399 minute(s).",
        ));
        let slots = BTreeMap::from([("default".to_string(), default_slot)]);
        let paused = claude_paused_usage_accounts(&slots, &snapshot, no_breaker, NOW);
        assert_eq!(paused.len(), 1);
        assert!(paused[0].after_sign_in_rejection);

        // A shape-failure circuit is not a sign-in rejection.
        snapshot.diagnostics[0].message =
            "Stopped calling the Claude OAuth usage endpoint after response shape; quota falls back to Claude Code's local statusLine for the next 5 minute(s).".to_string();
        let slots = BTreeMap::from([(
            "default".to_string(),
            provider_unavailable_status("2026-10-03T06:46:48Z", ACCOUNT_A, ORG),
        )]);
        assert!(claude_paused_usage_accounts(&slots, &snapshot, no_breaker, NOW).is_empty());
    }
}

/// Phase 0 of the durable Claude login fix: status passes never spawn a
/// credential-using `claude`, paused slots resume on their own, and a locally
/// expired access token is never sent. Every test runs on throwaway HOME and
/// support dirs with a logging fake `claude`, a fixture-emitting fake
/// `security`, fresh usage caches and provider requests forbidden.
#[cfg(test)]
mod claude_login_phase0_tests {
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
            let percent = u8::try_from(account.0.bytes().map(u32::from).sum::<u32>() % 90 + 5)
                .expect("percent");
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
            claude_oauth_stamp_account_identity(
                &mut usage,
                &account_hash,
                Some(&organization_hash),
            );
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
            fs::write(
                self.items.join(format!("{}.json", slot.service_name())),
                serde_json::to_vec(&credential).expect("item"),
            )
            .expect("write item");
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
    /// login's keychain item once per pass.
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
            crate::claude_refresher::maybe_refresh(
                &fixture.slot_ids[0],
                &fixture.slot(0),
                &live,
                true
            ),
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
        let proof =
            verify_claude_local_identity(&fixture.slot_ids[0], &dir.to_string_lossy(), &now)
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
                .any(|diagnostic| diagnostic.code
                    == "claude_oauth_usage_deferred_to_registered_slot"),
            "a paused slot no longer owns the account's reads"
        );
        assert_eq!(provider_calls(), before + 1, "the default login asks once");
        assert_only_version_probes(&fixture.spawns(), "takeover");
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
        fs::write(
            fixture.items.join("Claude Code-credentials.json"),
            serde_json::json!({
                "claudeAiOauth": {
                    "accessToken": "",
                    "refreshToken": "",
                    "expiresAt": 0,
                    "scopes": ["user:inference"]
                }
            })
            .to_string(),
        )
        .expect("cleared item");
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
        let (account_hash, organization_hash) =
            Phase0Fixture::hashes(("account-lapse", "org-lapse"));
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
        let ambient_bedrock =
            |key: &str| (key == "CLAUDE_CODE_USE_BEDROCK").then(|| "1".to_string());
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
        let slot =
            ClaudeConfigDirSlot::registered(dir.to_string_lossy().to_string()).expect("slot");
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
}

crate::heap_layout_bound::fields!(AgentStatusCollection; snapshots, source_health_snapshot, codex_scan_homes, codex_home_bindings);

crate::heap_layout_bound::fields!(CodexHomeBinding; home, account_identifier_hash, workspace_identifier_hash, auth_modified_at);
