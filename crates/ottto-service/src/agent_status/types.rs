//! Status collection records, provider evidence, and shared state types.
//! Used by the agent-status facade and its provider collectors.
//! Keeps existing data shapes, constants, and inherent operations together.

use crate::agent_status::claude_oauth_usage_opaque_caller_key;
use crate::agent_status::claude_oauth_usage_slot_caller_key;
use crate::agent_status::looks_like_safe_model_id;
use crate::agent_status::pi_route_classification;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentCreditBalance;
use crate::agent_status::AgentQuotaWindow;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusPlanObservation;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeCliOauthAccount;
use crate::agent_status::ClaudeConfigSlotCollectionStateV1;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticCodeV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticV1;
use crate::agent_status::ClaudeUnresolvedAccountDescriptorV1;
use crate::agent_status::CodexAccountSlotCollectionStatusV1;
use crate::agent_status::CodexAccountSlotOwnershipV1;
use crate::agent_status::Deserialize;
use crate::agent_status::Duration;
use crate::agent_status::File;
use crate::agent_status::Mutex;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::OnceLock;
use crate::agent_status::PathBuf;
use crate::agent_status::PathStamp;
use crate::agent_status::Rfc3339;
use crate::agent_status::Serialize;
use crate::agent_status::Value;

pub(super) const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) const CODEX_APP_SERVER_TIMEOUT: Duration = Duration::from_secs(20);

pub(super) const CODEX_APP_SERVER_MAX_LINE_BYTES: usize = 256 * 1024;

pub(super) const CODEX_APP_SERVER_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;

pub(super) const CODEX_APP_SERVER_MAX_MESSAGES: usize = 256;

pub(super) const CODEX_APP_SERVER_CHANNEL_CAPACITY: usize = 16;

pub(super) const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(750);

pub(super) const MAX_AVAILABLE_MODELS: usize = 250;

pub(super) const CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

pub(super) const CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS: u64 = 15 * 60;

pub(super) const CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES: usize = 48;

pub(super) const CLAUDE_OAUTH_USAGE_ENDPOINT: &str = "https://api.anthropic.com/api/oauth/usage";

pub(super) const CLAUDE_OAUTH_BETA_HEADER: &str = "oauth-2025-04-20";

pub(super) const CLAUDE_OAUTH_USAGE_CACHE_FILE: &str = "usage-cache.json";

pub(super) const CLAUDE_OAUTH_USAGE_ACCOUNT_STATE_DIR: &str = "claude-oauth-usage/accounts";

pub(super) const CLAUDE_OAUTH_USAGE_LEGACY_CACHE_FILE: &str = "claude-code-oauth-usage-cache.json";

/// Display fallback only: how long a cached payload may still be rendered (as
/// `Stale`) when the endpoint cannot be reached. Not a refresh cadence.
pub(super) const CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Unused-account slot: one read per ~40 min per account binding (~36/day).
/// Sparse polling is half of the recorded provider-endpoints posture
/// (identify honestly, poll sparsely, circuit-break instead of adapting). The
/// activity-based slot in `claude_credit_pools` shortens this to 5 min while
/// the binding is in use on this Mac, and a fresh local statusLine reading
/// stands in for those reads.
pub(super) const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS: u64 = 40 * 60;

/// Half-width of the deterministic spread applied to the base cadence, giving
/// an effective gate in the 38-42 minute range.
pub(super) const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS: u64 = 2 * 60;

/// Spacing after a successful read: 5 min to the next read of the account,
/// pass to pass. Measured from the start of the collection pass that read
/// ([`claude_spacing_anchor`]), so the daemon's next 5-min pass finds an
/// in-use account due wherever in the pass its read falls; two reads can
/// therefore be up to the anchor cap closer than 5 min. Retry-After and
/// breaker holds are stored and checked separately and are never shortened
/// by it.
pub(super) const CLAUDE_OAUTH_USAGE_REFRESH_SECONDS: u64 = 5 * 60;

pub(super) const CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS: u64 = 5 * 60;

/// Off-switch sentinel: while this file exists in the daemon support dir the
/// Claude OAuth usage endpoint is never contacted and quota comes from the
/// sanctioned local statusLine surface only. The name is a fixed contract with
/// the macOS Companion toggle - do not rename it.
pub(crate) const CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE: &str =
    "claude-oauth-usage-network-disabled";

pub(super) const CLAUDE_OAUTH_USAGE_BREAKER_FILE: &str = "breaker.json";

pub(super) const CLAUDE_OAUTH_USAGE_LEGACY_BREAKER_FILE: &str = "claude-oauth-usage-breaker.json";

pub(super) const CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE: &str =
    ".claude-config-slot-collection-state.lock";

pub(super) const CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION: u16 = 1;

pub(super) const CLAUDE_QUOTA_ACCESS_CAPABILITY: &str = "claude_quota_access_state_v1";

pub(super) const CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION: u16 = 1;

/// How long the breaker stays open once tripped. Long on purpose: an open
/// breaker means we believe further calls could be unwelcome or useless, and a
/// short cool-down would just re-probe the same wall.
pub(super) const CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS: u64 = 24 * 60 * 60;

/// Consecutive 401/403 responses before the breaker opens. Low: an auth/scope
/// rejection that survives a retry is structural, not transient.
pub(super) const CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD: u32 = 3;

/// Consecutive unreadable/unrecognised 200 bodies (or a vanished endpoint)
/// before the breaker opens.
pub(super) const CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD: u32 = 3;

/// Consecutive 429s before the breaker opens. Higher than the other classes:
/// a single 429 is routine here and is already handled by the retry-after
/// backoff; this catches the sustained case that backoff never clears.
pub(super) const CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD: u32 = 5;

/// First backoff after one caller's credential is rejected with 401/403. It
/// doubles for each further consecutive rejection of the same caller; once the
/// caller reaches `CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD` it holds the full
/// breaker cool-down. Other callers for the same account are not held.
pub(super) const CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS: u64 = 15 * 60;

pub(super) static CLAUDE_OAUTH_COLLECTION_ATTEMPT_LOCKS: OnceLock<
    Mutex<BTreeMap<String, &'static Mutex<()>>>,
> = OnceLock::new();

pub(super) static CLAUDE_OAUTH_LEGACY_MIGRATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) static CLAUDE_SLOT_COLLECTION_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) const CLAUDE_DESKTOP_CODE_SESSION_MAX_FILES_PER_ORG: usize = 500;

pub(super) const CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG: usize = 200;

pub(super) const CLAUDE_DESKTOP_DUPLICATE_SESSION_OBSERVATION_MAX: usize = 64;

/// Most plan observations one Desktop pair status carries: exact pairs first,
/// then their duplicate-session observations. The backend accepts at most 20
/// plan observations per snapshot and refuses the whole upload over it.
pub(super) const CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX: usize = 20;

/// The backend accepts at most this many status snapshots in one upload.
pub(super) const AGENT_STATUS_UPLOAD_SNAPSHOT_MAX: usize = 10;

// Reuse the daemon's existing detected-use/session retention contract. This
// warning is a view of the same local activity evidence, not a new lifetime.
pub(super) const CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS: i64 =
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
pub(super) struct CommandOutput {
    pub(super) command_found: bool,
    pub(super) success: bool,
    pub(super) status_code: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

#[derive(Debug, Clone)]
pub(super) struct CodexAuthCredentials {
    pub(super) access_token: Option<String>,
    pub(super) id_token: Option<String>,
    pub(super) account_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CodexCredentialReadError;

#[derive(Clone)]
pub(super) struct CodexUsageProbe {
    pub(super) quota_windows: Vec<AgentQuotaWindow>,
    pub(super) credit_balances: Vec<AgentCreditBalance>,
    pub(super) account: Option<AgentAccountStatus>,
    /// The provider read succeeded and named no account at all
    /// (`account: null`). Codex answers that once a refresh of the home's
    /// login failed for good, so a managed home then needs a new sign-in.
    pub(super) provider_account_absent: bool,
    /// Set by a provider read only; a saved reading carries `saved_identity`.
    pub(super) identity: Option<CodexStrongIdentity>,
    /// The identity hashes of a saved reading, whose provider validation
    /// happened when it was read (see `codex_saved_quota`).
    pub(super) saved_identity: Option<CodexIdentityHashes>,
    pub(super) credential_read_failed: bool,
    /// Completion of the app-server read, distinct from quota value changes.
    pub(super) response_completed_at: Option<String>,
    /// Fixed vocabulary and aggregate counts only; never provider ids/titles.
    pub(super) reset_credit_detail_summary: Option<String>,
    /// Counts-only view of the non-selected rate-limit pools.
    pub(super) rate_limit_pool_summary: Option<String>,
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
pub(super) struct CodexIdentityHashes {
    pub(super) account_identifier_hash: String,
    pub(super) workspace_identifier_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) superseded_account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) superseded_organization_identifier_hash: Option<String>,
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
pub(super) enum CodexQuotaRead {
    /// The home's saved reading (`codex_saved_quota`); never starts a
    /// provider read. Every status read uses this.
    Saved,
    /// Read the provider now (one `codex app-server` run) and save the
    /// outcome. Only the refresh schedule, an explicit refresh and setup
    /// checks use this.
    Provider,
}

#[derive(Clone)]
pub(super) struct CodexHomeSlot {
    pub(super) slot_id: String,
    pub(super) ownership: CodexAccountSlotOwnershipV1,
    pub(super) home: PathBuf,
    pub(super) registered_binding: Option<(String, String)>,
}

impl CodexHomeSlot {
    /// A home seen only through a running Codex process: read like an account
    /// home, but not registered.
    pub(super) fn process_home(home: PathBuf) -> Self {
        Self {
            slot_id: "process_home".to_string(),
            ownership: CodexAccountSlotOwnershipV1::Managed,
            home,
            registered_binding: None,
        }
    }
}

pub(super) struct CodexSlotCandidate {
    pub(super) slot: CodexHomeSlot,
    pub(super) snapshot: AgentStatusSnapshot,
    pub(super) status: CodexAccountSlotCollectionStatusV1,
    pub(super) binding: Option<(String, String)>,
    pub(super) workspace_targets: Vec<CodexWorkspaceTargetEvidence>,
    pub(super) quality: u8,
    pub(super) auth_modified_at: Option<std::time::SystemTime>,
}

#[derive(Clone)]
pub(super) struct CodexWorkspaceTargetEvidence {
    pub(super) account_identifier_hash: Option<String>,
    pub(super) workspace_identifier_hash: Option<String>,
    pub(super) workspace_label: Option<String>,
    /// Signed-in account name from the id_token `email` claim, sanitized through
    /// `safe_display_label`. Local-control display only; never uploaded.
    pub(super) account_label: Option<String>,
    /// Plan the credential claims via `chatgpt_plan_type`. It describes the
    /// workspace the credential is signed into, so it is carried only on the
    /// `is_default` evidence row; the other organizations in the same token have
    /// no claimed plan of their own.
    pub(super) plan_type: Option<String>,
    pub(super) is_default: bool,
    pub(super) observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ClaudeOAuthUsageCache {
    pub(super) schema_version: u16,
    /// Which Claude account the cached numbers belong to, as the same
    /// `billing_identity_hash` this collector uses everywhere else.
    ///
    /// The physical path is account-keyed, but every read still requires this
    /// field, the organization hash, and every embedded meter to agree exactly.
    #[serde(default)]
    pub(super) account_identifier_hash: String,
    /// Exact organization paired with the account when these meters were
    /// fetched. Both hashes and every embedded meter must agree on read.
    #[serde(default)]
    pub(super) organization_identifier_hash: String,
    pub(super) observed_at_epoch_seconds: u64,
    pub(super) next_refresh_after_epoch_seconds: u64,
    pub(super) windows: Vec<AgentQuotaWindow>,
    /// Usage-credit balances parsed from the same OAuth usage response.
    /// `serde(default)` permits safe parsing of older caches before their
    /// schema and identity are rejected.
    #[serde(default)]
    pub(super) credit_balances: Vec<AgentCreditBalance>,
    /// The response said this account has no account-wide weekly limit
    /// ([`claude_oauth_account_weekly_not_offered`]). Absent in older caches.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) account_weekly_not_offered: bool,
    /// The response said this account has no 5-hour session limit
    /// ([`claude_oauth_account_session_not_offered`]). Absent in older caches.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) account_session_not_offered: bool,
}

/// v4 adds organization identity and requires exact identity on every embedded
/// meter. Released v3 account-only caches cannot prove organization ownership
/// and are discarded rather than relabeled.
pub(super) const CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION: u16 = 4;

pub(super) const CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION: u16 = 3;

#[cfg(test)]
pub(super) static CLAUDE_OAUTH_PROVIDER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// `codex app-server` runs started by this test process: the seam that proves a
/// status read never starts one.
#[cfg(test)]
pub(super) static CODEX_APP_SERVER_RUNS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Tests that must never reach the provider set this: an attempted request is
/// still counted in `CLAUDE_OAUTH_PROVIDER_CALLS`, then refused locally.
#[cfg(test)]
pub(super) static CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Test-only hook run just before the final pre-request expiry check, to
/// simulate time passing (blocking I/O or sleep) inside the collection path.
#[cfg(test)]
pub(super) static CLAUDE_OAUTH_BEFORE_SEND_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

/// Everything the Claude OAuth usage endpoint yields in one fetch.
#[derive(Debug, Clone, Default)]
pub(super) struct ClaudeOAuthUsage {
    pub(super) windows: Vec<AgentQuotaWindow>,
    pub(super) credit_balances: Vec<AgentCreditBalance>,
    /// No account-wide weekly limit applies to this account (provider-stated),
    /// so a session window alone completes its account windows.
    pub(super) account_weekly_not_offered: bool,
    /// No 5-hour session limit applies (provider-stated; Max plans since
    /// late 2026), so a weekly window alone completes its account windows.
    pub(super) account_session_not_offered: bool,
}

/// A collection attempt plus anything the snapshot should say about *why* the
/// endpoint was or was not contacted. Diagnostics travel back to the caller
/// rather than being logged locally because they are the alerting channel:
/// snapshot diagnostics ride the agent-status upload to the backend (see
/// `AgentStatusSnapshot::redacted_for_backend`, which preserves `code` and
/// `message`), so an open breaker is visible server-side without a second
/// telemetry path.
#[derive(Debug)]
pub(super) struct ClaudeOAuthUsageOutcome {
    pub(super) result: Result<ClaudeOAuthUsage, String>,
    pub(super) diagnostics: Vec<AgentStatusDiagnostic>,
}

/// One source scan can now produce several Claude account snapshots while
/// local source health remains one row per source.
pub(crate) struct AgentStatusCollection {
    pub snapshots: Vec<AgentStatusSnapshot>,
    pub source_health_snapshot: AgentStatusSnapshot,
    pub codex_scan_homes: Vec<PathBuf>,
    pub codex_home_bindings: Vec<CodexHomeBinding>,
    /// Position in `snapshots` of the row the upload selected for the
    /// source's default login, recorded where the collector selects it. The
    /// setup scan sends that row; process-local, never serialized.
    pub setup_snapshot_index: Option<usize>,
}

impl AgentStatusCollection {
    /// The uploaded row the setup scan reports for this source, if any.
    pub(crate) fn setup_snapshot(&self) -> Option<&AgentStatusSnapshot> {
        self.snapshots.get(self.setup_snapshot_index?)
    }
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
pub(super) struct ResolvedClaudeSlot {
    pub(super) account: AgentAccountStatus,
    pub(super) account_identifier_hash: String,
    pub(super) organization_identifier_hash: String,
    pub(super) credential: ClaudeOAuthCredential,
}

/// One captured credential after display-safe identity stayed unchanged across
/// an exact-slot auth probe. The token is never debugged, serialized, logged,
/// persisted, or read a second time during the attempt.
pub(super) struct StableClaudeSlotCredential {
    pub(super) oauth_account: ClaudeCliOauthAccount,
    pub(super) credential: ClaudeOAuthCredential,
}

/// Exact-slot credential material read once per attempt. This type
/// deliberately implements neither `Debug` nor `Serialize`; only safe expiry
/// metadata can be copied into authenticated local status.
pub(super) struct ClaudeOAuthCredential {
    pub(super) access_token: Option<String>,
    /// Presence only. The refresh token itself is never retained, logged, or
    /// exposed; upkeep needs this bit to distinguish a signed-out credential
    /// from a refreshable expired access token.
    pub(super) has_refresh_token: bool,
    pub(super) access_expires_at: Option<String>,
    pub(super) relogin_required_at: Option<String>,
    /// `Some(true)` when the stored `scopes` list carries `user:inference`,
    /// `Some(false)` when the list lacks it, `None` when no list is stored.
    /// Claude Code itself reports `loggedIn` only for an inference-scoped
    /// token, so this is the same local evidence `claude auth status` used.
    pub(super) has_inference_scope: Option<bool>,
    /// The stored `scopes` list carries `user:profile`. Claude Code's
    /// `/usage` reads plan usage (and so refreshes the login first) only for
    /// such a login.
    pub(super) has_profile_scope: bool,
    /// The plan Claude Code stored with the login (`subscriptionType`), the
    /// same field `claude auth status` printed. Display metadata, not a secret.
    pub(super) subscription_type: Option<String>,
}

/// Seconds before the stored access deadline at which a login no longer counts
/// as usable. Claude Code itself refreshes inside a five-minute window; the
/// daemon never refreshes, so this only stops a usage read with a token that
/// is about to lapse.
pub(super) const CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS: i64 = 60;

/// What one local read of a Claude login found. `Absent` means there is no
/// stored OAuth login at all (no keychain item and no credentials file, or an
/// item without `claudeAiOauth`). `Unreadable` is every failed or malformed
/// read: callers fail closed on it and never treat it as "signed out".
pub(super) enum ClaudeCredentialRead {
    Absent,
    Unreadable,
    Present(ClaudeOAuthCredential),
}

impl ClaudeCredentialRead {
    pub(super) fn into_credential(self) -> Option<ClaudeOAuthCredential> {
        match self {
            Self::Present(credential) => Some(credential),
            Self::Absent | Self::Unreadable => None,
        }
    }

    pub(super) fn metadata(&self) -> Option<ClaudeOAuthCredentialMetadata> {
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

impl ClaudeOAuthCredential {
    /// The exact shape Claude Code writes after the token endpoint rejects a
    /// refresh (`invalid_grant`): no access token, no refresh token, and an
    /// `expiresAt` of 0. Only an official login or reconnect restores it.
    pub(super) fn cleared_by_cli(&self) -> bool {
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

pub(super) struct ClaudeSnapshotCandidate {
    pub(super) slot_id: String,
    pub(super) slot_class: ClaudeSnapshotSlotClass,
    pub(super) binding: ClaudeStrongBinding,
    pub(super) quality: ClaudeSnapshotQuality,
    pub(super) snapshot: AgentStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ClaudeStrongBinding {
    pub(super) account_identifier_hash: String,
    pub(super) organization_identifier_hash: String,
}

impl ClaudeStrongBinding {
    pub(super) fn new(
        account_identifier_hash: &str,
        organization_identifier_hash: &str,
    ) -> Option<Self> {
        (!account_identifier_hash.is_empty() && !organization_identifier_hash.is_empty()).then(
            || Self {
                account_identifier_hash: account_identifier_hash.to_string(),
                organization_identifier_hash: organization_identifier_hash.to_string(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ClaudeSnapshotQuality {
    pub(super) tier: u8,
    pub(super) provider_observed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaudeSnapshotSlotClass {
    Default,
    Registered,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ClaudeSnapshotSelection {
    pub(super) winning_by_binding: BTreeMap<ClaudeStrongBinding, usize>,
    pub(super) preferred_anchor_by_binding: BTreeMap<ClaudeStrongBinding, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaudeSnapshotDisposition {
    Upload,
    ShadowDefault,
    PreserveRegisteredAnchor,
    DuplicateRegistered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaudeSlotProbeFailure {
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
    pub(super) fn diagnostic_code(self) -> &'static str {
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

    pub(super) fn status(&self, observed_at: &str) -> ClaudeConfigSlotCollectionStatusV1 {
        let (state, code, message) = match self {
            Self::IdentityUnknown => (
                ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
                ClaudeConfigSlotDiagnosticCodeV1::IdentityUnknown,
                "This registered Claude slot has no complete strong local account and organization identity.",
            ),
            Self::CredentialUnavailable => (
                ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
                ClaudeConfigSlotDiagnosticCodeV1::CredentialUnavailable,
                "Claude Code isn't signed in for this account on this Mac.",
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
pub(super) struct PersistedClaudeSlotCollectionStateV1 {
    pub(super) schema_version: u16,
    pub(super) slots: BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    #[serde(default)]
    pub(super) unresolved_accounts: Vec<ClaudeUnresolvedAccountDescriptorV1>,
    #[serde(default)]
    pub(super) anchor_transitions: Vec<ottto_protocol::ClaudeAccountAnchorTransitionV1>,
}

pub(super) struct ClaudeSlotCollectionStateGuard {
    pub(super) _process: std::sync::MutexGuard<'static, ()>,
    pub(super) file: Option<File>,
}

pub(super) struct ClaudeOAuthCollectionAttemptGuard {
    pub(super) _process: std::sync::MutexGuard<'static, ()>,
    pub(super) file: File,
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
pub(super) enum ClaudeOAuthUsageFailure {
    /// 401/403 - the OAuth token is rejected or lacks the scope.
    AuthRejected,
    /// A 200 body we cannot read, a 200 body with none of the expected quota
    /// fields, or a 404/410 saying the endpoint no longer exists in this shape.
    ResponseShape,
    /// 429 that keeps coming back after the retry-after backoff.
    RateLimited,
}

impl ClaudeOAuthUsageFailure {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::AuthRejected => "auth_rejected",
            Self::ResponseShape => "response_shape_changed",
            Self::RateLimited => "rate_limited",
        }
    }

    pub(super) fn threshold(self) -> u32 {
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
pub(super) struct ClaudeOAuthUsageBreaker {
    pub(super) schema_version: u16,
    #[serde(default)]
    pub(super) account_identifier_hash: String,
    #[serde(default)]
    pub(super) organization_identifier_hash: String,
    /// Fingerprint of the call's own configuration (endpoint, headers, honest
    /// User-Agent, sentinel state). Changing any of them means the thing that
    /// was failing is not the thing we would call next, so the breaker resets.
    #[serde(default)]
    pub(super) config_fingerprint: String,
    #[serde(default)]
    pub(super) auth_failures: u32,
    #[serde(default)]
    pub(super) shape_failures: u32,
    #[serde(default)]
    pub(super) rate_limit_failures: u32,
    #[serde(default)]
    pub(super) opened_at_epoch_seconds: u64,
    /// Cool-down expiry. `0` means the breaker has never opened; the breaker is
    /// open while `now < reopen_after_epoch_seconds`.
    #[serde(default)]
    pub(super) reopen_after_epoch_seconds: u64,
    /// Which failure class opened it, for the diagnostic message.
    #[serde(default)]
    pub(super) opened_by: String,
    /// Per-caller 401/403 accounting, keyed by
    /// `ClaudeOAuthUsageCaller::breaker_key`. An auth rejection is a statement
    /// about one credential, so the default login and a registered slot that
    /// read the same account never add to each other's streak or backoff.
    /// Additive: older daemons ignore it, and `auth_failures` above remains the
    /// unattributed streak written by daemons from before caller attribution.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) auth_callers: BTreeMap<String, ClaudeOAuthUsageCallerAuthState>,
    /// The most recent 401/403 for this account from any caller. Secret-free:
    /// caller key, HTTP status, and local time only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_auth_failure: Option<ClaudeOAuthUsageAuthFailureRecord>,
}

/// One caller's consecutive auth rejections and its own backoff.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClaudeOAuthUsageCallerAuthState {
    #[serde(default)]
    pub(super) consecutive_failures: u32,
    /// HTTP status of the latest rejection (401 or 403).
    #[serde(default)]
    pub(super) last_status: u16,
    #[serde(default)]
    pub(super) last_failure_at_epoch_seconds: u64,
    /// This caller is not sent to the provider while `now` is before this.
    #[serde(default)]
    pub(super) backoff_until_epoch_seconds: u64,
    /// Access-token expiry metadata of the credential that was rejected (never
    /// the token). When the caller's current credential reports a different
    /// expiry, the credential was rotated: the hold is released and the streak
    /// starts over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) credential_expires_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClaudeOAuthUsageAuthFailureRecord {
    #[serde(default)]
    pub(super) caller: String,
    #[serde(default)]
    pub(super) status: u16,
    #[serde(default)]
    pub(super) at_epoch_seconds: u64,
}

pub(super) const CLAUDE_OAUTH_USAGE_DEFAULT_CALLER_KEY: &str = "default";

pub(super) const CLAUDE_OAUTH_USAGE_SLOT_CALLER_KEY_PREFIX: &str = "slot-sha256:";

/// Raw-slot-id key form written only by an unreleased build; migrated on read.
pub(super) const CLAUDE_OAUTH_USAGE_RAW_SLOT_CALLER_KEY_PREFIX: &str = "slot:";

impl ClaudeOAuthUsageBreaker {
    /// Rewrite any raw slot-id caller keys into their opaque form. Returns
    /// whether anything changed, so the caller can persist the migration.
    pub(super) fn migrate_raw_caller_keys(&mut self) -> bool {
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
    #[cfg(test)]
    pub(super) fn holds_no_state(&self) -> bool {
        self.auth_failures == 0
            && self.shape_failures == 0
            && self.rate_limit_failures == 0
            && self.opened_at_epoch_seconds == 0
            && self.reopen_after_epoch_seconds == 0
            && self.opened_by.is_empty()
            && self.auth_callers.is_empty()
    }
}

/// Which local credential is asking the Claude OAuth usage endpoint.
///
/// The default `~/.claude` login (rotated by Claude Code itself) and a
/// registered slot's own login can both belong to one account. They share the
/// account's cache, refresh gate, and endpoint-level breaker classes, but auth
/// rejections and their backoff are recorded per caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ClaudeOAuthUsageCaller {
    /// The default `~/.claude` login. May migrate the old root usage cache.
    Default,
    /// The default login for an account that a registered managed slot has
    /// proved it reads. The slot's credential is the single provider caller;
    /// the default path serves the shared account cache only. May migrate the
    /// old root usage cache.
    DefaultDeferredToSlot,
    /// A registered slot, by its local slot id.
    RegisteredSlot(String),
}

impl ClaudeOAuthUsageCaller {
    pub(super) fn legacy_root_migration(&self) -> bool {
        matches!(self, Self::Default | Self::DefaultDeferredToSlot)
    }

    pub(super) fn may_call_provider(&self) -> bool {
        !matches!(self, Self::DefaultDeferredToSlot)
    }

    /// Persisted key. The slot id stays in memory only: on disk a slot is a
    /// domain-separated opaque hash of its id.
    pub(super) fn breaker_key(&self) -> String {
        match self {
            Self::Default | Self::DefaultDeferredToSlot => {
                CLAUDE_OAUTH_USAGE_DEFAULT_CALLER_KEY.to_string()
            }
            Self::RegisteredSlot(slot_id) => claude_oauth_usage_slot_caller_key(slot_id),
        }
    }

    /// Words safe to upload: never the slot id or a path.
    pub(super) fn credential_kind(&self) -> &'static str {
        match self {
            Self::Default | Self::DefaultDeferredToSlot => "default Claude Code login",
            Self::RegisteredSlot(_) => "registered account slot",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct ClaudeDesktopConfig {
    #[serde(rename = "lastKnownAccountUuid")]
    pub(super) last_known_account_uuid: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct ClaudeDesktopCodeSessionMetadata {
    #[serde(rename = "cliSessionId")]
    pub(super) cli_session_id: Option<String>,
    #[serde(rename = "lastActivityAt")]
    pub(super) last_activity_at: Option<Value>,
    #[serde(rename = "createdAt")]
    pub(super) created_at: Option<Value>,
    /// Any `importedFrom` tag, null or malformed included, means the session
    /// was copied into this folder: not native evidence for its folder pair.
    /// The tag's value is never kept.
    #[serde(
        rename = "importedFrom",
        default,
        deserialize_with = "deserialize_field_present"
    )]
    pub(super) imported: bool,
}

pub(super) fn deserialize_field_present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer).map(|_| true)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct ClaudeDesktopAgentModeSessionMetadata {
    #[serde(rename = "cliSessionId")]
    pub(super) cli_session_id: Option<String>,
    #[serde(rename = "lastActivityAt")]
    pub(super) last_activity_at: Option<Value>,
    #[serde(rename = "createdAt")]
    pub(super) created_at: Option<Value>,
    #[serde(rename = "emailAddress")]
    pub(super) email_address: Option<String>,
    #[serde(rename = "accountEmail")]
    pub(super) account_email: Option<String>,
    pub(super) email: Option<String>,
    #[serde(rename = "accountName")]
    pub(super) account_name: Option<String>,
    #[serde(rename = "organizationName")]
    pub(super) organization_name: Option<String>,
    #[serde(rename = "workspaceName")]
    pub(super) workspace_name: Option<String>,
    #[serde(rename = "teamName")]
    pub(super) team_name: Option<String>,
    #[serde(rename = "subscriptionType")]
    pub(super) subscription_type: Option<String>,
    #[serde(rename = "planType")]
    pub(super) plan_type: Option<String>,
    pub(super) plan: Option<String>,
}

pub(super) type ClaudeDesktopMetadataEntries<T> = BTreeMap<PathBuf, (PathStamp, Option<T>)>;

/// Parsed Claude Desktop session metadata by file, kept in memory between
/// status passes so a file whose stamp is unchanged is not read again. Never
/// persisted or uploaded.
#[derive(Default)]
pub(crate) struct ClaudeDesktopMetadataCache {
    pub(super) code: ClaudeDesktopMetadataEntries<ClaudeDesktopCodeSessionMetadata>,
    pub(super) agent_mode: ClaudeDesktopMetadataEntries<ClaudeDesktopAgentModeSessionMetadata>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ClaudeDesktopProfileBuilder {
    pub(super) account_uuid: String,
    pub(super) account_label: Option<String>,
    pub(super) account_name: Option<String>,
    pub(super) organization_label: Option<String>,
    pub(super) plan_type: Option<String>,
    pub(super) organization_uuids: BTreeSet<String>,
    pub(super) current_organization_uuid: Option<String>,
    pub(super) latest_activity_epoch_seconds: Option<i64>,
    pub(super) latest_session_id: Option<String>,
    pub(super) session_activity_by_id: BTreeMap<String, Option<i64>>,
    pub(super) code_session_count: usize,
    pub(super) agent_mode_session_count: usize,
}

/// One Desktop `<account>/<organization>` folder pair, across the Code and
/// agent-mode stores. Every folder takes part in duplicate-session ownership;
/// only an `exact` one (both names canonical UUIDs) can become a pair. Labels
/// and plan come only from the same folder pair, never from the account's
/// other folders.
#[derive(Debug, Clone, Default)]
pub(super) struct ClaudeDesktopPairBuilder {
    pub(super) exact: bool,
    pub(super) account_label: Option<String>,
    pub(super) account_name: Option<String>,
    pub(super) organization_label: Option<String>,
    pub(super) plan_type: Option<String>,
    /// Every session seen in the folder pair, imported copies and agent-mode
    /// sessions included: input to the duplicate-session ownership rule.
    pub(super) session_activity_by_id: BTreeMap<String, Option<i64>>,
    /// Native Code sessions (no `importedFrom`) whose metadata carries a
    /// parseable activity time. Only these qualify the pair.
    pub(super) native_activity_by_id: BTreeMap<String, i64>,
}

/// One Desktop folder pair: the canonical UUIDs where the names are UUIDs,
/// otherwise the names as found (a non-UUID name never equals a canonical one).
pub(super) type ClaudeDesktopPairKey = (String, String);

/// One Desktop metadata scan per status pass: today's per-account observations
/// for the default snapshot, and the qualified exact folder pairs.
pub(super) struct ClaudeDesktopScan {
    pub(super) observations: Vec<AgentStatusPlanObservation>,
    pub(super) pairs: ClaudeDesktopPairs,
}

/// Qualified exact Desktop folder pairs, newest native activity first, and the
/// duplicate sessions they own, newest first. Nothing here is uploaded until
/// `claude_desktop_pairs_snapshot` subtracts the pairs another upload covers.
#[derive(Debug, Clone, Default)]
pub(super) struct ClaudeDesktopPairs {
    pub(super) pairs: Vec<ClaudeDesktopPairObservation>,
    pub(super) duplicate_sessions: Vec<ClaudeDesktopPairObservation>,
}

#[derive(Debug, Clone)]
pub(super) struct ClaudeDesktopPairObservation {
    pub(super) binding: ClaudeStrongBinding,
    pub(super) observation: AgentStatusPlanObservation,
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
    pub(super) fn new(provider: &str, model: &str, thinking_level: Option<&str>) -> Option<Self> {
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
