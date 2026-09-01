use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(test)]
use ottto_core::claude_account_identifier_hash;
use ottto_core::{
    billing_identity_hash, compiled_release_version, default_support_dir,
    read_claude_statusline_cache, read_claude_statusline_context_cache,
    read_claude_statusline_context_history, write_owner_only_file_atomic, ClaudeConfigDirSlot,
    ClaudeStatusLineContextWindowCache, ClaudeStatusLineContextWindowHistory,
    ClaudeStatusLineContextWindowSample, ClaudeStatusLineRateLimitCache, CodexHomeTrust,
    FileClaudeConfigSlotSettingsStore, FileCodexAccountSlotSettingsStore, MAX_CLAUDE_ACCOUNT_SLOTS,
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
    ClaudeAccountAnchorSetupBlockerV1, ClaudeAccountsStatusV1, ClaudeConfigSlotCollectionStateV1,
    ClaudeConfigSlotCollectionStatusV1, ClaudeConfigSlotDescriptorV1,
    ClaudeConfigSlotDiagnosticCodeV1, ClaudeConfigSlotDiagnosticV1, ClaudeConfigSlotOwnership,
    ClaudeConfigSlotQuotaSnapshotStateV1, ClaudeConfigSlotQuotaSnapshotV1,
    ClaudeConfigSlotUpkeepResultV1, ClaudeQuotaAccessState, ClaudeUnresolvedAccountDescriptorV1,
    ClaudeUnresolvedAccountEvidenceKind, CodexAccountSlotCollectionStateV1,
    CodexAccountSlotCollectionStatusV1, CodexAccountSlotDescriptorV1, CodexAccountSlotDiagnosticV1,
    CodexAccountSlotOwnershipV1, CodexAccountSlotQuotaSnapshotV1, CodexAccountSlotRelationshipV1,
    CodexAccountTargetCoverageV1, CodexAccountTargetDescriptorV1, CodexAccountTargetDurabilityV1,
    CodexAccountTargetHealthV1, CodexAccountTargetSetupBlockerV1, CodexAccountsStatusV1,
    SourceKind,
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
/// Base refresh cadence: ~1 fetch per hour per machine (~24/day), down from the
/// former 15-minute gate (~96/day). Sparse polling is half of the recorded
/// provider-endpoints posture (identify honestly, poll sparsely, circuit-break
/// instead of adapting).
const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS: u64 = 60 * 60;
/// Half-width of the deterministic spread applied to the base cadence, giving
/// an effective gate in the 55-65 minute range.
const CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS: u64 = 5 * 60;
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
    identity: Option<CodexStrongIdentity>,
    credential_read_failed: bool,
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

#[derive(Clone)]
struct CodexHomeSlot {
    slot_id: String,
    ownership: CodexAccountSlotOwnershipV1,
    home: PathBuf,
    registered_binding: Option<(String, String)>,
}

struct CodexSlotCandidate {
    slot: CodexHomeSlot,
    snapshot: AgentStatusSnapshot,
    status: CodexAccountSlotCollectionStatusV1,
    binding: Option<(String, String)>,
    workspace_targets: Vec<CodexWorkspaceTargetEvidence>,
    quality: u8,
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
}

/// v4 adds organization identity and requires exact identity on every embedded
/// meter. Released v3 account-only caches cannot prove organization ownership
/// and are discarded rather than relabeled.
const CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION: u16 = 4;
const CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION: u16 = 3;
#[cfg(test)]
static CLAUDE_OAUTH_PROVIDER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Everything the Claude OAuth usage endpoint yields in one fetch.
#[derive(Debug, Clone, Default)]
struct ClaudeOAuthUsage {
    windows: Vec<AgentQuotaWindow>,
    credit_balances: Vec<AgentCreditBalance>,
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
}

/// A validated exact-slot credential. Deliberately implements neither
/// `Debug` nor `Serialize`: the access token must stay in memory and never
/// become diagnostic or persistence material.
struct ResolvedClaudeSlot {
    descriptor: ClaudeConfigSlotDescriptorV1,
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
}

/// Secret-free projection used by the background upkeep scheduler. Reading it
/// drops the access token immediately and exposes only vendor deadlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeOAuthCredentialMetadata {
    pub(crate) access_expires_at: Option<String>,
    pub(crate) refresh_token_expires_at: Option<String>,
    pub(crate) has_refresh_token: bool,
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

fn select_claude_snapshot_candidates(
    candidates: &[ClaudeSnapshotCandidate],
) -> ClaudeSnapshotSelection {
    let mut selection = ClaudeSnapshotSelection::default();
    for (index, candidate) in candidates.iter().enumerate() {
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
            claude_slot_projection_quality(status) > claude_slot_projection_quality(current)
                || (claude_slot_projection_quality(status)
                    == claude_slot_projection_quality(current)
                    && slot_id < *current_slot_id)
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
}

impl ClaudeSlotProbeFailure {
    fn diagnostic_code(self) -> &'static str {
        match self {
            Self::IdentityUnknown => "claude_slot_identity_unknown",
            Self::CredentialUnavailable => "claude_slot_credential_unavailable",
            Self::IdentityMismatch => "claude_slot_identity_mismatch",
            Self::ConcurrentMutation => "claude_slot_concurrent_mutation",
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

pub fn collect_agent_status_snapshots(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
) -> Vec<AgentStatusSnapshot> {
    collect_agent_status_collection(source, captured_at, expires_at).snapshots
}

pub(crate) fn collect_agent_status_collection(
    source: &SourceKind,
    captured_at: String,
    expires_at: String,
) -> AgentStatusCollection {
    match source {
        SourceKind::Codex => collect_codex_status_snapshots(captured_at, expires_at),
        SourceKind::ClaudeCode => collect_claude_status_snapshots(captured_at, expires_at),
        SourceKind::Pi => {
            single_agent_status_collection(collect_pi_status(captured_at, expires_at))
        }
    }
}

fn single_agent_status_collection(snapshot: AgentStatusSnapshot) -> AgentStatusCollection {
    AgentStatusCollection {
        snapshots: vec![snapshot.clone()],
        source_health_snapshot: snapshot,
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

    let source_health_snapshot =
        codex_source_health_snapshot(&candidates, &captured_at, &expires_at);
    if snapshots.is_empty() {
        snapshots.push(source_health_snapshot.clone());
    }
    AgentStatusCollection {
        snapshots,
        source_health_snapshot,
    }
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
    let custom_needs_attention = candidates.iter().any(|candidate| {
        candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
            && !matches!(
                candidate.status.state,
                CodexAccountSlotCollectionStateV1::Fresh
                    | CodexAccountSlotCollectionStateV1::DuplicateAccount
            )
    });
    if !custom_needs_attention && source_health_snapshot.status != AgentStatusState::Available {
        if let Some(healthy_anchor) = candidates.iter().find(|candidate| {
            candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
                && candidate.status.state == CodexAccountSlotCollectionStateV1::Fresh
        }) {
            source_health_snapshot = healthy_anchor.snapshot.clone();
        }
    }
    if custom_needs_attention {
        source_health_snapshot.status = AgentStatusState::Degraded;
        source_health_snapshot
            .diagnostics
            .push(AgentStatusDiagnostic::source(
                "codex_registered_slot_needs_attention",
                AgentDiagnosticSeverity::Warning,
                "One or more durable Codex account connections need local attention; healthy accounts continue collecting independently.",
            ));
    }
    source_health_snapshot
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

pub(crate) fn collect_registered_codex_slot_for_setup(
    slot_id: &str,
) -> Result<(CodexStrongIdentity, CodexAccountSlotCollectionStatusV1), String> {
    let store = FileCodexAccountSlotSettingsStore::default();
    let home = store
        .slot_home(slot_id)
        .map_err(|_| "Codex durable connection state is unavailable.".to_string())?;
    let captured_at = crate::current_rfc3339_timestamp();
    let (snapshot, identity, _) = collect_codex_status_for_home(
        captured_at.clone(),
        captured_at,
        &home,
        CodexHomeTrust::Managed,
    );
    let identity = identity.ok_or_else(|| {
        "Codex sign-in has not produced a complete account and workspace identity.".to_string()
    })?;
    let status = codex_collection_status_from_snapshot(&snapshot);
    if status.state != CodexAccountSlotCollectionStateV1::Fresh
        || status.account_identifier_hash.as_deref()
            != Some(identity.account_identifier_hash.as_str())
        || status.workspace_identifier_hash.as_deref()
            != Some(identity.workspace_identifier_hash.as_str())
    {
        return Err(
            "Codex sign-in is present, but fresh quota for its exact account and workspace is not yet available."
                .to_string(),
        );
    }
    Ok((identity, status))
}

fn collect_codex_slot_candidates(
    status: CodexAccountsStatusV1,
    captured_at: &str,
    expires_at: &str,
) -> (CodexAccountsStatusV1, Vec<CodexSlotCandidate>) {
    let store = FileCodexAccountSlotSettingsStore::default();
    let mut slots = vec![CodexHomeSlot {
        slot_id: "default".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Default,
        home: default_codex_home(),
        registered_binding: None,
    }];
    let registered = store
        .registered_bindings()
        .unwrap_or_default()
        .into_iter()
        .filter(|binding| binding.accepted)
        .map(|binding| (binding.slot_id.clone(), binding))
        .collect::<BTreeMap<_, _>>();
    for descriptor in &status.managed_slots {
        if let Some(binding) = registered.get(&descriptor.slot_id) {
            let Ok(home) = store.slot_home(&descriptor.slot_id) else {
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
    let candidates = thread::scope(|scope| {
        let handles = slots
            .into_iter()
            .map(|slot| {
                scope.spawn(move || collect_codex_home_candidate(slot, captured_at, expires_at))
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .collect()
    });
    (status, candidates)
}

fn collect_codex_home_candidate(
    slot: CodexHomeSlot,
    captured_at: &str,
    expires_at: &str,
) -> CodexSlotCandidate {
    let home_trust = match slot.ownership {
        CodexAccountSlotOwnershipV1::Default => CodexHomeTrust::ProviderDefault,
        CodexAccountSlotOwnershipV1::Managed => CodexHomeTrust::Managed,
    };
    let (mut snapshot, _, workspace_targets) = collect_codex_status_for_home(
        captured_at.to_string(),
        expires_at.to_string(),
        &slot.home,
        home_trust,
    );
    let mut status = codex_collection_status_from_snapshot(&snapshot);
    let binding = enforce_codex_registered_binding(&slot, &mut snapshot, &mut status);
    let quality = codex_snapshot_quality(&snapshot, &status);
    CodexSlotCandidate {
        slot,
        snapshot,
        status,
        binding,
        workspace_targets,
        quality,
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
        status.default_slot.collection = candidate.status.clone();
    }
    for descriptor in &mut status.managed_slots {
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.slot.slot_id == descriptor.slot_id)
        {
            descriptor.collection = candidate.status.clone();
        }
    }
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
        CodexAccountSlotCollectionStateV1::IdentityUnknown => {
            CodexAccountTargetHealthV1::IdentityUnknown
        }
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
    }
}

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

fn collect_codex_status_for_home(
    captured_at: String,
    expires_at: String,
    codex_home: &Path,
    home_trust: CodexHomeTrust,
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
    });

    let login = run_codex_home_command(
        codex_home,
        &["login", "status"],
        COMMAND_TIMEOUT,
        allow_legacy_oauth,
    );
    if login.command_found {
        snapshot.collection_method = AgentStatusCollectionMethod::CliText;
        if login.success {
            if let Some(account) = parse_codex_account_text(&login.stdout) {
                snapshot.status = AgentStatusState::Available;
                snapshot.account = Some(account);
            }
        } else {
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
    match read_codex_auth_account_at(codex_home, home_trust) {
        Ok(Some(auth_account)) => {
            snapshot.status = AgentStatusState::Available;
            snapshot.account = Some(merge_codex_accounts(snapshot.account.take(), auth_account));
        }
        Ok(None) => {}
        Err(_) => append_codex_credential_read_failed_diagnostic(&mut snapshot),
    }

    let models = run_codex_home_command(
        codex_home,
        &["debug", "models", "--bundled"],
        COMMAND_TIMEOUT,
        allow_legacy_oauth,
    );
    let mut model_status = collect_codex_model_status_from_output(&models);
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
    match collect_codex_usage_for_home(codex_home, home_trust) {
        Ok(usage) => {
            if usage.credential_read_failed {
                append_codex_credential_read_failed_diagnostic(&mut snapshot);
            }
            if let Some(account) = usage.account {
                snapshot.account = Some(merge_codex_accounts(snapshot.account.take(), account));
            }
            if let Some(identity) = usage.identity {
                strong_identity = Some(identity.clone());
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
        Err(message) => {
            snapshot.quota_windows = vec![unsupported_quota_window("usage")];
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "codex_usage_probe_failed",
                AgentDiagnosticSeverity::Warning,
                message,
            ));
        }
    }
    snapshot.context = Some(AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("codex_cli_v1".to_string()),
        recent_samples: Vec::new(),
        observed_at: None,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some("codex_active_context_not_collected".to_string()),
        posture: None,
    });
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
) -> Result<CodexUsageProbe, String> {
    let allow_legacy_oauth = home_trust == CodexHomeTrust::ProviderDefault;
    match collect_codex_app_server_usage_for_home(codex_home, home_trust) {
        Ok(usage) => Ok(usage),
        Err(app_server_message) if legacy_codex_oauth_fallback_allowed(allow_legacy_oauth) => {
            collect_codex_oauth_usage_at(codex_home, home_trust).map_err(|oauth_message| {
                format!("{app_server_message} Legacy OAuth usage fallback failed: {oauth_message}")
            })
        }
        Err(message) => Err(message),
    }
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
                    // Claude Code's durable `effortLevel` setting, which
                    // `/effort` writes. Reported exactly as configured; absent
                    // means absent, never an invented default.
                    reasoning_effort: defaults.reasoning_effort,
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
        crate::snapshots::ClaudeConfigDefaultsOutcome::NothingConfigured => {
            ClaudeRuntimeDefaultsCapture {
                defaults: None,
                capability: unsupported_capability(
                    "runtime_defaults",
                    "Claude Code settings were read, but none set a display-safe default (model, effort level, permission mode, fast mode, or sandbox).",
                ),
                diagnostic: Some(AgentStatusDiagnostic::source(
                    "claude_runtime_defaults_not_configured",
                    AgentDiagnosticSeverity::Info,
                    "Claude Code settings parsed cleanly and configure none of the defaults Ottto displays.",
                )),
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

fn collect_claude_status(captured_at: String, expires_at: String) -> AgentStatusSnapshot {
    // Presence is decided by the canonical detector, which requires the `claude`
    // binary. A lone `~/.claude/settings.json` — which Ottto's own relay-base
    // patch writes during onboarding — must NOT read as "installed", or a Mac
    // that never had Claude reports it as present and then fails verification
    // with "claude is not installed or not executable".
    let claude_desktop_root = claude_desktop_support_dir();
    let claude_cli_present =
        crate::agent_configs::detection::source_present_locally(&SourceKind::ClaudeCode);
    if !claude_cli_present && !claude_desktop_metadata_present(&claude_desktop_root) {
        return not_installed_snapshot(SourceKind::ClaudeCode, "claude", captured_at, expires_at);
    }
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    let default_slot = ClaudeConfigDirSlot::Default;
    let claude_oauth_account = read_claude_cli_oauth_account(&claude_cli_config_path());
    let initial_credential = read_claude_oauth_credential_for_slot(&default_slot);
    let auth = run_claude_slot_command(
        &default_slot,
        &["auth", "status", "--json"],
        COMMAND_TIMEOUT,
    );
    let stable_default_credential = stable_claude_slot_credential(
        claude_oauth_account.clone(),
        initial_credential,
        read_claude_cli_oauth_account(&claude_cli_config_path()),
    );
    if auth.command_found && auth.success {
        snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
        if let Ok(json) = serde_json::from_str::<Value>(&auth.stdout) {
            let mut account = parse_claude_auth_json(&json);
            let mut refined_seat_plan = None;
            let mut refined_max_plan = None;
            match stable_default_credential.as_ref() {
                Ok(stable) => {
                    match require_claude_auth_identity_agreement(&account, &stable.oauth_account) {
                        Ok(()) => {
                            let refined = refine_claude_local_plan_metadata(
                                &mut account,
                                &stable.oauth_account,
                            );
                            refined_seat_plan = refined.seat_plan;
                            refined_max_plan = refined.max_plan;
                            // Positive account + organization agreement is required
                            // before local metadata can stamp full-meter identity.
                            stamp_claude_cli_account_identity(&mut account, &stable.oauth_account);
                        }
                        Err(failure) => snapshot
                            .diagnostics
                            .push(default_claude_identity_diagnostic(failure)),
                    }
                }
                Err(failure) => snapshot
                    .diagnostics
                    .push(default_claude_identity_diagnostic(*failure)),
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
            if let Some(max_plan) = refined_max_plan {
                snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                    "claude_max_rate_limit_tier_detected",
                    AgentDiagnosticSeverity::Info,
                    format!(
                        "Claude Max tier resolved to {max_plan} from local Claude Code account metadata."
                    ),
                ));
            }
        } else {
            snapshot.account = Some(unsupported_account("anthropic"));
            snapshot
                .diagnostics
                .push(default_claude_identity_diagnostic(
                    ClaudeSlotProbeFailure::CredentialUnavailable,
                ));
        }
    } else {
        snapshot.account = Some(unsupported_account("anthropic"));
        if auth.command_found {
            snapshot.diagnostics.push(command_diagnostic(
                "claude_auth_status_failed",
                "claude auth status --json did not return usable JSON.",
                &auth,
            ));
        }
    }
    let version = run_command_capture("claude", &["--version"], COMMAND_TIMEOUT);
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
    let desktop_plan_observations =
        claude_desktop_plan_observations_from_root(&claude_desktop_root, &snapshot.captured_at);
    let observable_account_identifier_hashes =
        claude_account_identifier_hashes_from_observations(&desktop_plan_observations);
    let apply_statusline_quota =
        |snapshot: &mut AgentStatusSnapshot, quota_capability: &mut AgentCapabilityGap| -> bool {
            match collect_claude_statusline_quota_windows(
                &claude_account_identifier_hash,
                &observable_account_identifier_hashes,
            ) {
                Ok(ClaudeStatusLineQuota::Windows(windows)) if !windows.is_empty() => {
                    snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
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
        strong_oauth_identity,
        stable_default_credential.as_ref().ok(),
    ) {
        (Some((account_hash, organization_hash)), Some(stable)) => {
            collect_claude_oauth_usage_with_access_token(
                &account_hash,
                &organization_hash,
                stable.credential.access_token.clone(),
                true,
            )
        }
        _ => ClaudeOAuthUsageOutcome::from(Err(
            "Claude OAuth usage requires strong matching local account and organization identity."
                .to_string(),
        )),
    };
    // Pushed before the quota branch below so the reason the endpoint was or
    // was not called rides the snapshot regardless of which source ends up
    // serving quota. These diagnostics are the alert channel for the circuit
    // breaker: they travel to the backend with the agent-status upload.
    snapshot.diagnostics.extend(oauth_outcome.diagnostics);
    let mut full_oauth_quota_collected = false;
    match oauth_outcome.result {
        Ok(usage) if !usage.windows.is_empty() => {
            full_oauth_quota_collected = true;
            snapshot.collection_method = AgentStatusCollectionMethod::CliJson;
            snapshot.quota_windows = usage.windows;
            snapshot.credit_balances = usage.credit_balances;
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
            "Read from claude auth status --json when available.",
        ),
        quota_capability,
        context_capability,
        runtime_defaults.capability,
    ];
    if let Some(diagnostic) = runtime_defaults.diagnostic {
        snapshot.diagnostics.push(diagnostic);
    }
    if version.command_found && version.success {
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
    snapshot
}

fn collect_claude_status_snapshots(
    captured_at: String,
    expires_at: String,
) -> AgentStatusCollection {
    let mut default_snapshot = collect_claude_status(captured_at.clone(), expires_at.clone());
    let mut candidates = Vec::new();
    let settings = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map(annotate_claude_accounts_status);
    let upkeep_consent = settings.as_ref().is_ok_and(|status| {
        status.consent == ottto_protocol::ClaudeAccountUpkeepConsentState::Granted
    });
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
    let mut default_state = claude_default_slot_collection_status(&default_snapshot);
    retain_verified_claude_slot_binding(
        "default",
        &ClaudeConfigDirSlot::Default,
        &mut default_state,
    );
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
    for descriptor in custom_descriptors {
        match crate::claude_browser_auth::collection_suppression(&descriptor.slot_id) {
            Some(
                crate::claude_browser_auth::ClaudeCollectionSuppression::HideProvisionalTarget,
            ) => continue,
            Some(
                crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveCanonicalReconnect
                | crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveWhileStateUnavailable,
            ) => {
                slot_states.insert(descriptor.slot_id.clone(), descriptor.collection.clone());
                continue;
            }
            None => {}
        }
        let upkeep = crate::claude_upkeep::observe_registered_slot_upkeep(
            &descriptor,
            upkeep_consent,
            !claude_oauth_usage_network_disabled(),
        );
        if !upkeep.proceed_with_collection {
            let mut status =
                blocked_claude_upkeep_status(&descriptor.slot_id, &captured_at, upkeep.status);
            if let Some(slot) = claude_config_slot_for_descriptor(&descriptor) {
                retain_verified_claude_slot_binding(&descriptor.slot_id, &slot, &mut status);
            } else {
                clear_claude_slot_binding(&mut status);
            }
            slot_states.insert(descriptor.slot_id, status);
            continue;
        }
        let mut resolved = match resolve_registered_claude_slot(descriptor.clone()) {
            Ok(resolved) => resolved,
            Err(failure) => {
                let mut status = failure.status(&captured_at);
                if let Some(slot) = claude_config_slot_for_descriptor(&descriptor) {
                    retain_verified_claude_slot_binding(&descriptor.slot_id, &slot, &mut status);
                }
                apply_claude_upkeep_observation(&mut status, upkeep.status);
                slot_states.insert(descriptor.slot_id, status);
                continue;
            }
        };
        let slot_id = resolved.descriptor.slot_id.clone();
        let account_hash = resolved.account_identifier_hash.clone();
        let organization_hash = resolved.organization_identifier_hash.clone();
        let access_token = resolved.credential.access_token.take();
        let credential_available = access_token.is_some();
        let outcome = collect_claude_oauth_usage_with_access_token(
            &account_hash,
            &organization_hash,
            access_token,
            false,
        );
        match custom_claude_snapshot_from_usage(
            resolved,
            outcome,
            credential_available,
            captured_at.clone(),
            expires_at.clone(),
        ) {
            Ok((snapshot, mut state)) => {
                apply_claude_upkeep_observation(&mut state, upkeep.status);
                let mut snapshot = snapshot;
                apply_claude_quota_access_state(&mut snapshot, &state);
                if claude_slot_status_carries_meters(&state) {
                    let quality = claude_snapshot_candidate_rank(&snapshot)
                        .expect("validated custom meter snapshot is rankable");
                    candidates.push(ClaudeSnapshotCandidate {
                        slot_id: slot_id.clone(),
                        slot_class: ClaudeSnapshotSlotClass::Registered,
                        binding: ClaudeStrongBinding {
                            account_identifier_hash: account_hash,
                            organization_identifier_hash: organization_hash,
                        },
                        quality,
                        snapshot,
                    });
                }
                slot_states.insert(slot_id, state);
            }
            Err(mut state) => {
                retain_exact_claude_slot_binding(&mut state, &account_hash, &organization_hash);
                apply_claude_upkeep_observation(&mut state, upkeep.status);
                slot_states.insert(slot_id, state);
            }
        }
    }
    let selection = select_claude_snapshot_candidates(&candidates);
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
    for (index, mut candidate) in candidates.into_iter().enumerate() {
        match dispositions[index] {
            ClaudeSnapshotDisposition::Upload => {
                let (durability, health) = anchor_health_by_binding
                    .get(&candidate.binding)
                    .map(|health| (ClaudeAccountAnchorDurabilityV1::Anchored, *health))
                    .unwrap_or((ClaudeAccountAnchorDurabilityV1::DefaultOnly, None));
                apply_claude_anchor_continuity(&mut candidate.snapshot, durability, health);
                snapshots.push(candidate.snapshot);
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
    snapshots.extend(degraded_claude_slot_snapshots(
        &slot_states,
        &canonical_anchors,
        &winning_accounts,
        &captured_at,
        &expires_at,
    ));
    let unresolved_accounts = derive_unresolved_claude_accounts(
        &default_snapshot,
        &snapshots,
        &slot_states,
        OffsetDateTime::parse(&captured_at, &Rfc3339).unwrap_or_else(|_| OffsetDateTime::now_utc()),
    );
    let _ = persist_claude_slot_collection_states(&slot_states, &unresolved_accounts);

    let mut source_health_snapshot = default_snapshot.clone();
    let mut custom_slot_states = slot_states
        .iter()
        .filter(|(slot_id, _)| slot_id.as_str() != "default")
        .map(|(_, status)| status);
    let has_healthy_custom_account = custom_slot_states
        .clone()
        .any(|status| status.state == ClaudeConfigSlotCollectionStateV1::Fresh);
    let has_actionable_custom_slot = custom_slot_states.any(|status| {
        !matches!(
            status.state,
            ClaudeConfigSlotCollectionStateV1::Fresh
                | ClaudeConfigSlotCollectionStateV1::Unverified
        )
    });
    let default_has_full_meter_evidence = default_snapshot
        .quota_windows
        .iter()
        .any(|window| window.organization_identifier_hash.is_some())
        || !default_snapshot.credit_balances.is_empty();
    let default_full_meter_needs_attention = default_has_full_meter_evidence
        && default_state.state != ClaudeConfigSlotCollectionStateV1::Fresh;
    if has_actionable_custom_slot || default_full_meter_needs_attention {
        source_health_snapshot.status = AgentStatusState::Degraded;
        source_health_snapshot
            .diagnostics
            .push(AgentStatusDiagnostic::source(
                "claude_registered_slot_needs_attention",
                AgentDiagnosticSeverity::Warning,
                "One or more registered Claude account slots need local attention; healthy accounts continue collecting independently.",
            ));
    } else if has_healthy_custom_account {
        source_health_snapshot.status = AgentStatusState::Available;
    }

    AgentStatusCollection {
        snapshots,
        source_health_snapshot,
    }
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

#[cfg(test)]
fn claude_default_snapshot_is_uploadable(snapshot: &AgentStatusSnapshot) -> bool {
    claude_snapshot_candidate_rank(snapshot).is_some()
}

fn claude_snapshot_candidate_rank(snapshot: &AgentStatusSnapshot) -> Option<ClaudeSnapshotQuality> {
    if snapshot.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ClaudeSlotProbeFailure::ConcurrentMutation.diagnostic_code()
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
            let complete = snapshot.quota_windows.iter().any(|window| {
                window.scope == AgentQuotaWindowScope::Account && window.name == "session"
            }) && snapshot.quota_windows.iter().any(|window| {
                window.scope == AgentQuotaWindowScope::Account && window.name == "weekly"
            }) && snapshot.quota_windows.iter().any(|window| {
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
        return ClaudeSlotProbeFailure::IdentityUnknown.status(&captured_at);
    };
    match crate::claude_browser_auth::collection_suppression(slot_id) {
        Some(crate::claude_browser_auth::ClaudeCollectionSuppression::HideProvisionalTarget) => {
            return ClaudeSlotProbeFailure::IdentityUnknown.status(&captured_at);
        }
        Some(
            crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveCanonicalReconnect
            | crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveWhileStateUnavailable,
        ) => return descriptor.collection,
        None => {}
    }
    let upkeep = crate::claude_upkeep::observe_registered_slot_upkeep(
        &descriptor,
        upkeep_consent,
        !claude_oauth_usage_network_disabled(),
    );
    if !upkeep.proceed_with_collection {
        let status = blocked_claude_upkeep_status(slot_id, &captured_at, upkeep.status);
        let _ = persist_one_claude_slot_collection_state(slot_id, &status);
        return status;
    }
    let mut resolved = match resolve_registered_claude_slot(descriptor) {
        Ok(resolved) => resolved,
        Err(failure) => {
            let mut status = failure.status(&captured_at);
            apply_claude_upkeep_observation(&mut status, upkeep.status);
            let _ = persist_one_claude_slot_collection_state(slot_id, &status);
            return status;
        }
    };
    let account_hash = resolved.account_identifier_hash.clone();
    let organization_hash = resolved.organization_identifier_hash.clone();
    let access_token = resolved.credential.access_token.take();
    let credential_available = access_token.is_some();
    let outcome = collect_claude_oauth_usage_with_access_token(
        &account_hash,
        &organization_hash,
        access_token,
        false,
    );
    let mut status = match custom_claude_snapshot_from_usage(
        resolved,
        outcome,
        credential_available,
        captured_at,
        expires_at,
    ) {
        Ok((_, status)) | Err(status) => status,
    };
    apply_claude_upkeep_observation(&mut status, upkeep.status);
    let _ = persist_one_claude_slot_collection_state(slot_id, &status);
    status
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
        ClaudeSlotProbeFailure::IdentityMismatch => ClaudeLocalIdentityFailure::IdentityMismatch,
        ClaudeSlotProbeFailure::ConcurrentMutation => {
            ClaudeLocalIdentityFailure::ConcurrentMutation
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
    Ok(ClaudeLocalIdentityProof {
        account_identifier_hash: resolved.account_identifier_hash,
        organization_identifier_hash: resolved.organization_identifier_hash,
        collection,
    })
}

fn resolve_registered_claude_slot(
    descriptor: ClaudeConfigSlotDescriptorV1,
) -> Result<ResolvedClaudeSlot, ClaudeSlotProbeFailure> {
    let config_dir = descriptor
        .config_dir
        .as_ref()
        .ok_or(ClaudeSlotProbeFailure::IdentityUnknown)?;
    let slot = ClaudeConfigDirSlot::registered(config_dir.clone())
        .map_err(|_| ClaudeSlotProbeFailure::IdentityUnknown)?;
    let initial_oauth_account = read_claude_cli_oauth_account(&slot.identity_path(&home_dir()));
    let initial_credential = read_claude_oauth_credential_for_slot(&slot);
    let auth = run_claude_slot_command(&slot, &["auth", "status", "--json"], COMMAND_TIMEOUT);
    let final_oauth_account = read_claude_cli_oauth_account(&slot.identity_path(&home_dir()));
    if !auth.command_found || !auth.success {
        return Err(ClaudeSlotProbeFailure::CredentialUnavailable);
    }
    let stable = stable_claude_slot_credential(
        initial_oauth_account,
        initial_credential,
        final_oauth_account,
    )?;
    let auth_json = serde_json::from_str::<Value>(&auth.stdout)
        .map_err(|_| ClaudeSlotProbeFailure::IdentityMismatch)?;
    let mut account = parse_claude_auth_json(&auth_json);
    if account.login_state != AgentLoginState::SignedIn {
        return Err(ClaudeSlotProbeFailure::CredentialUnavailable);
    }
    require_claude_auth_identity_agreement(&account, &stable.oauth_account)?;
    refine_claude_local_plan_metadata(&mut account, &stable.oauth_account);
    let (account_identifier_hash, organization_identifier_hash) =
        claude_strong_oauth_identity_hashes(&stable.oauth_account)
            .ok_or(ClaudeSlotProbeFailure::IdentityUnknown)?;
    if !stamp_claude_cli_account_identity(&mut account, &stable.oauth_account) {
        return Err(ClaudeSlotProbeFailure::IdentityMismatch);
    }
    account.account_identifier_hash = Some(account_identifier_hash.clone());
    account.organization_identifier_hash = Some(organization_identifier_hash.clone());
    account.billing_identity_evidence = billing_identity_evidence_for(
        &account.account_identifier_hash,
        &account.organization_identifier_hash,
        &account.credential_fingerprint_hash,
    );
    Ok(ResolvedClaudeSlot {
        descriptor,
        account,
        account_identifier_hash,
        organization_identifier_hash,
        credential: stable.credential,
    })
}

#[allow(clippy::result_large_err)]
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
    let stale = usage
        .windows
        .iter()
        .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh)
        || usage
            .credit_balances
            .iter()
            .any(|balance| balance.freshness != AgentQuotaWindowFreshness::Fresh);
    let has_account_windows =
        usage.windows.iter().any(|window| {
            window.scope == AgentQuotaWindowScope::Account && window.name == "session"
        }) && usage.windows.iter().any(|window| {
            window.scope == AgentQuotaWindowScope::Account && window.name == "weekly"
        });
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
    Ok((snapshot, state))
}

fn local_claude_quota_snapshot(
    captured_at: &str,
    quota_windows: &[AgentQuotaWindow],
    credit_balances: &[AgentCreditBalance],
    has_account_windows: bool,
    has_scoped_limits: bool,
) -> ClaudeConfigSlotQuotaSnapshotV1 {
    let stale = quota_windows
        .iter()
        .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh)
        || credit_balances
            .iter()
            .any(|balance| balance.freshness != AgentQuotaWindowFreshness::Fresh);
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
    for window in &mut snapshot.quota_windows {
        window.freshness = AgentQuotaWindowFreshness::Stale;
    }
    for balance in &mut snapshot.credit_balances {
        balance.freshness = AgentQuotaWindowFreshness::Stale;
    }
    snapshot
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
    if snapshot.state != ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
        || snapshot
            .quota_windows
            .iter()
            .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh)
        || snapshot
            .credit_balances
            .iter()
            .any(|balance| balance.freshness != AgentQuotaWindowFreshness::Fresh)
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
    (0
        ..=claude_oauth_usage_fresh_age_seconds(
            account_identifier_hash,
            organization_identifier_hash,
        ) as i64)
        .contains(&age_seconds)
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
        ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        | ClaudeConfigSlotCollectionStateV1::CollectionInProgress
        | ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
        | ClaudeConfigSlotCollectionStateV1::RefreshDue
        | ClaudeConfigSlotCollectionStateV1::StaleAccessToken
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
    status.last_full_quota_read_at = None;
    status.has_account_windows = false;
    status.has_scoped_limits = false;
    status.has_credit_balances = false;
    status.quota_snapshot = None;
}

fn retain_verified_claude_slot_binding(
    slot_id: &str,
    slot: &ClaudeConfigDirSlot,
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    let current_binding = read_claude_cli_oauth_account(&slot.identity_path(&home_dir()))
        .as_ref()
        .and_then(claude_strong_oauth_identity_hashes);
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
        return;
    };
    let (Some(previous_account), Some(previous_organization)) = (
        previous.account_identifier_hash.as_deref(),
        previous.organization_identifier_hash.as_deref(),
    ) else {
        clear_claude_slot_binding(status);
        return;
    };
    let Some((current_account, current_organization)) = current_binding else {
        clear_claude_slot_binding(status);
        return;
    };
    if current_account != previous_account || current_organization != previous_organization {
        clear_claude_slot_binding(status);
        return;
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
        return;
    }
    retain_exact_claude_slot_binding(status, &current_account, &current_organization);
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
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: None,
        subscription_product: None,
        billing_channel: Some("subscription".to_string()),
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash: Some(account_hash),
        organization_identifier_hash: Some(organization_hash),
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: Some("provider_account_id".to_string()),
        claude_quota_access_state: Some(access_state),
        claude_anchor_durability: Some(durability),
        claude_anchor_health: anchor_health,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    });
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
    snapshot.diagnostics.push(AgentStatusDiagnostic::source(
        code,
        AgentDiagnosticSeverity::Warning,
        message,
    ));
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
        ClaudeSlotProbeFailure::ConcurrentMutation,
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
                && snapshot.credit_balances.iter().all(|balance| {
                    balance.account_identifier_hash.as_deref() == Some(account_hash)
                        && balance.organization_identifier_hash.as_deref()
                            == Some(organization_hash)
                        && balance.freshness == AgentQuotaWindowFreshness::Fresh
                }) =>
        {
            let mut status = fresh_slot_status(
                &snapshot.captured_at,
                account_hash,
                organization_hash,
                snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Account && window.name == "session"
                }) && snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Account && window.name == "weekly"
                }),
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
                status.has_account_windows = snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Account && window.name == "session"
                }) && snapshot.quota_windows.iter().any(|window| {
                    window.scope == AgentQuotaWindowScope::Account && window.name == "weekly"
                });
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

fn apply_claude_upkeep_observation(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    upkeep: ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) {
    let deadline_approaching = upkeep
        .refresh_token_expires_at
        .as_deref()
        .and_then(|deadline| OffsetDateTime::parse(deadline, &Rfc3339).ok())
        .is_some_and(|deadline| {
            let now = OffsetDateTime::now_utc();
            deadline > now && deadline - now <= TimeDuration::hours(72)
        });
    match upkeep.result {
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching => {
            status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
                code: ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
                message: "This Claude login reaches its absolute refresh deadline within 72 hours; official login will be required again.".to_string(),
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
            message: "This Claude login reaches its absolute refresh deadline within 72 hours; official login will be required again.".to_string(),
        });
    }
    status.upkeep = Some(upkeep);
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
        ClaudeConfigSlotUpkeepResultV1::RefreshDue
        | ClaudeConfigSlotUpkeepResultV1::InProgress => (
            ClaudeConfigSlotCollectionStateV1::RefreshDue,
            ClaudeConfigSlotDiagnosticCodeV1::RefreshDue,
            "This expired Claude slot has one background upkeep attempt in progress.",
        ),
        ClaudeConfigSlotUpkeepResultV1::ReloginApproaching => (
            ClaudeConfigSlotCollectionStateV1::ReloginApproaching,
            ClaudeConfigSlotDiagnosticCodeV1::ReloginApproaching,
            "This Claude login reaches its absolute refresh deadline within 72 hours.",
        ),
        _ => (
            ClaudeConfigSlotCollectionStateV1::ProbeFailed,
            ClaudeConfigSlotDiagnosticCodeV1::ProbeFailed,
            "Claude Code background upkeep did not prove that this expired credential advanced; cached readings remain honestly stale.",
        ),
    }
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

fn persist_claude_slot_collection_states(
    slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    unresolved_accounts: &[ClaudeUnresolvedAccountDescriptorV1],
) -> std::io::Result<()> {
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    for (slot_id, candidate) in slots {
        let previous = persisted.slots.get(slot_id).cloned();
        merge_claude_slot_collection_state(&mut persisted.slots, slot_id, candidate);
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
    let current_slot_ids = FileClaudeConfigSlotSettingsStore::default()
        .load()
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
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    let previous = persisted.slots.get(slot_id).cloned();
    merge_claude_slot_collection_state(&mut persisted.slots, slot_id, status);
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
                unresolved.account_identifier_hash.as_deref() != Some(account_hash)
                    || exact_binding_count != 1
            });
        }
    }
    write_persisted_claude_slot_collection_state(&persisted)
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
    merge_claude_slot_collection_state_at(slots, slot_id, candidate, OffsetDateTime::now_utc());
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
                                snapshot.clone()
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
    let process = CLAUDE_SLOT_COLLECTION_STATE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(default_support_dir())?;
    #[cfg(unix)]
    let file = {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(default_support_dir().join(CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        file
    };
    #[cfg(not(unix))]
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(default_support_dir().join(CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE))?;
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

fn derive_unresolved_claude_accounts(
    desktop_snapshot: &AgentStatusSnapshot,
    full_snapshots: &[AgentStatusSnapshot],
    current_slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    now: OffsetDateTime,
) -> Vec<ClaudeUnresolvedAccountDescriptorV1> {
    let mut resolved = full_snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.quota_windows.iter().any(|window| {
                window.name == "session"
                    && window.scope == AgentQuotaWindowScope::Account
                    && window.freshness == AgentQuotaWindowFreshness::Fresh
            }) && snapshot.quota_windows.iter().any(|window| {
                window.name == "weekly"
                    && window.scope == AgentQuotaWindowScope::Account
                    && window.freshness == AgentQuotaWindowFreshness::Fresh
            }) && snapshot.quota_windows.iter().any(|window| {
                (window.scope == AgentQuotaWindowScope::Model
                    || window.model.is_some()
                    || window.group.is_some())
                    && window.freshness == AgentQuotaWindowFreshness::Fresh
            })
        })
        .filter_map(|snapshot| snapshot.account.as_ref())
        .filter_map(|account| account.account_identifier_hash.clone())
        .collect::<BTreeSet<_>>();
    resolved.extend(
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
            .filter_map(|state| state.account_identifier_hash),
    );
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
        if account_hash.is_empty() || resolved.contains(account_hash) {
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
    by_hash
        .into_iter()
        .map(|(account_hash, observed_at)| {
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
                observed_at: Some(observed_at),
                evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
            }
        })
        .collect()
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

fn claude_desktop_metadata_present(root: &Path) -> bool {
    root.join("config.json").is_file()
        || root.join("claude-code-sessions").is_dir()
        || root.join("local-agent-mode-sessions").is_dir()
}

fn claude_desktop_plan_observations_from_root(
    root: &Path,
    observed_at: &str,
) -> Vec<AgentStatusPlanObservation> {
    let config = read_claude_desktop_config(root);
    let last_known_account_uuid = config
        .last_known_account_uuid
        .as_deref()
        .and_then(safe_local_identifier)
        .map(ToString::to_string);
    let mut builders: BTreeMap<String, ClaudeDesktopProfileBuilder> = BTreeMap::new();

    collect_claude_desktop_code_sessions(
        &root.join("claude-code-sessions"),
        last_known_account_uuid.as_deref(),
        &mut builders,
    );
    collect_claude_desktop_agent_mode_sessions(
        &root.join("local-agent-mode-sessions"),
        &mut builders,
    );

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

    observations
}

/// Returns only duplicated Desktop session IDs. A session is attributed when
/// exactly one account bucket has the newest timestamp; equal or missing
/// timestamps fail closed so account cards never guess.
fn claude_desktop_unambiguous_duplicate_session_owners(
    builders: &[ClaudeDesktopProfileBuilder],
) -> BTreeMap<String, Option<(String, Option<i64>)>> {
    let mut candidates: BTreeMap<String, Vec<(String, Option<i64>)>> = BTreeMap::new();
    for builder in builders {
        for (session_id, activity) in &builder.session_activity_by_id {
            candidates
                .entry(session_id.clone())
                .or_default()
                .push((builder.account_uuid.clone(), *activity));
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
                let metadata = read_json_file::<ClaudeDesktopCodeSessionMetadata>(&file.path());
                let activity = metadata
                    .as_ref()
                    .and_then(|metadata| {
                        timestamp_value_epoch_seconds(metadata.last_activity_at.as_ref())
                            .or_else(|| timestamp_value_epoch_seconds(metadata.created_at.as_ref()))
                    })
                    .or_else(|| file_modified_epoch_seconds(&file.path()));
                let session_id = metadata
                    .and_then(|metadata| metadata.cli_session_id)
                    .and_then(|value| safe_local_identifier(&value).map(ToString::to_string));
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
            builder.organization_uuids.insert(org_uuid);
            let Ok(files) = fs::read_dir(org.path()) else {
                continue;
            };
            for file in files
                .flatten()
                .filter(|entry| looks_like_local_json_file(entry.path().as_path()))
                .take(CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG)
            {
                let Some(metadata) =
                    read_json_file::<ClaudeDesktopAgentModeSessionMetadata>(&file.path())
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
    let subscription_product = plan_type.clone().map(|plan| {
        if plan.starts_with("claude_") {
            plan
        } else {
            format!("claude_{plan}")
        }
    });
    let is_current = last_known_account_uuid == Some(builder.account_uuid.as_str());
    let activity_observed_at = builder
        .latest_activity_epoch_seconds
        .and_then(|seconds| u64::try_from(seconds).ok())
        .and_then(rfc3339_from_unix_seconds);
    Some(AgentStatusPlanObservation {
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

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let body = fs::read_to_string(path).ok()?;
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

fn collect_claude_oauth_usage_with_access_token(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    mirror_legacy_default: bool,
) -> ClaudeOAuthUsageOutcome {
    let mut outcome = collect_claude_oauth_usage_unstamped(
        account_identifier_hash,
        organization_identifier_hash,
        access_token,
        mirror_legacy_default,
    );
    if let Ok(usage) = &mut outcome.result {
        claude_oauth_stamp_account_identity(
            usage,
            account_identifier_hash,
            Some(organization_identifier_hash),
        );
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

fn collect_claude_oauth_usage_unstamped(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
    access_token: Option<String>,
    mirror_legacy_default: bool,
) -> ClaudeOAuthUsageOutcome {
    let now = current_unix_seconds();

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
            return ClaudeOAuthUsageOutcome::from(Ok(claude_oauth_usage_from_cache(cache, now)));
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
    let open_breaker = read_claude_oauth_usage_breaker_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        &config_fingerprint,
        mirror_legacy_default,
    )
    .and_then(|breaker| {
        if mirror_legacy_default {
            let _ = write_legacy_claude_oauth_usage_breaker(&breaker);
        }
        claude_oauth_usage_breaker_is_open(&breaker, now).then_some(breaker)
    });

    let mut exact_stale_fallback = None;
    if let Some(cache) = read_claude_oauth_usage_cache_with_legacy_migration(
        account_identifier_hash,
        organization_identifier_hash,
        mirror_legacy_default,
    ) {
        if mirror_legacy_default {
            let _ = write_legacy_claude_oauth_usage_cache(&cache);
        }
        let cache_age = now.saturating_sub(cache.observed_at_epoch_seconds);
        if !cache.windows.is_empty()
            && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
            && (cache_age
                <= claude_oauth_usage_fresh_age_seconds(
                    account_identifier_hash,
                    organization_identifier_hash,
                )
                || now < cache.next_refresh_after_epoch_seconds)
        {
            return ClaudeOAuthUsageOutcome::from(Ok(claude_oauth_usage_from_cache(cache, now)));
        }
        if now < cache.next_refresh_after_epoch_seconds {
            return ClaudeOAuthUsageOutcome::from(Err(
                "Claude OAuth usage endpoint is rate limited.".to_string(),
            ));
        }
        if !cache.windows.is_empty() && cache_age <= CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS {
            exact_stale_fallback = Some(cache);
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
            };
        }
        if let Some(breaker) = open_breaker {
            return ClaudeOAuthUsageOutcome {
                result: Err("Claude OAuth usage endpoint is not being called.".to_string()),
                diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
            };
        }
        return ClaudeOAuthUsageOutcome::from(Err(
            "Claude OAuth credentials were not available locally.".to_string(),
        ));
    };
    if let Some(breaker) = open_breaker {
        if let Some(cache) = exact_stale_fallback {
            return ClaudeOAuthUsageOutcome {
                result: Ok(claude_oauth_usage_from_cache(cache, now)),
                diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
            };
        }
        return ClaudeOAuthUsageOutcome {
            result: Err("Claude OAuth usage endpoint is not being called.".to_string()),
            diagnostics: vec![claude_oauth_usage_circuit_open_diagnostic(&breaker, now)],
        };
    }
    let authorization = format!("Bearer {token}");
    let user_agent = ottto_user_agent();
    #[cfg(test)]
    CLAUDE_OAUTH_PROVIDER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let response = ureq::get(CLAUDE_OAUTH_USAGE_ENDPOINT)
        .set("Accept", "application/json")
        .set("Content-Type", "application/json")
        .set("Authorization", &authorization)
        .set("anthropic-beta", CLAUDE_OAUTH_BETA_HEADER)
        .set("User-Agent", &user_agent)
        .timeout(COMMAND_TIMEOUT)
        .call();
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(429, response)) => {
            let retry_after = claude_oauth_retry_after_epoch_seconds(&response, now);
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
            });
            cache.next_refresh_after_epoch_seconds = retry_after;
            let _ = write_claude_oauth_usage_cache(&cache);
            if mirror_legacy_default {
                let _ = write_legacy_claude_oauth_usage_cache(&cache);
            }
            // The retry-after backoff above still handles the transient case
            // unchanged; the breaker only fires once 429s outlive it.
            let diagnostics = record_claude_oauth_usage_failure_with_legacy(
                ClaudeOAuthUsageFailure::RateLimited,
                account_identifier_hash,
                organization_identifier_hash,
                &config_fingerprint,
                now,
                mirror_legacy_default,
            );
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
            let diagnostics = match claude_oauth_usage_failure_class(&error) {
                Some(failure) => record_claude_oauth_usage_failure_with_legacy(
                    failure,
                    account_identifier_hash,
                    organization_identifier_hash,
                    &config_fingerprint,
                    now,
                    mirror_legacy_default,
                ),
                None => Vec::new(),
            };
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
    let Ok(value) = response.into_json::<Value>() else {
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
        };
    };
    let mut usage = ClaudeOAuthUsage {
        windows: claude_oauth_quota_windows(&value),
        credit_balances: claude_oauth_credit_balances(&value),
    };
    if usage.windows.is_empty() {
        // A 200 that carries none of the expected quota fields is a shape
        // change, not an empty account: every plan this endpoint answers for
        // reports at least one window.
        return ClaudeOAuthUsageOutcome {
            result: Ok(usage),
            diagnostics: record_claude_oauth_usage_failure_with_legacy(
                ClaudeOAuthUsageFailure::ResponseShape,
                account_identifier_hash,
                organization_identifier_hash,
                &config_fingerprint,
                now,
                mirror_legacy_default,
            ),
        };
    }
    claude_oauth_stamp_account_identity(
        &mut usage,
        account_identifier_hash,
        Some(organization_identifier_hash),
    );
    let cache = ClaudeOAuthUsageCache {
        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
        account_identifier_hash: account_identifier_hash.to_string(),
        organization_identifier_hash: organization_identifier_hash.to_string(),
        observed_at_epoch_seconds: now,
        next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
        windows: usage.windows.clone(),
        credit_balances: usage.credit_balances.clone(),
    };
    let _ = write_claude_oauth_usage_cache(&cache);
    if mirror_legacy_default {
        let _ = write_legacy_claude_oauth_usage_cache(&cache);
    }
    // One clean answer clears the accumulated failure counters: the thresholds
    // below are about *consecutive* failures.
    clear_claude_oauth_usage_breaker_with_legacy(
        account_identifier_hash,
        organization_identifier_hash,
        mirror_legacy_default,
    );
    ClaudeOAuthUsageOutcome::from(Ok(usage))
}

impl From<Result<ClaudeOAuthUsage, String>> for ClaudeOAuthUsageOutcome {
    fn from(result: Result<ClaudeOAuthUsage, String>) -> Self {
        Self {
            result,
            diagnostics: Vec::new(),
        }
    }
}

/// Effective freshness gate for the Claude OAuth usage read: the ~60-minute
/// base cadence spread deterministically across a 55-65 minute band.
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
    let lock_path = account_root.join(".collection-attempt.lock");
    #[cfg(unix)]
    let file = {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(lock_path)
            .ok()?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return None;
        }
        file
    };
    #[cfg(not(unix))]
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(lock_path)
        .ok()?;
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
    let body = fs::read_to_string(claude_oauth_usage_breaker_path(
        account_identifier_hash,
        organization_identifier_hash,
    ))
    .ok()?;
    let breaker: ClaudeOAuthUsageBreaker = serde_json::from_str(&body).ok()?;
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
    let Some(breaker) = fs::read_to_string(&legacy)
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
    read_claude_oauth_credential_from_keychain(slot)
        .or_else(|| read_claude_oauth_credential_from_credentials_file(slot))
}

pub(crate) fn read_claude_oauth_credential_metadata_for_slot(
    slot: &ClaudeConfigDirSlot,
) -> Option<ClaudeOAuthCredentialMetadata> {
    let credential = read_claude_oauth_credential_for_slot(slot)?;
    Some(ClaudeOAuthCredentialMetadata {
        access_expires_at: credential.access_expires_at,
        refresh_token_expires_at: credential.relogin_required_at,
        has_refresh_token: credential.has_refresh_token,
    })
}

fn read_claude_oauth_credential_from_keychain(
    slot: &ClaudeConfigDirSlot,
) -> Option<ClaudeOAuthCredential> {
    let account = effective_user_account_name()?;
    let arguments = claude_oauth_keychain_lookup_arguments(slot, &account)?;
    let argument_refs: Vec<_> = arguments.iter().map(String::as_str).collect();
    let output = run_command_capture("security", &argument_refs, COMMAND_TIMEOUT);
    if !output.command_found || !output.success {
        return None;
    }
    parse_claude_oauth_credential(&output.stdout)
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
) -> Option<ClaudeOAuthCredential> {
    let path = slot.credentials_path(&home_dir());
    let body = fs::read_to_string(path).ok()?;
    parse_claude_oauth_credential(&body)
}

#[cfg(test)]
fn parse_claude_oauth_access_token(payload: &str) -> Option<String> {
    parse_claude_oauth_credential(payload)?.access_token
}

fn parse_claude_oauth_credential(payload: &str) -> Option<ClaudeOAuthCredential> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let oauth = value.get("claudeAiOauth")?;
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
    Some(ClaudeOAuthCredential {
        access_token,
        has_refresh_token,
        access_expires_at: timestamp("expiresAt"),
        relogin_required_at: timestamp("refreshTokenExpiresAt"),
    })
}

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
    claude_oauth_spend_credit_balance(value.get("spend"))
        .or_else(|| claude_oauth_extra_usage_credit_balance(value.get("extra_usage")))
        .into_iter()
        .collect()
}

fn claude_oauth_spend_credit_balance(spend: Option<&Value>) -> Option<AgentCreditBalance> {
    let spend = spend?;
    if spend.get("enabled").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let used = claude_oauth_money_cents(spend.get("used"));
    let quota = claude_oauth_money_cents(spend.get("cap"))
        .or_else(|| claude_oauth_money_cents(spend.get("limit")));
    let remaining =
        claude_oauth_money_cents(spend.get("balance")).or_else(|| match (quota, used) {
            (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
            _ => None,
        });
    if used.is_none() && quota.is_none() && remaining.is_none() {
        return None;
    }
    let used_percent = json_u8(spend, &["percent"]).or_else(|| match (used, quota) {
        (Some(used), Some(quota)) if quota > 0 => {
            Some(((used.saturating_mul(100)) / quota).min(100) as u8)
        }
        _ => None,
    });
    let severity = spend.get("severity").and_then(Value::as_str).unwrap_or("");
    Some(AgentCreditBalance {
        name: "Usage credits".to_string(),
        status: claude_oauth_credit_status(severity, used, quota, remaining),
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining,
        used,
        quota,
        currency: claude_oauth_money_currency(spend.get("used"))
            .or_else(|| json_trimmed_string(spend, "currency")),
        resets_at: json_timestamp_rfc3339(spend, &["resets_at", "reset_at"]),
        used_percent,
        enabled: Some(true),
        ..Default::default()
    })
}

fn claude_oauth_extra_usage_credit_balance(extra: Option<&Value>) -> Option<AgentCreditBalance> {
    let extra = extra?;
    if extra.get("is_enabled").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let quota = claude_oauth_money_cents(extra.get("monthly_limit"));
    let used = claude_oauth_money_cents(extra.get("used_credits"));
    let remaining = match (quota, used) {
        (Some(quota), Some(used)) => Some(quota.saturating_sub(used)),
        _ => None,
    };
    if used.is_none() && quota.is_none() {
        return None;
    }
    let used_percent = json_u8(extra, &["utilization"]);
    Some(AgentCreditBalance {
        name: "Usage credits".to_string(),
        status: claude_oauth_credit_status("", used, quota, remaining),
        freshness: AgentQuotaWindowFreshness::Fresh,
        unit: AgentCreditBalanceUnit::Usd,
        remaining,
        used,
        quota,
        currency: json_trimmed_string(extra, "currency"),
        resets_at: None,
        used_percent,
        enabled: Some(true),
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
/// "USD", "exponent": 2}` (exponent 0..=6, scaled to 2 with round-half-up on
/// downscale) or a bare non-negative number interpreted as whole dollars.
fn claude_oauth_money_cents(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if let Some(object) = value.as_object() {
        let amount_minor = object.get("amount_minor").and_then(Value::as_i64)?;
        if amount_minor < 0 {
            return None;
        }
        let amount_minor = amount_minor as u64;
        let exponent = object.get("exponent").and_then(Value::as_u64).unwrap_or(2);
        if exponent > 6 {
            return None;
        }
        return Some(match exponent.cmp(&2) {
            std::cmp::Ordering::Equal => amount_minor,
            std::cmp::Ordering::Less => {
                amount_minor.saturating_mul(10_u64.pow((2 - exponent) as u32))
            }
            std::cmp::Ordering::Greater => {
                let divisor = 10_u64.pow((exponent - 2) as u32);
                (amount_minor + divisor / 2) / divisor
            }
        });
    }
    let dollars = value.as_f64()?;
    if !dollars.is_finite() || dollars < 0.0 {
        return None;
    }
    Some((dollars * 100.0).round() as u64)
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
    // Same jittered gate the refresh decision uses, seeded from the account the
    // cache belongs to: a payload served as fresh must not be labelled stale.
    let cache_is_stale = cache_age
        > claude_oauth_usage_fresh_age_seconds(
            &cache.account_identifier_hash,
            &cache.organization_identifier_hash,
        );
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
        credit_balances: cache
            .credit_balances
            .into_iter()
            .map(|mut credit| {
                credit.freshness = if cache_is_stale {
                    AgentQuotaWindowFreshness::Stale
                } else {
                    AgentQuotaWindowFreshness::Fresh
                };
                credit
            })
            .collect(),
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
    AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("claude_statusline_context_window".to_string()),
        recent_samples: Vec::new(),
        observed_at,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some(reason.to_string()),
        posture: None,
    }
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
    if !executable_exists("pi") && !home_path(".pi").exists() {
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
        auth_method: None,
        email: read_pi_safe_auth_metadata()
            .and_then(|metadata| first_json_string(&metadata, &["email"])),
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
        confidence: AgentStatusConfidence::Low,
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
            "Pi model route read from ~/.pi/agent/settings.json.",
        ));
    }
    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
    snapshot.context = Some(AgentContextStatus {
        status: AgentContextState::Unsupported,
        active_tokens: None,
        max_tokens: None,
        used_percent: None,
        remaining_tokens: None,
        source: Some("pi_cli_v1".to_string()),
        recent_samples: Vec::new(),
        observed_at: None,
        completeness: Some(AgentContextCompleteness::Unavailable),
        reason: Some("pi_active_context_not_collected".to_string()),
        posture: None,
    });
    snapshot.capabilities = vec![
        supported_capability(
            "model_list",
            "Collected from ~/.pi/agent/settings.json enabledModels, falling back to pi --list-models.",
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
    let Some(account) = &snapshot.account else {
        return;
    };
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
        return;
    }
    snapshot.plan_observations.push(AgentStatusPlanObservation {
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
        is_current: Some(
            account.login_state == AgentLoginState::SignedIn
                && matches!(
                    account.confidence,
                    AgentStatusConfidence::High | AgentStatusConfidence::Medium
                ),
        ),
    });
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
        confidence: AgentStatusConfidence::High,
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
            confidence: AgentStatusConfidence::Medium,
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
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(|plan| format!("chatgpt_{plan}")),
        billing_channel: Some("subscription".to_string()),
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
        confidence: AgentStatusConfidence::Medium,
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
        organization_label: None,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.map(chatgpt_subscription_product),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start,
        subscription_period_end,
        subscription_period_last_checked_at,
        account_identifier_hash: None,
        organization_identifier_hash: None,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: None,
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::Low,
        confidence: AgentStatusConfidence::Low,
    })
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
    let claims = structurally_valid_live_codex_jwt_claims(credentials.access_token.as_deref()?)?;
    let auth_claim = claims.get("https://api.openai.com/auth");
    let account_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
        .or_else(|| first_json_string(&claims, &["sub"]))?;
    let raw_workspace_id = auth_claim
        .and_then(|value| first_json_string(value, &["chatgpt_account_id"]))
        .or_else(|| first_json_string(&claims, &["chatgpt_account_id"]))?;
    if credentials.account_id.as_deref() != Some(raw_workspace_id.as_str()) {
        return None;
    }
    if let Some(id_token) = credentials.id_token.as_deref() {
        let id_claims = structurally_valid_live_codex_jwt_claims(id_token)?;
        let id_auth_claim = id_claims.get("https://api.openai.com/auth");
        let id_account = id_auth_claim
            .and_then(|value| first_json_string(value, &["chatgpt_user_id", "user_id"]))
            .or_else(|| first_json_string(&id_claims, &["sub"]))?;
        let id_workspace = id_auth_claim
            .and_then(|value| first_json_string(value, &["chatgpt_account_id"]))
            .or_else(|| first_json_string(&id_claims, &["chatgpt_account_id"]))?;
        if id_account != account_id || id_workspace != raw_workspace_id {
            return None;
        }
    }
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
    let expires_at = claims.get("exp").and_then(Value::as_i64)?;
    if expires_at <= OffsetDateTime::now_utc().unix_timestamp() {
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
) -> Result<CodexUsageProbe, String> {
    let observation = call_codex_app_server_rate_limits_for_home(codex_home, home_trust)?;
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
    Ok(CodexUsageProbe {
        quota_windows: codex_app_server_quota_windows(&observation.rate_limits),
        credit_balances: codex_app_server_credit_balances(&observation.rate_limits),
        account: codex_app_server_account(&observation.account),
        identity,
        credential_read_failed: observation.credential_read_failed,
    })
}

struct CodexAppServerObservation {
    account: Value,
    rate_limits: Value,
    refreshed_credentials: Option<CodexAuthCredentials>,
    credential_read_failed: bool,
}

fn call_codex_app_server_rate_limits_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<CodexAppServerObservation, String> {
    let Some(program_path) = crate::command_env::executable_path("codex") else {
        return Err("Codex CLI was not found for app-server rate-limit collection.".to_string());
    };
    let Some(identity) = effective_user_identity() else {
        return Err("Codex app-server user identity was unavailable.".to_string());
    };
    let mut command = Command::new(program_path);
    command.args(["app-server", "--stdio"]).env_clear();
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
    let mut child = command
        .spawn()
        .map_err(|_| "Codex app-server could not be started.".to_string())?;
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
    let account = serde_json::json!({
        "method": "account/read",
        "id": "ottto_account",
        "params": {"refreshToken": true}
    });
    let read = serde_json::json!({
        "method": "account/rateLimits/read",
        "id": "ottto_rate_limits"
    });
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
    let mut account_result = None;
    let mut rate_limits_result = None;
    let mut rate_limits_requested = false;
    while start.elapsed() < CODEX_APP_SERVER_TIMEOUT {
        let remaining = CODEX_APP_SERVER_TIMEOUT
            .checked_sub(start.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));
        match receiver.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(Err(message)) => {
                drop(stdin);
                let _ = child.kill();
                let _ = child.wait();
                return Err(message);
            }
            Ok(Ok(message)) => {
                let response_id = message.get("id").and_then(Value::as_str);
                if matches!(response_id, Some("ottto_account" | "ottto_rate_limits"))
                    && message.get("error").is_some()
                {
                    drop(stdin);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("Codex app-server account/quota read failed.".to_string());
                }
                if response_id == Some("ottto_account") {
                    account_result = message.get("result").cloned();
                } else if response_id == Some("ottto_rate_limits") {
                    rate_limits_result = message.get("result").cloned();
                }
                if account_result.is_some() && !rate_limits_requested {
                    if serde_json::to_writer(&mut stdin, &read)
                        .map_err(|_| "Codex app-server request serialization failed.".to_string())
                        .and_then(|()| {
                            stdin
                                .write_all(b"\n")
                                .map_err(|_| "Codex app-server request write failed.".to_string())
                        })
                        .and_then(|()| {
                            stdin
                                .flush()
                                .map_err(|_| "Codex app-server request flush failed.".to_string())
                        })
                        .is_err()
                    {
                        drop(stdin);
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err("Codex app-server quota request failed.".to_string());
                    }
                    rate_limits_requested = true;
                }
                if account_result.is_some() && rate_limits_result.is_some() {
                    let account = account_result.take().expect("checked account result");
                    let rate_limits = rate_limits_result
                        .take()
                        .expect("checked rate-limit result");
                    let (refreshed_credentials, credential_read_failed) =
                        match read_codex_auth_credentials_at(codex_home, home_trust) {
                            Ok(credentials) => (credentials, false),
                            Err(_) => (None, true),
                        };
                    drop(stdin);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(CodexAppServerObservation {
                        account,
                        rate_limits,
                        refreshed_credentials,
                        credential_read_failed,
                    });
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    Err("Codex app-server rate-limit read timed out.".to_string())
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
            Err(_) => return,
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
        if let Ok(value) = serde_json::from_str::<Value>(line) {
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
    value
        .get("rateLimits")
        .filter(|snapshot| codex_rate_limit_snapshot_has_usage(snapshot))
        .map(|snapshot| {
            vec![(
                first_json_string(snapshot, &["limitId", "limit_id"])
                    .unwrap_or_else(|| "codex".to_string()),
                snapshot,
            )]
        })
        .unwrap_or_default()
}

fn codex_rate_limit_snapshot_has_usage(value: &Value) -> bool {
    value.get("primary").is_some()
        || value.get("secondary").is_some()
        || value.get("credits").is_some()
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
    if let Some(reset_credits) = value.get("rateLimitResetCredits") {
        if let Some(remaining) = json_u64(reset_credits, &["availableCount", "available_count"]) {
            let balance = AgentCreditBalance {
                name: "reset_bank".to_string(),
                status: if remaining == 0 {
                    AgentCreditBalanceStatus::Exhausted
                } else {
                    AgentCreditBalanceStatus::Ok
                },
                freshness: AgentQuotaWindowFreshness::Fresh,
                unit: AgentCreditBalanceUnit::Resets,
                account_label: None,
                remaining: Some(remaining),
                used: None,
                quota: None,
                unlimited: Some(false),
                updated_at: None,
                ..Default::default()
            };
            balances.insert(balance.name.clone(), balance);
        }
    }
    balances.into_values().collect()
}

/// Parse Codex's effective workspace monthly credit limit.
///
/// The supported app-server surface calls this `individualLimit`; the legacy
/// `wham/usage` fallback uses `individual_limit`. It is a recurring budget, not
/// the earned reset bank and not the sparse `credits.balance`, so it gets a
/// stable, separate identity downstream.
fn codex_monthly_credit_limit_from_snapshot(container: &Value) -> Option<AgentCreditBalance> {
    let individual_limit = container
        .get("individualLimit")
        .or_else(|| container.get("individual_limit"))?;
    if individual_limit.is_null() {
        return None;
    }

    let quota = json_u64(individual_limit, &["limit"]);
    let used = json_u64(individual_limit, &["used"]);
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
        || remaining == Some(0)
        || remaining_percent == Some(0)
    {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining_percent.is_some_and(|value| value <= 20) {
        AgentCreditBalanceStatus::Low
    } else {
        AgentCreditBalanceStatus::Ok
    };

    Some(AgentCreditBalance {
        name: "workspace_monthly_credits".to_string(),
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
    let remaining = json_u64(credits, &["balance", "remaining", "credits"]);
    let unlimited = json_bool(credits, &["unlimited"]);
    let has_credits_claim = json_bool(credits, &["hasCredits", "has_credits"]);
    let has_credits = has_credits_claim.unwrap_or(false);
    // `credits` sits beside `primary`/`secondary` on the rate-limit snapshot; the
    // sibling `spend_control_reached`, `rate_limit_reached_type`, and `limit_id`
    // fields (e.g. `limitId: "codex"`) live on that container. Mirror the OAuth
    // wham/usage path so both collectors carry the spend-cap contract.
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
        name: "credits".to_string(),
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
    remaining: Option<u64>,
    spend_control_reached: Option<bool>,
) -> bool {
    has_credits_claim == Some(false)
        && unlimited != Some(true)
        && spend_control_reached != Some(true)
        && remaining.unwrap_or(0) == 0
}

fn codex_credit_balance_status(
    remaining: Option<u64>,
    unlimited: Option<bool>,
    has_credits: bool,
) -> AgentCreditBalanceStatus {
    if unlimited == Some(true) {
        AgentCreditBalanceStatus::Unlimited
    } else if remaining == Some(0) {
        AgentCreditBalanceStatus::Exhausted
    } else if remaining.is_some_and(|value| value > 0 && value <= 5) {
        AgentCreditBalanceStatus::Low
    } else if remaining.is_some() || has_credits {
        AgentCreditBalanceStatus::Ok
    } else {
        AgentCreditBalanceStatus::Unknown
    }
}

fn legacy_codex_oauth_usage_enabled() -> bool {
    std::env::var("OTTTO_CODEX_LEGACY_OAUTH_USAGE")
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn legacy_codex_oauth_fallback_allowed(is_default_slot: bool) -> bool {
    is_default_slot && legacy_codex_oauth_usage_enabled()
}

fn collect_codex_oauth_usage_at(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<CodexUsageProbe, String> {
    let credentials = read_codex_auth_credentials_at(codex_home, home_trust)
        .map_err(|_| "Codex OAuth credentials could not be read safely.".to_string())?
        .ok_or_else(|| "Codex OAuth credentials were not found.".to_string())?;
    let access_token = credentials
        .access_token
        .as_deref()
        .ok_or_else(|| "Codex OAuth access token was not available.".to_string())?;
    let authorization = format!("Bearer {access_token}");
    let mut request = ureq::get("https://chatgpt.com/backend-api/wham/usage")
        .set("Accept", "application/json")
        .set("Authorization", &authorization)
        .timeout(COMMAND_TIMEOUT);
    if let Some(account_id) = credentials.account_id.as_deref() {
        request = request.set("ChatGPT-Account-Id", account_id);
    }
    let value: Value = request
        .call()
        .map_err(codex_usage_probe_error)?
        .into_json()
        .map_err(|_| "Codex usage endpoint returned an unreadable response.".to_string())?;
    let identity = validated_codex_identity(&credentials, None, None, true);
    Ok(CodexUsageProbe {
        quota_windows: codex_usage_quota_windows(&value),
        credit_balances: codex_usage_credit_balances(&value),
        account: None,
        identity,
        credential_read_failed: false,
    })
}

fn codex_usage_probe_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) if status == 401 || status == 403 => {
            "Codex usage endpoint rejected the local OAuth session.".to_string()
        }
        ureq::Error::Status(status, _) => {
            format!("Codex usage endpoint returned HTTP {status}.")
        }
        ureq::Error::Transport(_) => "Codex usage endpoint was unreachable.".to_string(),
    }
}

fn codex_usage_quota_windows(value: &Value) -> Vec<AgentQuotaWindow> {
    // The wham/usage payload historically nested the windows under `rate_limit`
    // with `primary_window`/`secondary_window` keys. Since OpenAI's 2026-07-12
    // change the fields can arrive top-level as `primary`/`secondary` (with the
    // primary window now weekly and secondary null). Locate the container either
    // way, then accept both the legacy and current key names.
    let container = value
        .get("rate_limit")
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let mut windows = Vec::new();
    if let Some(primary) = container
        .get("primary_window")
        .or_else(|| container.get("primary"))
    {
        if let Some(window) = codex_usage_quota_window("primary", primary) {
            windows.push(window);
        }
    }
    if let Some(secondary) = container
        .get("secondary_window")
        .or_else(|| container.get("secondary"))
    {
        if let Some(window) = codex_usage_quota_window("secondary", secondary) {
            windows.push(window);
        }
    }
    windows
}

/// Window duration in seconds, reading `*_seconds` first and falling back to the
/// minutes-denominated fields (`limit_window_minutes`/`window_minutes`) that the
/// current wham/usage payload reports.
fn codex_usage_window_seconds(value: &Value) -> Option<u64> {
    json_u64(value, &["limit_window_seconds", "window_seconds"]).or_else(|| {
        json_u64(value, &["limit_window_minutes", "window_minutes"])
            .and_then(|minutes| minutes.checked_mul(60))
    })
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

fn codex_usage_quota_window(window_key: &str, value: &Value) -> Option<AgentQuotaWindow> {
    let used_percent = json_u8(value, &["used_percent", "usedPercent"]);
    let left_percent = used_percent.map(|used| 100_u8.saturating_sub(used));
    let resets_at = json_timestamp_rfc3339(value, &["reset_at", "resets_at", "resetAt"]);
    let window_seconds = codex_usage_window_seconds(value);
    let started_at = resets_at
        .as_deref()
        .zip(window_seconds)
        .and_then(|(reset, seconds)| rfc3339_minus_seconds(reset, seconds));
    if used_percent.is_none() && resets_at.is_none() && window_seconds.is_none() {
        return None;
    }
    Some(AgentQuotaWindow {
        name: codex_usage_window_key("legacy", window_key, window_seconds, resets_at.is_some()),
        scope: AgentQuotaWindowScope::Account,
        status: match left_percent {
            Some(0) => AgentQuotaWindowStatus::Exhausted,
            Some(value) if value <= 20 => AgentQuotaWindowStatus::NearLimit,
            Some(_) => AgentQuotaWindowStatus::Ok,
            None => AgentQuotaWindowStatus::Unknown,
        },
        freshness: AgentQuotaWindowFreshness::Fresh,
        model: None,
        account_label: None,
        window_seconds,
        started_at,
        resets_at,
        quota: None,
        remaining: None,
        used_percent,
        left_percent,
        ..Default::default()
    })
}

fn codex_usage_credit_balances(value: &Value) -> Vec<AgentCreditBalance> {
    // `credits` sits beside `primary`/`secondary`; the sibling `spend_control_reached`,
    // `rate_limit_reached_type`, and `limit_id` fields live on the same container.
    let container = value
        .get("rate_limit")
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let mut balances = Vec::new();
    let Some(credits) = container.get("credits") else {
        return codex_monthly_credit_limit_from_snapshot(container)
            .into_iter()
            .collect();
    };
    let remaining = json_u64(credits, &["balance", "remaining", "credits"]);
    let unlimited = json_bool(credits, &["unlimited"]);
    let has_credits_claim = json_bool(credits, &["has_credits", "hasCredits"]);
    let has_credits = has_credits_claim.unwrap_or(false);
    let spend_control_reached =
        json_bool(container, &["spend_control_reached", "spendControlReached"]);
    let rate_limit_reached_type = first_json_string(
        container,
        &["rate_limit_reached_type", "rateLimitReachedType"],
    );
    let limit_id = first_json_string(container, &["limit_id", "limitId"]);
    if (remaining.is_none()
        && unlimited.is_none()
        && !has_credits
        && spend_control_reached != Some(true))
        || codex_credits_do_not_apply(
            has_credits_claim,
            unlimited,
            remaining,
            spend_control_reached,
        )
    {
        if let Some(monthly) = codex_monthly_credit_limit_from_snapshot(container) {
            balances.push(monthly);
        }
        return balances;
    }
    // A reached spend control means the account is spend-capped even if a nominal
    // credit figure remains, so treat it as exhausted regardless of the balance.
    let status = if spend_control_reached == Some(true) {
        AgentCreditBalanceStatus::Exhausted
    } else {
        codex_credit_balance_status(remaining, unlimited, has_credits)
    };
    balances.push(AgentCreditBalance {
        name: "credits".to_string(),
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
    });
    if let Some(monthly) = codex_monthly_credit_limit_from_snapshot(container) {
        balances.push(monthly);
    }
    balances
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
    organization_type: Option<String>,
    seat_tier: Option<String>,
    organization_rate_limit_tier: Option<String>,
    user_rate_limit_tier: Option<String>,
}

/// Full-meter collection requires positive agreement from the exact slot's
/// live auth status and its local account metadata. The real Claude auth JSON
/// reports email and organization UUID (not account UUID), so both fields must
/// be present and equal before the account UUID from that exact slot's identity
/// file may become strong meter identity. Absence of contradiction is not
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
/// `claude auth status` reports a bare `team` for every seat tier and a bare
/// `max` for BOTH Max tiers, so the only disambiguator is the rate-limit /
/// seat metadata in the slot's own `.claude.json`. Every collector that parses
/// `claude auth status` must run these refinements, not just the default slot:
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

fn pi_billing_channel(provider: &str) -> &str {
    match provider {
        "openai-codex" | "anthropic" | "github-copilot" => "subscription",
        "amazon-bedrock" => "amazon_bedrock",
        "google-vertex" => "google_vertex",
        "azure-openai-responses" => "azure_openai",
        "cloudflare-ai-gateway" | "cloudflare-workers-ai" | "vercel-ai-gateway" => "gateway",
        _ => "direct_api",
    }
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
        "vercel-ai-gateway" | "vercel_ai_gateway" => {
            gateway_classification("vercel_ai_gateway", &model_key)
        }
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
            billing_channel: Some(pi_billing_channel(other).to_string()),
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

fn pi_agent_dir() -> PathBuf {
    if let Ok(value) = std::env::var("PI_CODING_AGENT_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            if let Some(relative) = trimmed.strip_prefix("~/") {
                return home_path(relative);
            }
            return PathBuf::from(trimmed);
        }
    }
    home_path(".pi/agent")
}

fn pi_agent_auth_path() -> PathBuf {
    pi_agent_dir().join("auth.json")
}

fn pi_agent_settings_path() -> PathBuf {
    pi_agent_dir().join("settings.json")
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
    run_command_capture_with_exact_env(program, args, timeout, None)
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

fn run_claude_slot_command(
    slot: &ClaudeConfigDirSlot,
    args: &[&str],
    timeout: Duration,
) -> CommandOutput {
    let Some(mut command) = resolved_claude_slot_command(slot, args) else {
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

/// Resolve Claude once and apply the single shared sanitized exact-slot
/// environment used by auth observation and background upkeep. No provider or
/// token-shaped ambient variables survive `env_clear`.
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
    claude_slot: Option<&ClaudeConfigDirSlot>,
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
    let mut command = if let Some(slot) = claude_slot {
        let Some(command) = resolved_claude_slot_command(slot, args) else {
            return CommandOutput {
                command_found: false,
                success: false,
                status_code: None,
                stdout: String::new(),
                stderr: String::new(),
            };
        };
        command
    } else {
        let mut command = Command::new(program_path);
        command.args(args);
        if let Some(path_env) = crate::command_env::path_env() {
            command.env("PATH", path_env);
        }
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_prepared_command_capture(command, timeout)
}

fn run_prepared_command_capture(mut command: Command, timeout: Duration) -> CommandOutput {
    let start = Instant::now();
    let mut child = match command.spawn() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The account resolution `collect_claude_status` performs, for tests that
    /// exercise the OAuth path directly.
    fn claude_oauth_account_identifier_hash() -> String {
        read_claude_cli_oauth_account(&claude_cli_config_path())
            .as_ref()
            .map(claude_oauth_account_identifier_hash_for)
            .unwrap_or_default()
    }

    fn local_meter_fixture(
        account_hash: &str,
        organization_hash: &str,
    ) -> ClaudeConfigSlotQuotaSnapshotV1 {
        local_claude_quota_snapshot(
            "2026-08-05T01:05:00Z",
            &[
                AgentQuotaWindow {
                    name: "session".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    observed_at: Some("2026-08-05T01:02:00Z".to_string()),
                    account_identifier_hash: Some(account_hash.to_string()),
                    organization_identifier_hash: Some(organization_hash.to_string()),
                    used_percent: Some(12),
                    ..Default::default()
                },
                AgentQuotaWindow {
                    name: "weekly".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    observed_at: Some("2026-08-05T01:01:00Z".to_string()),
                    account_identifier_hash: Some(account_hash.to_string()),
                    organization_identifier_hash: Some(organization_hash.to_string()),
                    used_percent: Some(34),
                    ..Default::default()
                },
                AgentQuotaWindow {
                    name: "weekly_sonnet".to_string(),
                    scope: AgentQuotaWindowScope::Model,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    observed_at: Some("2026-08-05T01:03:00Z".to_string()),
                    model: Some("claude-sonnet".to_string()),
                    account_identifier_hash: Some(account_hash.to_string()),
                    organization_identifier_hash: Some(organization_hash.to_string()),
                    used_percent: Some(56),
                    ..Default::default()
                },
            ],
            &[AgentCreditBalance {
                name: "Usage credits".to_string(),
                freshness: AgentQuotaWindowFreshness::Fresh,
                account_identifier_hash: Some(account_hash.to_string()),
                organization_identifier_hash: Some(organization_hash.to_string()),
                remaining: Some(789),
                updated_at: Some("2026-08-05T01:04:00Z".to_string()),
                ..Default::default()
            }],
            true,
            true,
        )
    }

    #[test]
    fn local_claude_meter_values_have_typed_fresh_stale_partial_and_safe_freshness() {
        let account_hash = "a".repeat(64);
        let organization_hash = "b".repeat(64);
        let fresh = local_meter_fixture(&account_hash, &organization_hash);
        assert_eq!(fresh.state, ClaudeConfigSlotQuotaSnapshotStateV1::Fresh);
        assert_eq!(fresh.captured_at, "2026-08-05T01:05:00Z");
        assert_eq!(fresh.observed_at.as_deref(), Some("2026-08-05T01:01:00Z"));
        assert_eq!(fresh.quota_windows.len(), 3);
        assert_eq!(fresh.credit_balances.len(), 1);

        let stale = stale_local_claude_quota_snapshot(&fresh);
        assert_eq!(stale.state, ClaudeConfigSlotQuotaSnapshotStateV1::Stale);
        assert!(stale
            .quota_windows
            .iter()
            .all(|window| window.freshness == AgentQuotaWindowFreshness::Stale));
        assert!(stale
            .credit_balances
            .iter()
            .all(|balance| balance.freshness == AgentQuotaWindowFreshness::Stale));

        let partial = local_claude_quota_snapshot(
            "2026-08-05T01:05:00Z",
            &fresh.quota_windows[..2],
            &[],
            true,
            false,
        );
        assert_eq!(partial.state, ClaudeConfigSlotQuotaSnapshotStateV1::Partial);
        assert!(!local_claude_quota_snapshot_within_retention(
            &fresh,
            OffsetDateTime::parse("2026-08-05T01:00:59Z", &Rfc3339).expect("now")
        ));

        let wire = serde_json::to_string(&fresh).expect("serialize local meters");
        assert!(wire.contains("weekly_sonnet"));
        assert!(wire.contains("Usage credits"));
        for forbidden in [
            "accessToken",
            "refreshToken",
            "claudeAiOauth",
            "CLAUDE_CONFIG_DIR",
            ".credentials.json",
            "Claude Code-credentials",
        ] {
            assert!(!wire.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn local_claude_meter_stale_reuse_requires_same_strong_account_and_org() {
        let account_hash = "a".repeat(64);
        let organization_hash = "b".repeat(64);
        let fresh_now = OffsetDateTime::parse("2026-08-05T02:00:00Z", &Rfc3339).expect("fresh now");
        let expired_now =
            OffsetDateTime::parse("2026-08-06T02:00:00Z", &Rfc3339).expect("expired now");
        let existing = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-05T01:00:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-05T01:00:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            has_credit_balances: true,
            quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
            ..Default::default()
        };
        let mut slots = BTreeMap::from([("slot-a".to_string(), existing.clone())]);
        merge_claude_slot_collection_state_at(
            &mut slots,
            "slot-a",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some(organization_hash.clone()),
                observed_at: Some("2026-08-05T01:10:00Z".to_string()),
                ..Default::default()
            },
            fresh_now,
        );
        assert_eq!(
            slots["slot-a"]
                .quota_snapshot
                .as_ref()
                .expect("same identity retains values")
                .state,
            ClaudeConfigSlotQuotaSnapshotStateV1::Stale
        );

        let mut expired = BTreeMap::from([("slot-a".to_string(), existing.clone())]);
        merge_claude_slot_collection_state_at(
            &mut expired,
            "slot-a",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some(organization_hash.clone()),
                observed_at: Some("2026-08-06T01:01:01Z".to_string()),
                ..Default::default()
            },
            expired_now,
        );
        assert!(
            expired["slot-a"].quota_snapshot.is_none(),
            "oldest represented meter observation expires after 24 hours"
        );

        for candidate in [
            ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some("c".repeat(64)),
                observed_at: Some("2026-08-05T01:20:00Z".to_string()),
                ..Default::default()
            },
            ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::IdentityMismatch,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some(organization_hash.clone()),
                observed_at: Some("2026-08-05T01:30:00Z".to_string()),
                ..Default::default()
            },
        ] {
            let mut isolated = BTreeMap::from([("slot-a".to_string(), existing.clone())]);
            merge_claude_slot_collection_state_at(&mut isolated, "slot-a", &candidate, fresh_now);
            assert!(isolated["slot-a"].quota_snapshot.is_none());
        }

        let sibling = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            account_identifier_hash: Some(account_hash),
            organization_identifier_hash: Some(organization_hash),
            observed_at: Some("2026-08-05T01:40:00Z".to_string()),
            ..Default::default()
        };
        merge_claude_slot_collection_state_at(&mut slots, "slot-b", &sibling, fresh_now);
        assert!(slots["slot-b"].quota_snapshot.is_none());
    }

    #[test]
    fn fresh_partial_default_observation_does_not_downgrade_fresh_exact_slot_meters() {
        let account_hash = "a".repeat(64);
        let organization_hash = "b".repeat(64);
        let existing = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-05T01:05:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-05T01:05:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            has_credit_balances: true,
            quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
            ..Default::default()
        };
        let partial_snapshot = local_claude_quota_snapshot(
            "2026-08-05T01:20:00Z",
            &existing
                .quota_snapshot
                .as_ref()
                .expect("full snapshot")
                .quota_windows[..2],
            &[],
            true,
            false,
        );
        let partial_statusline = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash),
            observed_at: Some("2026-08-05T01:20:00Z".to_string()),
            has_account_windows: true,
            quota_snapshot: Some(partial_snapshot),
            ..Default::default()
        };
        let mut slots = BTreeMap::from([("default".to_string(), existing)]);

        merge_claude_slot_collection_state_at(
            &mut slots,
            "default",
            &partial_statusline,
            OffsetDateTime::parse("2026-08-05T01:20:00Z", &Rfc3339).expect("now"),
        );

        let merged = &slots["default"];
        assert_eq!(merged.state, ClaudeConfigSlotCollectionStateV1::Fresh);
        assert!(merged.has_account_windows);
        assert!(merged.has_scoped_limits);
        assert!(merged.has_credit_balances);
        assert_eq!(
            merged
                .quota_snapshot
                .as_ref()
                .expect("fresh exact meters")
                .quota_windows
                .len(),
            3,
            "the retained full bundle keeps model-scoped limits"
        );
        assert_eq!(
            merged
                .quota_snapshot
                .as_ref()
                .expect("fresh exact meters")
                .credit_balances
                .len(),
            1,
            "the retained full bundle keeps usage credits"
        );
        assert_eq!(
            merged
                .quota_snapshot
                .as_ref()
                .expect("fresh exact meters")
                .state,
            ClaudeConfigSlotQuotaSnapshotStateV1::Fresh
        );
        assert!(merged
            .quota_snapshot
            .as_ref()
            .expect("fresh exact meters")
            .quota_windows
            .iter()
            .all(|window| window.freshness == AgentQuotaWindowFreshness::Fresh));
    }

    #[test]
    fn partial_default_observation_marks_exact_slot_meters_stale_after_fresh_horizon() {
        let account_hash = "a".repeat(64);
        let organization_hash = "b".repeat(64);
        let existing = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-05T01:05:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-05T01:05:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            has_credit_balances: true,
            quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
            ..Default::default()
        };
        let mut slots = BTreeMap::from([("default".to_string(), existing)]);

        merge_claude_slot_collection_state_at(
            &mut slots,
            "default",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_hash),
                organization_identifier_hash: Some(organization_hash),
                observed_at: Some("2026-08-05T02:07:00Z".to_string()),
                has_account_windows: true,
                ..Default::default()
            },
            OffsetDateTime::parse("2026-08-05T02:07:00Z", &Rfc3339).expect("now"),
        );

        assert_eq!(
            slots["default"]
                .quota_snapshot
                .as_ref()
                .expect("retained stale meters")
                .state,
            ClaudeConfigSlotQuotaSnapshotStateV1::Stale
        );
    }

    #[test]
    fn replayed_partial_observation_cannot_extend_exact_slot_meter_freshness() {
        let account_hash = "a".repeat(64);
        let organization_hash = "b".repeat(64);
        let existing = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.clone()),
            organization_identifier_hash: Some(organization_hash.clone()),
            observed_at: Some("2026-08-05T01:05:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-05T01:05:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            has_credit_balances: true,
            quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
            ..Default::default()
        };
        let mut slots = BTreeMap::from([("default".to_string(), existing)]);

        merge_claude_slot_collection_state_at(
            &mut slots,
            "default",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_hash),
                organization_identifier_hash: Some(organization_hash),
                observed_at: Some("2026-08-05T01:20:00Z".to_string()),
                has_account_windows: true,
                ..Default::default()
            },
            OffsetDateTime::parse("2026-08-05T02:07:00Z", &Rfc3339).expect("now"),
        );

        assert_eq!(
            slots["default"]
                .quota_snapshot
                .as_ref()
                .expect("retained stale meters")
                .state,
            ClaudeConfigSlotQuotaSnapshotStateV1::Stale
        );
    }

    #[test]
    fn slot_collection_merge_parses_timestamps_and_recovers_from_invalid_or_future_state() {
        let now = OffsetDateTime::parse("2026-08-05T02:00:00Z", &Rfc3339).expect("now");
        let account_hash = "a".repeat(64);
        let organization_hash = "b".repeat(64);
        for (observed_at, last_full_quota_read_at) in [
            ("not-a-timestamp", "2026-08-05T01:00:00Z"),
            ("2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
            ("2026-08-05T01:00:00Z", "2099-01-01T00:00:00Z"),
        ] {
            let poisoned = ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some(organization_hash.clone()),
                observed_at: Some(observed_at.to_string()),
                last_full_quota_read_at: Some(last_full_quota_read_at.to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                has_credit_balances: true,
                quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
                ..Default::default()
            };
            let mut slots = BTreeMap::from([("slot-a".to_string(), poisoned)]);
            merge_claude_slot_collection_state_at(
                &mut slots,
                "slot-a",
                &ClaudeConfigSlotCollectionStatusV1 {
                    state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
                    account_identifier_hash: Some(account_hash.clone()),
                    organization_identifier_hash: Some(organization_hash.clone()),
                    observed_at: Some("2026-08-05T01:59:00Z".to_string()),
                    ..Default::default()
                },
                now,
            );
            let recovered = &slots["slot-a"];
            assert_eq!(
                recovered.state,
                ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
            );
            assert!(recovered.last_full_quota_read_at.is_none());
            assert!(!recovered.has_account_windows);
            assert!(!recovered.has_scoped_limits);
            assert!(!recovered.has_credit_balances);
            assert!(recovered.quota_snapshot.is_none());
        }

        let mut initially_empty = BTreeMap::new();
        merge_claude_slot_collection_state_at(
            &mut initially_empty,
            "slot-a",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some(account_hash.clone()),
                organization_identifier_hash: Some(organization_hash.clone()),
                observed_at: Some("2099-01-01T00:00:00Z".to_string()),
                last_full_quota_read_at: Some("2099-01-01T00:00:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                has_credit_balances: true,
                quota_snapshot: Some(local_meter_fixture(&account_hash, &organization_hash)),
                ..Default::default()
            },
            now,
        );
        let sanitized = &initially_empty["slot-a"];
        assert!(sanitized.last_full_quota_read_at.is_none());
        assert!(!sanitized.has_account_windows);
        assert!(!sanitized.has_scoped_limits);
        assert!(!sanitized.has_credit_balances);
        assert!(sanitized.quota_snapshot.is_none());

        let mut offset_ordered = BTreeMap::from([(
            "slot-a".to_string(),
            ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::CollectionPaused,
                observed_at: Some("2026-08-05T03:00:00+02:00".to_string()),
                ..Default::default()
            },
        )]);
        merge_claude_slot_collection_state_at(
            &mut offset_ordered,
            "slot-a",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
                observed_at: Some("2026-08-05T01:30:00Z".to_string()),
                ..Default::default()
            },
            now,
        );
        assert_eq!(
            offset_ordered["slot-a"].state,
            ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        );
    }
    use ottto_core::{
        write_claude_statusline_cache, ClaudeStatusLineRateLimitWindow,
        CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
    };
    use serial_test::serial;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
        effective_home_previous: Option<Option<OsString>>,
    }

    impl EnvVarGuard {
        fn set_os(key: &'static str, value: OsString) -> Self {
            let previous = std::env::var_os(key);
            let effective_home_previous =
                (key == "HOME").then(|| std::env::var_os("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS"));
            std::env::set_var(key, &value);
            if key == "HOME" {
                std::env::set_var("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", &value);
            }
            Self {
                key,
                previous,
                effective_home_previous,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.as_ref() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
            if let Some(previous) = self.effective_home_previous.as_ref() {
                match previous {
                    Some(value) => std::env::set_var("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS", value),
                    None => std::env::remove_var("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS"),
                }
            }
        }
    }

    fn test_slot_descriptor(index: usize) -> ClaudeConfigSlotDescriptorV1 {
        ClaudeConfigDirSlot::registered(format!("/tmp/claude-slot-{index}"))
            .expect("test slot")
            .descriptor(
                format!("claude_slot_{index:032x}"),
                ClaudeConfigSlotOwnership::External,
            )
    }

    #[test]
    fn claude_snapshot_capacity_is_one_default_plus_nine_custom() {
        let descriptors = (0..12).map(test_slot_descriptor).collect::<Vec<_>>();
        let (collected, overflow) = bounded_claude_custom_descriptors(descriptors);

        assert_eq!(collected.len(), 9);
        assert_eq!(overflow.len(), 3);
        assert_eq!(
            collected[0].slot_id,
            "claude_slot_00000000000000000000000000000000"
        );
        assert_eq!(
            overflow[0].slot_id,
            "claude_slot_00000000000000000000000000000009"
        );
    }

    #[test]
    #[serial]
    fn claude_registered_slots_fan_out_full_usage_without_cross_account_mixing() {
        let root =
            std::env::temp_dir().join(format!("ottto-claude-multi-account-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let support = root.join("support");
        let bin = root.join("bin");
        fs::create_dir_all(home.join(".claude")).expect("create default config dir");
        fs::create_dir_all(&support).expect("create support dir");
        fs::create_dir_all(&bin).expect("create command dir");

        let claude = bin.join("claude");
        fs::write(
            &claude,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fixture-version"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
  if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] || [ -n "$ANTHROPIC_API_KEY" ] || [ -n "$CLAUDE_CODE_USE_BEDROCK" ] || [ -n "$CLAUDE_CODE_USE_VERTEX" ]; then
    exit 42
  fi
  if [ -n "$CLAUDE_CONFIG_DIR" ]; then
    config="$CLAUDE_CONFIG_DIR/.claude.json"
  else
    config="$HOME/.claude.json"
  fi
  exec /usr/bin/python3 - "$config" <<'PY'
import json, os, sys
account = json.load(open(sys.argv[1]))["oauthAccount"]
mode_path = os.path.join(os.path.dirname(sys.argv[1]), ".auth-mode")
mode = open(mode_path).read().strip() if os.path.exists(mode_path) else ""
if mode == "command_failure":
    raise SystemExit(7)
result = {
  "status": "authenticated",
  "email": account["emailAddress"],
  "organizationId": account["organizationUuid"],
  "subscriptionType": "max"
}
if mode == "missing_email":
    result.pop("email")
if mode == "missing_organization":
    result.pop("organizationId")
if mode == "identity_mismatch":
    result["email"] = "rotated@example.invalid"
    result["organizationId"] = "organization-rotated"
print(json.dumps(result))
PY
fi
exit 1
"#,
        )
        .expect("write fake claude");
        let security = bin.join("security");
        fs::write(&security, "#!/bin/sh\nexit 1\n").expect("write fake security");
        for executable in [&claude, &security] {
            let mut permissions = fs::metadata(executable).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(executable, permissions).expect("chmod executable");
        }

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
                serde_json::to_vec(&serde_json::json!({
                    "claudeAiOauth": {"accessToken": "fixture"}
                }))
                .expect("serialize credential fixture"),
            )
            .expect("write credential fixture");
        };

        write_identity(&home, "account-primary", "organization-primary");
        write_credential(&home.join(".claude"));
        let managed = root.join("managed-slot");
        write_identity(&managed, "account-secondary", "organization-secondary");
        // No token: stable exact identity must still serve this slot's
        // same-account, same-organization cache without a network fetch.
        let healthy_external = root.join("healthy-external-slot");
        write_identity(
            &healthy_external,
            "account-tertiary",
            "organization-tertiary",
        );
        write_credential(&healthy_external);
        let duplicate = root.join("duplicate-slot");
        write_identity(&duplicate, "account-secondary", "organization-secondary");
        write_credential(&duplicate);
        let failed = root.join("failed-slot");
        write_identity(&failed, "account-failed", "organization-failed");
        let auth_failed = root.join("auth-failed-slot");
        write_identity(&auth_failed, "account-secondary", "organization-secondary");
        write_credential(&auth_failed);
        fs::write(auth_failed.join(".auth-mode"), "command_failure")
            .expect("write auth failure mode");
        let missing_identity = root.join("missing-identity-slot");
        write_identity(
            &missing_identity,
            "account-missing-identity",
            "organization-missing-identity",
        );
        write_credential(&missing_identity);
        fs::write(missing_identity.join(".auth-mode"), "missing_email")
            .expect("write missing identity mode");
        let mismatched_identity = root.join("mismatched-identity-slot");
        write_identity(
            &mismatched_identity,
            "account-stale-identity",
            "organization-stale-identity",
        );
        write_credential(&mismatched_identity);
        fs::write(mismatched_identity.join(".auth-mode"), "identity_mismatch")
            .expect("write mismatch mode");

        let _home_guard = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
        let _support_guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support.as_os_str().to_os_string(),
        );
        let _command_guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string());
        let _oauth_poison = EnvVarGuard::set_os(
            "CLAUDE_CODE_OAUTH_TOKEN",
            OsString::from("ambient-wrong-account"),
        );
        let _api_poison =
            EnvVarGuard::set_os("ANTHROPIC_API_KEY", OsString::from("ambient-api-key"));
        let _bedrock_poison = EnvVarGuard::set_os("CLAUDE_CODE_USE_BEDROCK", OsString::from("1"));
        let _vertex_poison = EnvVarGuard::set_os("CLAUDE_CODE_USE_VERTEX", OsString::from("1"));
        let store = FileClaudeConfigSlotSettingsStore::default();
        store
            .register_managed_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                managed.to_string_lossy().to_string(),
            )
            .expect("register managed slot");
        store
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                healthy_external.to_string_lossy().to_string(),
            )
            .expect("register healthy external slot");
        store
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                duplicate.to_string_lossy().to_string(),
            )
            .expect("register duplicate slot");
        store
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                failed.to_string_lossy().to_string(),
            )
            .expect("register failed slot");
        for path in [&auth_failed, &missing_identity, &mismatched_identity] {
            store
                .register_path(
                    ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                    path.to_string_lossy().to_string(),
                )
                .expect("register invalid identity slot");
        }

        let now = current_unix_seconds();
        let primary_hash =
            billing_identity_hash("anthropic", "account", "account-primary").expect("primary hash");
        let primary_org =
            billing_identity_hash("anthropic", "organization", "organization-primary")
                .expect("primary org hash");
        let secondary_hash = billing_identity_hash("anthropic", "account", "account-secondary")
            .expect("secondary hash");
        let secondary_org =
            billing_identity_hash("anthropic", "organization", "organization-secondary")
                .expect("secondary org hash");
        let tertiary_hash = billing_identity_hash("anthropic", "account", "account-tertiary")
            .expect("tertiary hash");
        let tertiary_org =
            billing_identity_hash("anthropic", "organization", "organization-tertiary")
                .expect("tertiary org hash");
        let failed_hash = billing_identity_hash("anthropic", "account", "account-failed")
            .expect("failed account hash");
        let failed_org = billing_identity_hash("anthropic", "organization", "organization-failed")
            .expect("failed org hash");
        let usage_cache = |account_hash: &str,
                           organization_hash: &str,
                           used_percent: u8,
                           credits: u64| {
            let mut usage = ClaudeOAuthUsage {
                windows: vec![
                    AgentQuotaWindow {
                        name: "session".to_string(),
                        scope: AgentQuotaWindowScope::Account,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        used_percent: Some(used_percent),
                        ..Default::default()
                    },
                    AgentQuotaWindow {
                        name: "weekly".to_string(),
                        scope: AgentQuotaWindowScope::Account,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        used_percent: Some(used_percent),
                        ..Default::default()
                    },
                    AgentQuotaWindow {
                        name: "weekly_sonnet".to_string(),
                        scope: AgentQuotaWindowScope::Model,
                        status: AgentQuotaWindowStatus::Ok,
                        freshness: AgentQuotaWindowFreshness::Fresh,
                        model: Some("claude-sonnet".to_string()),
                        used_percent: Some(used_percent),
                        ..Default::default()
                    },
                ],
                credit_balances: vec![AgentCreditBalance {
                    name: "Usage credits".to_string(),
                    status: AgentCreditBalanceStatus::Ok,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    remaining: Some(credits),
                    ..Default::default()
                }],
            };
            claude_oauth_stamp_account_identity(&mut usage, account_hash, Some(organization_hash));
            ClaudeOAuthUsageCache {
                schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                account_identifier_hash: account_hash.to_string(),
                organization_identifier_hash: organization_hash.to_string(),
                observed_at_epoch_seconds: now,
                next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
                windows: usage.windows,
                credit_balances: usage.credit_balances,
            }
        };
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: primary_hash.clone(),
            organization_identifier_hash: primary_org.clone(),
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: u64::MAX,
            windows: Vec::new(),
            credit_balances: Vec::new(),
        })
        .expect("write unavailable primary cache");
        write_claude_oauth_usage_cache(&usage_cache(&secondary_hash, &secondary_org, 77, 777))
            .expect("write secondary cache");
        write_claude_oauth_usage_cache(&usage_cache(&tertiary_hash, &tertiary_org, 33, 333))
            .expect("write tertiary cache");

        let captured_at = "2026-08-04T12:34:56Z".to_string();
        let collection = collect_agent_status_collection(
            &SourceKind::ClaudeCode,
            captured_at.clone(),
            "2026-08-04T12:49:56Z".to_string(),
        );
        let snapshots = collection.snapshots;

        assert_eq!(
            snapshots.len(),
            4,
            "two healthy accounts plus two strongly bound degraded accounts are emitted"
        );
        assert!(snapshots
            .iter()
            .all(|snapshot| snapshot.captured_at == captured_at));
        let by_account = snapshots
            .iter()
            .map(|snapshot| {
                (
                    snapshot
                        .account
                        .as_ref()
                        .and_then(|account| account.account_identifier_hash.clone())
                        .expect("strong snapshot account"),
                    snapshot,
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_account.len(), 4);
        for (account_hash, organization_hash, expected_percent, expected_credits) in [
            (&secondary_hash, &secondary_org, 77, 777),
            (&tertiary_hash, &tertiary_org, 33, 333),
        ] {
            let snapshot = by_account.get(account_hash).expect("account snapshot");
            assert_eq!(snapshot.quota_windows.len(), 3);
            assert!(snapshot.quota_windows.iter().all(|window| {
                window.account_identifier_hash.as_ref() == Some(account_hash)
                    && window.organization_identifier_hash.as_ref() == Some(organization_hash)
                    && window.used_percent == Some(expected_percent)
            }));
            assert_eq!(snapshot.credit_balances.len(), 1);
            assert_eq!(
                snapshot.credit_balances[0].account_identifier_hash.as_ref(),
                Some(account_hash)
            );
            assert_eq!(
                snapshot.credit_balances[0]
                    .organization_identifier_hash
                    .as_ref(),
                Some(organization_hash)
            );
            assert_eq!(
                snapshot.credit_balances[0].remaining,
                Some(expected_credits)
            );
            assert_eq!(
                snapshot
                    .account
                    .as_ref()
                    .and_then(|account| account.claude_quota_access_state),
                Some(ClaudeQuotaAccessState::Full)
            );
        }
        let failed_snapshot = by_account
            .get(&failed_hash)
            .expect("strongly bound failed slot snapshot");
        assert_eq!(failed_snapshot.status, AgentStatusState::Degraded);
        assert!(failed_snapshot.quota_windows.is_empty());
        assert!(failed_snapshot.credit_balances.is_empty());
        assert!(failed_snapshot.plan_observations.is_empty());
        assert_eq!(
            failed_snapshot
                .account
                .as_ref()
                .and_then(|account| account.organization_identifier_hash.as_ref()),
            Some(&failed_org)
        );
        assert_eq!(
            failed_snapshot
                .account
                .as_ref()
                .and_then(|account| account.claude_quota_access_state),
            Some(ClaudeQuotaAccessState::AttentionRequired)
        );
        let primary_snapshot = by_account
            .get(&primary_hash)
            .expect("strongly bound unavailable default snapshot");
        assert_eq!(primary_snapshot.status, AgentStatusState::Degraded);
        assert!(primary_snapshot.quota_windows.is_empty());
        assert!(primary_snapshot.credit_balances.is_empty());
        assert!(primary_snapshot.plan_observations.is_empty());
        assert_eq!(
            primary_snapshot
                .account
                .as_ref()
                .and_then(|account| account.organization_identifier_hash.as_ref()),
            Some(&primary_org)
        );
        assert_eq!(
            primary_snapshot
                .account
                .as_ref()
                .and_then(|account| account.claude_quota_access_state),
            Some(ClaudeQuotaAccessState::TemporarilyUnavailable)
        );

        let status = annotate_claude_accounts_status(store.load().expect("load slot status"));
        let local_full_slots = status
            .managed_slots
            .iter()
            .chain(status.external_slots.iter())
            .filter(|slot| slot.collection.state == ClaudeConfigSlotCollectionStateV1::Fresh)
            .collect::<Vec<_>>();
        assert_eq!(local_full_slots.len(), 2);
        for slot in local_full_slots {
            let local = slot
                .collection
                .quota_snapshot
                .as_ref()
                .expect("fresh exact slot exposes local full meters");
            assert_eq!(local.state, ClaudeConfigSlotQuotaSnapshotStateV1::Fresh);
            assert_eq!(local.quota_windows.len(), 3);
            assert_eq!(local.credit_balances.len(), 1);
            let account = slot
                .collection
                .account_identifier_hash
                .as_deref()
                .expect("slot account hash");
            let organization = slot
                .collection
                .organization_identifier_hash
                .as_deref()
                .expect("slot organization hash");
            assert!(local.quota_windows.iter().all(|window| {
                window.account_identifier_hash.as_deref() == Some(account)
                    && window.organization_identifier_hash.as_deref() == Some(organization)
            }));
            assert!(local.credit_balances.iter().all(|balance| {
                balance.account_identifier_hash.as_deref() == Some(account)
                    && balance.organization_identifier_hash.as_deref() == Some(organization)
            }));
        }
        assert_eq!(
            status.default_slot.collection.state,
            ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        );
        assert_eq!(
            status
                .default_slot
                .collection
                .account_identifier_hash
                .as_ref(),
            Some(&primary_hash)
        );
        assert_eq!(
            status
                .default_slot
                .collection
                .organization_identifier_hash
                .as_ref(),
            Some(&primary_org)
        );
        let managed_status = status
            .managed_slots
            .iter()
            .find(|slot| slot.config_dir.as_deref() == managed.to_str())
            .expect("managed slot status");
        let duplicate_status = status
            .external_slots
            .iter()
            .find(|slot| slot.config_dir.as_deref() == duplicate.to_str())
            .expect("duplicate account slot status");
        let pair_states = [
            managed_status.collection.state.clone(),
            duplicate_status.collection.state.clone(),
        ];
        assert!(pair_states.contains(&ClaudeConfigSlotCollectionStateV1::Fresh));
        assert!(pair_states.contains(&ClaudeConfigSlotCollectionStateV1::DuplicateAccount));
        assert!(
            matches!(
                managed_status.collection.state,
                ClaudeConfigSlotCollectionStateV1::Fresh
                    | ClaudeConfigSlotCollectionStateV1::DuplicateAccount
            ),
            "the no-token slot must reach candidate ranking via its exact cache"
        );
        assert!(status.external_slots.iter().any(|slot| {
            slot.collection.state == ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
        }));
        assert!(status.external_slots.iter().any(|slot| {
            slot.collection.state == ClaudeConfigSlotCollectionStateV1::IdentityUnknown
        }));
        assert!(status.external_slots.iter().any(|slot| {
            slot.collection.state == ClaudeConfigSlotCollectionStateV1::IdentityMismatch
        }));
        for (path, expected) in [
            (
                &auth_failed,
                ClaudeConfigSlotCollectionStateV1::CredentialUnavailable,
            ),
            (
                &missing_identity,
                ClaudeConfigSlotCollectionStateV1::IdentityUnknown,
            ),
            (
                &mismatched_identity,
                ClaudeConfigSlotCollectionStateV1::IdentityMismatch,
            ),
        ] {
            let slot = status
                .external_slots
                .iter()
                .find(|slot| slot.config_dir.as_deref() == path.to_str())
                .expect("typed invalid slot status");
            assert_eq!(slot.collection.state, expected);
        }

        let backend_json = serde_json::to_string(
            &snapshots
                .into_iter()
                .map(AgentStatusSnapshot::redacted_for_backend)
                .collect::<Vec<_>>(),
        )
        .expect("serialize backend snapshots");
        for forbidden in [
            root.to_string_lossy().as_ref(),
            "account-primary",
            "account-secondary",
            "account-tertiary",
            "organization-primary",
            "organization-secondary",
            "organization-tertiary",
            "fixture",
            "claude_slot_",
        ] {
            assert!(
                !backend_json.contains(forbidden),
                "backend snapshots leaked forbidden local material"
            );
        }
        let local_state =
            fs::read_to_string(claude_slot_collection_state_path()).expect("read local slot state");
        assert!(!local_state.contains(root.to_string_lossy().as_ref()));
        assert!(!local_state.contains("fixture"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn claude_default_and_custom_rotation_during_auth_fail_closed() {
        let root =
            std::env::temp_dir().join(format!("ottto-claude-slot-rotation-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let support = root.join("support");
        let custom = root.join("custom");
        let bin = root.join("bin");
        for directory in [&home.join(".claude"), &support, &custom, &bin] {
            fs::create_dir_all(directory).expect("create rotation test directory");
        }
        let write_slot = |identity_dir: &Path, credential_dir: &Path, suffix: &str| {
            fs::write(
                identity_dir.join(".claude.json"),
                serde_json::to_vec(&serde_json::json!({
                    "oauthAccount": {
                        "accountUuid": format!("account-{suffix}"),
                        "organizationUuid": format!("organization-{suffix}"),
                        "emailAddress": format!("{suffix}@example.invalid")
                    }
                }))
                .expect("serialize rotation identity"),
            )
            .expect("write rotation identity");
            fs::write(
                credential_dir.join(".credentials.json"),
                serde_json::to_vec(&serde_json::json!({
                    "claudeAiOauth": {"accessToken": "test-captured-value"}
                }))
                .expect("serialize rotation credential"),
            )
            .expect("write rotation credential");
        };
        write_slot(&home, &home.join(".claude"), "default");
        write_slot(&custom, &custom, "custom");

        let claude = bin.join("claude");
        fs::write(
            &claude,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "test-version"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
  if [ -n "$CLAUDE_CONFIG_DIR" ]; then
    config="$CLAUDE_CONFIG_DIR/.claude.json"
  else
    config="$HOME/.claude.json"
  fi
  exec /usr/bin/python3 - "$config" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path))
account = value["oauthAccount"]
result = {
  "status": "authenticated",
  "email": account["emailAddress"],
  "organizationId": account["organizationUuid"],
  "subscriptionType": "max"
}
account["accountUuid"] += "-rotated"
account["organizationUuid"] += "-rotated"
account["emailAddress"] = "rotated@example.invalid"
with open(path, "w") as output:
    json.dump(value, output)
print(json.dumps(result))
PY
fi
exit 1
"#,
        )
        .expect("write rotating claude");
        let security = bin.join("security");
        fs::write(&security, "#!/bin/sh\nexit 1\n").expect("write security fallback");
        for executable in [&claude, &security] {
            let mut permissions = fs::metadata(executable).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(executable, permissions).expect("chmod executable");
        }

        let _home = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
        let _support = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support.as_os_str().to_os_string(),
        );
        let _commands =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string());
        let store = FileClaudeConfigSlotSettingsStore::default();
        store
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                custom.to_string_lossy().to_string(),
            )
            .expect("register rotating custom slot");

        let collection = collect_agent_status_collection(
            &SourceKind::ClaudeCode,
            "2026-08-04T13:00:00Z".to_string(),
            "2026-08-04T13:15:00Z".to_string(),
        );
        assert!(
            collection.snapshots.is_empty(),
            "rotating slots must emit no backend snapshot"
        );
        assert!(collection
            .source_health_snapshot
            .quota_windows
            .iter()
            .all(|window| window.account_identifier_hash.is_none()));
        let status = annotate_claude_accounts_status(store.load().expect("load rotating slots"));
        assert_eq!(
            status.default_slot.collection.state,
            ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
        );
        assert_eq!(status.external_slots.len(), 1);
        assert_eq!(
            status.external_slots[0].collection.state,
            ClaudeConfigSlotCollectionStateV1::ConcurrentMutation
        );
        let persisted = fs::read_to_string(claude_slot_collection_state_path())
            .expect("read rotation local state");
        assert!(!persisted.contains("test-captured-value"));
        assert!(!persisted.contains(root.to_string_lossy().as_ref()));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn run_command_capture_drains_large_stdout_before_waiting() {
        let dir =
            std::env::temp_dir().join(format!("ottto-command-capture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let executable = dir.join("large-output");
        std::fs::write(
            &executable,
            "#!/bin/sh\nexec /usr/bin/python3 -c 'import sys; sys.stdout.write(\"x\" * 200000)'\n",
        )
        .expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).expect("chmod executable");

        let _guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
        let output = run_command_capture("large-output", &[], Duration::from_secs(5));

        assert!(output.success, "{output:?}");
        assert_eq!(output.stdout.len(), 200000);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[serial]
    fn run_command_capture_timeout_does_not_wait_on_inherited_pipe() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-command-capture-held-pipe-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let executable = dir.join("held-pipe");
        std::fs::write(&executable, "#!/bin/sh\n(sh -c 'sleep 2') &\nsleep 30\n")
            .expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).expect("chmod executable");

        let _guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
        let started = Instant::now();
        let output = run_command_capture("held-pipe", &[], Duration::from_millis(200));

        assert!(!output.success, "{output:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout path must not block on a descendant-held stdout pipe"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    fn synthetic_codex_collector_home(label: &str, auth_mode: u32) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "ottto-codex-collector-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("collector fixture root");
        let root = root.canonicalize().expect("canonical collector root");
        let home = root.join("provider-home");
        std::fs::create_dir(&home).expect("provider home");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755))
            .expect("provider home mode");

        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let access_token = synthetic_codex_access_jwt_with_profile_email(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        );
        let id_token = synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace",
            "synthetic-account",
            "pro",
            expires_at,
        );
        let auth = home.join("auth.json");
        std::fs::write(
            &auth,
            serde_json::json!({
                "tokens": {
                    "access_token": access_token,
                    "id_token": id_token
                },
                "account_id": "synthetic-workspace"
            })
            .to_string(),
        )
        .expect("auth fixture");
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(auth_mode))
            .expect("auth mode");

        let executable = root.join("codex");
        std::fs::write(
            &executable,
            r#"#!/usr/bin/python3
import sys

if sys.argv[1:] == ["login", "status"]:
    print("Logged in")
    sys.exit(0)
if sys.argv[1:] == ["debug", "models", "--bundled"]:
    print('{"models":[{"id":"synthetic-model"}]}')
    sys.exit(0)
if sys.argv[1:] != ["app-server", "--stdio"]:
    sys.exit(1)

for line in sys.stdin:
    if '"id":1' in line:
        print('{"id":1,"result":{"userAgent":"synthetic"}}', flush=True)
    elif '"id":"ottto_account"' in line:
        print('{"id":"ottto_account","result":{"account":{"type":"chatgpt","email":"synthetic-account","planType":"pro"},"requiresOpenaiAuth":true}}', flush=True)
    elif "account/rateLimits/read" in line:
        print('{"id":"ottto_rate_limits","result":{"rateLimits":{"limitId":"synthetic-limit","planType":"pro","primary":{"usedPercent":25,"windowDurationMins":300}},"rateLimitResetCredits":{"availableCount":2}}}', flush=True)
"#,
        )
        .expect("fake Codex executable");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("fake Codex mode");

        (root, home)
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn provider_default_0755_home_retains_identity_and_real_quota() {
        let (root, home) = synthetic_codex_collector_home("default-0755", 0o600);
        let _commands =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());
        assert!(
            read_codex_auth_credentials_at(&home, CodexHomeTrust::ProviderDefault).is_ok(),
            "the safe fixture must be readable before collection"
        );

        let (snapshot, identity, _) = collect_codex_status_for_home(
            "2026-08-26T00:00:00Z".to_string(),
            "2026-08-26T00:15:00Z".to_string(),
            &home,
            CodexHomeTrust::ProviderDefault,
        );

        assert!(
            identity.is_some(),
            "diagnostic codes: {:?}; quota names: {:?}",
            snapshot
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            snapshot
                .quota_windows
                .iter()
                .map(|window| window.name.as_str())
                .collect::<Vec<_>>()
        );
        let account = snapshot.account.expect("provider account");
        assert!(account.account_identifier_hash.is_some());
        assert!(account.organization_identifier_hash.is_some());
        assert!(!snapshot.quota_windows.is_empty());
        assert!(snapshot
            .quota_windows
            .iter()
            .all(|window| window.name != "usage"));
        assert!(snapshot
            .quota_windows
            .iter()
            .all(|window| window.account_identifier_hash.is_some()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn credential_read_failure_emits_typed_diagnostic_with_fail_closed_meters() {
        let (root, home) = synthetic_codex_collector_home("unsafe-auth", 0o644);
        let _commands =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", root.as_os_str().to_os_string());

        let (snapshot, identity, _) = collect_codex_status_for_home(
            "2026-08-26T00:00:00Z".to_string(),
            "2026-08-26T00:15:00Z".to_string(),
            &home,
            CodexHomeTrust::ProviderDefault,
        );

        assert!(identity.is_none());
        assert!(snapshot.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "codex_credential_read_failed"
                && diagnostic.message
                    == "Codex credentials could not be read safely; account-bound meters were suppressed."
        }));
        assert!(snapshot.quota_windows.is_empty());
        assert!(snapshot.credit_balances.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn codex_app_server_reader_keeps_stdin_open_until_async_response() {
        let dir = std::env::temp_dir().join(format!("ottto-app-server-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let helper = dir.join("fake_codex.py");
        std::fs::write(
            &helper,
            r#"import os
import sys

if sys.argv[1:] != ["app-server", "--stdio"]:
    sys.exit(1)
if os.environ.get("CODEX_SQLITE_HOME") != os.environ.get("CODEX_HOME"):
    sys.exit(2)
if "OPENAI_API_KEY" in os.environ:
    sys.exit(3)

account_refreshed = False
for line in sys.stdin:
    if '"id":1' in line:
        print('{"id":1,"result":{"userAgent":"fake"}}', flush=True)
    if '"id":"ottto_account"' in line:
        if '"refreshToken":true' not in line:
            sys.exit(4)
        account_refreshed = True
        print('{"id":"ottto_account","result":{"account":{"type":"chatgpt","email":"synthetic-user","planType":"pro"},"requiresOpenaiAuth":true}}', flush=True)
    if "account/rateLimits/read" in line:
        if not account_refreshed:
            sys.exit(5)
        print('{"id":"ottto_rate_limits","result":{"rateLimitResetCredits":{"availableCount":2},"rateLimitsByLimitId":{},"rateLimits":{}}}', flush=True)
"#,
        )
        .expect("write helper");
        let executable = dir.join("codex");
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nexec /usr/bin/python3 '{}' \"$@\"\n",
                helper.display()
            ),
        )
        .expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).expect("chmod executable");

        let _guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
        let _provider = EnvVarGuard::set_os("OPENAI_API_KEY", OsString::from("must-not-pass"));
        let _sqlite = EnvVarGuard::set_os(
            "CODEX_SQLITE_HOME",
            OsString::from("synthetic-shared-store"),
        );
        let value = call_codex_app_server_rate_limits().expect("rate limits");

        assert_eq!(
            value
                .pointer("/rateLimitResetCredits/availableCount")
                .and_then(Value::as_u64),
            Some(2)
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn codex_app_server_stdout_reader_enforces_line_total_and_message_bounds() {
        let oversized = vec![b'x'; CODEX_APP_SERVER_MAX_LINE_BYTES + 1];
        let (sender, receiver) = mpsc::sync_channel(CODEX_APP_SERVER_CHANNEL_CAPACITY);
        read_bounded_codex_app_server_stdout(std::io::Cursor::new(oversized), sender);

        assert!(receiver
            .recv()
            .expect("bounded reader result")
            .expect_err("oversized output must fail")
            .contains("byte limit"));

        let chunk = vec![b'x'; CODEX_APP_SERVER_MAX_LINE_BYTES / 2];
        let mut total_oversized = Vec::new();
        while total_oversized.len() <= CODEX_APP_SERVER_MAX_TOTAL_BYTES {
            total_oversized.extend_from_slice(&chunk);
            total_oversized.push(b'\n');
        }
        let (sender, receiver) = mpsc::sync_channel(CODEX_APP_SERVER_CHANNEL_CAPACITY);
        read_bounded_codex_app_server_stdout(std::io::Cursor::new(total_oversized), sender);
        assert!(receiver
            .recv()
            .expect("bounded reader result")
            .expect_err("total output must fail")
            .contains("byte limit"));

        let messages = "{}\n".repeat(CODEX_APP_SERVER_MAX_MESSAGES + 1);
        let (sender, receiver) = mpsc::sync_channel(CODEX_APP_SERVER_MAX_MESSAGES + 1);
        read_bounded_codex_app_server_stdout(std::io::Cursor::new(messages), sender);
        let results = receiver.into_iter().collect::<Vec<_>>();
        assert_eq!(results.len(), CODEX_APP_SERVER_MAX_MESSAGES + 1);
        assert!(results
            .last()
            .expect("message-limit result")
            .as_ref()
            .expect_err("message count must fail")
            .contains("message limit"));
    }

    #[test]
    #[serial]
    fn managed_slot_never_enables_private_oauth_fallback() {
        let _guard = EnvVarGuard::set_os("OTTTO_CODEX_LEGACY_OAUTH_USAGE", OsString::from("true"));

        assert!(legacy_codex_oauth_fallback_allowed(true));
        assert!(!legacy_codex_oauth_fallback_allowed(false));
    }

    #[test]
    #[serial]
    fn codex_slots_pin_sqlite_home_and_drop_all_ambient_credentials() {
        let dir =
            std::env::temp_dir().join(format!("ottto-codex-exact-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let executable = dir.join("codex");
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf '%s|%s|%s' \"$CODEX_HOME\" \"$CODEX_SQLITE_HOME\" \"${OPENAI_API_KEY+present}\"\n",
        )
        .expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).expect("chmod executable");
        let managed_home = dir.join("managed-home");
        std::fs::create_dir(&managed_home).expect("managed home");

        let _commands =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", dir.as_os_str().to_os_string());
        let _provider = EnvVarGuard::set_os("OPENAI_API_KEY", OsString::from("must-not-pass"));
        let _shared_sqlite = EnvVarGuard::set_os(
            "CODEX_SQLITE_HOME",
            OsString::from("synthetic-shared-store"),
        );
        let output = run_codex_home_command(
            &managed_home,
            &["login", "status"],
            Duration::from_secs(2),
            false,
        );

        assert!(output.success, "{output:?}");
        assert_eq!(
            output.stdout,
            format!("{}|{}|", managed_home.display(), managed_home.display())
        );

        let second_home = dir.join("second-home");
        std::fs::create_dir(&second_home).expect("second home");
        let default_style_output = run_codex_home_command(
            &second_home,
            &["login", "status"],
            Duration::from_secs(2),
            true,
        );
        assert!(default_style_output.success, "{default_style_output:?}");
        assert_eq!(
            default_style_output.stdout,
            format!("{}|{}|", second_home.display(), second_home.display())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn codex_text_parser_extracts_account_model_quota_and_context() {
        let snapshot = parse_codex_status_fallback(
            "Logged in as test@example.com\nPlan: Pro\nModel: gpt-5.1\nUsage quota: 18% left\nContext: 72% used",
            "2026-05-06T10:00:00Z".to_string(),
            "2026-05-06T10:05:00Z".to_string(),
        );

        assert_eq!(snapshot.status, AgentStatusState::Available);
        assert_eq!(
            snapshot.account.and_then(|account| account.email),
            Some("test@example.com".to_string())
        );
        assert_eq!(
            snapshot.model.and_then(|model| model.active_model),
            Some("gpt-5.1".to_string())
        );
        assert_eq!(
            snapshot.quota_windows[0].status,
            AgentQuotaWindowStatus::NearLimit
        );
        assert_eq!(
            snapshot.context.and_then(|context| context.used_percent),
            Some(72)
        );
    }

    #[test]
    fn codex_model_parser_drops_automatic_review_prose() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {"name": "Automatic approval review model for Codex."},
                    {"id": "gpt-5.4-codex"}
                ]
            })
            .to_string(),
            stderr: String::new(),
        };

        let status = collect_model_status_from_output(&output, "openai");

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.4-codex"));
        assert!(!status
            .available_models
            .iter()
            .any(|model| model.contains("approval review")));
    }

    #[test]
    fn codex_config_model_overrides_bundled_debug_model_summary() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {"id": "gpt-5.4-codex"}
                ]
            })
            .to_string(),
            stderr: String::new(),
        };
        let mut status = collect_model_status_from_output(&output, "openai");
        let mut collection_method = AgentStatusCollectionMethod::CommandProbe;

        apply_codex_config_model(
            &mut status,
            Some("gpt-5.5".to_string()),
            &mut collection_method,
        );

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.5"));
        assert_eq!(status.default_model.as_deref(), Some("gpt-5.5"));
        assert_eq!(
            status.available_models.first().map(String::as_str),
            Some("gpt-5.5")
        );
        assert!(status
            .available_models
            .iter()
            .any(|model| model == "gpt-5.4-codex"));
        assert_eq!(collection_method, AgentStatusCollectionMethod::CommandProbe);
    }

    #[test]
    fn codex_bundled_models_preserve_structured_gpt56_metadata() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {
                        "slug": "gpt-5.6-sol",
                        "display_name": "GPT-5.6-Sol",
                        "description": "Latest frontier agentic coding model.",
                        "context_window": 372000,
                        "max_context_window": 372000,
                        "supported_reasoning_levels": [
                            {"effort": "low"},
                            {"effort": "max"}
                        ],
                        "input_modalities": ["text", "image"]
                    },
                    {
                        "slug": "gpt-5.6-terra",
                        "context_window": 372000,
                        "supported_reasoning_levels": [{"effort": "medium"}],
                        "input_modalities": ["text", "image"]
                    }
                ]
            })
            .to_string(),
            stderr: String::new(),
        };

        let status = collect_codex_model_status_from_output(&output);

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(status.default_model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(status.context_window_tokens, Some(372_000));
        assert_eq!(
            status.available_models,
            vec!["gpt-5.6-sol".to_string(), "gpt-5.6-terra".to_string()]
        );
        assert_eq!(status.available_model_details.len(), 2);
        assert_eq!(
            status.available_model_details[0].context_window_tokens,
            Some(372_000)
        );
        assert_eq!(
            status.available_model_details[0].supports_thinking,
            Some(true)
        );
        assert_eq!(
            status.available_model_details[0].supports_images,
            Some(true)
        );
        assert!(!status
            .available_models
            .iter()
            .any(|model| model.contains("frontier")));
    }

    #[test]
    fn codex_config_model_selects_matching_structured_context_window() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: serde_json::json!({
                "models": [
                    {"slug": "gpt-5.6-sol", "context_window": 372000},
                    {"slug": "gpt-5.4-mini", "context_window": 258400}
                ]
            })
            .to_string(),
            stderr: String::new(),
        };
        let mut status = collect_codex_model_status_from_output(&output);
        let mut collection_method = AgentStatusCollectionMethod::CommandProbe;

        apply_codex_config_model(
            &mut status,
            Some("gpt-5.4-mini".to_string()),
            &mut collection_method,
        );

        assert_eq!(status.active_model.as_deref(), Some("gpt-5.4-mini"));
        assert_eq!(status.context_window_tokens, Some(258_400));
    }

    fn codex_candidate_for_test(
        slot_id: &str,
        ownership: CodexAccountSlotOwnershipV1,
        account_hash: &str,
        workspace_hash: &str,
        quality: u8,
    ) -> CodexSlotCandidate {
        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::AppServer,
            "2026-08-23T00:00:00Z".to_string(),
            "2026-08-23T00:15:00Z".to_string(),
        );
        let mut account = unsupported_account("openai");
        account.login_state = AgentLoginState::SignedIn;
        account.account_identifier_hash = Some(account_hash.to_string());
        account.organization_identifier_hash = Some(workspace_hash.to_string());
        snapshot.account = Some(account);
        let status = CodexAccountSlotCollectionStatusV1 {
            state: CodexAccountSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account_hash.to_string()),
            workspace_identifier_hash: Some(workspace_hash.to_string()),
            ..Default::default()
        };
        CodexSlotCandidate {
            slot: CodexHomeSlot {
                slot_id: slot_id.to_string(),
                ownership,
                home: PathBuf::from("/tmp/codex-candidate-test"),
                registered_binding: (ownership == CodexAccountSlotOwnershipV1::Managed)
                    .then(|| (account_hash.to_string(), workspace_hash.to_string())),
            },
            snapshot,
            status,
            binding: Some((account_hash.to_string(), workspace_hash.to_string())),
            workspace_targets: Vec::new(),
            quality,
        }
    }

    fn codex_workspace_target_token_for(
        account: &str,
        workspace: &str,
        organizations: Value,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "email": "private.person@example.test",
                "sub": account,
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": account,
                    "chatgpt_account_id": workspace,
                    "organizations": organizations
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.raw-secret-signature")
    }

    fn codex_workspace_target_token(organizations: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "email": "private.person@example.test",
                "sub": "raw-account-123",
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": "raw-account-123",
                    "chatgpt_account_id": "raw-workspace-default",
                    "organizations": organizations
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.raw-secret-signature")
    }

    /// The shipped fixture gave `chatgpt_account_id` and the default organization
    /// the SAME raw id, which is the one case where the two identifier spaces
    /// coincide. Real provider tokens never do that, so every coverage test passed
    /// while the live current login rendered twice. This token keeps them distinct.
    fn codex_split_identity_token(chatgpt_account_id: &str, organizations: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "email": "private.person@example.test",
                "sub": "raw-account-123",
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": "raw-account-123",
                    "chatgpt_account_id": chatgpt_account_id,
                    "chatgpt_plan_type": "pro",
                    "organizations": organizations
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.raw-secret-signature")
    }

    #[test]
    fn codex_target_coverage_ignores_platform_orgs_that_are_not_the_signed_in_workspace() {
        // `organizations[]` lists platform.openai.com organizations, which govern
        // API keys. Only the one flagged `is_default` corresponds to the
        // chatgpt.com workspace this credential is signed into, and only that
        // workspace carries a subscription. The rest are not connectable: one seen
        // live is not even offered by the ChatGPT workspace picker.
        let token = codex_split_identity_token(
            "raw-workspace-binding",
            serde_json::json!([
                {"id": "raw-org-personal", "title": "Personal", "is_default": true},
                {"id": "raw-org-singular", "title": "Singular", "is_default": false},
                {"id": "raw-org-deprecated", "title": "Singular Deprecated", "is_default": false}
            ]),
        );
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let binding_workspace_hash =
            billing_identity_hash("openai", "workspace", "raw-workspace-binding")
                .expect("workspace hash");
        let mut candidate = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &binding_workspace_hash,
            5,
        );
        candidate.workspace_targets = evidence;

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);

        assert_eq!(
            coverage.targets.len(),
            1,
            "one signed-in workspace, one row"
        );
        let target = &coverage.targets[0];
        assert!(target.is_current);
        assert_eq!(target.workspace_label.as_deref(), Some("Personal"));
        assert_eq!(target.subscription_product.as_deref(), Some("chatgpt_pro"));
        assert!(
            coverage
                .targets
                .iter()
                .all(|target| target.workspace_label.as_deref() != Some("Singular Deprecated")),
            "a platform org the owner cannot sign into must never be offered"
        );
    }

    #[test]
    fn codex_durable_slot_is_one_row_and_platform_orgs_add_nothing() {
        let token = codex_split_identity_token(
            "raw-workspace-binding",
            serde_json::json!([
                {"id": "raw-org-singular", "title": "Singular", "is_default": true},
                {"id": "raw-org-deprecated", "title": "Singular Deprecated", "is_default": false},
                {"id": "raw-org-personal", "title": "Personal", "is_default": false}
            ]),
        );
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let binding_workspace_hash =
            billing_identity_hash("openai", "workspace", "raw-workspace-binding")
                .expect("workspace hash");
        let mut durable = codex_candidate_for_test(
            "codex_slot_durable",
            CodexAccountSlotOwnershipV1::Managed,
            &account_hash,
            &binding_workspace_hash,
            5,
        );
        durable.workspace_targets = evidence;

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[durable]);

        assert_eq!(coverage.targets.len(), 1);
        let connected = &coverage.targets[0];
        assert_eq!(
            connected.durability,
            CodexAccountTargetDurabilityV1::Durable
        );
        assert_eq!(connected.workspace_label.as_deref(), Some("Singular"));
        assert_eq!(
            connected.subscription_product.as_deref(),
            Some("chatgpt_pro")
        );
        assert!(!connected.connectable, "already connected");
        assert_eq!(coverage.connectable_targets, 0);
    }

    #[test]
    fn codex_non_default_platform_org_adds_no_row_even_when_it_claims_a_plan() {
        // A platform organization naming its own plan is still a platform
        // organization. A claimed plan must not smuggle it back in as a
        // subscription the owner could connect.
        let token = codex_split_identity_token(
            "raw-workspace-binding",
            serde_json::json!([
                {"id": "raw-org-singular", "title": "Singular", "is_default": true},
                {"id": "raw-org-team", "title": "Team", "is_default": false, "plan_type": "business"}
            ]),
        );
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let binding_workspace_hash =
            billing_identity_hash("openai", "workspace", "raw-workspace-binding")
                .expect("workspace hash");
        let mut candidate = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &binding_workspace_hash,
            5,
        );
        candidate.workspace_targets = evidence;

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);

        assert_eq!(coverage.targets.len(), 1);
        assert_eq!(
            coverage.targets[0].workspace_label.as_deref(),
            Some("Singular")
        );
        assert!(coverage
            .targets
            .iter()
            .all(|target| target.workspace_label.as_deref() != Some("Team")));
    }

    #[test]
    fn codex_current_login_is_one_target_when_binding_and_default_org_ids_differ() {
        // Live shape: the credential is bound by `chatgpt_account_id`, and its only
        // organization is the default one, named "Personal", carrying a different id.
        let token = codex_split_identity_token(
            "raw-workspace-binding",
            serde_json::json!([
                {"id": "raw-org-personal", "title": "Personal", "is_default": true}
            ]),
        );
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let binding_workspace_hash =
            billing_identity_hash("openai", "workspace", "raw-workspace-binding")
                .expect("workspace hash");
        let mut candidate = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &binding_workspace_hash,
            5,
        );
        candidate.workspace_targets = evidence;

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);

        // One workspace, so one row. Before the alias the binding and the default
        // organization produced two, and the duplicate offered to connect a
        // subscription that was already the current login.
        assert_eq!(coverage.targets.len(), 1);
        assert_eq!(coverage.current_targets, 1);
        let target = &coverage.targets[0];
        assert!(target.is_current);
        assert_eq!(target.durability, CodexAccountTargetDurabilityV1::Current);
        assert_eq!(target.workspace_label.as_deref(), Some("Personal"));
        assert_eq!(
            target.workspace_identifier_hash.as_deref(),
            Some(binding_workspace_hash.as_str()),
            "the binding identity stays canonical so persisted slots keep resolving"
        );
        assert_eq!(target.subscription_product.as_deref(), Some("chatgpt_pro"));
    }

    #[test]
    fn codex_targets_name_the_account_from_the_id_token_email() {
        let token = codex_split_identity_token(
            "raw-workspace-binding",
            serde_json::json!([
                {"id": "raw-org-personal", "title": "Personal", "is_default": true},
                {"id": "raw-org-other", "title": "Other", "is_default": false}
            ]),
        );
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let binding_workspace_hash =
            billing_identity_hash("openai", "workspace", "raw-workspace-binding")
                .expect("workspace hash");
        let mut candidate = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &binding_workspace_hash,
            5,
        );
        candidate.workspace_targets = evidence;

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);

        assert!(
            coverage
                .targets
                .iter()
                .all(|target| target.account_label == "private.person@example.test"),
            "every row of one account names that account, including the bound one"
        );
    }

    #[test]
    fn codex_target_account_label_falls_back_when_the_token_claims_no_email() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "sub": "raw-account-123",
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": "raw-account-123",
                    "chatgpt_account_id": "raw-workspace-binding",
                    "organizations": [
                        {"id": "raw-org-personal", "title": "Personal", "is_default": true}
                    ]
                }
            })
            .to_string(),
        );
        let token = format!("{header}.{payload}.raw-secret-signature");
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let binding_workspace_hash =
            billing_identity_hash("openai", "workspace", "raw-workspace-binding")
                .expect("workspace hash");
        let mut candidate = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &binding_workspace_hash,
            5,
        );
        candidate.workspace_targets = evidence;

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);
        assert_eq!(coverage.targets[0].account_label, "Codex account");
    }

    #[test]
    fn codex_workspace_target_coverage_collapses_durable_current_composite() {
        let token = codex_workspace_target_token(serde_json::json!([
            {"id": "raw-workspace-default", "title": "Personal", "is_default": true}
        ]));
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let workspace_hash = billing_identity_hash("openai", "workspace", "raw-workspace-default")
            .expect("workspace hash");
        let mut default = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &workspace_hash,
            5,
        );
        default.workspace_targets = evidence;
        let durable = codex_candidate_for_test(
            "codex_slot_durable",
            CodexAccountSlotOwnershipV1::Managed,
            &account_hash,
            &workspace_hash,
            5,
        );
        let mut candidates = vec![default, durable];
        canonicalize_codex_candidates(&mut candidates);

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &candidates);

        assert_eq!(coverage.targets.len(), 1);
        let target = &coverage.targets[0];
        assert_eq!(target.durability, CodexAccountTargetDurabilityV1::Durable);
        assert!(target.is_current);
        assert!(!target.connectable);
        assert_eq!(target.health, Some(CodexAccountTargetHealthV1::Healthy));
        assert_eq!(target.workspace_label.as_deref(), Some("Personal"));
    }

    #[test]
    fn codex_workspace_target_coverage_keeps_unconfirmed_identity_blocked() {
        // Only the signed-in workspace can be a subscription, so it is the only
        // one whose missing identity is worth surfacing. A non-default platform
        // organization with no id is not a blocked subscription, it is not a
        // subscription at all.
        let token = codex_workspace_target_token(serde_json::json!([
            {"title": "Identity pending", "is_default": true}
        ]));
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let workspace_hash = billing_identity_hash("openai", "workspace", "raw-workspace-default")
            .expect("workspace hash");
        let mut candidate = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &workspace_hash,
            5,
        );
        candidate.workspace_targets = evidence;

        let coverage =
            derive_codex_account_target_coverage(&empty_codex_accounts_status(), &[candidate]);
        let unconfirmed = coverage
            .targets
            .iter()
            .find(|target| target.workspace_label.as_deref() == Some("Identity pending"))
            .expect("unconfirmed workspace remains visible");

        assert!(unconfirmed.workspace_identifier_hash.is_none());
        assert!(!unconfirmed.connectable);
        assert_eq!(
            unconfirmed.setup_blockers,
            vec![CodexAccountTargetSetupBlockerV1::IdentityUnconfirmed]
        );
    }

    #[test]
    fn codex_workspace_target_status_serialization_never_leaks_raw_identity() {
        // Two candidates, each signed into its own workspace, so both labels
        // reach the wire: a non-default platform organization would contribute
        // no row at all.
        let token = codex_workspace_target_token(serde_json::json!([
            {"id": "raw-workspace-default", "title": "Personal", "is_default": true}
        ]));
        let singular_token = codex_workspace_target_token_for(
            "raw-account-456",
            "raw-workspace-singular",
            serde_json::json!([
                {"id": "raw-workspace-singular", "title": "Singular", "is_default": true}
            ]),
        );
        let evidence =
            codex_workspace_target_evidence_from_id_token(&token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let account_hash =
            billing_identity_hash("openai", "account", "raw-account-123").expect("account hash");
        let workspace_hash = billing_identity_hash("openai", "workspace", "raw-workspace-default")
            .expect("workspace hash");
        let mut candidate = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            &account_hash,
            &workspace_hash,
            5,
        );
        candidate.workspace_targets = evidence;
        let singular_account_hash =
            billing_identity_hash("openai", "account", "raw-account-456").expect("account hash");
        let singular_workspace_hash =
            billing_identity_hash("openai", "workspace", "raw-workspace-singular")
                .expect("workspace hash");
        let mut singular = codex_candidate_for_test(
            "codex_slot_singular",
            CodexAccountSlotOwnershipV1::Managed,
            &singular_account_hash,
            &singular_workspace_hash,
            5,
        );
        singular.workspace_targets =
            codex_workspace_target_evidence_from_id_token(&singular_token, "2026-08-27T00:00:00Z")
                .expect("target evidence");
        let mut status = empty_codex_accounts_status();
        status.target_coverage =
            derive_codex_account_target_coverage(&status, &[candidate, singular]);

        let wire = serde_json::to_string(&status).expect("serialize Codex account status");
        assert!(wire.contains("Personal"));
        assert!(wire.contains("Singular"));
        // Raw provider identifiers and credential material never appear, whatever
        // else the payload carries.
        for forbidden in [
            "raw-account-123",
            "raw-account-456",
            "raw-workspace-default",
            "raw-workspace-singular",
            "raw-secret-signature",
        ] {
            assert!(
                !wire.contains(forbidden),
                "serialized raw identity: {forbidden}"
            );
        }
        // The signed-in email is the one exception, and only as the human-readable
        // account name: two connected Codex accounts are otherwise indistinguishable
        // on screen. This status answers `codex_accounts_status` over the local Unix
        // socket and is never uploaded, so the name stays on this Mac. If that ever
        // stops being true, this assertion is the thing that has to be revisited
        // first.
        let named = status
            .target_coverage
            .targets
            .iter()
            .filter(|target| target.account_label == "private.person@example.test")
            .count();
        assert_eq!(named, status.target_coverage.targets.len());
        assert_eq!(
            wire.matches("private.person@example.test").count(),
            named,
            "the email appears as the account name and nowhere else"
        );
    }

    #[test]
    fn codex_composite_dedup_shadows_default_but_keeps_two_workspaces() {
        let mut candidates = vec![
            codex_candidate_for_test(
                "default",
                CodexAccountSlotOwnershipV1::Default,
                "same_user",
                "personal_workspace",
                5,
            ),
            codex_candidate_for_test(
                "codex_slot_a",
                CodexAccountSlotOwnershipV1::Managed,
                "same_user",
                "personal_workspace",
                5,
            ),
            codex_candidate_for_test(
                "codex_slot_b",
                CodexAccountSlotOwnershipV1::Managed,
                "same_user",
                "business_workspace",
                5,
            ),
            codex_candidate_for_test(
                "codex_slot_c",
                CodexAccountSlotOwnershipV1::Managed,
                "same_user",
                "personal_workspace",
                4,
            ),
        ];

        canonicalize_codex_candidates(&mut candidates);

        assert_eq!(
            candidates[0].status.relationship,
            Some(CodexAccountSlotRelationshipV1::ShadowedByAnchor)
        );
        assert_eq!(
            candidates[1].status.relationship,
            Some(CodexAccountSlotRelationshipV1::CanonicalAnchor)
        );
        assert_eq!(
            candidates[2].status.relationship,
            Some(CodexAccountSlotRelationshipV1::CanonicalAnchor)
        );
        assert_eq!(
            candidates[3].status.state,
            CodexAccountSlotCollectionStateV1::DuplicateAccount
        );
        assert_eq!(
            candidates[3].status.relationship,
            Some(CodexAccountSlotRelationshipV1::DuplicateAnchor)
        );
    }

    #[test]
    fn codex_healthy_anchor_restores_source_health_when_default_is_signed_out() {
        let mut default = codex_candidate_for_test(
            "default",
            CodexAccountSlotOwnershipV1::Default,
            "default_user",
            "default_workspace",
            1,
        );
        default.snapshot.status = AgentStatusState::AuthRequired;
        default.status.state = CodexAccountSlotCollectionStateV1::NeedsLogin;
        let managed = codex_candidate_for_test(
            "codex_slot_a",
            CodexAccountSlotOwnershipV1::Managed,
            "managed_user",
            "managed_workspace",
            5,
        );

        let health = codex_source_health_snapshot(
            &[default, managed],
            "2026-08-23T00:00:00Z",
            "2026-08-23T00:15:00Z",
        );

        assert_eq!(health.status, AgentStatusState::Available);
        assert_eq!(
            health
                .account
                .and_then(|account| account.account_identifier_hash),
            Some("managed_user".to_string())
        );
    }

    #[test]
    fn codex_accepted_slot_suppresses_meters_after_identity_change() {
        let mut candidate = codex_candidate_for_test(
            "codex_slot_a",
            CodexAccountSlotOwnershipV1::Managed,
            "registered_user",
            "registered_workspace",
            5,
        );
        candidate.status.account_identifier_hash = Some("different_user".to_string());
        candidate.status.workspace_identifier_hash = Some("different_workspace".to_string());
        candidate.snapshot.quota_windows.push(AgentQuotaWindow {
            name: "weekly".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });
        candidate.snapshot.credit_balances.push(AgentCreditBalance {
            name: "credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });

        let binding = enforce_codex_registered_binding(
            &candidate.slot,
            &mut candidate.snapshot,
            &mut candidate.status,
        );

        assert_eq!(binding, None);
        assert_eq!(
            candidate.status.state,
            CodexAccountSlotCollectionStateV1::IdentityMismatch
        );
        assert!(candidate.status.quota_snapshot.is_none());
        assert!(candidate.snapshot.quota_windows.is_empty());
        assert!(candidate.snapshot.credit_balances.is_empty());
    }

    #[test]
    fn codex_id_token_parser_extracts_chatgpt_plan_claims() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "account_123",
                    "chatgpt_user_id": "user_123",
                    "chatgpt_plan_type": "Team",
                    "chatgpt_subscription_active_start": 1782864000,
                    "chatgpt_subscription_active_until": 1785542400,
                    "chatgpt_subscription_last_checked": 1785283200,
                    "organizations": [
                        {"id": "org_old", "title": "Old Org", "is_default": false},
                        {"id": "org_current", "title": "Current Org", "is_default": true}
                    ]
                }
            }"#,
        );
        let token = format!("{header}.{payload}.signature");

        let account = parse_codex_id_token_account(&token).expect("account");

        assert_eq!(account.login_state, AgentLoginState::SignedIn);
        assert_eq!(account.provider.as_deref(), Some("openai"));
        assert_eq!(account.email.as_deref(), Some("codex@example.com"));
        assert_eq!(account.account_id.as_deref(), Some("user_123"));
        assert_eq!(account.organization_id.as_deref(), Some("account_123"));
        assert_eq!(account.organization_label, None);
        assert_eq!(account.plan_type.as_deref(), Some("team"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("chatgpt_team")
        );
        assert_eq!(
            account.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            account.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
        assert_eq!(
            account.subscription_period_last_checked_at.as_deref(),
            Some("2026-07-29T00:00:00Z")
        );
        assert_eq!(account.account_identifier_hash, None);
        assert_eq!(account.organization_identifier_hash, None);
        assert_eq!(account.confidence, AgentStatusConfidence::Low);
    }

    fn synthetic_codex_jwt(
        user: &str,
        workspace: &str,
        account_label: &str,
        plan: &str,
        expires_at: i64,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "https://auth.openai.com",
                "aud": "synthetic-client",
                "exp": expires_at,
                "email": account_label,
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": user,
                    "chatgpt_account_id": workspace,
                    "chatgpt_plan_type": plan
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.synthetic-signature")
    }

    fn synthetic_codex_access_jwt_with_profile_email(
        user: &str,
        workspace: &str,
        account_label: &str,
        plan: &str,
        expires_at: i64,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "https://auth.openai.com",
                "aud": "synthetic-client",
                "exp": expires_at,
                "https://api.openai.com/profile": {
                    "email": account_label
                },
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": user,
                    "chatgpt_account_id": workspace,
                    "chatgpt_plan_type": plan
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.synthetic-signature")
    }

    #[test]
    fn unrefreshed_or_mismatched_jwt_identity_never_carries_provider_meters() {
        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let credentials = CodexAuthCredentials {
            access_token: Some(synthetic_codex_jwt(
                "synthetic-user",
                "synthetic-workspace-b",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            id_token: Some(synthetic_codex_jwt(
                "synthetic-user",
                "synthetic-workspace-a",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            account_id: Some("synthetic-workspace-a".to_string()),
        };
        let provider_account = serde_json::json!({
            "account": {
                "type": "chatgpt",
                "email": "synthetic-account",
                "planType": "pro"
            },
            "requiresOpenaiAuth": true
        });
        let rate_limits = serde_json::json!({
            "rateLimits": {
                "limitId": "synthetic-limit",
                "planType": "pro",
                "primary": {"usedPercent": 25, "windowDurationMins": 300}
            }
        });

        assert!(
            validated_codex_identity(
                &credentials,
                Some(&provider_account),
                Some(&rate_limits),
                false,
            )
            .is_none(),
            "decoded claims are unusable until the provider refreshes the active credential"
        );
        assert!(
            validated_codex_identity(
                &credentials,
                Some(&provider_account),
                Some(&rate_limits),
                true,
            )
            .is_none(),
            "an ID-token workspace cannot override the authenticated access-token workspace"
        );
        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::AppServer,
            "2026-08-23T00:00:00Z".to_string(),
            "2026-08-23T00:15:00Z".to_string(),
        );
        snapshot.account = parse_codex_id_token_account(
            credentials.id_token.as_deref().expect("synthetic id token"),
        );
        snapshot.quota_windows = codex_app_server_quota_windows(&rate_limits);
        stamp_codex_meter_identity(&mut snapshot);
        assert!(snapshot.quota_windows.is_empty());

        let correlated = CodexAuthCredentials {
            access_token: Some(synthetic_codex_jwt(
                "synthetic-user",
                "synthetic-workspace-b",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            id_token: Some(synthetic_codex_jwt(
                "synthetic-user",
                "synthetic-workspace-b",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            account_id: Some("synthetic-workspace-b".to_string()),
        };
        assert!(validated_codex_identity(
            &correlated,
            Some(&provider_account),
            Some(&rate_limits),
            true,
        )
        .is_some());

        let mut expired = credentials;
        expired.id_token = Some(synthetic_codex_jwt(
            "synthetic-user",
            "synthetic-workspace-b",
            "synthetic-account",
            "pro",
            OffsetDateTime::now_utc().unix_timestamp() - 1,
        ));
        assert!(validated_codex_identity(
            &expired,
            Some(&provider_account),
            Some(&rate_limits),
            true,
        )
        .is_none());
    }

    fn synthetic_codex_jwt_with_organizations(
        user: &str,
        workspace: &str,
        account_label: &str,
        plan: &str,
        expires_at: i64,
        organizations: Value,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "https://auth.openai.com",
                "aud": "synthetic-client",
                "exp": expires_at,
                "email": account_label,
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": user,
                    "chatgpt_account_id": workspace,
                    "chatgpt_plan_type": plan,
                    "organizations": organizations
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.synthetic-signature")
    }

    #[test]
    fn codex_identity_carries_the_hashes_it_produced_before_the_derivation_changed() {
        // The account used to be keyed on `chatgpt_account_id` and the
        // organization on `organizations[].id` under the `organization` kind.
        // Both moved, so a server holding the old digests sees an unrelated
        // account and prices it as a second subscription. These two fields are
        // the only thing that can join them again: nothing downstream holds the
        // raw values, so nothing downstream can derive the equivalence itself.
        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let organizations = serde_json::json!([
            {"id": "synthetic-org-default", "title": "Personal", "is_default": true},
            {"id": "synthetic-org-other", "title": "Other", "is_default": false}
        ]);
        let credentials = CodexAuthCredentials {
            access_token: Some(synthetic_codex_access_jwt_with_profile_email(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            id_token: Some(synthetic_codex_jwt_with_organizations(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
                organizations,
            )),
            account_id: Some("synthetic-workspace".to_string()),
        };
        let provider_account = serde_json::json!({
            "account": {"type": "chatgpt", "email": "synthetic-account", "planType": "pro"}
        });
        let rate_limits = serde_json::json!({
            "rateLimits": {"limitId": "codex", "planType": "pro"}
        });

        let identity = validated_codex_identity(
            &credentials,
            Some(&provider_account),
            Some(&rate_limits),
            true,
        )
        .expect("identity");

        assert_eq!(
            identity.account_identifier_hash,
            billing_identity_hash("openai", "account", "synthetic-user").expect("account hash"),
            "the account is keyed on the user id now"
        );
        assert_eq!(
            identity.superseded_account_identifier_hash,
            billing_identity_hash("openai", "account", "synthetic-workspace"),
            "and was keyed on the workspace id before"
        );
        assert_eq!(
            identity.workspace_identifier_hash,
            billing_identity_hash("openai", "workspace", "synthetic-workspace")
                .expect("workspace hash"),
        );
        assert_eq!(
            identity.superseded_organization_identifier_hash,
            billing_identity_hash("openai", "organization", "synthetic-org-default"),
            "the DEFAULT organization is the one the credential was signed into"
        );
        assert_ne!(
            identity.superseded_organization_identifier_hash,
            billing_identity_hash("openai", "organization", "synthetic-org-other"),
            "a non-default organization never supplies the superseded identity"
        );
        // Superseded hashes must never collide with current ones, or a consumer
        // adopting them would rewrite an identity onto itself.
        assert_ne!(
            Some(identity.account_identifier_hash.clone()),
            identity.superseded_account_identifier_hash
        );
        assert_ne!(
            Some(identity.workspace_identifier_hash.clone()),
            identity.superseded_organization_identifier_hash
        );
    }

    #[test]
    fn codex_identity_omits_the_superseded_organization_when_no_default_is_claimed() {
        // No default organization means nothing to key the old organization
        // hash on. Emitting one from a non-default membership would invite a
        // consumer to merge two genuinely different workspaces.
        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let credentials = CodexAuthCredentials {
            access_token: Some(synthetic_codex_access_jwt_with_profile_email(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            id_token: Some(synthetic_codex_jwt_with_organizations(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
                serde_json::json!([{"id": "synthetic-org-other", "title": "Other"}]),
            )),
            account_id: Some("synthetic-workspace".to_string()),
        };
        let provider_account = serde_json::json!({
            "account": {"type": "chatgpt", "email": "synthetic-account", "planType": "pro"}
        });

        let identity = validated_codex_identity(&credentials, Some(&provider_account), None, true)
            .expect("identity");

        assert_eq!(identity.superseded_organization_identifier_hash, None);
        assert!(
            identity.superseded_account_identifier_hash.is_some(),
            "the account side does not depend on organizations at all"
        );
    }

    #[test]
    fn codex_profile_email_identity_retains_provider_meters() {
        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let credentials = CodexAuthCredentials {
            access_token: Some(synthetic_codex_access_jwt_with_profile_email(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            id_token: Some(synthetic_codex_jwt(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            account_id: Some("synthetic-workspace".to_string()),
        };
        let provider_account = serde_json::json!({
            "account": {
                "type": "chatgpt",
                "email": "synthetic-account",
                "planType": "pro"
            }
        });
        let rate_limits = serde_json::json!({
            "rateLimits": {
                "limitId": "synthetic-limit",
                "planType": "pro",
                "primary": {"usedPercent": 25, "windowDurationMins": 300}
            }
        });

        let identity = validated_codex_identity(
            &credentials,
            Some(&provider_account),
            Some(&rate_limits),
            true,
        )
        .expect("profile email should correlate the authenticated identity");
        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::AppServer,
            "2026-08-23T00:00:00Z".to_string(),
            "2026-08-23T00:15:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            account_identifier_hash: Some(identity.account_identifier_hash.clone()),
            organization_identifier_hash: Some(identity.workspace_identifier_hash.clone()),
            ..unsupported_account("openai")
        });
        snapshot.quota_windows.push(AgentQuotaWindow {
            name: "synthetic_primary".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });
        snapshot.credit_balances.push(AgentCreditBalance {
            name: "synthetic_credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });

        stamp_codex_meter_identity(&mut snapshot);

        assert_eq!(snapshot.quota_windows.len(), 1);
        assert_eq!(snapshot.credit_balances.len(), 1);
        assert_eq!(
            snapshot.quota_windows[0].account_identifier_hash.as_deref(),
            Some(identity.account_identifier_hash.as_str())
        );
        assert_eq!(
            snapshot.credit_balances[0]
                .organization_identifier_hash
                .as_deref(),
            Some(identity.workspace_identifier_hash.as_str())
        );
    }

    #[test]
    fn codex_profile_email_mismatch_clears_provider_meters() {
        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let matching_credentials = CodexAuthCredentials {
            access_token: Some(synthetic_codex_access_jwt_with_profile_email(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            id_token: Some(synthetic_codex_jwt(
                "synthetic-user",
                "synthetic-workspace",
                "synthetic-account",
                "pro",
                expires_at,
            )),
            account_id: Some("synthetic-workspace".to_string()),
        };
        let provider_account = serde_json::json!({
            "account": {
                "type": "chatgpt",
                "email": "synthetic-account",
                "planType": "pro"
            }
        });
        let rate_limits = serde_json::json!({
            "rateLimits": {
                "limitId": "synthetic-limit",
                "planType": "pro",
                "primary": {"usedPercent": 25, "windowDurationMins": 300}
            }
        });
        assert!(validated_codex_identity(
            &matching_credentials,
            Some(&provider_account),
            Some(&rate_limits),
            true,
        )
        .is_some());

        let mismatched_credentials = CodexAuthCredentials {
            access_token: Some(synthetic_codex_access_jwt_with_profile_email(
                "synthetic-user",
                "synthetic-workspace",
                "different-synthetic-account",
                "pro",
                expires_at,
            )),
            ..matching_credentials
        };
        let identity = validated_codex_identity(
            &mismatched_credentials,
            Some(&provider_account),
            Some(&rate_limits),
            true,
        );
        assert!(identity.is_none());

        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::AppServer,
            "2026-08-23T00:00:00Z".to_string(),
            "2026-08-23T00:15:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            account_identifier_hash: identity
                .as_ref()
                .map(|value| value.account_identifier_hash.clone()),
            organization_identifier_hash: identity
                .as_ref()
                .map(|value| value.workspace_identifier_hash.clone()),
            ..unsupported_account("openai")
        });
        snapshot.quota_windows.push(AgentQuotaWindow {
            name: "synthetic_primary".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });
        snapshot.credit_balances.push(AgentCreditBalance {
            name: "synthetic_credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });

        stamp_codex_meter_identity(&mut snapshot);

        assert!(snapshot.quota_windows.is_empty());
        assert!(snapshot.credit_balances.is_empty());
    }

    #[test]
    fn codex_partial_identity_never_emits_hash_or_quota_snapshot() {
        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::AppServer,
            "2026-08-23T00:00:00Z".to_string(),
            "2026-08-23T00:15:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            account_identifier_hash: Some("a".repeat(64)),
            organization_identifier_hash: None,
            ..unsupported_account("openai")
        });
        snapshot.quota_windows.push(AgentQuotaWindow {
            name: "synthetic_primary".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });
        snapshot.credit_balances.push(AgentCreditBalance {
            name: "synthetic_credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            ..Default::default()
        });

        stamp_codex_meter_identity(&mut snapshot);

        let status = codex_collection_status_from_snapshot(&snapshot);
        assert_eq!(
            status.state,
            CodexAccountSlotCollectionStateV1::IdentityUnknown
        );
        assert_eq!(status.account_identifier_hash, None);
        assert_eq!(status.workspace_identifier_hash, None);
        assert!(status.quota_snapshot.is_none());
        assert!(snapshot.quota_windows.is_empty());
        assert!(snapshot.credit_balances.is_empty());
    }

    fn codex_id_token_with_auth_claim(auth_claim: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(
            r#"{{
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {auth_claim}
            }}"#
        ));
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn codex_id_token_subscription_period_is_absent_when_the_claims_are_absent() {
        let token = codex_id_token_with_auth_claim(
            r#"{"chatgpt_account_id": "account_123", "chatgpt_plan_type": "Pro"}"#,
        );

        let account = parse_codex_id_token_account(&token).expect("account");

        assert_eq!(account.plan_type.as_deref(), Some("pro"));
        assert_eq!(account.subscription_period_start, None);
        assert_eq!(account.subscription_period_end, None);
        assert_eq!(account.subscription_period_last_checked_at, None);
    }

    #[test]
    fn codex_id_token_subscription_period_reads_rfc3339_strings_as_utc() {
        let token = codex_id_token_with_auth_claim(
            r#"{
                "chatgpt_account_id": "account_123",
                "chatgpt_plan_type": "Pro",
                "chatgpt_subscription_active_start": "2026-07-01T03:00:00+03:00",
                "chatgpt_subscription_active_until": "1785542400",
                "chatgpt_subscription_last_checked": "2026-07-29T03:00:00+03:00"
            }"#,
        );

        let account = parse_codex_id_token_account(&token).expect("account");

        // An offset-bearing string is converted, not reinterpreted: same instant.
        assert_eq!(
            account.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            account.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
        assert_eq!(
            account.subscription_period_last_checked_at.as_deref(),
            Some("2026-07-29T00:00:00Z")
        );
    }

    #[test]
    fn codex_id_token_subscription_period_drops_malformed_and_out_of_range_claims() {
        // Milliseconds, a non-date string, a null, and a nested object are all
        // "not reported" - never a panic, never a substituted `now`.
        for claim in [
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": 1782864000000, "chatgpt_subscription_active_until": 1785542400000, "chatgpt_subscription_last_checked": 1785283200000}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": "not-a-date", "chatgpt_subscription_active_until": "also-not-a-date", "chatgpt_subscription_last_checked": "still-not-a-date"}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": null, "chatgpt_subscription_active_until": null, "chatgpt_subscription_last_checked": null}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": {"seconds": 1782864000}, "chatgpt_subscription_active_until": [], "chatgpt_subscription_last_checked": {"seconds": 1785283200}}"#,
            r#"{"chatgpt_plan_type": "Pro", "chatgpt_subscription_active_start": 0, "chatgpt_subscription_active_until": -1, "chatgpt_subscription_last_checked": 0}"#,
        ] {
            let account = parse_codex_id_token_account(&codex_id_token_with_auth_claim(claim))
                .expect("account");
            assert_eq!(account.plan_type.as_deref(), Some("pro"), "claim: {claim}");
            assert_eq!(account.subscription_period_start, None, "claim: {claim}");
            assert_eq!(account.subscription_period_end, None, "claim: {claim}");
            assert_eq!(
                account.subscription_period_last_checked_at, None,
                "claim: {claim}"
            );
        }
    }

    #[test]
    fn codex_id_token_subscription_period_accepts_one_sided_reporting() {
        let token = codex_id_token_with_auth_claim(
            r#"{
                "chatgpt_plan_type": "Pro",
                "chatgpt_subscription_active_until": 1785542400
            }"#,
        );

        let account = parse_codex_id_token_account(&token).expect("account");

        assert_eq!(account.subscription_period_start, None);
        assert_eq!(account.subscription_period_last_checked_at, None);
        assert_eq!(
            account.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
    }

    #[test]
    fn codex_id_token_subscription_period_alone_does_not_resurrect_an_empty_account() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{
                "https://api.openai.com/auth": {
                    "chatgpt_subscription_active_start": 1782864000,
                    "chatgpt_subscription_active_until": 1785542400,
                    "chatgpt_subscription_last_checked": 1785283200
                }
            }"#,
        );
        let token = format!("{header}.{payload}.signature");

        assert!(parse_codex_id_token_account(&token).is_none());
    }

    #[test]
    fn merged_codex_accounts_carry_the_subscription_period() {
        let mut auth_account = unsupported_account("openai");
        auth_account.login_state = AgentLoginState::SignedIn;
        auth_account.subscription_period_start = Some("2026-07-01T00:00:00Z".to_string());
        auth_account.subscription_period_end = Some("2026-08-01T00:00:00Z".to_string());
        auth_account.subscription_period_last_checked_at = Some("2026-07-29T00:00:00Z".to_string());
        let mut existing = unsupported_account("openai");
        existing.email = Some("codex@example.com".to_string());

        let merged = merge_codex_accounts(Some(existing), auth_account.clone());

        assert_eq!(
            merged.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            merged.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
        assert_eq!(
            merged.subscription_period_last_checked_at.as_deref(),
            Some("2026-07-29T00:00:00Z")
        );

        // A later probe that reports nothing must not blank a known period.
        let mut silent = unsupported_account("openai");
        silent.login_state = AgentLoginState::SignedIn;
        let preserved = merge_codex_accounts(Some(merged), silent);

        assert_eq!(
            preserved.subscription_period_start.as_deref(),
            Some("2026-07-01T00:00:00Z")
        );
        assert_eq!(
            preserved.subscription_period_end.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
        assert_eq!(
            preserved.subscription_period_last_checked_at.as_deref(),
            Some("2026-07-29T00:00:00Z")
        );
    }

    #[test]
    fn subscription_period_is_omitted_from_the_wire_when_absent() {
        let account = unsupported_account("openai");

        let wire = serde_json::to_value(&account).expect("serialize");

        assert!(wire.get("subscription_period_start").is_none());
        assert!(wire.get("subscription_period_end").is_none());
        assert!(wire.get("subscription_period_last_checked_at").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn codex_platform_organizations_never_witness_a_subscription() {
        use std::os::unix::fs::PermissionsExt;

        // `organizations[]` lists platform.openai.com organizations, which
        // govern API keys. ChatGPT/Codex subscriptions live in chatgpt.com
        // workspaces keyed by `chatgpt_account_id`, and the id spaces differ
        // even where the names match -- proven live: a platform organization
        // absent from the ChatGPT picker entirely, and a target prepared from a
        // platform organization id titled the same as a ChatGPT workspace
        // returning `identity_mismatch`.
        //
        // "Team Org" below carries a plan name, which used to be uploaded as a
        // plan observation with `billing_channel: "subscription"` and no account
        // identifier at all. The backend materialized that into its own priced
        // subscription row keyed on the account label -- a plan nobody pays for,
        // added to the operator's monthly total.
        let root = std::env::temp_dir().join(format!(
            "ottto-codex-platform-orgs-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        // macOS `temp_dir()` reaches the real directory through a symlinked
        // `/var`, and the secure reader opens every component with O_NOFOLLOW.
        // Without canonicalizing, the fixture is refused and the assertions
        // below would all pass on an untouched snapshot.
        let root = root.canonicalize().expect("canonical root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("provider home mode");

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "email": "codex@example.com",
                "sub": "account_sub",
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": "account_sub",
                    "chatgpt_account_id": "workspace_binding",
                    "chatgpt_plan_type": "Pro",
                    "organizations": [
                        {"id": "org_current", "title": "Current Org", "is_default": true},
                        {"id": "org_related", "title": "Related Org", "is_default": false},
                        {"id": "org_team", "title": "Team Org", "subscription_plan": "Team"}
                    ]
                }
            })
            .to_string(),
        );
        let id_token = format!("{header}.{payload}.signature");
        std::fs::write(
            root.join("auth.json"),
            serde_json::json!({
                "tokens": {"id_token": id_token},
                "account_id": "workspace_binding"
            })
            .to_string(),
        )
        .expect("auth fixture");
        // `auth.json` must be exactly 0600 or the secure reader refuses it, the
        // collector returns early, and every assertion below would pass for the
        // wrong reason.
        std::fs::set_permissions(
            root.join("auth.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("auth mode");

        let mut snapshot = base_snapshot(
            SourceKind::Codex,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::AppServer,
            "2026-09-01T10:00:00Z".to_string(),
            "2026-09-01T10:15:00Z".to_string(),
        );

        let targets = append_codex_workspace_observations_at(
            &mut snapshot,
            &root,
            CodexHomeTrust::ProviderDefault,
        );

        // Prove the fixture was actually read before trusting any absence.
        assert!(
            !snapshot
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "codex_credential_read_failed"),
            "the credential fixture was rejected, so this test would prove nothing"
        );
        assert!(
            !targets.is_empty(),
            "the signed-in workspace must still produce a target"
        );

        assert!(
            snapshot.plan_observations.is_empty(),
            "platform organizations must not claim a subscription: {:?}",
            snapshot.plan_observations
        );
        assert!(
            !snapshot
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "codex_workspace_memberships_detected"),
            "the membership diagnostic described observations that are no longer emitted"
        );
        // Target EVIDENCE still enumerates every organization the token names;
        // `derive_codex_account_target_coverage` is what narrows it to the
        // signed-in workspace, so exactly one default target is the shape the
        // coverage step expects to receive.
        assert_eq!(
            targets.iter().filter(|target| target.is_default).count(),
            1,
            "the signed-in workspace must be the one default target"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn codex_usage_parser_extracts_windows_and_credits() {
        let json = serde_json::json!({
            "rate_limit": {
                "primary_window": {
                    "used_percent": 3,
                    "reset_at": 1779049800,
                    "limit_window_seconds": 18000
                },
                "secondary_window": {
                    "used_percent": 1,
                    "reset_at": "1779613200",
                    "limit_window_seconds": 604800
                },
                "credits": {
                    "has_credits": true,
                    "unlimited": false,
                    "balance": 0
                }
            }
        });

        let windows = codex_usage_quota_windows(&json);
        let credits = codex_usage_credit_balances(&json);

        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].name, "legacy_primary_five_hour_reset_known");
        assert_eq!(windows[0].left_percent, Some(97));
        assert_eq!(
            windows[0].started_at.as_deref(),
            Some("2026-05-17T15:30:00Z")
        );
        assert_eq!(windows[1].name, "legacy_secondary_weekly_reset_known");
        assert_eq!(windows[1].left_percent, Some(99));
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].remaining, Some(0));
        // The legacy payload carries none of the 2026-07 credit metadata.
        assert_eq!(credits[0].spend_control_reached, None);
        assert_eq!(credits[0].rate_limit_reached_type, None);
        assert_eq!(credits[0].limit_id, None);
    }

    #[test]
    fn codex_usage_parser_handles_weekly_primary_window() {
        // OpenAI's 2026-07-12 change: the wham/usage fields arrive top-level with
        // a weekly primary window (minutes-denominated), a null secondary, and
        // sibling credit metadata (limit_id, spend_control_reached, ...).
        let json = serde_json::json!({
            "limit_id": "codex",
            "limit_name": null,
            "primary": {
                "used_percent": 30.0,
                "window_minutes": 10080,
                "resets_at": 1784963503_u64
            },
            "secondary": null,
            "credits": {
                "has_credits": false,
                "unlimited": false,
                "balance": "0"
            },
            "individual_limit": null,
            "spend_control_reached": null,
            "plan_type": "pro",
            "rate_limit_reached_type": null
        });

        let windows = codex_usage_quota_windows(&json);
        let credits = codex_usage_credit_balances(&json);

        // Single window: the null secondary is dropped; the primary is weekly by
        // duration (10080 min == 7 days) despite arriving in the primary slot.
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, "legacy_primary_weekly_reset_known");
        assert_eq!(windows[0].window_seconds, Some(604800));
        assert_eq!(windows[0].used_percent, Some(30));
        assert_eq!(windows[0].left_percent, Some(70));

        // `has_credits: false` says the credits program does not apply to this
        // account; the `balance: "0"` beside it is filler, not a spent balance. This
        // test used to assert a single Exhausted row, which is how a red
        // "credits - 0 left - exhausted" meter reached the UI for an account that
        // has no credits at all. Nothing true can be said here, so say nothing.
        assert!(credits.is_empty());
    }

    #[test]
    fn codex_usage_parser_keeps_exhausted_credits_when_the_account_has_a_credits_program() {
        // Same zero balance, opposite meaning: the provider claims the program
        // applies, so zero really is spent and the row has to stay.
        let json = serde_json::json!({
            "limit_id": "codex",
            "primary": {"used_percent": 30.0, "window_minutes": 10080, "resets_at": 1784963503_u64},
            "credits": {"has_credits": true, "unlimited": false, "balance": "0"}
        });

        let credits = codex_usage_credit_balances(&json);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].remaining, Some(0));
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
    }

    #[test]
    fn codex_usage_parser_keeps_disowned_credits_that_still_say_something_true() {
        // `has_credits: false` never hides a positive balance, an unlimited grant,
        // or a reached spend control - suppression is only for the empty case.
        for credits_value in [
            serde_json::json!({"has_credits": false, "unlimited": true, "balance": "0"}),
            serde_json::json!({"has_credits": false, "unlimited": false, "balance": "12"}),
        ] {
            let json = serde_json::json!({
                "limit_id": "codex",
                "primary": {"used_percent": 1.0, "window_minutes": 10080},
                "credits": credits_value.clone()
            });
            assert_eq!(
                codex_usage_credit_balances(&json).len(),
                1,
                "kept for {credits_value}"
            );
        }

        let spend_capped = serde_json::json!({
            "limit_id": "codex",
            "primary": {"used_percent": 1.0, "window_minutes": 10080},
            "spend_control_reached": true,
            "credits": {"has_credits": false, "unlimited": false, "balance": "0"}
        });
        let credits = codex_usage_credit_balances(&spend_capped);
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
    }

    #[test]
    fn codex_usage_parser_carries_workspace_monthly_credit_limit() {
        let json = serde_json::json!({
            "limit_id": "codex",
            "primary": {
                "used_percent": 100,
                "window_minutes": 10080,
                "resets_at": 1786431605_u64
            },
            "credits": {
                "has_credits": true,
                "unlimited": false,
                "balance": null
            },
            "individual_limit": {
                "limit": "8000",
                "used": "4841",
                "remaining_percent": 39,
                "resets_at": 1788220800_u64
            },
            "spend_control_reached": false
        });

        let credits = codex_usage_credit_balances(&json);

        assert_eq!(credits.len(), 2);
        let monthly = &credits[1];
        assert_eq!(monthly.name, "workspace_monthly_credits");
        assert_eq!(monthly.status, AgentCreditBalanceStatus::Ok);
        assert_eq!(monthly.used, Some(4841));
        assert_eq!(monthly.quota, Some(8000));
        assert_eq!(monthly.remaining, Some(3159));
        assert_eq!(monthly.used_percent, Some(61));
        assert_eq!(monthly.resets_at.as_deref(), Some("2026-09-01T00:00:00Z"));
        assert_eq!(monthly.enabled, Some(true));
        assert_eq!(monthly.limit_id.as_deref(), Some("codex"));
    }

    #[test]
    fn codex_usage_parser_treats_spend_control_reached_as_exhausted() {
        // A reached spend control caps the account even with a positive balance.
        let json = serde_json::json!({
            "limit_id": "codex",
            "primary": {
                "used_percent": 12,
                "window_minutes": 10080,
                "resets_at": 1784963503_u64
            },
            "secondary": null,
            "credits": {
                "has_credits": true,
                "unlimited": false,
                "balance": "42"
            },
            "spend_control_reached": true,
            "rate_limit_reached_type": "primary"
        });

        let credits = codex_usage_credit_balances(&json);
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].remaining, Some(42));
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].spend_control_reached, Some(true));
        assert_eq!(
            credits[0].rate_limit_reached_type.as_deref(),
            Some("primary")
        );
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
    }

    #[test]
    fn codex_app_server_parser_extracts_windows_and_reset_bank() {
        let json = serde_json::json!({
            "rateLimits": {
                "limitId": "codex_bengalfox",
                "primary": {
                    "usedPercent": 9,
                    "windowDurationMins": 300,
                    "resetsAt": 1779049800
                },
                "secondary": {
                    "usedPercent": 37,
                    "windowDurationMins": 10080,
                    "resetsAt": 1779613200
                },
                "credits": {
                    "hasCredits": true,
                    "unlimited": false,
                    "balance": "4"
                },
                "planType": "pro"
            },
            "rateLimitsByLimitId": {
                "codex_bengalfox": {
                    "limitId": "codex_bengalfox",
                    "primary": {"usedPercent": 9, "windowDurationMins": 300, "resetsAt": 1779049800}
                },
                "codex": {
                    "limitId": "codex",
                    "primary": {
                        "usedPercent": 3,
                        "windowDurationMins": 300,
                        "resetsAt": 1779049800
                    },
                    "secondary": {
                        "usedPercent": 5,
                        "windowDurationMins": 10080,
                        "resetsAt": 1779613200
                    },
                    "credits": {
                        "hasCredits": true,
                        "unlimited": false,
                        "balance": "12.4"
                    },
                    "planType": "pro"
                }
            },
            "rateLimitResetCredits": {
                "availableCount": 2
            }
        });

        let windows = codex_app_server_quota_windows(&json);
        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0].name, "codex_primary_five_hour_reset_known");
        assert_eq!(windows[0].left_percent, Some(97));
        assert_eq!(
            windows[0].started_at.as_deref(),
            Some("2026-05-17T15:30:00Z")
        );
        assert_eq!(windows[1].name, "codex_secondary_weekly_reset_known");
        assert_eq!(windows[1].left_percent, Some(95));
        assert_eq!(
            windows[2].name,
            "codex_5fbengalfox_primary_five_hour_reset_known"
        );
        assert_eq!(windows[2].left_percent, Some(91));
        assert_eq!(credits.len(), 2);
        assert_eq!(credits[0].name, "credits");
        assert_eq!(credits[0].remaining, Some(12));
        // A payload without the spend-cap fields leaves them unset.
        assert_eq!(credits[0].spend_control_reached, None);
        assert_eq!(credits[0].rate_limit_reached_type, None);
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
        assert_eq!(credits[1].name, "reset_bank");
        assert_eq!(credits[1].unit, AgentCreditBalanceUnit::Resets);
        assert_eq!(credits[1].status, AgentCreditBalanceStatus::Ok);
        assert_eq!(credits[1].remaining, Some(2));
    }

    #[test]
    fn codex_app_server_windows_are_nonpositional_unique_and_preserve_unknowns() {
        let json = serde_json::json!({
            "rateLimitsByLimitId": {
                "synthetic-alpha": {
                    "limitId": "ignored-inner-id",
                    "primary": {"usedPercent": 10, "windowDurationMins": 300, "resetsAt": 1779049800},
                    "secondary": {"usedPercent": 20, "windowDurationMins": 300, "resetsAt": 1779049800},
                    "futureWindow": {"usedPercent": 30, "windowDurationMins": 45},
                    "spendControlReached": true,
                    "rateLimitReachedType": "workspace_owner_usage_limit_reached"
                },
                "synthetic-beta": {
                    "primary": {"usedPercent": 40, "windowDurationMins": 10080, "resetsAt": 1779613200}
                },
                "synthetic/alpha": {
                    "primary": {"usedPercent": 50}
                },
                "synthetic_alpha": {
                    "primary": {"usedPercent": 60}
                }
            }
        });

        let windows = codex_app_server_quota_windows(&json);
        let names = windows
            .iter()
            .map(|window| window.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(windows.len(), 6);
        assert_eq!(names.len(), 6, "distinct windows must never collapse");
        assert!(names.contains("synthetic-alpha_primary_five_hour_reset_known"));
        assert!(names.contains("synthetic-alpha_secondary_five_hour_reset_known"));
        assert!(names.contains("synthetic-alpha_futureWindow_unknown_45m_reset_unknown"));
        assert!(names.contains("synthetic-beta_primary_weekly_reset_known"));
        assert!(names.contains("synthetic_2falpha_primary_unknown_duration_reset_unknown"));
        assert!(names.contains("synthetic_5falpha_primary_unknown_duration_reset_unknown"));
        let reached = windows
            .iter()
            .find(|window| window.name.starts_with("synthetic-alpha_primary"))
            .expect("reached window");
        assert_eq!(reached.limit_id.as_deref(), Some("synthetic-alpha"));
        assert_eq!(reached.spend_control_reached, Some(true));
        assert_eq!(
            reached.rate_limit_reached_type.as_deref(),
            Some("workspaceOwnerUsageLimitReached")
        );
        assert_eq!(reached.status, AgentQuotaWindowStatus::Exhausted);
    }

    #[test]
    fn reset_credit_null_details_never_fabricate_zero_credits() {
        for details in [Value::Null, Value::Array(Vec::new())] {
            let json = serde_json::json!({
                "rateLimits": {},
                "rateLimitResetCredits": {
                    "availableCount": 3,
                    "credits": details
                }
            });
            let balances = codex_app_server_credit_balances(&json);
            assert_eq!(balances.len(), 1);
            assert_eq!(balances[0].name, "reset_bank");
            assert_eq!(balances[0].remaining, Some(3));
            assert_eq!(balances[0].unit, AgentCreditBalanceUnit::Resets);
        }
    }

    #[test]
    fn codex_app_server_parser_carries_credit_spend_control_fields() {
        // The app-server snapshot is the PRIMARY collector (the OAuth wham/usage
        // path is legacy fallback), so it must carry the spend-cap contract too.
        let json = serde_json::json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "primary": {
                        "usedPercent": 100,
                        "windowDurationMins": 300,
                        "resetsAt": 1779049800
                    },
                    "credits": {
                        "hasCredits": true,
                        "unlimited": false,
                        "balance": "9"
                    },
                    "spendControlReached": true,
                    "rateLimitReachedType": "workspaceMemberCreditsDepleted"
                }
            }
        });

        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].name, "credits");
        assert_eq!(credits[0].remaining, Some(9));
        // A reached spend cap is a hard stop even with a nominal balance remaining.
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].spend_control_reached, Some(true));
        assert_eq!(
            credits[0].rate_limit_reached_type.as_deref(),
            Some("workspaceMemberCreditsDepleted")
        );
        assert_eq!(credits[0].limit_id.as_deref(), Some("codex"));
    }

    #[test]
    fn codex_app_server_preserves_credit_balances_from_multiple_limit_buckets() {
        let json = serde_json::json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "credits": {"hasCredits": true, "balance": "12"}
                },
                "codex_business": {
                    "limitId": "codex_business",
                    "credits": {"hasCredits": true, "balance": "4"}
                }
            }
        });

        let balances = codex_app_server_credit_balances(&json);
        let by_name = balances
            .into_iter()
            .map(|balance| (balance.name.clone(), balance))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(by_name["credits"].remaining, Some(12));
        assert_eq!(by_name["codex_business_credits"].remaining, Some(4));
        assert_eq!(
            by_name["codex_business_credits"].limit_id.as_deref(),
            Some("codex_business")
        );
    }

    #[test]
    fn codex_app_server_parser_carries_workspace_monthly_credit_limit() {
        let json = serde_json::json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "primary": {
                        "usedPercent": 100,
                        "windowDurationMins": 10080,
                        "resetsAt": 1786431605_u64
                    },
                    "credits": {
                        "hasCredits": true,
                        "unlimited": false,
                        "balance": null
                    },
                    "individualLimit": {
                        "limit": "8000",
                        "used": "4841",
                        "remainingPercent": 39,
                        "resetsAt": 1788220800_u64
                    },
                    "spendControlReached": false
                }
            }
        });

        let windows = codex_app_server_quota_windows(&json);
        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Exhausted);
        assert_eq!(credits.len(), 2);
        assert_eq!(credits[0].name, "credits");
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Ok);
        let monthly = &credits[1];
        assert_eq!(monthly.name, "workspace_monthly_credits");
        assert_eq!(monthly.status, AgentCreditBalanceStatus::Ok);
        assert_eq!(monthly.used, Some(4841));
        assert_eq!(monthly.quota, Some(8000));
        assert_eq!(monthly.remaining, Some(3159));
        assert_eq!(monthly.used_percent, Some(61));
        assert_eq!(monthly.resets_at.as_deref(), Some("2026-09-01T00:00:00Z"));
        assert_eq!(monthly.spend_control_reached, Some(false));
    }

    #[test]
    fn codex_app_server_selects_snapshot_with_only_monthly_credit_limit() {
        let json = serde_json::json!({
            "rateLimits": {
                "limitId": "codex",
                "primary": null,
                "secondary": null,
                "credits": null,
                "individualLimit": {
                    "limit": "100",
                    "used": "100",
                    "remainingPercent": 0,
                    "resetsAt": 1788220800_u64
                }
            }
        });

        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].name, "workspace_monthly_credits");
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].remaining, Some(0));
    }

    #[test]
    fn codex_app_server_ignores_null_monthly_placeholder_when_selecting_snapshot() {
        let json = serde_json::json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "individualLimit": null
                }
            },
            "rateLimits": {
                "individualLimit": {
                    "limit": "8000",
                    "used": "4525",
                    "remainingPercent": 43,
                    "resetsAt": 1788220800_u64
                }
            }
        });

        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].name, "workspace_monthly_credits");
        assert_eq!(credits[0].remaining, Some(3475));
    }

    #[test]
    fn codex_app_server_parser_preserves_zero_reset_bank_count() {
        let json = serde_json::json!({
            "rateLimits": {
                "limitId": "codex",
                "primary": null,
                "secondary": null,
                "credits": null
            },
            "rateLimitResetCredits": {
                "availableCount": 0
            }
        });

        let credits = codex_app_server_credit_balances(&json);

        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].name, "reset_bank");
        assert_eq!(credits[0].unit, AgentCreditBalanceUnit::Resets);
        assert_eq!(credits[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(credits[0].remaining, Some(0));
    }

    #[test]
    fn claude_json_parser_normalizes_safe_fields() {
        let json = serde_json::json!({
            "status": "authenticated",
            "email": "user@example.com",
            "organization": {"id": "org_1", "name": "Research"},
            "subscription_type": "max_5x"
        });

        let account = parse_claude_auth_json(&json);

        assert_eq!(account.login_state, AgentLoginState::SignedIn);
        assert_eq!(account.provider.as_deref(), Some("anthropic"));
        assert_eq!(account.email.as_deref(), Some("user@example.com"));
        assert_eq!(account.organization_id.as_deref(), Some("org_1"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_max_5x")
        );
    }

    #[test]
    fn claude_json_parser_accepts_current_camel_case_auth_status() {
        let json = serde_json::json!({
            "loggedIn": true,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "email": "user@example.com",
            "orgId": "org_2",
            "orgName": "Research Team",
            "subscriptionType": "max"
        });

        let account = parse_claude_auth_json(&json);

        assert_eq!(account.login_state, AgentLoginState::SignedIn);
        assert_eq!(account.auth_method.as_deref(), Some("claude.ai"));
        assert_eq!(account.organization_id.as_deref(), Some("org_2"));
        assert_eq!(account.organization_label.as_deref(), Some("Research Team"));
        assert_eq!(account.plan_type.as_deref(), Some("max"));
        assert_eq!(account.subscription_product.as_deref(), Some("claude_max"));
        assert_eq!(account.billing_channel.as_deref(), Some("subscription"));
    }

    fn team_auth_account(email: &str, org_id: &str) -> AgentAccountStatus {
        parse_claude_auth_json(&serde_json::json!({
            "loggedIn": true,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "email": email,
            "orgId": org_id,
            "orgName": "Singular",
            "subscriptionType": "team"
        }))
    }

    #[test]
    fn claude_cli_oauth_account_parser_reads_display_safe_fields() {
        let parsed = parse_claude_cli_oauth_account(&serde_json::json!({
            "oauthAccount": {
                "accountUuid": "acct-1",
                "emailAddress": "ron.s@singular.net",
                "organizationUuid": "org-1",
                "organizationType": "claude_team",
                "seatTier": "premium",
                "organizationRateLimitTier": "claude_team",
                "userRateLimitTier": "default_claude_max_5x"
            }
        }))
        .expect("oauthAccount parsed");

        assert_eq!(parsed.account_uuid.as_deref(), Some("acct-1"));
        assert_eq!(parsed.email_address.as_deref(), Some("ron.s@singular.net"));
        assert_eq!(parsed.organization_uuid.as_deref(), Some("org-1"));
        assert_eq!(parsed.organization_type.as_deref(), Some("claude_team"));
        assert_eq!(parsed.seat_tier.as_deref(), Some("premium"));
        assert_eq!(
            parsed.user_rate_limit_tier.as_deref(),
            Some("default_claude_max_5x")
        );
        assert!(parse_claude_cli_oauth_account(&serde_json::json!({})).is_none());
    }

    #[test]
    fn claude_cli_account_identity_stamps_account_hash_onto_plan_observation() {
        // `claude auth status --json` names the org but not the account uuid;
        // the uuid rides `~/.claude.json` `oauthAccount`. The stamped hash must
        // be the exact `billing_identity_hash` the quota windows carry so plan
        // and quota evidence converge on one billing identity.
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        assert!(account.account_id.is_none());
        assert!(account.account_identifier_hash.is_none());
        let oauth = ClaudeCliOauthAccount {
            account_uuid: Some("acct-1".to_string()),
            email_address: Some("ron.s@singular.net".to_string()),
            organization_uuid: Some("org-1".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert!(stamp_claude_cli_account_identity(&mut account, &oauth));

        assert_eq!(account.account_id.as_deref(), Some("acct-1"));
        assert_eq!(
            account.account_identifier_hash,
            billing_identity_hash("anthropic", "account", "acct-1")
        );
        assert!(account.organization_identifier_hash.is_some());
        assert_eq!(
            account.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );

        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-07-28T10:00:00Z".to_string(),
            "2026-07-28T10:30:00Z".to_string(),
        );
        snapshot.account = Some(account);
        append_current_plan_observation(&mut snapshot);

        let observation = snapshot
            .plan_observations
            .first()
            .expect("plan observation");
        assert_eq!(observation.account_id.as_deref(), Some("acct-1"));
        assert_eq!(
            observation.account_identifier_hash,
            billing_identity_hash("anthropic", "account", "acct-1")
        );
        assert!(observation.organization_identifier_hash.is_some());
        assert_eq!(
            observation.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
    }

    #[test]
    fn claude_cli_account_identity_refuses_mismatched_metadata() {
        // `~/.claude.json` lagging behind an account switch must never stamp a
        // different account's uuid onto the signed-in account.
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let stale_email = ClaudeCliOauthAccount {
            account_uuid: Some("acct-other".to_string()),
            email_address: Some("someone.else@example.com".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert!(!stamp_claude_cli_account_identity(
            &mut account,
            &stale_email
        ));
        assert!(account.account_id.is_none());
        assert!(account.account_identifier_hash.is_none());

        let stale_org = ClaudeCliOauthAccount {
            account_uuid: Some("acct-other".to_string()),
            organization_uuid: Some("org-other".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert!(!stamp_claude_cli_account_identity(&mut account, &stale_org));
        assert!(account.account_identifier_hash.is_none());

        // A present auth-status account id that disagrees with `accountUuid`
        // refuses too, and the existing id is left untouched.
        account.account_id = Some("acct-auth-status".to_string());
        let conflicting = ClaudeCliOauthAccount {
            account_uuid: Some("acct-other".to_string()),
            email_address: Some("ron.s@singular.net".to_string()),
            organization_uuid: Some("org-1".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert!(!stamp_claude_cli_account_identity(
            &mut account,
            &conflicting
        ));
        assert_eq!(account.account_id.as_deref(), Some("acct-auth-status"));
        assert!(account.account_identifier_hash.is_none());

        // No account uuid in the metadata: nothing to stamp.
        let uuid_less = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        let mut fresh = team_auth_account("ron.s@singular.net", "org-1");
        assert!(!stamp_claude_cli_account_identity(&mut fresh, &uuid_less));
        assert!(fresh.account_identifier_hash.is_none());
    }

    #[test]
    fn claude_team_seat_tier_refines_premium_from_seat_tier() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            organization_uuid: Some("org-1".to_string()),
            organization_type: Some("claude_team".to_string()),
            seat_tier: Some("premium".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let refined = refine_claude_team_seat_plan(&mut account, &oauth);

        assert_eq!(refined, Some("team_premium"));
        assert_eq!(account.plan_type.as_deref(), Some("team_premium"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_team_premium")
        );
    }

    #[test]
    fn claude_team_seat_tier_refines_premium_from_user_rate_limit_tier() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            user_rate_limit_tier: Some("default_claude_max_5x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_team_seat_plan(&mut account, &oauth),
            Some("team_premium")
        );
    }

    #[test]
    fn claude_team_seat_tier_refines_standard_from_seat_tier() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            seat_tier: Some("standard".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_team_seat_plan(&mut account, &oauth),
            Some("team_standard")
        );
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_team_standard")
        );
    }

    #[test]
    fn claude_team_seat_tier_leaves_generic_team_without_explicit_signal() {
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("ron.s@singular.net".to_string()),
            organization_type: Some("claude_team".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(refine_claude_team_seat_plan(&mut account, &oauth), None);
        assert_eq!(account.plan_type.as_deref(), Some("team"));
        assert_eq!(account.subscription_product.as_deref(), Some("claude_team"));
    }

    #[test]
    fn claude_team_seat_tier_ignores_mismatched_account_metadata() {
        // `~/.claude.json` lagging behind an account switch must not leak a
        // different account's seat tier onto the signed-in account.
        let mut account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("someone.else@example.com".to_string()),
            seat_tier: Some("premium".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(refine_claude_team_seat_plan(&mut account, &oauth), None);
        assert_eq!(account.plan_type.as_deref(), Some("team"));
    }

    #[test]
    fn claude_team_seat_tier_ignores_non_team_plans_and_orgs() {
        let mut max_account = parse_claude_auth_json(&serde_json::json!({
            "loggedIn": true,
            "email": "user@example.com",
            "subscriptionType": "max"
        }));
        let premium_oauth = ClaudeCliOauthAccount {
            seat_tier: Some("premium".to_string()),
            user_rate_limit_tier: Some("default_claude_max_5x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_team_seat_plan(&mut max_account, &premium_oauth),
            None
        );
        assert_eq!(max_account.plan_type.as_deref(), Some("max"));

        // A stale non-team organizationType blocks refinement even when the
        // auth status says team.
        let mut team_account = team_auth_account("ron.s@singular.net", "org-1");
        let stale_oauth = ClaudeCliOauthAccount {
            organization_type: Some("claude_max".to_string()),
            seat_tier: Some("premium".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_team_seat_plan(&mut team_account, &stale_oauth),
            None
        );
    }

    fn max_auth_account(email: &str) -> AgentAccountStatus {
        parse_claude_auth_json(&serde_json::json!({
            "loggedIn": true,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "email": email,
            "subscriptionType": "max"
        }))
    }

    #[test]
    fn claude_max_tier_refines_20x_from_organization_rate_limit_tier() {
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            organization_type: Some("claude_max".to_string()),
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let refined = refine_claude_max_rate_limit_plan(&mut account, &oauth);

        assert_eq!(refined, Some("max_20x"));
        assert_eq!(account.plan_type.as_deref(), Some("max_20x"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_max_20x")
        );
    }

    #[test]
    fn claude_max_tier_refines_5x_from_user_rate_limit_tier_fallback() {
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            user_rate_limit_tier: Some("default_claude_max_5x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut account, &oauth),
            Some("max_5x")
        );
        assert_eq!(account.plan_type.as_deref(), Some("max_5x"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_max_5x")
        );
    }

    #[test]
    fn claude_max_tier_left_generic_without_explicit_signal() {
        // Bare `max` is emitted for BOTH Max tiers: no recognized rate-limit
        // tier means no refinement, never a guess.
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            organization_rate_limit_tier: Some("claude_max".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut account, &oauth),
            None
        );
        assert_eq!(account.plan_type.as_deref(), Some("max"));
        assert_eq!(account.subscription_product.as_deref(), Some("claude_max"));
    }

    #[test]
    #[serial]
    fn registered_slot_resolution_refines_max_20x_from_slot_local_metadata() {
        // End-to-end regression over `resolve_registered_claude_slot` itself,
        // which is where the refinement used to be missing. The fake
        // `claude auth status --json` returns the bare `max` the real CLI
        // returns for BOTH Max tiers; only the slot's own `.claude.json`
        // carries `default_claude_max_20x`. Asserting on the resolved account
        // pins the call site, not just the helper: deleting the
        // `refine_claude_local_plan_metadata` call from the slot path fails
        // this test while every helper-level test still passes.
        let root =
            std::env::temp_dir().join(format!("ottto-claude-slot-max-tier-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let bin = root.join("bin");
        let slot_dir = root.join("max-20x-slot");
        fs::create_dir_all(&home).expect("create home");
        fs::create_dir_all(&bin).expect("create bin");
        fs::create_dir_all(&slot_dir).expect("create slot dir");

        let claude = bin.join("claude");
        fs::write(
            &claude,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fixture-version"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
  exec /usr/bin/python3 - "$CLAUDE_CONFIG_DIR/.claude.json" <<'PY'
import json, sys
account = json.load(open(sys.argv[1]))["oauthAccount"]
# The real CLI collapses Max 5x and Max 20x to a bare `max`.
print(json.dumps({
  "status": "authenticated",
  "email": account["emailAddress"],
  "organizationId": account["organizationUuid"],
  "subscriptionType": "max",
}))
PY
fi
exit 1
"#,
        )
        .expect("write fake claude");
        let security = bin.join("security");
        fs::write(&security, "#!/bin/sh\nexit 1\n").expect("write fake security");
        for executable in [&claude, &security] {
            let mut permissions = fs::metadata(executable).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(executable, permissions).expect("chmod executable");
        }

        fs::write(
            slot_dir.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "oauthAccount": {
                    "accountUuid": "account-max-20x",
                    "organizationUuid": "organization-max-20x",
                    "emailAddress": "max20x@example.invalid",
                    "organizationType": "claude_max",
                    "organizationRateLimitTier": "default_claude_max_20x"
                }
            }))
            .expect("serialize identity"),
        )
        .expect("write slot identity");
        fs::write(
            slot_dir.join(".credentials.json"),
            serde_json::to_vec(&serde_json::json!({
                "claudeAiOauth": {"accessToken": "fixture"}
            }))
            .expect("serialize credential"),
        )
        .expect("write slot credential");

        let _home_guard = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
        let _command_guard =
            EnvVarGuard::set_os("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str().to_os_string());

        let descriptor = ClaudeConfigDirSlot::registered(slot_dir.to_string_lossy().to_string())
            .expect("registered slot")
            .descriptor(
                "claude_slot_max_20x".to_string(),
                ClaudeConfigSlotOwnership::External,
            );
        let resolved = resolve_registered_claude_slot(descriptor).expect("resolve slot");

        assert_eq!(resolved.account.plan_type.as_deref(), Some("max_20x"));
        assert_eq!(
            resolved.account.subscription_product.as_deref(),
            Some("claude_max_20x")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn refine_claude_local_plan_metadata_resolves_max_20x_for_a_registered_slot() {
        // Regression: a registered (`CLAUDE_CONFIG_DIR`) slot used to skip the
        // refinements the default slot applied, so a Max 20x account in an
        // external slot shipped a bare `max` and the backend priced it as the
        // conservative Max 5x lower bound ($100 instead of $200). This is the
        // exact on-disk shape of such a slot: bare `max` from
        // `claude auth status --json`, 20x only in the slot's `.claude.json`.
        let mut account = max_auth_account("user@example.com");
        assert_eq!(account.plan_type.as_deref(), Some("max"));
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            organization_type: Some("claude_max".to_string()),
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let refined = refine_claude_local_plan_metadata(&mut account, &oauth);

        assert_eq!(refined.max_plan, Some("max_20x"));
        assert_eq!(refined.seat_plan, None);
        assert_eq!(account.plan_type.as_deref(), Some("max_20x"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_max_20x")
        );
    }

    #[test]
    fn refine_claude_local_plan_metadata_resolves_team_premium_for_a_registered_slot() {
        // Same gap, the Team seat half: an external-slot Premium seat used to
        // ship a bare `team` and price as Standard ($25 instead of $125).
        let mut account = team_auth_account("user@example.com", "org-1");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            organization_type: Some("claude_team".to_string()),
            seat_tier: Some("team_tier_1".to_string()),
            user_rate_limit_tier: Some("default_claude_max_5x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let refined = refine_claude_local_plan_metadata(&mut account, &oauth);

        assert_eq!(refined.seat_plan, Some("team_premium"));
        assert_eq!(refined.max_plan, None);
        assert_eq!(account.plan_type.as_deref(), Some("team_premium"));
        assert_eq!(
            account.subscription_product.as_deref(),
            Some("claude_team_premium")
        );
    }

    #[test]
    fn refine_claude_local_plan_metadata_leaves_a_bare_plan_untouched() {
        // No explicit signal stays no refinement, through the shared helper
        // too: the backend's conservative pricing depends on never guessing.
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("user@example.com".to_string()),
            organization_type: Some("claude_max".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_local_plan_metadata(&mut account, &oauth),
            RefinedClaudeLocalPlan::default()
        );
        assert_eq!(account.plan_type.as_deref(), Some("max"));
        assert_eq!(account.subscription_product.as_deref(), Some("claude_max"));
    }

    #[test]
    fn claude_max_tier_ignores_mismatched_account_metadata() {
        // `~/.claude.json` lagging behind an account switch must not leak a
        // different account's tier onto the signed-in account.
        let mut account = max_auth_account("user@example.com");
        let oauth = ClaudeCliOauthAccount {
            email_address: Some("someone.else@example.com".to_string()),
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut account, &oauth),
            None
        );
        assert_eq!(account.plan_type.as_deref(), Some("max"));
    }

    #[test]
    fn claude_max_tier_ignores_non_max_plans_and_orgs() {
        // Team plan: the max refinement never fires.
        let mut team_account = team_auth_account("ron.s@singular.net", "org-1");
        let oauth = ClaudeCliOauthAccount {
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut team_account, &oauth),
            None
        );

        // A stale non-max organizationType blocks refinement even when the
        // auth status says max.
        let mut max_account = max_auth_account("user@example.com");
        let stale_oauth = ClaudeCliOauthAccount {
            organization_type: Some("claude_team".to_string()),
            organization_rate_limit_tier: Some("default_claude_max_20x".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            refine_claude_max_rate_limit_plan(&mut max_account, &stale_oauth),
            None
        );
        assert_eq!(max_account.plan_type.as_deref(), Some("max"));
    }

    #[test]
    fn claude_desktop_metadata_observations_split_current_desktop_account() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-desktop-profile-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(
            root.join("config.json"),
            r#"{"lastKnownAccountUuid":"desktop-account-current"}"#,
        )
        .expect("write config");

        let current_code = root
            .join("claude-code-sessions")
            .join("desktop-account-current")
            .join("singular-org-bucket");
        std::fs::create_dir_all(&current_code).expect("create current code bucket");
        std::fs::write(
            current_code.join("local_current.json"),
            r#"{
              "cliSessionId": "current-cli-session",
              "lastActivityAt": "2026-07-08T10:00:00Z",
              "cwd": "/Users/example/private",
              "title": "ignored"
            }"#,
        )
        .expect("write current code metadata");
        let current_identity = root
            .join("local-agent-mode-sessions")
            .join("desktop-account-current")
            .join("different-agent-mode-bucket");
        std::fs::create_dir_all(&current_identity).expect("create current identity bucket");
        std::fs::write(
            current_identity.join("local_identity.json"),
            // lastActivityAt must be explicit and OLDER than the code-session
            // bucket's: without it the reader falls back to file mtime (= test
            // run time), which outranks the code session's fixed timestamp and
            // flips latest_session_id — a wall-clock time bomb.
            r#"{
              "cliSessionId": "identity-cli-session",
              "lastActivityAt": "2026-07-06T10:00:00Z",
              "emailAddress": "ron.s@singular.net",
              "accountName": "Ron",
              "organizationName": "Singular",
              "subscriptionType": "team",
              "initialMessage": "must not be persisted"
            }"#,
        )
        .expect("write current identity metadata");

        let old_code = root
            .join("claude-code-sessions")
            .join("desktop-account-old")
            .join("gmail-org-bucket");
        std::fs::create_dir_all(&old_code).expect("create old code bucket");
        std::fs::write(
            old_code.join("local_old.json"),
            r#"{"cliSessionId":"old-cli-session","lastActivityAt":"2026-07-07T10:00:00Z"}"#,
        )
        .expect("write old code metadata");
        let old_identity = root
            .join("local-agent-mode-sessions")
            .join("desktop-account-old")
            .join("gmail-org-bucket");
        std::fs::create_dir_all(&old_identity).expect("create old identity bucket");
        std::fs::write(
            old_identity.join("local_identity.json"),
            r#"{"emailAddress":"ronshub88@gmail.com"}"#,
        )
        .expect("write old identity metadata");

        let observations =
            claude_desktop_plan_observations_from_root(&root, "2026-07-08T10:01:00Z");

        assert_eq!(observations.len(), 2);
        let current = observations
            .iter()
            .find(|observation| observation.is_current == Some(true))
            .expect("current desktop observation");
        assert_eq!(
            current.evidence_method.as_deref(),
            Some("claude_desktop_session_bucket")
        );
        assert_eq!(current.auth_mode.as_deref(), Some("claude_desktop"));
        assert_eq!(current.billing_channel.as_deref(), Some("subscription"));
        assert_eq!(current.account_label.as_deref(), Some("ron.s@singular.net"));
        assert_eq!(current.organization_label.as_deref(), Some("Singular"));
        assert_eq!(current.plan_type.as_deref(), Some("team"));
        assert_eq!(current.subscription_product.as_deref(), Some("claude_team"));
        assert_eq!(
            current.account_id.as_deref(),
            Some("desktop-account-current")
        );
        assert_eq!(
            current.organization_id.as_deref(),
            Some("singular-org-bucket")
        );
        assert_eq!(
            current.source_session_id.as_deref(),
            Some("current-cli-session")
        );
        assert!(current.account_identifier_hash.is_some());
        assert!(current.organization_identifier_hash.is_some());
        assert_eq!(
            current.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
        assert_eq!(
            current.billing_identity_confidence,
            AgentStatusConfidence::High
        );

        let old = observations
            .iter()
            .find(|observation| observation.account_label.as_deref() == Some("ronshub88@gmail.com"))
            .expect("old desktop observation");
        assert_eq!(old.is_current, Some(false));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_desktop_duplicate_session_owner_uses_newest_account_bucket() {
        let builders = vec![
            ClaudeDesktopProfileBuilder {
                account_uuid: "older-account".to_string(),
                session_activity_by_id: BTreeMap::from([(
                    "resumed-session".to_string(),
                    Some(1_700_000_000),
                )]),
                ..ClaudeDesktopProfileBuilder::default()
            },
            ClaudeDesktopProfileBuilder {
                account_uuid: "newer-account".to_string(),
                session_activity_by_id: BTreeMap::from([(
                    "resumed-session".to_string(),
                    Some(1_700_000_100),
                )]),
                ..ClaudeDesktopProfileBuilder::default()
            },
        ];

        assert_eq!(
            claude_desktop_unambiguous_duplicate_session_owners(&builders).get("resumed-session"),
            Some(&Some(("newer-account".to_string(), Some(1_700_000_100))))
        );
    }

    #[test]
    fn claude_desktop_timestamp_parser_normalizes_javascript_milliseconds() {
        let milliseconds = serde_json::json!(1_786_522_486_333_i64);
        let seconds = serde_json::json!(1_786_522_486_i64);

        assert_eq!(
            timestamp_value_epoch_seconds(Some(&milliseconds)),
            Some(1_786_522_486)
        );
        assert_eq!(
            timestamp_value_epoch_seconds(Some(&seconds)),
            Some(1_786_522_486)
        );
    }

    #[test]
    fn claude_desktop_resumed_session_emits_only_newest_exact_account_binding() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-desktop-resumed-session-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(
            root.join("config.json"),
            r#"{"lastKnownAccountUuid":"gmail-account"}"#,
        )
        .expect("write config");

        for (account, org, file, session, activity) in [
            (
                "team-account",
                "team-org",
                "local_team.json",
                "resumed",
                100,
            ),
            (
                "gmail-account",
                "gmail-org",
                "local_resumed.json",
                "resumed",
                200,
            ),
            (
                "gmail-account",
                "gmail-org",
                "local_newer.json",
                "other",
                300,
            ),
        ] {
            let directory = root.join("claude-code-sessions").join(account).join(org);
            std::fs::create_dir_all(&directory).expect("create account bucket");
            std::fs::write(
                directory.join(file),
                format!(r#"{{"cliSessionId":"{session}","lastActivityAt":{activity}}}"#),
            )
            .expect("write session metadata");
        }

        let observations =
            claude_desktop_plan_observations_from_root(&root, "2026-08-12T08:00:00Z");
        let exact = observations
            .iter()
            .filter(|observation| observation.source_session_id.as_deref() == Some("resumed"))
            .collect::<Vec<_>>();

        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].account_id.as_deref(), Some("gmail-account"));
        assert!(observations.iter().any(|observation| {
            observation.account_id.as_deref() == Some("team-account")
                && observation.source_session_id.is_none()
        }));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_desktop_duplicate_session_owner_fails_closed_on_tie() {
        let builders = vec![
            ClaudeDesktopProfileBuilder {
                account_uuid: "first-account".to_string(),
                session_activity_by_id: BTreeMap::from([(
                    "ambiguous-session".to_string(),
                    Some(1_700_000_000),
                )]),
                ..ClaudeDesktopProfileBuilder::default()
            },
            ClaudeDesktopProfileBuilder {
                account_uuid: "second-account".to_string(),
                session_activity_by_id: BTreeMap::from([(
                    "ambiguous-session".to_string(),
                    Some(1_700_000_000),
                )]),
                ..ClaudeDesktopProfileBuilder::default()
            },
        ];

        assert_eq!(
            claude_desktop_unambiguous_duplicate_session_owners(&builders).get("ambiguous-session"),
            Some(&None)
        );
    }

    #[test]
    fn claude_desktop_duplicate_session_owner_fails_closed_on_missing_activity() {
        let builders = vec![
            ClaudeDesktopProfileBuilder {
                account_uuid: "timestamped-account".to_string(),
                session_activity_by_id: BTreeMap::from([(
                    "ambiguous-session".to_string(),
                    Some(1_700_000_000),
                )]),
                ..ClaudeDesktopProfileBuilder::default()
            },
            ClaudeDesktopProfileBuilder {
                account_uuid: "untimestamped-account".to_string(),
                session_activity_by_id: BTreeMap::from([("ambiguous-session".to_string(), None)]),
                ..ClaudeDesktopProfileBuilder::default()
            },
        ];

        assert_eq!(
            claude_desktop_unambiguous_duplicate_session_owners(&builders).get("ambiguous-session"),
            Some(&None)
        );
    }

    #[test]
    fn claude_oauth_token_parser_extracts_access_and_refresh_presence_only() {
        let payload = r#"{
          "claudeAiOauth": {
            "accessToken": " access-token ",
            "refreshToken": "refresh-token",
            "expiresAt": 1782750000000
          }
        }"#;

        assert_eq!(
            parse_claude_oauth_access_token(payload).as_deref(),
            Some("access-token")
        );
        assert!(
            parse_claude_oauth_credential(payload)
                .expect("credential")
                .has_refresh_token
        );

        let signed_out = r#"{
          "claudeAiOauth": {
            "accessToken": "",
            "refreshToken": "   ",
            "expiresAt": 0,
            "refreshTokenExpiresAt": 1782750000000
          }
        }"#;
        let credential = parse_claude_oauth_credential(signed_out).expect("signed-out shape");
        assert!(credential.access_token.is_none());
        assert!(!credential.has_refresh_token);
        assert_eq!(
            credential.access_expires_at.as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert!(credential.relogin_required_at.is_some());
    }

    #[test]
    fn claude_oauth_keychain_lookup_pins_current_account_and_exact_slot_service() {
        assert_eq!(
            claude_oauth_keychain_lookup_arguments(&ClaudeConfigDirSlot::Default, "local-user")
                .expect("default lookup"),
            vec![
                "find-generic-password",
                "-a",
                "local-user",
                "-s",
                "Claude Code-credentials",
                "-w",
            ]
        );
        assert_eq!(
            claude_oauth_keychain_lookup_arguments(
                &ClaudeConfigDirSlot::registered("/tmp/claude-account").expect("slot"),
                "local-user",
            )
            .expect("custom lookup"),
            vec![
                "find-generic-password",
                "-a",
                "local-user",
                "-s",
                "Claude Code-credentials-ae4ef741",
                "-w",
            ]
        );
        assert!(
            claude_oauth_keychain_lookup_arguments(&ClaudeConfigDirSlot::Default, "").is_none()
        );
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn claude_oauth_keychain_account_comes_from_effective_uid_not_user_environment() {
        let _guard = EnvVarGuard::set_os(
            "USER",
            OsString::from("ottto-environment-account-must-not-win"),
        );
        let account = effective_user_account_name().expect("effective uid account");
        assert_ne!(account, "ottto-environment-account-must-not-win");
        assert!(!account.is_empty());
    }

    #[test]
    fn current_claude_desktop_profile_gets_safe_label_fallback() {
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-123".to_string(),
                organization_uuids: BTreeSet::from(["organization-456".to_string()]),
                code_session_count: 1,
                ..Default::default()
            },
            "2026-07-14T18:00:00Z",
            Some("account-123"),
        )
        .expect("current Desktop observation");

        assert_eq!(observation.account_label.as_deref(), Some("Claude Desktop"));
    }

    #[test]
    fn claude_desktop_multi_org_account_without_current_org_omits_organization() {
        // A non-current account with session buckets under several orgs must
        // not have one picked for it: pairing an account hash with an
        // arbitrary org hash minted a chimera billing identity in production
        // (personal account + employer org). Fail closed: no org at all.
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-multi".to_string(),
                organization_uuids: BTreeSet::from([
                    "employer-org".to_string(),
                    "personal-org".to_string(),
                ]),
                code_session_count: 2,
                ..Default::default()
            },
            "2026-07-28T10:00:00Z",
            Some("some-other-account"),
        )
        .expect("multi-org Desktop observation");

        assert_eq!(observation.organization_id, None);
        assert_eq!(observation.organization_identifier_hash, None);
        assert_eq!(
            observation.account_identifier_hash,
            billing_identity_hash("anthropic", "account", "account-multi")
        );
        assert_eq!(
            observation.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
        assert_eq!(observation.is_current, Some(false));
    }

    #[test]
    fn claude_desktop_single_org_account_keeps_its_organization() {
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-single".to_string(),
                organization_uuids: BTreeSet::from(["only-org".to_string()]),
                code_session_count: 1,
                ..Default::default()
            },
            "2026-07-28T10:00:00Z",
            None,
        )
        .expect("single-org Desktop observation");

        assert_eq!(observation.organization_id.as_deref(), Some("only-org"));
        assert_eq!(
            observation.organization_identifier_hash,
            billing_identity_hash("anthropic", "organization", "only-org")
        );
        assert_eq!(observation.is_current, Some(false));
    }

    #[test]
    fn claude_desktop_current_org_wins_over_multi_org_ambiguity() {
        let observation = claude_desktop_builder_plan_observation(
            ClaudeDesktopProfileBuilder {
                account_uuid: "account-current".to_string(),
                organization_uuids: BTreeSet::from([
                    "employer-org".to_string(),
                    "personal-org".to_string(),
                ]),
                current_organization_uuid: Some("employer-org".to_string()),
                code_session_count: 2,
                ..Default::default()
            },
            "2026-07-28T10:00:00Z",
            Some("account-current"),
        )
        .expect("current multi-org Desktop observation");

        assert_eq!(observation.organization_id.as_deref(), Some("employer-org"));
        assert_eq!(
            observation.organization_identifier_hash,
            billing_identity_hash("anthropic", "organization", "employer-org")
        );
        assert_eq!(observation.is_current, Some(true));
    }

    #[test]
    fn claude_oauth_usage_maps_five_hour_and_weekly_windows() {
        let json = serde_json::json!({
            "five_hour": {
                "utilization": 24.0,
                "resets_at": "2026-06-29T18:10:00.937562+00:00"
            },
            "seven_day": {
                "utilization": 72.0,
                "resets_at": "2026-07-04T05:00:00.937587+00:00"
            },
            "seven_day_sonnet": {
                "utilization": 7.0,
                "resets_at": "2026-07-04T05:00:00.937594+00:00"
            }
        });

        let windows = claude_oauth_quota_windows(&json);

        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].scope, AgentQuotaWindowScope::Account);
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(windows[0].freshness, AgentQuotaWindowFreshness::Fresh);
        assert_eq!(windows[0].used_percent, Some(24));
        assert_eq!(windows[0].left_percent, Some(76));
        assert_eq!(windows[0].window_seconds, Some(5 * 60 * 60));
        assert_eq!(
            windows[0].resets_at.as_deref(),
            Some("2026-06-29T18:10:00.937562Z")
        );
        assert_eq!(windows[1].name, "weekly");
        assert_eq!(windows[1].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(windows[1].used_percent, Some(72));
        assert_eq!(windows[1].left_percent, Some(28));
        assert_eq!(windows[1].window_seconds, Some(7 * 24 * 60 * 60));
        assert_eq!(
            windows[1].resets_at.as_deref(),
            Some("2026-07-04T05:00:00.937587Z")
        );
    }

    #[test]
    fn claude_oauth_usage_cache_keeps_fresh_windows() {
        let cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            organization_identifier_hash: "organization-a".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 400,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                window_seconds: Some(5 * 60 * 60),
                resets_at: Some("2026-06-29T18:10:00Z".to_string()),
                used_percent: Some(25),
                left_percent: Some(75),
                ..Default::default()
            }],
            credit_balances: vec![AgentCreditBalance {
                name: "Usage credits".to_string(),
                status: AgentCreditBalanceStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                unit: AgentCreditBalanceUnit::Usd,
                used: Some(321),
                quota: Some(500),
                remaining: Some(179),
                enabled: Some(true),
                ..Default::default()
            }],
        };

        let usage = claude_oauth_usage_from_cache(cache, 200);

        assert_eq!(usage.windows.len(), 1);
        assert_eq!(usage.windows[0].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Fresh);
        assert_eq!(usage.windows[0].used_percent, Some(25));
        assert_eq!(
            usage.windows[0].observed_at.as_deref(),
            Some("1970-01-01T00:01:40Z")
        );
        assert_eq!(usage.credit_balances.len(), 1);
        assert_eq!(
            usage.credit_balances[0].freshness,
            AgentQuotaWindowFreshness::Fresh
        );
        assert_eq!(usage.credit_balances[0].used, Some(321));
    }

    #[test]
    fn claude_oauth_usage_cache_marks_old_windows_stale() {
        let cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            organization_identifier_hash: "organization-a".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 400,
            windows: vec![AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                window_seconds: Some(7 * 24 * 60 * 60),
                resets_at: Some("2026-07-04T05:00:00Z".to_string()),
                used_percent: Some(72),
                left_percent: Some(28),
                ..Default::default()
            }],
            credit_balances: vec![AgentCreditBalance {
                name: "Usage credits".to_string(),
                status: AgentCreditBalanceStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                unit: AgentCreditBalanceUnit::Usd,
                used: Some(321),
                quota: Some(500),
                enabled: Some(true),
                ..Default::default()
            }],
        };

        // Past the account's own jittered gate, not the bare base constant.
        let usage = claude_oauth_usage_from_cache(
            cache,
            100 + claude_oauth_usage_fresh_age_seconds("account-a", "organization-a") + 1,
        );

        assert_eq!(usage.windows.len(), 1);
        assert_eq!(usage.windows[0].status, AgentQuotaWindowStatus::Unknown);
        assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Stale);
        assert_eq!(usage.windows[0].used_percent, Some(72));
        assert_eq!(
            usage.credit_balances[0].freshness,
            AgentQuotaWindowFreshness::Stale
        );
    }

    #[test]
    fn claude_oauth_usage_cache_discards_v1_schema() {
        let v1 = serde_json::json!({
            "schema_version": 1,
            "observed_at_epoch_seconds": 100,
            "next_refresh_after_epoch_seconds": 400,
            "windows": []
        });
        let cache: ClaudeOAuthUsageCache = serde_json::from_value(v1).unwrap();
        assert_ne!(
            cache.schema_version,
            CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION
        );
    }

    #[test]
    fn claude_oauth_usage_cache_discards_v2_schema() {
        // Version-2 caches predate `account_identifier_hash`: their numbers
        // cannot be attributed to any account, so they must be discarded on
        // upgrade rather than adopted by whoever is logged in now.
        let v2 = serde_json::json!({
            "schema_version": 2,
            "observed_at_epoch_seconds": 100,
            "next_refresh_after_epoch_seconds": 400,
            "windows": [],
            "credit_balances": []
        });
        let cache: ClaudeOAuthUsageCache = serde_json::from_value(v2).unwrap();
        assert!(cache.account_identifier_hash.is_empty());
        assert_ne!(
            cache.schema_version,
            CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION
        );
    }

    #[test]
    fn claude_oauth_account_identifier_hash_prefers_account_uuid() {
        let account_a = ClaudeCliOauthAccount {
            account_uuid: Some("acct-a".to_string()),
            email_address: Some("a@example.test".to_string()),
            organization_uuid: Some("org-shared".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        let account_b = ClaudeCliOauthAccount {
            account_uuid: Some("acct-b".to_string()),
            email_address: Some("b@example.test".to_string()),
            organization_uuid: Some("org-shared".to_string()),
            ..ClaudeCliOauthAccount::default()
        };

        let hash_a = claude_oauth_account_identifier_hash_for(&account_a);
        let hash_b = claude_oauth_account_identifier_hash_for(&account_b);

        assert_eq!(
            hash_a,
            billing_identity_hash("anthropic", "account", "acct-a").expect("account hash")
        );
        // Two accounts inside one organization must still separate.
        assert_ne!(hash_a, hash_b);

        // Falls back to organization, then email, then gives up.
        let org_only = ClaudeCliOauthAccount {
            organization_uuid: Some("org-shared".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            claude_oauth_account_identifier_hash_for(&org_only),
            billing_identity_hash("anthropic", "organization", "org-shared")
                .expect("organization hash")
        );
        let email_only = ClaudeCliOauthAccount {
            email_address: Some("a@example.test".to_string()),
            ..ClaudeCliOauthAccount::default()
        };
        assert_eq!(
            claude_oauth_account_identifier_hash_for(&email_only),
            billing_identity_hash("anthropic", "email", "a@example.test").expect("email hash")
        );
        assert!(
            claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount::default()).is_empty()
        );
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_cache_is_not_served_across_accounts() {
        // Regression, observed live 2026-07-26 on Ottto 0.1.96: the Claude Code
        // CLI credential store was historically single-slot, so `/login` as a
        // second account replaced the first while the machine-global cache kept
        // the first account's numbers. Account A's weekly window rendered under account
        // B's Team subscription, complete with A's reset boundary.
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-usage-cache-account-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        let account_a = claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount {
            account_uuid: Some("acct-a".to_string()),
            ..ClaudeCliOauthAccount::default()
        });
        let account_b = claude_oauth_account_identifier_hash_for(&ClaudeCliOauthAccount {
            account_uuid: Some("acct-b".to_string()),
            ..ClaudeCliOauthAccount::default()
        });
        let organization_a = "organization-a";
        let organization_b = "organization-b";
        assert_ne!(account_a, account_b);

        let now = 10_000;
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_a.clone(),
            organization_identifier_hash: organization_a.to_string(),
            observed_at_epoch_seconds: now,
            next_refresh_after_epoch_seconds: now + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
            windows: vec![AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                window_seconds: Some(7 * 24 * 60 * 60),
                // Account A's reset boundary -- the tell that made the live
                // misattribution unambiguous.
                resets_at: Some("2026-08-01T05:00:00Z".to_string()),
                used_percent: Some(44),
                left_percent: Some(56),
                account_identifier_hash: Some(account_a.clone()),
                organization_identifier_hash: Some(organization_a.to_string()),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        })
        .expect("write cache");

        // The account that wrote it still reads it.
        let served = read_claude_oauth_usage_cache(&account_a, organization_a)
            .expect("own account is served");
        assert_eq!(served.windows[0].used_percent, Some(44));
        assert!(claude_oauth_usage_cache_path(&account_a, organization_a).is_file());
        assert!(
            read_claude_oauth_usage_cache(&account_a, organization_b).is_none(),
            "an account-only match must not relabel cached meters under another organization"
        );

        // The replacing account must not.
        assert!(
            read_claude_oauth_usage_cache(&account_b, organization_b).is_none(),
            "cache written under account A was served to account B"
        );
        // Nor may an unidentifiable credential inherit a named account's cache.
        assert!(read_claude_oauth_usage_cache("", "").is_none());

        // Same guard on the 429 / transport fallback path, where the 24h max
        // age applies and serving another account's numbers is worse than
        // serving none. This mirrors the `unwrap_or` in
        // `collect_claude_oauth_usage`'s 429 arm.
        let retry_after = now + CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS;
        let fallback = read_claude_oauth_usage_cache(&account_b, organization_b).unwrap_or(
            ClaudeOAuthUsageCache {
                schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                account_identifier_hash: account_b.clone(),
                organization_identifier_hash: organization_b.to_string(),
                observed_at_epoch_seconds: now,
                next_refresh_after_epoch_seconds: retry_after,
                windows: Vec::new(),
                credit_balances: Vec::new(),
            },
        );
        assert!(
            fallback.windows.is_empty(),
            "429 fallback served account A's windows to account B"
        );
        assert_eq!(fallback.account_identifier_hash, account_b);
        // Writing B's fallback now creates B's physical account store without
        // replacing A's. Future multi-slot collection can therefore maintain
        // both accounts independently.
        write_claude_oauth_usage_cache(&fallback).expect("write fallback cache");
        assert!(read_claude_oauth_usage_cache(&account_a, organization_a).is_some());
        assert!(claude_oauth_usage_cache_path(&account_b, organization_b).is_file());
        assert_ne!(
            claude_oauth_usage_cache_path(&account_a, organization_a),
            claude_oauth_usage_cache_path(&account_b, organization_b)
        );

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_oauth_usage_cache_rejects_mismatched_embedded_meter_identity() {
        let mut cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            organization_identifier_hash: "organization-a".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 200,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                account_identifier_hash: Some("account-a".to_string()),
                organization_identifier_hash: Some("organization-a".to_string()),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        };
        assert!(claude_oauth_usage_cache_belongs_to_identity(
            &cache,
            "account-a",
            "organization-a",
        ));
        cache.windows[0].organization_identifier_hash = Some("organization-b".to_string());
        assert!(!claude_oauth_usage_cache_belongs_to_identity(
            &cache,
            "account-a",
            "organization-a",
        ));
    }

    #[test]
    #[serial]
    fn same_account_two_organizations_have_independent_state_and_admission() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-composite-state-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        let account = "same-account";
        let organization_a = "organization-a";
        let organization_b = "organization-b";
        assert_ne!(
            claude_oauth_usage_cache_path(account, organization_a),
            claude_oauth_usage_cache_path(account, organization_b)
        );
        let held = try_claude_oauth_collection_attempt(account, organization_a)
            .expect("organization A admission");
        assert!(
            try_claude_oauth_collection_attempt(account, organization_a).is_none(),
            "same composite binding must coalesce"
        );
        let other = try_claude_oauth_collection_attempt(account, organization_b)
            .expect("organization B remains independent");
        drop(other);
        drop(held);

        let fingerprint = "composite-fingerprint";
        record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::AuthRejected,
            account,
            organization_a,
            fingerprint,
            1_000,
        );
        assert!(read_claude_oauth_usage_breaker(account, organization_a, fingerprint).is_some());
        assert!(read_claude_oauth_usage_breaker(account, organization_b, fingerprint).is_none());
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    #[serial]
    fn missing_token_serves_exact_two_hour_cache_stale_past_open_breaker() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-no-token-stale-cache-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _support_guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        let _network_guard =
            EnvVarGuard::set_os("OTTTO_DISABLE_CLAUDE_OAUTH_USAGE", OsString::from("0"));
        let account = "account-stale";
        let organization = "organization-stale";
        let now = current_unix_seconds();
        let observed_at = now.saturating_sub(2 * 60 * 60);
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account.to_string(),
            organization_identifier_hash: organization.to_string(),
            observed_at_epoch_seconds: observed_at,
            next_refresh_after_epoch_seconds: observed_at + CLAUDE_OAUTH_USAGE_REFRESH_SECONDS,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                freshness: AgentQuotaWindowFreshness::Fresh,
                account_identifier_hash: Some(account.to_string()),
                organization_identifier_hash: Some(organization.to_string()),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        })
        .expect("write exact stale cache");
        let fingerprint = claude_oauth_usage_config_fingerprint();
        for _ in 0..ClaudeOAuthUsageFailure::AuthRejected.threshold() {
            record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::AuthRejected,
                account,
                organization,
                &fingerprint,
                now,
            );
        }
        assert!(
            read_claude_oauth_usage_breaker(account, organization, &fingerprint)
                .is_some_and(|breaker| claude_oauth_usage_breaker_is_open(&breaker, now))
        );
        let calls_before = CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);

        let outcome =
            collect_claude_oauth_usage_with_access_token(account, organization, None, false);

        let usage = outcome.result.expect("serve exact stale cache");
        assert_eq!(usage.windows.len(), 1);
        assert_eq!(usage.windows[0].freshness, AgentQuotaWindowFreshness::Stale);
        assert!(outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "claude_oauth_usage_circuit_open"));
        assert_eq!(
            CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            calls_before,
            "a missing token must never admit a provider call"
        );
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    fn claude_oauth_usage_cache_identity_match_is_exact_both_ways() {
        let cache = |account_hash: &str, organization_hash: &str| ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_hash.to_string(),
            organization_identifier_hash: organization_hash.to_string(),
            observed_at_epoch_seconds: 0,
            next_refresh_after_epoch_seconds: 0,
            windows: Vec::new(),
            credit_balances: Vec::new(),
        };

        assert!(claude_oauth_usage_cache_belongs_to_identity(
            &cache("account-a", "organization-a"),
            "account-a",
            "organization-a",
        ));
        assert!(!claude_oauth_usage_cache_belongs_to_identity(
            &cache("account-a", "organization-a"),
            "account-b",
            "organization-a",
        ));
        assert!(!claude_oauth_usage_cache_belongs_to_identity(
            &cache("account-a", "organization-a"),
            "account-a",
            "organization-b",
        ));
        assert!(!claude_oauth_usage_cache_belongs_to_identity(
            &cache("account-a", "organization-a"),
            "",
            "",
        ));
        assert!(!claude_oauth_usage_cache_belongs_to_identity(
            &cache("", ""),
            "",
            "",
        ));
    }

    #[test]
    #[serial]
    fn legacy_usage_cache_migrates_into_its_physical_account_store() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-cache-migration-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        let cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            organization_identifier_hash: "organization-a".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 200,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                account_identifier_hash: Some("account-a".to_string()),
                organization_identifier_hash: Some("organization-a".to_string()),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        };
        fs::write(
            claude_oauth_usage_legacy_cache_path(),
            serde_json::to_vec_pretty(&cache).expect("serialize legacy cache"),
        )
        .expect("write legacy cache");

        assert!(read_claude_oauth_usage_cache("account-b", "organization-b").is_none());
        assert!(claude_oauth_usage_legacy_cache_path().is_file());
        assert_eq!(
            read_claude_oauth_usage_cache("account-a", "organization-a")
                .expect("migrated cache")
                .account_identifier_hash,
            "account-a"
        );
        assert!(claude_oauth_usage_cache_path("account-a", "organization-a").is_file());
        assert!(!claude_oauth_usage_legacy_cache_path().exists());
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    #[serial]
    fn default_account_state_is_mirrored_for_downgrade_without_custom_account_leakage() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-downgrade-mirror-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        let default_cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-default".to_string(),
            organization_identifier_hash: "organization-default".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: u64::MAX,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                used_percent: Some(20),
                account_identifier_hash: Some("account-default".to_string()),
                organization_identifier_hash: Some("organization-default".to_string()),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        };
        let custom_cache = ClaudeOAuthUsageCache {
            account_identifier_hash: "account-custom".to_string(),
            organization_identifier_hash: "organization-custom".to_string(),
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                used_percent: Some(80),
                account_identifier_hash: Some("account-custom".to_string()),
                organization_identifier_hash: Some("organization-custom".to_string()),
                ..Default::default()
            }],
            ..default_cache.clone()
        };
        write_claude_oauth_usage_cache(&default_cache).expect("write default account cache");
        write_legacy_claude_oauth_usage_cache(&default_cache).expect("mirror legacy cache");
        assert!(read_claude_oauth_usage_cache_with_legacy_migration(
            "account-custom",
            "organization-custom",
            false,
        )
        .is_none());
        assert!(
            claude_oauth_usage_legacy_cache_path().is_file(),
            "a custom-first read must not consume the default downgrade cache"
        );
        write_claude_oauth_usage_cache(&custom_cache).expect("write custom account cache");

        let legacy_cache: ClaudeOAuthUsageCache = serde_json::from_str(
            &fs::read_to_string(claude_oauth_usage_legacy_cache_path()).expect("read legacy cache"),
        )
        .expect("parse legacy cache");
        assert_eq!(legacy_cache.account_identifier_hash, "account-default");
        assert_eq!(
            legacy_cache.schema_version,
            CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION
        );
        assert_eq!(legacy_cache.windows[0].used_percent, Some(20));
        assert_eq!(
            read_claude_oauth_usage_cache("account-custom", "organization-custom")
                .expect("read custom cache")
                .windows[0]
                .used_percent,
            Some(80)
        );

        let fingerprint = "fingerprint-default";
        record_claude_oauth_usage_failure_with_legacy(
            ClaudeOAuthUsageFailure::AuthRejected,
            "account-default",
            "organization-default",
            fingerprint,
            1_000,
            true,
        );
        assert!(read_claude_oauth_usage_breaker_with_legacy_migration(
            "account-custom",
            "organization-custom",
            "fingerprint-custom",
            false,
        )
        .is_none());
        assert!(
            claude_oauth_usage_legacy_breaker_path().is_file(),
            "a custom-first read must not consume the default downgrade breaker"
        );
        record_claude_oauth_usage_failure_with_legacy(
            ClaudeOAuthUsageFailure::ResponseShape,
            "account-custom",
            "organization-custom",
            "fingerprint-custom",
            1_000,
            false,
        );
        let legacy_breaker: ClaudeOAuthUsageBreaker = serde_json::from_str(
            &fs::read_to_string(claude_oauth_usage_legacy_breaker_path())
                .expect("read legacy breaker"),
        )
        .expect("parse legacy breaker");
        assert_eq!(legacy_breaker.account_identifier_hash, "account-default");
        assert_eq!(legacy_breaker.config_fingerprint, fingerprint);
        assert_eq!(legacy_breaker.auth_failures, 1);
        assert_eq!(legacy_breaker.shape_failures, 0);
        assert_eq!(
            read_claude_oauth_usage_breaker(
                "account-custom",
                "organization-custom",
                "fingerprint-custom"
            )
            .expect("read custom breaker")
            .shape_failures,
            1
        );

        clear_claude_oauth_usage_breaker_with_legacy(
            "account-default",
            "organization-default",
            true,
        );
        assert!(!claude_oauth_usage_legacy_breaker_path().exists());
        assert!(read_claude_oauth_usage_breaker(
            "account-default",
            "organization-default",
            fingerprint
        )
        .is_none());
        assert!(read_claude_oauth_usage_breaker(
            "account-custom",
            "organization-custom",
            "fingerprint-custom"
        )
        .is_some());
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    #[serial]
    fn concurrent_legacy_cache_migration_is_single_copy_and_owner_only() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-cache-concurrent-migration-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        let cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION,
            account_identifier_hash: "account-concurrent".to_string(),
            organization_identifier_hash: "organization-concurrent".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 200,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                account_identifier_hash: Some("account-concurrent".to_string()),
                organization_identifier_hash: Some("organization-concurrent".to_string()),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        };
        fs::write(
            claude_oauth_usage_legacy_cache_path(),
            serde_json::to_vec_pretty(&cache).expect("serialize legacy cache"),
        )
        .expect("write legacy cache");

        let workers: Vec<_> = (0..12)
            .map(|_| {
                std::thread::spawn(|| {
                    read_claude_oauth_usage_cache("account-concurrent", "organization-concurrent")
                        .expect("migrated cache")
                        .account_identifier_hash
                })
            })
            .collect();
        for worker in workers {
            assert_eq!(worker.join().expect("worker"), "account-concurrent");
        }
        let target = claude_oauth_usage_cache_path("account-concurrent", "organization-concurrent");
        assert!(target.is_file());
        assert!(!claude_oauth_usage_legacy_cache_path().exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    #[serial]
    fn cache_and_breaker_writes_are_atomic_owner_only_and_symlink_safe() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-state-atomic-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        let account = "account-atomic";
        let cache = ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account.to_string(),
            organization_identifier_hash: "organization-atomic".to_string(),
            observed_at_epoch_seconds: 100,
            next_refresh_after_epoch_seconds: 200,
            windows: Vec::new(),
            credit_balances: Vec::new(),
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let cache_path = claude_oauth_usage_cache_path(account, "organization-atomic");
            fs::create_dir_all(cache_path.parent().expect("cache parent"))
                .expect("create cache parent");
            let sentinel = support_dir.join("sentinel.json");
            fs::write(&sentinel, b"untouched").expect("write sentinel");
            symlink(&sentinel, &cache_path).expect("plant cache symlink");

            write_claude_oauth_usage_cache(&cache).expect("atomic cache write");
            assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"untouched");
            assert!(!fs::symlink_metadata(&cache_path)
                .expect("cache metadata")
                .file_type()
                .is_symlink());
            assert_eq!(
                fs::metadata(&cache_path)
                    .expect("cache metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        #[cfg(not(unix))]
        write_claude_oauth_usage_cache(&cache).expect("atomic cache write");

        record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::AuthRejected,
            account,
            "organization-atomic",
            "fingerprint-atomic",
            100,
        );
        let breaker_path = claude_oauth_usage_breaker_path(account, "organization-atomic");
        let _: ClaudeOAuthUsageBreaker =
            serde_json::from_slice(&fs::read(&breaker_path).expect("read complete breaker JSON"))
                .expect("parse complete breaker JSON");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&breaker_path)
                    .expect("breaker metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        for entry in fs::read_dir(
            claude_oauth_usage_cache_path(account, "organization-atomic")
                .parent()
                .expect("account state dir"),
        )
        .expect("read account state dir")
        {
            let name = entry
                .expect("state entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            assert!(!name.contains(".tmp."), "orphaned atomic temp file: {name}");
        }
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    #[serial]
    fn concurrent_cache_writes_leave_one_complete_account_document() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-cache-concurrent-write-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        const WORKERS: u64 = 20;
        let workers: Vec<_> = (0..WORKERS)
            .map(|observed_at_epoch_seconds| {
                std::thread::spawn(move || {
                    write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
                        schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
                        account_identifier_hash: "account-concurrent-cache".to_string(),
                        organization_identifier_hash: "organization-concurrent-cache".to_string(),
                        observed_at_epoch_seconds,
                        next_refresh_after_epoch_seconds: observed_at_epoch_seconds + 100,
                        windows: Vec::new(),
                        credit_balances: Vec::new(),
                    })
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker").expect("cache write");
        }
        let cache = read_claude_oauth_usage_cache(
            "account-concurrent-cache",
            "organization-concurrent-cache",
        )
        .expect("complete cache after concurrent writes");
        assert!(cache.observed_at_epoch_seconds < WORKERS);
        assert_eq!(
            cache.next_refresh_after_epoch_seconds,
            cache.observed_at_epoch_seconds + 100
        );
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    fn claude_oauth_usage_cadence_is_hourly_within_a_five_minute_spread() {
        // The spread is load-spreading across our own installs, so it must be
        // bounded and deterministic -- never an open-ended random delay.
        for seed in [
            "",
            "account-a",
            "account-b",
            "9f1c0c1a4b5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7",
        ] {
            let gate = claude_oauth_usage_fresh_age_seconds(seed, "organization-test");
            assert!(
                (55 * 60..=65 * 60).contains(&gate),
                "gate for {seed:?} out of the 55-65 minute band: {gate}"
            );
            assert_eq!(
                gate,
                claude_oauth_usage_fresh_age_seconds(seed, "organization-test"),
                "gate must be stable for a given account, not redrawn per call"
            );
        }
        // Different accounts land on different phases; that is the whole point.
        assert_ne!(
            claude_oauth_usage_fresh_age_seconds("account-a", "organization-test"),
            claude_oauth_usage_fresh_age_seconds("account-b", "organization-test")
        );
        // Sanity on the base cadence itself: ~24 calls/day, not ~96.
        assert_eq!(CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS, 60 * 60);
        // The 24h max age stays a display fallback, well clear of the gate.
        assert!(
            CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS
                > claude_oauth_usage_fresh_age_seconds("account-a", "organization-test")
        );
    }

    #[test]
    fn claude_oauth_usage_breaker_opens_on_each_trigger_class() {
        for (failure, threshold, code) in [
            (
                ClaudeOAuthUsageFailure::AuthRejected,
                CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
                "auth_rejected",
            ),
            (
                ClaudeOAuthUsageFailure::ResponseShape,
                CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD,
                "response_shape_changed",
            ),
            (
                ClaudeOAuthUsageFailure::RateLimited,
                CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD,
                "rate_limited",
            ),
        ] {
            let mut breaker = None;
            for attempt in 1..=threshold {
                breaker = Some(claude_oauth_usage_breaker_after_failure(
                    breaker,
                    failure,
                    "account-a",
                    "organization-a",
                    "fingerprint-a",
                    1_000,
                ));
                let current = breaker.as_ref().expect("breaker");
                let open = claude_oauth_usage_breaker_is_open(current, 1_000);
                assert_eq!(
                    open,
                    attempt >= threshold,
                    "{code} opened at attempt {attempt} of {threshold}"
                );
            }
            let opened = breaker.expect("breaker");
            assert_eq!(opened.opened_by, code);
            assert_eq!(opened.opened_at_epoch_seconds, 1_000);
            assert_eq!(
                opened.reopen_after_epoch_seconds,
                1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS
            );
        }
    }

    #[test]
    fn claude_oauth_usage_breaker_counts_failure_classes_separately() {
        // One 429 plus one 401 must not add up to a trip: a mixed dribble of
        // unrelated transient failures is not the structural signal.
        let mut breaker = None;
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
            breaker = Some(claude_oauth_usage_breaker_after_failure(
                breaker,
                ClaudeOAuthUsageFailure::RateLimited,
                "account-a",
                "organization-a",
                "fingerprint-a",
                1_000,
            ));
        }
        let breaker = breaker.expect("breaker");
        assert!(!claude_oauth_usage_breaker_is_open(&breaker, 1_000));
        assert_eq!(breaker.auth_failures, 0);
        assert_eq!(breaker.shape_failures, 0);
    }

    #[test]
    fn claude_oauth_usage_breaker_closes_after_cooldown() {
        let mut breaker = None;
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
            breaker = Some(claude_oauth_usage_breaker_after_failure(
                breaker,
                ClaudeOAuthUsageFailure::AuthRejected,
                "account-a",
                "organization-a",
                "fingerprint-a",
                1_000,
            ));
        }
        let breaker = breaker.expect("breaker");
        assert!(claude_oauth_usage_breaker_is_open(&breaker, 1_000));
        assert!(claude_oauth_usage_breaker_is_open(
            &breaker,
            1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS - 1
        ));
        assert!(!claude_oauth_usage_breaker_is_open(
            &breaker,
            1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS
        ));
    }

    #[test]
    fn claude_oauth_usage_config_fingerprint_tracks_the_call_it_governs() {
        let baseline = claude_oauth_usage_config_fingerprint_for(
            "https://api.anthropic.com/api/oauth/usage",
            "oauth-2025-04-20",
            "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
            false,
        );
        assert_eq!(
            baseline,
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2025-04-20",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                false,
            )
        );
        for changed in [
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage/v2",
                "oauth-2025-04-20",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                false,
            ),
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2026-01-01",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                false,
            ),
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2025-04-20",
                "ottto/1.2.4 (subscription-usage-reader; +https://ottto.net)",
                false,
            ),
            // Toggling the off-switch resets the breaker: the sentinel is part
            // of the configuration the verdict was about.
            claude_oauth_usage_config_fingerprint_for(
                "https://api.anthropic.com/api/oauth/usage",
                "oauth-2025-04-20",
                "ottto/1.2.3 (subscription-usage-reader; +https://ottto.net)",
                true,
            ),
        ] {
            assert_ne!(baseline, changed);
        }
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_breaker_state_is_scoped_and_resettable() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-breaker-state-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        assert!(
            read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a")
                .is_none()
        );
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD {
            record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::AuthRejected,
                "account-a",
                "organization-a",
                "fingerprint-a",
                1_000,
            );
        }
        let stored =
            read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a")
                .expect("stored breaker");
        assert!(claude_oauth_usage_breaker_is_open(&stored, 1_000));
        // Account-keyed and config-keyed, exactly like the usage cache: a
        // different account or a changed call configuration starts clean.
        assert!(
            read_claude_oauth_usage_breaker("account-b", "organization-b", "fingerprint-a")
                .is_none()
        );
        assert!(
            read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-b")
                .is_none()
        );

        clear_claude_oauth_usage_breaker("account-a", "organization-a");
        assert!(
            read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a")
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    #[serial]
    fn concurrent_breaker_failures_are_one_account_transaction_without_lost_updates() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-breaker-concurrent-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        const WORKERS: usize = 24;
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                std::thread::spawn(|| {
                    record_claude_oauth_usage_failure(
                        ClaudeOAuthUsageFailure::AuthRejected,
                        "account-concurrent-breaker",
                        "organization-concurrent-breaker",
                        "fingerprint-concurrent-breaker",
                        1_000,
                    )
                })
            })
            .collect();
        let emitted = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        let breaker = read_claude_oauth_usage_breaker(
            "account-concurrent-breaker",
            "organization-concurrent-breaker",
            "fingerprint-concurrent-breaker",
        )
        .expect("concurrent breaker");
        assert_eq!(breaker.auth_failures, WORKERS as u32);
        assert_eq!(emitted.len(), 1, "open transition should emit exactly once");
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    #[serial]
    fn legacy_breaker_migrates_into_its_physical_account_store() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-breaker-migration-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&support_dir);
        fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        let breaker = ClaudeOAuthUsageBreaker {
            schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            organization_identifier_hash: "organization-a".to_string(),
            config_fingerprint: "fingerprint-a".to_string(),
            auth_failures: 2,
            ..Default::default()
        };
        fs::write(
            claude_oauth_usage_legacy_breaker_path(),
            serde_json::to_vec_pretty(&breaker).expect("serialize legacy breaker"),
        )
        .expect("write legacy breaker");

        assert!(
            read_claude_oauth_usage_breaker("account-b", "organization-b", "fingerprint-a")
                .is_none()
        );
        assert!(claude_oauth_usage_legacy_breaker_path().is_file());
        assert_eq!(
            read_claude_oauth_usage_breaker("account-a", "organization-a", "fingerprint-a")
                .expect("migrated breaker")
                .auth_failures,
            2
        );
        assert!(claude_oauth_usage_breaker_path("account-a", "organization-a").is_file());
        assert!(!claude_oauth_usage_legacy_breaker_path().exists());
        let _ = fs::remove_dir_all(support_dir);
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_breaker_alerts_once_and_then_skips_the_network() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-breaker-alert-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );
        // Pin the account to "unidentifiable" (no `~/.claude.json` under this
        // HOME) so the state this test writes is the state
        // `collect_claude_oauth_usage` reads back, on any machine.
        let _home_guard = EnvVarGuard::set_os("HOME", support_dir.as_os_str().to_os_string());
        let account = claude_oauth_account_identifier_hash();
        let fingerprint = claude_oauth_usage_config_fingerprint();
        let now = current_unix_seconds();

        let mut emitted = Vec::new();
        for _ in 0..CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD {
            emitted.extend(record_claude_oauth_usage_failure(
                ClaudeOAuthUsageFailure::RateLimited,
                &account,
                "organization-alert",
                &fingerprint,
                now,
            ));
        }
        assert_eq!(
            emitted.len(),
            1,
            "the breaker alerts on the transition, not on every failure"
        );
        assert_eq!(emitted[0].code, "claude_oauth_usage_circuit_open");
        assert_eq!(emitted[0].severity, AgentDiagnosticSeverity::Warning);
        assert!(emitted[0].message.contains("rate limited"));
        // Further failures while open must not re-alert.
        assert!(record_claude_oauth_usage_failure(
            ClaudeOAuthUsageFailure::RateLimited,
            &account,
            "organization-alert",
            &fingerprint,
            now + 100,
        )
        .is_empty());

        // While open, the collector never reaches the network: it returns the
        // breaker error plus the alert without a token read or a request.
        let outcome = collect_claude_oauth_usage_with_access_token(
            &account,
            "organization-alert",
            None,
            false,
        );
        assert!(outcome.result.is_err());
        assert!(outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "claude_oauth_usage_circuit_open"));

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_oauth_usage_transient_errors_do_not_count_toward_the_breaker() {
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                401,
                ureq::Response::new(401, "Unauthorized", "{}").expect("response")
            )),
            Some(ClaudeOAuthUsageFailure::AuthRejected)
        );
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                403,
                ureq::Response::new(403, "Forbidden", "{}").expect("response")
            )),
            Some(ClaudeOAuthUsageFailure::AuthRejected)
        );
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                404,
                ureq::Response::new(404, "Not Found", "{}").expect("response")
            )),
            Some(ClaudeOAuthUsageFailure::ResponseShape)
        );
        // A 5xx is the vendor having a bad day, not a signal to stop asking.
        assert_eq!(
            claude_oauth_usage_failure_class(&ureq::Error::Status(
                503,
                ureq::Response::new(503, "Unavailable", "{}").expect("response")
            )),
            None
        );
    }

    #[test]
    #[serial]
    fn claude_oauth_usage_sentinel_disables_the_network_read() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-oauth-off-switch-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        // Default (no sentinel) is enabled -- unchanged behaviour.
        assert!(!claude_oauth_usage_network_disabled());

        // A previously fetched payload remains local and keeps its original
        // observation time while the sentinel pauses all network reads.
        let account_hash = "off-switch-account";
        let organization_hash = "off-switch-organization";
        write_claude_oauth_usage_cache(&ClaudeOAuthUsageCache {
            schema_version: CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION,
            account_identifier_hash: account_hash.to_string(),
            organization_identifier_hash: organization_hash.to_string(),
            observed_at_epoch_seconds: current_unix_seconds(),
            next_refresh_after_epoch_seconds: current_unix_seconds() + 60,
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                scope: AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                used_percent: Some(25),
                account_identifier_hash: Some(account_hash.to_string()),
                organization_identifier_hash: Some(organization_hash.to_string()),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        })
        .expect("write cache fixture");

        // The exact filename is a contract with the macOS Companion toggle.
        std::fs::write(
            support_dir.join("claude-oauth-usage-network-disabled"),
            b"disabled\n",
        )
        .expect("write sentinel");
        assert!(claude_oauth_usage_network_disabled());
        let provider_calls_before =
            CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst);

        let outcome = collect_claude_oauth_usage_with_access_token(
            account_hash,
            organization_hash,
            None,
            true,
        );
        assert!(outcome.result.is_err());
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(
            outcome.diagnostics[0].code,
            "claude_oauth_usage_network_disabled"
        );
        assert_eq!(
            outcome.diagnostics[0].severity,
            AgentDiagnosticSeverity::Info
        );
        assert!(claude_oauth_usage_cache_path(account_hash, organization_hash).exists());

        std::fs::remove_file(support_dir.join("claude-oauth-usage-network-disabled"))
            .expect("re-enable collection");
        let resumed = collect_claude_oauth_usage_with_access_token(
            account_hash,
            organization_hash,
            None,
            true,
        );
        assert!(
            resumed.result.is_ok(),
            "the retained fresh cache resumes without another prompt"
        );
        assert_eq!(
            CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            provider_calls_before,
            "the off-switch and cache-only resume must never admit a provider call"
        );

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_oauth_usage_diagnostics_survive_the_backend_upload_redaction() {
        // The circuit-breaker alert reaches our servers by riding the
        // agent-status snapshot upload; `redacted_for_backend` is the only
        // transform between the collector and the wire.
        let breaker = ClaudeOAuthUsageBreaker {
            schema_version: CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION,
            account_identifier_hash: "account-a".to_string(),
            config_fingerprint: "fingerprint-a".to_string(),
            auth_failures: CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD,
            opened_at_epoch_seconds: 1_000,
            reopen_after_epoch_seconds: 1_000 + CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS,
            opened_by: "auth_rejected".to_string(),
            ..Default::default()
        };
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::StatusLine,
            "2026-07-26T00:00:00Z".to_string(),
            "2026-07-26T00:30:00Z".to_string(),
        );
        snapshot
            .diagnostics
            .push(claude_oauth_usage_circuit_open_diagnostic(&breaker, 1_000));
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_oauth_usage_network_disabled",
            AgentDiagnosticSeverity::Info,
            "Claude subscription quota is read from Claude Code's local statusLine only: the Claude OAuth usage network read is switched off on this machine.",
        ));

        let uploaded = snapshot.redacted_for_backend();
        let codes: Vec<&str> = uploaded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![
                "claude_oauth_usage_circuit_open",
                "claude_oauth_usage_network_disabled"
            ]
        );
        // Codes and messages must survive intact -- a redacted message would
        // reach the backend as "diagnostic redacted" and the alert would be
        // useless.
        assert!(uploaded.diagnostics.iter().all(|diagnostic| {
            diagnostic.message != "diagnostic redacted" && diagnostic.code != "redacted"
        }));
    }

    #[test]
    fn claude_oauth_spend_disabled_emits_no_credit_balance() {
        // Live disabled-state sample observed 2026-07-06 (Max account).
        let json = serde_json::json!({
            "spend": {
                "used": {"amount_minor": 0, "currency": "USD", "exponent": 2},
                "limit": null, "cap": null, "balance": null,
                "percent": 0, "severity": "normal", "enabled": false,
                "can_purchase_credits": false, "can_toggle": false
            },
            "extra_usage": {"is_enabled": false, "monthly_limit": null, "used_credits": null}
        });
        assert!(claude_oauth_credit_balances(&json).is_empty());
    }

    #[test]
    fn claude_oauth_spend_enabled_maps_usage_credit_balance() {
        let json = serde_json::json!({
            "spend": {
                "used": {"amount_minor": 321, "currency": "USD", "exponent": 2},
                "cap": {"amount_minor": 500, "currency": "USD", "exponent": 2},
                "balance": {"amount_minor": 179, "currency": "USD", "exponent": 2},
                "percent": 64, "severity": "warning", "enabled": true
            }
        });
        let balances = claude_oauth_credit_balances(&json);
        assert_eq!(balances.len(), 1);
        let credit = &balances[0];
        assert_eq!(credit.name, "Usage credits");
        assert_eq!(credit.unit, AgentCreditBalanceUnit::Usd);
        assert_eq!(credit.status, AgentCreditBalanceStatus::Low);
        assert_eq!(credit.used, Some(321));
        assert_eq!(credit.quota, Some(500));
        assert_eq!(credit.remaining, Some(179));
        assert_eq!(credit.used_percent, Some(64));
        assert_eq!(credit.currency.as_deref(), Some("USD"));
        assert_eq!(credit.enabled, Some(true));
    }

    #[test]
    fn claude_oauth_spend_falls_back_to_limit_and_derives_remaining() {
        let json = serde_json::json!({
            "spend": {
                "used": {"amount_minor": 500, "currency": "USD", "exponent": 2},
                "limit": 5.0,
                "severity": "critical",
                "enabled": true
            }
        });
        let balances = claude_oauth_credit_balances(&json);
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].status, AgentCreditBalanceStatus::Exhausted);
        assert_eq!(balances[0].used, Some(500));
        assert_eq!(balances[0].quota, Some(500));
        assert_eq!(balances[0].remaining, Some(0));
    }

    #[test]
    fn claude_oauth_money_cents_normalizes_exponents_and_bare_numbers() {
        let object = serde_json::json!({"amount_minor": 3215, "exponent": 3});
        assert_eq!(claude_oauth_money_cents(Some(&object)), Some(322));
        let zero_exp = serde_json::json!({"amount_minor": 5, "exponent": 0});
        assert_eq!(claude_oauth_money_cents(Some(&zero_exp)), Some(500));
        let bare = serde_json::json!(5.0);
        assert_eq!(claude_oauth_money_cents(Some(&bare)), Some(500));
        let negative = serde_json::json!({"amount_minor": -1, "exponent": 2});
        assert_eq!(claude_oauth_money_cents(Some(&negative)), None);
        assert_eq!(claude_oauth_money_cents(None), None);
    }

    #[test]
    fn claude_oauth_extra_usage_fallback_maps_credit_balance() {
        let json = serde_json::json!({
            "extra_usage": {
                "is_enabled": true,
                "monthly_limit": 5.0,
                "used_credits": 3.21,
                "utilization": 64,
                "currency": "USD"
            }
        });
        let balances = claude_oauth_credit_balances(&json);
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].used, Some(321));
        assert_eq!(balances[0].quota, Some(500));
        assert_eq!(balances[0].remaining, Some(179));
        assert_eq!(balances[0].used_percent, Some(64));
    }

    #[test]
    fn claude_oauth_scoped_limits_map_model_windows_and_skip_account_kinds() {
        let json = serde_json::json!({
            "five_hour": {"utilization": 0.0, "resets_at": "2026-07-06T22:40:00+00:00"},
            "seven_day": {"utilization": 82.0, "resets_at": "2026-07-11T05:00:00+00:00"},
            "limits": [
                {"kind": "session", "group": "session", "percent": 0,
                 "severity": "normal", "resets_at": "2026-07-06T22:40:00+00:00",
                 "scope": null, "is_active": false},
                {"kind": "weekly_all", "group": "weekly", "percent": 82,
                 "severity": "warning", "resets_at": "2026-07-11T05:00:00+00:00",
                 "scope": null, "is_active": false},
                {"kind": "weekly_scoped", "group": "weekly", "percent": 98,
                 "severity": "critical", "resets_at": "2026-07-11T05:00:00+00:00",
                 "scope": {"model": {"id": null, "display_name": "Fable"}},
                 "is_active": true}
            ]
        });
        let windows = claude_oauth_quota_windows(&json);
        // session + weekly account windows, plus exactly one scoped model window
        assert_eq!(windows.len(), 3);
        let scoped = &windows[2];
        assert_eq!(scoped.name, "weekly_scoped");
        assert_eq!(scoped.scope, AgentQuotaWindowScope::Model);
        assert_eq!(scoped.model.as_deref(), Some("Fable"));
        assert_eq!(scoped.used_percent, Some(98));
        assert_eq!(scoped.group.as_deref(), Some("weekly"));
        assert_eq!(scoped.severity.as_deref(), Some("critical"));
        assert_eq!(scoped.is_active, Some(true));
    }

    #[test]
    fn claude_oauth_window_dollar_fields_map_to_cents() {
        let json = serde_json::json!({
            "five_hour": {
                "utilization": 24.0,
                "resets_at": "2026-06-29T18:10:00+00:00",
                "limit_dollars": 25.0,
                "used_dollars": 6.0,
                "remaining_dollars": 19.0
            }
        });
        let windows = claude_oauth_quota_windows(&json);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].limit_cents, Some(2500));
        assert_eq!(windows[0].used_cents, Some(600));
        assert_eq!(windows[0].remaining_cents, Some(1900));
    }

    /// The hash a Claude Desktop plan observation would carry for `account_uuid`
    /// -- the same `billing_identity_hash` shape
    /// `claude_desktop_builder_plan_observation` produces.
    fn observable_account_hashes(account_uuids: &[&str]) -> Vec<String> {
        account_uuids
            .iter()
            .filter_map(|uuid| billing_identity_hash("anthropic", "account", uuid))
            .collect()
    }

    #[test]
    fn claude_statusline_sample_is_attributed_only_to_the_account_that_owns_the_credential() {
        let account_a = claude_account_identifier_hash(Some("acct-a"), None, None);
        let account_b = claude_account_identifier_hash(Some("acct-b"), None, None);
        assert_ne!(account_a, account_b);

        // Same account, nothing else on the machine: provable, so serve it.
        assert_eq!(
            claude_statusline_attribution_failure(&account_a, "config_dir", &account_a, &[]),
            None
        );
        // A Desktop observation for the SAME account is not a second account.
        assert_eq!(
            claude_statusline_attribution_failure(
                &account_a,
                "config_dir",
                &account_a,
                &observable_account_hashes(&["acct-a"])
            ),
            None
        );

        // Written under a credential that has since been replaced.
        assert_eq!(
            claude_statusline_attribution_failure(&account_a, "config_dir", &account_b, &[]),
            Some(ClaudeStatusLineUnattributable::CredentialReplaced)
        );

        // An unnamed account on either side matches nothing. Unlike the OAuth
        // cache, two empty hashes must NOT match here: statusLine re-observes on
        // the next render, so refusing costs nothing.
        assert_eq!(
            claude_statusline_attribution_failure("", "unknown", &account_a, &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        );
        assert_eq!(
            claude_statusline_attribution_failure(&account_a, "unknown", "", &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        );
        assert_eq!(
            claude_statusline_attribution_failure("", "unknown", "", &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown)
        );
    }

    #[test]
    fn claude_statusline_sample_serves_when_resolved_via_session_store_despite_multiple_accounts() {
        // NEW BEHAVIOR: if the Desktop session store proved which account owns the session,
        // serve it even when other accounts are observable -- the store join is the proof.
        let team = claude_account_identifier_hash(Some("acct-team"), None, None);

        // session_store method: serve despite multiple accounts being observable
        assert_eq!(
            claude_statusline_attribution_failure(
                &team,
                "session_store",
                &team,
                &observable_account_hashes(&["acct-max"])
            ),
            None,
            "session_store resolution proves ownership even when another account is present"
        );
    }

    #[test]
    fn claude_statusline_sample_serves_config_dir_when_hash_matches_despite_multiple_accounts() {
        // NEW BEHAVIOR: CLI credential (config_dir method) serves if the hash matches,
        // even when other accounts are observable -- the credential holder owns their own sessions.
        let team = claude_account_identifier_hash(Some("acct-team"), None, None);
        let max = claude_account_identifier_hash(Some("acct-max"), None, None);

        // config_dir method with matching hash: serve despite multiple accounts
        assert_eq!(
            claude_statusline_attribution_failure(
                &team,
                "config_dir",
                &team,
                &observable_account_hashes(&["acct-max"])
            ),
            None,
            "config_dir resolution matches current credential and serves despite multiple accounts"
        );

        // config_dir method with non-matching hash: refuse as CredentialReplaced
        assert_eq!(
            claude_statusline_attribution_failure(
                &max,
                "config_dir",
                &team,
                &observable_account_hashes(&["acct-max"])
            ),
            Some(ClaudeStatusLineUnattributable::CredentialReplaced),
            "config_dir refuses when hash differs from current credential"
        );
    }

    #[test]
    fn claude_statusline_sample_refuses_ambiguous_resolution() {
        // NEW BEHAVIOR: ambiguous resolution (multiple Desktop store matches) always refuses
        let team = claude_account_identifier_hash(Some("acct-team"), None, None);

        assert_eq!(
            claude_statusline_attribution_failure(&team, "ambiguous", &team, &[]),
            Some(ClaudeStatusLineUnattributable::MultipleAccounts),
            "ambiguous resolution is unresolvable and must refuse"
        );
    }

    #[test]
    fn claude_statusline_sample_refuses_unknown_resolution() {
        // NEW BEHAVIOR: unknown resolution (no store match, no CLI entrypoint, etc) refuses
        let team = claude_account_identifier_hash(Some("acct-team"), None, None);

        assert_eq!(
            claude_statusline_attribution_failure(&team, "unknown", &team, &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown),
            "unknown resolution cannot be proven"
        );

        // Empty method (v2 cache missing method field) is treated as unknown
        assert_eq!(
            claude_statusline_attribution_failure(&team, "", &team, &[]),
            Some(ClaudeStatusLineUnattributable::AccountUnknown),
            "v2 cache with no method field is unresolved"
        );
    }

    #[test]
    #[serial]
    fn claude_statusline_quota_is_not_served_across_accounts() {
        let support_dir = std::env::temp_dir().join(format!(
            "ottto-claude-statusline-account-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&support_dir);
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        let _guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            support_dir.as_os_str().to_os_string(),
        );

        let account_a = claude_account_identifier_hash(Some("acct-a"), None, None);
        let account_b = claude_account_identifier_hash(Some("acct-b"), None, None);
        let now = current_unix_seconds();
        write_claude_statusline_cache(
            &support_dir,
            &ClaudeStatusLineRateLimitCache {
                schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
                observed_under_account_identifier_hash: account_a.clone(),
                observed_under_account_method: "config_dir".to_string(),
                observed_at_epoch_seconds: now,
                windows: vec![ClaudeStatusLineRateLimitWindow {
                    name: "seven_day".to_string(),
                    used_percent: 44,
                    resets_at_epoch_seconds: now + 7 * 24 * 60 * 60,
                }],
            },
        )
        .expect("write cache");

        // Its own account, alone on the machine: served.
        match collect_claude_statusline_quota_windows(&account_a, &[]).expect("collect") {
            ClaudeStatusLineQuota::Windows(windows) => {
                assert_eq!(windows.len(), 1);
                assert_eq!(windows[0].used_percent, Some(44));
            }
            other => panic!("own account was not served: {other:?}"),
        }

        // The replacing account must not be shown account A's 44%.
        assert_eq!(
            collect_claude_statusline_quota_windows(&account_b, &[]).expect("collect"),
            ClaudeStatusLineQuota::Unattributable(
                ClaudeStatusLineUnattributable::CredentialReplaced
            )
        );

        // With the new resolution method system, config_dir method serves the cache
        // even when another account is observable, because the method proves it was
        // resolved from the CLI credential holder. The store join is what breaks the
        // old "any second account makes everything ambiguous" logic.
        match collect_claude_statusline_quota_windows(
            &account_a,
            &observable_account_hashes(&["acct-max"])
        )
        .expect("collect") {
            ClaudeStatusLineQuota::Windows(windows) => {
                assert_eq!(windows.len(), 1);
                assert_eq!(windows[0].used_percent, Some(44));
            }
            other => panic!(
                "config_dir method should serve despite multiple accounts when hash matches: {other:?}"
            ),
        }

        // A pre-fix (v1) cache carries no account identity and is discarded
        // outright rather than adopted by whoever is signed in now.
        std::fs::write(
            support_dir.join("claude-code-rate-limits.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1,
                "observed_at_epoch_seconds": now,
                "windows": [{
                    "name": "seven_day",
                    "used_percent": 44,
                    "resets_at_epoch_seconds": now + 7 * 24 * 60 * 60
                }]
            }))
            .expect("serialize v1"),
        )
        .expect("write v1 cache");
        assert_eq!(
            collect_claude_statusline_quota_windows(&account_a, &[]).expect("collect"),
            ClaudeStatusLineQuota::NotObserved
        );

        let _ = std::fs::remove_dir_all(&support_dir);
    }

    #[test]
    fn claude_statusline_cache_maps_fresh_windows() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_under_account_method: "config_dir".to_string(),
            observed_at_epoch_seconds: 100,
            windows: vec![
                ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 24,
                    resets_at_epoch_seconds: 200,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "seven_day".to_string(),
                    used_percent: 91,
                    resets_at_epoch_seconds: 300,
                },
            ],
        };

        let windows = claude_statusline_quota_windows_from_cache(cache, 150);

        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].scope, AgentQuotaWindowScope::Account);
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Ok);
        assert_eq!(windows[0].used_percent, Some(24));
        assert_eq!(windows[0].left_percent, Some(76));
        assert_eq!(windows[0].window_seconds, Some(5 * 60 * 60));
        assert_eq!(
            windows[0].observed_at.as_deref(),
            Some("1970-01-01T00:01:40Z")
        );
        assert_eq!(windows[1].name, "weekly");
        assert_eq!(windows[1].status, AgentQuotaWindowStatus::NearLimit);
        assert_eq!(windows[1].window_seconds, Some(7 * 24 * 60 * 60));
        // Every served statusLine window names the account whose credential
        // was active when the CLI writer observed it.
        assert_eq!(
            windows[0].account_identifier_hash.as_deref(),
            Some("account-a")
        );
        assert_eq!(
            windows[1].account_identifier_hash.as_deref(),
            Some("account-a")
        );
    }

    #[test]
    fn claude_statusline_windows_from_unidentified_writer_stay_unstamped() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: String::new(),
            observed_under_account_method: "config_dir".to_string(),
            observed_at_epoch_seconds: 100,
            windows: vec![ClaudeStatusLineRateLimitWindow {
                name: "five_hour".to_string(),
                used_percent: 24,
                resets_at_epoch_seconds: 200,
            }],
        };

        let windows = claude_statusline_quota_windows_from_cache(cache, 150);

        assert_eq!(windows.len(), 1);
        assert_eq!(
            windows[0].account_identifier_hash, None,
            "an unidentifiable writer must serve as unknown, never as a guessed account"
        );
    }

    #[test]
    fn claude_oauth_usage_stamps_served_windows_and_balances() {
        let mut usage = ClaudeOAuthUsage {
            windows: vec![
                AgentQuotaWindow {
                    name: "session".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    ..Default::default()
                },
                AgentQuotaWindow {
                    name: "weekly".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    ..Default::default()
                },
            ],
            credit_balances: vec![AgentCreditBalance {
                name: "Usage credits".to_string(),
                ..Default::default()
            }],
        };

        claude_oauth_stamp_account_identity(&mut usage, "account-hash", Some("org-hash"));

        for window in &usage.windows {
            assert_eq!(
                window.account_identifier_hash.as_deref(),
                Some("account-hash")
            );
            assert_eq!(
                window.organization_identifier_hash.as_deref(),
                Some("org-hash")
            );
        }
        assert_eq!(
            usage.credit_balances[0].account_identifier_hash.as_deref(),
            Some("account-hash")
        );
        assert_eq!(
            usage.credit_balances[0]
                .organization_identifier_hash
                .as_deref(),
            Some("org-hash")
        );

        // Negative control: an unresolved account stamps nothing -- unknown
        // must stay unknown downstream, never become a guessed identity.
        let mut unresolved = ClaudeOAuthUsage {
            windows: vec![AgentQuotaWindow {
                name: "session".to_string(),
                ..Default::default()
            }],
            credit_balances: Vec::new(),
        };
        claude_oauth_stamp_account_identity(&mut unresolved, "", Some(""));
        assert_eq!(unresolved.windows[0].account_identifier_hash, None);
        assert_eq!(unresolved.windows[0].organization_identifier_hash, None);
    }

    #[test]
    fn claude_exact_slot_auth_requires_positive_real_cli_field_agreement() {
        let oauth = ClaudeCliOauthAccount {
            account_uuid: Some("account-a".to_string()),
            email_address: Some("person@example.invalid".to_string()),
            organization_uuid: Some("organization-a".to_string()),
            ..Default::default()
        };
        let auth = AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            email: Some("person@example.invalid".to_string()),
            organization_id: Some("organization-a".to_string()),
            account_id: None,
            ..unsupported_account("anthropic")
        };
        assert_eq!(
            require_claude_auth_identity_agreement(&auth, &oauth),
            Ok(())
        );

        let missing_email = AgentAccountStatus {
            email: None,
            ..auth.clone()
        };
        assert_eq!(
            require_claude_auth_identity_agreement(&missing_email, &oauth),
            Err(ClaudeSlotProbeFailure::IdentityUnknown)
        );
        let missing_organization = AgentAccountStatus {
            organization_id: None,
            ..auth.clone()
        };
        assert_eq!(
            require_claude_auth_identity_agreement(&missing_organization, &oauth),
            Err(ClaudeSlotProbeFailure::IdentityUnknown)
        );
        let rotated_credential = AgentAccountStatus {
            email: Some("rotated@example.invalid".to_string()),
            organization_id: Some("organization-rotated".to_string()),
            ..auth
        };
        assert_eq!(
            require_claude_auth_identity_agreement(&rotated_credential, &oauth),
            Err(ClaudeSlotProbeFailure::IdentityMismatch)
        );
    }

    #[test]
    fn claude_stale_same_account_fallback_is_uploadable_but_not_fresh() {
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-04T12:00:00Z".to_string(),
            "2026-08-04T12:15:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            ..unsupported_account("anthropic")
        });
        snapshot.quota_windows = vec![AgentQuotaWindow {
            name: "session".to_string(),
            freshness: AgentQuotaWindowFreshness::Stale,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            ..Default::default()
        }];
        snapshot.credit_balances = vec![AgentCreditBalance {
            name: "Usage credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Stale,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            ..Default::default()
        }];

        assert!(claude_default_snapshot_is_uploadable(&snapshot));
        assert_eq!(
            claude_snapshot_candidate_rank(&snapshot).map(|quality| quality.tier),
            Some(1)
        );
        assert_eq!(
            claude_default_slot_collection_status(&snapshot).state,
            ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        );
        assert!(
            !claude_slot_status_carries_meters(&claude_default_slot_collection_status(&snapshot)),
            "an exact stale bundle is replaced by a meterless degraded current witness"
        );

        snapshot.quota_windows.push(AgentQuotaWindow {
            name: "weekly".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: None,
            ..Default::default()
        });
        assert!(
            !claude_default_snapshot_is_uploadable(&snapshot),
            "partial identity must not create a backend row"
        );
        assert_eq!(
            claude_default_slot_collection_status(&snapshot).state,
            ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
        );

        snapshot.collection_method = AgentStatusCollectionMethod::StatusLine;
        snapshot.quota_windows.truncate(1);
        snapshot.quota_windows[0].organization_identifier_hash = None;
        snapshot.credit_balances.clear();
        assert!(
            claude_default_snapshot_is_uploadable(&snapshot),
            "an attributed default statusLine partial remains uploadable"
        );
        assert_eq!(
            claude_snapshot_candidate_rank(&snapshot).map(|quality| quality.tier),
            Some(1),
            "stale statusLine meters are the stale-partial tier"
        );
        let partial = claude_default_slot_collection_status(&snapshot);
        assert_eq!(partial.state, ClaudeConfigSlotCollectionStateV1::Fresh);
        assert_eq!(
            projected_claude_quota_access_state(&partial),
            Some(ClaudeQuotaAccessState::Partial),
            "strongly bound statusLine meters remain an honest partial view"
        );
        assert!(claude_slot_status_carries_meters(&partial));
    }

    #[test]
    fn claude_candidate_rank_prefers_fresh_full_over_stale_full() {
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-04T12:00:00Z".to_string(),
            "2026-08-04T12:15:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            account_identifier_hash: Some("account-a".to_string()),
            organization_identifier_hash: Some("organization-a".to_string()),
            ..unsupported_account("anthropic")
        });
        snapshot.quota_windows = vec![AgentQuotaWindow {
            name: "session".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            account_identifier_hash: Some("account-a".to_string()),
            organization_identifier_hash: Some("organization-a".to_string()),
            ..Default::default()
        }];
        assert_eq!(
            claude_snapshot_candidate_rank(&snapshot).map(|quality| quality.tier),
            Some(3)
        );
        snapshot.quota_windows[0].freshness = AgentQuotaWindowFreshness::Stale;
        assert_eq!(
            claude_snapshot_candidate_rank(&snapshot).map(|quality| quality.tier),
            Some(1)
        );
    }

    #[test]
    fn claude_candidate_selection_prefers_anchor_only_on_equal_quality() {
        let candidate = |slot_id: &str, slot_class: ClaudeSnapshotSlotClass, rank: u8| {
            ClaudeSnapshotCandidate {
                slot_id: slot_id.to_string(),
                slot_class,
                binding: ClaudeStrongBinding {
                    account_identifier_hash: "account-a".to_string(),
                    organization_identifier_hash: "organization-a".to_string(),
                },
                quality: ClaudeSnapshotQuality {
                    tier: rank,
                    provider_observed_at: "2026-08-23T00:00:00Z".to_string(),
                },
                snapshot: base_snapshot(
                    SourceKind::ClaudeCode,
                    AgentStatusState::Available,
                    AgentStatusCollectionMethod::CliJson,
                    "2026-08-23T00:00:00Z".to_string(),
                    "2026-08-23T00:05:00Z".to_string(),
                ),
            }
        };

        let equal = vec![
            candidate("default", ClaudeSnapshotSlotClass::Default, 3),
            candidate(
                "claude_slot_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ClaudeSnapshotSlotClass::Registered,
                3,
            ),
            candidate(
                "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ClaudeSnapshotSlotClass::Registered,
                3,
            ),
        ];
        let selected = select_claude_snapshot_candidates(&equal);
        let binding = ClaudeStrongBinding {
            account_identifier_hash: "account-a".to_string(),
            organization_identifier_hash: "organization-a".to_string(),
        };
        assert_eq!(selected.winning_by_binding[&binding], 2);
        assert_eq!(selected.preferred_anchor_by_binding[&binding], 2);
        assert_eq!(
            claude_snapshot_candidate_disposition(0, &equal[0], &selected),
            ClaudeSnapshotDisposition::ShadowDefault
        );
        assert_eq!(
            claude_snapshot_candidate_disposition(1, &equal[1], &selected),
            ClaudeSnapshotDisposition::DuplicateRegistered
        );
        assert_eq!(
            claude_snapshot_candidate_disposition(2, &equal[2], &selected),
            ClaudeSnapshotDisposition::Upload
        );

        let fresher_default = vec![
            candidate("default", ClaudeSnapshotSlotClass::Default, 3),
            candidate(
                "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ClaudeSnapshotSlotClass::Registered,
                2,
            ),
            candidate(
                "claude_slot_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ClaudeSnapshotSlotClass::Registered,
                2,
            ),
        ];
        let selected = select_claude_snapshot_candidates(&fresher_default);
        assert_eq!(selected.winning_by_binding[&binding], 0);
        assert_eq!(
            selected.preferred_anchor_by_binding[&binding], 1,
            "the preferred registered anchor remains stable while fresher default meters win"
        );
        assert_eq!(
            claude_snapshot_candidate_disposition(1, &fresher_default[1], &selected),
            ClaudeSnapshotDisposition::PreserveRegisteredAnchor
        );
        assert_eq!(
            claude_snapshot_candidate_disposition(2, &fresher_default[2], &selected),
            ClaudeSnapshotDisposition::DuplicateRegistered
        );

        let shadow = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            relationship: Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor),
            ..Default::default()
        };
        assert_eq!(
            shadow.relationship,
            Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor)
        );
        assert!(!shadow.has_account_windows);
        assert!(shadow.quota_snapshot.is_none());
        let duplicate =
            duplicate_account_status("2026-08-23T00:00:00Z", "account-a", Some("organization-a"));
        assert_eq!(
            duplicate.state,
            ClaudeConfigSlotCollectionStateV1::DuplicateAccount
        );
    }

    #[test]
    fn claude_candidate_selection_keeps_same_account_under_two_organizations() {
        let candidate = |slot_id: &str, organization: &str| ClaudeSnapshotCandidate {
            slot_id: slot_id.to_string(),
            slot_class: ClaudeSnapshotSlotClass::Registered,
            binding: ClaudeStrongBinding {
                account_identifier_hash: "shared-account".to_string(),
                organization_identifier_hash: organization.to_string(),
            },
            quality: ClaudeSnapshotQuality {
                tier: 4,
                provider_observed_at: "2026-08-23T00:00:00Z".to_string(),
            },
            snapshot: base_snapshot(
                SourceKind::ClaudeCode,
                AgentStatusState::Available,
                AgentStatusCollectionMethod::CliJson,
                "2026-08-23T00:00:00Z".to_string(),
                "2026-08-23T00:05:00Z".to_string(),
            ),
        };
        let candidates = vec![
            candidate(
                "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "organization-a",
            ),
            candidate(
                "claude_slot_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "organization-b",
            ),
        ];
        let selected = select_claude_snapshot_candidates(&candidates);
        assert_eq!(selected.winning_by_binding.len(), 2);
        assert_eq!(selected.preferred_anchor_by_binding.len(), 2);
    }

    #[test]
    fn fresh_default_meters_do_not_hide_broken_registered_anchor_health() {
        let binding = ClaudeStrongBinding {
            account_identifier_hash: "account-a".to_string(),
            organization_identifier_hash: "organization-a".to_string(),
        };
        let slot_id = "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let slot_states = BTreeMap::from([(
            slot_id.clone(),
            ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::NeedsLogin,
                account_identifier_hash: Some(binding.account_identifier_hash.clone()),
                organization_identifier_hash: Some(binding.organization_identifier_hash.clone()),
                observed_at: Some("2026-08-23T00:00:00Z".to_string()),
                ..Default::default()
            },
        )]);
        let canonical = canonical_registered_anchors([slot_id], &slot_states);
        let health = canonical_anchor_health(&canonical, &slot_states);
        assert_eq!(
            health.get(&binding),
            Some(&Some(ClaudeAccountAnchorHealthV1::ReconnectRequired))
        );
        let mut default_snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-23T00:01:00Z".to_string(),
            "2026-08-23T00:06:00Z".to_string(),
        );
        default_snapshot.account = Some(AgentAccountStatus {
            account_identifier_hash: Some(binding.account_identifier_hash),
            organization_identifier_hash: Some(binding.organization_identifier_hash),
            ..unsupported_account("anthropic")
        });
        apply_claude_anchor_continuity(
            &mut default_snapshot,
            ClaudeAccountAnchorDurabilityV1::Anchored,
            *health.values().next().expect("anchor health"),
        );
        assert_eq!(
            default_snapshot
                .account
                .as_ref()
                .and_then(|account| account.claude_anchor_durability),
            Some(ClaudeAccountAnchorDurabilityV1::Anchored)
        );
        assert_eq!(
            default_snapshot
                .account
                .as_ref()
                .and_then(|account| account.claude_anchor_health),
            Some(ClaudeAccountAnchorHealthV1::ReconnectRequired)
        );
    }

    #[test]
    fn claude_anchor_projection_supports_five_accounts_and_default_switching() {
        let collection = |account: &str, organization: &str| ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some(account.to_string()),
            organization_identifier_hash: Some(organization.to_string()),
            observed_at: Some("2026-08-23T00:00:00Z".to_string()),
            last_full_quota_read_at: Some("2026-08-23T00:00:00Z".to_string()),
            has_account_windows: true,
            has_scoped_limits: true,
            ..Default::default()
        };
        let mut managed_slots = (0..5)
            .map(|index| {
                let mut slot = test_slot_descriptor(index);
                slot.ownership = ClaudeConfigSlotOwnership::Managed;
                slot.collection = collection(
                    &format!("account-{index}"),
                    &format!("organization-{index}"),
                );
                slot
            })
            .collect::<Vec<_>>();
        managed_slots.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
        let mut status = ClaudeAccountsStatusV1 {
            schema_version: 1,
            consent: ottto_protocol::ClaudeAccountUpkeepConsentState::Granted,
            setup_operation: ottto_protocol::ClaudeAccountSetupOperationV1 {
                kind: ottto_protocol::ClaudeAccountSetupOperationKind::ConnectManagedAccount,
                state: ottto_protocol::ClaudeAccountSetupOperationState::Idle,
                operation_id: None,
                slot_id: None,
                target_id: None,
                expected_account_identifier_hash: None,
                expected_organization_identifier_hash: None,
                account_identifier_hash: None,
                organization_identifier_hash: None,
                launch_command: None,
                browser_auth: None,
                message: None,
            },
            default_slot: ClaudeConfigDirSlot::Default
                .descriptor("default", ClaudeConfigSlotOwnership::External),
            managed_slots,
            external_slots: Vec::new(),
            unresolved_accounts: Vec::new(),
            anchor_coverage: ClaudeAccountAnchorCoverageV1::default(),
            anchor_transitions: Vec::new(),
            capacity: ottto_protocol::ClaudeAccountCapacityV1 {
                max_slots: 10,
                used_slots: 6,
                remaining_slots: 4,
            },
            browser_auth_supported: None,
            retained_provisional_login_count: None,
        };

        for switched_to in [0, 1, 4, 2, 0] {
            status.default_slot.collection = collection(
                &format!("account-{switched_to}"),
                &format!("organization-{switched_to}"),
            );
            let coverage = derive_claude_account_anchor_coverage(&status);
            assert_eq!(coverage.observed_accounts, 5);
            assert_eq!(coverage.anchored_accounts, 5);
            assert_eq!(coverage.default_only_accounts, 0);
            assert_eq!(coverage.unresolved_accounts, 0);
            assert_eq!(coverage.capacity_blocked_accounts, 0);
            assert!(coverage
                .accounts
                .iter()
                .all(|account| account.durability == ClaudeAccountAnchorDurabilityV1::Anchored));
        }

        status.default_slot.collection = collection("account-5", "organization-5");
        let coverage = derive_claude_account_anchor_coverage(&status);
        assert_eq!(coverage.observed_accounts, 6);
        assert_eq!(coverage.anchored_accounts, 5);
        assert_eq!(coverage.default_only_accounts, 1);
        assert_eq!(
            coverage
                .accounts
                .iter()
                .find(|account| account.account_identifier_hash == "account-5")
                .map(|account| account.durability),
            Some(ClaudeAccountAnchorDurabilityV1::DefaultOnly)
        );

        status.capacity.remaining_slots = 0;
        let coverage = derive_claude_account_anchor_coverage(&status);
        assert_eq!(coverage.default_only_accounts, 1);
        assert_eq!(coverage.capacity_blocked_accounts, 1);
    }

    #[test]
    fn claude_anchor_transition_ledger_is_bounded_and_secret_free() {
        let previous = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some("account-secret-a".to_string()),
            organization_identifier_hash: Some("organization-secret-a".to_string()),
            observed_at: Some("2026-08-23T00:00:00Z".to_string()),
            ..Default::default()
        };
        let current = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some("account-secret-b".to_string()),
            organization_identifier_hash: Some("organization-secret-b".to_string()),
            relationship: Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor),
            observed_at: Some("2026-08-23T00:01:00Z".to_string()),
            ..Default::default()
        };
        let mut transitions = Vec::new();
        record_claude_anchor_transitions(&mut transitions, "default", Some(&previous), &current);
        assert!(transitions.iter().any(|transition| {
            transition.kind
                == ottto_protocol::ClaudeAccountAnchorTransitionKindV1::DefaultIdentityChanged
        }));
        assert!(transitions.iter().any(|transition| {
            transition.kind
                == ottto_protocol::ClaudeAccountAnchorTransitionKindV1::DefaultShadowObserved
        }));
        let wire = serde_json::to_string(&transitions).expect("serialize transitions");
        for forbidden in [
            "account-secret",
            "organization-secret",
            "config_dir",
            "access_token",
            "refresh_token",
        ] {
            assert!(!wire.contains(forbidden), "ledger leaked {forbidden}");
        }

        let bound = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::Fresh,
            account_identifier_hash: Some("same-account".to_string()),
            organization_identifier_hash: Some("same-organization".to_string()),
            ..Default::default()
        };
        for second in 0..80 {
            let mut observed = bound.clone();
            observed.observed_at = Some(format!("2026-08-23T00:{:02}:00Z", second % 60));
            record_claude_anchor_transitions(
                &mut transitions,
                "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                Some(&bound),
                &observed,
            );
        }
        assert_eq!(transitions.len(), 64);
    }

    #[test]
    fn claude_statusline_cache_skips_expired_and_unknown_windows() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_under_account_method: "config_dir".to_string(),
            observed_at_epoch_seconds: 100,
            windows: vec![
                ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 100,
                    resets_at_epoch_seconds: 150,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "monthly".to_string(),
                    used_percent: 10,
                    resets_at_epoch_seconds: 300,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "seven_day".to_string(),
                    used_percent: 100,
                    resets_at_epoch_seconds: 300,
                },
            ],
        };

        let windows = claude_statusline_quota_windows_from_cache(cache, 150);

        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, "weekly");
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Exhausted);
        assert_eq!(windows[0].left_percent, Some(0));
    }

    #[test]
    fn claude_statusline_cache_marks_old_windows_stale() {
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_under_account_method: "config_dir".to_string(),
            observed_at_epoch_seconds: 100,
            windows: vec![ClaudeStatusLineRateLimitWindow {
                name: "five_hour".to_string(),
                used_percent: 24,
                resets_at_epoch_seconds: 2_000,
            }],
        };

        let windows = claude_statusline_quota_windows_from_cache(
            cache,
            100 + CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS + 1,
        );

        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, "session");
        assert_eq!(windows[0].status, AgentQuotaWindowStatus::Stale);
        assert_eq!(windows[0].freshness, AgentQuotaWindowFreshness::Stale);
        assert_eq!(windows[0].used_percent, Some(24));
        assert_eq!(windows[0].left_percent, Some(76));
    }

    #[test]
    fn claude_statusline_context_never_downgrades_full_oauth_quota_provenance() {
        let mut full = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-05T01:00:00Z".to_string(),
            "2026-08-05T01:15:00Z".to_string(),
        );
        apply_claude_statusline_context_provenance(&mut full, true);
        assert_eq!(full.collection_method, AgentStatusCollectionMethod::CliJson);

        let mut partial = full;
        apply_claude_statusline_context_provenance(&mut partial, false);
        assert_eq!(
            partial.collection_method,
            AgentStatusCollectionMethod::StatusLine
        );
    }

    #[test]
    fn claude_statusline_context_cache_maps_live_context() {
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: 100,
            active_tokens: Some(42_000),
            max_tokens: Some(1_000_000),
            used_percent: Some(4),
            remaining_tokens: Some(958_000),
        };

        let context = claude_statusline_context_from_cache(cache, None);

        assert_eq!(context.status, AgentContextState::Available);
        assert_eq!(context.active_tokens, Some(42_000));
        assert_eq!(context.max_tokens, Some(1_000_000));
        assert_eq!(context.used_percent, Some(4));
        assert_eq!(context.remaining_tokens, Some(958_000));
        assert_eq!(
            context.completeness,
            Some(AgentContextCompleteness::FullPressure)
        );
        assert_eq!(context.reason.as_deref(), Some("full_pressure_observed"));
        assert_eq!(
            context.source.as_deref(),
            Some("claude_statusline_context_window")
        );
    }

    #[test]
    fn claude_statusline_context_cache_maps_window_size_only() {
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: 100,
            active_tokens: None,
            max_tokens: Some(1_000_000),
            used_percent: None,
            remaining_tokens: None,
        };

        let context = claude_statusline_context_from_cache(cache, None);

        assert_eq!(context.status, AgentContextState::Available);
        assert_eq!(context.active_tokens, None);
        assert_eq!(context.max_tokens, Some(1_000_000));
        assert_eq!(context.used_percent, None);
        assert_eq!(context.remaining_tokens, None);
        assert_eq!(
            context.completeness,
            Some(AgentContextCompleteness::WindowSizeOnly)
        );
        assert_eq!(context.reason.as_deref(), Some("context_window_size_only"));
        assert!(context.recent_samples.is_empty());
    }

    #[test]
    fn claude_statusline_context_cache_normalizes_legacy_zero_sentinel() {
        let now = current_unix_seconds();
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: now,
            active_tokens: Some(0),
            max_tokens: Some(1_000_000),
            used_percent: None,
            remaining_tokens: Some(1_000_000),
        };
        let history = ClaudeStatusLineContextWindowHistory {
            schema_version: 1,
            samples: vec![ClaudeStatusLineContextWindowSample {
                observed_at_epoch_seconds: now.saturating_sub(60),
                active_tokens: Some(0),
                max_tokens: Some(1_000_000),
                used_percent: None,
                remaining_tokens: Some(1_000_000),
            }],
        };

        let context = claude_statusline_context_from_cache(cache, Some(history));

        assert_eq!(context.status, AgentContextState::Available);
        assert_eq!(context.active_tokens, None);
        assert_eq!(context.max_tokens, Some(1_000_000));
        assert_eq!(context.used_percent, None);
        assert_eq!(context.remaining_tokens, None);
        assert_eq!(
            context.completeness,
            Some(AgentContextCompleteness::WindowSizeOnly)
        );
        assert_eq!(context.reason.as_deref(), Some("context_window_size_only"));
        assert!(context.recent_samples.is_empty());
    }

    #[test]
    fn claude_statusline_context_cache_maps_recent_history_samples() {
        let now = current_unix_seconds();
        let cache = ClaudeStatusLineContextWindowCache {
            schema_version: 1,
            observed_at_epoch_seconds: now,
            active_tokens: Some(45_000),
            max_tokens: Some(1_000_000),
            used_percent: Some(5),
            remaining_tokens: Some(955_000),
        };
        let history = ClaudeStatusLineContextWindowHistory {
            schema_version: 1,
            samples: vec![
                ClaudeStatusLineContextWindowSample {
                    observed_at_epoch_seconds: now.saturating_sub(120),
                    active_tokens: Some(40_000),
                    max_tokens: Some(1_000_000),
                    used_percent: Some(4),
                    remaining_tokens: Some(960_000),
                },
                ClaudeStatusLineContextWindowSample {
                    observed_at_epoch_seconds: now.saturating_sub(60),
                    active_tokens: Some(42_000),
                    max_tokens: Some(1_000_000),
                    used_percent: Some(4),
                    remaining_tokens: Some(958_000),
                },
            ],
        };

        let context = claude_statusline_context_from_cache(cache, Some(history));

        assert_eq!(context.recent_samples.len(), 3);
        assert_eq!(context.recent_samples[0].active_tokens, Some(40_000));
        assert_eq!(context.recent_samples[1].active_tokens, Some(42_000));
        assert_eq!(context.recent_samples[2].active_tokens, Some(45_000));
    }

    #[test]
    fn secret_keys_are_removed_from_pi_metadata() {
        let stripped = strip_secret_json(serde_json::json!({
            "email": "pi@example.com",
            "api_key": "secret",
            "nested": {"refresh_token": "secret", "org": "team"}
        }));

        assert_eq!(
            first_json_string(&stripped, &["email"]).as_deref(),
            Some("pi@example.com")
        );
        assert!(first_json_string(&stripped, &["api_key", "refresh_token"]).is_none());
        assert_eq!(
            first_json_string(&stripped, &["org"]).as_deref(),
            Some("team")
        );
    }

    #[test]
    fn pi_model_table_parser_preserves_provider_billing_and_capabilities() {
        let output = CommandOutput {
            command_found: true,
            success: true,
            status_code: Some(0),
            stdout: String::new(),
            stderr: "\
provider        model                                  context  max-out  thinking  images
openai-codex    gpt-5.4-mini                           272K     128K     yes       yes
google-vertex   gemini-2.5-flash-lite                  1.0M     65.5K    yes       yes
amazon-bedrock  global.anthropic.claude-sonnet-4-6     1M       64K      yes       yes
"
            .to_string(),
        };

        let model_status = collect_pi_model_status_from_output(&output, None);

        assert_eq!(model_status.provider.as_deref(), Some("multi_provider"));
        assert_eq!(model_status.available_models.len(), 3);
        assert_eq!(model_status.available_model_details.len(), 3);
        assert_eq!(
            model_status.available_model_details[0]
                .billing_provider
                .as_deref(),
            Some("openai")
        );
        assert_eq!(
            model_status.available_model_details[1]
                .billing_provider
                .as_deref(),
            Some("google")
        );
        assert_eq!(
            model_status.available_model_details[2]
                .billing_provider
                .as_deref(),
            Some("anthropic")
        );
        assert_eq!(
            model_status.available_model_details[0]
                .source_category
                .as_deref(),
            Some("chatgpt_openai_subscription")
        );
        assert_eq!(
            model_status.available_model_details[1]
                .source_category
                .as_deref(),
            Some("google_cloud_vertex")
        );
        assert_eq!(
            model_status.available_model_details[2]
                .model_provider
                .as_deref(),
            Some("anthropic")
        );
        assert_eq!(
            model_status.available_model_details[0].context_window_tokens,
            Some(272_000)
        );
        assert_eq!(
            model_status.available_model_details[1].max_output_tokens,
            Some(65_500)
        );
        assert_eq!(
            model_status.available_model_details[2]
                .billing_channel
                .as_deref(),
            Some("amazon_bedrock")
        );
        assert_eq!(
            model_status.available_model_details[2].supports_images,
            Some(true)
        );
    }

    #[test]
    fn pi_settings_parser_prefers_enabled_default_route() {
        let settings = serde_json::json!({
            "defaultProvider": "openai-codex",
            "defaultModel": "gpt-5.4-mini",
            "defaultThinkingLevel": "high",
            "enabledModels": [
                {"provider": "openai-codex", "model": "gpt-5.4-mini"},
                {"provider": "google-vertex", "model": "gemini-2.5-flash-lite"},
                "amazon-bedrock/global.anthropic.claude-sonnet-4-6"
            ]
        });

        let model_status = collect_pi_model_status_from_settings(&settings, None);

        assert_eq!(model_status.active_model.as_deref(), Some("gpt-5.4-mini"));
        assert_eq!(model_status.default_model.as_deref(), Some("gpt-5.4-mini"));
        assert_eq!(model_status.provider.as_deref(), Some("multi_provider"));
        assert_eq!(model_status.available_model_details.len(), 3);
        assert_eq!(
            model_status.available_model_details[0].provider.as_deref(),
            Some("openai-codex")
        );
        assert_eq!(
            model_status.available_model_details[0].supports_thinking,
            Some(true)
        );
        assert_eq!(
            model_status.available_model_details[2]
                .billing_channel
                .as_deref(),
            Some("amazon_bedrock")
        );

        let routes = collect_pi_routes_from_settings(&settings);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].provider, "openai-codex");
        assert_eq!(routes[0].thinking_level.as_deref(), Some("high"));
        assert_eq!(
            routes[1].classification.source_category.as_deref(),
            Some("google_cloud_vertex")
        );
    }

    #[test]
    fn pi_smoke_route_prefers_default_model_only() {
        let settings = serde_json::json!({
            "defaultProvider": "google-vertex",
            "defaultModel": "gemini-3.1-pro-preview-customtools",
            "defaultThinkingLevel": "high",
            "enabledModels": [
                "google-vertex/gemini-3.1-pro-preview-customtools:xhigh",
                "google-vertex/gemini-3.1-pro-preview:xhigh",
                "google-vertex/gemini-2.5-pro:xhigh"
            ]
        });

        let route = collect_default_pi_smoke_route_from_settings(&settings)
            .expect("default Pi smoke route");

        assert_eq!(route.provider, "google-vertex");
        assert_eq!(route.model, "gemini-3.1-pro-preview-customtools");
        assert_eq!(route.thinking_level.as_deref(), Some("high"));
    }

    #[test]
    fn pi_settings_parser_splits_string_route_thinking_suffix() {
        let settings = serde_json::json!({
            "defaultProvider": "google-vertex",
            "defaultModel": "gemini-3.1-pro-preview-customtools",
            "defaultThinkingLevel": "high",
            "enabledModels": [
                "OpenAI Codex/gpt-5.5:xhigh",
                "Google Vertex/gemini-3.1-pro-preview:xhigh"
            ]
        });

        let routes = collect_pi_routes_from_settings(&settings);

        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].provider, "OpenAI Codex");
        assert_eq!(routes[0].model, "gpt-5.5");
        assert_eq!(routes[0].thinking_level.as_deref(), Some("xhigh"));
        assert_eq!(
            routes[0].classification.source_category.as_deref(),
            Some("chatgpt_openai_subscription")
        );
        assert_eq!(routes[1].provider, "Google Vertex");
        assert_eq!(routes[1].model, "gemini-3.1-pro-preview");
        assert_eq!(routes[1].thinking_level.as_deref(), Some("xhigh"));
        assert_eq!(
            routes[1].classification.source_category.as_deref(),
            Some("google_cloud_vertex")
        );
        assert_eq!(routes[2].provider, "google-vertex");
        assert_eq!(routes[2].model, "gemini-3.1-pro-preview-customtools");

        let model_status = collect_pi_model_status_from_settings(&settings, None);
        assert_eq!(model_status.available_model_details[0].id, "gpt-5.5");
        assert_eq!(
            model_status.available_model_details[0].provider.as_deref(),
            Some("OpenAI Codex")
        );
        assert_eq!(
            model_status.available_model_details[0]
                .billing_channel
                .as_deref(),
            Some("subscription")
        );
        assert_eq!(
            model_status.available_model_details[1]
                .billing_channel
                .as_deref(),
            Some("google_vertex")
        );
    }

    #[test]
    fn pi_route_classifier_maps_supported_platforms() {
        let openai = pi_route_classification("openai", "gpt-5.4-mini");
        assert_eq!(openai.source_category.as_deref(), Some("openai_api_key"));
        assert_eq!(openai.auth_mode.as_deref(), Some("api_key"));

        let codex_subscription = pi_route_classification("OpenAI Codex", "gpt-5.5");
        assert_eq!(
            codex_subscription.billing_channel.as_deref(),
            Some("subscription")
        );
        assert_eq!(codex_subscription.auth_mode.as_deref(), Some("oauth"));
        assert_eq!(
            codex_subscription.source_category.as_deref(),
            Some("chatgpt_openai_subscription")
        );

        let vertex = pi_route_classification("google-vertex", "gemini-2.5-flash-lite");
        assert_eq!(vertex.billing_channel.as_deref(), Some("google_vertex"));
        assert_eq!(
            vertex.source_category.as_deref(),
            Some("google_cloud_vertex")
        );

        let display_vertex = pi_route_classification("Google Vertex", "gemini-3.1-pro-preview");
        assert_eq!(
            display_vertex.billing_channel.as_deref(),
            Some("google_vertex")
        );
        assert_eq!(display_vertex.auth_mode.as_deref(), Some("service_account"));
        assert_eq!(
            display_vertex.source_category.as_deref(),
            Some("google_cloud_vertex")
        );

        let bedrock =
            pi_route_classification("amazon-bedrock", "global.anthropic.claude-sonnet-4-6");
        assert_eq!(bedrock.billing_provider.as_deref(), Some("anthropic"));
        assert_eq!(bedrock.source_category.as_deref(), Some("aws_bedrock"));

        let gateway = pi_route_classification("vercel-ai-gateway", "openai.gpt-5.4-mini");
        assert_eq!(gateway.billing_channel.as_deref(), Some("gateway"));
        assert_eq!(
            gateway.gateway_provider.as_deref(),
            Some("vercel_ai_gateway")
        );
    }

    fn claude_settings_fixture(name: &str, body: &str) -> (PathBuf, Vec<(String, PathBuf)>) {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-runtime-defaults-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let claude_dir = root.join(".claude");
        std::fs::create_dir_all(&claude_dir).expect("create .claude");
        if !body.is_empty() {
            std::fs::write(claude_dir.join("settings.json"), body).expect("write settings");
        }
        let paths = vec![
            (
                "claude_code.settings".to_string(),
                claude_dir.join("settings.json"),
            ),
            (
                "claude_code.settings_local".to_string(),
                claude_dir.join("settings.local.json"),
            ),
            (
                "claude_code.managed_settings".to_string(),
                root.join("managed-settings.json"),
            ),
        ];
        (root, paths)
    }

    #[test]
    fn claude_runtime_defaults_carry_config_file_provenance() {
        let (root, paths) = claude_settings_fixture(
            "provenance",
            "{\"model\": \"claude-opus-4-7\", \"permissions\": {\"defaultMode\": \"plan\"}}\n",
        );

        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
        let defaults = capture.defaults.expect("runtime defaults present");
        assert_eq!(defaults.provenance.as_deref(), Some("config_file"));
        // The backend fills machine_id from the stored snapshot.
        assert_eq!(defaults.machine_id, None);
        assert_eq!(
            defaults.captured_at.as_deref(),
            Some("2026-07-25T10:00:00Z")
        );
        assert_eq!(defaults.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(defaults.approval_policy.as_deref(), Some("plan"));
        assert_eq!(capture.capability.capability, "runtime_defaults");
        assert_eq!(capture.capability.status, AgentCapabilityStatus::Supported);
        assert!(capture.diagnostic.is_none());

        // The strict backend schema must accept what we emit unchanged.
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-07-25T10:00:00Z".to_string(),
            "2026-07-25T10:05:00Z".to_string(),
        );
        snapshot.runtime_defaults = Some(defaults);
        let redacted = snapshot.redacted_for_backend();
        let survived = redacted.runtime_defaults.expect("survives redaction");
        assert_eq!(survived.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(survived.approval_policy.as_deref(), Some("plan"));

        let _ = std::fs::remove_dir_all(root);
    }

    /// Claude Code's `effortLevel` is durable: `/effort` writes it to the
    /// settings file and it persists across sessions. It maps straight through
    /// to `reasoning_effort`.
    #[test]
    fn claude_runtime_defaults_report_configured_effort_level() {
        let (root, paths) = claude_settings_fixture(
            "effort-level",
            "{\"model\": \"claude-opus-4-7\", \"effortLevel\": \"xhigh\"}\n",
        );

        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
        let defaults = capture.defaults.expect("runtime defaults present");
        assert_eq!(defaults.reasoning_effort.as_deref(), Some("xhigh"));
        assert_eq!(
            defaults
                .selector_sources
                .get("reasoning_effort")
                .map(String::as_str),
            Some("claude_code.settings.effortLevel")
        );
        // The Codex-shaped tier fields Claude's settings have no equivalent for
        // stay unset.
        assert_eq!(defaults.service_tier, None);
        assert_eq!(defaults.speed_mode, None);
        assert_eq!(defaults.priority_enabled, None);

        // The emitted effort value must survive the backend-facing guard.
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-07-25T10:00:00Z".to_string(),
            "2026-07-25T10:05:00Z".to_string(),
        );
        snapshot.runtime_defaults = Some(defaults);
        let survived = snapshot
            .redacted_for_backend()
            .runtime_defaults
            .expect("survives redaction");
        assert_eq!(survived.reasoning_effort.as_deref(), Some("xhigh"));

        let _ = std::fs::remove_dir_all(root);
    }

    /// Absent `effortLevel` must stay absent. Claude Code's own default is not
    /// ours to invent, and an unset field is what tells the UI "not configured".
    #[test]
    fn claude_runtime_defaults_leave_effort_unset_when_not_configured() {
        let (root, paths) = claude_settings_fixture(
            "no-effort-level",
            concat!(
                "{\"model\": \"claude-opus-4-7\",\n",
                " \"alwaysThinkingEnabled\": true,\n",
                " \"env\": {\"MAX_THINKING_TOKENS\": \"32000\"}}\n"
            ),
        );

        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &paths);
        let defaults = capture.defaults.expect("runtime defaults present");
        assert_eq!(defaults.reasoning_effort, None);
        assert!(!defaults.selector_context.contains_key("reasoning_effort"));
        assert!(!defaults.selector_sources.contains_key("reasoning_effort"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_runtime_defaults_absent_marks_not_configured_and_unreadable_apart() {
        let (configured_root, configured_paths) =
            claude_settings_fixture("not-configured", "{\"agentPushNotifEnabled\": true}\n");
        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &configured_paths);
        assert!(
            capture.defaults.is_none(),
            "an empty struct must not be attached when nothing is configured"
        );
        assert_eq!(
            capture.capability.status,
            AgentCapabilityStatus::Unsupported
        );
        assert_eq!(
            capture.diagnostic.as_ref().map(|entry| entry.code.as_str()),
            Some("claude_runtime_defaults_not_configured")
        );
        let _ = std::fs::remove_dir_all(configured_root);

        let (missing_root, missing_paths) = claude_settings_fixture("unreadable", "");
        let capture = claude_runtime_defaults_from_paths("2026-07-25T10:00:00Z", &missing_paths);
        assert!(capture.defaults.is_none());
        assert_eq!(
            capture.diagnostic.as_ref().map(|entry| entry.code.as_str()),
            Some("claude_runtime_defaults_unreadable")
        );
        let _ = std::fs::remove_dir_all(missing_root);
    }

    #[test]
    fn ottto_user_agent_identifies_honestly() {
        let user_agent = ottto_user_agent();
        assert!(
            user_agent.starts_with("ottto/"),
            "usage reads must identify as ottto, got {user_agent}"
        );
        assert!(user_agent.contains("subscription-usage-reader"));
        assert!(
            !user_agent.to_ascii_lowercase().contains("claude"),
            "never present a claude-* client identity: {user_agent}"
        );
    }

    #[test]
    fn full_slot_marker_requires_both_canonical_windows_and_a_scoped_limit() {
        let partial = fresh_slot_status("2026-08-04T10:00:00Z", "aaaa", "bbbb", true, false, true);
        assert!(partial.last_full_quota_read_at.is_none());
        let no_credits =
            fresh_slot_status("2026-08-04T10:00:00Z", "aaaa", "bbbb", true, true, false);
        assert_eq!(
            no_credits.last_full_quota_read_at.as_deref(),
            Some("2026-08-04T10:00:00Z")
        );
        assert!(
            !no_credits.has_credit_balances,
            "credits are optional for completeness"
        );
    }

    #[test]
    fn claude_quota_access_projection_is_strongly_bound_and_fail_closed() {
        let mut full = fresh_slot_status(
            "2026-08-12T10:00:00Z",
            "account-hash",
            "organization-hash",
            true,
            true,
            false,
        );
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::Full)
        );
        full.has_scoped_limits = false;
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::Partial)
        );

        full.state = ClaudeConfigSlotCollectionStateV1::ConcurrentMutation;
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::TemporarilyUnavailable),
            "a concurrent login mutation retries from stable state"
        );
        full.state = ClaudeConfigSlotCollectionStateV1::CredentialUnavailable;
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::AttentionRequired),
            "an ambiguous credential failure must not claim reconnect is sufficient"
        );
        full.upkeep = Some(ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        });
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::AttentionRequired),
            "unreadable metadata does not prove that login is the remedy"
        );

        full.state = ClaudeConfigSlotCollectionStateV1::NeedsLogin;
        full.upkeep.as_mut().expect("upkeep").result = ClaudeConfigSlotUpkeepResultV1::NeedsLogin;
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::ReconnectRequired),
            "only explicit absolute login expiry is reconnect-required"
        );

        full.state = ClaudeConfigSlotCollectionStateV1::ProbeFailed;
        full.upkeep.as_mut().expect("upkeep").result =
            ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled;
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::Paused)
        );
        full.upkeep.as_mut().expect("upkeep").result =
            ClaudeConfigSlotUpkeepResultV1::MissingBinary;
        assert_eq!(
            projected_claude_quota_access_state(&full),
            Some(ClaudeQuotaAccessState::AttentionRequired)
        );

        full.organization_identifier_hash = None;
        assert_eq!(projected_claude_quota_access_state(&full), None);
    }

    #[test]
    fn claude_quota_access_projection_marks_capability_without_guessing_account_state() {
        let mut snapshot = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-12T10:00:00Z".to_string(),
            "2026-08-12T10:05:00Z".to_string(),
        );
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            ..unsupported_account("anthropic")
        });
        let full = fresh_slot_status(
            "2026-08-12T10:00:00Z",
            "account-hash",
            "organization-hash",
            true,
            true,
            false,
        );
        apply_claude_quota_access_state(&mut snapshot, &full);
        assert_eq!(
            snapshot
                .account
                .as_ref()
                .and_then(|account| account.claude_quota_access_state),
            Some(ClaudeQuotaAccessState::Full)
        );
        assert!(snapshot
            .capabilities
            .iter()
            .any(|capability| capability.capability == CLAUDE_QUOTA_ACCESS_CAPABILITY));

        let mut mismatched = snapshot.clone();
        mismatched
            .account
            .as_mut()
            .expect("account")
            .claude_quota_access_state = None;
        let other = fresh_slot_status(
            "2026-08-12T10:00:00Z",
            "other-account",
            "organization-hash",
            true,
            true,
            false,
        );
        apply_claude_quota_access_state(&mut mismatched, &other);
        assert_eq!(
            mismatched
                .account
                .as_ref()
                .and_then(|account| account.claude_quota_access_state),
            None,
            "a state for another identity must never be stamped onto this account"
        );
        assert!(mismatched
            .capabilities
            .iter()
            .any(|capability| capability.capability == CLAUDE_QUOTA_ACCESS_CAPABILITY));
    }

    #[test]
    fn degraded_claude_slot_witness_is_meterless_planless_and_account_deduplicated() {
        let temporary = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            ..Default::default()
        };
        let reconnect = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::NeedsLogin,
            account_identifier_hash: Some("account-hash".to_string()),
            organization_identifier_hash: Some("organization-hash".to_string()),
            ..Default::default()
        };
        let unbound = ClaudeConfigSlotCollectionStatusV1 {
            state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
            account_identifier_hash: Some("unbound-account".to_string()),
            organization_identifier_hash: None,
            ..Default::default()
        };
        let slots = BTreeMap::from([
            ("claude_slot_a".to_string(), temporary),
            ("claude_slot_b".to_string(), reconnect),
            ("claude_slot_c".to_string(), unbound),
        ]);
        let binding = ClaudeStrongBinding {
            account_identifier_hash: "account-hash".to_string(),
            organization_identifier_hash: "organization-hash".to_string(),
        };
        let anchors = BTreeMap::from([(binding.clone(), "claude_slot_b".to_string())]);

        let snapshots = degraded_claude_slot_snapshots(
            &slots,
            &anchors,
            &BTreeSet::new(),
            "2026-08-12T10:00:00Z",
            "2026-08-12T10:05:00Z",
        );
        assert_eq!(snapshots.len(), 1, "one current row per strong account");
        let snapshot = &snapshots[0];
        assert_eq!(snapshot.status, AgentStatusState::Degraded);
        assert!(snapshot.quota_windows.is_empty());
        assert!(snapshot.credit_balances.is_empty());
        assert!(snapshot.plan_observations.is_empty());
        assert_eq!(
            snapshot
                .account
                .as_ref()
                .and_then(|account| account.claude_quota_access_state),
            Some(ClaudeQuotaAccessState::ReconnectRequired)
        );
        let wire = serde_json::to_string(snapshot).expect("serialize degraded witness");
        assert!(!wire.contains("claude_slot_a"));
        assert!(!wire.contains("claude_slot_b"));
        assert!(!wire.contains("config_dir"));
        assert!(!wire.contains("quota_snapshot"));

        let suppressed = degraded_claude_slot_snapshots(
            &slots,
            &anchors,
            &BTreeSet::from([binding]),
            "2026-08-12T10:00:00Z",
            "2026-08-12T10:05:00Z",
        );
        assert!(
            suppressed.is_empty(),
            "a healthy winner for the account must suppress its failed duplicate slot"
        );
    }

    #[test]
    fn degraded_default_only_witness_is_never_reported_as_anchored() {
        let slots = BTreeMap::from([(
            "default".to_string(),
            ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::ProviderUnavailable,
                account_identifier_hash: Some("account-hash".to_string()),
                organization_identifier_hash: Some("organization-hash".to_string()),
                ..Default::default()
            },
        )]);

        let snapshots = degraded_claude_slot_snapshots(
            &slots,
            &BTreeMap::new(),
            &BTreeSet::new(),
            "2026-08-12T10:00:00Z",
            "2026-08-12T10:05:00Z",
        );
        let account = snapshots[0].account.as_ref().expect("default account");
        assert_eq!(
            account.claude_anchor_durability,
            Some(ClaudeAccountAnchorDurabilityV1::DefaultOnly)
        );
        assert_eq!(account.claude_anchor_health, None);
    }

    #[test]
    #[serial]
    fn degraded_claude_slot_witness_retains_only_the_same_slots_strong_binding() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-quota-access-witness-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _support_guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        fs::create_dir_all(&root).expect("support root");
        let config_dir = root.join("exact-config");
        fs::create_dir_all(&config_dir).expect("config dir");
        let write_identity = |account: &str, organization: &str| {
            fs::write(
                config_dir.join(".claude.json"),
                serde_json::to_vec(&serde_json::json!({
                    "oauthAccount": {
                        "accountUuid": account,
                        "organizationUuid": organization,
                        "emailAddress": "person@example.invalid"
                    }
                }))
                .expect("identity json"),
            )
            .expect("write identity");
        };
        write_identity("account-current", "organization-current");
        let account_hash =
            billing_identity_hash("anthropic", "account", "account-current").expect("account hash");
        let organization_hash =
            billing_identity_hash("anthropic", "organization", "organization-current")
                .expect("organization hash");
        let slot = ClaudeConfigDirSlot::registered(config_dir.to_string_lossy().into_owned())
            .expect("registered slot");
        let slot_id = "claude_slot_strong_binding";
        write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
            schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
            slots: BTreeMap::from([
                (
                    slot_id.to_string(),
                    ClaudeConfigSlotCollectionStatusV1 {
                        state: ClaudeConfigSlotCollectionStateV1::Fresh,
                        account_identifier_hash: Some(account_hash.clone()),
                        organization_identifier_hash: Some(organization_hash.clone()),
                        last_full_quota_read_at: Some("2026-08-12T09:00:00Z".to_string()),
                        has_account_windows: true,
                        has_scoped_limits: true,
                        quota_snapshot: Some(ClaudeConfigSlotQuotaSnapshotV1 {
                            state: ClaudeConfigSlotQuotaSnapshotStateV1::Fresh,
                            captured_at: "2026-08-12T09:00:00Z".to_string(),
                            observed_at: Some("2026-08-12T09:00:00Z".to_string()),
                            quota_windows: Vec::new(),
                            credit_balances: Vec::new(),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "default".to_string(),
                    ClaudeConfigSlotCollectionStatusV1 {
                        state: ClaudeConfigSlotCollectionStateV1::Fresh,
                        account_identifier_hash: Some(account_hash.clone()),
                        organization_identifier_hash: Some(organization_hash.clone()),
                        last_full_quota_read_at: Some("2026-08-12T09:00:00Z".to_string()),
                        has_account_windows: true,
                        has_scoped_limits: true,
                        quota_snapshot: Some(ClaudeConfigSlotQuotaSnapshotV1 {
                            state: ClaudeConfigSlotQuotaSnapshotStateV1::Fresh,
                            captured_at: "2026-08-12T09:00:00Z".to_string(),
                            observed_at: Some("2026-08-12T09:00:00Z".to_string()),
                            quota_windows: Vec::new(),
                            credit_balances: Vec::new(),
                        }),
                        ..Default::default()
                    },
                ),
            ]),
            unresolved_accounts: Vec::new(),
            anchor_transitions: Vec::new(),
        })
        .expect("seed exact slot binding");

        let mut failed = ClaudeSlotProbeFailure::IdentityMismatch.status("2026-08-12T10:00:00Z");
        retain_verified_claude_slot_binding(slot_id, &slot, &mut failed);
        assert_eq!(
            failed.account_identifier_hash.as_deref(),
            Some(account_hash.as_str())
        );
        assert_eq!(
            failed.organization_identifier_hash.as_deref(),
            Some(organization_hash.as_str())
        );
        assert_eq!(
            failed.quota_snapshot, None,
            "binding verification must not copy older meters before the bounded merge"
        );
        assert_eq!(
            projected_claude_quota_access_state(&failed),
            Some(ClaudeQuotaAccessState::AttentionRequired)
        );

        let mut current_full = fresh_slot_status(
            "2026-08-12T10:00:00Z",
            &account_hash,
            &organization_hash,
            true,
            true,
            false,
        );
        current_full.quota_snapshot = Some(ClaudeConfigSlotQuotaSnapshotV1 {
            state: ClaudeConfigSlotQuotaSnapshotStateV1::Fresh,
            captured_at: "2026-08-12T10:00:00Z".to_string(),
            observed_at: Some("2026-08-12T10:00:00Z".to_string()),
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
        });
        retain_verified_claude_slot_binding(slot_id, &slot, &mut current_full);
        assert_eq!(
            current_full.last_full_quota_read_at.as_deref(),
            Some("2026-08-12T10:00:00Z"),
            "a current full read must not be replaced by the prior slot timestamp"
        );
        assert_eq!(
            current_full
                .quota_snapshot
                .as_ref()
                .map(|snapshot| snapshot.captured_at.as_str()),
            Some("2026-08-12T10:00:00Z"),
            "a current full snapshot must remain authoritative"
        );

        write_identity("account-rotated", "organization-rotated");
        let mut rotated = ClaudeSlotProbeFailure::IdentityMismatch.status("2026-08-12T10:01:00Z");
        retain_verified_claude_slot_binding(slot_id, &slot, &mut rotated);
        assert_eq!(rotated.account_identifier_hash, None);
        assert_eq!(rotated.organization_identifier_hash, None);
        assert_eq!(projected_claude_quota_access_state(&rotated), None);

        let mut blocked_rotated = blocked_claude_upkeep_status(
            slot_id,
            "2026-08-12T10:01:30Z",
            ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
                result: ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
                due_access_expires_at: None,
                refresh_token_expires_at: None,
                attempted_at: None,
                next_allowed_attempt_at: None,
                consecutive_failures: 0,
            },
        );
        retain_verified_claude_slot_binding(slot_id, &slot, &mut blocked_rotated);
        assert_eq!(blocked_rotated.account_identifier_hash, None);
        assert_eq!(blocked_rotated.organization_identifier_hash, None);

        fs::remove_file(config_dir.join(".claude.json")).expect("remove current identity");
        let mut missing = blocked_claude_upkeep_status(
            slot_id,
            "2026-08-12T10:02:00Z",
            ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
                result: ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
                due_access_expires_at: None,
                refresh_token_expires_at: None,
                attempted_at: None,
                next_allowed_attempt_at: None,
                consecutive_failures: 0,
            },
        );
        assert!(
            missing.account_identifier_hash.is_some(),
            "blocked upkeep starts from the local persisted status"
        );
        retain_verified_claude_slot_binding(slot_id, &slot, &mut missing);
        assert_eq!(missing.account_identifier_hash, None);
        assert_eq!(missing.organization_identifier_hash, None);
        assert_eq!(missing.quota_snapshot, None);

        let home = root.join("home");
        fs::create_dir_all(&home).expect("default home");
        let _home_guard = EnvVarGuard::set_os("HOME", home.as_os_str().to_os_string());
        let mut default_failed =
            ClaudeSlotProbeFailure::CredentialUnavailable.status("2026-08-12T10:03:00Z");
        retain_verified_claude_slot_binding(
            "default",
            &ClaudeConfigDirSlot::Default,
            &mut default_failed,
        );
        assert_eq!(default_failed.account_identifier_hash, None);
        assert_eq!(default_failed.organization_identifier_hash, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unresolved_accounts_use_only_strong_desktop_evidence_and_subtract_full_accounts() {
        let mut desktop = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-04T10:00:00Z".to_string(),
            "2026-08-04T10:05:00Z".to_string(),
        );
        let observation =
            |hash: Option<&str>, confidence: AgentStatusConfidence| AgentStatusPlanObservation {
                observed_at: Some("2026-08-04T10:00:00Z".to_string()),
                evidence_method: Some("claude_desktop_session_bucket".to_string()),
                source_session_id: None,
                provider: Some("anthropic".to_string()),
                billing_provider: Some("anthropic".to_string()),
                model_provider: Some("anthropic".to_string()),
                billing_channel: Some("subscription".to_string()),
                auth_mode: Some("claude_desktop".to_string()),
                gateway_provider: None,
                subscription_product: None,
                plan_type: None,
                account_label: None,
                account_id: None,
                organization_label: None,
                organization_id: None,
                account_identifier_hash: hash.map(ToString::to_string),
                organization_identifier_hash: None,
                superseded_account_identifier_hash: None,
                superseded_organization_identifier_hash: None,
                credential_fingerprint_hash: None,
                billing_identity_evidence: None,
                billing_identity_confidence: confidence.clone(),
                confidence,
                is_current: None,
            };
        let mut expired = observation(Some("expired"), AgentStatusConfidence::High);
        expired.observed_at = Some("2026-05-05T09:59:59Z".to_string());
        desktop.plan_observations = vec![
            observation(Some("strong-unresolved"), AgentStatusConfidence::High),
            observation(Some("weak"), AgentStatusConfidence::Low),
            observation(None, AgentStatusConfidence::High),
            observation(Some("resolved"), AgentStatusConfidence::High),
            expired,
        ];
        let mut full = base_snapshot(
            SourceKind::ClaudeCode,
            AgentStatusState::Available,
            AgentStatusCollectionMethod::CliJson,
            "2026-08-04T10:00:00Z".to_string(),
            "2026-08-04T10:05:00Z".to_string(),
        );
        full.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            provider: Some("anthropic".to_string()),
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
            account_identifier_hash: Some("resolved".to_string()),
            organization_identifier_hash: None,
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: None,
            claude_quota_access_state: None,
            claude_anchor_durability: None,
            claude_anchor_health: None,
            billing_identity_confidence: AgentStatusConfidence::High,
            confidence: AgentStatusConfidence::High,
        });
        full.quota_windows = vec![
            AgentQuotaWindow {
                name: "session".to_string(),
                scope: AgentQuotaWindowScope::Account,
                freshness: AgentQuotaWindowFreshness::Fresh,
                ..Default::default()
            },
            AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: AgentQuotaWindowScope::Account,
                freshness: AgentQuotaWindowFreshness::Fresh,
                ..Default::default()
            },
            AgentQuotaWindow {
                name: "weekly_sonnet".to_string(),
                scope: AgentQuotaWindowScope::Model,
                freshness: AgentQuotaWindowFreshness::Fresh,
                model: Some("claude-sonnet".to_string()),
                ..Default::default()
            },
        ];
        let unresolved = derive_unresolved_claude_accounts(
            &desktop,
            &[full],
            &BTreeMap::new(),
            OffsetDateTime::parse("2026-08-04T10:00:00Z", &Rfc3339).expect("fixed now"),
        );
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            unresolved[0].account_identifier_hash.as_deref(),
            Some("strong-unresolved")
        );
        assert_eq!(
            unresolved[0].evidence,
            vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession]
        );
    }

    #[test]
    #[serial]
    fn advisory_upkeep_never_overwrites_a_successful_fresh_collection() {
        for result in [
            ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented,
            ClaudeConfigSlotUpkeepResultV1::ReloginApproaching,
        ] {
            let mut status = ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some("account-hash".to_string()),
                last_full_quota_read_at: Some("2026-08-04T10:00:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                ..Default::default()
            };
            apply_claude_upkeep_observation(
                &mut status,
                ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
                    result,
                    due_access_expires_at: Some("2026-08-04T11:00:00Z".to_string()),
                    refresh_token_expires_at: Some("2026-08-07T09:00:00Z".to_string()),
                    attempted_at: None,
                    next_allowed_attempt_at: None,
                    consecutive_failures: 0,
                },
            );
            assert_eq!(status.state, ClaudeConfigSlotCollectionStateV1::Fresh);
            assert!(status.upkeep.is_some());
            assert!(!status.diagnostics.is_empty());
        }
    }

    #[test]
    #[serial]
    fn paused_upkeep_retains_previous_safe_deadlines_without_a_credential_read() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-paused-deadlines-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _support_guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        fs::create_dir_all(&root).expect("support root");
        let slot_id = "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
            schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
            slots: BTreeMap::from([(
                slot_id.to_string(),
                ClaudeConfigSlotCollectionStatusV1 {
                    access_expires_at: Some("2026-08-04T10:00:00Z".to_string()),
                    relogin_required_at: Some("2026-08-20T00:00:00Z".to_string()),
                    account_identifier_hash: Some("safe-account-hash".to_string()),
                    ..Default::default()
                },
            )]),
            unresolved_accounts: Vec::new(),
            anchor_transitions: Vec::new(),
        })
        .expect("seed slot state");

        let status = blocked_claude_upkeep_status(
            slot_id,
            "2026-08-04T11:00:00Z",
            ottto_protocol::ClaudeConfigSlotUpkeepStatusV1 {
                result: ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
                due_access_expires_at: None,
                refresh_token_expires_at: None,
                attempted_at: None,
                next_allowed_attempt_at: None,
                consecutive_failures: 0,
            },
        );
        assert_eq!(
            status.access_expires_at.as_deref(),
            Some("2026-08-04T10:00:00Z")
        );
        assert_eq!(
            status.relogin_required_at.as_deref(),
            Some("2026-08-20T00:00:00Z")
        );
        assert_eq!(
            status.account_identifier_hash.as_deref(),
            Some("safe-account-hash")
        );
        assert_eq!(
            status.state,
            ClaudeConfigSlotCollectionStateV1::CollectionPaused
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn exact_full_slot_persistence_atomically_clears_matching_unresolved_account() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-unresolved-clear-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _support_guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        fs::create_dir_all(&root).expect("support root");
        write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
            schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
            slots: BTreeMap::new(),
            unresolved_accounts: vec![ClaudeUnresolvedAccountDescriptorV1 {
                unresolved_id: "claude-unresolved-test".to_string(),
                account_identifier_hash: Some("account-full".to_string()),
                observed_at: Some("2026-08-04T10:00:00Z".to_string()),
                evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
            }],
            anchor_transitions: Vec::new(),
        })
        .expect("seed unresolved state");
        persist_one_claude_slot_collection_state(
            "claude_slot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some("account-full".to_string()),
                organization_identifier_hash: Some("organization-full".to_string()),
                observed_at: Some("2026-08-04T10:01:00Z".to_string()),
                last_full_quota_read_at: Some("2026-08-04T10:01:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                ..Default::default()
            },
        )
        .expect("persist exact full proof");
        assert!(
            read_persisted_claude_slot_collection_state()
                .unresolved_accounts
                .is_empty(),
            "the same Complete response must not retain a stale unresolved warning"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn stale_bulk_persistence_cannot_resurrect_exactly_resolved_account() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-unresolved-stale-bulk-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _support_guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        fs::create_dir_all(&root).expect("support root");
        let config_dir = root.join("registered-account");
        fs::create_dir_all(&config_dir).expect("registered config dir");
        let status = FileClaudeConfigSlotSettingsStore::default()
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                config_dir.to_string_lossy().into_owned(),
            )
            .expect("register current slot");
        let slot_id = status
            .external_slots
            .first()
            .expect("registered external slot")
            .slot_id
            .clone();
        let stale_unresolved = ClaudeUnresolvedAccountDescriptorV1 {
            unresolved_id: "claude-unresolved-stale".to_string(),
            account_identifier_hash: Some("account-full".to_string()),
            observed_at: Some("2026-08-04T10:00:00Z".to_string()),
            evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
        };
        write_persisted_claude_slot_collection_state(&PersistedClaudeSlotCollectionStateV1 {
            schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
            slots: BTreeMap::new(),
            unresolved_accounts: vec![stale_unresolved.clone()],
            anchor_transitions: Vec::new(),
        })
        .expect("seed unresolved state");
        persist_one_claude_slot_collection_state(
            &slot_id,
            &ClaudeConfigSlotCollectionStatusV1 {
                state: ClaudeConfigSlotCollectionStateV1::Fresh,
                account_identifier_hash: Some("account-full".to_string()),
                organization_identifier_hash: Some("organization-full".to_string()),
                observed_at: Some("2026-08-04T10:01:00Z".to_string()),
                last_full_quota_read_at: Some("2026-08-04T10:01:00Z".to_string()),
                has_account_windows: true,
                has_scoped_limits: true,
                ..Default::default()
            },
        )
        .expect("persist exact full proof");

        persist_claude_slot_collection_states(&BTreeMap::new(), &[stale_unresolved])
            .expect("persist delayed stale scheduled state");

        assert!(
            read_persisted_claude_slot_collection_state()
                .unresolved_accounts
                .is_empty(),
            "a delayed bulk writer must subtract newer full proof under its lock"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_collection_attempt_lock_child() {
        let Ok(account) = std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_ACCOUNT") else {
            return;
        };
        let mode = std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_MODE").expect("child mode");
        if mode == "contender" {
            assert!(try_claude_oauth_collection_attempt(&account, "organization-a").is_none());
            return;
        }
        let ready =
            PathBuf::from(std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_READY").expect("ready path"));
        let release = PathBuf::from(
            std::env::var("OTTTO_TEST_CLAUDE_ATTEMPT_RELEASE").expect("release path"),
        );
        let guard =
            try_claude_oauth_collection_attempt(&account, "organization-a").expect("holder lock");
        fs::write(&ready, b"ready").expect("signal ready");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !release.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(release.exists(), "parent released holder");
        drop(guard);
    }

    #[test]
    #[serial]
    fn claude_collection_attempt_lock_is_cross_process_and_account_scoped() {
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-attempt-process-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("root");
        let ready = root.join("ready");
        let release = root.join("release");
        let executable = std::env::current_exe().expect("test executable");
        let child_args = [
            "--exact",
            "agent_status::tests::claude_collection_attempt_lock_child",
            "--nocapture",
        ];
        let mut holder = std::process::Command::new(&executable)
            .args(child_args)
            .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root)
            .env("OTTTO_TEST_CLAUDE_ATTEMPT_ACCOUNT", "account-a")
            .env("OTTTO_TEST_CLAUDE_ATTEMPT_MODE", "holder")
            .env("OTTTO_TEST_CLAUDE_ATTEMPT_READY", &ready)
            .env("OTTTO_TEST_CLAUDE_ATTEMPT_RELEASE", &release)
            .spawn()
            .expect("spawn holder");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "holder acquired lock");
        let contender = std::process::Command::new(&executable)
            .args(child_args)
            .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root)
            .env("OTTTO_TEST_CLAUDE_ATTEMPT_ACCOUNT", "account-a")
            .env("OTTTO_TEST_CLAUDE_ATTEMPT_MODE", "contender")
            .status()
            .expect("run contender");
        assert!(contender.success());
        fs::write(&release, b"release").expect("release holder");
        assert!(holder.wait().expect("wait holder").success());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn scheduled_collection_and_exact_check_share_one_account_provider_admission() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let root = std::env::temp_dir().join(format!(
            "ottto-claude-attempt-shared-paths-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _support_guard = EnvVarGuard::set_os(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let scheduled_calls = Arc::clone(&provider_calls);
        let scheduled = thread::spawn(move || {
            let _guard = try_claude_oauth_collection_attempt(
                "same-strong-account",
                "same-strong-organization",
            )
            .expect("scheduled collector admission");
            scheduled_calls.fetch_add(1, Ordering::SeqCst);
            entered_tx.send(()).expect("entered");
            release_rx.recv().expect("release");
        });
        entered_rx.recv().expect("scheduled admitted");
        let exact_check_admission =
            try_claude_oauth_collection_attempt("same-strong-account", "same-strong-organization");
        if exact_check_admission.is_some() {
            provider_calls.fetch_add(1, Ordering::SeqCst);
        }
        assert!(exact_check_admission.is_none());
        release_tx.send(()).expect("release scheduled");
        scheduled.join().expect("join scheduled");
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(root);
    }
}
