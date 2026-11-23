//! Daemon state ownership, construction and account transitions.
//! Owns control authorization, source persistence and connection binding.
//! Called through the root LocalDaemon API and sibling daemon modules.

use crate::agent_status;
use crate::agent_status_refresh;
use crate::bound_user;
use crate::clear_local_health_upload_auth_rejection;
use crate::clear_setup_run_read_rejection;
use crate::codex_prelude_footprint;
use crate::context_footprint;
use crate::load_source_state;
use crate::otlp_relay;
use crate::seed_registered_sources;
use crate::session_launch;
use crate::setup_run_read_revision;
use crate::snapshot_sync;
use crate::snapshots;
use crate::source_slug;
use crate::tracking_confirmation;
use crate::SetupRunReadStart;
use ottto_core::default_connection_api_base_url;
use ottto_core::source_state_file_name;
use ottto_core::FileConnectionStore;
use ottto_core::FileSourceStateStore;
use ottto_core::LocalConnectionBinding;
use ottto_core::LocalDeviceBinding;
use ottto_core::LocalSourceState;
use ottto_protocol::AuthCompleteResponse;
use ottto_protocol::AuthResetResponse;
use ottto_protocol::AuthStartResponse;
use ottto_protocol::LocalAccountBinding;
use ottto_protocol::LocalAccountState;
use ottto_protocol::LocalHealthCommandResultV1;
use ottto_protocol::LocalHealthEventV1;
use ottto_protocol::MachineIdentity;
use ottto_protocol::RelayRuntimeState;
use ottto_protocol::RelayState;
use ottto_protocol::SourceHealth;
use ottto_protocol::SourceKind;
use ottto_protocol::StableMessage;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendErrorKind {
    Unreachable,
    Rejected,
    Unavailable,
    ResponseUnexpected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendErrorDetails {
    pub kind: BackendErrorKind,
    pub endpoint: String,
    pub status: Option<u16>,
    pub body_excerpt: Option<String>,
    /// Stable machine code the error body named, when it named one.
    pub reason_code: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalApiError {
    #[error("local daemon authentication failed")]
    Unauthorized,
    #[error("another repair is already running")]
    RepairLocked,
    #[error("daemon state lock is poisoned")]
    StatePoisoned,
    #[error("control token cannot be empty")]
    EmptyControlToken,
    #[error("local client is not trusted")]
    LocalClientNotTrusted,
    #[error(
        "this Mac is connected to a different Ottto account; reset local account binding first"
    )]
    AccountResetRequired,
    /// A sign-in claim completed for a different user than the one this Mac is
    /// bound to, and the completion is staged for an explicit
    /// `auth_switch_account` confirmation. Carries display-safe identity so the
    /// client can render a confirm dialog. Maps to the same wire error code as
    /// [`Self::AccountResetRequired`] (`account_reset_required`) so pre-switch
    /// clients keep their existing reset flow; switch-aware clients read the
    /// `switch_candidate` details instead.
    #[error(
        "this Mac is connected to a different Ottto account; reset local account binding first"
    )]
    AccountSwitchCandidate {
        current_user_email: String,
        new_user_email: String,
        new_organization_name: String,
        claim_code: String,
    },
    #[error("no pending Ottto sign-in claim")]
    NoPendingAuthClaim,
    #[error("Ottto sign-in claim does not match this local session")]
    AuthClaimMismatch,
    #[error("setup-run connection is missing")]
    SetupRunConnectionMissing,
    #[error("this Mac is attached to a different setup run; open the Ottto app from Ottto")]
    SetupRunConnectionMismatch,
    #[error(
        "Codex cloud task listing did not stop in time to change this Mac's Ottto account or device; wait a minute, then retry"
    )]
    CloudSessionCleanupRequired,
    #[error(
        "another Ottto account or device update is in progress; wait for it to finish, then retry"
    )]
    IdentityMutationInProgress,
    #[error("invalid local control request: {0}")]
    InvalidRequest(String),
    /// A retired command, answered with a fixed message only after the
    /// caller is authorized. The message must never echo request fields.
    #[error("{0}")]
    RetiredCommand(&'static str),
    #[error("Ottto left the configuration unchanged. Review the Ottto telemetry entries and fence markers in the source config, then retry.")]
    ManualFenceReviewRequired,
    #[error("local operation failed: {0}")]
    LocalOperationFailed(String),
    #[error("network unavailable")]
    NetworkUnavailable,
    #[error("operation timed out: {0}")]
    TimedOut(String),
    #[error("backend request failed: {0:?}")]
    Backend(BackendErrorDetails),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlToken(String);

impl ControlToken {
    pub fn new(value: impl Into<String>) -> Result<Self, LocalApiError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(LocalApiError::EmptyControlToken);
        }
        Ok(Self(value))
    }

    pub(crate) fn authorize(&self, candidate: &str) -> Result<(), LocalApiError> {
        // ct_eq returns early on unequal lengths; generated tokens are 64 hex.
        if bool::from(self.0.as_bytes().ct_eq(candidate.as_bytes())) {
            Ok(())
        } else {
            Err(LocalApiError::Unauthorized)
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalDaemon {
    pub(crate) session_launch: Arc<Mutex<session_launch::Registry>>,
    pub(crate) transcript_cache: Arc<snapshots::sampled_scan::SharedCache>,
    pub(crate) footprint_cwds: Arc<context_footprint::CwdProjection>,
    pub(crate) codex_preludes: Arc<codex_prelude_footprint::CodexPreludeFeed>,
    pub(crate) codex_versions: Arc<snapshots::codex_version::CodexVersionFeed>,
    pub(crate) relay_mismatch: Arc<otlp_relay::RelayMismatchDebounce>,
    pub(crate) inner: Arc<Mutex<DaemonState>>,
    pub(crate) control_token: ControlToken,
}

#[derive(Debug, Clone)]
pub(crate) struct DaemonState {
    pub(crate) machine: MachineIdentity,
    pub(crate) relay: RelayState,
    pub(crate) sources: Vec<SourceHealth>,
    /// Real per-source first-seen timestamps, keyed by source slug. Boot-loaded
    /// from `<source_state_dir>/<slug>-state.json` and stamped on first
    /// observation; drives `SourceHealth.connected_at`.
    pub(crate) source_first_seen: BTreeMap<String, String>,
    /// Most recent `local_usage_reconciliation_enabled` per source slug,
    /// recorded by the snapshot-sync loop; drives
    /// `SourceHealth.reconciliation_enabled`. In-memory only (cleared on reset
    /// and restart), which the Companion tolerates as "managed by workspace".
    pub(crate) source_reconciliation: BTreeMap<String, bool>,
    pub(crate) tracking_confirmation: tracking_confirmation::TrackingEpisodes,
    pub(crate) registered_source_grants: Vec<String>,
    pub(crate) scan_index_health_revisions: [[u64; 3]; 3],
    /// Directory for the persisted per-source state files. `None` keeps
    /// source state purely in-memory (tests); production sets it via
    /// `with_source_state_dir(default_sources_dir())`.
    pub(crate) source_state_dir: Option<PathBuf>,
    pub(crate) local_health_events: Vec<LocalHealthEventV1>,
    pub(crate) command_ledger: Vec<LocalHealthCommandResultV1>,
    pub(crate) account: LocalAccountBinding,
    pub(crate) connection: Option<LocalConnectionBinding>,
    pub(crate) pending_auth: Option<PendingAuthClaim>,
    /// A claim completion for a DIFFERENT user than the current binding,
    /// held in memory until the client confirms the switch via
    /// `auth_switch_account` (or it is superseded by a new claim / reset).
    /// Never persisted: a daemon restart drops it and the user re-runs
    /// sign-in.
    pub(crate) pending_switch: Option<StagedAccountSwitch>,
    pub(crate) repair_locked: bool,
    pub(crate) running: bool,
    pub(crate) now: String,
    /// Wall-clock instant this daemon process started, stamped once at
    /// construction. `RuntimeIdentityV1.started_at` and the runtime heartbeat
    /// report it; every status query reports the query time only as
    /// `last_seen_at`.
    pub(crate) started_at: String,
    /// In memory only: when each active read-time blocker was first seen.
    pub(crate) blocker_first_seen: BlockerFirstSeen,
}

/// First-seen `since` per blocker, keyed by `(code, source)`.
pub(crate) type BlockerFirstSeen = BTreeMap<(String, String), String>;

impl DaemonState {
    pub(crate) fn first_seen(&self, source: &SourceKind) -> Option<String> {
        self.source_first_seen.get(source_slug(source)).cloned()
    }

    pub(crate) fn reconciliation_enabled(&self, source: &SourceKind) -> Option<bool> {
        self.source_reconciliation.get(source_slug(source)).copied()
    }

    /// Record the first time `source` is observed. A no-op once known, so the
    /// persisted original timestamp wins after a restart rather than being
    /// overwritten by a later re-observation. Persists to disk when a
    /// source-state dir is configured.
    pub(crate) fn stamp_first_seen(&mut self, source: &SourceKind, observed_at: Option<&str>) {
        let Some(observed_at) = observed_at else {
            return; // No honest timestamp to stamp yet.
        };
        let slug = source_slug(source);
        if self.source_first_seen.contains_key(slug) {
            return;
        }
        self.source_first_seen
            .insert(slug.to_string(), observed_at.to_string());
        self.persist_source_state(source);
    }

    pub(crate) fn persist_source_state(&self, source: &SourceKind) {
        let slug = source_slug(source);
        if let Some(dir) = self.source_state_dir.as_ref() {
            let store = FileSourceStateStore::new(dir.join(source_state_file_name(slug)));
            let last_health = self
                .sources
                .iter()
                .find(|health| health.source == *source)
                .cloned();
            if let Err(error) = store.save(&LocalSourceState {
                first_seen_at: self.first_seen(source),
                last_health,
                tracking_confirmation: self.tracking_confirmation.saved(source).cloned(),
            }) {
                eprintln!("failed to persist source state for {slug}: {error}");
            }
        }
    }

    pub(crate) fn binds_setup_run(&self, binding: &LocalConnectionBinding) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|current| setup_run_binding_matches(current, binding))
    }

    /// Clear the in-memory first-seen + reconciliation maps and delete the
    /// persisted per-source state files. Called at the account reset sites so a
    /// fresh account starts with a fresh source history.
    pub(crate) fn clear_source_state(&mut self) {
        if let Some(dir) = self.source_state_dir.as_ref() {
            for source in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
                let slug = source_slug(&source);
                let store = FileSourceStateStore::new(dir.join(source_state_file_name(slug)));
                if let Err(error) = store.reset() {
                    eprintln!("failed to clear first-seen for {slug}: {error}");
                }
            }
        }
        self.source_first_seen.clear();
        self.source_reconciliation.clear();
        self.tracking_confirmation.clear_all();
        for source in [
            snapshots::SnapshotSource::ClaudeCode,
            snapshots::SnapshotSource::Codex,
            snapshots::SnapshotSource::Pi,
        ] {
            snapshot_sync::reset_collection_health(source);
        }
        self.registered_source_grants.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthClaim {
    pub claim_code: String,
    pub claim_token: String,
    pub nonce: String,
    pub claim_url: String,
    pub expires_at: String,
}

/// Stable message code set on the account binding when the backend reports
/// that the bound account no longer exists (deleted server-side). A binding in
/// this state is treated as unbound for claim purposes: the next sign-in by
/// ANY user proceeds as a fresh first claim instead of demanding a reset.
pub const ACCOUNT_NOT_FOUND_MESSAGE_CODE: &str = "account_not_found";

/// A fully backend-completed sign-in claim for a different user, staged in
/// memory pending an explicit `auth_switch_account` confirmation. Nothing is
/// persisted (files, keychain) until the switch is confirmed, so cancelling
/// leaves the old binding's credentials intact.
#[derive(Clone)]
pub struct StagedAccountSwitch {
    pub claim_code: String,
    pub new_account: LocalAccountBinding,
    pub setup_run_id: String,
    /// Secret. In-memory only; redacted from `Debug`.
    pub setup_run_token: String,
    pub setup_run_token_expires_at: String,
    pub machine_id: Option<String>,
    pub relay_device: Option<LocalDeviceBinding>,
    /// Secret. In-memory only; redacted from `Debug`.
    pub relay_device_secret: Option<String>,
    /// Modern two-phase relay credential staged durably outside this in-memory
    /// switch record. Presence prohibits fallback to the legacy secret fields.
    pub relay_device_credential_preparation_id: Option<String>,
    /// Additive backend backfill policy from the claim completion ("full" |
    /// "from"); `None` when the backend predates the field. Applied to the
    /// snapshot backfill state when the switch is confirmed and installed.
    pub backfill_policy: Option<String>,
    /// Server-UTC cutoff accompanying `backfill_policy: "from"`.
    pub backfill_cutoff_at: Option<String>,
}

impl std::fmt::Debug for StagedAccountSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedAccountSwitch")
            .field("claim_code", &self.claim_code)
            .field("new_account", &self.new_account)
            .field("setup_run_id", &self.setup_run_id)
            .field("setup_run_token", &"[redacted]")
            .field(
                "setup_run_token_expires_at",
                &self.setup_run_token_expires_at,
            )
            .field("machine_id", &self.machine_id)
            .field("relay_device", &self.relay_device)
            .field(
                "relay_device_secret",
                &self.relay_device_secret.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "relay_device_credential_preparation_id",
                &self.relay_device_credential_preparation_id,
            )
            .field("backfill_policy", &self.backfill_policy)
            .field("backfill_cutoff_at", &self.backfill_cutoff_at)
            .finish()
    }
}

/// Display-safe summary of a staged switch, surfaced to the client in the
/// `account_reset_required` error details so it can render a confirm dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSwitchCandidateInfo {
    pub current_user_email: String,
    pub new_user_email: String,
    pub new_organization_name: String,
    pub claim_code: String,
}

fn account_binding_is_account_not_found(account: &LocalAccountBinding) -> bool {
    account.state == LocalAccountState::Error
        && account
            .message
            .as_ref()
            .is_some_and(|message| message.code == ACCOUNT_NOT_FOUND_MESSAGE_CODE)
}

/// Privacy-safe discriminator for the OS account this install runs under; see
/// `MachineIdentity::account_scope` for the contract. Derived from the POSIX
/// uid on every call, so it survives daemon restarts and reinstalls without
/// persisting anything about the account.
pub fn local_account_scope(machine_id: &str) -> Option<String> {
    account_scope_from_uid(machine_id, current_account_uid())
}

/// Hash-only half of `local_account_scope`, split out so tests can pin the
/// stability and distinctness guarantees without depending on whichever account
/// runs them. The uid is digest input only; it never appears in the output, and
/// neither does the username, the home directory, nor any path.
pub fn account_scope_from_uid(machine_id: &str, uid: Option<u32>) -> Option<String> {
    let uid = uid?;
    Some(ottto_core::prefixed_sha256_id(
        "otu",
        &format!("account:{machine_id}:{uid}"),
    ))
}

/// The POSIX uid the daemon runs as. `getuid` cannot fail on unix. Non-unix
/// targets have no POSIX uid, so they report `None` instead of a placeholder
/// that would collapse distinct accounts onto one scope.
pub fn current_account_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // `libc::uid_t` is `u32` on every supported unix target.
        Some(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

impl LocalDaemon {
    pub fn new(
        machine: MachineIdentity,
        control_token: ControlToken,
        now: impl Into<String>,
    ) -> Self {
        let now = now.into();
        let footprint_cwds = Arc::<context_footprint::CwdProjection>::default();
        let codex_preludes =
            codex_prelude_footprint::CodexPreludeFeed::new(footprint_cwds.inputs());
        Self {
            session_launch: Arc::default(),
            transcript_cache: Arc::new(snapshots::sampled_scan::SharedCache::default()),
            footprint_cwds,
            codex_preludes: Arc::new(codex_preludes),
            codex_versions: Arc::new(snapshots::codex_version::CodexVersionFeed::new(
                snapshot_sync::home_dir().ok().as_deref(),
            )),
            relay_mismatch: Arc::default(),
            inner: Arc::new(Mutex::new(DaemonState {
                machine,
                relay: RelayState {
                    state: RelayRuntimeState::Unknown,
                    endpoint: None,
                    last_connected_at: None,
                    last_error: None,
                },
                sources: Vec::new(),
                source_first_seen: BTreeMap::new(),
                source_reconciliation: BTreeMap::new(),
                tracking_confirmation: Default::default(),
                registered_source_grants: Vec::new(),
                scan_index_health_revisions: [[0; 3]; 3],
                source_state_dir: None,
                local_health_events: Vec::new(),
                command_ledger: Vec::new(),
                account: LocalAccountBinding::not_connected(),
                connection: None,
                pending_auth: None,
                pending_switch: None,
                repair_locked: false,
                running: true,
                started_at: now.clone(),
                now,
                blocker_first_seen: BlockerFirstSeen::new(),
            })),
            control_token,
        }
    }

    pub fn with_account(self, account: LocalAccountBinding) -> Self {
        if let Ok(mut state) = self.inner.lock() {
            state.account = account;
        }
        self
    }

    pub fn with_connection(self, connection: Option<LocalConnectionBinding>) -> Self {
        if let Ok(mut state) = self.inner.lock() {
            state.connection = connection;
        }
        self
    }

    /// Seed known registered sources from the persisted relay-device binding so
    /// a freshly restarted daemon never reports a connected account with zero
    /// sources while the slower agent scan is still pending. Only sources that
    /// are genuinely present on THIS machine are seeded — `device.sources` is the
    /// account-wide registered set, and seeding an app that this Mac never had
    /// would show a phantom "needs attention" row. Seeded rows are intentionally
    /// `verifying` and carry no agent snapshot; a real scan or verification
    /// result replaces them with authoritative health.
    pub fn with_registered_device_sources(self, device: Option<LocalDeviceBinding>) -> Self {
        if let Ok(mut state) = self.inner.lock() {
            seed_registered_sources(&mut state, device.as_ref());
        }
        self
    }

    /// Enable persistence of per-source state under `dir`
    /// (`<dir>/<slug>-state.json`) and boot-load any existing files into the
    /// in-memory map/source rows. Production passes `default_sources_dir()`;
    /// constructors that omit this keep source state purely in-memory.
    pub fn with_source_state_dir(self, dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        if let Ok(mut state) = self.inner.lock() {
            load_source_state(&mut state, &dir);
            state.source_state_dir = Some(dir);
        }
        self
    }

    /// Record the most recent reconciliation policy for a source, learned by
    /// the snapshot-sync loop's activity hint. This is an internal,
    /// trusted-process call (no control token), mirroring how the local OTLP
    /// relay updates daemon state. Keep the raw enabled flag even for a zero window.
    pub fn record_reconciliation_enabled(
        &self,
        source: SourceKind,
        enabled: bool,
        receipt_window_days: u64,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        state
            .source_reconciliation
            .insert(source_slug(&source).to_string(), enabled);
        let policy_enabled = enabled && receipt_window_days > 0;
        let snapshot_source = snapshot_sync::snapshot_source_of_kind(&source);
        if !policy_enabled || !state.tracking_confirmation.policy_allows(&source) {
            // A cycle offered while policy-stopped cannot supply the resume baseline.
            snapshot_sync::reset_collection_health(snapshot_source);
        }
        if policy_enabled {
            snapshot_sync::start_collection_health(snapshot_source);
        }
        if state
            .tracking_confirmation
            .record_policy(&source, receipt_window_days, enabled)
        {
            state.persist_source_state(&source);
        }
        Ok(())
    }

    /// Snapshot of the current pending claim plus the account binding, used by
    /// `auth_start` to make repeated Sign-in presses idempotent: an unexpired
    /// in-flight claim is returned as-is instead of minting a parallel one.
    pub fn pending_auth_claim_snapshot(
        &self,
    ) -> Result<Option<(PendingAuthClaim, LocalAccountBinding)>, LocalApiError> {
        let state = self.state()?;
        Ok(state
            .pending_auth
            .as_ref()
            .map(|claim| (claim.clone(), state.account.clone())))
    }

    pub fn begin_auth_with_claim(
        &self,
        claim: PendingAuthClaim,
    ) -> Result<AuthStartResponse, LocalApiError> {
        let mut state = self.state()?;
        let mut previous_account = state.account.clone();
        // A binding whose account was deleted server-side is unbound for claim
        // purposes: drop the dead identity so the fresh claim proceeds as a
        // first claim for ANY user (and the UI doesn't show a ghost account).
        if account_binding_is_account_not_found(&previous_account) {
            previous_account = LocalAccountBinding::not_connected();
        }
        // A fresh claim supersedes any staged switch from an earlier claim —
        // the staged claim's backend completion is single-use anyway.
        state.pending_switch = None;
        state.pending_auth = Some(claim.clone());
        state.account = LocalAccountBinding {
            state: LocalAccountState::ClaimPending,
            user: previous_account.user,
            organization: previous_account.organization,
            connected_at: previous_account.connected_at,
            last_refreshed_at: Some(state.now.clone()),
            message: Some(StableMessage {
                code: "claim_pending".to_string(),
                text: "Waiting for browser sign-in to finish.".to_string(),
            }),
            can_reconnect: None,
        };
        Ok(AuthStartResponse {
            account: state.account.clone(),
            claim_code: claim.claim_code,
            claim_url: claim.claim_url,
            nonce: claim.nonce,
            expires_at: claim.expires_at,
        })
    }

    pub fn pending_auth_claim(
        &self,
        claim_code: &str,
        nonce: &str,
    ) -> Result<PendingAuthClaim, LocalApiError> {
        let state = self.state()?;
        let Some(claim) = &state.pending_auth else {
            return Err(LocalApiError::NoPendingAuthClaim);
        };
        if claim.claim_code != claim_code || claim.nonce != nonce {
            return Err(LocalApiError::AuthClaimMismatch);
        }
        Ok(claim.clone())
    }

    pub fn pending_auth_claim_for_resume(
        &self,
        claim_code: &str,
    ) -> Result<PendingAuthClaim, LocalApiError> {
        let state = self.state()?;
        let Some(claim) = &state.pending_auth else {
            return Err(LocalApiError::NoPendingAuthClaim);
        };
        if claim.claim_code != claim_code {
            return Err(LocalApiError::AuthClaimMismatch);
        }
        Ok(claim.clone())
    }

    pub fn complete_auth_with_account(
        &self,
        claim_code: &str,
        nonce: &str,
        account: LocalAccountBinding,
        setup_run_id: String,
        setup_run_token_expires_at: String,
        machine_id: Option<String>,
    ) -> Result<AuthCompleteResponse, LocalApiError> {
        let mut state = self.state()?;
        let Some(claim) = &state.pending_auth else {
            return Err(LocalApiError::NoPendingAuthClaim);
        };
        if claim.claim_code != claim_code || claim.nonce != nonce {
            return Err(LocalApiError::AuthClaimMismatch);
        }
        // A binding whose account was deleted server-side (`account_not_found`)
        // is unbound for claim purposes: any user may claim fresh without the
        // reset ceremony.
        if !account_binding_is_account_not_found(&state.account) {
            if let Some(existing_user) = bound_user(&state.account) {
                if let Some(new_user) = bound_user(&account) {
                    if existing_user.id != new_user.id {
                        state.account.state = LocalAccountState::ResetRequired;
                        state.account.message = Some(StableMessage {
                            code: "account_reset_required".to_string(),
                            text: "This Mac is connected to a different Ottto account.".to_string(),
                        });
                        return Err(LocalApiError::AccountResetRequired);
                    }
                }
            }
        }
        state.pending_auth = None;
        state.pending_switch = None;
        state.connection = Some(LocalConnectionBinding {
            setup_run_id: setup_run_id.clone(),
            setup_run_token_expires_at: setup_run_token_expires_at.clone(),
            machine_id: machine_id.clone(),
            claim_code: Some(claim_code.to_string()),
            api_base_url: default_connection_api_base_url(),
        });
        clear_setup_run_read_rejection(&mut state);
        clear_local_health_upload_auth_rejection(&mut state);
        state.account = account.clone();
        Ok(AuthCompleteResponse {
            account,
            setup_run_id,
            setup_run_token_expires_at,
            machine_id,
        })
    }

    /// If the completed claim belongs to a different user than the current
    /// binding, stage it for an explicit `auth_switch_account` confirmation and
    /// return the display-safe candidate info. Returns `Ok(None)` when the
    /// claim may proceed as a normal completion (same user, no bound user, or
    /// the previous account no longer exists server-side).
    ///
    /// On staging, the account transitions to `ResetRequired` with the
    /// long-standing `account_reset_required` message so pre-switch clients
    /// keep their existing reset flow; the pending claim is consumed (the
    /// backend completion is single-use).
    pub fn stage_account_switch_if_user_mismatch(
        &self,
        staged: StagedAccountSwitch,
    ) -> Result<Option<AccountSwitchCandidateInfo>, LocalApiError> {
        let mut state = self.state()?;
        if account_binding_is_account_not_found(&state.account) {
            return Ok(None);
        }
        let Some(existing_user) = bound_user(&state.account) else {
            return Ok(None);
        };
        let Some(new_user) = bound_user(&staged.new_account) else {
            return Ok(None);
        };
        if existing_user.id == new_user.id {
            return Ok(None);
        }
        let info = AccountSwitchCandidateInfo {
            current_user_email: existing_user.email.clone(),
            new_user_email: new_user.email.clone(),
            new_organization_name: staged
                .new_account
                .organization
                .as_ref()
                .map(|organization| organization.name.clone())
                .unwrap_or_else(|| "Unknown workspace".to_string()),
            claim_code: staged.claim_code.clone(),
        };
        state.pending_auth = None;
        state.pending_switch = Some(staged);
        state.account.state = LocalAccountState::ResetRequired;
        state.account.last_refreshed_at = Some(state.now.clone());
        state.account.message = Some(StableMessage {
            code: "account_reset_required".to_string(),
            text: "This Mac is connected to a different Ottto account.".to_string(),
        });
        Ok(Some(info))
    }

    /// Consume the staged account switch for `claim_code`. Errors when nothing
    /// is staged (or a different claim is staged) so a stray confirm cannot
    /// install stale credentials.
    pub fn require_staged_account_switch(&self, claim_code: &str) -> Result<(), LocalApiError> {
        let state = self.state()?;
        match state.pending_switch.as_ref() {
            Some(staged) if staged.claim_code == claim_code => Ok(()),
            Some(_) | None => Err(LocalApiError::InvalidRequest(
                "no staged account switch for this sign-in claim; start Sign in again".to_string(),
            )),
        }
    }

    /// Return the exact user-approved switch candidate before any cleanup or
    /// destructive consume step. The caller durably records confirmation of a
    /// modern credential preparation from this snapshot so a process crash
    /// cannot forget the user's explicit switch intent.
    pub fn staged_account_switch_snapshot(
        &self,
        claim_code: &str,
    ) -> Result<StagedAccountSwitch, LocalApiError> {
        let state = self.state()?;
        match state.pending_switch.as_ref() {
            Some(staged) if staged.claim_code == claim_code => Ok(staged.clone()),
            Some(_) | None => Err(LocalApiError::InvalidRequest(
                "no staged account switch for this sign-in claim; start Sign in again".to_string(),
            )),
        }
    }

    /// Consume the previously validated staged account switch. The separate
    /// read-only validation lets trust-boundary preflights fail before this
    /// method mutates retry state.
    pub fn take_staged_account_switch(
        &self,
        claim_code: &str,
    ) -> Result<StagedAccountSwitch, LocalApiError> {
        let mut state = self.state()?;
        match state.pending_switch.as_ref() {
            Some(staged) if staged.claim_code == claim_code => {
                Ok(state.pending_switch.take().expect("checked above"))
            }
            Some(_) | None => Err(LocalApiError::InvalidRequest(
                "no staged account switch for this sign-in claim; start Sign in again".to_string(),
            )),
        }
    }

    /// Re-stage a switch that failed mid-install so the client can retry the
    /// confirmation instead of restarting the whole browser claim.
    pub fn restore_staged_account_switch(
        &self,
        staged: StagedAccountSwitch,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state.pending_switch.is_none() {
            state.pending_switch = Some(staged);
        }
        Ok(())
    }

    /// Install a confirmed account switch as the new binding in one state
    /// transition (no intermediate `ResetRequired`/`NotConnected` exposure to
    /// status readers between the reset and the install).
    pub fn install_switched_account(
        &self,
        account: LocalAccountBinding,
        setup_run_id: String,
        setup_run_token_expires_at: String,
        machine_id: Option<String>,
        claim_code: &str,
    ) -> Result<AuthCompleteResponse, LocalApiError> {
        let mut state = self.state()?;
        state.pending_auth = None;
        state.pending_switch = None;
        state.sources.clear();
        state.clear_source_state();
        state.connection = Some(LocalConnectionBinding {
            setup_run_id: setup_run_id.clone(),
            setup_run_token_expires_at: setup_run_token_expires_at.clone(),
            machine_id: machine_id.clone(),
            claim_code: Some(claim_code.to_string()),
            api_base_url: default_connection_api_base_url(),
        });
        clear_setup_run_read_rejection(&mut state);
        clear_local_health_upload_auth_rejection(&mut state);
        state.account = account.clone();
        Ok(AuthCompleteResponse {
            account,
            setup_run_id,
            setup_run_token_expires_at,
            machine_id,
        })
    }

    /// Transition the binding to the unbound-equivalent `account_not_found`
    /// state after the backend reports the bound account no longer exists.
    /// Keeps the last-known user for display ("previous account no longer
    /// exists") while freeing the Mac for a fresh first claim by any user.
    /// Idempotent; no-op when nothing is bound.
    pub fn mark_account_not_found(&self) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state.account.state == LocalAccountState::NotConnected {
            return Ok(());
        }
        if account_binding_is_account_not_found(&state.account) {
            return Ok(());
        }
        state.account.state = LocalAccountState::Error;
        state.account.last_refreshed_at = Some(state.now.clone());
        state.account.message = Some(StableMessage {
            code: ACCOUNT_NOT_FOUND_MESSAGE_CODE.to_string(),
            text: "The Ottto account this Mac was connected to no longer exists. Sign in to connect it to an account.".to_string(),
        });
        Ok(())
    }

    /// Registration requested browser consent. Preserve the bound account and
    /// candidate; expose the existing sign-in action instead of a failed setup.
    pub(crate) fn mark_history_choice_required(&self) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        state.account.state = LocalAccountState::ReattachRequired;
        state.account.message = Some(StableMessage {
            code: "history_choice_required".to_string(),
            text: "Waiting for browser sign-in to finish.".to_string(),
        });
        state.account.can_reconnect = Some(true);
        Ok(())
    }

    /// Keep the pending browser claim resumable while exposing an actionable,
    /// typed device-authority conflict instead of an endless claim-pending loop.
    pub fn mark_reattach_required(
        &self,
        message: StableMessage,
        can_reconnect: bool,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state.pending_auth.is_none() {
            return Err(LocalApiError::NoPendingAuthClaim);
        }
        state.account.state = LocalAccountState::ReattachRequired;
        state.account.user = None;
        state.account.organization = None;
        state.account.connected_at = None;
        state.account.last_refreshed_at = Some(state.now.clone());
        state.account.message = Some(message);
        state.account.can_reconnect = Some(can_reconnect);
        Ok(())
    }

    pub fn completed_auth_claim_for_resume(
        &self,
        claim_code: &str,
    ) -> Result<Option<AuthCompleteResponse>, LocalApiError> {
        let state = self.state()?;
        let Some(connection) = &state.connection else {
            return Ok(None);
        };
        if connection.claim_code.as_deref() != Some(claim_code) {
            return Ok(None);
        }
        if state.account.state != LocalAccountState::Connected {
            return Ok(None);
        }
        Ok(Some(AuthCompleteResponse {
            account: state.account.clone(),
            setup_run_id: connection.setup_run_id.clone(),
            setup_run_token_expires_at: connection.setup_run_token_expires_at.clone(),
            machine_id: connection.machine_id.clone(),
        }))
    }

    pub fn clear_recoverable_pending_auth_for_authorized_client(
        &self,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state.account.state != LocalAccountState::ClaimPending {
            return Ok(());
        }
        if state.connection.is_none() || state.account.user.is_none() {
            return Ok(());
        }
        state.pending_auth = None;
        state.account.state = LocalAccountState::Connected;
        state.account.last_refreshed_at = Some(state.now.clone());
        state.account.message = None;
        Ok(())
    }

    pub fn reset_account_for_authorized_client(&self) -> Result<AuthResetResponse, LocalApiError> {
        let mut state = self.state()?;
        let removed_account = if state.account.state == LocalAccountState::NotConnected {
            None
        } else {
            Some(state.account.clone())
        };
        state.account = LocalAccountBinding::not_connected();
        state.connection = None;
        clear_setup_run_read_rejection(&mut state);
        state.pending_auth = None;
        state.pending_switch = None;
        state.sources.clear();
        state.clear_source_state();
        Ok(AuthResetResponse {
            account: state.account.clone(),
            removed_account,
            local_only: true,
            cloud_disconnected: false,
            setup_run_id: None,
            disconnected_at: None,
            device_released: None,
            message: StableMessage {
                code: "disconnected".to_string(),
                text: "This Mac is disconnected from Ottto.".to_string(),
            },
        })
    }

    pub fn connection_for_authorized_client(
        &self,
    ) -> Result<Option<LocalConnectionBinding>, LocalApiError> {
        self.connection_for_authorized_client_with(load_persisted_connection)
    }

    pub(crate) fn connection_for_authorized_client_with<F>(
        &self,
        load_connection: F,
    ) -> Result<Option<LocalConnectionBinding>, LocalApiError>
    where
        F: FnOnce() -> Result<Option<LocalConnectionBinding>, LocalApiError>,
    {
        let mut state = self.state()?;
        load_connection_into(&mut state, load_connection)
    }

    /// The setup-run binding an agent read starts with, together with the
    /// read-rejection revision it starts from. Both are captured under one
    /// state lock, so the revision describes exactly what this binding's
    /// reads had recorded when this read began.
    pub(crate) fn setup_run_read_start(&self) -> Result<Option<SetupRunReadStart>, LocalApiError> {
        let mut state = self.state()?;
        let Some(binding) = load_connection_into(&mut state, load_persisted_connection)? else {
            return Ok(None);
        };
        Ok(Some(SetupRunReadStart {
            binding,
            revision: setup_run_read_revision(&state.local_health_events),
        }))
    }

    pub fn bind_setup_run_for_authorized_client(
        &self,
        connection: LocalConnectionBinding,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        let replaces_binding = !state
            .connection
            .as_ref()
            .is_some_and(|current| setup_run_binding_matches(current, &connection));
        state.connection = Some(connection);
        if replaces_binding {
            clear_setup_run_read_rejection(&mut state);
        }
        Ok(())
    }

    pub fn clear_setup_run_for_authorized_client_if_matches(
        &self,
        setup_run_id: &str,
        api_base_url: &str,
    ) -> Result<bool, LocalApiError> {
        let mut state = self.state()?;
        let Some(connection) = state.connection.as_ref() else {
            return Ok(false);
        };
        if connection.setup_run_id != setup_run_id || connection.api_base_url != api_base_url {
            return Ok(false);
        }
        state.connection = None;
        clear_setup_run_read_rejection(&mut state);
        Ok(true)
    }

    pub fn stop(&self, token: &str) -> Result<(), LocalApiError> {
        self.control_token.authorize(token)?;
        self.stop_authorized()
    }

    pub fn stop_for_trusted_client(&self) -> Result<(), LocalApiError> {
        self.stop_authorized()
    }

    fn stop_authorized(&self) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        state.running = false;
        drop(state);
        agent_status_refresh::stop();
        agent_status::stop_codex_quota_scheduler();
        Ok(())
    }

    pub(crate) fn state(&self) -> Result<MutexGuard<'_, DaemonState>, LocalApiError> {
        self.inner.lock().map_err(|_| LocalApiError::StatePoisoned)
    }
}

fn load_persisted_connection() -> Result<Option<LocalConnectionBinding>, LocalApiError> {
    FileConnectionStore::default()
        .load()
        .map_err(|_| LocalApiError::StatePoisoned)
}

fn load_connection_into<F>(
    state: &mut DaemonState,
    load_connection: F,
) -> Result<Option<LocalConnectionBinding>, LocalApiError>
where
    F: FnOnce() -> Result<Option<LocalConnectionBinding>, LocalApiError>,
{
    if state.connection.is_none() {
        if let Some(connection) = load_connection()? {
            state.connection = Some(connection);
        }
    }
    Ok(state.connection.clone())
}

fn setup_run_binding_matches(
    current: &LocalConnectionBinding,
    replacement: &LocalConnectionBinding,
) -> bool {
    current.setup_run_id == replacement.setup_run_id
        && current.api_base_url == replacement.api_base_url
}

mod tests;
