//! Consented, post-expiry Claude Code credential upkeep for registered custom
//! slots.
//!
//! The only vendor command this module may spawn is the resolved installed
//! `claude` binary with argv `doctor`. It never handles tokens, invokes a shell,
//! initiates login, or calls an OAuth endpoint. Success is proved only by a
//! read-only post-command metadata observation whose access expiry advanced.

use crate::agent_status::{
    read_claude_oauth_credential_metadata_for_slot, ClaudeOAuthCredentialMetadata,
};
use ottto_core::{
    default_support_dir, write_owner_only_file_atomic, ClaudeConfigDirSlot,
    FileClaudeConfigSlotSettingsStore,
};
use ottto_protocol::{
    ClaudeAccountUpkeepConsentState, ClaudeConfigSlotDescriptorV1, ClaudeConfigSlotUpkeepResultV1,
    ClaudeConfigSlotUpkeepStatusV1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const UPKEEP_STATE_SCHEMA_VERSION: u16 = 1;
const UPKEEP_STATE_FILE: &str = "claude-background-upkeep-state.json";
const UPKEEP_STATE_LOCK_FILE: &str = ".claude-background-upkeep-state.lock";
/// Operational stop: absent means normal consent/network-gated GA behavior.
pub(crate) const UPKEEP_DISABLED_FILE: &str = "claude-background-upkeep-disabled";
const DOCTOR_TIMEOUT: Duration = Duration::from_secs(20);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(50);
const RELLOGIN_APPROACHING_SECONDS: i64 = 72 * 60 * 60;
const INITIAL_BACKOFF_SECONDS: i64 = 5 * 60;
const MAX_BACKOFF_SECONDS: i64 = 6 * 60 * 60;

static UPKEEP_STATE_TRANSACTION: OnceLock<Mutex<()>> = OnceLock::new();
static PRODUCTION_UPKEEP_QUEUE: OnceLock<Mutex<ProductionUpkeepQueue>> = OnceLock::new();

#[derive(Default)]
struct ProductionUpkeepQueue {
    running: bool,
    queued_slot_ids: BTreeSet<String>,
    descriptors: VecDeque<ClaudeConfigSlotDescriptorV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeUpkeepObservation {
    pub(crate) proceed_with_collection: bool,
    pub(crate) status: ClaudeConfigSlotUpkeepStatusV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedUpkeepStateV1 {
    schema_version: u16,
    #[serde(default)]
    slots: BTreeMap<String, PersistedUpkeepWitnessV1>,
}

impl Default for PersistedUpkeepStateV1 {
    fn default() -> Self {
        Self {
            schema_version: UPKEEP_STATE_SCHEMA_VERSION,
            slots: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedUpkeepWitnessV1 {
    due_access_expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token_expires_at: Option<String>,
    attempted_at: String,
    next_allowed_attempt_at: String,
    result: ClaudeConfigSlotUpkeepResultV1,
    consecutive_failures: u32,
}

impl PersistedUpkeepWitnessV1 {
    fn local_status(&self) -> ClaudeConfigSlotUpkeepStatusV1 {
        ClaudeConfigSlotUpkeepStatusV1 {
            result: self.result,
            due_access_expires_at: Some(self.due_access_expires_at.clone()),
            refresh_token_expires_at: self.refresh_token_expires_at.clone(),
            attempted_at: Some(self.attempted_at.clone()),
            next_allowed_attempt_at: Some(self.next_allowed_attempt_at.clone()),
            consecutive_failures: self.consecutive_failures,
        }
    }
}

struct UpkeepStateGuard {
    _process: std::sync::MutexGuard<'static, ()>,
    file: File,
}

impl Drop for UpkeepStateGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimToken {
    slot_id: String,
    due_access_expires_at: String,
    attempted_at: String,
    previous_failures: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaimOutcome {
    Claimed(ClaimToken, ClaudeConfigSlotUpkeepStatusV1),
    Deferred(ClaudeConfigSlotUpkeepStatusV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DoctorProcessResult {
    ExitZero,
    MissingBinary,
    SpawnFailed,
    TimedOut,
    NonzeroExit,
}

trait UpkeepClock {
    fn now(&self) -> OffsetDateTime;
}

struct SystemClock;

impl UpkeepClock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

trait CredentialMetadataReader {
    fn read(&self, slot: &ClaudeConfigDirSlot) -> Option<ClaudeOAuthCredentialMetadata>;
}

struct ProductionCredentialMetadataReader;

impl CredentialMetadataReader for ProductionCredentialMetadataReader {
    fn read(&self, slot: &ClaudeConfigDirSlot) -> Option<ClaudeOAuthCredentialMetadata> {
        read_claude_oauth_credential_metadata_for_slot(slot)
    }
}

trait DoctorProcessRunner {
    fn run(&self, config_dir: &str, timeout: Duration) -> DoctorProcessResult;

    fn start(&self, config_dir: &str) -> DoctorProcessStart {
        DoctorProcessStart::Finished(self.run(config_dir, DOCTOR_TIMEOUT))
    }
}

enum DoctorProcessStart {
    Started(std::process::Child),
    Finished(DoctorProcessResult),
}

impl DoctorProcessStart {
    fn wait(self, timeout: Duration) -> DoctorProcessResult {
        match self {
            Self::Finished(result) => result,
            Self::Started(child) => wait_for_doctor_process(child, timeout),
        }
    }
}

trait FinalSpawnGate {
    fn start_if_allowed(
        &self,
        descriptor: &ClaudeConfigSlotDescriptorV1,
        process: &dyn DoctorProcessRunner,
        config_dir: &str,
    ) -> Result<DoctorProcessStart, ClaudeConfigSlotUpkeepResultV1>;
}

#[cfg(test)]
struct FixedFinalSpawnGate<'a> {
    consent: bool,
    network_enabled: bool,
    support_dir: &'a Path,
}

#[cfg(test)]
impl FinalSpawnGate for FixedFinalSpawnGate<'_> {
    fn start_if_allowed(
        &self,
        _descriptor: &ClaudeConfigSlotDescriptorV1,
        process: &dyn DoctorProcessRunner,
        config_dir: &str,
    ) -> Result<DoctorProcessStart, ClaudeConfigSlotUpkeepResultV1> {
        if !self.network_enabled {
            return Err(ClaudeConfigSlotUpkeepResultV1::CollectionPaused);
        }
        if !self.consent {
            return Err(ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented);
        }
        if self.support_dir.join(UPKEEP_DISABLED_FILE).is_file() {
            return Err(ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled);
        }
        Ok(process.start(config_dir))
    }
}

struct ProductionFinalSpawnGate;

impl FinalSpawnGate for ProductionFinalSpawnGate {
    fn start_if_allowed(
        &self,
        descriptor: &ClaudeConfigSlotDescriptorV1,
        process: &dyn DoctorProcessRunner,
        config_dir: &str,
    ) -> Result<DoctorProcessStart, ClaudeConfigSlotUpkeepResultV1> {
        FileClaudeConfigSlotSettingsStore::default()
            .with_locked_status(|status| {
                if status.consent != ClaudeAccountUpkeepConsentState::Granted {
                    return Err(ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented);
                }
                let still_registered = status
                    .managed_slots
                    .iter()
                    .chain(status.external_slots.iter())
                    .any(|current| current == descriptor);
                if !still_registered {
                    return Err(ClaudeConfigSlotUpkeepResultV1::NeedsLogin);
                }
                if crate::agent_status::claude_oauth_usage_network_disabled() {
                    return Err(ClaudeConfigSlotUpkeepResultV1::CollectionPaused);
                }
                if default_support_dir().join(UPKEEP_DISABLED_FILE).is_file() {
                    return Err(ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled);
                }
                // Serialize the final consent/removal check with process spawn,
                // then release settings before the bounded wait.
                Ok(process.start(config_dir))
            })
            .unwrap_or(Err(ClaudeConfigSlotUpkeepResultV1::ProbeFailed))
    }
}

struct ProductionDoctorProcessRunner;

impl DoctorProcessRunner for ProductionDoctorProcessRunner {
    fn run(&self, config_dir: &str, timeout: Duration) -> DoctorProcessResult {
        run_doctor_process(config_dir, timeout)
    }

    fn start(&self, config_dir: &str) -> DoctorProcessStart {
        start_doctor_process(config_dir)
    }
}

pub(crate) fn observe_registered_slot_upkeep(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    consent: bool,
    network_enabled: bool,
) -> ClaudeUpkeepObservation {
    let now = OffsetDateTime::now_utc();
    let metadata = ClaudeOAuthCredentialMetadata {
        access_expires_at: descriptor.collection.access_expires_at.clone(),
        refresh_token_expires_at: descriptor.collection.relogin_required_at.clone(),
        // Persisted local status intentionally records deadlines, not grant
        // contents. The background worker performs the authoritative read.
        has_refresh_token: true,
    };
    if !network_enabled {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
            &metadata,
        );
    }
    let Some(access_expiry) = parse_timestamp(metadata.access_expires_at.as_deref()) else {
        return observation_with_metadata(
            true,
            ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
            &metadata,
        );
    };
    if access_expiry > now {
        let approaching = parse_timestamp(metadata.refresh_token_expires_at.as_deref())
            .is_some_and(|expiry| {
                expiry > now && expiry - now <= TimeDuration::seconds(RELLOGIN_APPROACHING_SECONDS)
            });
        return observation_with_metadata(
            true,
            if approaching {
                ClaudeConfigSlotUpkeepResultV1::ReloginApproaching
            } else if consent {
                ClaudeConfigSlotUpkeepResultV1::NotRequired
            } else {
                ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented
            },
            &metadata,
        );
    }
    if descriptor
        .collection
        .upkeep
        .as_ref()
        .is_some_and(|status| status.result == ClaudeConfigSlotUpkeepResultV1::NeedsLogin)
    {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::NeedsLogin,
            &metadata,
        );
    }
    if !consent {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented,
            &metadata,
        );
    }
    if default_support_dir().join(UPKEEP_DISABLED_FILE).is_file() {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled,
            &metadata,
        );
    }
    enqueue_production_upkeep(descriptor.clone());
    observation_with_metadata(false, ClaudeConfigSlotUpkeepResultV1::InProgress, &metadata)
}

fn enqueue_production_upkeep(descriptor: ClaudeConfigSlotDescriptorV1) {
    let queue =
        PRODUCTION_UPKEEP_QUEUE.get_or_init(|| Mutex::new(ProductionUpkeepQueue::default()));
    let should_spawn = {
        let mut queue = queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if queue.queued_slot_ids.insert(descriptor.slot_id.clone()) {
            queue.descriptors.push_back(descriptor);
        }
        if queue.running {
            false
        } else {
            queue.running = true;
            true
        }
    };
    if !should_spawn {
        return;
    }
    let spawn = thread::Builder::new()
        .name("ottto-claude-upkeep".to_string())
        .spawn(run_production_upkeep_queue);
    if spawn.is_err() {
        let mut queue = queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.running = false;
        queue.queued_slot_ids.clear();
        queue.descriptors.clear();
    }
}

fn run_production_upkeep_queue() {
    let queue =
        PRODUCTION_UPKEEP_QUEUE.get_or_init(|| Mutex::new(ProductionUpkeepQueue::default()));
    loop {
        let descriptor = {
            let mut queue = queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(descriptor) = queue.descriptors.pop_front() else {
                queue.running = false;
                break;
            };
            descriptor
        };
        let observation = observe_registered_slot_upkeep_with_gate(
            &descriptor,
            true,
            true,
            &default_support_dir(),
            &SystemClock,
            &ProductionCredentialMetadataReader,
            &ProductionDoctorProcessRunner,
            &ProductionFinalSpawnGate,
        );
        if observation.status.result == ClaudeConfigSlotUpkeepResultV1::Refreshed {
            crate::snapshot_sync::spawn_claude_agent_status_refresh("upkeep");
        }
        queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queued_slot_ids
            .remove(&descriptor.slot_id);
    }
}

#[cfg(test)]
fn observe_registered_slot_upkeep_with(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    consent: bool,
    network_enabled: bool,
    support_dir: &Path,
    clock: &dyn UpkeepClock,
    credentials: &dyn CredentialMetadataReader,
    process: &dyn DoctorProcessRunner,
) -> ClaudeUpkeepObservation {
    let gate = FixedFinalSpawnGate {
        consent,
        network_enabled,
        support_dir,
    };
    observe_registered_slot_upkeep_with_gate(
        descriptor,
        consent,
        network_enabled,
        support_dir,
        clock,
        credentials,
        process,
        &gate,
    )
}

#[allow(clippy::too_many_arguments)]
fn observe_registered_slot_upkeep_with_gate(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    consent: bool,
    network_enabled: bool,
    support_dir: &Path,
    clock: &dyn UpkeepClock,
    credentials: &dyn CredentialMetadataReader,
    process: &dyn DoctorProcessRunner,
    final_gate: &dyn FinalSpawnGate,
) -> ClaudeUpkeepObservation {
    let Some(config_dir) = descriptor.config_dir.as_deref() else {
        // The default slot is intentionally never eligible.
        return observation(true, ClaudeConfigSlotUpkeepResultV1::NotRequired, None);
    };
    if !network_enabled {
        return observation(
            false,
            ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
            None,
        );
    }
    let now = clock.now();
    let Some(before) = credentials.read(
        &ClaudeConfigDirSlot::registered(config_dir.to_string())
            .expect("registered descriptor must retain a valid exact path"),
    ) else {
        return observation(
            true,
            ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
            None,
        );
    };
    let Some(access_expiry) = parse_timestamp(before.access_expires_at.as_deref()) else {
        return observation_with_metadata(
            true,
            ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
            &before,
        );
    };
    let refresh_expiry = parse_timestamp(before.refresh_token_expires_at.as_deref());
    let approaching = refresh_expiry.is_some_and(|expiry| {
        expiry > now && expiry - now <= TimeDuration::seconds(RELLOGIN_APPROACHING_SECONDS)
    });

    if access_expiry > now {
        let result = if approaching {
            ClaudeConfigSlotUpkeepResultV1::ReloginApproaching
        } else if consent {
            ClaudeConfigSlotUpkeepResultV1::NotRequired
        } else {
            ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented
        };
        return observation_with_metadata(true, result, &before);
    }
    // Claude Code can leave the old refresh deadline behind after signing out
    // while clearing both token strings. The deadline alone is therefore not
    // proof that `claude doctor` can refresh the credential. Fail directly to
    // the official-login state instead of spending the durable retry budget on
    // a command that cannot recover a missing refresh grant.
    if !before.has_refresh_token {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::NeedsLogin,
            &before,
        );
    }
    let Some(refresh_expiry) = refresh_expiry else {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::NeedsLogin,
            &before,
        );
    };
    if refresh_expiry <= now {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::NeedsLogin,
            &before,
        );
    }
    if !consent {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented,
            &before,
        );
    }
    if support_dir.join(UPKEEP_DISABLED_FILE).is_file() {
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled,
            &before,
        );
    }

    let due_access_expires_at = before
        .access_expires_at
        .clone()
        .expect("parsed access expiry must retain its source");
    let claim = match claim_attempt(
        support_dir,
        &descriptor.slot_id,
        &due_access_expires_at,
        before.refresh_token_expires_at.clone(),
        now,
    ) {
        Ok(claim) => claim,
        Err(()) => {
            return observation_with_metadata(
                false,
                ClaudeConfigSlotUpkeepResultV1::ProbeFailed,
                &before,
            )
        }
    };
    let (token, in_progress) = match claim {
        ClaimOutcome::Deferred(status) => {
            let result = if status.result == ClaudeConfigSlotUpkeepResultV1::InProgress {
                ClaudeConfigSlotUpkeepResultV1::InProgress
            } else {
                ClaudeConfigSlotUpkeepResultV1::Backoff
            };
            return ClaudeUpkeepObservation {
                proceed_with_collection: false,
                status: ClaudeConfigSlotUpkeepStatusV1 { result, ..status },
            };
        }
        ClaimOutcome::Claimed(token, status) => (token, status),
    };

    let process_start = match final_gate.start_if_allowed(descriptor, process, config_dir) {
        Ok(result) => result,
        Err(result) => {
            let completed = complete_attempt(support_dir, &token, result, clock.now()).unwrap_or(
                ClaudeConfigSlotUpkeepStatusV1 {
                    result: ClaudeConfigSlotUpkeepResultV1::ProbeFailed,
                    ..in_progress
                },
            );
            if result == ClaudeConfigSlotUpkeepResultV1::NeedsLogin {
                // A removal may commit after the initial descriptor snapshot
                // but before the final gate. Do not recreate its stale
                // per-slot witness after the control path pruned it.
                let _ = prune_slot_upkeep_state_at(support_dir, &descriptor.slot_id);
            }
            return ClaudeUpkeepObservation {
                proceed_with_collection: false,
                status: completed,
            };
        }
    };
    let (result, proceed) = match process_start.wait(DOCTOR_TIMEOUT) {
        DoctorProcessResult::ExitZero => match credentials.read(
            &ClaudeConfigDirSlot::registered(config_dir.to_string())
                .expect("registered descriptor must retain a valid exact path"),
        ) {
            Some(after)
                if parse_timestamp(after.access_expires_at.as_deref())
                    .is_some_and(|expiry| expiry > access_expiry && expiry > clock.now()) =>
            {
                (ClaudeConfigSlotUpkeepResultV1::Refreshed, true)
            }
            Some(_) => (ClaudeConfigSlotUpkeepResultV1::ExpiryUnchanged, false),
            None => (ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable, false),
        },
        DoctorProcessResult::MissingBinary => {
            (ClaudeConfigSlotUpkeepResultV1::MissingBinary, false)
        }
        DoctorProcessResult::SpawnFailed => (ClaudeConfigSlotUpkeepResultV1::SpawnFailed, false),
        DoctorProcessResult::TimedOut => (ClaudeConfigSlotUpkeepResultV1::TimedOut, false),
        DoctorProcessResult::NonzeroExit => (ClaudeConfigSlotUpkeepResultV1::NonzeroExit, false),
    };
    let completed = complete_attempt(support_dir, &token, result, clock.now()).unwrap_or(
        ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::ProbeFailed,
            ..in_progress
        },
    );
    ClaudeUpkeepObservation {
        proceed_with_collection: proceed,
        status: completed,
    }
}

fn observation(
    proceed_with_collection: bool,
    result: ClaudeConfigSlotUpkeepResultV1,
    witness: Option<&PersistedUpkeepWitnessV1>,
) -> ClaudeUpkeepObservation {
    ClaudeUpkeepObservation {
        proceed_with_collection,
        status: witness.map_or(
            ClaudeConfigSlotUpkeepStatusV1 {
                result,
                due_access_expires_at: None,
                refresh_token_expires_at: None,
                attempted_at: None,
                next_allowed_attempt_at: None,
                consecutive_failures: 0,
            },
            PersistedUpkeepWitnessV1::local_status,
        ),
    }
}

fn observation_with_metadata(
    proceed_with_collection: bool,
    result: ClaudeConfigSlotUpkeepResultV1,
    metadata: &ClaudeOAuthCredentialMetadata,
) -> ClaudeUpkeepObservation {
    ClaudeUpkeepObservation {
        proceed_with_collection,
        status: ClaudeConfigSlotUpkeepStatusV1 {
            result,
            due_access_expires_at: metadata.access_expires_at.clone(),
            refresh_token_expires_at: metadata.refresh_token_expires_at.clone(),
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        },
    }
}

fn claim_attempt(
    support_dir: &Path,
    slot_id: &str,
    due_access_expires_at: &str,
    refresh_token_expires_at: Option<String>,
    now: OffsetDateTime,
) -> Result<ClaimOutcome, ()> {
    let _guard = upkeep_state_guard(support_dir).map_err(|_| ())?;
    let mut state = load_state(support_dir)?;
    let now_text = format_timestamp(now)?;
    let previous = state.slots.get(slot_id).cloned();
    if let Some(existing) = previous.as_ref().filter(|witness| {
        witness.due_access_expires_at == due_access_expires_at
            && parse_timestamp(Some(&witness.next_allowed_attempt_at))
                .is_some_and(|next| now < next)
    }) {
        return Ok(ClaimOutcome::Deferred(existing.local_status()));
    }
    let previous_failures = previous
        .as_ref()
        .filter(|witness| witness.due_access_expires_at == due_access_expires_at)
        .map_or(0, |witness| {
            if witness.result == ClaudeConfigSlotUpkeepResultV1::InProgress {
                // Reaching this point means the persisted claim's deadline
                // elapsed without completion (process/daemon crash). Count
                // that abandoned attempt so repeated crashes back off
                // exponentially instead of retrying forever every five
                // minutes.
                witness.consecutive_failures.saturating_add(1)
            } else {
                witness.consecutive_failures
            }
        });
    let next_allowed = now + backoff_duration(previous_failures.saturating_add(1));
    let witness = PersistedUpkeepWitnessV1 {
        due_access_expires_at: due_access_expires_at.to_string(),
        refresh_token_expires_at,
        attempted_at: now_text.clone(),
        next_allowed_attempt_at: format_timestamp(next_allowed)?,
        result: ClaudeConfigSlotUpkeepResultV1::InProgress,
        consecutive_failures: previous_failures,
    };
    let status = witness.local_status();
    state.slots.insert(slot_id.to_string(), witness);
    write_state(support_dir, &state)?;
    Ok(ClaimOutcome::Claimed(
        ClaimToken {
            slot_id: slot_id.to_string(),
            due_access_expires_at: due_access_expires_at.to_string(),
            attempted_at: now_text,
            previous_failures,
        },
        status,
    ))
}

fn complete_attempt(
    support_dir: &Path,
    token: &ClaimToken,
    result: ClaudeConfigSlotUpkeepResultV1,
    now: OffsetDateTime,
) -> Result<ClaudeConfigSlotUpkeepStatusV1, ()> {
    let _guard = upkeep_state_guard(support_dir).map_err(|_| ())?;
    let mut state = load_state(support_dir)?;
    let witness = state.slots.get_mut(&token.slot_id).ok_or(())?;
    if witness.due_access_expires_at != token.due_access_expires_at
        || witness.attempted_at != token.attempted_at
        || witness.result != ClaudeConfigSlotUpkeepResultV1::InProgress
    {
        return Err(());
    }
    let success = result == ClaudeConfigSlotUpkeepResultV1::Refreshed;
    let neutral = matches!(
        result,
        ClaudeConfigSlotUpkeepResultV1::CollectionPaused
            | ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented
            | ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled
            | ClaudeConfigSlotUpkeepResultV1::NeedsLogin
    );
    witness.result = result;
    witness.consecutive_failures = if success {
        0
    } else if neutral {
        token.previous_failures
    } else {
        token.previous_failures.saturating_add(1)
    };
    witness.next_allowed_attempt_at = if neutral {
        format_timestamp(now)?
    } else {
        format_timestamp(now + backoff_duration(witness.consecutive_failures.max(1)))?
    };
    let status = witness.local_status();
    write_state(support_dir, &state)?;
    Ok(status)
}

fn backoff_duration(failures: u32) -> TimeDuration {
    let exponent = failures.saturating_sub(1).min(16);
    let factor = 1_i64.checked_shl(exponent).unwrap_or(i64::MAX);
    TimeDuration::seconds(
        INITIAL_BACKOFF_SECONDS
            .saturating_mul(factor)
            .min(MAX_BACKOFF_SECONDS),
    )
}

fn load_state(support_dir: &Path) -> Result<PersistedUpkeepStateV1, ()> {
    let path = support_dir.join(UPKEEP_STATE_FILE);
    if !path.exists() {
        return Ok(PersistedUpkeepStateV1::default());
    }
    let body = fs::read(&path).map_err(|_| ())?;
    let state = serde_json::from_slice::<PersistedUpkeepStateV1>(&body).map_err(|_| ())?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &PersistedUpkeepStateV1) -> Result<(), ()> {
    if state.schema_version != UPKEEP_STATE_SCHEMA_VERSION {
        return Err(());
    }
    for (slot_id, witness) in &state.slots {
        if slot_id.is_empty()
            || parse_timestamp(Some(&witness.due_access_expires_at)).is_none()
            || parse_timestamp(Some(&witness.attempted_at)).is_none()
            || parse_timestamp(Some(&witness.next_allowed_attempt_at)).is_none()
            || witness
                .refresh_token_expires_at
                .as_deref()
                .is_some_and(|value| parse_timestamp(Some(value)).is_none())
        {
            return Err(());
        }
    }
    Ok(())
}

fn write_state(support_dir: &Path, state: &PersistedUpkeepStateV1) -> Result<(), ()> {
    let body = serde_json::to_vec_pretty(state).map_err(|_| ())?;
    write_owner_only_file_atomic(&support_dir.join(UPKEEP_STATE_FILE), &body).map_err(|_| ())
}

pub(crate) fn prune_slot_upkeep_state(slot_id: &str) -> std::io::Result<()> {
    let support_dir = default_support_dir();
    prune_slot_upkeep_state_at(&support_dir, slot_id)
}

fn prune_slot_upkeep_state_at(support_dir: &Path, slot_id: &str) -> std::io::Result<()> {
    let _guard = upkeep_state_guard(support_dir)?;
    let mut state = load_state(support_dir).map_err(|()| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Claude upkeep state is invalid",
        )
    })?;
    if state.slots.remove(slot_id).is_some() {
        write_state(support_dir, &state)
            .map_err(|()| std::io::Error::other("write Claude upkeep state"))?;
    }
    Ok(())
}

fn upkeep_state_guard(support_dir: &Path) -> std::io::Result<UpkeepStateGuard> {
    let process = UPKEEP_STATE_TRANSACTION
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(support_dir)?;
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
            .open(support_dir.join(UPKEEP_STATE_LOCK_FILE))?;
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
        .open(support_dir.join(UPKEEP_STATE_LOCK_FILE))?;
    Ok(UpkeepStateGuard {
        _process: process,
        file,
    })
}

fn run_doctor_process(config_dir: &str, timeout: Duration) -> DoctorProcessResult {
    start_doctor_process(config_dir).wait(timeout)
}

fn start_doctor_process(config_dir: &str) -> DoctorProcessStart {
    let slot = ClaudeConfigDirSlot::registered(config_dir.to_string())
        .expect("registered descriptor must retain a valid exact path");
    let Some(mut command) = crate::agent_status::resolved_claude_slot_command(&slot, &["doctor"])
    else {
        return DoctorProcessStart::Finished(DoctorProcessResult::MissingBinary);
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(child) = command.spawn() else {
        return DoctorProcessStart::Finished(DoctorProcessResult::SpawnFailed);
    };
    DoctorProcessStart::Started(child)
}

fn wait_for_doctor_process(
    mut child: std::process::Child,
    timeout: Duration,
) -> DoctorProcessResult {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return DoctorProcessResult::ExitZero,
            Ok(Some(_)) => return DoctorProcessResult::NonzeroExit,
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return DoctorProcessResult::TimedOut;
            }
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return DoctorProcessResult::SpawnFailed;
            }
        }
    }
}

fn parse_timestamp(value: Option<&str>) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value?, &Rfc3339).ok()
}

fn format_timestamp(value: OffsetDateTime) -> Result<String, ()> {
    value.format(&Rfc3339).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{ClaudeConfigSlotOwnership, CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION};
    use serial_test::serial;
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    struct FixedClock(OffsetDateTime);

    impl UpkeepClock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    struct SequenceCredentials {
        values: Mutex<Vec<Option<ClaudeOAuthCredentialMetadata>>>,
    }

    impl SequenceCredentials {
        fn new(values: Vec<Option<ClaudeOAuthCredentialMetadata>>) -> Self {
            Self {
                values: Mutex::new(values.into_iter().rev().collect()),
            }
        }
    }

    impl CredentialMetadataReader for SequenceCredentials {
        fn read(&self, _slot: &ClaudeConfigDirSlot) -> Option<ClaudeOAuthCredentialMetadata> {
            self.values.lock().expect("credential sequence").pop()?
        }
    }

    struct FixedProcess(DoctorProcessResult);

    impl DoctorProcessRunner for FixedProcess {
        fn run(&self, _config_dir: &str, _timeout: Duration) -> DoctorProcessResult {
            self.0
        }
    }

    struct CountingProcess {
        result: DoctorProcessResult,
        calls: Arc<AtomicUsize>,
    }

    struct CountingCredentials {
        value: Option<ClaudeOAuthCredentialMetadata>,
        calls: Arc<AtomicUsize>,
    }

    impl CredentialMetadataReader for CountingCredentials {
        fn read(&self, _slot: &ClaudeConfigDirSlot) -> Option<ClaudeOAuthCredentialMetadata> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.value.clone()
        }
    }

    impl DoctorProcessRunner for CountingProcess {
        fn run(&self, _config_dir: &str, _timeout: Duration) -> DoctorProcessResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result
        }
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl Into<OsString>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value.into());
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.as_ref() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ottto-claude-upkeep-{label}-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        fs::create_dir_all(&path).expect("create test dir");
        path
    }

    fn descriptor() -> ClaudeConfigSlotDescriptorV1 {
        ClaudeConfigDirSlot::registered("/tmp/exact-claude-slot")
            .expect("slot")
            .descriptor(
                "claude_slot_0123456789abcdef0123456789abcdef",
                ClaudeConfigSlotOwnership::Managed,
            )
    }

    fn metadata(access: &str, refresh: &str) -> ClaudeOAuthCredentialMetadata {
        ClaudeOAuthCredentialMetadata {
            access_expires_at: Some(access.to_string()),
            refresh_token_expires_at: Some(refresh.to_string()),
            has_refresh_token: true,
        }
    }

    #[test]
    #[serial]
    fn five_due_registered_anchors_enqueue_without_blocking_collection_or_settings() {
        let root = temp_dir("five-due-production-queue");
        let _support_guard = EnvGuard::set(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        let store = FileClaudeConfigSlotSettingsStore::default();
        store
            .set_upkeep_consent(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                true,
            )
            .expect("grant upkeep consent");
        let mut descriptors = Vec::new();
        for index in 0..5 {
            let config_dir = root.join(format!("account-{index}"));
            fs::create_dir_all(&config_dir).expect("create config dir");
            let status = store
                .register_path(
                    ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                    config_dir.to_string_lossy().into_owned(),
                )
                .expect("register anchor");
            let mut descriptor = status
                .external_slots
                .last()
                .expect("registered slot")
                .clone();
            descriptor.collection.access_expires_at = Some("2020-01-01T00:00:00Z".to_string());
            descriptor.collection.relogin_required_at = Some("2099-01-01T00:00:00Z".to_string());
            descriptors.push(descriptor);
        }

        let collection_started = Instant::now();
        for descriptor in &descriptors {
            let observation = observe_registered_slot_upkeep(descriptor, true, true);
            assert!(!observation.proceed_with_collection);
            assert_eq!(
                observation.status.result,
                ClaudeConfigSlotUpkeepResultV1::InProgress
            );
        }
        assert!(
            collection_started.elapsed() < Duration::from_millis(250),
            "five due anchors must enqueue without synchronous credential or doctor waits"
        );

        let settings_started = Instant::now();
        store
            .set_upkeep_consent(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                false,
            )
            .expect("settings remain responsive while worker owns upkeep");
        assert!(
            settings_started.elapsed() < Duration::from_millis(250),
            "background upkeep must not retain the registry lock while waiting"
        );
        let drain_deadline = Instant::now() + Duration::from_secs(5);
        while PRODUCTION_UPKEEP_QUEUE.get().is_some_and(|queue| {
            !queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .queued_slot_ids
                .is_empty()
        }) && Instant::now() < drain_deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn expired_access_without_refresh_token_requires_login_without_spawning() {
        let now = "2026-08-04T10:00:00Z";
        let dir = temp_dir("missing-refresh-token");
        let calls = Arc::new(AtomicUsize::new(0));
        let observation = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            true,
            &dir,
            &FixedClock(at(now)),
            &SequenceCredentials::new(vec![Some(ClaudeOAuthCredentialMetadata {
                access_expires_at: Some("1970-01-01T00:00:00Z".to_string()),
                // Claude Code may retain this old deadline after clearing the
                // grant, so it must not make the credential look refreshable.
                refresh_token_expires_at: Some("2026-09-15T04:52:51Z".to_string()),
                has_refresh_token: false,
            })]),
            &CountingProcess {
                result: DoctorProcessResult::ExitZero,
                calls: Arc::clone(&calls),
            },
        );

        assert!(!observation.proceed_with_collection);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::NeedsLogin
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!dir.join(UPKEEP_STATE_FILE).exists());
    }

    fn at(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &Rfc3339).expect("timestamp")
    }

    #[test]
    fn before_expiry_never_spawns() {
        let dir = temp_dir("before-expiry");
        let observation = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            true,
            &dir,
            &FixedClock(at("2026-08-04T10:00:00Z")),
            &SequenceCredentials::new(vec![Some(metadata(
                "2026-08-04T10:00:01Z",
                "2026-08-20T00:00:00Z",
            ))]),
            &FixedProcess(DoctorProcessResult::NonzeroExit),
        );
        assert!(observation.proceed_with_collection);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::NotRequired
        );
        assert!(!dir.join(UPKEEP_STATE_FILE).exists());
    }

    #[test]
    fn expiry_boundary_succeeds_only_when_expiry_advances() {
        let now = "2026-08-04T10:00:00Z";
        let dir = temp_dir("advance");
        let observation = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            true,
            &dir,
            &FixedClock(at(now)),
            &SequenceCredentials::new(vec![
                Some(metadata(now, "2026-08-20T00:00:00Z")),
                Some(metadata("2026-08-04T18:00:00Z", "2026-08-20T00:00:00Z")),
            ]),
            &FixedProcess(DoctorProcessResult::ExitZero),
        );
        assert!(observation.proceed_with_collection);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::Refreshed
        );

        let unchanged_dir = temp_dir("unchanged");
        let unchanged = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            true,
            &unchanged_dir,
            &FixedClock(at(now)),
            &SequenceCredentials::new(vec![
                Some(metadata(now, "2026-08-20T00:00:00Z")),
                Some(metadata(now, "2026-08-20T00:00:00Z")),
            ]),
            &FixedProcess(DoctorProcessResult::ExitZero),
        );
        assert!(!unchanged.proceed_with_collection);
        assert_eq!(
            unchanged.status.result,
            ClaudeConfigSlotUpkeepResultV1::ExpiryUnchanged
        );
    }

    #[test]
    fn consent_network_kill_switch_and_refresh_deadline_fail_closed() {
        let now = "2026-08-04T10:00:00Z";
        for (label, consent, network, disabled, refresh, expected) in [
            (
                "no-consent",
                false,
                true,
                false,
                "2026-08-20T00:00:00Z",
                ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented,
            ),
            (
                "network-off",
                true,
                false,
                false,
                "2026-08-20T00:00:00Z",
                ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
            ),
            (
                "kill-switch",
                true,
                true,
                true,
                "2026-08-20T00:00:00Z",
                ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled,
            ),
            (
                "deadline",
                true,
                true,
                false,
                now,
                ClaudeConfigSlotUpkeepResultV1::NeedsLogin,
            ),
        ] {
            let dir = temp_dir(label);
            if disabled {
                fs::write(dir.join(UPKEEP_DISABLED_FILE), b"disabled\n").expect("kill switch");
            }
            let observation = observe_registered_slot_upkeep_with(
                &descriptor(),
                consent,
                network,
                &dir,
                &FixedClock(at(now)),
                &SequenceCredentials::new(vec![Some(metadata(now, refresh))]),
                &FixedProcess(DoctorProcessResult::ExitZero),
            );
            assert!(!observation.proceed_with_collection, "{label}");
            assert_eq!(observation.status.result, expected, "{label}");
            assert!(!dir.join(UPKEEP_STATE_FILE).exists(), "{label}");
            if network {
                assert_eq!(
                    observation.status.due_access_expires_at.as_deref(),
                    Some(now),
                    "{label} access deadline"
                );
                assert_eq!(
                    observation.status.refresh_token_expires_at.as_deref(),
                    Some(refresh),
                    "{label} refresh deadline"
                );
            } else {
                assert!(observation.status.due_access_expires_at.is_none());
                assert!(observation.status.refresh_token_expires_at.is_none());
            }
        }
    }

    #[test]
    fn network_off_switch_prevents_even_credential_metadata_reads() {
        let dir = temp_dir("network-no-read");
        let calls = Arc::new(AtomicUsize::new(0));
        let observation = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            false,
            &dir,
            &FixedClock(at("2026-08-04T10:00:00Z")),
            &CountingCredentials {
                value: Some(metadata("2026-08-04T10:00:00Z", "2026-08-20T00:00:00Z")),
                calls: Arc::clone(&calls),
            },
            &FixedProcess(DoctorProcessResult::ExitZero),
        );
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::CollectionPaused
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[serial]
    fn production_final_gate_rechecks_revoke_network_kill_and_removal_before_spawn() {
        let root = temp_dir("production-final-gate");
        let config_dir = root.join("custom");
        fs::create_dir_all(&config_dir).expect("config dir");
        let _support = EnvGuard::set(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        let store = FileClaudeConfigSlotSettingsStore::default();
        let status = store
            .register_path(
                CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                config_dir.to_string_lossy().into_owned(),
            )
            .expect("register");
        let descriptor = status.external_slots.first().expect("registered").clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let process = CountingProcess {
            result: DoctorProcessResult::ExitZero,
            calls: Arc::clone(&calls),
        };

        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, false)
            .expect("revoke");
        assert_eq!(
            ProductionFinalSpawnGate
                .start_if_allowed(
                    &descriptor,
                    &process,
                    descriptor.config_dir.as_deref().expect("config")
                )
                .map(|start| start.wait(DOCTOR_TIMEOUT)),
            Err(ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented)
        );

        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
            .expect("grant");
        fs::write(
            root.join(crate::agent_status::CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE),
            b"disabled\n",
        )
        .expect("network sentinel");
        assert_eq!(
            ProductionFinalSpawnGate
                .start_if_allowed(
                    &descriptor,
                    &process,
                    descriptor.config_dir.as_deref().expect("config")
                )
                .map(|start| start.wait(DOCTOR_TIMEOUT)),
            Err(ClaudeConfigSlotUpkeepResultV1::CollectionPaused)
        );
        fs::remove_file(root.join(crate::agent_status::CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE))
            .expect("remove network sentinel");

        fs::write(root.join(UPKEEP_DISABLED_FILE), b"disabled\n").expect("kill sentinel");
        assert_eq!(
            ProductionFinalSpawnGate
                .start_if_allowed(
                    &descriptor,
                    &process,
                    descriptor.config_dir.as_deref().expect("config")
                )
                .map(|start| start.wait(DOCTOR_TIMEOUT)),
            Err(ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled)
        );
        fs::remove_file(root.join(UPKEEP_DISABLED_FILE)).expect("remove kill sentinel");

        store
            .remove(
                CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                &descriptor.slot_id,
            )
            .expect("remove slot");
        assert_eq!(
            ProductionFinalSpawnGate
                .start_if_allowed(
                    &descriptor,
                    &process,
                    descriptor.config_dir.as_deref().expect("config")
                )
                .map(|start| start.wait(DOCTOR_TIMEOUT)),
            Err(ClaudeConfigSlotUpkeepResultV1::NeedsLogin)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refresh_deadline_within_72_hours_is_typed_but_allows_collection() {
        let dir = temp_dir("approaching");
        let observation = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            true,
            &dir,
            &FixedClock(at("2026-08-04T10:00:00Z")),
            &SequenceCredentials::new(vec![Some(metadata(
                "2026-08-04T11:00:00Z",
                "2026-08-07T09:59:59Z",
            ))]),
            &FixedProcess(DoctorProcessResult::ExitZero),
        );
        assert!(observation.proceed_with_collection);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::ReloginApproaching
        );
    }

    #[test]
    fn process_failure_classes_are_typed_and_backed_off() {
        let now = "2026-08-04T10:00:00Z";
        for (label, process_result, expected) in [
            (
                "missing",
                DoctorProcessResult::MissingBinary,
                ClaudeConfigSlotUpkeepResultV1::MissingBinary,
            ),
            (
                "spawn",
                DoctorProcessResult::SpawnFailed,
                ClaudeConfigSlotUpkeepResultV1::SpawnFailed,
            ),
            (
                "timeout",
                DoctorProcessResult::TimedOut,
                ClaudeConfigSlotUpkeepResultV1::TimedOut,
            ),
            (
                "nonzero",
                DoctorProcessResult::NonzeroExit,
                ClaudeConfigSlotUpkeepResultV1::NonzeroExit,
            ),
        ] {
            let dir = temp_dir(label);
            let observation = observe_registered_slot_upkeep_with(
                &descriptor(),
                true,
                true,
                &dir,
                &FixedClock(at(now)),
                &SequenceCredentials::new(vec![Some(metadata(now, "2026-08-20T00:00:00Z"))]),
                &FixedProcess(process_result),
            );
            assert!(!observation.proceed_with_collection, "{label}");
            assert_eq!(observation.status.result, expected, "{label}");
            assert_eq!(observation.status.consecutive_failures, 1, "{label}");
        }
    }

    #[test]
    fn same_expiry_threads_claim_once_and_restart_obeys_backoff() {
        let dir = Arc::new(temp_dir("threads"));
        let barrier = Arc::new(Barrier::new(9));
        let mut joins = Vec::new();
        for _ in 0..8 {
            let dir = Arc::clone(&dir);
            let barrier = Arc::clone(&barrier);
            joins.push(thread::spawn(move || {
                barrier.wait();
                claim_attempt(
                    &dir,
                    "claude_slot_0123456789abcdef0123456789abcdef",
                    "2026-08-04T10:00:00Z",
                    Some("2026-08-20T00:00:00Z".to_string()),
                    at("2026-08-04T10:00:00Z"),
                )
                .expect("claim")
            }));
        }
        barrier.wait();
        let claims = joins
            .into_iter()
            .map(|join| join.join().expect("join"))
            .filter(|outcome| matches!(outcome, ClaimOutcome::Claimed(..)))
            .count();
        assert_eq!(claims, 1);
        assert!(matches!(
            claim_attempt(
                &dir,
                "claude_slot_0123456789abcdef0123456789abcdef",
                "2026-08-04T10:00:00Z",
                Some("2026-08-20T00:00:00Z".to_string()),
                at("2026-08-04T10:04:59Z"),
            )
            .expect("restart backoff"),
            ClaimOutcome::Deferred(_)
        ));
        let second = claim_attempt(
            &dir,
            "claude_slot_0123456789abcdef0123456789abcdef",
            "2026-08-04T10:00:00Z",
            Some("2026-08-20T00:00:00Z".to_string()),
            at("2026-08-04T10:05:00Z"),
        )
        .expect("backoff elapsed");
        let ClaimOutcome::Claimed(_, second_status) = second else {
            panic!("second crash retry must claim");
        };
        assert_eq!(second_status.consecutive_failures, 1);
        assert_eq!(
            second_status.next_allowed_attempt_at.as_deref(),
            Some("2026-08-04T10:15:00Z")
        );
        assert!(matches!(
            claim_attempt(
                &dir,
                "claude_slot_0123456789abcdef0123456789abcdef",
                "2026-08-04T10:00:00Z",
                Some("2026-08-20T00:00:00Z".to_string()),
                at("2026-08-04T10:14:59Z"),
            )
            .expect("second crash backoff"),
            ClaimOutcome::Deferred(_)
        ));
        let third = claim_attempt(
            &dir,
            "claude_slot_0123456789abcdef0123456789abcdef",
            "2026-08-04T10:00:00Z",
            Some("2026-08-20T00:00:00Z".to_string()),
            at("2026-08-04T10:15:00Z"),
        )
        .expect("second backoff elapsed");
        let ClaimOutcome::Claimed(_, third_status) = third else {
            panic!("third crash retry must claim");
        };
        assert_eq!(third_status.consecutive_failures, 2);
        assert_eq!(
            third_status.next_allowed_attempt_at.as_deref(),
            Some("2026-08-04T10:35:00Z")
        );
        assert_eq!(backoff_duration(100), TimeDuration::hours(6));
    }

    #[test]
    fn default_slot_is_never_eligible() {
        let dir = temp_dir("default");
        let descriptor =
            ClaudeConfigDirSlot::Default.descriptor("default", ClaudeConfigSlotOwnership::External);
        let observation = observe_registered_slot_upkeep_with(
            &descriptor,
            true,
            true,
            &dir,
            &FixedClock(at("2026-08-04T10:00:00Z")),
            &SequenceCredentials::new(Vec::new()),
            &FixedProcess(DoctorProcessResult::ExitZero),
        );
        assert!(observation.proceed_with_collection);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::NotRequired
        );
        assert!(!dir.join(UPKEEP_STATE_FILE).exists());
    }

    #[test]
    fn persisted_witness_contains_only_safe_timestamps_slot_id_and_result() {
        let dir = temp_dir("secrecy");
        let _ = claim_attempt(
            &dir,
            "claude_slot_0123456789abcdef0123456789abcdef",
            "2026-08-04T10:00:00Z",
            Some("2026-08-20T00:00:00Z".to_string()),
            at("2026-08-04T10:00:00Z"),
        )
        .expect("claim");
        let body = fs::read_to_string(dir.join(UPKEEP_STATE_FILE)).expect("state");
        assert!(!body.contains("accessToken"));
        assert!(!body.contains("refreshToken"));
        assert!(!body.contains("CLAUDE_CONFIG_DIR"));
        assert!(!body.contains("/tmp/exact-claude-slot"));
        assert!(body.contains("due_access_expires_at"));
        assert!(body.contains("refresh_token_expires_at"));
        assert!(body.contains("in_progress"));
    }

    #[test]
    fn crash_after_success_before_completion_never_reprobes_a_fresh_credential() {
        let dir = temp_dir("crash-after-success");
        let _claim = claim_attempt(
            &dir,
            "claude_slot_0123456789abcdef0123456789abcdef",
            "2026-08-04T10:00:00Z",
            Some("2026-08-20T00:00:00Z".to_string()),
            at("2026-08-04T10:00:00Z"),
        )
        .expect("claim before simulated crash");
        let calls = Arc::new(AtomicUsize::new(0));
        let observation = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            true,
            &dir,
            &FixedClock(at("2026-08-04T10:00:10Z")),
            &SequenceCredentials::new(vec![Some(metadata(
                "2026-08-04T18:00:00Z",
                "2026-08-20T00:00:00Z",
            ))]),
            &CountingProcess {
                result: DoctorProcessResult::ExitZero,
                calls: Arc::clone(&calls),
            },
        );
        assert!(observation.proceed_with_collection);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::NotRequired
        );
    }

    struct SharedCredentialState {
        refreshed: Arc<AtomicBool>,
    }

    impl CredentialMetadataReader for SharedCredentialState {
        fn read(&self, _slot: &ClaudeConfigDirSlot) -> Option<ClaudeOAuthCredentialMetadata> {
            Some(if self.refreshed.load(Ordering::SeqCst) {
                metadata("2026-08-04T18:00:00Z", "2026-08-20T00:00:00Z")
            } else {
                metadata("2026-08-04T10:00:00Z", "2026-08-20T00:00:00Z")
            })
        }
    }

    struct RefreshingProcess {
        refreshed: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl DoctorProcessRunner for RefreshingProcess {
        fn run(&self, _config_dir: &str, _timeout: Duration) -> DoctorProcessResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.refreshed.store(true, Ordering::SeqCst);
            DoctorProcessResult::ExitZero
        }
    }

    #[test]
    fn startup_wake_and_collection_storm_spawn_one_doctor() {
        let dir = Arc::new(temp_dir("three-hooks"));
        let refreshed = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();
        for _opportunity in ["startup", "wake", "collection"] {
            let dir = Arc::clone(&dir);
            let refreshed = Arc::clone(&refreshed);
            let calls = Arc::clone(&calls);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                observe_registered_slot_upkeep_with(
                    &descriptor(),
                    true,
                    true,
                    &dir,
                    &FixedClock(at("2026-08-04T10:00:00Z")),
                    &SharedCredentialState {
                        refreshed: Arc::clone(&refreshed),
                    },
                    &RefreshingProcess { refreshed, calls },
                )
            }));
        }
        barrier.wait();
        let observations = workers
            .into_iter()
            .map(|worker| worker.join().expect("hook worker"))
            .collect::<Vec<_>>();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(observations
            .iter()
            .any(|result| { result.status.result == ClaudeConfigSlotUpkeepResultV1::Refreshed }));
    }

    #[test]
    fn one_failed_slot_does_not_suppress_a_sibling_due_boundary() {
        let dir = temp_dir("siblings");
        let first = observe_registered_slot_upkeep_with(
            &descriptor(),
            true,
            true,
            &dir,
            &FixedClock(at("2026-08-04T10:00:00Z")),
            &SequenceCredentials::new(vec![Some(metadata(
                "2026-08-04T10:00:00Z",
                "2026-08-20T00:00:00Z",
            ))]),
            &FixedProcess(DoctorProcessResult::NonzeroExit),
        );
        let mut sibling = descriptor();
        sibling.slot_id = "claude_slot_fedcba9876543210fedcba9876543210".to_string();
        let second = observe_registered_slot_upkeep_with(
            &sibling,
            true,
            true,
            &dir,
            &FixedClock(at("2026-08-04T10:00:00Z")),
            &SequenceCredentials::new(vec![
                Some(metadata("2026-08-04T10:00:00Z", "2026-08-20T00:00:00Z")),
                Some(metadata("2026-08-04T18:00:00Z", "2026-08-20T00:00:00Z")),
            ]),
            &FixedProcess(DoctorProcessResult::ExitZero),
        );
        assert_eq!(
            first.status.result,
            ClaudeConfigSlotUpkeepResultV1::NonzeroExit
        );
        assert_eq!(
            second.status.result,
            ClaudeConfigSlotUpkeepResultV1::Refreshed
        );
        assert!(second.proceed_with_collection);
    }

    #[test]
    #[serial]
    fn doctor_process_uses_exact_argv_shared_cleared_env_and_closed_streams() {
        let root = temp_dir("process-contract");
        let bin = root.join("bin");
        fs::create_dir_all(&bin).expect("bin");
        let capture = root.join("capture.txt");
        let script = format!(
            "#!/bin/sh\n{{\nprintf 'argc=%s\\n' \"$#\"\nprintf 'argv=%s\\n' \"$*\"\nprintf 'config=%s\\n' \"$CLAUDE_CONFIG_DIR\"\nprintf 'home=%s\\n' \"$HOME\"\nprintf 'user=%s\\n' \"$USER\"\nprintf 'provider=%s\\n' \"${{ANTHROPIC_API_KEY-unset}}\"\nprintf 'poison=%s\\n' \"${{OTTTO_SECRET_PROBE-unset}}\"\nif IFS= read -r ignored; then printf 'stdin=open\\n'; else printf 'stdin=closed\\n'; fi\n}} > \"{}\"\nprintf 'secret-shaped stdout'\nprintf 'secret-shaped stderr' >&2\n",
            capture.display()
        );
        let claude = bin.join("claude");
        fs::write(&claude, script).expect("fake claude");
        let mut permissions = fs::metadata(&claude).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&claude, permissions).expect("chmod");
        let _path = EnvGuard::set("OTTTO_COMMAND_SEARCH_PATH", bin.as_os_str());
        let effective_home = root.join("effective-home");
        fs::create_dir_all(&effective_home).expect("effective home");
        let _effective_home = EnvGuard::set(
            "OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS",
            effective_home.as_os_str(),
        );
        let _ambient_home = EnvGuard::set("HOME", "relative-ambient-home-must-not-win");
        let _provider = EnvGuard::set("ANTHROPIC_API_KEY", "must-not-survive");
        let _poison = EnvGuard::set("OTTTO_SECRET_PROBE", "must-not-survive");

        assert_eq!(
            run_doctor_process("/tmp/exact-claude-slot/", Duration::from_secs(2)),
            DoctorProcessResult::ExitZero
        );
        let observed = fs::read_to_string(capture).expect("capture");
        assert!(observed.contains("argc=1\n"));
        assert!(observed.contains("argv=doctor\n"));
        assert!(observed.contains("config=/tmp/exact-claude-slot/\n"));
        assert!(observed.contains("stdin=closed\n"));
        assert!(observed.contains("provider=unset\n"));
        assert!(observed.contains("poison=unset\n"));
        assert!(observed.contains(&format!("home={}\n", effective_home.display())));
        assert!(!observed.contains("relative-ambient-home-must-not-win"));
        assert!(observed
            .lines()
            .any(|line| line.starts_with("user=") && line.len() > 5));
        assert!(!observed.contains("--model"));
        assert!(!observed.contains("--prompt"));
    }

    #[test]
    fn multiprocess_claim_worker() {
        let Some(dir) = std::env::var_os("OTTTO_UPKEEP_MP_DIR") else {
            return;
        };
        if matches!(
            claim_attempt(
                Path::new(&dir),
                "claude_slot_0123456789abcdef0123456789abcdef",
                "2026-08-04T10:00:00Z",
                Some("2026-08-20T00:00:00Z".to_string()),
                at("2026-08-04T10:00:00Z"),
            )
            .expect("multiprocess claim"),
            ClaimOutcome::Claimed(..)
        ) {
            let mut claims = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&dir).join("claims.txt"))
                .expect("open claims");
            claims.write_all(b"claimed\n").expect("append claim");
        }
    }

    #[test]
    fn true_multiprocess_same_expiry_has_one_claim() {
        let dir = temp_dir("multiprocess");
        let executable = std::env::current_exe().expect("test binary");
        let mut children = (0..4)
            .map(|_| {
                std::process::Command::new(&executable)
                    .args([
                        "--exact",
                        "claude_upkeep::tests::multiprocess_claim_worker",
                        "--test-threads=1",
                    ])
                    .env("OTTTO_UPKEEP_MP_DIR", &dir)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn worker")
            })
            .collect::<Vec<_>>();
        for child in &mut children {
            assert!(child.wait().expect("wait worker").success());
        }
        let claims = fs::read_to_string(dir.join("claims.txt")).expect("one claim");
        assert_eq!(claims.lines().count(), 1);
    }

    #[test]
    fn upkeep_state_is_separate_from_downgrade_readable_registration_and_consent() {
        let dir = temp_dir("downgrade");
        let settings_path = dir.join(ottto_core::CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME);
        let store = FileClaudeConfigSlotSettingsStore::new(&settings_path);
        let status = store
            .register_path(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                "/tmp/exact-claude-slot".to_string(),
            )
            .expect("register");
        store
            .set_upkeep_consent(
                ottto_protocol::CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                true,
            )
            .expect("consent");
        let before = fs::read(&settings_path).expect("settings before");
        let descriptor = status.external_slots.first().expect("slot");
        let _ = observe_registered_slot_upkeep_with(
            descriptor,
            true,
            true,
            &dir,
            &FixedClock(at("2026-08-04T10:00:00Z")),
            &SequenceCredentials::new(vec![Some(metadata(
                "2026-08-04T10:00:00Z",
                "2026-08-20T00:00:00Z",
            ))]),
            &FixedProcess(DoctorProcessResult::NonzeroExit),
        );
        assert_eq!(fs::read(&settings_path).expect("settings after"), before);
        let reloaded = store.load().expect("old settings still load");
        assert_eq!(reloaded.consent, ClaudeAccountUpkeepConsentState::Granted);
        assert_eq!(reloaded.external_slots.len(), 1);
        assert!(dir.join(UPKEEP_STATE_FILE).is_file());
    }
}
