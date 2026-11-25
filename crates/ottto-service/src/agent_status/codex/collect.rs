//! Codex status collect operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::append_codex_workspace_observations_at;
use crate::agent_status::append_current_plan_observation;
use crate::agent_status::apply_codex_candidate_statuses;
use crate::agent_status::base_snapshot;
use crate::agent_status::billing_identity_evidence_for;
use crate::agent_status::canonicalize_codex_candidates;
use crate::agent_status::codex_app_server_success_diagnostic;
use crate::agent_status::codex_candidate_is_better;
use crate::agent_status::codex_credential_claimed_binding;
use crate::agent_status::codex_credit_grants;
use crate::agent_status::codex_identity_hashes;
use crate::agent_status::codex_last_known;
use crate::agent_status::codex_probe_catalog;
use crate::agent_status::codex_saved_quota;
use crate::agent_status::collect_codex_app_server_usage_for_home;
use crate::agent_status::collect_codex_home_candidate;
use crate::agent_status::collect_codex_slot_candidates;
use crate::agent_status::collect_model_names_from_json;
use crate::agent_status::command_diagnostic;
use crate::agent_status::command_output_text;
use crate::agent_status::current_unix_seconds;
use crate::agent_status::empty_codex_accounts_status;
use crate::agent_status::executable_exists;
#[cfg(test)]
use crate::agent_status::extract_percent_before;
use crate::agent_status::looks_like_model_name;
use crate::agent_status::looks_like_safe_model_id;
use crate::agent_status::merge_codex_accounts;
use crate::agent_status::not_installed_snapshot;
use crate::agent_status::parse_codex_account_text;
use crate::agent_status::read_codex_auth_account_at;
use crate::agent_status::read_codex_auth_credentials_at;
use crate::agent_status::read_codex_config_model_at;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::run_codex_home_command;
use crate::agent_status::run_command_capture;
use crate::agent_status::supported_capability;
use crate::agent_status::unsupported_account;
use crate::agent_status::unsupported_capability;
use crate::agent_status::unsupported_context;
use crate::agent_status::unsupported_quota_window;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentAvailableModelStatus;
#[cfg(test)]
use crate::agent_status::AgentContextCompleteness;
#[cfg(test)]
use crate::agent_status::AgentContextState;
#[cfg(test)]
use crate::agent_status::AgentContextStatus;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentModelStatus;
#[cfg(test)]
use crate::agent_status::AgentQuotaWindow;
#[cfg(test)]
use crate::agent_status::AgentQuotaWindowFreshness;
#[cfg(test)]
use crate::agent_status::AgentQuotaWindowScope;
#[cfg(test)]
use crate::agent_status::AgentQuotaWindowStatus;
use crate::agent_status::AgentRuntimeDefaults;
use crate::agent_status::AgentStatusCollection;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::CliFacts;
use crate::agent_status::CodexAccountSlotCollectionStateV1;
use crate::agent_status::CodexAccountSlotCollectionStatusV1;
use crate::agent_status::CodexAccountSlotOwnershipV1;
use crate::agent_status::CodexAccountSlotQuotaSnapshotV1;
use crate::agent_status::CodexAccountSlotSettingsError;
use crate::agent_status::CodexHomeBinding;
use crate::agent_status::CodexHomeSlot;
use crate::agent_status::CodexHomeTrust;
use crate::agent_status::CodexIdentityHashes;
use crate::agent_status::CodexQuotaRead;
use crate::agent_status::CodexSlotCandidate;
use crate::agent_status::CodexStrongIdentity;
use crate::agent_status::CodexUsageProbe;
use crate::agent_status::CodexWorkspaceTargetEvidence;
use crate::agent_status::CommandOutput;
use crate::agent_status::Duration;
use crate::agent_status::FileCodexAccountSlotSettingsStore;
use crate::agent_status::Instant;
use crate::agent_status::Mutex;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::Rfc3339;
use crate::agent_status::SourceKind;
use crate::agent_status::Value;
use crate::agent_status::CLAUDE_CLI_META;
use crate::agent_status::CODEX_CLI_META;
use crate::agent_status::CODEX_CLI_NOT_FOUND_FOR_PROBE;
use crate::agent_status::COMMAND_TIMEOUT;
use crate::agent_status::MAX_AVAILABLE_MODELS;
use crate::agent_status::{CODEX_LOGIN_REJECTED_FAILURE_PREFIX, CODEX_NO_ACCOUNT_FAILURE_PREFIX};

// One failure latch per read stage, never per account or slot.
pub(in crate::agent_status) fn note_codex_scope_read(
    stage: usize,
    error: Option<&CodexAccountSlotSettingsError>,
    skipped: usize,
) {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    static FAILED: [AtomicBool; 3] = [const { AtomicBool::new(false) }; 3];
    if FAILED[stage].swap(error.is_some(), Relaxed) != error.is_some() {
        let kind = match error {
            None => "none",
            Some(CodexAccountSlotSettingsError::Invalid(_)) => "validation",
            Some(CodexAccountSlotSettingsError::State(message))
                if message.starts_with("parse settings:") =>
            {
                "parse"
            }
            // The core API erases io::ErrorKind into this opaque variant.
            Some(CodexAccountSlotSettingsError::State(_)) => "state",
        };
        eprintln!(
            "warning: codex_scope_read stage={} failed={} error_kind={kind} skipped={skipped}",
            ["roster", "registered_bindings", "slot_home"][stage],
            error.is_some()
        );
    }
}

pub(in crate::agent_status) fn collect_codex_status_snapshots(
    captured_at: String,
    expires_at: String,
) -> AgentStatusCollection {
    let settings = FileCodexAccountSlotSettingsStore::default().load();
    note_codex_scope_read(0, settings.as_ref().err(), usize::from(settings.is_err()));
    let settings = settings.unwrap_or_else(|_| empty_codex_accounts_status());
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

    let (snapshots, setup_snapshot_index, source_health_snapshot) =
        codex_status_selection(&candidates, &captured_at, &expires_at);
    AgentStatusCollection {
        snapshots,
        source_health_snapshot,
        codex_scan_homes,
        codex_home_bindings,
        setup_snapshot_index,
    }
}

/// The uploaded Codex rows, the position among them of the default home's
/// row (its binding's winner, else its failed-probe witness, else the
/// no-row fallback), and the source-health aggregate.
pub(in crate::agent_status) fn codex_status_selection(
    candidates: &[CodexSlotCandidate],
    captured_at: &str,
    expires_at: &str,
) -> (Vec<AgentStatusSnapshot>, Option<usize>, AgentStatusSnapshot) {
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
    let default_binding = candidates
        .iter()
        .find(|candidate| candidate.slot.ownership == CodexAccountSlotOwnershipV1::Default)
        .and_then(|candidate| candidate.binding.as_ref());
    let mut setup_snapshot_index = None;
    for (binding, index) in winning_by_binding {
        if default_binding == Some(&binding) {
            setup_snapshot_index = Some(snapshots.len());
        }
        snapshots.push(candidates[index].snapshot.clone());
    }
    let failed_default = append_failed_default_codex_snapshot(&mut snapshots, candidates);
    setup_snapshot_index = setup_snapshot_index.or(failed_default);
    append_configured_codex_unavailable_snapshots(
        &mut snapshots,
        candidates,
        captured_at,
        expires_at,
    );

    let source_health_snapshot = codex_source_health_snapshot(candidates, captured_at, expires_at);
    if snapshots.is_empty() {
        let mut upload = source_health_snapshot.clone();
        codex_canonical_identity_spelling(&mut upload);
        snapshots.push(upload);
        setup_snapshot_index = Some(0);
    }
    (snapshots, setup_snapshot_index, source_health_snapshot)
}

pub(in crate::agent_status) fn append_configured_codex_unavailable_snapshots(
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
        // A dead login's needs-login cause rides along, so the web can show it.
        if let Some(needs_login) = candidate
            .snapshot
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "codex_account_needs_login")
        {
            snapshot.diagnostics.push(
                needs_login
                    .clone()
                    .with_quota_binding(Some(account.clone()), Some(workspace.clone())),
            );
        }
        snapshots.push(snapshot);
    }
}

/// Upload the default home's failed-probe snapshot when it kept the hashes of
/// its last validated account ([`keep_failed_default_codex_binding`]) and no
/// other snapshot already represents that account. Without this, a batch that
/// has any other row never carried the default account's degraded reading.
/// The candidate's binding stays empty, so transcript attribution is unchanged.
/// Returns the position of the row it pushed.
pub(in crate::agent_status) fn append_failed_default_codex_snapshot(
    snapshots: &mut Vec<AgentStatusSnapshot>,
    candidates: &[CodexSlotCandidate],
) -> Option<usize> {
    let mut pushed = None;
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
            pushed = pushed.or(Some(snapshots.len()));
            snapshots.push(candidate.snapshot.clone());
        }
    }
    pushed
}

/// Whether a slot's only problem is a failed usage probe: the app-server read
/// failed (`codex_usage_probe_failed`) while the login itself is not known to
/// be broken. A signed-in home then has no identity hashes
/// (`identity_unknown`); a signed-out one is `needs_login` and does not count,
/// and neither does a missing `codex` executable, which is not transient.
pub(in crate::agent_status) fn codex_probe_failed_only(
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
pub(in crate::agent_status) fn codex_home_kept_binding(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Option<String> {
    let last = codex_credit_grants::home_binding(codex_home)?;
    let credentials = read_codex_auth_credentials_at(codex_home, home_trust)
        .ok()
        .flatten()?;
    let claimed = codex_credential_claimed_binding(&credentials, true)?;
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
pub(in crate::agent_status) fn keep_failed_default_codex_binding(
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
pub(in crate::agent_status) fn remember_codex_last_known_reading(
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
pub(in crate::agent_status) fn codex_last_known_slot_reading(
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

pub(in crate::agent_status) fn codex_source_health_snapshot(
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

/// Name every raw-only Codex identity on `snapshot` in its canonical spelling.
///
/// A login read only from the local id token (no saved reading with identity
/// yet: first pairing, setup, a login change) carries raw user and workspace
/// ids and no hashes. Sent like that, the backend hashes them with its own
/// fallback recipe and files the same account under a second identity. Each
/// ABSENT hash is set from its raw id with the recipe a provider-validated
/// binding uses ([`codex_identity_hashes`]); a present hash is never
/// overwritten, and confidence and billing identity stay as they are. A plan
/// row filled here that said `is_current: false` leaves its currentness
/// unsaid instead (`is_current` absent): that false only means the local
/// reading was not confirmed, and sent with the canonical hashes it would mark
/// the account's existing profile not current. A row that said `true` (a
/// signed-in High or Medium login, [`append_current_plan_observation`]) is a
/// correct claim and keeps it, as does a row that said nothing.
///
/// Runs on the main lane's fallback copy when no home is bound
/// ([`codex_status_selection`]), also selected for the setup scan by
/// [`AgentStatusCollection::setup_snapshot`]. The collection's own source-health
/// snapshot, which local status and active-session reconciliation read, keeps
/// what was collected, so bindings,
/// dedup, representation and local attribution are unchanged.
pub(in crate::agent_status) fn codex_canonical_identity_spelling(
    snapshot: &mut AgentStatusSnapshot,
) {
    if snapshot.source != SourceKind::Codex {
        return;
    }
    if let Some(account) = snapshot.account.as_mut() {
        fill_absent_codex_identity_hashes(
            account.account_id.as_deref(),
            account.organization_id.as_deref(),
            &mut account.account_identifier_hash,
            &mut account.organization_identifier_hash,
        );
    }
    for observation in &mut snapshot.plan_observations {
        if fill_absent_codex_identity_hashes(
            observation.account_id.as_deref(),
            observation.organization_id.as_deref(),
            &mut observation.account_identifier_hash,
            &mut observation.organization_identifier_hash,
        ) && observation.is_current == Some(false)
        {
            observation.is_current = None;
        }
    }
}

/// Set each absent hash from its raw id, per field. Returns whether any was set.
pub(in crate::agent_status) fn fill_absent_codex_identity_hashes(
    account_id: Option<&str>,
    workspace_id: Option<&str>,
    account_hash: &mut Option<String>,
    workspace_hash: &mut Option<String>,
) -> bool {
    let (account, workspace) = codex_identity_hashes(account_id, workspace_id);
    let mut filled = false;
    for (slot, hash) in [(account_hash, account), (workspace_hash, workspace)] {
        if slot.is_none() && hash.is_some() {
            *slot = hash;
            filled = true;
        }
    }
    filled
}

pub(in crate::agent_status) const CLI_META_MAX_AGE: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub(in crate::agent_status) struct CliMeta<F> {
    pub(in crate::agent_status) loaded_at: Instant,
    pub(in crate::agent_status) facts: F,
}

#[derive(Clone)]
pub(in crate::agent_status) struct CodexCliMeta {
    // No account, email, plan or identity is retained from CLI text.
    pub(in crate::agent_status) login: AgentLoginState,
    pub(in crate::agent_status) models: AgentModelStatus,
}

pub(in crate::agent_status) fn cli_meta<K: Ord + Clone, F: Clone, E, const N: usize>(
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

pub(in crate::agent_status) fn cli_binary_stamp(
    binary: &str,
) -> std::io::Result<crate::transcript_acquisition::SourceStamp> {
    let path = crate::command_env::executable_path(binary)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let stamp = crate::transcript_acquisition::SourceStamp::capture_file(&path.canonicalize()?)?;
    match stamp {
        crate::transcript_acquisition::SourceStamp::File(_) => Ok(stamp),
        _ => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
    }
}

pub(in crate::agent_status) fn codex_cli_meta(
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
            let binary = cli_binary_stamp("codex");
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
                // That binary's own list, for its limits probe.
                if let (Ok(binary), Ok(after)) = (binary, cli_binary_stamp("codex")) {
                    if binary.same(&after) {
                        codex_probe_catalog::save(binary, &models.stdout);
                    }
                }
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
        crate::scan_clock::now(),
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

pub(in crate::agent_status) fn claude_version_detected() -> bool {
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
        crate::scan_clock::now(),
        false,
    )
    .is_ok()
}

pub(in crate::agent_status) fn collect_codex_status_for_home(
    captured_at: String,
    expires_at: String,
    codex_home: &Path,
    home_trust: CodexHomeTrust,
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
    match collect_codex_usage_for_home(codex_home, home_trust, quota_read) {
        Ok(usage) => {
            if usage.credential_read_failed {
                append_codex_credential_read_failed_diagnostic(&mut snapshot);
            }
            if let Some(account) = usage.account {
                snapshot.account = Some(merge_codex_accounts(snapshot.account.take(), account));
            }
            // A served reading never carries a rejected login: that read failed.
            apply_codex_dead_login(
                &mut snapshot,
                codex_home,
                home_trust,
                usage.provider_account_absent,
                false,
            );
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
            apply_codex_dead_login(
                &mut snapshot,
                codex_home,
                home_trust,
                failure.message.starts_with(CODEX_NO_ACCOUNT_FAILURE_PREFIX),
                failure
                    .message
                    .starts_with(CODEX_LOGIN_REJECTED_FAILURE_PREFIX),
            );
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

/// A home with an auth file whose login is dead needs a new sign-in, not
/// merely unconfirmed. For an Ottto slot's home, which the probe reads
/// regularly (each read lets Codex refresh its login when due), a provider
/// read that named no account (`account: null`) or rejected the login is
/// dead. For the user's own default home only a refused refresh is
/// (`login_rejected`: "sign in again" on either read). A 401, which Codex
/// also answers when a refresh failed for a transient reason, and
/// `account: null` leave it as it was.
/// Changes the status cause only.
pub(in crate::agent_status) fn apply_codex_dead_login(
    snapshot: &mut AgentStatusSnapshot,
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    provider_account_absent: bool,
    login_rejected: bool,
) {
    let dead = match home_trust {
        CodexHomeTrust::Managed => provider_account_absent || login_rejected,
        CodexHomeTrust::ProviderDefault => login_rejected,
    };
    if !dead || ottto_core::codex_auth_file_mark(codex_home).is_none() {
        return;
    }
    snapshot.status = AgentStatusState::AuthRequired;
    if let Some(account) = snapshot.account.as_mut() {
        account.login_state = AgentLoginState::SignedOut;
    }
    // The slot's own cause, on the snapshot too, so the web can show it.
    if !snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "codex_account_needs_login")
    {
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "codex_account_needs_login",
            AgentDiagnosticSeverity::Warning,
            match home_trust {
                CodexHomeTrust::Managed => {
                    "Codex must be signed in again for this durable connection."
                }
                CodexHomeTrust::ProviderDefault => {
                    "Codex asked to sign in again: run `codex login` to keep its limits current."
                }
            },
        ));
    }
}

pub(in crate::agent_status) fn collect_codex_usage_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    quota_read: CodexQuotaRead,
) -> Result<CodexUsageProbe, codex_saved_quota::CodexQuotaFailure> {
    match quota_read {
        CodexQuotaRead::Saved => {
            codex_saved_quota::serve_saved(codex_home, home_trust, current_unix_seconds())
        }
        CodexQuotaRead::Provider => {
            codex_saved_quota::read_provider_and_save(codex_home, home_trust, |_, _| true)
                .unwrap_or_else(|| Err(codex_saved_quota::CODEX_QUOTA_NOT_READ_YET.to_string()))
                .map_err(|message| codex_saved_quota::CodexQuotaFailure {
                    message,
                    at_epoch_seconds: current_unix_seconds(),
                })
        }
    }
}

/// One provider read of a Codex home's quota from its local app-server.
/// Callers go through [`codex_saved_quota::read_provider_and_save`], which
/// saves the outcome.
pub(in crate::agent_status) fn read_codex_usage_from_provider(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<CodexUsageProbe, String> {
    collect_codex_app_server_usage_for_home(codex_home, home_trust)
}

pub(in crate::agent_status) fn stamp_codex_meter_identity(snapshot: &mut AgentStatusSnapshot) {
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

pub(in crate::agent_status) fn append_codex_credential_read_failed_diagnostic(
    snapshot: &mut AgentStatusSnapshot,
) {
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
pub(in crate::agent_status) fn build_codex_runtime_defaults_at(
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

#[cfg(test)]
pub(in crate::agent_status) fn parse_codex_text_model(text: &str) -> Option<AgentModelStatus> {
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
pub(in crate::agent_status) fn parse_codex_text_quota_windows(text: &str) -> Vec<AgentQuotaWindow> {
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
pub(in crate::agent_status) fn parse_codex_text_context(text: &str) -> Option<AgentContextStatus> {
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

pub(in crate::agent_status) fn collect_model_status_from_output(
    output: &CommandOutput,
    provider: &str,
) -> AgentModelStatus {
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

pub(in crate::agent_status) fn collect_codex_model_status_from_output(
    output: &CommandOutput,
) -> AgentModelStatus {
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

pub(in crate::agent_status) fn apply_codex_config_model(
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
