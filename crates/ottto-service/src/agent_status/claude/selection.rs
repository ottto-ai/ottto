//! Claude status selection operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::annotate_claude_accounts_status;
use crate::agent_status::append_claude_desktop_pairs_snapshot;
use crate::agent_status::append_registered_claude_plan_observations;
use crate::agent_status::apply_claude_quota_access_state;
use crate::agent_status::apply_claude_slot_approval_notice;
use crate::agent_status::apply_claude_token_owner;
use crate::agent_status::canonical_anchor_health;
use crate::agent_status::canonical_registered_anchors;
use crate::agent_status::capacity_exceeded_status;
use crate::agent_status::claude_config_slot_for_descriptor;
use crate::agent_status::claude_cross_binding_meter_collisions;
use crate::agent_status::claude_oauth_end_slot_run;
use crate::agent_status::claude_oauth_usage_caller_auth_hold;
use crate::agent_status::claude_oauth_usage_config_fingerprint;
use crate::agent_status::claude_settings_failure_bound_exceeded;
use crate::agent_status::claude_slot_approvals;
use crate::agent_status::claude_slot_connection_usable;
use crate::agent_status::claude_slot_owned_usage_bindings;
use crate::agent_status::claude_slot_status_carries_meters;
use crate::agent_status::claude_snapshot_candidate_disposition;
use crate::agent_status::claude_snapshot_has_account_windows;
use crate::agent_status::claude_stale_cross_binding_meter_collisions;
use crate::agent_status::claude_strong_oauth_identity_hashes;
use crate::agent_status::claude_worker_diagnostic_message;
use crate::agent_status::collect_claude_status;
use crate::agent_status::collect_registered_claude_slot_step;
use crate::agent_status::current_unix_seconds;
use crate::agent_status::degraded_claude_slot_snapshots;
use crate::agent_status::derive_unresolved_claude_accounts;
use crate::agent_status::home_dir;
use crate::agent_status::inherit_claude_slot_account_profile;
use crate::agent_status::load_claude_slot_settings_for_pass;
use crate::agent_status::ordered_claude_slot_descriptors;
use crate::agent_status::persist_claude_slot_collection_states;
use crate::agent_status::prepare_default_claude_slot_status;
use crate::agent_status::quarantine_claude_cross_account_meters;
use crate::agent_status::read_claude_cli_oauth_account;
use crate::agent_status::read_claude_oauth_usage_breaker;
use crate::agent_status::read_persisted_claude_slot_collection_state;
use crate::agent_status::remember_claude_slot_account_profile;
use crate::agent_status::retain_verified_claude_binding;
use crate::agent_status::retain_verified_claude_slot_binding;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::safe_claude_slot_check_diagnostics;
use crate::agent_status::select_claude_snapshot_candidates;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentStatusCollection;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusPlanObservation;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeAccountAnchorDurabilityV1;
use crate::agent_status::ClaudeAccountAnchorHealthV1;
use crate::agent_status::ClaudeCliOauthAccount;
use crate::agent_status::ClaudeConfigDirSlot;
use crate::agent_status::ClaudeConfigSlotCollectionStateV1;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeConfigSlotDescriptorV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticCodeV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticV1;
use crate::agent_status::ClaudeConfigSlotOwnership;
use crate::agent_status::ClaudeConfigSlotQuotaSnapshotStateV1;
use crate::agent_status::ClaudeDesktopMetadataCache;
use crate::agent_status::ClaudeOAuthCollectionPass;
use crate::agent_status::ClaudeOAuthUsageBreaker;
use crate::agent_status::ClaudeOAuthUsageCaller;
use crate::agent_status::ClaudeSlotCollectionStep;
use crate::agent_status::ClaudeSlotProbeFailure;
use crate::agent_status::ClaudeSnapshotCandidate;
use crate::agent_status::ClaudeSnapshotDisposition;
use crate::agent_status::ClaudeSnapshotQuality;
use crate::agent_status::ClaudeSnapshotSlotClass;
use crate::agent_status::ClaudeStrongBinding;
use crate::agent_status::ClaudeTokenOwner;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Rfc3339;
use crate::agent_status::SourceKind;
use crate::agent_status::CLAUDE_RELOGIN_APPROACHING_CODE;
use crate::agent_status::MAX_CLAUDE_ACCOUNT_SLOTS;

pub(in crate::agent_status) fn collect_claude_status_snapshots(
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
                    read_claude_oauth_usage_breaker(
                        &binding.account_identifier_hash,
                        &binding.organization_identifier_hash,
                        &claude_oauth_usage_config_fingerprint(),
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
    // The setup index is read after the degraded and Desktop appends, so it
    // addresses the final upload rows; keep it after both.
    let desktop_carrier_only = snapshots.is_empty();
    append_claude_desktop_pairs_snapshot(&mut snapshots, &desktop_pairs, &captured_at, &expires_at);
    let setup_snapshot_index =
        claude_setup_snapshot_index(&snapshots, default_binding.as_ref(), desktop_carrier_only);
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
    let signed_in = claude_ottto_accounts_signed_in(
        custom_slot_states
            .clone()
            .filter(|status| claude_slot_connection_usable(status, OffsetDateTime::now_utc()))
            .count(),
    );
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
            read_claude_oauth_usage_breaker(
                account,
                organization,
                &claude_oauth_usage_config_fingerprint(),
            )
        },
        now_epoch,
    )) {
        source_health_snapshot.diagnostics.push(diagnostic);
    }
    append_registered_claude_plan_observations(&mut source_health_snapshot, &snapshots);
    source_health_snapshot.diagnostics.extend(signed_in.clone());
    for snapshot in &mut snapshots {
        snapshot.diagnostics.extend(signed_in.clone());
    }

    AgentStatusCollection {
        snapshots,
        source_health_snapshot,
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
        setup_snapshot_index,
    }
}

/// Position of the final uploaded row for the default login's strong pair:
/// its own winner, the registered slot that won it, or its degraded witness.
/// With no such row, the account-less Desktop carrier when it is the only
/// row (`desktop_carrier_only`: no row existed before it was appended).
pub(in crate::agent_status) fn claude_setup_snapshot_index(
    snapshots: &[AgentStatusSnapshot],
    default_binding: Option<&ClaudeStrongBinding>,
    desktop_carrier_only: bool,
) -> Option<usize> {
    default_binding
        .and_then(|default| {
            snapshots.iter().position(|snapshot| {
                snapshot.account.as_ref().is_some_and(|account| {
                    account.account_identifier_hash.as_deref()
                        == Some(default.account_identifier_hash.as_str())
                        && account.organization_identifier_hash.as_deref()
                            == Some(default.organization_identifier_hash.as_str())
                })
            })
        })
        .or_else(|| (desktop_carrier_only && snapshots.len() == 1).then_some(0))
}

pub(crate) const CLAUDE_OTTTO_SIGNED_IN: &str = "claude_ottto_account_signed_in";

pub(crate) fn claude_default_check_skipped(snapshot: &AgentStatusSnapshot) -> bool {
    snapshot.source == SourceKind::ClaudeCode
        && matches!(&snapshot.account, Some(a) if a.login_state == AgentLoginState::SignedOut)
        && snapshot
            .diagnostics
            .iter()
            .any(|d| d.code == CLAUDE_OTTTO_SIGNED_IN)
}

pub(in crate::agent_status) fn claude_ottto_accounts_signed_in(
    count: usize,
) -> Option<AgentStatusDiagnostic> {
    let noun = if count == 1 { "account" } else { "accounts" };
    (count > 0).then(|| {
        AgentStatusDiagnostic::source(
            CLAUDE_OTTTO_SIGNED_IN,
            AgentDiagnosticSeverity::Info,
            format!("{count} Claude {noun} signed in through Ottto"),
        )
    })
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
pub(in crate::agent_status) fn claude_custom_slot_needs_attention(
    state: &ClaudeConfigSlotCollectionStateV1,
) -> bool {
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
pub(in crate::agent_status) fn claude_default_full_meter_needs_attention(
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
pub(in crate::agent_status) struct ClaudePausedUsageAccount {
    /// The provider rejected this account's sign-in (auth hold or open
    /// breaker), as opposed to the provider not answering.
    pub(in crate::agent_status) after_sign_in_rejection: bool,
    /// When Ottto may automatically check this account again, if known.
    pub(in crate::agent_status) next_check_epoch_seconds: Option<u64>,
}

/// A slot diagnostic that proves the provider rejected this slot's sign-in
/// and the slot is now held back. Matches both the raw producer text and the
/// sanitized slot-state copy of the circuit-open alert.
pub(in crate::agent_status) fn claude_diagnostic_is_auth_pause(
    diagnostic: &AgentStatusDiagnostic,
) -> bool {
    match diagnostic.code.as_str() {
        "claude_oauth_usage_auth_rejected" | "claude_oauth_usage_auth_backoff" => true,
        "claude_oauth_usage_circuit_open" => diagnostic.message.contains("auth"),
        _ => false,
    }
}

/// When the breaker next lets any caller for this account ask the provider.
/// An account-wide auth verdict gates every caller; otherwise the earliest
/// live per-caller hold is the next possible automatic check.
pub(in crate::agent_status) fn claude_breaker_auth_pause_until(
    breaker: &ClaudeOAuthUsageBreaker,
    now: u64,
) -> Option<u64> {
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
pub(in crate::agent_status) fn claude_paused_usage_accounts(
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
pub(in crate::agent_status) fn claude_usage_checks_paused_diagnostic(
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

pub(in crate::agent_status) fn apply_claude_anchor_continuity(
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
pub(in crate::agent_status) fn claude_uploaded_candidate_snapshot(
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
pub(in crate::agent_status) fn claude_registered_owned_bindings(
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
pub(in crate::agent_status) fn claude_stale_saved_slot_states(
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
pub(in crate::agent_status) fn claude_runtime_defaults_carrier(
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
pub(in crate::agent_status) fn claude_default_upload_withheld(
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
pub(in crate::agent_status) fn strip_slot_owned_plan_observations(
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
pub(in crate::agent_status) fn append_canonical_anchor_worker_receipts(
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
pub(in crate::agent_status) fn claude_default_snapshot_is_uploadable(
    snapshot: &AgentStatusSnapshot,
) -> bool {
    claude_snapshot_candidate_rank(snapshot).is_some()
}

pub(in crate::agent_status) fn claude_snapshot_candidate_rank(
    snapshot: &AgentStatusSnapshot,
) -> Option<ClaudeSnapshotQuality> {
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

pub(in crate::agent_status) fn coherent_claude_provider_observed_at(
    snapshot: &AgentStatusSnapshot,
) -> String {
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

pub(in crate::agent_status) fn bounded_claude_custom_descriptors(
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
