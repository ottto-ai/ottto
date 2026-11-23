//! Claude status desktop operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::base_snapshot;
use crate::agent_status::billing_identity_evidence_for;
use crate::agent_status::billing_identity_hash;
use crate::agent_status::file_modified_epoch_seconds;
use crate::agent_status::first_non_empty;
use crate::agent_status::fs;
use crate::agent_status::home_dir;
use crate::agent_status::home_path;
use crate::agent_status::looks_like_local_json_file;
use crate::agent_status::normalize_plan_type;
use crate::agent_status::path_stamp;
use crate::agent_status::read_claude_cli_oauth_account;
use crate::agent_status::read_json_file;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::safe_display_label;
use crate::agent_status::safe_local_identifier;
use crate::agent_status::supported_capability;
use crate::agent_status::timestamp_value_epoch_seconds;
use crate::agent_status::unsupported_capability;
use crate::agent_status::unsupported_quota_window;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusPlanObservation;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeConfigDirSlot;
use crate::agent_status::ClaudeDesktopAgentModeSessionMetadata;
use crate::agent_status::ClaudeDesktopCodeSessionMetadata;
use crate::agent_status::ClaudeDesktopConfig;
use crate::agent_status::ClaudeDesktopMetadataCache;
use crate::agent_status::ClaudeDesktopMetadataEntries;
use crate::agent_status::ClaudeDesktopPairBuilder;
use crate::agent_status::ClaudeDesktopPairKey;
use crate::agent_status::ClaudeDesktopPairObservation;
use crate::agent_status::ClaudeDesktopPairs;
use crate::agent_status::ClaudeDesktopProfileBuilder;
use crate::agent_status::ClaudeDesktopScan;
use crate::agent_status::ClaudeStrongBinding;
use crate::agent_status::Deserialize;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::SourceKind;
use crate::agent_status::AGENT_STATUS_UPLOAD_SNAPSHOT_MAX;
use crate::agent_status::CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG;
use crate::agent_status::CLAUDE_DESKTOP_CODE_SESSION_MAX_FILES_PER_ORG;
use crate::agent_status::CLAUDE_DESKTOP_DUPLICATE_SESSION_OBSERVATION_MAX;
use crate::agent_status::CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX;

pub(in crate::agent_status) fn claude_desktop_pair_builder<'a>(
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

/// Takes the observations rather than recomputing them: the statusLine
/// attribution gate above needs the same set, and scanning the Desktop session
/// buckets twice per status tick would be pure waste.
pub(in crate::agent_status) fn append_claude_desktop_plan_observations(
    snapshot: &mut AgentStatusSnapshot,
    observations: Vec<AgentStatusPlanObservation>,
) -> usize {
    let count = observations.len();
    snapshot.plan_observations.extend(observations);
    count
}

pub(in crate::agent_status) fn claude_desktop_support_dir() -> PathBuf {
    home_path("Library/Application Support/Claude")
}

pub(in crate::agent_status) fn claude_cli_config_path() -> PathBuf {
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

pub(in crate::agent_status) fn claude_desktop_metadata_present(root: &Path) -> bool {
    root.join("config.json").is_file()
        || root.join("claude-code-sessions").is_dir()
        || root.join("local-agent-mode-sessions").is_dir()
}

#[cfg(test)]
pub(in crate::agent_status) fn claude_desktop_plan_observations_from_root(
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

pub(in crate::agent_status) fn claude_desktop_scan_from_root(
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
pub(in crate::agent_status) fn claude_desktop_unambiguous_duplicate_session_owners(
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
pub(in crate::agent_status) fn claude_desktop_duplicate_session_owners<'a, K: Clone + PartialEq>(
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

pub(in crate::agent_status) fn read_claude_desktop_config(root: &Path) -> ClaudeDesktopConfig {
    let path = root.join("config.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_json::from_str::<ClaudeDesktopConfig>(&body).ok())
        .unwrap_or_default()
}

pub(in crate::agent_status) fn collect_claude_desktop_code_sessions(
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

pub(in crate::agent_status) fn collect_claude_desktop_agent_mode_sessions(
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

pub(in crate::agent_status) fn claude_desktop_builder_plan_observation(
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

pub(in crate::agent_status) fn claude_desktop_subscription_product(plan: String) -> String {
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
pub(in crate::agent_status) fn claude_desktop_qualified_pairs(
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
pub(in crate::agent_status) fn claude_desktop_pair_observation(
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
pub(in crate::agent_status) fn claude_desktop_pairs_snapshot(
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
pub(in crate::agent_status) fn append_claude_desktop_pairs_snapshot(
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
    pub(in crate::agent_status) fn record_session(
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

    pub(in crate::agent_status) fn record_agent_mode_metadata(
        &mut self,
        metadata: &ClaudeDesktopAgentModeSessionMetadata,
    ) {
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
    pub(in crate::agent_status) fn record_activity(
        &mut self,
        activity: Option<i64>,
        session_id: Option<String>,
    ) -> bool {
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
pub(in crate::agent_status) type ClaudeDesktopMetadataPass<'a, T> = (
    &'a mut ClaudeDesktopMetadataEntries<T>,
    &'a mut ClaudeDesktopMetadataEntries<T>,
);

/// One Desktop session file's metadata: the previous pass's parse, failures
/// included, while the file's stamp is unchanged, else a fresh read. A file
/// written too recently for a rewrite to change its stamp is not kept.
pub(in crate::agent_status) fn claude_desktop_session_metadata<
    T: for<'de> Deserialize<'de> + Clone,
>(
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
