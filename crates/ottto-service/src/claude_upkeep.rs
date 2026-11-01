//! Claude Code login upkeep decisions for registered custom slots.
//!
//! `claude doctor` upkeep is off: a short `doctor` run after access expiry
//! could start a token refresh and exit before the rotated token was saved,
//! which signs the login out (anthropics/claude-code#95822). Refreshing is
//! done by `claude_refresher` (one waiting `claude -p /usage` per login). The
//! foreground decision here reads the slot's stored credential on every pass
//! and either collects, waits while the refresher runs, stays paused when
//! "Keep my Claude accounts signed in" is off, or asks for sign-in when the
//! refresh grant is gone or the refresher could not advance the expiry. The
//! retired background `doctor` worker is no longer part of production.

use crate::agent_status::{ClaudeLiveLogin, ClaudeLocalLoginState, ClaudeOAuthCredentialMetadata};
use crate::claude_refresher::RefreshDecision;
#[cfg(test)]
use ottto_core::{ClaudeConfigDirSlot, FileClaudeConfigSlotSettingsStore};
use ottto_protocol::{
    ClaudeAccountUpkeepConsentState, ClaudeConfigSlotDescriptorV1, ClaudeConfigSlotUpkeepResultV1,
    ClaudeConfigSlotUpkeepStatusV1,
};
use std::path::Path;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

/// Operational stop: absent means normal consent/network-gated GA behavior.
pub(crate) const UPKEEP_DISABLED_FILE: &str = "claude-background-upkeep-disabled";

const RELLOGIN_APPROACHING_SECONDS: i64 = 72 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeUpkeepObservation {
    pub(crate) proceed_with_collection: bool,
    pub(crate) status: ClaudeConfigSlotUpkeepStatusV1,
    /// A completed local upkeep observation, never a provider quota check.
    pub(crate) result_observed_at: Option<String>,
    /// The access login lapsed while its refresh grant is alive: only Claude
    /// Code may refresh it, so collection waits (presented as paused).
    pub(crate) paused_awaiting_claude_refresh: bool,
}

/// Whether the settings registry still holds this exact slot.
///
/// Compares registration identity only. `ClaudeConfigSlotDescriptorV1` also
/// carries `collection`, which is collector-owned and changes on every pass:
/// the registry builds descriptors with an empty collection status while the
/// caller's copy has been annotated with live expiry, quota, and upkeep state.
/// Comparing whole descriptors therefore answered "still registered?" with
/// "no" for every slot that had ever collected, so consented upkeep returned
/// `NeedsLogin`, pruned its own witness, and left the account's limits dark
/// while its refresh grant was still valid.
fn slot_is_still_registered(
    registry: &ottto_protocol::ClaudeAccountsStatusV1,
    descriptor: &ClaudeConfigSlotDescriptorV1,
) -> bool {
    registry
        .managed_slots
        .iter()
        .chain(registry.external_slots.iter())
        .any(|current| {
            current.slot_id == descriptor.slot_id
                && current.ownership == descriptor.ownership
                && current.config_dir == descriptor.config_dir
                && current.service_name == descriptor.service_name
        })
}

/// Shared final consent/registration/suppression fence for local status writes;
/// used by the native refresher and foreground publication helpers.
pub(crate) fn registered_slot_publication_allowed(
    registry: &ottto_protocol::ClaudeAccountsStatusV1,
    descriptor: &ClaudeConfigSlotDescriptorV1,
    support_dir: &Path,
) -> bool {
    registry.consent == ClaudeAccountUpkeepConsentState::Granted
        && slot_is_still_registered(registry, descriptor)
        && crate::claude_browser_auth::collection_suppression(&descriptor.slot_id).is_none()
        && !crate::agent_status::claude_slot_login_unapproved(descriptor)
        && !crate::agent_status::claude_oauth_usage_network_disabled()
        && !support_dir.join(UPKEEP_DISABLED_FILE).is_file()
}

/// Foreground upkeep decision for one registered slot, from the live local
/// read the caller made this pass (`live`). Never spawns anything.
pub(crate) fn observe_registered_slot_upkeep(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    consent: bool,
    network_enabled: bool,
    live: &ClaudeLiveLogin,
    refresh: RefreshDecision,
) -> ClaudeUpkeepObservation {
    observe_registered_slot_upkeep_reading(
        descriptor,
        consent,
        network_enabled,
        live,
        refresh,
        OffsetDateTime::now_utc(),
    )
}

/// The decision always comes from the live read, never from the persisted
/// `access_expires_at`: a stale persisted deadline latched slots in the past
/// (H58), and a login the user restored must resume in the same pass.
fn observe_registered_slot_upkeep_reading(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    consent: bool,
    network_enabled: bool,
    live: &ClaudeLiveLogin,
    refresh: RefreshDecision,
    now: OffsetDateTime,
) -> ClaudeUpkeepObservation {
    if !network_enabled {
        let persisted = ClaudeOAuthCredentialMetadata {
            access_expires_at: descriptor.collection.access_expires_at.clone(),
            refresh_token_expires_at: descriptor.collection.relogin_required_at.clone(),
            has_refresh_token: true,
            cleared_by_cli: false,
            has_profile_scope: false,
        };
        return observation_with_metadata(
            false,
            ClaudeConfigSlotUpkeepResultV1::CollectionPaused,
            &persisted,
        );
    }
    let metadata = live
        .metadata
        .clone()
        .unwrap_or(ClaudeOAuthCredentialMetadata {
            access_expires_at: None,
            refresh_token_expires_at: None,
            has_refresh_token: false,
            cleared_by_cli: false,
            has_profile_scope: false,
        });
    match live.state {
        // Claude Code signed this slot out, or its refresh grant is gone. No
        // command can restore it; wait for the stored item to change.
        ClaudeLocalLoginState::SignedOutByCli | ClaudeLocalLoginState::NeedsLogin => {
            observation_with_metadata(false, ClaudeConfigSlotUpkeepResultV1::NeedsLogin, &metadata)
        }
        // Resolution reports the exact failure (credential unavailable, or a
        // transient fail-closed read) from the same local read.
        ClaudeLocalLoginState::NotSignedIn => observation_with_metadata(
            true,
            ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
            &metadata,
        ),
        ClaudeLocalLoginState::Unreadable => {
            observation_with_metadata(true, ClaudeConfigSlotUpkeepResultV1::ProbeFailed, &metadata)
        }
        ClaudeLocalLoginState::AccessValid => {
            let approaching = parse_timestamp(metadata.refresh_token_expires_at.as_deref())
                .is_some_and(|expiry| {
                    expiry > now
                        && expiry - now <= TimeDuration::seconds(RELLOGIN_APPROACHING_SECONDS)
                });
            observation_with_metadata(
                true,
                if approaching {
                    ClaudeConfigSlotUpkeepResultV1::ReloginApproaching
                } else if consent {
                    ClaudeConfigSlotUpkeepResultV1::NotRequired
                } else {
                    ClaudeConfigSlotUpkeepResultV1::UpkeepNotConsented
                },
                &metadata,
            )
        }
        ClaudeLocalLoginState::RefreshPending => {
            let result = match refresh {
                // The background refresh of this exact credential signed it
                // out or failed twice: sign in again; no retry until a new
                // credential appears.
                RefreshDecision::FailedWaitingForSignIn => {
                    return observation_with_metadata(
                        false,
                        ClaudeConfigSlotUpkeepResultV1::NeedsLogin,
                        &metadata,
                    )
                }
                // A background refresh is running for this login, or its one
                // retry after an intact failure is due on a later pass.
                RefreshDecision::Started
                | RefreshDecision::Running
                | RefreshDecision::RetryWaiting => ClaudeConfigSlotUpkeepResultV1::InProgress,
                RefreshDecision::Disabled | RefreshDecision::NotNeeded => {
                    ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled
                }
            };
            let mut observation = observation_with_metadata(false, result, &metadata);
            observation.paused_awaiting_claude_refresh = true;
            observation
        }
    }
}

fn observation_with_metadata(
    proceed_with_collection: bool,
    result: ClaudeConfigSlotUpkeepResultV1,
    metadata: &ClaudeOAuthCredentialMetadata,
) -> ClaudeUpkeepObservation {
    ClaudeUpkeepObservation {
        proceed_with_collection,
        paused_awaiting_claude_refresh: false,
        result_observed_at: None,
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

pub(crate) fn preclaim_descriptor(
    descriptor: &ClaudeConfigSlotDescriptorV1,
) -> Option<ClaudeConfigSlotDescriptorV1> {
    let account = descriptor
        .collection
        .account_identifier_hash
        .as_deref()
        .filter(|value| !value.is_empty())?;
    let organization = descriptor
        .collection
        .organization_identifier_hash
        .as_deref()
        .filter(|value| !value.is_empty())?;
    parse_timestamp(descriptor.collection.access_expires_at.as_deref())?;
    let mut fence = descriptor.clone();
    fence.collection = Default::default();
    fence.collection.account_identifier_hash = Some(account.to_string());
    fence.collection.organization_identifier_hash = Some(organization.to_string());
    fence.collection.access_expires_at = descriptor.collection.access_expires_at.clone();
    fence.collection.relogin_required_at = descriptor.collection.relogin_required_at.clone();
    Some(fence)
}

/// Compatibility hook for registration-removal callers. The retired worker has
/// no live state readers or writers, so leave any stale files untouched.
pub(crate) fn prune_slot_upkeep_state(_slot_id: &str) -> std::io::Result<()> {
    Ok(())
}

fn parse_timestamp(value: Option<&str>) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value?, &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{ClaudeConfigSlotOwnership, CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION};
    use serial_test::serial;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;

    const UPKEEP_STATE_FILE: &str = "claude-background-upkeep-state.json";

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
            cleared_by_cli: false,
            has_profile_scope: false,
        }
    }

    /// The settings registry returns descriptors carrying registration
    /// identity only; the collector hands upkeep the same slot annotated with
    /// its live collection status. Comparing whole descriptors answers "is
    /// this slot still registered?" with "no" for every slot that has ever
    /// collected, so every consented refresh returns `NeedsLogin`, the witness
    /// is pruned, and the account's limits stay dark while its refresh grant
    /// is still valid.
    #[test]
    #[serial]
    fn collector_annotated_descriptor_is_still_a_registered_slot() {
        let root = temp_dir("gate-annotated-descriptor");
        let _support_guard = EnvGuard::set(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        let store = FileClaudeConfigSlotSettingsStore::default();
        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
            .expect("grant upkeep consent");
        let config_dir = root.join("registered-account");
        fs::create_dir_all(&config_dir).expect("create config dir");
        let config_dir = config_dir.to_string_lossy().into_owned();
        let registered = store
            .register_path(
                CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                config_dir.clone(),
            )
            .expect("register anchor")
            .external_slots
            .last()
            .expect("registered slot")
            .clone();

        let mut annotated = registered.clone();
        annotated.collection.observed_at = Some("2026-09-12T18:44:32Z".to_string());
        annotated.collection.access_expires_at = Some("2026-09-11T20:46:23Z".to_string());
        annotated.collection.relogin_required_at = Some("2026-10-09T22:37:38Z".to_string());
        annotated.collection.has_account_windows = true;
        assert_ne!(
            annotated, registered,
            "the annotated descriptor must differ from its registry twin, or this proves nothing"
        );

        let publication_allowed = |descriptor| {
            registered_slot_publication_allowed(&store.load().expect("registry"), descriptor, &root)
        };
        assert!(
            publication_allowed(&annotated),
            "collector annotations are allowed"
        );

        let mut unregistered = registered.clone();
        unregistered.slot_id = "claude_slot_ffffffffffffffffffffffffffffffff".to_string();
        assert!(
            !publication_allowed(&unregistered),
            "unregistered slot refused"
        );

        let mut moved = registered.clone();
        moved.config_dir = Some(root.join("somewhere-else").to_string_lossy().into_owned());
        assert!(!publication_allowed(&moved), "changed config dir refused");

        let _ = fs::remove_dir_all(root);
    }

    fn bound_preclaim_descriptor() -> ClaudeConfigSlotDescriptorV1 {
        let mut descriptor = descriptor();
        descriptor.collection.account_identifier_hash = Some("test-account".to_string());
        descriptor.collection.organization_identifier_hash = Some("test-org".to_string());
        descriptor.collection.access_expires_at = Some("2026-08-04T10:00:00Z".to_string());
        descriptor.collection.relogin_required_at = Some("2026-09-01T00:00:00Z".to_string());
        descriptor
    }

    // Retain the retired preclaim terminal fence on the live batch publication path.
    #[test]
    #[serial]
    fn live_blocked_publication_fences_consent_binding_suppression_and_registration() {
        use crate::agent_status::persist_one_claude_slot_collection_state as persist;
        use ottto_protocol::{
            AgentDiagnosticSeverity, AgentStatusDiagnostic, ClaudeConfigSlotCollectionStateV1,
        };

        let root = temp_dir("live-publication-fences");
        let _support_guard = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", root.as_os_str());
        let config = root.join("registered");
        fs::create_dir(&config).unwrap();
        let store = FileClaudeConfigSlotSettingsStore::default();
        let registered = store
            .register_path(
                CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                config.to_string_lossy().into_owned(),
            )
            .unwrap();
        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
            .unwrap();
        let mut descriptor = registered.external_slots[0].clone();
        descriptor.collection = bound_preclaim_descriptor().collection;
        descriptor.collection.observed_at = Some("2026-08-04T10:00:00Z".to_string());
        let receipt = AgentStatusDiagnostic::source(
            "claude_slot_worker_reconciliation_refused",
            AgentDiagnosticSeverity::Info,
            "The local worker observed valid access metadata, but the same-fence proof or observation clocks did not permit saved metadata reconciliation.",
        )
        .with_observed_at(Some("2026-08-04T10:00:01Z".to_string()))
        .with_quota_binding(
            descriptor.collection.account_identifier_hash.clone(),
            descriptor.collection.organization_identifier_hash.clone(),
        );
        descriptor.collection.quota_check_diagnostics = vec![receipt.clone()];
        let mut candidate = descriptor.collection.clone();
        candidate.state = ClaudeConfigSlotCollectionStateV1::RefreshDue;
        candidate.quota_check_diagnostics.clear();
        assert!(
            preclaim_descriptor(&descriptor).is_some(),
            "complete binding and deadline"
        );
        assert!(at(receipt.observed_at.as_deref().unwrap()) <= OffsetDateTime::now_utc());
        assert!(
            at(candidate.observed_at.as_deref().unwrap())
                <= at(receipt.observed_at.as_deref().unwrap())
        );
        let publish = |current: &ottto_protocol::ClaudeConfigSlotCollectionStatusV1| {
            persist(&descriptor.slot_id, current).unwrap();
            crate::agent_status::publish_blocked_claude_slot_for_test(&descriptor, &candidate)
                .unwrap()
                .expect("published candidate")
                .quota_check_diagnostics
        };
        assert_eq!(publish(&descriptor.collection), vec![receipt.clone()]);
        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, false)
            .unwrap();
        assert!(publish(&descriptor.collection).is_empty(), "consent off");
        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
            .unwrap();
        assert_eq!(publish(&descriptor.collection), vec![receipt.clone()]);
        fs::write(root.join("claude-browser-auth-state.json"), b"{corrupt").unwrap();
        assert!(
            publish(&descriptor.collection).is_empty(),
            "suppression unavailable"
        );
        fs::remove_file(root.join("claude-browser-auth-state.json")).unwrap();
        assert_eq!(publish(&descriptor.collection), vec![receipt.clone()]);
        let mut rebound = descriptor.collection.clone();
        rebound.organization_identifier_hash = Some("other-org".to_string());
        rebound.quota_check_diagnostics[0].organization_identifier_hash =
            rebound.organization_identifier_hash.clone();
        assert!(publish(&rebound).is_empty(), "rebound binding");
        assert_eq!(publish(&descriptor.collection), vec![receipt]);
        store
            .remove(
                CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                &descriptor.slot_id,
            )
            .unwrap();
        assert!(
            publish(&descriptor.collection).is_empty(),
            "removed registration"
        );
        assert!(
            !root.join(UPKEEP_STATE_FILE).exists(),
            "live publication must not recreate the retired upkeep witness"
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn at(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &Rfc3339).expect("timestamp")
    }

    #[test]
    #[serial]
    fn live_publication_gate_rechecks_revoke_network_kill_and_removal() {
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
        let publication_allowed = || {
            registered_slot_publication_allowed(
                &store.load().expect("registry"),
                &descriptor,
                &root,
            )
        };
        assert!(publication_allowed(), "registered slot with consent");

        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, false)
            .expect("revoke");
        assert!(!publication_allowed(), "consent revoked");

        store
            .set_upkeep_consent(CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION, true)
            .expect("grant");
        assert!(publication_allowed(), "consent restored");
        fs::write(
            root.join(crate::agent_status::CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE),
            b"disabled\n",
        )
        .expect("network sentinel");
        assert!(!publication_allowed(), "network disabled");
        fs::remove_file(root.join(crate::agent_status::CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE))
            .expect("remove network sentinel");
        assert!(publication_allowed(), "network restored");

        fs::write(root.join(UPKEEP_DISABLED_FILE), b"disabled\n").expect("kill sentinel");
        assert!(!publication_allowed(), "upkeep disabled");
        fs::remove_file(root.join(UPKEEP_DISABLED_FILE)).expect("remove kill sentinel");
        assert!(publication_allowed(), "upkeep restored");

        store
            .remove(
                CLAUDE_CONFIG_SLOT_SETTINGS_SCHEMA_VERSION,
                &descriptor.slot_id,
            )
            .expect("remove slot");
        assert!(!publication_allowed(), "registration removed");
        fs::remove_dir_all(root).expect("remove test dir");
    }

    #[test]
    #[serial]
    fn retired_prune_never_creates_or_changes_files() {
        let root = temp_dir("retired-prune");
        let support = root.join("missing-support");
        let _support_guard = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support.as_os_str());
        prune_slot_upkeep_state("removed-slot").expect("absent state is harmless");
        assert!(
            !support.exists(),
            "prune must not create its support directory"
        );

        fs::create_dir(&support).expect("fixture directory");
        let lock = support.join(".claude-background-upkeep-state.lock");
        let unrelated = support.join("unrelated");
        fs::write(&lock, b"old lock bytes").expect("old lock");
        fs::write(&unrelated, b"keep me").expect("unrelated file");
        for state in [
            b"{\"schema_version\":1,\"slots\":{}}".as_slice(),
            b"{corrupt",
        ] {
            fs::write(support.join(UPKEEP_STATE_FILE), state).expect("stale state");
            prune_slot_upkeep_state("removed-slot").expect("stale state is harmless");
            prune_slot_upkeep_state("other-slot").expect("repeated prune is harmless");
            assert_eq!(fs::read(support.join(UPKEEP_STATE_FILE)).unwrap(), state);
            assert_eq!(fs::read(&lock).unwrap(), b"old lock bytes");
            assert_eq!(fs::read(&unrelated).unwrap(), b"keep me");
            assert_eq!(fs::read_dir(&support).unwrap().count(), 3);
        }
        fs::remove_dir_all(root).expect("remove fixture");
    }

    fn rfc3339_from_now(offset: TimeDuration) -> String {
        (OffsetDateTime::now_utc() + offset)
            .format(&Rfc3339)
            .expect("format timestamp")
    }

    /// A collection status persisted by a failed probe, with no deadlines:
    /// exactly what `claude auth status` exiting 1 after a CLI token rotation
    /// left behind on 2026-10-03.
    fn descriptor_without_persisted_deadline() -> ClaudeConfigSlotDescriptorV1 {
        let mut descriptor = descriptor();
        descriptor.collection.access_expires_at = None;
        descriptor.collection.relogin_required_at = None;
        descriptor.collection.upkeep = Some(ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable,
            due_access_expires_at: None,
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        });
        descriptor
    }

    fn live(state: ClaudeLocalLoginState, access: &str, refresh: &str) -> ClaudeLiveLogin {
        ClaudeLiveLogin {
            state,
            metadata: Some(metadata(access, refresh)),
        }
    }

    #[test]
    #[serial]
    fn missing_persisted_deadline_uses_the_live_read_instead_of_latching() {
        let access = rfc3339_from_now(TimeDuration::hours(7));
        let refresh = rfc3339_from_now(TimeDuration::days(20));

        let observation = observe_registered_slot_upkeep_reading(
            &descriptor_without_persisted_deadline(),
            true,
            true,
            &live(ClaudeLocalLoginState::AccessValid, &access, &refresh),
            RefreshDecision::Disabled,
            OffsetDateTime::now_utc(),
        );

        assert!(observation.proceed_with_collection);
        assert!(!observation.paused_awaiting_claude_refresh);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::NotRequired,
            "a missing persisted deadline must not latch credential_unreadable"
        );
        assert_eq!(
            observation.status.due_access_expires_at.as_deref(),
            Some(access.as_str())
        );
        assert_eq!(
            observation.status.refresh_token_expires_at.as_deref(),
            Some(refresh.as_str())
        );
    }

    /// H58 latch regression: the decision never comes from the persisted
    /// deadline. A past persisted deadline with a valid live login resumes in
    /// the same pass.
    #[test]
    #[serial]
    fn persisted_past_deadline_with_a_valid_live_login_resumes() {
        let mut descriptor = descriptor();
        descriptor.collection.access_expires_at = Some(rfc3339_from_now(-TimeDuration::hours(9)));
        descriptor.collection.upkeep = Some(ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::UpkeepDisabled,
            due_access_expires_at: descriptor.collection.access_expires_at.clone(),
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        });
        let access = rfc3339_from_now(TimeDuration::hours(8));

        let observation = observe_registered_slot_upkeep_reading(
            &descriptor,
            true,
            true,
            &live(
                ClaudeLocalLoginState::AccessValid,
                &access,
                &rfc3339_from_now(TimeDuration::days(25)),
            ),
            RefreshDecision::Disabled,
            OffsetDateTime::now_utc(),
        );

        assert!(observation.proceed_with_collection);
        assert_eq!(
            observation.status.due_access_expires_at.as_deref(),
            Some(access.as_str())
        );
    }

    #[test]
    #[serial]
    fn unreadable_or_absent_live_login_lets_resolution_report_the_exact_failure() {
        let unreadable = observe_registered_slot_upkeep_reading(
            &descriptor_without_persisted_deadline(),
            true,
            true,
            &ClaudeLiveLogin::unreadable(),
            RefreshDecision::Disabled,
            OffsetDateTime::now_utc(),
        );
        assert!(unreadable.proceed_with_collection);
        assert_eq!(
            unreadable.status.result,
            ClaudeConfigSlotUpkeepResultV1::ProbeFailed
        );

        let absent = observe_registered_slot_upkeep_reading(
            &descriptor_without_persisted_deadline(),
            true,
            true,
            &ClaudeLiveLogin {
                state: ClaudeLocalLoginState::NotSignedIn,
                metadata: None,
            },
            RefreshDecision::Disabled,
            OffsetDateTime::now_utc(),
        );
        assert!(absent.proceed_with_collection);
        assert_eq!(
            absent.status.result,
            ClaudeConfigSlotUpkeepResultV1::CredentialUnreadable
        );
    }

    #[test]
    #[serial]
    fn network_off_switch_pauses_collection_without_a_live_read() {
        let observation = observe_registered_slot_upkeep_reading(
            &descriptor(),
            true,
            false,
            &ClaudeLiveLogin::unreadable(),
            RefreshDecision::Disabled,
            OffsetDateTime::now_utc(),
        );
        assert!(!observation.proceed_with_collection);
        assert_eq!(
            observation.status.result,
            ClaudeConfigSlotUpkeepResultV1::CollectionPaused
        );
    }

    /// T5: five expired, consented anchors pause in the foreground. Nothing is
    /// enqueued, no worker thread starts, and an old `Backoff` witness from a
    /// pre-upgrade worker is not resurrected.
    #[test]
    #[serial]
    fn expired_consented_slots_pause_without_enqueueing_or_resurrecting_witnesses() {
        let root = temp_dir("five-expired-paused");
        let _support_guard = EnvGuard::set(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            root.as_os_str().to_os_string(),
        );
        let access = rfc3339_from_now(-TimeDuration::hours(2));
        let refresh = rfc3339_from_now(TimeDuration::days(20));
        let mut slots = serde_json::Map::new();
        let mut descriptors = Vec::new();
        for index in 0..5 {
            let mut descriptor = descriptor();
            descriptor.slot_id = format!("claude_slot_0123456789abcdef0123456789abcd{index:02}");
            descriptor.collection.access_expires_at = Some(access.clone());
            descriptor.collection.relogin_required_at = Some(refresh.clone());
            slots.insert(
                descriptor.slot_id.clone(),
                serde_json::json!({
                    "due_access_expires_at": access,
                    "refresh_token_expires_at": refresh,
                    "attempted_at": rfc3339_from_now(-TimeDuration::minutes(30)),
                    "result_observed_at": rfc3339_from_now(-TimeDuration::minutes(29)),
                    "next_allowed_attempt_at": rfc3339_from_now(TimeDuration::hours(5)),
                    "result": "backoff",
                    "consecutive_failures": 3
                }),
            );
            descriptors.push(descriptor);
        }
        // Freeze the retired wire shape independently of any production codec.
        let state = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "slots": slots
        }))
        .expect("old worker fixture");
        fs::write(root.join(UPKEEP_STATE_FILE), &state).expect("old worker witnesses");

        for descriptor in &descriptors {
            let observation = observe_registered_slot_upkeep(
                descriptor,
                true,
                true,
                &live(ClaudeLocalLoginState::RefreshPending, &access, &refresh),
                RefreshDecision::Disabled,
            );
            assert!(!observation.proceed_with_collection);
            assert!(observation.paused_awaiting_claude_refresh);
            assert_ne!(
                observation.status.result,
                ClaudeConfigSlotUpkeepResultV1::Backoff,
                "an old witness must not be resurrected"
            );
            assert_eq!(observation.status.consecutive_failures, 0);
            assert_eq!(observation.status.next_allowed_attempt_at, None);
        }
        assert_eq!(
            fs::read(root.join(UPKEEP_STATE_FILE)).expect("state bytes"),
            state,
            "the foreground never rewrites the old upkeep state"
        );
        let _ = fs::remove_dir_all(root);
    }

    fn cli_cleared_metadata() -> ClaudeOAuthCredentialMetadata {
        ClaudeOAuthCredentialMetadata {
            access_expires_at: Some("1970-01-01T00:00:00Z".to_string()),
            refresh_token_expires_at: Some(rfc3339_from_now(TimeDuration::days(25))),
            has_refresh_token: false,
            cleared_by_cli: true,
            has_profile_scope: false,
        }
    }

    #[test]
    #[serial]
    fn needs_login_slot_resumes_once_the_stored_item_carries_tokens_again() {
        let mut waiting = descriptor();
        waiting.collection.access_expires_at = Some("1970-01-01T00:00:00Z".to_string());
        waiting.collection.upkeep = Some(ClaudeConfigSlotUpkeepStatusV1 {
            result: ClaudeConfigSlotUpkeepResultV1::NeedsLogin,
            due_access_expires_at: Some("1970-01-01T00:00:00Z".to_string()),
            refresh_token_expires_at: None,
            attempted_at: None,
            next_allowed_attempt_at: None,
            consecutive_failures: 0,
        });

        let still_cleared = observe_registered_slot_upkeep_reading(
            &waiting,
            true,
            true,
            &ClaudeLiveLogin {
                state: ClaudeLocalLoginState::SignedOutByCli,
                metadata: Some(cli_cleared_metadata()),
            },
            RefreshDecision::Disabled,
            OffsetDateTime::now_utc(),
        );
        assert!(!still_cleared.proceed_with_collection);
        assert_eq!(
            still_cleared.status.result,
            ClaudeConfigSlotUpkeepResultV1::NeedsLogin
        );

        let access = rfc3339_from_now(TimeDuration::hours(8));
        let reconnected = observe_registered_slot_upkeep_reading(
            &waiting,
            true,
            true,
            &live(
                ClaudeLocalLoginState::AccessValid,
                &access,
                &rfc3339_from_now(TimeDuration::days(30)),
            ),
            RefreshDecision::Disabled,
            OffsetDateTime::now_utc(),
        );
        assert!(
            reconnected.proceed_with_collection,
            "a reconnect resumes collection without a manual state reset"
        );
        assert_eq!(
            reconnected.status.result,
            ClaudeConfigSlotUpkeepResultV1::NotRequired
        );
        assert_eq!(
            reconnected.status.due_access_expires_at.as_deref(),
            Some(access.as_str())
        );
    }
}
