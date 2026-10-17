use ottto_protocol::{
    CliError, CliErrorCode, DaemonRuntimeState, DaemonStatus, HealthProblem, InstallOwner,
    LocalAccountBinding, MachineIdentity, RedactedValue, RelayRuntimeState, RelayState,
    ReleaseChannel, StableMessage, StableProblemCode, UpdateGate, UpdateState, UpdateStatus,
    PROTOCOL_VERSION,
};
use std::collections::BTreeMap;

pub fn empty_status(machine: MachineIdentity, now: impl Into<String>) -> DaemonStatus {
    DaemonStatus {
        protocol_version: PROTOCOL_VERSION,
        daemon_version: compiled_release_version(),
        machine,
        account: LocalAccountBinding::not_connected(),
        daemon: DaemonRuntimeState::Running,
        relay: RelayState {
            state: RelayRuntimeState::Unknown,
            endpoint: None,
            last_connected_at: None,
            last_error: None,
        },
        sources: Vec::new(),
        service_owner: Default::default(),
        update: UpdateState {
            current_version: compiled_release_version(),
            latest_version: None,
            channel: compiled_release_channel(),
            status: UpdateStatus::Unknown,
            gate: UpdateGate::Unknown,
            install_owner: InstallOwner::Unknown,
            min_supported_version: None,
            min_protocol_version: None,
            checked_at: None,
            reason: Some("update check has not run".to_string()),
            download_url: None,
            build_id: compiled_build_id(),
            update_command: None,
            update_instructions: None,
            release_notes: None,
        },
        canonical_health: None,
        runtime_heartbeat: None,
        local_health_events: Vec::new(),
        command_ledger: Vec::new(),
        native_comparison: None,
        generated_at: now.into(),
    }
}

pub fn compiled_release_version() -> String {
    option_env!("OTTTO_RELEASE_VERSION")
        .filter(|value| !value.is_empty())
        .unwrap_or(env!("CARGO_PKG_VERSION"))
        .to_string()
}

pub fn compiled_build_id() -> Option<String> {
    option_env!("GIT_COMMIT")
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub fn compiled_release_channel() -> ReleaseChannel {
    release_channel_from_str(option_env!("OTTTO_RELEASE_CHANNEL").unwrap_or("dev"))
}

pub fn release_channel_from_str(value: &str) -> ReleaseChannel {
    match value {
        "stable" => ReleaseChannel::Stable,
        "stable-candidate" => ReleaseChannel::StableCandidate,
        "preview" => ReleaseChannel::Preview,
        _ => ReleaseChannel::Dev,
    }
}

pub fn problem(
    code: StableProblemCode,
    title: impl Into<String>,
    detail: impl Into<String>,
    retryable: bool,
) -> HealthProblem {
    HealthProblem {
        code,
        title: title.into(),
        detail: detail.into(),
        retryable,
    }
}

pub fn daemon_unavailable_error(message: impl Into<String>) -> CliError {
    CliError {
        code: CliErrorCode::DaemonUnavailable,
        message: message.into(),
        retryable: true,
        details: BTreeMap::<String, RedactedValue>::new(),
    }
}

pub fn message(code: impl Into<String>, text: impl Into<String>) -> StableMessage {
    StableMessage {
        code: code.into(),
        text: text.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::OperatingSystem;

    #[test]
    fn empty_status_uses_protocol_version() {
        let status = empty_status(
            MachineIdentity {
                machine_id: "machine_test".to_string(),
                installation_id: "install_test".to_string(),
                display_name: "Local Mac".to_string(),
                hostname: "local-mac".to_string(),
                os: OperatingSystem::Macos,
                arch: "arm64".to_string(),
                local_platform_version: "0.1.0".to_string(),
                hardware_uuid: None,
                account_scope: None,
            },
            "2026-05-05T00:00:00Z",
        );

        assert_eq!(status.protocol_version, PROTOCOL_VERSION);
        assert_eq!(status.daemon_version, compiled_release_version());
        assert_eq!(status.sources.len(), 0);
        assert_eq!(status.update.current_version, compiled_release_version());
        // Older/inactive payloads remain byte-shape compatible: optional local
        // diagnostics are absent, and missing diagnostics decode as UNKNOWN.
        let old = serde_json::to_value(&status).unwrap();
        assert!(old.get("native_comparison").is_none());
        let old_decoded: DaemonStatus = serde_json::from_value(old).unwrap();
        assert!(old_decoded.native_comparison.is_none());
        let mut with_diagnostics = status;
        with_diagnostics.native_comparison = Some(ottto_protocol::NativeComparisonStatus {
            observation_available: true,
            in_flight: true,
            deferred_family_count: Some(1),
            withheld_candidate_count: Some(2),
            withheld_new_local_candidate_count: Some(1),
            prior_process_debt_unknown: true,
            counts_are_upper_bounds: true,
            ..Default::default()
        });
        let encoded = serde_json::to_value(&with_diagnostics).unwrap();
        assert!(encoded["native_comparison"]["unknown_age_family_count"].is_null());
        assert_eq!(
            encoded["native_comparison"]["withheld_new_local_candidate_count"],
            1
        );
        let decoded: DaemonStatus = serde_json::from_value(encoded).unwrap();
        assert_eq!(
            decoded.native_comparison,
            with_diagnostics.native_comparison
        );
    }

    #[test]
    fn release_channel_from_str_defaults_to_dev() {
        assert_eq!(release_channel_from_str("dev"), ReleaseChannel::Dev);
        assert_eq!(release_channel_from_str("preview"), ReleaseChannel::Preview);
        assert_eq!(
            release_channel_from_str("stable-candidate"),
            ReleaseChannel::StableCandidate
        );
        assert_eq!(release_channel_from_str("stable"), ReleaseChannel::Stable);
        assert_eq!(release_channel_from_str("unexpected"), ReleaseChannel::Dev);
    }
}
