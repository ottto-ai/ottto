//! Local-only, command-scoped v28 session handoff and display nicknames.
//! Response fields are optional for mixed CLI/daemon/app upgrades. Unknown enum
//! values are inert: callers must explicitly accept a known successful outcome.
use crate::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SESSION_LAUNCH_CONTROL_PROTOCOL_VERSION: u16 = 28;
pub const ACCOUNT_NICKNAME_CONTROL_PROTOCOL_VERSION: u16 = 28;

macro_rules! lenient_enum {
    ($name:ident { $($variant:ident),* $(,)? }) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant,)* #[default] #[serde(other)] Unknown }
    };
}

lenient_enum!(SessionLaunchProviderV1 { ClaudeCode, Codex });
lenient_enum!(SessionLaunchOutcomeV1 { Ready, Blocked });
lenient_enum!(SessionLaunchStateV1 {
    Pending,
    Starting,
    Blocked,
    Expired
});
lenient_enum!(SessionLaunchSettingLayerV1 {
    User,
    Local,
    Project,
    ProjectLocal,
    Managed,
    Shell
});
lenient_enum!(SessionLaunchBlockReasonV1 {
    SlotNotFound,
    SlotNeedsLogin,
    AccountMismatch,
    SlotNotVerified,
    CliNotFound,
    CliVersionUnsupported,
    CliChanged,
    CloudProviderRoute,
    ApiKeyRoute,
    SettingsEnvOverride,
    ForcedLoginMethod,
    ForcedOrgMismatch,
    CodexProviderNotOpenai,
    CodexApiKeyLogin,
    SettingsUnreadable,
    SettingsMalformed,
    ConfigUnsupported,
    FolderMissing,
    FolderNotDirectory,
    FolderNotLocal,
    FolderInvalid,
    FolderChanged,
    LauncherDirUnsafe,
    LaunchExpired,
    LaunchAlreadyUsed,
    LaunchUnknown,
    LaunchCancelled,
    LaunchLimit,
    ExecFailed,
    ChdirFailed,
    DaemonTooOld
});
lenient_enum!(SessionLaunchFolderKindV1 {
    Directory,
    Repository,
    Worktree
});
lenient_enum!(SessionLaunchRecencyPrecisionV1 { Exact, Day });
lenient_enum!(AccountNicknameOutcomeV1 {
    Saved,
    NotConnected,
    Unavailable,
    Invalid,
    TargetUnknown
});

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchFolderV1 {
    pub path: Option<String>,
    pub recent_id: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchBlockV1 {
    pub reason: SessionLaunchBlockReasonV1,
    pub setting_layer: Option<SessionLaunchSettingLayerV1>,
    pub detail_code: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchPrepareResultV1 {
    pub outcome: Option<SessionLaunchOutcomeV1>,
    pub launch_id: Option<String>,
    pub launcher_path: Option<String>,
    pub expires_at: Option<String>,
    pub block: Option<SessionLaunchBlockV1>,
    pub folder_label: Option<String>,
    pub cli_version: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchExecPlanV1 {
    pub program: Option<String>,
    pub argv: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub cwd_dev: Option<u64>,
    pub cwd_ino: Option<u64>,
    pub env_unset: Option<Vec<String>>,
    pub env_set: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchConsumeResultV1 {
    pub state: Option<SessionLaunchStateV1>,
    pub plan: Option<SessionLaunchExecPlanV1>,
    pub attempt_id: Option<SecretString>,
    pub block: Option<SessionLaunchBlockV1>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchStatusV1 {
    pub state: Option<SessionLaunchStateV1>,
    pub block: Option<SessionLaunchBlockV1>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchRecentFolderV1 {
    pub id: Option<String>,
    pub path: Option<String>,
    pub label: Option<String>,
    pub kind: Option<SessionLaunchFolderKindV1>,
    pub repository_label: Option<String>,
    pub last_used_at: Option<String>,
    pub last_used_day: Option<String>,
    pub precision: Option<SessionLaunchRecencyPrecisionV1>,
    pub live: Option<bool>,
    pub providers: Option<Vec<SessionLaunchProviderV1>>,
    pub slot_ids: Option<Vec<String>>,
    pub with_this_login: Option<bool>,
    pub exists: Option<bool>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLaunchRecentFoldersV1 {
    pub items: Option<Vec<SessionLaunchRecentFolderV1>>,
    pub partial: Option<bool>,
    pub partial_reason: Option<String>,
    pub cli_launchable: Option<bool>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountNicknamePairV1 {
    pub source: SessionLaunchProviderV1,
    pub account_identifier_hash: Option<String>,
    pub organization_identifier_hash: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountNicknameV1 {
    pub pair: Option<AccountNicknamePairV1>,
    pub nickname: Option<SecretString>,
    pub revision: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountNicknamesV1 {
    pub entries: Option<Vec<AccountNicknameV1>>,
    pub stale: Option<bool>,
    pub connected: Option<bool>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountNicknameSetResultV1 {
    pub outcome: Option<AccountNicknameOutcomeV1>,
    pub entry: Option<AccountNicknameV1>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expected_local_control_protocol_version, LocalControlCommand, LocalControlRequest,
    };
    use serde_json::json;

    #[test]
    fn v28_is_command_scoped_and_all_commands_roundtrip() {
        let commands = [
            json!({"command":"session_launch_prepare", "schema_version":1, "provider":"codex", "slot_id":"default", "expected_account_identifier_hash":"abc", "folder":{"path":"/tmp/project"}}),
            json!({"command":"session_launch_consume", "schema_version":1, "launch_id":"one", "secret":"secret"}),
            json!({"command":"session_launch_report", "schema_version":1, "launch_id":"one", "attempt_id":"attempt", "reason":"exec_failed"}),
            json!({"command":"session_launch_status", "schema_version":1, "launch_id":"one"}),
            json!({"command":"session_launch_cancel", "schema_version":1, "launch_id":"one"}),
            json!({"command":"session_launch_recent_folders", "schema_version":1}),
            json!({"command":"account_nicknames"}),
            json!({"command":"account_nickname_set", "source":"codex", "account_identifier_hash":"abc"}),
        ];
        for command in commands {
            let mut wire = command;
            wire["request_id"] = json!("v28-test");
            wire["protocol_version"] = json!(28);
            let request: LocalControlRequest = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(
                expected_local_control_protocol_version(&request.command),
                28
            );
            let encoded = serde_json::to_value(request).unwrap();
            serde_json::from_value::<LocalControlRequest>(encoded).unwrap();
            wire["protocol_version"] = json!(27);
            assert!(serde_json::from_value::<LocalControlRequest>(wire).is_err());
        }
        assert_eq!(
            expected_local_control_protocol_version(&LocalControlCommand::AuthStatus),
            15
        );
    }

    #[test]
    fn missing_fields_and_future_enums_are_inert() {
        let result: SessionLaunchConsumeResultV1 =
            serde_json::from_value(json!({"state":"started"})).unwrap();
        assert_eq!(result.state, Some(SessionLaunchStateV1::Unknown));
        assert!(result.plan.is_none());
        let result: SessionLaunchPrepareResultV1 = serde_json::from_value(json!({})).unwrap();
        assert!(result.outcome.is_none());
        assert_eq!(
            serde_json::from_value::<SessionLaunchProviderV1>(json!("future")).unwrap(),
            SessionLaunchProviderV1::Unknown
        );
    }

    #[test]
    fn terminal_handoff_fixture_keeps_its_exact_version() {
        let request: LocalControlRequest = serde_json::from_str(include_str!(
            "../../../fixtures/cli/session-launch-consume-request.json"
        ))
        .unwrap();
        assert_eq!(request.protocol_version, 28);
        assert!(matches!(
            request.command,
            LocalControlCommand::SessionLaunchConsume {
                schema_version: 1,
                ..
            }
        ));
    }
}
