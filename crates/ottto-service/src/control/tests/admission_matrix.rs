//! Caller outcomes through the request entry: every command's cell for each
//! caller column and the launch identity fence, backend-token authority, Verify
//! effects, public updates, check precedence, internal against manual
//! verification, and output profiles.

use super::*;
use crate::test_effects::{Effect, Recording, Scalar};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cell {
    InvalidRequest,
    NotTrusted,
    AuthFailed,
    Poisoned,
    Ok,
    NeedsUserAction,
    Internal,
    BackendResponseUnexpected,
    NetworkUnavailable,
}
use Cell::{
    AuthFailed as A, BackendResponseUnexpected as B, Internal as H, InvalidRequest as I,
    NeedsUserAction as U, NetworkUnavailable as X, NotTrusted as N, Ok as O, Poisoned as P,
};

struct Row {
    name: &'static str,
    authority: &'static str,
    sample: fn() -> LocalControlCommand,
    cells: [Cell; 12],
}

// Cells are literal, in COLUMNS order; this oracle reads no production policy.
const ROWS: &[Row] = &[
    Row {
        name: "SessionLaunchPrepare",
        authority: "Local",
        sample: || LocalControlCommand::SessionLaunchPrepare {
            schema_version: 0,
            provider: ottto_protocol::SessionLaunchProviderV1::Codex,
            slot_id: "missing".into(),
            expected_account_identifier_hash: "".into(),
            expected_organization_identifier_hash: None,
            folder: ottto_protocol::SessionLaunchFolderV1 {
                path: None,
                recent_id: None,
            },
            terminal: None,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "SessionLaunchConsume",
        authority: "LocalCli",
        sample: || LocalControlCommand::SessionLaunchConsume {
            schema_version: 0,
            launch_id: "missing".into(),
            secret: SecretString::new("synthetic"),
        },
        cells: [I, N, N, N, A, A, I, A, A, P, P, A],
    },
    Row {
        name: "SessionLaunchReport",
        authority: "LocalCli",
        sample: || LocalControlCommand::SessionLaunchReport {
            schema_version: 0,
            launch_id: "missing".into(),
            attempt_id: SecretString::new("synthetic"),
            reason: ottto_protocol::SessionLaunchBlockReasonV1::ExecFailed,
        },
        cells: [I, N, N, N, A, A, I, A, A, P, P, A],
    },
    Row {
        name: "SessionLaunchStatus",
        authority: "Local",
        sample: || LocalControlCommand::SessionLaunchStatus {
            schema_version: 0,
            launch_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "SessionLaunchCancel",
        authority: "Local",
        sample: || LocalControlCommand::SessionLaunchCancel {
            schema_version: 0,
            launch_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "SessionLaunchRecentFolders",
        authority: "Local",
        sample: || LocalControlCommand::SessionLaunchRecentFolders {
            schema_version: 0,
            provider: None,
            slot_id: None,
            limit: None,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AccountNicknames",
        authority: "Local",
        sample: || LocalControlCommand::AccountNicknames,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "AccountNicknameSet",
        authority: "Local",
        sample: || LocalControlCommand::AccountNicknameSet {
            source: ottto_protocol::SessionLaunchProviderV1::Codex,
            account_identifier_hash: "".into(),
            organization_identifier_hash: None,
            nickname: None,
            base_revision: None,
        },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "Status",
        authority: "Local",
        sample: || LocalControlCommand::Status {
            refresh_agent_status: false,
            retry_relay_authorization: false,
        },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "Receipts",
        authority: "Local",
        sample: || LocalControlCommand::Receipts {
            limit: 0,
            since: None,
            source: None,
            before: None,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AuthStatus",
        authority: "Local",
        sample: || LocalControlCommand::AuthStatus,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "AgentStatusRefresh",
        authority: "Local",
        sample: || LocalControlCommand::AgentStatusRefresh {
            source: Some(SourceKind::Pi),
            quota_refresh: false,
        },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "AgentStatusCached",
        authority: "LocalNoPoisonCheck",
        sample: || LocalControlCommand::AgentStatusCached { source: None },
        cells: [I, N, N, N, A, A, O, O, O, O, O, A],
    },
    Row {
        name: "PersonalMeterLocalSnapshot",
        authority: "Local",
        sample: || LocalControlCommand::PersonalMeterLocalSnapshot { source: None },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "AgentContext",
        authority: "Local",
        sample: || LocalControlCommand::AgentContext {
            query: Default::default(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AgentCosts",
        authority: "Local",
        sample: || LocalControlCommand::AgentCosts {
            query: Default::default(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AgentSessions",
        authority: "Local",
        sample: || LocalControlCommand::AgentSessions {
            query: Default::default(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AgentRecommendations",
        authority: "Local",
        sample: || LocalControlCommand::AgentRecommendations {
            query: Default::default(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AgentProviderImpact",
        authority: "Local",
        sample: || LocalControlCommand::AgentProviderImpact {
            query: Default::default(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CloudStatus",
        authority: "Local",
        sample: || LocalControlCommand::CloudStatus { source: None },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CloudConnectCancel",
        authority: "LocalCli",
        sample: || LocalControlCommand::CloudConnectCancel {
            attempt_id: "".into(),
            timeout_ms: 0,
        },
        cells: [I, N, N, N, A, A, O, A, A, P, P, A],
    },
    Row {
        name: "CloudConnectPoll",
        authority: "LocalCli",
        sample: || LocalControlCommand::CloudConnectPoll {
            attempt_id: "".into(),
            observed_aws_account_id: "".into(),
            timeout_ms: 0,
        },
        cells: [I, N, N, N, A, A, O, A, A, P, P, A],
    },
    Row {
        name: "CloudConnectSubmit",
        authority: "LocalCli",
        sample: || LocalControlCommand::CloudConnectSubmit {
            attempt_id: "".into(),
            body: ottto_protocol::CloudConnectSubmit {
                input_revision: 0,
                account_id: "".into(),
                stack_id: "".into(),
                request_id: "".into(),
            },
            timeout_ms: 0,
        },
        cells: [I, N, N, N, A, A, O, A, A, P, P, A],
    },
    Row {
        name: "CloudConnectEnsure",
        authority: "LocalCli",
        sample: || LocalControlCommand::CloudConnectEnsure {
            body: ottto_protocol::CloudConnectEnsure {
                source: "".into(),
                reconnect: false,
                restart: false,
                metrics: false,
                client_request_id: "".into(),
                observed_aws_account_id: "".into(),
            },
            timeout_ms: 0,
        },
        cells: [I, N, N, N, A, A, O, A, A, P, P, A],
    },
    Row {
        name: "CloudConnectStatus",
        authority: "LocalCli",
        sample: || LocalControlCommand::CloudConnectStatus {
            attempt_id: None,
            timeout_ms: 0,
        },
        cells: [I, N, N, N, A, A, O, A, A, P, P, A],
    },
    Row {
        name: "AuthStart",
        authority: "Local",
        sample: || LocalControlCommand::AuthStart,
        cells: [I, N, N, N, A, A, B, B, B, P, P, A],
    },
    Row {
        name: "AuthComplete",
        authority: "Local",
        sample: || LocalControlCommand::AuthComplete {
            claim_code: "missing".into(),
            nonce: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AuthCompletePending",
        authority: "Local",
        sample: || LocalControlCommand::AuthCompletePending {
            claim_code: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AuthSwitchAccount",
        authority: "Local",
        sample: || LocalControlCommand::AuthSwitchAccount {
            claim_code: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "AuthReset",
        authority: "Local",
        sample: || LocalControlCommand::AuthReset {
            local_only: false,
            forget_installation: false,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "Account",
        authority: "Local",
        sample: || LocalControlCommand::Account,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "ClaudeAccountsStatus",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountsStatus,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "ClaudeAccountSetUpkeepConsent",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountSetUpkeepConsent {
            schema_version: 0,
            consent: false,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountRemove",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountRemove {
            schema_version: 0,
            slot_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountRegisterPath",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountRegisterPath {
            schema_version: 0,
            config_dir: "".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountPrepare",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountPrepare {
            schema_version: 0,
            operation_id: "missing".into(),
            expected_account_identifier_hash: None,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountPrepareTarget",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountPrepareTarget {
            schema_version: 0,
            operation_id: "missing".into(),
            target_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountReconnect",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountReconnect {
            schema_version: 0,
            operation_id: "missing".into(),
            slot_id: "missing".into(),
            expected_account_identifier_hash: "".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountReconnectTarget",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountReconnectTarget {
            schema_version: 0,
            operation_id: "missing".into(),
            slot_id: "missing".into(),
            target_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountCheck",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountCheck {
            schema_version: 0,
            operation_id: "missing".into(),
            expected_account_identifier_hash: None,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountStopWaiting",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountStopWaiting {
            schema_version: 0,
            operation_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountStartBrowserLogin",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountStartBrowserLogin {
            schema_version: 0,
            operation_id: "missing".into(),
            target_id: Some("missing".into()),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "ClaudeAccountStartBrowserReconnect",
        authority: "Local",
        sample: || LocalControlCommand::ClaudeAccountStartBrowserReconnect {
            schema_version: 0,
            operation_id: "missing".into(),
            slot_id: "missing".into(),
            target_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "RetiredClaudeAccountSubmitAuthCode",
        authority: "Local",
        sample: || LocalControlCommand::RetiredClaudeAccountSubmitAuthCode {},
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountsStatus",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountsStatus,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "CodexAccountPrepare",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountPrepare {
            schema_version: 0,
            operation_id: "missing".into(),
            expected_account_identifier_hash: "".into(),
            expected_workspace_identifier_hash: "".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountPrepareOpen",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountPrepareOpen {
            schema_version: 0,
            operation_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountPrepareTarget",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountPrepareTarget {
            schema_version: 0,
            operation_id: "missing".into(),
            target_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountReconnect",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountReconnect {
            schema_version: 0,
            operation_id: "missing".into(),
            slot_id: "missing".into(),
            expected_account_identifier_hash: "".into(),
            expected_workspace_identifier_hash: "".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountCheck",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountCheck {
            schema_version: 0,
            operation_id: "missing".into(),
            explicit: false,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountStartSignIn",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountStartSignIn {
            schema_version: 0,
            operation_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountStopWaiting",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountStopWaiting {
            schema_version: 0,
            operation_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountRemove",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountRemove {
            schema_version: 0,
            slot_id: "missing".into(),
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "CodexAccountSetQuotaRefreshConsent",
        authority: "Local",
        sample: || LocalControlCommand::CodexAccountSetQuotaRefreshConsent {
            schema_version: 0,
            consent: false,
        },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "Detect",
        authority: "Local",
        sample: || LocalControlCommand::Detect {
            source: SourceKind::Pi,
        },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "Setup",
        authority: "Local",
        sample: || LocalControlCommand::Setup {
            sources: vec![],
            claim_code: None,
            setup_run_id: None,
            // An untrusted destination is refused before any keychain read.
            api_base_url: Some("invalid".into()),
        },
        cells: [I, N, N, N, A, A, X, X, X, P, P, A],
    },
    Row {
        name: "SetupAnswer",
        authority: "Local",
        sample: || LocalControlCommand::SetupAnswer {
            source: SourceKind::Pi,
            answer_type: "unknown".into(),
            api_base_url: None,
        },
        cells: [I, N, N, N, A, A, U, U, U, P, P, A],
    },
    Row {
        name: "SetupAction",
        authority: "Local",
        sample: || LocalControlCommand::SetupAction {
            source: SourceKind::Pi,
            action_type: "unknown".into(),
            api_base_url: None,
        },
        cells: [I, N, N, N, A, A, U, U, U, P, P, A],
    },
    Row {
        name: "SourceCollection",
        authority: "Local",
        sample: || LocalControlCommand::SourceCollection {
            source: SourceKind::Pi,
            enabled: true,
        },
        cells: [I, N, N, N, A, A, H, H, H, P, P, A],
    },
    Row {
        name: "TelemetryControl",
        authority: "TelemetryToken",
        sample: || LocalControlCommand::TelemetryControl {
            action: TelemetryControlAction::Status,
            source: SourceKind::Codex,
            control_token: "".into(),
            api_base_url: None,
            key_id: None,
            organization_id: None,
            otlp_endpoint: None,
            ingest_key: None,
        },
        cells: [I, N, N, N, N, N, N, N, N, N, N, N],
    },
    Row {
        name: "ProviderDailyReferenceControl",
        authority: "DailyReferenceToken",
        sample: || LocalControlCommand::ProviderDailyReferenceControl {
            action: ProviderDailyReferenceControlAction::Status,
            control_token: SecretString::new(""),
            api_base_url: None,
            backend_grant: None,
            expected_account_fingerprint: None,
        },
        cells: [I, N, N, N, N, N, N, N, N, N, N, N],
    },
    Row {
        name: "Repair",
        authority: "Local",
        sample: || LocalControlCommand::Repair {
            source: SourceKind::Pi,
            dry_run: true,
        },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "Verify",
        authority: "Local",
        sample: || LocalControlCommand::Verify {
            source: SourceKind::Pi,
            repair: false,
        },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "RelayStart",
        authority: "Local",
        sample: || LocalControlCommand::RelayStart,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "RelayStop",
        authority: "Local",
        sample: || LocalControlCommand::RelayStop,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "DiagnosticsCollect",
        authority: "Local",
        sample: || LocalControlCommand::DiagnosticsCollect {
            upload: false,
            upload_approval: None,
            api_base_url: None,
        },
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "UpdateCheck",
        authority: "Public",
        sample: || LocalControlCommand::UpdateCheck,
        cells: [I, O, O, O, O, O, O, O, O, O, O, O],
    },
    Row {
        name: "UninstallPlan",
        authority: "Local",
        sample: || LocalControlCommand::UninstallPlan,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
    Row {
        name: "UninstallExecute",
        authority: "Local",
        sample: || LocalControlCommand::UninstallExecute { confirm: false },
        cells: [I, N, N, N, A, A, I, I, I, P, P, A],
    },
    Row {
        name: "Uninstall",
        authority: "Local",
        sample: || LocalControlCommand::Uninstall,
        cells: [I, N, N, N, A, A, O, O, O, P, P, A],
    },
];

fn row_name(command: &LocalControlCommand) -> &'static str {
    match command {
        LocalControlCommand::SessionLaunchPrepare { .. } => "SessionLaunchPrepare",
        LocalControlCommand::SessionLaunchConsume { .. } => "SessionLaunchConsume",
        LocalControlCommand::SessionLaunchReport { .. } => "SessionLaunchReport",
        LocalControlCommand::SessionLaunchStatus { .. } => "SessionLaunchStatus",
        LocalControlCommand::SessionLaunchCancel { .. } => "SessionLaunchCancel",
        LocalControlCommand::SessionLaunchRecentFolders { .. } => "SessionLaunchRecentFolders",
        LocalControlCommand::AccountNicknames => "AccountNicknames",
        LocalControlCommand::AccountNicknameSet { .. } => "AccountNicknameSet",
        LocalControlCommand::Status { .. } => "Status",
        LocalControlCommand::Receipts { .. } => "Receipts",
        LocalControlCommand::AuthStatus => "AuthStatus",
        LocalControlCommand::AgentStatusRefresh { .. } => "AgentStatusRefresh",
        LocalControlCommand::AgentStatusCached { .. } => "AgentStatusCached",
        LocalControlCommand::PersonalMeterLocalSnapshot { .. } => "PersonalMeterLocalSnapshot",
        LocalControlCommand::AgentContext { .. } => "AgentContext",
        LocalControlCommand::AgentCosts { .. } => "AgentCosts",
        LocalControlCommand::AgentSessions { .. } => "AgentSessions",
        LocalControlCommand::AgentRecommendations { .. } => "AgentRecommendations",
        LocalControlCommand::AgentProviderImpact { .. } => "AgentProviderImpact",
        LocalControlCommand::CloudConnectStatus { .. } => "CloudConnectStatus",
        LocalControlCommand::CloudConnectEnsure { .. } => "CloudConnectEnsure",
        LocalControlCommand::CloudConnectSubmit { .. } => "CloudConnectSubmit",
        LocalControlCommand::CloudConnectPoll { .. } => "CloudConnectPoll",
        LocalControlCommand::CloudConnectCancel { .. } => "CloudConnectCancel",
        LocalControlCommand::CloudStatus { .. } => "CloudStatus",
        LocalControlCommand::AuthStart => "AuthStart",
        LocalControlCommand::AuthComplete { .. } => "AuthComplete",
        LocalControlCommand::AuthCompletePending { .. } => "AuthCompletePending",
        LocalControlCommand::AuthSwitchAccount { .. } => "AuthSwitchAccount",
        LocalControlCommand::AuthReset { .. } => "AuthReset",
        LocalControlCommand::Account => "Account",
        LocalControlCommand::ClaudeAccountsStatus => "ClaudeAccountsStatus",
        LocalControlCommand::ClaudeAccountSetUpkeepConsent { .. } => {
            "ClaudeAccountSetUpkeepConsent"
        }
        LocalControlCommand::ClaudeAccountRemove { .. } => "ClaudeAccountRemove",
        LocalControlCommand::ClaudeAccountRegisterPath { .. } => "ClaudeAccountRegisterPath",
        LocalControlCommand::ClaudeAccountPrepare { .. } => "ClaudeAccountPrepare",
        LocalControlCommand::ClaudeAccountPrepareTarget { .. } => "ClaudeAccountPrepareTarget",
        LocalControlCommand::ClaudeAccountReconnect { .. } => "ClaudeAccountReconnect",
        LocalControlCommand::ClaudeAccountReconnectTarget { .. } => "ClaudeAccountReconnectTarget",
        LocalControlCommand::ClaudeAccountCheck { .. } => "ClaudeAccountCheck",
        LocalControlCommand::ClaudeAccountStopWaiting { .. } => "ClaudeAccountStopWaiting",
        LocalControlCommand::ClaudeAccountStartBrowserLogin { .. } => {
            "ClaudeAccountStartBrowserLogin"
        }
        LocalControlCommand::ClaudeAccountStartBrowserReconnect { .. } => {
            "ClaudeAccountStartBrowserReconnect"
        }
        LocalControlCommand::RetiredClaudeAccountSubmitAuthCode {} => {
            "RetiredClaudeAccountSubmitAuthCode"
        }
        LocalControlCommand::CodexAccountsStatus => "CodexAccountsStatus",
        LocalControlCommand::CodexAccountPrepare { .. } => "CodexAccountPrepare",
        LocalControlCommand::CodexAccountPrepareOpen { .. } => "CodexAccountPrepareOpen",
        LocalControlCommand::CodexAccountPrepareTarget { .. } => "CodexAccountPrepareTarget",
        LocalControlCommand::CodexAccountReconnect { .. } => "CodexAccountReconnect",
        LocalControlCommand::CodexAccountCheck { .. } => "CodexAccountCheck",
        LocalControlCommand::CodexAccountStartSignIn { .. } => "CodexAccountStartSignIn",
        LocalControlCommand::CodexAccountStopWaiting { .. } => "CodexAccountStopWaiting",
        LocalControlCommand::CodexAccountRemove { .. } => "CodexAccountRemove",
        LocalControlCommand::CodexAccountSetQuotaRefreshConsent { .. } => {
            "CodexAccountSetQuotaRefreshConsent"
        }
        LocalControlCommand::Detect { .. } => "Detect",
        LocalControlCommand::Setup { .. } => "Setup",
        LocalControlCommand::SetupAnswer { .. } => "SetupAnswer",
        LocalControlCommand::SetupAction { .. } => "SetupAction",
        LocalControlCommand::SourceCollection { .. } => "SourceCollection",
        LocalControlCommand::TelemetryControl { .. } => "TelemetryControl",
        LocalControlCommand::ProviderDailyReferenceControl { .. } => {
            "ProviderDailyReferenceControl"
        }
        LocalControlCommand::Repair { .. } => "Repair",
        LocalControlCommand::Verify { .. } => "Verify",
        LocalControlCommand::RelayStart => "RelayStart",
        LocalControlCommand::RelayStop => "RelayStop",
        LocalControlCommand::DiagnosticsCollect { .. } => "DiagnosticsCollect",
        LocalControlCommand::UpdateCheck => "UpdateCheck",
        LocalControlCommand::UninstallPlan => "UninstallPlan",
        LocalControlCommand::UninstallExecute { .. } => "UninstallExecute",
        LocalControlCommand::Uninstall => "Uninstall",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    MismatchedVersion,
    NoCaller,
    CompanionNoPeer,
    CompanionForeignEuid,
    BadTokenCli,
    BadTokenTrustedPeer,
    GoodTokenCli,
    GoodTokenNoncli,
    Trusted,
    PoisonedGoodToken,
    PoisonedTrusted,
    PoisonedBadToken,
}
const COLUMNS: [Column; 12] = [
    Column::MismatchedVersion,
    Column::NoCaller,
    Column::CompanionNoPeer,
    Column::CompanionForeignEuid,
    Column::BadTokenCli,
    Column::BadTokenTrustedPeer,
    Column::GoodTokenCli,
    Column::GoodTokenNoncli,
    Column::Trusted,
    Column::PoisonedGoodToken,
    Column::PoisonedTrusted,
    Column::PoisonedBadToken,
];

impl Column {
    fn poisoned(self) -> bool {
        matches!(
            self,
            Self::PoisonedGoodToken | Self::PoisonedTrusted | Self::PoisonedBadToken
        )
    }
}

// Independent of the production prelude: the commands that cancel pending
// launch handoffs once their caller is admitted.
const IDENTITY_FENCE: [&str; 10] = [
    "AuthComplete",
    "AuthCompletePending",
    "AuthSwitchAccount",
    "AuthReset",
    "ClaudeAccountRemove",
    "ClaudeAccountReconnect",
    "ClaudeAccountReconnectTarget",
    "ClaudeAccountStartBrowserReconnect",
    "CodexAccountRemove",
    "CodexAccountReconnect",
];

fn request_for(
    command: LocalControlCommand,
    column: Column,
) -> (LocalControlRequest, Option<LocalClientPeer>) {
    use Column::*;
    let token = match column {
        GoodTokenCli | GoodTokenNoncli | PoisonedGoodToken => Some("token".into()),
        BadTokenCli | BadTokenTrustedPeer | PoisonedBadToken => Some("wrong-token".into()),
        _ => None,
    };
    let client_kind = match column {
        GoodTokenCli | BadTokenCli | PoisonedGoodToken | PoisonedBadToken => {
            Some(LocalClientKind::Cli)
        }
        CompanionNoPeer | CompanionForeignEuid | BadTokenTrustedPeer | Trusted
        | PoisonedTrusted => Some(LocalClientKind::CompanionApp),
        GoodTokenNoncli => Some(LocalClientKind::WebUi),
        _ => None,
    };
    let peer = match column {
        BadTokenTrustedPeer | Trusted | PoisonedTrusted => {
            Some(LocalClientPeer::trusted_for_tests())
        }
        CompanionForeignEuid => Some(LocalClientPeer::from_pid_and_euid(
            Some(std::process::id()),
            Some(daemon_effective_uid().wrapping_add(1)),
        )),
        _ => None,
    };
    let version = ottto_protocol::expected_local_control_protocol_version(&command);
    (
        LocalControlRequest {
            request_id: "caller-matrix".into(),
            protocol_version: version + u16::from(column == MismatchedVersion),
            token,
            client_kind,
            client_install_owner: None,
            command,
        },
        peer,
    )
}

fn run(daemon: &LocalDaemon, command: LocalControlCommand, column: Column) -> LocalControlResponse {
    let (request, peer) = request_for(command, column);
    handle_request_with_peer(daemon, request, peer)
}

/// The one test-only record made when a request reaches command dispatch.
fn dispatch_entered(trusted_companion: bool) -> Vec<Effect> {
    vec![Effect {
        label: "control_dispatch_entered",
        fields: vec![("trusted_companion", Scalar::Bool(trusted_companion))],
    }]
}

fn assert_cell(response: &LocalControlResponse, expected: Cell, context: &str) {
    if expected == O {
        assert!(
            response.ok && response.error.is_none(),
            "{context}: {response:?}"
        );
        return;
    }
    assert!(!response.ok, "{context}: {response:?}");
    let error = response
        .error
        .as_ref()
        .expect("refused cell must carry an error");
    let code = match expected {
        I => CliErrorCode::InvalidRequest,
        N => CliErrorCode::LocalClientNotTrusted,
        A => CliErrorCode::LocalAuthFailed,
        P | H => CliErrorCode::Internal,
        U => CliErrorCode::NeedsUserAction,
        B => CliErrorCode::BackendResponseUnexpected,
        X => CliErrorCode::NetworkUnavailable,
        O => unreachable!(),
    };
    assert_eq!(error.code, code, "{context}: {response:?}");
    let poisoned = error.message == cli_error_message(&LocalApiError::StatePoisoned);
    assert_eq!(poisoned, expected == P, "{context}: {response:?}");
}

fn poison<T>(mutex: &Mutex<T>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = mutex.lock().expect("state before poison");
        panic!("synthetic poisoned state");
    }));
    assert!(result.is_err());
}

// No daemon.status(): that call can itself reconcile state, hiding effects.
fn health_snapshot(daemon: &LocalDaemon) -> serde_json::Value {
    let state = daemon
        .inner
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    json!({
        "relay": state.relay,
        "sources": state.sources,
        "events": state.local_health_events,
        "ledger": state.command_ledger,
    })
}

// Include bytes, not just paths, so a rewrite of an existing file is visible.
fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(path).expect("list synthetic tree") {
            let entry = entry.expect("synthetic entry");
            let path = entry.path();
            let kind = entry.file_type().expect("synthetic entry type");
            assert!(!kind.is_symlink(), "unexpected fixture symlink");
            let contents = kind
                .is_file()
                .then(|| fs::read(&path).expect("read synthetic file"));
            result.insert(path.strip_prefix(root).unwrap().to_owned(), contents);
            if kind.is_dir() {
                walk(root, &path, result);
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

fn pending_state(daemon: &LocalDaemon, id: &str) -> Option<ottto_protocol::SessionLaunchStateV1> {
    daemon
        .session_launch
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .status(id, false)
        .state
}

// A stoppable listener makes zero-request cells observable without hanging on accept.
struct CountingBackend {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl CountingBackend {
    fn new(status: u16, body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counting backend");
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let request = read_complete_http_request(&mut stream);
                        captured.lock().unwrap().push(request);
                        write_json_response(&mut stream, status, "Synthetic", &body);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("counting backend accept: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn all_validate(&self) -> bool {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("POST /api/v1/apps/control-token/validate "))
    }
}
impl Drop for CountingBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("counting backend");
    }
}

struct Fixture {
    root: PathBuf,
    backend: CountingBackend,
    _env: Vec<EnvVarGuard>,
}
impl Fixture {
    fn new(status: u16, body: String) -> Self {
        let root = control_test_root("caller-matrix");
        for dir in ["home", "support", "secrets", "keys", "bin"] {
            create_control_test_dir(&root.join(dir));
        }
        let backend = CountingBackend::new(status, body);
        let env = vec![
            EnvVarGuard::set_path("HOME", &root.join("home")),
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support")),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &root.join("secrets")),
            EnvVarGuard::set_path(TELEMETRY_KEY_FILE_STORE_ENV, &root.join("keys")),
            EnvVarGuard::set_path("OTTTO_COMMAND_SEARCH_PATH", &root.join("bin")),
            EnvVarGuard::set_path("PATH", &root.join("bin")),
            EnvVarGuard::set_str("OTTTO_API_BASE_URL", &backend.url),
            EnvVarGuard::set_str("OTTTO_RELEASE_MANIFEST_URL", &backend.url),
            EnvVarGuard::remove("CLAUDE_CONFIG_DIR"),
            EnvVarGuard::remove("CODEX_HOME"),
            EnvVarGuard::remove("OTTTO_PATCH_CODEX_DISABLED"),
            EnvVarGuard::remove("OTTTO_PATCH_CLAUDE_CODE_DISABLED"),
        ];
        Self {
            root,
            backend,
            _env: env,
        }
    }

    fn daemon(&self) -> LocalDaemon {
        daemon().with_source_state_dir(self.root.join("support/sources"))
    }

    /// A fresh daemon holding one Pending launch handoff.
    fn daemon_with_pending(&self) -> (LocalDaemon, String) {
        let daemon = self.daemon();
        let pending = daemon
            .session_launch
            .lock()
            .unwrap()
            .seed_pending_for_control_test(&self.root);
        (daemon, pending)
    }

    fn bind_codex_account(&self, device_id: &str) {
        FileAccountStore::default()
            .save(&connected_account())
            .unwrap();
        FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: device_id.into(),
                machine_id: Some("machine_test".into()),
                sources: vec!["codex".into()],
            })
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Fields restore env and stop the server after the synthetic tree is removed.
        fs::remove_dir_all(&self.root).expect("remove caller fixture");
    }
}

/// Runs one request and pins its code, its dispatch record and, for a
/// refusal at the protocol, caller or poison boundary, zero effects.
fn assert_boundary(
    fixture: &Fixture,
    daemon: &LocalDaemon,
    pending: &str,
    request: (LocalControlRequest, Option<LocalClientPeer>),
    expected: Cell,
    expect_dispatch: bool,
    context: &str,
) -> LocalControlResponse {
    let health = health_snapshot(daemon);
    let files = tree_snapshot(&fixture.root);
    let trusted = request.0.token.is_none()
        && request.0.client_kind == Some(LocalClientKind::CompanionApp)
        && request
            .1
            .as_ref()
            .is_some_and(|peer| peer.trusted_for_tests);
    let recording = Recording::start();
    let response = handle_request_with_peer(daemon, request.0, request.1);
    let entered = recording.take();
    drop(recording);
    assert_cell(&response, expected, context);
    let expected_entry = if expect_dispatch {
        dispatch_entered(trusted)
    } else {
        Vec::new()
    };
    assert_eq!(entered, expected_entry, "dispatch: {context}");
    if matches!(expected, N | A | P) || !expect_dispatch {
        assert_eq!(health_snapshot(daemon), health, "health: {context}");
        assert_eq!(tree_snapshot(&fixture.root), files, "tree: {context}");
        assert_eq!(fixture.backend.count(), 0, "network: {context}");
        assert_eq!(
            pending_state(daemon, pending),
            Some(ottto_protocol::SessionLaunchStateV1::Pending),
            "launch: {context}"
        );
    }
    response
}

#[test]
fn matrix_names_are_unique_exhaustive_and_cells_match_authority() {
    let names: BTreeSet<_> = ROWS.iter().map(|row| row.name).collect();
    let samples: BTreeSet<_> = ROWS.iter().map(|row| row_name(&(row.sample)())).collect();
    assert_eq!(ROWS.len(), 70);
    assert_eq!(names.len(), ROWS.len());
    assert_eq!(names, samples);
    assert_eq!(
        IDENTITY_FENCE.into_iter().collect::<BTreeSet<_>>().len(),
        10
    );
    assert!(IDENTITY_FENCE.iter().all(|name| names.contains(name)));
    for row in ROWS {
        assert_eq!(row.name, row_name(&(row.sample)()));
        assert_eq!(row.cells[0], I, "{} mismatched protocol version", row.name);
        match row.authority {
            "Local" | "LocalCli" | "LocalNoPoisonCheck" => {
                assert_eq!(&row.cells[1..6], &[N, N, N, A, A], "{}", row.name);
                assert_eq!(row.cells[11], A, "{}", row.name);
                if row.authority == "LocalNoPoisonCheck" {
                    assert_eq!(&row.cells[9..11], &[O, O]);
                } else {
                    assert_eq!(&row.cells[9..11], &[P, P]);
                }
                if row.authority == "LocalCli" {
                    assert_eq!(&row.cells[7..9], &[A, A]);
                }
            }
            "Public" => assert_eq!(&row.cells[1..], &[O; 11]),
            "TelemetryToken" | "DailyReferenceToken" => {
                assert_eq!(&row.cells[1..], &[N; 11]);
            }
            other => panic!("unrecognized oracle authority {other}"),
        }
    }
}

#[test]
#[serial]
fn every_command_cell_and_the_identity_fence() {
    let _lock = lock_backend_test_env();
    for row in ROWS {
        for (index, column) in COLUMNS.into_iter().enumerate() {
            let fixture = Fixture::new(200, "{}".into());
            let (daemon, pending) = fixture.daemon_with_pending();
            if column.poisoned() {
                poison(&daemon.inner);
            }
            let context = format!("{} {column:?}", row.name);
            let expected = row.cells[index];
            let request = request_for((row.sample)(), column);
            let local_refusal =
                matches!(row.authority, "Local" | "LocalCli" | "LocalNoPoisonCheck")
                    && matches!(expected, N | A | P);
            let response = assert_boundary(
                &fixture,
                &daemon,
                &pending,
                request,
                expected,
                column != Column::MismatchedVersion && !local_refusal,
                &context,
            );
            if row.name == "RetiredClaudeAccountSubmitAuthCode" && expected == I && index > 0 {
                assert_eq!(
                    response.error.unwrap().message,
                    crate::claude_browser_auth::RETIRED_CODE_SUBMISSION_MESSAGE,
                    "{context}"
                );
            }
            // Exactly the ten identity commands cancel the handoff, and only
            // for an admitted caller; invalid arguments still fence.
            let cancelled = IDENTITY_FENCE.contains(&row.name)
                && matches!(
                    column,
                    Column::GoodTokenCli | Column::GoodTokenNoncli | Column::Trusted
                );
            let launch = daemon
                .session_launch
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .status(&pending, false);
            if cancelled {
                assert_eq!(
                    launch.state,
                    Some(ottto_protocol::SessionLaunchStateV1::Blocked),
                    "fence cancels: {context}"
                );
                assert_eq!(
                    launch.block.unwrap().reason,
                    ottto_protocol::SessionLaunchBlockReasonV1::LaunchCancelled,
                    "fence reason: {context}"
                );
            } else {
                assert_eq!(
                    launch.state,
                    Some(ottto_protocol::SessionLaunchStateV1::Pending),
                    "fence untouched: {context}"
                );
            }
        }
    }
}

#[test]
#[serial]
fn poisoned_launch_registry_refuses_only_the_identity_fence() {
    let _lock = lock_backend_test_env();
    for row in ROWS {
        let fixture = Fixture::new(200, "{}".into());
        let daemon = fixture.daemon();
        poison(&daemon.session_launch);
        let health = health_snapshot(&daemon);
        let files = tree_snapshot(&fixture.root);
        let response = run(&daemon, (row.sample)(), Column::GoodTokenCli);
        let context = format!("poisoned registry {}", row.name);
        if IDENTITY_FENCE.contains(&row.name) {
            assert_cell(&response, P, &context);
            assert_eq!(health_snapshot(&daemon), health, "{context}");
            assert_eq!(tree_snapshot(&fixture.root), files, "{context}");
            assert_eq!(fixture.backend.count(), 0, "{context}");
        } else {
            // Outside the fence, the registry is read only after the launch
            // schema check, which each sample fails.
            assert_cell(&response, row.cells[6], &context);
        }
    }
}

#[test]
#[serial]
fn installation_reset_needs_its_own_protocol_version() {
    let _lock = lock_backend_test_env();
    let reset = || LocalControlCommand::AuthReset {
        local_only: false,
        forget_installation: true,
    };
    for (label, base_version, column, expected) in [
        ("base version", true, Column::GoodTokenCli, I),
        ("base version, trusted", true, Column::Trusted, I),
        ("untrusted", false, Column::NoCaller, N),
        ("bad token", false, Column::BadTokenCli, A),
        ("poisoned", false, Column::PoisonedTrusted, P),
    ] {
        let fixture = Fixture::new(200, "{}".into());
        let (daemon, pending) = fixture.daemon_with_pending();
        if column.poisoned() {
            poison(&daemon.inner);
        }
        let mut request = request_for(reset(), column);
        if base_version {
            request.0.protocol_version = PROTOCOL_VERSION;
        }
        assert_boundary(&fixture, &daemon, &pending, request, expected, false, label);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackendFamily {
    Telemetry,
    DailyReference,
    DailyReferenceRevoke,
}
impl BackendFamily {
    fn action(self) -> &'static str {
        match self {
            Self::Telemetry => "status",
            Self::DailyReference => "provider_daily_reference_status",
            Self::DailyReferenceRevoke => "revoke_provider_daily_reference",
        }
    }

    fn command(
        self,
        token: String,
        key_id: Option<&str>,
        organization: &str,
    ) -> LocalControlCommand {
        match self {
            Self::Telemetry => LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::Status,
                source: SourceKind::Codex,
                control_token: token,
                // The request field must never redirect validation.
                api_base_url: Some(ATTACKER_LOOPBACK_API_BASE_URL.into()),
                key_id: key_id.map(str::to_owned),
                organization_id: Some(organization.into()),
                otlp_endpoint: None,
                ingest_key: None,
            },
            Self::DailyReference | Self::DailyReferenceRevoke => {
                LocalControlCommand::ProviderDailyReferenceControl {
                    action: if self == Self::DailyReference {
                        ProviderDailyReferenceControlAction::Status
                    } else {
                        ProviderDailyReferenceControlAction::Revoke
                    },
                    control_token: SecretString::new(token),
                    api_base_url: Some(ATTACKER_LOOPBACK_API_BASE_URL.into()),
                    backend_grant: None,
                    expected_account_fingerprint: None,
                }
            }
        }
    }
}

/// One backend-token request, sent without a local token or peer.
struct BackendCase {
    label: &'static str,
    /// Token action, source and lifetime; `None` sends an empty token.
    token: Option<(&'static str, &'static str, i64)>,
    /// One claim the validation answer overrides.
    claim: (&'static str, serde_json::Value),
    status: u16,
    request_key: Option<&'static str>,
    request_organization: &'static str,
    /// Local binding: `Some(device)` saves account and device, `None` neither.
    binding: Option<&'static str>,
    broken_device: bool,
    reserved: bool,
    expected: Cell,
    posts: usize,
}

fn backend_case(family: BackendFamily, label: &'static str) -> BackendCase {
    BackendCase {
        label,
        token: Some((family.action(), "codex", 300)),
        claim: ("", json!(null)),
        status: 200,
        request_key: None,
        request_organization: "org_test",
        binding: Some("device_test"),
        broken_device: false,
        reserved: false,
        expected: O,
        posts: 1,
    }
}

fn run_backend_case(family: BackendFamily, case: BackendCase) {
    let mut body = json!({
        "valid": true, "source": "codex", "action": family.action(),
        "organization_id": "org_test", "user_id": "user_test", "device_id": "device_test",
        "token_id": "synthetic-backend-token", "expires_at": "2099-01-01T00:00:00Z",
    });
    if !case.claim.0.is_empty() {
        body[case.claim.0] = case.claim.1.clone();
    }
    let fixture = Fixture::new(case.status, body.to_string());
    if let Some(device) = case.binding {
        fixture.bind_codex_account(device);
    }
    if case.broken_device {
        let devices = FileDeviceStore::default();
        fs::create_dir_all(devices.path().parent().unwrap()).unwrap();
        fs::write(devices.path(), b"{not json").unwrap();
    }
    let (daemon, pending) = fixture.daemon_with_pending();
    let files = tree_snapshot(&fixture.root);
    let health = health_snapshot(&daemon);
    let token = case
        .token
        .map(|(action, source, expires)| test_control_token(action, source, expires))
        .unwrap_or_default();
    let command = family.command(token, case.request_key, case.request_organization);
    let (mut request, _) = request_for(command, Column::NoCaller);
    request.client_kind = Some(LocalClientKind::WebUi);
    let _reservation = case.reserved.then(|| reserve_identity_mutation().unwrap());
    let response = handle_request_with_peer(&daemon, request, None);
    let context = format!("{} {family:?}", case.label);
    assert_cell(&response, case.expected, &context);
    assert_eq!(fixture.backend.count(), case.posts, "{context}");
    assert!(fixture.backend.all_validate(), "{context}");
    if case.expected == U {
        assert_eq!(
            response.error.as_ref().unwrap().details.get("reason_code"),
            Some(&RedactedValue::String(
                "identity_mutation_in_progress".into()
            )),
            "{context}"
        );
    }
    if case.expected != O {
        // Byte-for-byte tree equality includes secrets, grants and replay-use
        // files, even when rejection follows a validation request.
        assert_eq!(tree_snapshot(&fixture.root), files, "{context}");
        assert_eq!(health_snapshot(&daemon), health, "{context}");
    }
    assert_eq!(
        pending_state(&daemon, &pending),
        Some(ottto_protocol::SessionLaunchStateV1::Pending),
        "{context}"
    );
}

#[test]
#[serial]
fn telemetry_and_daily_reference_token_authority() {
    let _lock = lock_backend_test_env();
    for family in [BackendFamily::Telemetry, BackendFamily::DailyReference] {
        let case = |label| backend_case(family, label);
        for case in [
            BackendCase {
                token: None,
                expected: N,
                posts: 0,
                ..case("empty token")
            },
            BackendCase {
                token: Some((family.action(), "codex", -60)),
                expected: N,
                posts: 0,
                ..case("expired")
            },
            BackendCase {
                token: Some(("wrong-action", "codex", 300)),
                expected: N,
                posts: 0,
                ..case("wrong action")
            },
            BackendCase {
                token: Some((family.action(), "pi", 300)),
                expected: N,
                posts: 0,
                ..case("wrong source")
            },
            BackendCase {
                claim: ("organization_id", json!("other-org")),
                expected: N,
                ..case("backend org")
            },
            BackendCase {
                claim: ("user_id", json!("other-user")),
                expected: N,
                ..case("backend user")
            },
            BackendCase {
                claim: ("device_id", json!("other-device")),
                expected: N,
                ..case("backend device")
            },
            BackendCase {
                status: 401,
                expected: N,
                ..case("backend refusal")
            },
            BackendCase {
                binding: None,
                expected: N,
                ..case("no local binding")
            },
            case("valid, both keys absent"),
        ] {
            run_backend_case(family, case);
        }
    }
}

#[test]
#[serial]
fn backend_branch_points_reservation_and_binding_order() {
    let _lock = lock_backend_test_env();
    let telemetry = |label| backend_case(BackendFamily::Telemetry, label);
    for case in [
        // The optional request organization is compared after the binding.
        BackendCase {
            request_organization: "other-org",
            expected: I,
            ..telemetry("request org")
        },
        BackendCase {
            claim: ("key_id", json!("key_local")),
            request_key: Some("key_local"),
            ..telemetry("matched key")
        },
        BackendCase {
            claim: ("key_id", json!("key_other")),
            request_key: Some("key_local"),
            expected: N,
            ..telemetry("mismatched key")
        },
        BackendCase {
            request_key: Some("key_local"),
            expected: N,
            ..telemetry("request key only")
        },
        BackendCase {
            claim: ("key_id", json!("key_local")),
            expected: N,
            ..telemetry("claim key only")
        },
        BackendCase {
            broken_device: true,
            expected: N,
            ..telemetry("broken device")
        },
        BackendCase {
            reserved: true,
            expected: U,
            ..telemetry("reservation")
        },
    ] {
        run_backend_case(BackendFamily::Telemetry, case);
    }
    let daily = |label| backend_case(BackendFamily::DailyReference, label);
    for case in [
        // Once the account binding passes, an unreadable device is internal.
        BackendCase {
            broken_device: true,
            expected: H,
            ..daily("broken device")
        },
        // The account refusal precedes the device read.
        BackendCase {
            binding: None,
            broken_device: true,
            expected: N,
            ..daily("no account, broken device")
        },
        // Status skips the identity-mutation reservation.
        BackendCase {
            reserved: true,
            ..daily("reservation")
        },
    ] {
        run_backend_case(BackendFamily::DailyReference, case);
    }
    let revoke = BackendFamily::DailyReferenceRevoke;
    run_backend_case(
        revoke,
        BackendCase {
            binding: None,
            reserved: true,
            expected: U,
            ..backend_case(revoke, "reserved daily reference mutation")
        },
    );

    // A present blank key is refused before any validation request.
    let fixture = Fixture::new(200, "{}".into());
    let (daemon, pending) = fixture.daemon_with_pending();
    let command = LocalControlCommand::TelemetryControl {
        action: TelemetryControlAction::DisableTelemetry,
        source: SourceKind::Codex,
        control_token: test_control_token("disable_telemetry", "codex", 300),
        api_base_url: None,
        key_id: Some(" ".into()),
        organization_id: None,
        otlp_endpoint: None,
        ingest_key: None,
    };
    let request = request_for(command, Column::NoCaller);
    assert_boundary(&fixture, &daemon, &pending, request, I, true, "blank key");
    assert_eq!(fixture.backend.count(), 0);
}

#[test]
#[serial]
fn backend_tokens_ignore_an_invalid_outer_token_and_poisoned_daemon() {
    let _lock = lock_backend_test_env();
    for family in [BackendFamily::Telemetry, BackendFamily::DailyReference] {
        let body = json!({
            "valid": true, "source": "codex", "action": family.action(),
            "organization_id": "org_test", "user_id": "user_test", "device_id": "device_test",
            "token_id": "synthetic-backend-token", "expires_at": "2099-01-01T00:00:00Z",
        });
        let fixture = Fixture::new(200, body.to_string());
        fixture.bind_codex_account("device_test");
        let token = test_control_token(family.action(), "codex", 300);
        let send = || {
            let (daemon, pending) = fixture.daemon_with_pending();
            poison(&daemon.inner);
            let command = family.command(token.clone(), None, "org_test");
            let (request, _) = request_for(command, Column::PoisonedBadToken);
            let recording = Recording::start();
            let response = handle_request_with_peer(&daemon, request, None);
            assert_eq!(recording.take(), dispatch_entered(false), "{family:?}");
            assert_eq!(
                pending_state(&daemon, &pending),
                Some(ottto_protocol::SessionLaunchStateV1::Pending),
                "{family:?}"
            );
            response
        };
        assert_cell(&send(), O, &format!("poisoned daemon {family:?}"));
        assert_eq!(fixture.backend.count(), 1, "{family:?}");
        let accepted_files = tree_snapshot(&fixture.root);
        let replay = send();
        assert_eq!(fixture.backend.count(), 2, "{family:?}");
        // DailyReference consumed the token; Telemetry has no replay record.
        let expected = if family == BackendFamily::DailyReference {
            assert_eq!(tree_snapshot(&fixture.root), accepted_files);
            N
        } else {
            O
        };
        assert_cell(
            &replay,
            expected,
            &format!("poisoned daemon replay {family:?}"),
        );
        assert!(fixture.backend.all_validate());
    }
}

// Malformed config stops at the patch-disabled return; a relay block is drift
// that only repair rewrites; a clean config reaches the account check.
const DISABLED_CONFIG: &str = "[otel\n";
const CLEAN_CONFIG: &str = "model = \"gpt-6.1-sol\"\n";

fn verify_fixture(fixture: &Fixture, config: &str) -> PathBuf {
    let root = fixture.root.join("home/.codex");
    create_control_test_dir(&root);
    let path = root.join("config.toml");
    fs::write(&path, config).unwrap();
    path
}

fn drifted_config() -> String {
    render_codex_relay_toml_block_for_base("http://127.0.0.1:44621")
}

fn verify_command(repair: bool) -> LocalControlCommand {
    LocalControlCommand::Verify {
        source: SourceKind::Codex,
        repair,
    }
}

fn assert_verify_recorded(daemon: &LocalDaemon) {
    let health = health_snapshot(daemon);
    assert_eq!(health["sources"].as_array().unwrap().len(), 1);
    assert_eq!(health["sources"][0]["source"], "codex");
    assert_eq!(health["events"].as_array().unwrap().len(), 1);
    assert_eq!(health["ledger"].as_array().unwrap().len(), 1);
    assert_eq!(health["ledger"][0]["action_id"], "verify_codex");
}

#[test]
#[serial]
fn verify_records_only_for_an_admitted_caller() {
    let _lock = lock_backend_test_env();
    let drifted = drifted_config();
    for (label, config, disabled, repair, column, expected) in [
        (
            "untrusted, disabled patch",
            DISABLED_CONFIG,
            true,
            false,
            Column::NoCaller,
            N,
        ),
        (
            "untrusted, clean config",
            CLEAN_CONFIG,
            false,
            false,
            Column::NoCaller,
            N,
        ),
        (
            "untrusted, drift repair",
            drifted.as_str(),
            false,
            true,
            Column::NoCaller,
            N,
        ),
        (
            "trusted, disabled patch",
            DISABLED_CONFIG,
            true,
            false,
            Column::Trusted,
            O,
        ),
        (
            "poisoned token, drift repair",
            drifted.as_str(),
            false,
            true,
            Column::PoisonedGoodToken,
            P,
        ),
        (
            "poisoned trusted, drift repair",
            drifted.as_str(),
            false,
            true,
            Column::PoisonedTrusted,
            P,
        ),
    ] {
        let fixture = Fixture::new(200, "{}".into());
        let path = verify_fixture(&fixture, config);
        let _disabled = EnvVarGuard::set_str(
            "OTTTO_PATCH_CODEX_DISABLED",
            if disabled { "1" } else { "0" },
        );
        let original = fs::read(&path).unwrap();
        let (daemon, pending) = fixture.daemon_with_pending();
        if column.poisoned() {
            poison(&daemon.inner);
        }
        if expected == O {
            assert_cell(&run(&daemon, verify_command(repair), column), O, label);
            assert_verify_recorded(&daemon);
            assert!(
                fixture
                    .root
                    .join("support/sources/codex-state.json")
                    .is_file(),
                "{label}: persisted source health"
            );
        } else {
            let request = request_for(verify_command(repair), column);
            assert_boundary(&fixture, &daemon, &pending, request, expected, false, label);
        }
        assert_eq!(fs::read(&path).unwrap(), original, "{label}: no repair");
        assert_eq!(fixture.backend.count(), 0, "{label}");
    }
}

#[test]
#[serial]
fn public_update_works_with_untrusted_and_poisoned_state() {
    let _lock = lock_backend_test_env();
    for poisoned in [false, true] {
        let fixture = Fixture::new(200, "{}".into());
        let daemon = fixture.daemon();
        if poisoned {
            poison(&daemon.inner);
        }
        let health = health_snapshot(&daemon);
        let files = tree_snapshot(&fixture.root);
        let response = run(&daemon, LocalControlCommand::UpdateCheck, Column::NoCaller);
        assert_cell(&response, O, "public update");
        assert_eq!(fixture.backend.count(), 1);
        assert!(fixture.backend.requests.lock().unwrap()[0].starts_with("GET / "));
        assert_eq!(health_snapshot(&daemon), health);
        assert_eq!(tree_snapshot(&fixture.root), files);
    }
}

#[test]
#[serial]
fn protocol_token_guard_and_cached_read_precedence() {
    let _lock = lock_backend_test_env();
    for (label, column, expected) in [
        ("mismatched version", Column::MismatchedVersion, I),
        ("bad token, trusted peer", Column::BadTokenTrustedPeer, A),
        ("cached read, poisoned", Column::PoisonedGoodToken, O),
    ] {
        let fixture = Fixture::new(200, "{}".into());
        let (daemon, pending) = fixture.daemon_with_pending();
        if column.poisoned() {
            poison(&daemon.inner);
        }
        let health = health_snapshot(&daemon);
        let files = tree_snapshot(&fixture.root);
        let command = LocalControlCommand::AgentStatusCached { source: None };
        assert_cell(&run(&daemon, command, column), expected, label);
        assert_eq!(health_snapshot(&daemon), health, "{label}");
        assert_eq!(tree_snapshot(&fixture.root), files, "{label}");
        assert_eq!(fixture.backend.count(), 0, "{label}");
        assert_eq!(
            pending_state(&daemon, &pending),
            Some(ottto_protocol::SessionLaunchStateV1::Pending),
            "{label}"
        );
    }

    // Protocol, caller and poison refusals precede argument validation.
    let expected_cells = [I, N, N, N, A, A, I, I, I, P, P, A];
    let timezone_message = "invalid local control request: --timezone is not supported. Ottto uses the timezone saved in your account settings for calendar windows.";
    for (column, expected) in COLUMNS.into_iter().zip(expected_cells) {
        let fixture = Fixture::new(200, "{}".into());
        let (daemon, pending) = fixture.daemon_with_pending();
        let daemon = daemon
            .with_account(connected_account())
            .with_connection(Some(LocalConnectionBinding {
                setup_run_id: "matrix-setup".into(),
                setup_run_token_expires_at: "2099-01-01T00:00:00Z".into(),
                machine_id: Some("machine_test".into()),
                claim_code: None,
                api_base_url: fixture.backend.url.clone(),
            }));
        if column.poisoned() {
            poison(&daemon.inner);
        }
        let timezone = || Some("UTC".into());
        for (command, validation_message) in [
            (
                LocalControlCommand::AgentContext {
                    query: AgentContextQuery {
                        timezone: timezone(),
                        ..Default::default()
                    },
                },
                timezone_message,
            ),
            (
                LocalControlCommand::AgentCosts {
                    query: AgentCostsQuery {
                        timezone: timezone(),
                        ..Default::default()
                    },
                },
                timezone_message,
            ),
            (
                LocalControlCommand::AgentSessions {
                    query: AgentSessionsQuery {
                        timezone: timezone(),
                        ..Default::default()
                    },
                },
                timezone_message,
            ),
            (
                LocalControlCommand::CloudStatus {
                    source: Some("".into()),
                },
                "invalid local control request: cloud source must be bedrock or vertex",
            ),
        ] {
            let context = format!("{} {column:?}", row_name(&command));
            let request = request_for(command, column);
            let mismatched = column == Column::MismatchedVersion;
            let error = assert_boundary(
                &fixture,
                &daemon,
                &pending,
                request,
                expected,
                expected == I && !mismatched,
                &context,
            )
            .error
            .unwrap();
            let message = match expected {
                I if mismatched => "unsupported local control protocol_version 16; expected 15",
                I => validation_message,
                N => "local client is not trusted",
                A => "local daemon authentication failed",
                P => "daemon state lock is poisoned",
                other => unreachable!("{other:?}"),
            };
            assert_eq!(error.message, message, "{context}");
            assert_eq!(error.retryable, expected == P, "{context}");
            assert_eq!(fixture.backend.count(), 0, "{context}");
        }
    }
}

#[test]
#[serial]
fn refused_identity_command_leaves_held_lock_and_pending_handoff_untouched() {
    let _lock = lock_backend_test_env();
    let fixture = Fixture::new(200, "{}".into());
    let (daemon, pending) = fixture.daemon_with_pending();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let identity_lock = lock_setup_run_binding();
        scope.spawn(|| {
            let recording = Recording::start();
            let command = LocalControlCommand::AuthReset {
                local_only: true,
                forget_installation: false,
            };
            let response = run(&daemon, command, Column::BadTokenTrustedPeer);
            sender.send((response, recording.take())).unwrap();
        });
        let result = receiver.recv_timeout(Duration::from_secs(5));
        drop(identity_lock);
        let (response, effects) = result.expect("refusal must finish while identity lock is held");
        assert_cell(&response, A, "locked identity");
        assert!(effects.is_empty());
        assert_eq!(
            pending_state(&daemon, &pending),
            Some(ottto_protocol::SessionLaunchStateV1::Pending),
        );
    });
}

fn assert_keys(value: &serde_json::Value, expected: &[&str]) {
    let keys: BTreeSet<_> = value
        .as_object()
        .expect("profile object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, expected.iter().copied().collect());
}

#[test]
#[serial]
fn output_profiles_preserve_account_and_icon_boundaries() {
    let _lock = lock_backend_test_env();
    let status_keys = [
        "protocol_version",
        "daemon_version",
        "machine",
        "account",
        "daemon",
        "service_owner",
        "relay",
        "sources",
        "update",
        "canonical_health",
        "runtime_heartbeat",
        "generated_at",
        "local_health_events",
    ];
    for (label, command, icon, account) in [
        (
            "status",
            LocalControlCommand::Status {
                refresh_agent_status: false,
                retry_relay_authorization: false,
            },
            true,
            true,
        ),
        ("auth status", LocalControlCommand::AuthStatus, false, true),
        ("account", LocalControlCommand::Account, false, false),
        ("verify", verify_command(false), false, false),
    ] {
        let fixture = Fixture::new(200, "{}".into());
        fs::write(
            fixture.root.join("support/machine_icon.json"),
            r#"{"machine_id":"machine_test","icon_url":"synthetic-icon"}"#,
        )
        .unwrap();
        if label == "verify" {
            verify_fixture(&fixture, DISABLED_CONFIG);
        }
        let _disabled = EnvVarGuard::set_str("OTTTO_PATCH_CODEX_DISABLED", "1");
        let daemon = if label == "verify" {
            fixture.daemon()
        } else {
            let daemon = fixture.daemon().with_account(connected_account());
            daemon
                .record_local_health_upload_failed(
                    crate::LocalHealthUploadFailureKind::AuthRejected,
                )
                .unwrap();
            daemon
        };
        let response = run(&daemon, command, Column::Trusted);
        assert_cell(&response, O, label);
        let payload = response.payload.unwrap();
        match label {
            "status" | "auth status" => assert_keys(&payload, &status_keys),
            "account" => assert_keys(
                &payload,
                &[
                    "state",
                    "user",
                    "organization",
                    "connected_at",
                    "last_refreshed_at",
                    "message",
                ],
            ),
            "verify" => assert_keys(
                &payload,
                &[
                    "source",
                    "config",
                    "status",
                    "verified",
                    "records_seen",
                    "last_record_id",
                    "last_received_at",
                    "smoke_after",
                    "message",
                    "check",
                    "canonical_health",
                    "runtime_heartbeat",
                    "local_health_events",
                    "command_ledger",
                ],
            ),
            _ => unreachable!(),
        }
        assert_eq!(payload.get("account").is_some(), account, "{label}");
        assert_eq!(
            payload.pointer("/machine/icon_url").is_some(),
            icon,
            "{label}"
        );
        if icon {
            assert_eq!(payload["machine"]["icon_url"], "synthetic-icon");
        }
        if label != "verify" {
            let status = daemon.status_for_trusted_client().unwrap();
            let effective = to_value(crate::effective_account_binding(&status)).unwrap();
            assert_eq!(effective["state"], "error", "{label}");
            let shown = if account {
                &payload["account"]
            } else {
                &payload
            };
            assert_eq!(*shown, effective, "{label}");
        }
        assert_eq!(fixture.backend.count(), 0, "{label}");
    }
}
