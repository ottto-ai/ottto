use super::auth::{require_authorized_local_client, require_cli_token, require_local_caller};
use super::peer::RequestAuthorization;
use crate::{LocalApiError, LocalDaemon};
use ottto_protocol::LocalControlCommand;

enum Access {
    Local,
    LocalCli,
    LocalNoPoisonCheck,
    Public,
    BackendToken,
}

pub(super) struct CommandPolicy {
    access: Access,
    pub(super) changes_identity: bool,
}

pub(super) fn policy(command: &LocalControlCommand) -> CommandPolicy {
    use LocalControlCommand as Command;

    let (access, changes_identity) = match command {
        Command::AuthComplete { .. }
        | Command::AuthCompletePending { .. }
        | Command::AuthSwitchAccount { .. }
        | Command::AuthReset { .. }
        | Command::ClaudeAccountRemove { .. }
        | Command::ClaudeAccountReconnect { .. }
        | Command::ClaudeAccountReconnectTarget { .. }
        | Command::ClaudeAccountStartBrowserReconnect { .. }
        | Command::CodexAccountRemove { .. }
        | Command::CodexAccountReconnect { .. } => (Access::Local, true),
        Command::SessionLaunchConsume { .. }
        | Command::SessionLaunchReport { .. }
        | Command::CloudConnectStatus { .. }
        | Command::CloudConnectEnsure { .. }
        | Command::CloudConnectSubmit { .. }
        | Command::CloudConnectPoll { .. }
        | Command::CloudConnectCancel { .. } => (Access::LocalCli, false),
        Command::AgentStatusCached { .. } => (Access::LocalNoPoisonCheck, false),
        Command::UpdateCheck => (Access::Public, false),
        // Admission does nothing for these two: their handlers' backend-token,
        // binding and replay checks are the only layer. Never remove them.
        Command::TelemetryControl { .. } | Command::ProviderDailyReferenceControl { .. } => {
            (Access::BackendToken, false)
        }
        Command::SessionLaunchPrepare { .. }
        | Command::SessionLaunchStatus { .. }
        | Command::SessionLaunchCancel { .. }
        | Command::SessionLaunchRecentFolders { .. }
        | Command::AccountNicknames
        | Command::AccountNicknameSet { .. }
        | Command::Status { .. }
        | Command::Receipts { .. }
        | Command::AuthStatus
        | Command::AgentStatusRefresh { .. }
        | Command::PersonalMeterLocalSnapshot { .. }
        | Command::AgentContext { .. }
        | Command::AgentCosts { .. }
        | Command::AgentSessions { .. }
        | Command::AgentRecommendations { .. }
        | Command::AgentProviderImpact { .. }
        | Command::CloudStatus { .. }
        | Command::AuthStart
        | Command::Account
        | Command::ClaudeAccountsStatus
        | Command::ClaudeAccountSetUpkeepConsent { .. }
        | Command::ClaudeAccountRegisterPath { .. }
        | Command::ClaudeAccountPrepare { .. }
        | Command::ClaudeAccountPrepareTarget { .. }
        | Command::ClaudeAccountCheck { .. }
        | Command::ClaudeAccountStopWaiting { .. }
        | Command::ClaudeAccountStartBrowserLogin { .. }
        | Command::RetiredClaudeAccountSubmitAuthCode {}
        | Command::CodexAccountsStatus
        | Command::CodexAccountPrepare { .. }
        | Command::CodexAccountPrepareOpen { .. }
        | Command::CodexAccountPrepareTarget { .. }
        | Command::CodexAccountCheck { .. }
        | Command::CodexAccountStartSignIn { .. }
        | Command::CodexAccountStopWaiting { .. }
        | Command::CodexAccountSetQuotaRefreshConsent { .. }
        | Command::Detect { .. }
        | Command::Setup { .. }
        | Command::SetupAnswer { .. }
        | Command::SetupAction { .. }
        | Command::SourceCollection { .. }
        | Command::Repair { .. }
        | Command::Verify { .. }
        | Command::RelayStart
        | Command::RelayStop
        | Command::DiagnosticsCollect { .. }
        | Command::UninstallPlan
        | Command::UninstallExecute { .. }
        | Command::Uninstall => (Access::Local, false),
    };
    CommandPolicy {
        access,
        changes_identity,
    }
}

pub(super) fn admit(
    policy: &CommandPolicy,
    cli_client: bool,
    authorization: &RequestAuthorization,
    daemon: &LocalDaemon,
) -> Result<(), LocalApiError> {
    match policy.access {
        Access::Local => require_authorized_local_client(daemon, authorization),
        Access::LocalCli => {
            require_authorized_local_client(daemon, authorization)?;
            require_cli_token(cli_client, authorization)
        }
        Access::LocalNoPoisonCheck => require_local_caller(daemon, authorization),
        Access::Public | Access::BackendToken => Ok(()),
    }
}
