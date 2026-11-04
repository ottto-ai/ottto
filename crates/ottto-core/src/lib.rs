pub mod account_store;
pub mod claude_account;
pub mod claude_config_slots;
pub mod claude_statusline;
pub mod codex_account_slots;
mod credential_file;
pub mod lifecycle;
pub mod local_client;
pub mod local_service;
pub mod provider_call_log;
pub mod redaction;
pub mod session_launch;
#[cfg(unix)]
pub mod state_dir_lock;
pub mod status;
pub mod token_store;

pub use credential_file::CredentialFileCapRefused;

pub use account_store::{
    default_connection_api_base_url, default_pending_device_credential_path,
    default_prior_device_path, default_sources_dir, default_support_dir,
    is_persistent_installation_id, is_persistent_machine_id, source_state_file_name,
    FileAccountStore, FileConnectionStore, FileDeviceStore, FileMachineStore,
    FilePendingDeviceCredentialStore, FileSourceStateStore, LocalConnectionBinding,
    LocalDeviceBinding, LocalDeviceCredentialBinding, LocalMachineBinding, LocalSourceState,
    PendingClaimCredentialCommit, PendingDeviceCredentialPreparation,
    PendingDeviceCredentialRequestAuthority,
};
pub use claude_account::{
    billing_identity_hash, claude_account_identifier_hash, claude_cli_account_identifier_hash,
    claude_cli_account_identifier_hash_at, default_claude_cli_config_path,
};
pub use claude_config_slots::{
    prepare_managed_claude_provisional_root, validate_managed_claude_auth_root,
    ClaudeConfigDirSlot, ClaudeConfigSlotSettingsError, ClaudeSlotAccountBinding,
    ClaudeSlotApproval, ClaudeSlotApprovalSource, FileClaudeConfigSlotSettingsStore,
    CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME, CLAUDE_MANAGED_ACCOUNTS_DIR_NAME,
    MAX_CLAUDE_ACCOUNT_SLOTS,
};
pub use claude_statusline::{
    ingest_claude_statusline_payload, read_claude_statusline_cache,
    read_claude_statusline_context_cache, read_claude_statusline_context_history,
    write_claude_statusline_cache, ClaudeStatusLineContextWindowCache,
    ClaudeStatusLineContextWindowHistory, ClaudeStatusLineContextWindowSample,
    ClaudeStatusLineRateLimitCache, ClaudeStatusLineRateLimitWindow,
    CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
};
pub use codex_account_slots::{
    read_codex_auth_file_secure, read_codex_config_file_secure, CodexAccountSlotSettingsError,
    CodexHomeTrust, FileCodexAccountSlotSettingsStore, CODEX_ACCOUNT_SLOT_SETTINGS_FILE_NAME,
    MAX_CODEX_ACCOUNT_SLOTS,
};
pub use lifecycle::{
    execute_local_uninstall, launch_agent_path, launchd_target, local_lifecycle_home_dir,
    plan_local_uninstall, UninstallExecutionOptions,
};
pub use local_client::{
    default_socket_path, request_unix_socket, request_unix_socket_with_timeout,
    LOCAL_CONTROL_REFRESH_TIMEOUT, LOCAL_CONTROL_SOCKET_TIMEOUT,
};
pub use local_service::{
    install_owner_for_path, kickstart_macos_launch_agent, macos_launch_agent_target,
    user_launchctl_domain, MACOS_LAUNCH_AGENT_LABEL, MACOS_LEGACY_LAUNCH_AGENT_LABEL,
    OTTTO_CLIENT_NAME, OTTTO_CONTROL_TOKEN_ENV, OTTTO_SECRET_FALLBACK_DIR_ENV,
    OTTTO_SERVICE_BINARY_NAME, OTTTO_SERVICE_SOCKET_NAME, OTTTO_SOCKET_ENV,
};
pub use redaction::{redact_inline, RedactionPolicy};
pub use status::{
    compiled_build_id, compiled_release_channel, compiled_release_version, empty_status, problem,
    release_channel_from_str,
};
pub use token_store::{
    client_control_token, disable_keychain_user_interaction, generate_control_token,
    load_or_create_control_token, load_or_create_control_token_unless_daemon_owns,
    write_owner_only_cache_file_atomic, write_owner_only_file_atomic, ControlTokenStore,
    KeychainSecretStore, TokenStoreError, OTTTO_KEYCHAIN_ACCOUNT, OTTTO_KEYCHAIN_SERVICE,
    OTTTO_LEGACY_KEYCHAIN_SERVICE, OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT, OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_RELAY_DEVICE_SECRET_ACCOUNT, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};

#[cfg(unix)]
#[doc(hidden)]
pub mod service_lifecycle;
