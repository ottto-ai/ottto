pub mod account_store;
pub mod claude_account;
pub mod claude_statusline;
pub mod lifecycle;
pub mod local_client;
pub mod local_service;
pub mod redaction;
pub mod status;
pub mod token_store;

pub use account_store::{
    default_account_path, default_connection_api_base_url, default_connection_path,
    default_device_path, default_machine_path, default_sources_dir, default_support_dir,
    is_persistent_installation_id, is_persistent_machine_id, source_state_file_name,
    FileAccountStore, FileConnectionStore, FileDeviceStore, FileMachineStore, FileSourceStateStore,
    LocalConnectionBinding, LocalDeviceBinding, LocalMachineBinding, LocalSourceState,
};
pub use claude_account::{
    billing_identity_hash, claude_account_identifier_hash, claude_cli_account_identifier_hash,
    claude_cli_account_identifier_hash_at, claude_cli_account_identifier_hash_from_config,
    default_claude_cli_config_path, CLAUDE_CLI_CONFIG_FILE_NAME,
};
pub use claude_statusline::{
    append_claude_statusline_context_history, claude_statusline_cache_path,
    claude_statusline_context_cache_path, claude_statusline_context_history_path,
    ingest_claude_statusline_payload, parse_claude_statusline_context_window_payload,
    parse_claude_statusline_payload, read_claude_statusline_cache,
    read_claude_statusline_context_cache, read_claude_statusline_context_history,
    write_claude_statusline_cache, write_claude_statusline_context_cache,
    write_claude_statusline_context_history, ClaudeStatusLineContextWindowCache,
    ClaudeStatusLineContextWindowHistory, ClaudeStatusLineContextWindowSample,
    ClaudeStatusLineIngestResult, ClaudeStatusLineRateLimitCache, ClaudeStatusLineRateLimitWindow,
    CLAUDE_STATUSLINE_CACHE_FILE_NAME, CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
    CLAUDE_STATUSLINE_CONTEXT_CACHE_FILE_NAME, CLAUDE_STATUSLINE_CONTEXT_HISTORY_FILE_NAME,
    CLAUDE_STATUSLINE_CONTEXT_HISTORY_MAX_SAMPLES,
    CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
};
pub use lifecycle::{
    execute_local_uninstall, launch_agent_path, launchd_target, local_lifecycle_home_dir,
    plan_local_uninstall, LifecycleError, UninstallExecutionOptions,
};
pub use local_client::{
    default_socket_path, request_unix_socket, request_unix_socket_with_timeout, LocalRequestError,
    LOCAL_CONTROL_REFRESH_TIMEOUT, LOCAL_CONTROL_SOCKET_TIMEOUT,
};
pub use local_service::{
    install_owner_for_path, kickstart_macos_launch_agent, macos_launch_agent_target,
    user_launchctl_domain, MACOS_LAUNCH_AGENT_LABEL, MACOS_LEGACY_LAUNCH_AGENT_LABEL,
    OTTTO_CLIENT_NAME, OTTTO_CONTROL_TOKEN_ENV, OTTTO_LEGACY_SERVICE_BINARY_NAME,
    OTTTO_LEGACY_SOCKET_NAME, OTTTO_SECRET_FALLBACK_DIR_ENV, OTTTO_SERVICE_BINARY_NAME,
    OTTTO_SERVICE_SOCKET_NAME, OTTTO_SOCKET_ENV,
};
pub use redaction::{redact_inline, redact_key_value, RedactionPolicy};
pub use status::{
    compiled_build_id, compiled_release_channel, compiled_release_version, empty_status, problem,
    release_channel_from_str,
};
pub use token_store::{
    client_control_token, disable_keychain_user_interaction, generate_control_token,
    load_or_create_control_token, ControlTokenStore, KeychainSecretStore, TokenStoreError,
    OTTTO_KEYCHAIN_ACCOUNT, OTTTO_KEYCHAIN_SERVICE, OTTTO_LEGACY_KEYCHAIN_SERVICE,
    OTTTO_RELAY_DEVICE_SECRET_ACCOUNT, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};
