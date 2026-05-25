pub mod account_store;
pub mod claude_statusline;
pub mod lifecycle;
pub mod local_client;
pub mod local_service;
pub mod redaction;
pub mod status;
pub mod token_store;

pub use account_store::{
    default_account_path, default_connection_api_base_url, default_connection_path,
    default_device_path, default_machine_path, default_support_dir, is_persistent_installation_id,
    is_persistent_machine_id, FileAccountStore, FileConnectionStore, FileDeviceStore,
    FileMachineStore, LocalConnectionBinding, LocalDeviceBinding, LocalMachineBinding,
};
pub use claude_statusline::{
    claude_statusline_cache_path, ingest_claude_statusline_payload,
    parse_claude_statusline_payload, read_claude_statusline_cache, write_claude_statusline_cache,
    ClaudeStatusLineIngestResult, ClaudeStatusLineRateLimitCache, ClaudeStatusLineRateLimitWindow,
    CLAUDE_STATUSLINE_CACHE_FILE_NAME, CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
};
pub use lifecycle::{
    execute_local_uninstall, launch_agent_path, launchd_target, local_lifecycle_home_dir,
    plan_local_uninstall, LifecycleError, UninstallExecutionOptions,
};
pub use local_client::{default_socket_path, request_unix_socket};
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
    client_control_token, generate_control_token, load_or_create_control_token, ControlTokenStore,
    KeychainSecretStore, TokenStoreError, OTTTO_KEYCHAIN_ACCOUNT, OTTTO_KEYCHAIN_SERVICE,
    OTTTO_LEGACY_KEYCHAIN_SERVICE, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};
