use crate::agent_configs::claude_env;
use crate::agent_configs::codex_toml;
use crate::agent_configs::detection::detect_agent_installation;
use crate::agent_configs::fence::AgentConfigError;
use crate::agent_status::pi_identity_hints_for_route;
use crate::agent_status::read_pi_agent_auth;
use crate::agent_status::read_pi_smoke_routes;
use crate::agent_status::BillingIdentityHints;
use crate::agent_status::PiModelRoute;
use crate::current_rfc3339_timestamp;
use crate::diagnostics_local_only_upload_report;
use crate::keychain::TelemetryKeyStore;
use crate::snapshot_client::relay_token_request_payload;
use crate::BackendErrorDetails;
use crate::BackendErrorKind;
use crate::LocalApiError;
use crate::LocalDaemon;
use crate::PendingAuthClaim;
use crate::SetupRunReadStart;
use crate::StagedAccountSwitch;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ottto_core::compiled_build_id;
use ottto_core::compiled_release_channel;
use ottto_core::compiled_release_version;
use ottto_core::default_prior_device_path;
use ottto_core::default_support_dir;
use ottto_core::execute_local_uninstall;
use ottto_core::generate_control_token;
use ottto_core::install_owner_for_path;
use ottto_core::local_lifecycle_home_dir;
use ottto_core::plan_local_uninstall;
use ottto_core::redact_inline;
use ottto_core::release_channel_from_str;
use ottto_core::token_store::OTTTO_HISTORY_BROWSER_CLAIM_ACCOUNT as HISTORY_BROWSER_ACCOUNT;
use ottto_core::token_store::OTTTO_LOCAL_RELEASE_MARKER_ACCOUNT as HISTORY_MARKER_ACCOUNT;
use ottto_core::token_store::OTTTO_LOCAL_RELEASE_PROOF_ACCOUNT as HISTORY_PROOF_ACCOUNT;
use ottto_core::token_store::OTTTO_REVOCATION_RECEIPT_ACCOUNT;
use ottto_core::ClaudeConfigSlotSettingsError;
use ottto_core::CodexAccountSlotSettingsError;
use ottto_core::ControlTokenStore;
use ottto_core::DeviceCredentialContinuity;
use ottto_core::FileAccountStore;
use ottto_core::FileClaudeConfigSlotSettingsStore;
use ottto_core::FileCodexAccountSlotSettingsStore;
use ottto_core::FileConnectionStore;
use ottto_core::FileDeviceStore;
use ottto_core::FileMachineStore;
use ottto_core::FileOwnerSnapshotNamespaceStore;
use ottto_core::FilePendingDeviceCredentialStore;
use ottto_core::KeychainSecretStore;
use ottto_core::LocalConnectionBinding;
use ottto_core::LocalCredentialOwner;
use ottto_core::LocalDeviceBinding;
use ottto_core::LocalDeviceCredentialBinding;
use ottto_core::LocalDeviceEnvelope;
#[cfg(test)]
use ottto_core::LocalMachineBinding;
use ottto_core::OwnerSnapshotKey;
use ottto_core::OwnerSnapshotNamespace;
use ottto_core::PendingClaimCredentialCommit;
use ottto_core::PendingDeviceCredentialPreparation;
use ottto_core::PendingDeviceCredentialRequestAuthority;
use ottto_core::SnapshotNamespaceAlias;
use ottto_core::TokenStoreError;
use ottto_core::UninstallExecutionOptions;
use ottto_core::OTTTO_CLIENT_NAME;
use ottto_core::OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT;
use ottto_core::OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT;
use ottto_core::OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT;
use ottto_core::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT;
use ottto_core::OTTTO_SERVICE_BINARY_NAME;
use ottto_core::OTTTO_SETUP_RUN_TOKEN_ACCOUNT;
use ottto_protocol::validate_local_control_protocol_version;
use ottto_protocol::AgentContextQuery;
use ottto_protocol::AgentCostsQuery;
use ottto_protocol::AgentInstallationDetection;
use ottto_protocol::AgentProviderImpactQuery;
use ottto_protocol::AgentRecommendationsQuery;
use ottto_protocol::AgentSessionsQuery;
use ottto_protocol::AgentStatusSnapshot;
use ottto_protocol::AuthCompleteResponse;
use ottto_protocol::AuthResetResponse;
use ottto_protocol::AuthStartResponse;
use ottto_protocol::ClaudeAccountSetupOperationState;
use ottto_protocol::ClaudeConfigSlotCollectionStateV1;
use ottto_protocol::CliError;
use ottto_protocol::CliErrorCode;
use ottto_protocol::CodexAccountSetupOperationStateV1;
use ottto_protocol::ConfigDrift;
use ottto_protocol::ControlResult;
use ottto_protocol::ControlResultStatus;
use ottto_protocol::DiagnosticsBundle;
use ottto_protocol::DiagnosticsRetentionDisclosure;
use ottto_protocol::DiagnosticsUploadApproval;
use ottto_protocol::DiagnosticsUploadAuthorization;
use ottto_protocol::DiagnosticsUploadReport;
use ottto_protocol::DiagnosticsUploadStatus;
use ottto_protocol::InstallOwner;
use ottto_protocol::LocalAccountBinding;
use ottto_protocol::LocalAccountOrganization;
use ottto_protocol::LocalAccountState;
use ottto_protocol::LocalAccountUser;
use ottto_protocol::LocalClientKind;
use ottto_protocol::LocalControlCommand;
use ottto_protocol::LocalControlRequest;
use ottto_protocol::LocalControlResponse;
use ottto_protocol::MachineIdentity;
use ottto_protocol::ProviderDailyReferenceBackendGrantResponseV1;
use ottto_protocol::ProviderDailyReferenceControlAction;
use ottto_protocol::RedactedValue;
use ottto_protocol::RelayRuntimeState;
use ottto_protocol::RelayState;
use ottto_protocol::ReleaseChannel;
use ottto_protocol::RepairAction;
use ottto_protocol::RepairActionApproval;
use ottto_protocol::RepairActionKind;
use ottto_protocol::RepairApprovalSurface;
use ottto_protocol::RepairPlan;
use ottto_protocol::RepairPlanStatus;
use ottto_protocol::SecretString;
use ottto_protocol::ServiceOwnerState;
use ottto_protocol::SourceConfigState;
use ottto_protocol::SourceKind;
use ottto_protocol::SourceRouteVerificationResult;
use ottto_protocol::SourceVerificationCheck;
use ottto_protocol::SourceVerificationMethod;
use ottto_protocol::SourceVerificationResult;
use ottto_protocol::SourceVerificationScope;
use ottto_protocol::SourceVerificationStatus;
use ottto_protocol::StableMessage;
use ottto_protocol::TelemetryControlAction;
use ottto_protocol::UninstallExecutionResult;
use ottto_protocol::UpdateGate;
use ottto_protocol::UpdateState;
use ottto_protocol::UpdateStatus;
use ottto_protocol::DIAGNOSTICS_RETENTION_DISCLOSURE;
use ottto_protocol::PROTOCOL_VERSION;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fs;
use std::io;
use std::io::Read;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::FromRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
#[cfg(test)]
pub(crate) use tests::account_return_claim_for_test;
#[cfg(test)]
pub(crate) use tests::owner_return_credential_for_test;
#[cfg(test)]
pub(crate) use tests::owner_return_seed_for_test;
use toml_edit::DocumentMut;
use toml_edit::Item;

mod accounts;
mod auth;
mod backend_http;
mod diagnostics;
mod managed_config;
mod peer;
mod protocol;
mod setup;
mod status;
pub(crate) use accounts::claude::approved_managed_claude_relay_endpoint;
use accounts::claude::approved_managed_claude_relay_env;
pub(crate) use accounts::claude::check_claude_account;
#[cfg(test)]
use accounts::claude::check_claude_account_with_collector;
use accounts::claude::disable_managed_claude_relay_settings;
use accounts::claude::load_claude_config_slot_settings;
use accounts::claude::lock_managed_claude_settings;
#[cfg(test)]
use accounts::claude::prepare_claude_account;
use accounts::claude::prepare_claude_account_legacy;
use accounts::claude::prepare_claude_account_target;
#[cfg(test)]
use accounts::claude::prepare_claude_account_target_mode;
pub(crate) use accounts::claude::provision_managed_claude_relay_settings;
pub(crate) use accounts::claude::read_managed_claude_relay_settings;
use accounts::claude::reconnect_claude_account;
use accounts::claude::reconnect_claude_account_target;
#[cfg(test)]
use accounts::claude::recover_failed_claude_browser_registry_mutation;
use accounts::claude::register_claude_account_path;
use accounts::claude::remove_claude_account;
pub(crate) use accounts::claude::remove_claude_registration_with_relay_cleanup;
#[cfg(test)]
use accounts::claude::repair_registered_managed_claude_relay_settings;
use accounts::claude::repair_registered_managed_claude_relay_settings_locked;
use accounts::claude::set_claude_account_upkeep_consent;
use accounts::claude::start_claude_browser_login;
use accounts::claude::start_claude_browser_reconnect;
use accounts::claude::stop_waiting_for_claude_account;
pub(crate) use accounts::claude::ManagedClaudeRelaySettings;
use accounts::codex::check_codex_account;
#[cfg(test)]
use accounts::codex::codex_account_target_binding;
pub(crate) use accounts::codex::codex_setup_slot_id;
pub(crate) use accounts::codex::finish_codex_setup_validation;
use accounts::codex::load_codex_account_settings_for_status_read;
use accounts::codex::prepare_codex_account;
use accounts::codex::prepare_codex_account_target;
use accounts::codex::prepare_open_codex_account;
use accounts::codex::reconnect_codex_account;
use accounts::codex::remove_codex_account;
use accounts::codex::set_codex_quota_refresh_consent;
use accounts::codex::start_codex_sign_in;
use accounts::codex::stop_waiting_for_codex_account;
pub(crate) use accounts::codex::verify_pinned_codex_setup;
pub(crate) use accounts::codex::CodexSetupValidationEnd;
#[cfg(test)]
use auth::action_slug;
#[cfg(test)]
use auth::provider_daily_reference_action_slug;
use auth::provider_daily_reference_control;
#[cfg(test)]
use auth::provider_daily_reference_control_with_stores;
use auth::require_authorized_local_client;
use auth::require_local_control_account;
use auth::require_non_empty_field;
use auth::validate_control_token_fresh;
use auth::validate_control_token_with_backend;
use backend_http::api_url_with_base;
use backend_http::backend_error_from_ureq;
use backend_http::backend_get_agent_read_json;
use backend_http::backend_get_json;
use backend_http::backend_get_json_with_timeout;
use backend_http::backend_post_json;
use backend_http::backend_post_json_with_timeout;
#[cfg(test)]
use backend_http::backend_reason_code;
use backend_http::backend_response_unexpected;
use backend_http::backend_success;
use backend_http::bounded_display_text;
use backend_http::cli_error;
use backend_http::cli_error_message;
use backend_http::control_token_validation_base_url;
use backend_http::form_url_encode;
pub(crate) use backend_http::is_production_api_base_url;
use backend_http::reattach_required_state;
#[cfg(test)]
use backend_http::safe_backend_body_excerpt;
use backend_http::safe_backend_endpoint;
pub(crate) use backend_http::terminal_refresh_rejection;
use backend_http::validated_api_base_url;
pub(crate) use backend_http::TerminalRefreshRejection;
#[cfg(test)]
use backend_http::MAC_DISCONNECTED_FROM_EARLIER_ACCOUNT_MESSAGE;
#[cfg(test)]
use backend_http::MAC_DISCONNECTED_MESSAGE;
use diagnostics::diagnostics_collect;
use managed_config::apply_telemetry_config;
use managed_config::claude_code_relay_env_for_machine_id;
#[cfg(test)]
use managed_config::claude_code_relay_env_with_base;
#[cfg(test)]
use managed_config::claude_code_settings_config_state_at;
#[cfg(test)]
use managed_config::claude_code_settings_has_relay_env;
#[cfg(test)]
use managed_config::claude_code_settings_has_statusline_helper;
use managed_config::claude_code_telemetry_config_installed;
use managed_config::claude_managed_config_preview;
use managed_config::claude_settings_kept_reason;
#[cfg(test)]
use managed_config::claude_statusline_refresh_repair_needed;
#[cfg(test)]
use managed_config::claude_statusline_wrapper_path;
#[cfg(test)]
use managed_config::codex_config_has_relay_otel;
use managed_config::codex_config_state_at;
use managed_config::codex_managed_config_preview;
#[cfg(test)]
use managed_config::codex_source_off_body;
#[cfg(test)]
use managed_config::config_backup_retention_limit;
#[cfg(test)]
use managed_config::config_drift;
use managed_config::empty_source_config;
use managed_config::executable_exists;
use managed_config::execute_write_config_repair;
#[cfg(test)]
use managed_config::expected_claude_statusline_command;
use managed_config::home_path;
use managed_config::local_relay_base_url_for_daemon;
use managed_config::local_relay_port_for_daemon;
use managed_config::loopback_listener_available;
#[cfg(test)]
use managed_config::managed_config_preview;
#[cfg(test)]
use managed_config::patch_claude_code_env_at;
#[cfg(test)]
use managed_config::patch_claude_code_settings_at;
#[cfg(test)]
use managed_config::patch_claude_code_settings_at_with_relay_base;
use managed_config::patch_claude_code_settings_with_relay_base;
#[cfg(test)]
use managed_config::patch_codex_config_at;
use managed_config::preferred_ottto_cli_path;
#[cfg(test)]
use managed_config::propose_repair_plan;
#[cfg(test)]
use managed_config::prune_config_backups;
use managed_config::read_optional_to_string;
use managed_config::reconcile_codex_source_off;
#[cfg(test)]
use managed_config::reconcile_codex_source_off_at;
pub use managed_config::reconcile_codex_source_off_at_startup;
#[cfg(test)]
use managed_config::remove_claude_code_env_at;
use managed_config::remove_telemetry_config;
#[cfg(test)]
use managed_config::render_codex_relay_toml_block_for_base;
use managed_config::repair_claude_statusline_for_refresh_at;
use managed_config::repair_source;
#[cfg(test)]
use managed_config::repair_source_config;
use managed_config::request_snapshot_sync_after_device_registration;
#[cfg(test)]
use managed_config::scan_index_rebuild_override_repair;
use managed_config::setup_source_paused;
use managed_config::snapshot_device_credentials_include_source;
use managed_config::source_config_state_for_daemon;
use managed_config::source_patch_disabled;
#[cfg(test)]
use managed_config::source_patch_env_token;
use managed_config::source_requires_config_patch;
use managed_config::source_requires_device_registration;
use managed_config::sweep_telemetry_keys_for_uninstall;
#[cfg(test)]
use managed_config::write_codex_source_off_body;
#[cfg(test)]
use managed_config::ConfigPatchResult;
#[cfg(target_os = "macos")]
#[cfg(test)]
use peer::companion_code_requirement;
#[cfg(target_os = "macos")]
#[cfg(test)]
use peer::companion_identity_code_requirement;
#[cfg(test)]
use peer::companion_peer_is_trusted;
#[cfg(target_os = "macos")]
#[cfg(test)]
use peer::companion_team_code_requirement;
#[cfg(unix)]
#[cfg(test)]
use peer::daemon_effective_uid;
#[cfg(not(unix))]
#[cfg(test)]
use peer::daemon_effective_uid;
#[cfg(target_os = "macos")]
#[cfg(test)]
use peer::daemon_is_release_signed;
#[cfg(target_os = "macos")]
#[cfg(test)]
use peer::daemon_release_code_requirement;
use peer::request_authorization;
#[cfg(target_os = "macos")]
#[cfg(test)]
use peer::resolve_companion_code_requirement;
#[cfg(target_os = "macos")]
#[cfg(test)]
use peer::CompanionCodeRequirement;
pub use peer::LocalClientPeer;
use peer::RequestAuthorization;
use protocol::api_url;
use protocol::append_nonce_to_claim_url;
use protocol::to_value;
use protocol::BackendControlTokenClaims;
use protocol::BackendControlTokenValidationRequest;
use protocol::BackendControlTokenValidationResponse;
use protocol::DeviceCredentialConfirmationApiResponse;
use protocol::DeviceCredentialPreparationApiResponse;
use protocol::DeviceCredentialPreparationStatusApiResponse;
use protocol::DeviceReleaseProof;
use protocol::DeviceSelfReleaseResponse;
use protocol::DiagnosticsUploadApprovalSummary;
use protocol::DiagnosticsUploadBody;
use protocol::DiagnosticsUploadClient;
use protocol::DiagnosticsUploadResponse;
use protocol::InstallSessionApiResponse;
use protocol::InstallSessionEvent;
use protocol::OrStatePoisoned;
use protocol::RefreshedSetupRunToken;
#[cfg(test)]
use protocol::ReleaseArtifact;
use protocol::ReleaseManifest;
#[cfg(test)]
use protocol::ReleaseRollback;
use protocol::SetupActionEvent;
use protocol::SetupActionResult;
#[cfg(test)]
use protocol::SetupClaimCompleteOrganization;
#[cfg(test)]
use protocol::SetupClaimCompleteRelayDevice;
use protocol::SetupClaimCompleteResponse;
#[cfg(test)]
use protocol::SetupClaimCompleteUser;
use protocol::SetupClaimCompletion;
use protocol::SetupClaimCreateResponse;
use protocol::SetupRunActionApiResponse;
use protocol::SetupRunAttachResponse;
use protocol::SetupRunCredentials;
use protocol::SetupRunDetailApiResponse;
use protocol::SetupRunDisconnectResponse;
use protocol::SetupRunNextActionResponse;
use protocol::SetupRunRefreshResponse;
use protocol::SetupRunVerificationFilters;
use protocol::SetupRunVerificationResponse;
use protocol::SetupScanPayload;
use protocol::SetupScanSource;
use protocol::SetupVerificationTimeouts;
use setup::actions::pi_sessions::local_session_observed;
use setup::actions::pi_sessions::new_pi_route_session_files;
#[cfg(unix)]
#[cfg(test)]
use setup::actions::pi_sessions::open_or_create_pi_directory_component_with;
#[cfg(unix)]
#[cfg(test)]
use setup::actions::pi_sessions::open_or_create_pi_session_root_from_home_io;
#[cfg(not(unix))]
#[cfg(test)]
use setup::actions::pi_sessions::open_or_create_pi_session_root_from_home_io;
#[cfg(unix)]
#[cfg(test)]
use setup::actions::pi_sessions::open_pi_session_file_beneath_root;
#[cfg(not(unix))]
#[cfg(test)]
use setup::actions::pi_sessions::open_pi_session_file_beneath_root;
#[cfg(test)]
use setup::actions::pi_sessions::open_pi_session_root_direct;
#[cfg(unix)]
#[cfg(test)]
use setup::actions::pi_sessions::open_pi_session_root_direct_io;
#[cfg(not(unix))]
#[cfg(test)]
use setup::actions::pi_sessions::open_pi_session_root_direct_io;
#[cfg(test)]
use setup::actions::pi_sessions::open_pi_session_root_from_home;
use setup::actions::pi_sessions::pi_session_file_count;
#[cfg(test)]
use setup::actions::pi_sessions::pi_session_files_for_root;
#[cfg(test)]
use setup::actions::pi_sessions::pi_session_files_in;
#[cfg(test)]
use setup::actions::pi_sessions::pi_session_files_modified_since;
use setup::actions::pi_sessions::prepare_pi_live_session_census;
use setup::actions::pi_sessions::recent_pi_session_files;
#[cfg(test)]
use setup::actions::pi_sessions::OpenPiSessionRoot;
use setup::actions::pi_sessions::PiSessionCensus;
#[cfg(test)]
use setup::actions::smoke::classify_source_smoke_failure;
#[cfg(test)]
use setup::actions::smoke::command_diagnostic_is_usage_limited;
#[cfg(test)]
use setup::actions::smoke::command_diagnostic_requires_claude_reauth;
use setup::actions::smoke::emit_api_key_verification_marker;
use setup::actions::smoke::no_fresh_telemetry_code;
use setup::actions::smoke::not_installed_verification_result;
#[cfg(test)]
use setup::actions::smoke::otlp_metrics_url;
use setup::actions::smoke::pi_route_is_unscoped;
use setup::actions::smoke::pi_route_label;
use setup::actions::smoke::pi_route_model;
use setup::actions::smoke::pi_route_provider;
use setup::actions::smoke::pi_route_summary_metadata;
use setup::actions::smoke::pi_smoke_command;
#[cfg(test)]
use setup::actions::smoke::pi_smoke_command_with_version;
use setup::actions::smoke::record_smoke_prompt;
#[cfg(test)]
use setup::actions::smoke::redact_command_diagnostic;
use setup::actions::smoke::run_bounded_command;
#[cfg(test)]
use setup::actions::smoke::run_smoke_prompt;
use setup::actions::smoke::run_verification_smoke_prompt;
#[cfg(test)]
use setup::actions::smoke::smoke_command;
use setup::actions::smoke::smoke_failure_verification_result;
use setup::actions::smoke::smoke_failure_verification_result_with_config;
use setup::actions::smoke::smoke_result_metadata;
use setup::actions::smoke::source_binary_present;
use setup::actions::smoke::telemetry_disabled_by_admin_message;
use setup::actions::smoke::truncate_diagnostic;
#[cfg(test)]
use setup::actions::smoke::usage_limited_smoke_message;
use setup::actions::smoke::verification_failure_code;
use setup::actions::smoke::verification_failure_message;
#[cfg(test)]
use setup::actions::smoke::verification_marker_body;
use setup::actions::smoke::SmokeResult;
#[cfg(test)]
pub(crate) use setup::actions::smoke::CLAUDE_LOGIN_REFRESH_PENDING_CODE;
pub(crate) use setup::actions::smoke::CLAUDE_SMOKE_TIMEOUT_MESSAGE;
#[cfg(test)]
use setup::actions::verification::attach_verification_check;
#[cfg(test)]
use setup::actions::verification::codex_local_import_verification;
#[cfg(test)]
use setup::actions::verification::get_setup_run_verification_with_base_timeout;
#[cfg(test)]
use setup::actions::verification::is_telemetry_disabled_by_admin_error;
use setup::actions::verification::no_fresh_telemetry_message;
#[cfg(test)]
use setup::actions::verification::pi_route_aggregate_result;
#[cfg(test)]
use setup::actions::verification::pi_route_has_local_verification_evidence;
#[cfg(test)]
use setup::actions::verification::pi_route_passive_result;
#[cfg(test)]
use setup::actions::verification::pi_route_result_from_backend_error;
#[cfg(test)]
use setup::actions::verification::pi_route_result_from_verification;
pub(crate) use setup::actions::verification::reverify_failed_source;
#[cfg(test)]
use setup::actions::verification::run_one_pi_route_verification;
#[cfg(test)]
use setup::actions::verification::run_pi_route_pre_smoke;
#[cfg(test)]
use setup::actions::verification::run_pi_route_pre_smoke_with;
use setup::actions::verification::run_verify_source_action;
#[cfg(test)]
use setup::actions::verification::verification_result;
#[cfg(test)]
use setup::actions::verification::verification_result_for_backend_error;
use setup::actions::verification::verification_result_with_config;
use setup::actions::verification::verification_status_slug;
use setup::actions::verification::verify_source;
use setup::actions::verification::wait_for_setup_run_verification_with_base_timeout;
#[cfg(test)]
use setup::actions::verification::PI_LOCAL_ONLY_CODE;
#[cfg(test)]
use setup::actions::verification::PI_OAUTH_REAUTH_CODE;
use setup::claims::credentials::agent_read_with_refresh;
use setup::claims::credentials::clear_prior_device_credential;
use setup::claims::credentials::clear_prior_device_selector;
#[cfg(test)]
use setup::claims::credentials::commit_refreshed_setup_run_binding_locked;
use setup::claims::credentials::confirm_device_credential_preparation;
#[cfg(test)]
use setup::claims::credentials::device_credential_preparation_idempotency_key;
use setup::claims::credentials::device_credential_request_authority;
#[cfg(test)]
use setup::claims::credentials::device_release_proof;
use setup::claims::credentials::disconnect_setup_run_with_refresh;
use setup::claims::credentials::emit_setup_run_fast_verification_marker_with_refresh_mut;
use setup::claims::credentials::inspect_device_credential_preparation;
use setup::claims::credentials::load_device_release_proof;
#[cfg(test)]
use setup::claims::credentials::owner_snapshot_logout_can_retain_active;
use setup::claims::credentials::pending_credential_owner;
#[cfg(test)]
use setup::claims::credentials::pending_owner_snapshot_key;
use setup::claims::credentials::prepare_telemetry_device_registration;
use setup::claims::credentials::prior_device_credential_for_registration;
#[cfg(test)]
use setup::claims::credentials::prior_device_credential_with_stores;
use setup::claims::credentials::publish_owner_snapshot_history;
use setup::claims::credentials::record_install_session_event;
pub(crate) use setup::claims::credentials::refresh_setup_run_token_for_persisted_connection;
use setup::claims::credentials::refresh_setup_run_token_via_device_secret;
use setup::claims::credentials::release_device_without_setup_run;
use setup::claims::credentials::retain_prior_device_credential_for_logout;
#[cfg(test)]
use setup::claims::credentials::retain_prior_device_credential_with_stores;
use setup::claims::credentials::same_prior_device_authority;
use setup::claims::credentials::seed_owner_snapshot_history_for_logout;
use setup::claims::credentials::select_owner_snapshot_namespace;
#[cfg(test)]
use setup::claims::credentials::setup_run_disconnect_body;
use setup::claims::credentials::setup_run_request_with_refresh_mut;
use setup::claims::credentials::setup_run_token_for_connection;
use setup::claims::credentials::supported_pending_credential_schema;
#[cfg(test)]
use setup::claims::credentials::telemetry_device_register_body;
#[cfg(test)]
use setup::claims::credentials::telemetry_device_register_body_with_prior;
#[cfg(test)]
use setup::claims::credentials::validate_device_credential_confirmation;
use setup::claims::credentials::validate_device_credential_preparation;
use setup::claims::credentials::validate_owner_snapshot_selection;
use setup::claims::credentials::wait_for_setup_run_verification_with_refresh_mut_timeout;
use setup::claims::credentials::wait_for_verification_with_refresh_mut;
use setup::claims::credentials::PriorDeviceCredential;
#[cfg(test)]
use setup::claims::credentials::SetupRunConnectionStore;
use setup::claims::credentials::IDENTITY_CONTINUITY_CAPABILITY;
use setup::claims::credentials::MACHINE_IDENTITY_CAPABILITY;
#[cfg(test)]
use setup::claims::credentials::OWNER_SNAPSHOT_MACHINE_FOR_TEST;
pub(crate) use setup::reconcile::reconcile_setup_scan_in_background;
#[cfg(test)]
use setup::reconcile::setup_reconcile_backend_fields;
#[cfg(test)]
use setup::reconcile::setup_reconcile_refused;
#[cfg(test)]
use setup::reconcile::SetupScanReconcile;
use setup::reconcile::SETUP_SCAN;
#[cfg(test)]
use setup::scan::build_local_scan;
#[cfg(test)]
use setup::scan::clear_setup_run_connection_if_current;
use setup::scan::queue_setup_action;
use setup::scan::require_setup_run_still_bound;
#[cfg(test)]
use setup::scan::save_source_collection;
use setup::scan::scan_setup_run_with_action_count;
#[cfg(test)]
use setup::scan::scan_source;
use setup::scan::set_source_marker;
use setup::scan::setup_answer;
use setup::scan::setup_run;
use setup::scan::setup_run_binding_matches;
use setup::scan::source_collection;
use status::account_for;
use status::agent_context;
use status::agent_costs;
#[cfg(test)]
use status::agent_costs_url;
use status::agent_provider_impact;
use status::agent_recommendations;
use status::agent_sessions;
#[cfg(test)]
use status::apply_machine_icon;
use status::check_update_state;
#[cfg(test)]
use status::client_owner_conflict;
use status::cloud_status;
#[cfg(test)]
use status::commits_equivalent;
use status::current_millis;
use status::current_rfc3339;
use status::detect_install_owner;
use status::inject_machine_icon;
use status::local_lifecycle_home;
use status::operating_system_slug;
use status::refresh_agent_status_for;
use status::request_explicit_quota_refresh;
use status::rfc3339_after_minutes;
use status::service_owner_state;
use status::source_display_name;
use status::source_from_slug;
use status::source_slug;
use status::status_for;
#[cfg(test)]
use status::update_state_from_manifest;
#[cfg(test)]
use status::upload_agent_status_snapshots_in_background;
use status::url_with_query_params;
#[cfg(test)]
use status::validate_cloud_status_source;
use status::verification_result_should_refresh_agent_status;
#[cfg(test)]
use status::version_tuple;
use status::TIMEZONE_OVERRIDE_UNSUPPORTED;

// Direct API host (was the apex `ottto.net/backend` proxy, retired in the
// marketing-site cutover). Matches DIRECT_API_BASE_URL below.
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";

const DIRECT_API_BASE_URL: &str = "https://api.ottto.net";

const DEVICE_CREDENTIAL_PREPARATION_CAPABILITY: &str = "device_credential_prepare_confirm_v1";

const DEVICE_CREDENTIAL_PREPARATION_SECRET_HEADER: &str =
    "X-Ottto-Device-Credential-Preparation-Secret";

const PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION: u16 = 2;

// v2 is already released. History-bearing ceremonies must reject downgrade.
const OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION: u16 = 3;

// Legacy apex proxy base persisted by daemons installed before the marketing
// cutover. Still trusted/recognized so existing installs keep ingesting until
// they re-onboard onto the direct api.ottto.net base.
const LEGACY_API_BASE_URL: &str = "https://ottto.net/backend";

const SMOKE_PROMPT: &str = "Reply with exactly: ottto smoke test";

const BACKEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

const AGENT_READ_HTTP_TIMEOUT: Duration = Duration::from_secs(120);

const SETUP_SCAN_RESULT_HTTP_TIMEOUT: Duration = Duration::from_secs(120);

const SETUP_VERIFICATION_HTTP_TIMEOUT: Duration = Duration::from_secs(120);

const SETUP_VERIFICATION_MARKER_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

const SMOKE_COMMAND_TIMEOUT: Duration = Duration::from_secs(45);

const PI_SMOKE_COMMAND_TIMEOUT: Duration = Duration::from_secs(25);

const PI_VERIFICATION_WAIT_TIMEOUT: Duration = Duration::from_secs(8);

const PI_VERIFICATION_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

const PI_SESSION_IMPORT_UNSUPPORTED_PLATFORM_REASON: &str =
    "race-safe rooted session access is unavailable on this platform";

const PI_SESSION_CENSUS_FAILED_CODE: &str = "pi_session_census_failed";

// Poll long enough for slow-arriving agent telemetry (codex batches + flushes
// its token records, then the relay forwards them) to reach the backend before
// we give up — claude/pi still return early on success. Kept under
// SETUP_VERIFICATION_HTTP_TIMEOUT (120s).
const VERIFICATION_WAIT_TIMEOUT: Duration = Duration::from_secs(110);

const VERIFICATION_POLL_INTERVAL: Duration = Duration::from_secs(2);

const AGENT_STATUS_SNAPSHOT_TTL_MINUTES: u64 = 15;

const VERIFICATION_MARKER_METRIC_NAME: &str = "ottto.verification.smoke";

const VERIFICATION_MARKER_ATTRIBUTE: &str = "ottto.verification";

const VERIFICATION_MARKER_HEADER: &str = "X-Ottto-Verification";

const SMOKE_USAGE_LIMIT_ERROR_CODE: &str = "usage_limited";

const CLAUDE_OAUTH_REAUTH_REQUIRED_CODE: &str =
    crate::CLAUDE_OAUTH_REAUTH_REQUIRED_VERIFICATION_CODE;

/// Verification message/error code for a source whose CLI is genuinely not
/// installed on this machine. Reported instead of running a doomed smoke that
/// would surface "not installed or not executable" as a blocking telemetry
/// failure. Maps to a non-blocking `not_found` source state. Shared with the
/// crate-root health projection via [`crate::SOURCE_NOT_INSTALLED_VERIFICATION_CODE`].
const SOURCE_NOT_INSTALLED_CODE: &str = crate::SOURCE_NOT_INSTALLED_VERIFICATION_CODE;

/// Data/config present but the CLI binary can't be found or executed (desktop-
/// app-only installs). Maps to a visible, non-blocking soft warning. Shared
/// with the crate-root health projection via
/// [`crate::AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE`].
const AGENT_CLI_UNAVAILABLE_CODE: &str = crate::AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE;

const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(750);

const MAX_CONFIG_BACKUPS_PER_SOURCE: usize = 10;

const OTTTO_CONFIG_BACKUP_RETENTION_ENV: &str = "OTTTO_CONFIG_BACKUP_RETENTION";

/// Apple Developer Team ID that signs the official Ottto Companion app, baked
/// into the binary at compile time.
///
/// SECURITY: this is what makes the Companion code requirement enforced *by
/// default*. It used to be supplied only through `OTTTO_COMPANION_TEAM_ID` /
/// `OTTTO_COMPANION_CODE_REQUIREMENT`, and nothing in the shipped installers
/// or LaunchAgents ever set either one — so every production install fell back
/// to trusting any binary sitting at one of the [`trusted_companion_paths`]
/// (including the user-writable `~/Applications/Ottto.app`). A compile-time
/// default cannot be un-set by an installer regression, and — unlike a
/// LaunchAgent `EnvironmentVariables` entry — it is not stored in a
/// user-writable file.
///
/// The value is not a secret: it is the `subject.OU` of the Developer ID
/// certificate in every signed, notarized Ottto release and is printed by
/// `codesign -dv --verbose=4 /Applications/Ottto.app`.
///
/// It has two jobs: it is the team the Companion must be signed by, and — via
/// [`daemon_is_release_signed`] — the team whose signature on *this daemon*
/// marks the install as a customer artifact rather than an internal build.
///
/// Forks and downstream builds override it at build time:
/// `OTTTO_COMPANION_DEFAULT_TEAM_ID=ABCDE12345 cargo build --release`.
/// Building with an empty value (`OTTTO_COMPANION_DEFAULT_TEAM_ID=`) disables
/// token-less Companion trust entirely rather than falling back to path-only
/// trust — see [`resolve_companion_code_requirement`].
#[cfg(target_os = "macos")]
const OTTTO_COMPANION_DEFAULT_TEAM_ID: &str = match option_env!("OTTTO_COMPANION_DEFAULT_TEAM_ID") {
    Some(team_id) => team_id,
    None => "YRNP9UD7WY",
};

// Serializes every account/device identity mutation with Codex cloud-task I/O
// admission. The same lock covers that admission and the identity write/reset.
static SETUP_RUN_BINDING_LOCK: Mutex<()> = Mutex::new(());

static IDENTITY_MUTATION_RESERVATION: AtomicU64 = AtomicU64::new(0);

static NEXT_IDENTITY_MUTATION_RESERVATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn lock_setup_run_binding() -> MutexGuard<'static, ()> {
    SETUP_RUN_BINDING_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn try_lock_setup_run_binding() -> Option<MutexGuard<'static, ()>> {
    SETUP_RUN_BINDING_LOCK.try_lock().ok()
}

pub(crate) fn identity_mutation_in_progress() -> bool {
    IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire) != 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalIdentityAuthoritySnapshot {
    account: LocalAccountBinding,
    device: Option<LocalDeviceBinding>,
}

struct IdentityMutationReservation {
    id: u64,
    snapshot: LocalIdentityAuthoritySnapshot,
}

impl IdentityMutationReservation {
    fn validate_locked(&self) -> Result<(), LocalApiError> {
        require_identity_mutation_reservation(Some(self))?;
        if load_local_identity_authority_snapshot()? != self.snapshot {
            return Err(LocalApiError::IdentityMutationInProgress);
        }
        Ok(())
    }
}

impl Drop for IdentityMutationReservation {
    fn drop(&mut self) {
        let _ = IDENTITY_MUTATION_RESERVATION.compare_exchange(
            self.id,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn reserve_identity_mutation() -> Result<IdentityMutationReservation, LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    reserve_identity_mutation_locked()
}

/// [`reserve_identity_mutation`] for a caller already holding the identity
/// lifecycle lock.
fn reserve_identity_mutation_locked() -> Result<IdentityMutationReservation, LocalApiError> {
    require_identity_mutation_reservation(None)?;
    let snapshot = load_local_identity_authority_snapshot()?;
    crate::account_nicknames::invalidate_locked();
    let id = NEXT_IDENTITY_MUTATION_RESERVATION.fetch_add(1, Ordering::Relaxed);
    if id == 0
        || IDENTITY_MUTATION_RESERVATION
            .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    let reservation = IdentityMutationReservation { id, snapshot };
    // The reservation closes new Codex cloud-task admission. Drain work
    // already admitted before replacing local identity.
    crate::cloud_sessions::CloudSessionCheckpointStore::default()
        .wait_for_collector_io_idle(crate::cloud_sessions::COLLECTOR_IO_STOP_TIMEOUT)
        .map_err(|_| LocalApiError::CloudSessionCleanupRequired)?;
    Ok(reservation)
}

fn require_identity_mutation_reservation(
    owner: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    let active = IDENTITY_MUTATION_RESERVATION.load(Ordering::Acquire);
    if match owner {
        Some(owner) => active == owner.id,
        None => active == 0,
    } {
        Ok(())
    } else {
        Err(LocalApiError::IdentityMutationInProgress)
    }
}

fn load_local_identity_authority_snapshot() -> Result<LocalIdentityAuthoritySnapshot, LocalApiError>
{
    let account = FileAccountStore::default().load().or_state_poisoned()?;
    let device = FileDeviceStore::default().load().or_state_poisoned()?;
    Ok(LocalIdentityAuthoritySnapshot { account, device })
}

pub fn handle_request(daemon: &LocalDaemon, request: LocalControlRequest) -> LocalControlResponse {
    handle_request_with_peer(daemon, request, None)
}

pub fn handle_request_with_peer(
    daemon: &LocalDaemon,
    request: LocalControlRequest,
    peer: Option<LocalClientPeer>,
) -> LocalControlResponse {
    let request_id = request.request_id.clone();
    if let Err(message) =
        validate_local_control_protocol_version(request.protocol_version, &request.command)
    {
        return LocalControlResponse {
            request_id,
            ok: false,
            payload: None,
            error: Some(CliError {
                message,
                retryable: false,
                code: CliErrorCode::InvalidRequest,
                details: BTreeMap::new(),
            }),
        };
    }
    let authorization = request_authorization(&request, peer.as_ref());
    let client_install_owner = request
        .client_install_owner
        .unwrap_or(InstallOwner::Unknown);
    let cli_session_exec = request.client_kind == Some(LocalClientKind::Cli);
    let status_refresh_quota_source =
        status_refresh_quota_source(request.client_kind, request.protocol_version);
    match handle_command(
        daemon,
        authorization,
        request.command,
        client_install_owner,
        status_refresh_quota_source,
        cli_session_exec,
    ) {
        Ok(payload) => LocalControlResponse {
            request_id,
            ok: true,
            payload: Some(payload),
            error: None,
        },
        Err(error) => LocalControlResponse {
            request_id,
            ok: false,
            payload: None,
            error: Some(cli_error(error)),
        },
    }
}

/// The diagnostic class of a control command; counts only, no ids or args.
pub(crate) fn control_command_class(command: &LocalControlCommand) -> &'static str {
    match command {
        LocalControlCommand::Status { .. } => "status",
        LocalControlCommand::ClaudeAccountsStatus => "claude_accounts_status",
        LocalControlCommand::CodexAccountsStatus => "codex_accounts_status",
        LocalControlCommand::AgentStatusRefresh { .. } => "agent_status_refresh",
        _ => "other",
    }
}

pub fn handle_request_json_with_peer(
    daemon: &LocalDaemon,
    request_json: &str,
    peer: Option<LocalClientPeer>,
) -> String {
    let request = serde_json::from_str::<LocalControlRequest>(request_json);
    crate::local_resource_diagnostics::control_class(
        request
            .as_ref()
            .map_or("other", |request| control_command_class(&request.command)),
    );
    let response = match request {
        Ok(request) => handle_request_with_peer(daemon, request, peer),
        Err(error) => LocalControlResponse {
            request_id: "req_xpc_invalid".to_string(),
            ok: false,
            payload: None,
            error: Some(CliError {
                message: format!("invalid local control request: {error}"),
                retryable: false,
                code: CliErrorCode::InvalidRequest,
                details: BTreeMap::new(),
            }),
        },
    };
    serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"request_id":"req_xpc_invalid","ok":false,"payload":null,"error":{"code":"internal","message":"failed to serialize local control response","retryable":false,"details":{}}}"#.to_string()
    })
}

/// Companion apps up to this protocol version have no `quota_refresh`: their
/// Refresh button sends `status` with `refresh_agent_status`, the same request
/// as their 5-minute scan. Those requests stand in for an explicit refresh of
/// every Codex home, at most once per
/// [`LEGACY_APP_QUOTA_REFRESH_MIN_GAP_SECONDS`] per home. Claude is left out:
/// its Refresh never forced a provider read, and its accounts are served the
/// stored reading the daemon's schedule keeps current. Such a request cannot
/// be told from the app's timer, so it reads nothing while Codex background
/// limit refresh is off.
const LEGACY_APP_QUOTA_REFRESH_MAX_PROTOCOL_VERSION: u16 = 15;

const LEGACY_APP_QUOTA_REFRESH_MIN_GAP_SECONDS: u64 = 5 * 60;

/// The source whose quota a `status` refresh from this client refreshes
/// explicitly, if any.
fn status_refresh_quota_source(
    client_kind: Option<LocalClientKind>,
    protocol_version: u16,
) -> Option<SourceKind> {
    (client_kind == Some(LocalClientKind::CompanionApp)
        && protocol_version <= LEGACY_APP_QUOTA_REFRESH_MAX_PROTOCOL_VERSION)
        .then_some(SourceKind::Codex)
}

fn require_session_launch_schema(version: u16) -> Result<(), LocalApiError> {
    if version != 1 {
        return Err(LocalApiError::InvalidRequest(
            "unsupported session launch schema".into(),
        ));
    }
    Ok(())
}

fn handle_command(
    daemon: &LocalDaemon,
    authorization: RequestAuthorization,
    command: LocalControlCommand,
    client_install_owner: InstallOwner,
    status_refresh_quota_source: Option<SourceKind>,
    cli_session_exec: bool,
) -> Result<serde_json::Value, LocalApiError> {
    // Invalidate pending handoffs before any explicit account/slot mutation.
    // Existing mutation handlers retain all of their authorization and order.
    if matches!(
        &command,
        LocalControlCommand::AuthComplete { .. }
            | LocalControlCommand::AuthCompletePending { .. }
            | LocalControlCommand::AuthSwitchAccount { .. }
            | LocalControlCommand::AuthReset { .. }
            | LocalControlCommand::ClaudeAccountRemove { .. }
            | LocalControlCommand::ClaudeAccountReconnect { .. }
            | LocalControlCommand::ClaudeAccountReconnectTarget { .. }
            | LocalControlCommand::ClaudeAccountStartBrowserReconnect { .. }
            | LocalControlCommand::CodexAccountRemove { .. }
            | LocalControlCommand::CodexAccountReconnect { .. }
    ) {
        require_authorized_local_client(daemon, &authorization)?;
        daemon
            .session_launch
            .lock()
            .or_state_poisoned()?
            .invalidate();
    }
    match command {
        LocalControlCommand::SessionLaunchPrepare {
            schema_version,
            provider,
            slot_id,
            expected_account_identifier_hash,
            expected_organization_identifier_hash,
            folder,
            ..
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon.session_launch.lock().or_state_poisoned()?.prepare(
                    provider,
                    &slot_id,
                    &expected_account_identifier_hash,
                    expected_organization_identifier_hash
                        .as_deref()
                        .unwrap_or(""),
                    folder,
                    preferred_ottto_cli_path(),
                    &default_support_dir(),
                ),
            )
        }
        LocalControlCommand::SessionLaunchConsume {
            schema_version,
            launch_id,
            secret,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            // Only the token-authenticated CLI owns the exec plan. The trusted
            // Companion can prepare/poll/cancel, but never consume a handoff.
            if !cli_session_exec || !matches!(&authorization, RequestAuthorization::Token(_)) {
                return Err(LocalApiError::Unauthorized);
            }
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon
                    .session_launch
                    .lock()
                    .or_state_poisoned()?
                    .consume(&launch_id, secret.expose_secret()),
            )
        }
        LocalControlCommand::SessionLaunchReport {
            schema_version,
            launch_id,
            attempt_id,
            reason,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            if !cli_session_exec || !matches!(&authorization, RequestAuthorization::Token(_)) {
                return Err(LocalApiError::Unauthorized);
            }
            require_session_launch_schema(schema_version)?;
            to_value(daemon.session_launch.lock().or_state_poisoned()?.report(
                &launch_id,
                attempt_id.expose_secret(),
                reason,
            ))
        }
        LocalControlCommand::SessionLaunchStatus {
            schema_version,
            launch_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon
                    .session_launch
                    .lock()
                    .or_state_poisoned()?
                    .status(&launch_id, false),
            )
        }
        LocalControlCommand::SessionLaunchCancel {
            schema_version,
            launch_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(
                daemon
                    .session_launch
                    .lock()
                    .or_state_poisoned()?
                    .status(&launch_id, true),
            )
        }
        LocalControlCommand::SessionLaunchRecentFolders {
            schema_version,
            provider,
            slot_id,
            limit,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            require_session_launch_schema(schema_version)?;
            to_value(daemon.session_launch.lock().or_state_poisoned()?.recent(
                provider,
                slot_id.as_deref(),
                usize::from(limit.unwrap_or(100)),
                &default_support_dir(),
            ))
        }
        LocalControlCommand::AccountNicknames => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::account_nicknames::read())
        }
        LocalControlCommand::AccountNicknameSet {
            source,
            account_identifier_hash,
            organization_identifier_hash,
            nickname,
            base_revision,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::account_nicknames::set(
                ottto_protocol::AccountNicknamePairV1 {
                    source,
                    account_identifier_hash: Some(account_identifier_hash),
                    organization_identifier_hash,
                },
                nickname,
                base_revision,
            ))
        }
        LocalControlCommand::Status {
            refresh_agent_status,
            retry_relay_authorization,
        } => {
            if retry_relay_authorization {
                require_authorized_local_client(daemon, &authorization)?;
                crate::snapshot_sync::reset_relay_authorization_backoff();
                daemon.refresh_shell_profile_health()?;
            }
            if refresh_agent_status {
                if let Some(source) = status_refresh_quota_source.as_ref().filter(|_| {
                    FileCodexAccountSlotSettingsStore::default().background_quota_refresh_allowed()
                }) {
                    require_authorized_local_client(daemon, &authorization)?;
                    crate::provider_calls::with_trigger(
                        crate::provider_calls::Trigger::OlderAppCompat,
                        || {
                            request_explicit_quota_refresh(
                                Some(source),
                                LEGACY_APP_QUOTA_REFRESH_MIN_GAP_SECONDS,
                            )
                        },
                    );
                }
                refresh_agent_status_for(daemon, &authorization, None)?;
            }
            let mut status = status_for(daemon, &authorization)?;
            status.update.install_owner = detect_install_owner();
            status.service_owner = service_owner_state(client_install_owner);
            crate::refresh_canonical_local_health(&mut status);
            status.account = crate::effective_account_binding(&status);
            let mut value = to_value(status)?;
            inject_machine_icon(&mut value);
            // Doctor only: ordinary status polls must not walk the store.
            #[cfg(unix)]
            if retry_relay_authorization {
                if let Ok((files, bytes)) =
                    crate::claude_local_otel::support_health::store_size(&default_support_dir())
                {
                    value["local_otel"] = serde_json::json!({"files": files, "bytes": bytes});
                }
            }
            Ok(value)
        }
        LocalControlCommand::Receipts {
            limit,
            since,
            source,
            before,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            if limit == 0 || usize::from(limit) > crate::upload_receipts::UPLOAD_RECEIPT_PAGE_SIZE {
                return Err(LocalApiError::InvalidRequest(format!(
                    "receipts limit must be between 1 and {}",
                    crate::upload_receipts::UPLOAD_RECEIPT_PAGE_SIZE
                )));
            }
            if let Some(value) = since.as_deref() {
                time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                    .map_err(|_| {
                        LocalApiError::InvalidRequest(
                            "receipts since must be an RFC3339 timestamp".to_string(),
                        )
                    })?;
            }
            to_value(
                crate::upload_receipts::read_page(
                    &default_support_dir(),
                    limit,
                    since.as_deref(),
                    source,
                    before,
                )
                .map_err(|_| {
                    LocalApiError::LocalOperationFailed(
                        "could not read snapshot upload receipts".to_string(),
                    )
                })?,
            )
        }
        LocalControlCommand::AuthStatus => {
            let mut status = status_for(daemon, &authorization)?;
            status.account = crate::effective_account_binding(&status);
            to_value(status)
        }
        LocalControlCommand::AgentStatusRefresh {
            source,
            quota_refresh,
        } => {
            if quota_refresh {
                require_authorized_local_client(daemon, &authorization)?;
                crate::provider_calls::with_trigger(
                    crate::provider_calls::Trigger::ExplicitRefresh,
                    || request_explicit_quota_refresh(source.as_ref(), 0),
                );
            }
            to_value(refresh_agent_status_for(daemon, &authorization, source)?)
        }
        LocalControlCommand::AgentStatusCached { source } => {
            // Unlike the usual authorization helper, this skips the daemon-state
            // poison check: the cached read uses no daemon state.
            match &authorization {
                RequestAuthorization::Token(token) => daemon.control_token.authorize(token)?,
                RequestAuthorization::TrustedCompanionApp => {}
                RequestAuthorization::Untrusted => {
                    return Err(LocalApiError::LocalClientNotTrusted)
                }
            }
            to_value(crate::agent_status_refresh::cached(source.as_ref()))
        }
        LocalControlCommand::PersonalMeterLocalSnapshot { source } => {
            let status = status_for(daemon, &authorization)?;
            to_value(crate::personal_meter_local_snapshot_from_status(
                &status,
                source.as_ref(),
            ))
        }
        LocalControlCommand::AgentContext { query } => agent_context(daemon, &authorization, query),
        LocalControlCommand::AgentCosts { query } => agent_costs(daemon, &authorization, query),
        LocalControlCommand::AgentSessions { query } => {
            agent_sessions(daemon, &authorization, query)
        }
        LocalControlCommand::AgentRecommendations { query } => {
            agent_recommendations(daemon, &authorization, query)
        }
        LocalControlCommand::AgentProviderImpact { query } => {
            agent_provider_impact(daemon, &authorization, query)
        }
        LocalControlCommand::CloudStatus { source } => cloud_status(daemon, &authorization, source),
        LocalControlCommand::AuthStart => to_value(auth_start(daemon, &authorization)?),
        LocalControlCommand::AuthComplete { claim_code, nonce } => {
            to_value(auth_complete(daemon, &authorization, &claim_code, &nonce)?)
        }
        LocalControlCommand::AuthCompletePending { claim_code } => {
            to_value(auth_complete_pending(daemon, &authorization, &claim_code)?)
        }
        LocalControlCommand::AuthSwitchAccount { claim_code } => {
            to_value(auth_switch_account(daemon, &authorization, &claim_code)?)
        }
        LocalControlCommand::AuthReset {
            local_only,
            forget_installation,
        } => to_value(auth_reset(
            daemon,
            &authorization,
            local_only,
            forget_installation,
            None,
        )?),
        LocalControlCommand::Account => to_value(account_for(daemon, &authorization)?),
        LocalControlCommand::ClaudeAccountsStatus => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(load_claude_config_slot_settings()?)
        }
        LocalControlCommand::ClaudeAccountSetUpkeepConsent {
            schema_version,
            consent,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(set_claude_account_upkeep_consent(schema_version, consent)?)
        }
        LocalControlCommand::ClaudeAccountRemove {
            schema_version,
            slot_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(remove_claude_account(schema_version, &slot_id)?)
        }
        LocalControlCommand::ClaudeAccountRegisterPath {
            schema_version,
            config_dir,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(register_claude_account_path(schema_version, config_dir)?)
        }
        LocalControlCommand::ClaudeAccountPrepare {
            schema_version,
            operation_id,
            expected_account_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(prepare_claude_account_legacy(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
            )?)
        }
        LocalControlCommand::ClaudeAccountPrepareTarget {
            schema_version,
            operation_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(prepare_claude_account_target(
                schema_version,
                operation_id,
                target_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountReconnect {
            schema_version,
            operation_id,
            slot_id,
            expected_account_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(reconnect_claude_account(
                schema_version,
                operation_id,
                &slot_id,
                None,
                expected_account_identifier_hash,
                None,
            )?)
        }
        LocalControlCommand::ClaudeAccountReconnectTarget {
            schema_version,
            operation_id,
            slot_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(reconnect_claude_account_target(
                schema_version,
                operation_id,
                &slot_id,
                target_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountCheck {
            schema_version,
            operation_id,
            expected_account_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(check_claude_account(
                schema_version,
                &operation_id,
                expected_account_identifier_hash.as_deref(),
            )?)
        }
        LocalControlCommand::ClaudeAccountStopWaiting {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(stop_waiting_for_claude_account(
                schema_version,
                &operation_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountStartBrowserLogin {
            schema_version,
            operation_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(start_claude_browser_login(
                schema_version,
                operation_id,
                target_id,
            )?)
        }
        LocalControlCommand::ClaudeAccountStartBrowserReconnect {
            schema_version,
            operation_id,
            slot_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(start_claude_browser_reconnect(
                schema_version,
                operation_id,
                &slot_id,
                target_id,
            )?)
        }
        LocalControlCommand::RetiredClaudeAccountSubmitAuthCode {} => {
            // Authorization runs first so untrusted callers keep the normal
            // rejection; nothing reaches browser-auth state or the provider.
            require_authorized_local_client(daemon, &authorization)?;
            Err(LocalApiError::RetiredCommand(
                crate::claude_browser_auth::RETIRED_CODE_SUBMISSION_MESSAGE,
            ))
        }
        LocalControlCommand::CodexAccountsStatus => {
            require_authorized_local_client(daemon, &authorization)?;
            crate::codex_sign_in::end_stale_run();
            to_value(crate::codex_sign_in::present(
                load_codex_account_settings_for_status_read()?,
            ))
        }
        LocalControlCommand::CodexAccountPrepare {
            schema_version,
            operation_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(prepare_codex_account(
                schema_version,
                operation_id,
                expected_account_identifier_hash,
                expected_workspace_identifier_hash,
            )?))
        }
        LocalControlCommand::CodexAccountPrepareOpen {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(prepare_open_codex_account(
                schema_version,
                operation_id,
            )?))
        }
        LocalControlCommand::CodexAccountPrepareTarget {
            schema_version,
            operation_id,
            target_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(prepare_codex_account_target(
                schema_version,
                operation_id,
                target_id,
            )?))
        }
        LocalControlCommand::CodexAccountReconnect {
            schema_version,
            operation_id,
            slot_id,
            expected_account_identifier_hash,
            expected_workspace_identifier_hash,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(reconnect_codex_account(
                schema_version,
                operation_id,
                &slot_id,
                expected_account_identifier_hash,
                expected_workspace_identifier_hash,
            )?))
        }
        LocalControlCommand::CodexAccountCheck {
            schema_version,
            operation_id,
            explicit,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(check_codex_account(
                schema_version,
                &operation_id,
                explicit,
            )?))
        }
        LocalControlCommand::CodexAccountStartSignIn {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(start_codex_sign_in(
                schema_version,
                &operation_id,
            )?))
        }
        LocalControlCommand::CodexAccountStopWaiting {
            schema_version,
            operation_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(
                stop_waiting_for_codex_account(schema_version, &operation_id)?,
            ))
        }
        LocalControlCommand::CodexAccountRemove {
            schema_version,
            slot_id,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(remove_codex_account(
                schema_version,
                &slot_id,
            )?))
        }
        LocalControlCommand::CodexAccountSetQuotaRefreshConsent {
            schema_version,
            consent,
        } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(crate::codex_sign_in::present(
                set_codex_quota_refresh_consent(schema_version, consent)?,
            ))
        }
        LocalControlCommand::Detect { source } => {
            require_authorized_local_client(daemon, &authorization)?;
            to_value(detect_agent_installation(&source))
        }
        LocalControlCommand::Repair { source, dry_run } => {
            to_value(repair_source(daemon, &authorization, source, dry_run)?)
        }
        LocalControlCommand::DiagnosticsCollect {
            upload,
            upload_approval,
            api_base_url,
        } => diagnostics_collect(
            daemon,
            &authorization,
            upload,
            upload_approval,
            api_base_url,
        ),
        LocalControlCommand::RelayStart => {
            let relay = RelayState {
                state: RelayRuntimeState::Starting,
                endpoint: None,
                last_connected_at: None,
                last_error: None,
            };
            match &authorization {
                RequestAuthorization::Token(token) => {
                    daemon.set_relay_state(token, relay)?;
                    to_value(daemon.status(token)?.relay)
                }
                RequestAuthorization::TrustedCompanionApp => {
                    daemon.set_relay_state_for_trusted_client(relay)?;
                    to_value(daemon.status_for_trusted_client()?.relay)
                }
                RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
            }
        }
        LocalControlCommand::RelayStop => {
            let relay = RelayState {
                state: RelayRuntimeState::Stopping,
                endpoint: None,
                last_connected_at: None,
                last_error: None,
            };
            match &authorization {
                RequestAuthorization::Token(token) => {
                    daemon.set_relay_state(token, relay)?;
                    to_value(daemon.status(token)?.relay)
                }
                RequestAuthorization::TrustedCompanionApp => {
                    daemon.set_relay_state_for_trusted_client(relay)?;
                    to_value(daemon.status_for_trusted_client()?.relay)
                }
                RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
            }
        }
        LocalControlCommand::Verify { source, repair } => {
            // A person's Verify (the app or `ottto verify`) is a setup check.
            let result =
                crate::provider_calls::with_trigger(crate::provider_calls::Trigger::Setup, || {
                    verify_source(daemon, &authorization, source, repair)
                })?;
            if verification_result_should_refresh_agent_status(&result) {
                if let Err(error) =
                    refresh_agent_status_for(daemon, &authorization, Some(result.source.clone()))
                {
                    eprintln!(
                        "post-verify agent status refresh skipped: {}",
                        cli_error_message(&error)
                    );
                }
            }
            let mut value = to_value(result)?;
            let mut status = status_for(daemon, &authorization)?;
            status.update.install_owner = detect_install_owner();
            status.service_owner = service_owner_state(client_install_owner);
            crate::refresh_canonical_local_health(&mut status);
            if let Err(error) = crate::snapshot_sync::upload_local_health_projection_now(daemon) {
                eprintln!(
                    "manual local health projection upload skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            if let serde_json::Value::Object(object) = &mut value {
                object.insert(
                    "canonical_health".to_string(),
                    to_value(status.canonical_health)?,
                );
                object.insert(
                    "runtime_heartbeat".to_string(),
                    to_value(status.runtime_heartbeat)?,
                );
                object.insert(
                    "local_health_events".to_string(),
                    to_value(status.local_health_events)?,
                );
                object.insert(
                    "command_ledger".to_string(),
                    to_value(status.command_ledger)?,
                );
            }
            Ok(value)
        }
        LocalControlCommand::Setup {
            sources,
            claim_code,
            setup_run_id,
            api_base_url,
        } => setup_run(
            daemon,
            &authorization,
            sources,
            claim_code,
            setup_run_id,
            api_base_url,
        ),
        LocalControlCommand::SetupAnswer {
            source,
            answer_type,
            api_base_url,
        } => setup_answer(daemon, &authorization, source, answer_type, api_base_url),
        LocalControlCommand::SetupAction {
            source,
            action_type,
            api_base_url,
        } => setup_action(daemon, &authorization, source, action_type, api_base_url),
        LocalControlCommand::SourceCollection { source, enabled } => {
            source_collection(daemon, &authorization, source, enabled)
        }
        LocalControlCommand::TelemetryControl {
            action,
            source,
            control_token,
            api_base_url,
            key_id,
            organization_id,
            otlp_endpoint,
            ingest_key,
        } => to_value(telemetry_control(
            daemon,
            action,
            source,
            control_token,
            api_base_url,
            key_id,
            organization_id,
            otlp_endpoint,
            ingest_key,
        )?),
        LocalControlCommand::ProviderDailyReferenceControl {
            action,
            control_token,
            api_base_url,
            backend_grant,
            expected_account_fingerprint,
        } => to_value(provider_daily_reference_control(
            action,
            control_token,
            api_base_url,
            backend_grant,
            expected_account_fingerprint,
        )?),
        LocalControlCommand::UpdateCheck => to_value(check_update_state()),
        LocalControlCommand::UninstallPlan | LocalControlCommand::Uninstall => {
            require_authorized_local_client(daemon, &authorization)?;
            let home = local_lifecycle_home()?;
            to_value(plan_local_uninstall(&home))
        }
        LocalControlCommand::UninstallExecute { confirm } => {
            require_authorized_local_client(daemon, &authorization)?;
            if !confirm {
                return Err(LocalApiError::InvalidRequest(
                    "uninstall_execute requires confirm=true".to_string(),
                ));
            }
            let home = local_lifecycle_home()?;
            #[cfg(target_os = "macos")]
            crate::snapshots::invalidate_claude_state_v2_sessions(
                &home.join("Library/Application Support/Ottto"),
            )
            .or_state_poisoned()?;
            crate::claude_local_otel::disable_appends_for_uninstall().or_state_poisoned()?;
            let mut result = execute_local_uninstall(&home, UninstallExecutionOptions::DAEMON);
            sweep_telemetry_keys_for_uninstall(&mut result);
            match &authorization {
                RequestAuthorization::Token(token) => daemon.stop(token)?,
                RequestAuthorization::TrustedCompanionApp => daemon.stop_for_trusted_client()?,
                RequestAuthorization::Untrusted => {
                    return Err(LocalApiError::LocalClientNotTrusted)
                }
            }
            to_value(result)
        }
    }
}

#[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
fn telemetry_control(
    daemon: &LocalDaemon,
    action: TelemetryControlAction,
    source: SourceKind,
    control_token: String,
    api_base_url: Option<String>,
    key_id: Option<String>,
    organization_id: Option<String>,
    otlp_endpoint: Option<String>,
    ingest_key: Option<SecretString>,
) -> Result<ControlResult, LocalApiError> {
    telemetry_control_with_detector(
        daemon,
        action,
        source,
        control_token,
        api_base_url,
        key_id,
        organization_id,
        otlp_endpoint,
        ingest_key,
        &detect_agent_installation,
    )
}

#[expect(clippy::too_many_arguments, reason = "12 args; no options struct yet")]
fn telemetry_control_with_detector(
    daemon: &LocalDaemon,
    action: TelemetryControlAction,
    source: SourceKind,
    control_token: String,
    // SECURITY: the request-supplied `api_base_url` cannot freely choose where the
    // control token is validated. Token validation is the only gate protecting
    // this telemetry-config mutation against an untrusted local peer, so
    // `control_token_validation_base_url` only honors this value when it is a
    // trusted production backend (never a request-supplied loopback URL), closing
    // the bypass where a co-resident attacker points validation at their own
    // server. See that resolver for the full rationale.
    api_base_url: Option<String>,
    key_id: Option<String>,
    organization_id: Option<String>,
    otlp_endpoint: Option<String>,
    ingest_key: Option<SecretString>,
    detector: &dyn Fn(&SourceKind) -> AgentInstallationDetection,
) -> Result<ControlResult, LocalApiError> {
    let mut key_id = key_id;
    if source == SourceKind::Codex && matches!(action, TelemetryControlAction::EnableTelemetry) {
        return Err(LocalApiError::InvalidRequest(
            "Ottto Codex live telemetry is disabled; local session import remains available"
                .to_string(),
        ));
    }
    if !matches!(source, SourceKind::Codex | SourceKind::ClaudeCode) {
        return Err(LocalApiError::InvalidRequest(
            "telemetry control supports codex and claude_code only".to_string(),
        ));
    }

    let token_validation_base_url = control_token_validation_base_url(api_base_url.as_deref())?;
    validate_control_token_fresh(&control_token, &action, &source)?;

    match &action {
        TelemetryControlAction::EnableTelemetry => {
            require_non_empty_field(key_id.as_deref(), "key_id")?;
            require_non_empty_field(organization_id.as_deref(), "organization_id")?;
            require_non_empty_field(otlp_endpoint.as_deref(), "otlp_endpoint")?;
            let Some(secret) = ingest_key.as_ref() else {
                return Err(LocalApiError::InvalidRequest(
                    "enable_telemetry requires ingest_key".to_string(),
                ));
            };
            require_non_empty_field(Some(secret.expose_secret()), "ingest_key")?;
        }
        TelemetryControlAction::DisableTelemetry => {
            // Older installs, manually repaired installs, or installs that lost the
            // key index can still have local agent config patched to the Ottto
            // relay even though there is no indexed ingest key id to revoke.
            // Disabling live telemetry must still remove that local config; key
            // deletion is best-effort and only possible when the caller knows the
            // key id.
            if key_id
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(LocalApiError::InvalidRequest(
                    "key_id must not be empty when provided".to_string(),
                ));
            }
        }
        TelemetryControlAction::Status => {}
    }

    let claims = validate_control_token_with_backend(
        &token_validation_base_url,
        &control_token,
        &action,
        &source,
    )?;
    let _binding_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    require_local_control_account(&claims, &FileAccountStore::default(), "telemetry control")?;
    if matches!(
        action,
        TelemetryControlAction::Status | TelemetryControlAction::DisableTelemetry
    ) {
        let device = FileDeviceStore::default()
            .load()
            .map_err(|_| LocalApiError::LocalClientNotTrusted)?
            .ok_or(LocalApiError::LocalClientNotTrusted)?;
        if device.device_id.trim().is_empty()
            || claims.device_id.as_deref() != Some(device.device_id.as_str())
            || key_id != claims.key_id
        {
            return Err(LocalApiError::LocalClientNotTrusted);
        }
    }
    if let (Some(expected), Some(observed)) = (
        claims.organization_id.as_deref(),
        organization_id
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
    ) {
        if expected != observed {
            return Err(LocalApiError::InvalidRequest(
                "control token organization does not match request".to_string(),
            ));
        }
    }

    let installation = match action {
        TelemetryControlAction::EnableTelemetry | TelemetryControlAction::Status => {
            Some(detector(&source))
        }
        TelemetryControlAction::DisableTelemetry => None,
    };
    if matches!(action, TelemetryControlAction::EnableTelemetry)
        && installation
            .as_ref()
            .is_some_and(|detected| !detected.installed)
    {
        return Ok(ControlResult {
            requires_restart: false,
            key_id,
            action,
            source: source.clone(),
            status: ControlResultStatus::NeedsAttention,
            message: StableMessage {
                code: "agent_not_installed".to_string(),
                text: format!(
                    "Install {} first - we'll wait.",
                    source_display_name(&source)
                ),
            },
            config_preview: None,
            installation,
        });
    }

    match &action {
        TelemetryControlAction::EnableTelemetry => {
            let key_id = key_id
                .as_deref()
                .expect("enable key_id validated before backend call");
            let secret = ingest_key
                .as_ref()
                .expect("enable ingest_key validated before backend call");
            TelemetryKeyStore::production()
                .save(&source, key_id, secret.expose_secret())
                .map_err(|error| {
                    LocalApiError::LocalOperationFailed(format!(
                        "telemetry key storage failed: {error}"
                    ))
                })?;
            if let Err(error) = apply_telemetry_config(daemon, &source) {
                let _ = TelemetryKeyStore::production().delete(&source, key_id);
                return Err(error);
            }
            let otlp_endpoint = otlp_endpoint
                .as_deref()
                .expect("enable otlp_endpoint validated before backend call");
            if let Err(error) = emit_api_key_verification_marker(
                otlp_endpoint,
                secret.expose_secret(),
                &source,
                key_id,
                organization_id.as_deref(),
            ) {
                let _ = remove_telemetry_config(daemon, &source);
                return Err(error);
            }
        }
        TelemetryControlAction::DisableTelemetry => {
            remove_telemetry_config(daemon, &source)?;
            if let Some(key_id) = key_id.as_deref() {
                TelemetryKeyStore::production()
                    .delete(&source, key_id)
                    .map_err(|error| {
                        LocalApiError::LocalOperationFailed(format!(
                            "telemetry key removal failed: {error}"
                        ))
                    })?;
            }
        }
        TelemetryControlAction::Status => {}
    }

    if matches!(action, TelemetryControlAction::Status) && key_id.is_none() {
        key_id = TelemetryKeyStore::production()
            .latest_key_id(&source)
            .map_err(|error| {
                LocalApiError::LocalOperationFailed(format!("telemetry key lookup failed: {error}"))
            })?;
    }

    let requires_restart = matches!(action, TelemetryControlAction::EnableTelemetry)
        || (source == SourceKind::Codex
            && matches!(action, TelemetryControlAction::DisableTelemetry));
    Ok(ControlResult {
        requires_restart,
        key_id,
        action,
        source,
        status: ControlResultStatus::Accepted,
        message: StableMessage {
            code: "telemetry_control_accepted".to_string(),
            text: format!("Telemetry control request accepted by {OTTTO_SERVICE_BINARY_NAME}."),
        },
        config_preview: None,
        installation,
    })
}

fn auth_start(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<AuthStartResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    // A connected Mac whose setup run Ottto no longer accepts can only recover
    // through a fresh claim: Verify and `ottto doctor` tell the user to sign
    // in, so refusing here would dead-end them. The claim keeps the bound
    // user, and completing it for that user replaces the dead binding.
    let history_pending = local_history_recovery_expected()?
        || registration_history_choice_account(&status.account)
        || history_load::<StoredHistoryBrowserClaim>(history_stores().browser.as_ref())
            .is_ok_and(|claim| claim.is_some_and(|claim| claim.registration_pending))
        || history_account_store()
            .load()
            .is_ok_and(|account| registration_history_choice_account(&account));
    if status.account.state == LocalAccountState::Connected
        && status.account.user.is_some()
        && !history_pending
        && !daemon.connected_setup_run_needs_reconnect()?
    {
        return Err(LocalApiError::InvalidRequest(
            "This Mac is already connected. Run `ottto account` to view it, or `ottto logout` before pairing a different account."
                .to_string(),
        ));
    }
    // Idempotent re-trigger: while a claim is in flight and unexpired,
    // repeated Sign-in presses return the SAME claim instead of minting a
    // parallel one. Racing claims were one writer behind the observed
    // ClaimPending/ResetRequired status flip-flop (a completion for claim A
    // landing while claim B had already replaced the pending state).
    if let Some((pending, account)) = daemon.pending_auth_claim_snapshot()? {
        if matches!(
            account.state,
            LocalAccountState::ClaimPending | LocalAccountState::ReattachRequired
        ) && !auth_claim_is_expired(&pending.expires_at)
        {
            return Ok(AuthStartResponse {
                account,
                claim_code: pending.claim_code,
                claim_url: pending.claim_url,
                nonce: pending.nonce,
                expires_at: pending.expires_at,
            });
        }
    }
    if let Some(pending) =
        resume_history_browser_claim(&status.machine, &validated_api_base_url(None)?)?
    {
        let response = begin_durable_browser_claim(daemon, pending)?;
        crate::snapshot_sync::reset_relay_authorization_backoff();
        return Ok(response);
    }
    if !history_pending {
        discard_abandoned_unconfirmed_claim_credential()?;
    }
    let nonce = generate_control_token().or_state_poisoned()?;
    let claim = create_setup_claim(&status.machine, &nonce)?;
    let nonce = claim.client_nonce.unwrap_or(nonce);
    let claim_url = append_nonce_to_claim_url(&claim.claim_url, &nonce);
    let response = begin_durable_browser_claim(
        daemon,
        PendingAuthClaim {
            claim_code: claim.claim_code,
            claim_token: claim.claim_token,
            nonce,
            claim_url,
            expires_at: claim.expires_at,
        },
    )?;
    crate::snapshot_sync::reset_relay_authorization_backoff();
    Ok(response)
}

fn begin_durable_browser_claim(
    daemon: &LocalDaemon,
    pending: PendingAuthClaim,
) -> Result<AuthStartResponse, LocalApiError> {
    let _identity_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    let registration = history_account_store()
        .load()
        .is_ok_and(|account| registration_history_choice_account(&account));
    let response = daemon.begin_auth_with_claim(pending)?;
    let mut persisted = response.account.clone();
    if registration {
        persisted.message = Some(registration_history_choice_message());
    }
    history_account_store()
        .save(&persisted)
        .or_state_poisoned()?;
    Ok(response)
}

fn retire_refused_registration_after_browser_answer(claim_code: &str) -> Result<(), LocalApiError> {
    retire_refused_registration_after_browser_answer_with_stores(claim_code, &history_stores())
}

fn retire_refused_registration_after_browser_answer_with_stores(
    claim_code: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    let browser: Option<StoredHistoryBrowserClaim> = match history_load(stores.browser.as_ref()) {
        Ok(browser) => browser,
        Err(_) if !local_history_recovery_expected()? => return Ok(()),
        Err(error) => return Err(error),
    };
    if !browser.is_some_and(|browser| {
        browser.registration_pending && browser.claim.claim_code == claim_code
    }) {
        return Ok(());
    }
    let pending_store = FilePendingDeviceCredentialStore::default();
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(());
    };
    if pending.claim_commit.is_some() {
        return Ok(());
    }
    if pending.confirmed_at.is_some() {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    let secret_store = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    let candidate = secret_store.load().or_state_poisoned()?;
    match inspect_device_credential_preparation(&pending, &candidate) {
        Ok(status) if matches!(status.status.as_str(), "expired" | "superseded") => {
            discard_server_inactive_pending_device_credential(&pending_store, &secret_store)
        }
        Err(error) if backend_error_has_status(&error, 410) => {
            discard_server_inactive_pending_device_credential(&pending_store, &secret_store)
        }
        Err(error) => Err(error),
        Ok(_) => Err(LocalApiError::IdentityMutationInProgress),
    }
}

fn history_recovery_indicator_path() -> PathBuf {
    history_support_dir().join("local-history-recovery-required")
}

fn local_history_recovery_expected() -> Result<bool, LocalApiError> {
    // Presence only: no device selector, timestamp, receipt, or credential is
    // mirrored here. The actual marker/proof remain Keychain-only. This lets a
    // locked optional Keychain be distinguished from ordinary first sign-in,
    // without changing the account captured by an identity reservation.
    match fs::symlink_metadata(history_recovery_indicator_path()) {
        Ok(metadata) if metadata.is_file() => return Ok(true),
        Ok(_) => return Err(LocalApiError::StatePoisoned),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(LocalApiError::StatePoisoned),
    }
    history_account_store()
        .load()
        .map(|account| registration_history_choice_account(&account))
        .or_state_poisoned()
}

fn persist_local_release_expected() -> Result<(), LocalApiError> {
    ottto_core::write_owner_only_file_atomic(&history_recovery_indicator_path(), b"1")
        .or_state_poisoned()
}

fn clear_local_release_expected() -> Result<(), LocalApiError> {
    match fs::remove_file(history_recovery_indicator_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LocalApiError::StatePoisoned),
    }
}

fn registration_history_choice_account(account: &LocalAccountBinding) -> bool {
    account
        .message
        .as_ref()
        .is_some_and(|m| m.code == "history_choice_required")
}

fn registration_history_choice_required(error: &LocalApiError) -> bool {
    matches!(error, LocalApiError::Backend(details) if details.status == Some(400)
        && (details.reason_code.as_deref() == Some("history_choice_required") || auth_complete_error_is_pending(error)))
}

fn registration_history_choice_message() -> StableMessage {
    StableMessage {
        code: "history_choice_required".to_string(),
        text: "Waiting for browser sign-in to finish.".to_string(),
    }
}

fn persist_registration_history_choice() -> Result<(), LocalApiError> {
    let _lock = lock_setup_run_binding();
    let store = history_account_store();
    let mut account = store.load().or_state_poisoned()?;
    // Preserve the bound identity and all credential journals. This is a
    // durable user action, not an authority transition or a failed install.
    account.state = LocalAccountState::ReattachRequired;
    account.message = Some(registration_history_choice_message());
    account.can_reconnect = Some(true);
    store.save(&account).or_state_poisoned()
}

fn registration_history_choice_error(error: LocalApiError) -> LocalApiError {
    if registration_history_choice_required(&error) {
        if let Err(error) = persist_registration_history_choice() {
            return error;
        }
    }
    error
}

fn reoffer_registration_browser_claim(
    daemon: &LocalDaemon,
    machine: &MachineIdentity,
    base: &str,
) -> Result<AuthStartResponse, LocalApiError> {
    daemon.mark_history_choice_required()?;
    if let Some((claim, _)) = daemon.pending_auth_claim_snapshot()? {
        if !auth_claim_is_expired(&claim.expires_at) {
            return begin_durable_browser_claim(daemon, claim);
        }
    }
    if let Some(claim) = resume_history_browser_claim(machine, base)? {
        return begin_durable_browser_claim(daemon, claim);
    }
    let nonce = generate_control_token().or_state_poisoned()?;
    let claim = {
        let _lock = lock_history_recovery()?;
        create_setup_claim_with_history(
            &api_url_with_base(base, "/api/v1/setup-claims"),
            machine,
            &nonce,
            &history_stores(),
            history_now(),
        )?
    };
    let nonce = claim.client_nonce.unwrap_or(nonce);
    let pending = PendingAuthClaim {
        claim_code: claim.claim_code,
        claim_token: claim.claim_token,
        claim_url: append_nonce_to_claim_url(&claim.claim_url, &nonce),
        nonce,
        expires_at: claim.expires_at,
    };
    begin_durable_browser_claim(daemon, pending)
}

/// A fresh claim is the explicit cancellation boundary for an older completed
/// claim that was waiting for account-switch confirmation. The journal is not
/// active authority until confirmation is authorized, so invalidate it before
/// asking the backend to mint a different immutable preparation. The binding
/// lock plus the reservation check exclude a concurrently completing claim.
fn discard_abandoned_unconfirmed_claim_credential() -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    let pending_store = FilePendingDeviceCredentialStore::default();
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(());
    };
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.confirmed_at.is_some()
        || pending.confirmation_authorized
        || pending.preconfirm_guards_passed
        || pending.claim_commit.is_none()
    {
        return Err(LocalApiError::IdentityMutationInProgress);
    }
    clear_pending_device_credential(
        &pending_store,
        &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
    )
}

/// Whether a pending claim's `expires_at` is in the past (with a 30s safety
/// margin so a claim that is about to lapse mid-browser-open is not reused).
/// Unparseable timestamps count as expired so a fresh claim is minted.
fn auth_claim_is_expired(expires_at: &str) -> bool {
    use time::format_description::well_known::Rfc3339;
    let Ok(expires) = time::OffsetDateTime::parse(expires_at, &Rfc3339) else {
        return true;
    };
    expires - time::Duration::seconds(30) <= time::OffsetDateTime::now_utc()
}

fn auth_complete(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
    nonce: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    let pending = daemon.pending_auth_claim(claim_code, nonce)?;
    complete_pending_auth_claim(daemon, &status.machine, pending)
}

fn auth_complete_pending(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    let status = status_for(daemon, authorization)?;
    match daemon.pending_auth_claim_for_resume(claim_code) {
        Ok(pending) => complete_pending_auth_claim(daemon, &status.machine, pending),
        Err(LocalApiError::NoPendingAuthClaim) => daemon
            .completed_auth_claim_for_resume(claim_code)?
            .ok_or(LocalApiError::NoPendingAuthClaim),
        Err(error) => Err(error),
    }
}

fn complete_pending_auth_claim(
    daemon: &LocalDaemon,
    machine: &MachineIdentity,
    pending: PendingAuthClaim,
) -> Result<AuthCompleteResponse, LocalApiError> {
    // Claim completion can rotate/revoke backend device credentials. Reserve
    // identity mutation before that remote side effect, but release the
    // lifecycle mutex during network I/O. The RAII guard blocks concurrent
    // Codex cloud-task admission and clears on every return or panic.
    let identity_reservation = reserve_identity_mutation()?;
    let completion = match complete_setup_claim(&pending, machine, Some(&identity_reservation)) {
        Ok(completed) => completed,
        Err(error) => {
            log_auth_complete_backend_failure(&error);
            if let Some(reattach) = reattach_required_state(&error) {
                let _binding_lock = lock_setup_run_binding();
                daemon.mark_reattach_required(reattach.message.clone(), reattach.can_reconnect)?;
                let account = daemon.account_for_trusted_client()?;
                FileAccountStore::default()
                    .save(&account)
                    .or_state_poisoned()?;
            }
            return Err(error);
        }
    };
    let completed = completion.response;
    // Validate the relay-device payload up front so a malformed completion is
    // rejected before any staging or persistence.
    let relay_credentials = relay_device_credentials_from_claim_completion(
        &completed,
        completion.prior_device_credential.as_ref(),
    )?;
    retire_refused_registration_after_browser_answer(&pending.claim_code)?;
    let _ = finish_history_browser_claim(&pending.claim_code);
    let account = LocalAccountBinding {
        state: LocalAccountState::Connected,
        user: Some(LocalAccountUser {
            id: completed.user.id.clone(),
            email: completed.user.email.clone(),
            display_name: completed.user.display_name.clone(),
        }),
        organization: Some(LocalAccountOrganization {
            id: completed.organization.id.clone(),
            name: completed.organization.name.clone(),
        }),
        connected_at: Some(completed.connected_at.clone()),
        last_refreshed_at: Some(completed.connected_at.clone()),
        message: Some(StableMessage {
            code: "connected".to_string(),
            text: "This Mac is connected to Ottto.".to_string(),
        }),
        can_reconnect: None,
    };
    let prepared_pending = match &relay_credentials {
        ClaimRelayDeviceCredential::Prepared(prepared) => {
            let claim_commit = PendingClaimCredentialCommit {
                account: account.clone(),
                connection: LocalConnectionBinding {
                    setup_run_id: completed.setup_run_id.clone(),
                    setup_run_token_expires_at: completed.setup_run_token_expires_at.clone(),
                    machine_id: completed.machine_id.clone(),
                    claim_code: Some(pending.claim_code.clone()),
                    api_base_url: validated_api_base_url(None)?,
                },
                target_user_id: completed.user.id.clone(),
                setup_run_token_sha256: secret_sha256(&completed.setup_run_token),
                backfill_policy: completed.backfill_policy.clone(),
                backfill_cutoff_at: completed.backfill_cutoff_at.clone(),
            };
            let mut pending = pending_device_credential_from_preparation(
                &validated_api_base_url(None)?,
                prepared,
                false,
                Some(claim_commit),
                completion.request_authority.clone(),
            )?;
            {
                let _binding_lock = lock_setup_run_binding();
                identity_reservation.validate_locked()?;
                select_owner_snapshot_namespace(
                    &mut pending,
                    &prepared.candidate_secret,
                    completion.prior_device_credential.as_ref(),
                    &FileOwnerSnapshotNamespaceStore::default(),
                    &default_support_dir(),
                )?;
            }
            stage_pending_device_credential(&pending, &prepared.candidate_secret)?;
            stage_pending_setup_run_token(&pending, &completed.setup_run_token)?;
            let staged = FilePendingDeviceCredentialStore::default()
                .load()
                .or_state_poisoned()?
                .ok_or(LocalApiError::StatePoisoned)?;
            if staged.preparation_id != pending.preparation_id {
                return Err(LocalApiError::StatePoisoned);
            }
            Some(staged)
        }
        ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Legacy(_, _) => None,
    };
    // Claim-collision check BEFORE any persistence. Previously the new
    // setup-run token and relay-device credentials were written to the
    // keychain before the user-mismatch check fired, leaving a half-installed
    // credential set for the wrong user alongside the old account files. On a
    // mismatch the fully-completed claim is staged in memory and surfaced as a
    // switch candidate. A modern candidate may already be present in the
    // separate pending journal/Keychain account, but active account/device
    // authority remains unchanged until `auth_switch_account`.
    if let Some(candidate) = daemon.stage_account_switch_if_user_mismatch(StagedAccountSwitch {
        claim_code: pending.claim_code.clone(),
        new_account: account.clone(),
        setup_run_id: completed.setup_run_id.clone(),
        setup_run_token: completed.setup_run_token.clone(),
        setup_run_token_expires_at: completed.setup_run_token_expires_at.clone(),
        machine_id: completed.machine_id.clone(),
        relay_device: match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(device, _) => Some(device.clone()),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
        relay_device_secret: match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(_, secret) => Some(secret.clone()),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
        relay_device_credential_preparation_id: prepared_pending
            .as_ref()
            .map(|pending| pending.preparation_id.clone()),
        backfill_policy: completed.backfill_policy.clone(),
        backfill_cutoff_at: completed.backfill_cutoff_at.clone(),
    })? {
        return Err(LocalApiError::AccountSwitchCandidate {
            current_user_email: candidate.current_user_email,
            new_user_email: candidate.new_user_email,
            new_organization_name: candidate.new_organization_name,
            claim_code: candidate.claim_code,
        });
    }
    let prepared_pending = match prepared_pending {
        Some(pending) => Some(authorize_pending_device_credential_confirmation(
            &pending.preparation_id,
        )?),
        None => None,
    };
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let prepared_pending = match prepared_pending {
        Some(pending) => Some(mark_pending_device_credential_guards_passed(
            &pending,
            &FilePendingDeviceCredentialStore::default(),
        )?),
        None => None,
    };
    let confirmed_pending = match (&relay_credentials, prepared_pending.as_ref()) {
        (ClaimRelayDeviceCredential::Prepared(prepared), Some(pending)) => {
            if pending.confirmed_at.is_some() {
                Some(pending.clone())
            } else {
                let confirmed =
                    confirm_device_credential_preparation(pending, &prepared.candidate_secret)?;
                Some(mark_pending_device_credential_confirmed(
                    pending,
                    &confirmed.confirmed_at,
                    &FilePendingDeviceCredentialStore::default(),
                )?)
            }
        }
        (ClaimRelayDeviceCredential::Prepared(_), None) => {
            return Err(LocalApiError::StatePoisoned)
        }
        _ => None,
    };
    if let (ClaimRelayDeviceCredential::Prepared(prepared), Some(confirmed)) =
        (&relay_credentials, confirmed_pending.as_ref())
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        write_and_verify_pending_claim_commit(confirmed, &prepared.candidate_secret)?;
        let response = daemon.complete_auth_with_account(
            &pending.claim_code,
            &pending.nonce,
            account,
            completed.setup_run_id,
            completed.setup_run_token_expires_at,
            completed.machine_id,
        )?;
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        let _ = clear_prior_device_credential();
        request_snapshot_sync_after_device_registration(daemon);
        return Ok(response);
    }
    let _binding_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    // Persist the server-issued backfill policy BEFORE committing any of the
    // new binding (token, relay credentials, account/connection files): if
    // this write failed after the binding were already durable, the daemon
    // would come up connected without the cutoff and the next snapshot sync
    // would re-attribute the previous owner's pre-cutoff history to the new
    // account. A stray cutoff for a never-installed binding is harmless; a
    // binding without its cutoff is not.
    persist_claim_backfill_policy(
        completed.backfill_policy.as_deref(),
        completed.backfill_cutoff_at.as_deref(),
        &completed.user.id,
        match &relay_credentials {
            ClaimRelayDeviceCredential::Legacy(device, secret) => Some(
                crate::snapshot_sync::snapshot_destination_namespace(device, secret, None),
            ),
            ClaimRelayDeviceCredential::None | ClaimRelayDeviceCredential::Prepared(_) => None,
        },
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&completed.setup_run_token)
        .or_state_poisoned()?;
    let relay_credentials_persisted = match (&relay_credentials, confirmed_pending.as_ref()) {
        (ClaimRelayDeviceCredential::Legacy(device, secret), _) => {
            persist_relay_device_credentials_locked(device, secret, Some(&identity_reservation))?;
            true
        }
        (ClaimRelayDeviceCredential::Prepared(_), _) => return Err(LocalApiError::StatePoisoned),
        (ClaimRelayDeviceCredential::None, _) => false,
    };
    let response = daemon.complete_auth_with_account(
        &pending.claim_code,
        &pending.nonce,
        account.clone(),
        completed.setup_run_id.clone(),
        completed.setup_run_token_expires_at.clone(),
        completed.machine_id.clone(),
    )?;
    FileAccountStore::default()
        .save(&account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: completed.setup_run_id,
            setup_run_token_expires_at: completed.setup_run_token_expires_at,
            machine_id: completed.machine_id,
            claim_code: Some(pending.claim_code),
            api_base_url: validated_api_base_url(None)?,
        })
        .or_state_poisoned()?;
    if relay_credentials_persisted {
        let _ = clear_prior_device_credential();
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(response)
}

/// Persist the additive claim-completion backfill policy into the snapshot
/// backfill state (`snapshot_backfill_state.json`). An unwritable state file is
/// a poisoned-state error for `"from"` decisions — proceeding without the
/// cutoff would double-count the previous owner's history at org level.
fn persist_claim_backfill_policy(
    policy: Option<&str>,
    cutoff_at: Option<&str>,
    user_id: &str,
    namespace: Option<String>,
) -> Result<(), LocalApiError> {
    let support_dir = default_support_dir();
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &support_dir,
        policy,
        cutoff_at,
        user_id,
        namespace.as_deref(),
    )
    .map_err(|error| {
        eprintln!("ottto-service: persisting claim backfill policy failed: {error}");
        LocalApiError::StatePoisoned
    })
}

/// Confirmed account switch (`auth_switch_account`): consume the staged claim
/// completion for `claim_code`, best-effort disconnect the OLD cloud binding
/// (tolerating auth failures and an already-deleted account), clear the old
/// local artifacts, and install the new binding in one in-memory state
/// transition. Status readers never observe an intermediate
/// `ResetRequired`→`NotConnected` hop — the binding goes straight to the new
/// `Connected` account.
fn auth_switch_account(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    claim_code: &str,
) -> Result<AuthCompleteResponse, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    daemon.require_staged_account_switch(claim_code)?;
    let staged_snapshot = daemon.staged_account_switch_snapshot(claim_code)?;
    if let Some(preparation_id) = staged_snapshot
        .relay_device_credential_preparation_id
        .as_deref()
    {
        // This bit is only the user's durable approval. The reservation is
        // revalidated immediately before every confirm, including startup
        // recovery after a crash at the next instruction.
        authorize_pending_device_credential_confirmation(preparation_id)?;
    }
    // Reserve before `take_staged_account_switch`, which mutates the
    // in-memory switch state.
    let identity_reservation = reserve_identity_mutation()?;
    let staged = daemon.take_staged_account_switch(claim_code)?;
    if staged.relay_device_credential_preparation_id.is_none() {
        disconnect_previous_binding_best_effort(
            daemon,
            staged
                .relay_device
                .as_ref()
                .map(|device| device.device_id.as_str()),
        );
    }
    match install_staged_account_switch(daemon, &staged, &identity_reservation) {
        Ok(response) => Ok(response),
        Err(error) => {
            // Keep the staged completion so the user can retry the confirm
            // (e.g. after a transient keychain/file failure) without redoing
            // the whole browser claim.
            let _ = daemon.restore_staged_account_switch(staged);
            Err(error)
        }
    }
}

/// Best-effort cloud disconnect of the binding being replaced. Failures are
/// tolerated by design: the old account may already be deleted server-side
/// (401/404), the token may be unrefreshable, or the network may be down. The
/// switch proceeds either way; the backend reconciles a dangling setup run on
/// its side.
///
/// The request also asks the server to release the previous device
/// registration, unless the incoming binding reuses the same device id: a
/// release must never revoke the credential the switch is about to install.
fn disconnect_previous_binding_best_effort(daemon: &LocalDaemon, incoming_device_id: Option<&str>) {
    let connection = match daemon.connection_for_authorized_client() {
        Ok(Some(connection)) => connection,
        Ok(None) | Err(_) => return,
    };
    let Ok(setup_run_token) = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load() else {
        return;
    };
    let Ok(api_base_url) = validated_api_base_url(Some(connection.api_base_url.as_str())) else {
        return;
    };
    let release =
        load_device_release_proof().filter(|proof| releasable_on_switch(proof, incoming_device_id));
    if let Err(error) = disconnect_setup_run_with_refresh(
        &api_base_url,
        &connection,
        &setup_run_token,
        release.as_ref(),
    ) {
        eprintln!(
            "ottto-service: account switch: cloud disconnect of previous binding skipped: {error}"
        );
    }
}

fn releasable_on_switch(proof: &DeviceReleaseProof, incoming_device_id: Option<&str>) -> bool {
    incoming_device_id.map_or(true, |incoming| incoming != proof.device_id)
}

fn install_staged_account_switch(
    daemon: &LocalDaemon,
    staged: &StagedAccountSwitch,
    identity_reservation: &IdentityMutationReservation,
) -> Result<AuthCompleteResponse, LocalApiError> {
    {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let modern_credential = if let Some(preparation_id) =
        staged.relay_device_credential_preparation_id.as_deref()
    {
        if staged.relay_device.is_some() || staged.relay_device_secret.is_some() {
            return Err(LocalApiError::StatePoisoned);
        }
        let pending_store = FilePendingDeviceCredentialStore::default();
        let pending = pending_store
            .load()
            .or_state_poisoned()?
            .ok_or(LocalApiError::StatePoisoned)?;
        if pending.preparation_id != preparation_id {
            return Err(LocalApiError::StatePoisoned);
        }
        let pending = authorize_pending_device_credential_confirmation(&pending.preparation_id)?;
        let pending = mark_pending_device_credential_guards_passed(&pending, &pending_store)?;
        let candidate_secret = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .or_state_poisoned()?;
        let confirmed_pending = if pending.confirmed_at.is_some() {
            pending
        } else {
            let confirmed = confirm_device_credential_preparation(&pending, &candidate_secret)?;
            mark_pending_device_credential_confirmed(
                &pending,
                &confirmed.confirmed_at,
                &pending_store,
            )?
        };
        // Only now may the old local/cloud binding be disconnected: every
        // earlier failure cut retained usable old authority.
        disconnect_previous_binding_best_effort(
            daemon,
            Some(confirmed_pending.device.device_id.as_str()),
        );
        Some((confirmed_pending, candidate_secret))
    } else {
        None
    };
    if let Some((pending, candidate_secret)) = modern_credential.as_ref() {
        let _binding_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        let claim = pending
            .claim_commit
            .as_ref()
            .ok_or(LocalApiError::StatePoisoned)?;
        if claim.account != staged.new_account
            || claim.connection.setup_run_id != staged.setup_run_id
            || claim.connection.setup_run_token_expires_at != staged.setup_run_token_expires_at
            || claim.connection.machine_id != staged.machine_id
            || claim.connection.claim_code.as_deref() != Some(staged.claim_code.as_str())
            || claim.backfill_policy != staged.backfill_policy
            || claim.backfill_cutoff_at != staged.backfill_cutoff_at
        {
            return Err(LocalApiError::StatePoisoned);
        }
        write_and_verify_pending_claim_commit(pending, candidate_secret)?;
        let response = daemon.install_switched_account(
            staged.new_account.clone(),
            staged.setup_run_id.clone(),
            staged.setup_run_token_expires_at.clone(),
            staged.machine_id.clone(),
            &staged.claim_code,
        )?;
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        request_snapshot_sync_after_device_registration(daemon);
        return Ok(response);
    }
    let _binding_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    reset_local_account_files_locked(Some(identity_reservation))?;
    let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
    let _ = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).delete();
    // Persist the server-issued backfill policy BEFORE committing the new
    // binding (see auth claim completion for the failure-ordering rationale):
    // a same-org takeover must not re-attribute the previous owner's
    // already-ingested history to the new account.
    persist_claim_backfill_policy(
        staged.backfill_policy.as_deref(),
        staged.backfill_cutoff_at.as_deref(),
        staged
            .new_account
            .user
            .as_ref()
            .map(|user| user.id.as_str())
            .unwrap_or_default(),
        staged
            .relay_device
            .as_ref()
            .zip(staged.relay_device_secret.as_deref())
            .map(|(device, secret)| {
                crate::snapshot_sync::snapshot_destination_namespace(device, secret, None)
            }),
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&staged.setup_run_token)
        .or_state_poisoned()?;
    let relay_credentials_persisted = match (
        &staged.relay_device,
        &staged.relay_device_secret,
        modern_credential.as_ref(),
    ) {
        (Some(device), Some(secret), None) => {
            persist_relay_device_credentials_locked(device, secret, Some(identity_reservation))?;
            true
        }
        (None, None, Some(_)) => return Err(LocalApiError::StatePoisoned),
        (None, None, None) => false,
        _ => return Err(LocalApiError::StatePoisoned),
    };
    let response = daemon.install_switched_account(
        staged.new_account.clone(),
        staged.setup_run_id.clone(),
        staged.setup_run_token_expires_at.clone(),
        staged.machine_id.clone(),
        &staged.claim_code,
    )?;
    FileAccountStore::default()
        .save(&staged.new_account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&LocalConnectionBinding {
            setup_run_id: staged.setup_run_id.clone(),
            setup_run_token_expires_at: staged.setup_run_token_expires_at.clone(),
            machine_id: staged.machine_id.clone(),
            claim_code: Some(staged.claim_code.clone()),
            api_base_url: validated_api_base_url(None)?,
        })
        .or_state_poisoned()?;
    if relay_credentials_persisted {
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(response)
}

/// Whether a terminal backend auth failure indicates the bound account (or its
/// setup run/device row) no longer exists server-side — as opposed to an
/// expired/invalid token, which is recoverable via refresh. Used to transition
/// the binding to the unbound-equivalent `account_not_found` state so the next
/// sign-in by ANY user proceeds as a fresh first claim.
pub(crate) fn backend_error_indicates_account_gone(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status == Some(404)
        && (details.endpoint.contains("/setup-runs/")
            || details.endpoint.contains("/local-client/"))
    {
        return true;
    }
    if !matches!(details.status, Some(401) | Some(403)) {
        return false;
    }
    let Some(body) = details.body_excerpt.as_deref() else {
        return false;
    };
    let body = body.to_ascii_lowercase();
    body.contains("account_not_found")
        || body.contains("user_not_found")
        || body.contains("workspace_not_found")
        || body.contains("account no longer exists")
        || body.contains("user no longer exists")
        || body.contains("workspace no longer exists")
}

fn log_auth_complete_backend_failure(error: &LocalApiError) {
    if auth_complete_error_is_pending(error) {
        return;
    }
    match error {
        LocalApiError::Backend(details) => {
            let status = details
                .status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string());
            let body = details
                .body_excerpt
                .as_deref()
                .unwrap_or("backend returned no response body");
            eprintln!(
                "ottto-service: auth_complete backend request failed endpoint={} status={} kind={:?} body_excerpt={}",
                auth_complete_log_endpoint(&details.endpoint),
                status,
                details.kind,
                body,
            );
        }
        LocalApiError::TimedOut(detail) => {
            eprintln!(
                "ottto-service: auth_complete backend request timed out endpoint=/api/v1/setup-claims/[claim]/local-client/complete detail={}",
                redact_inline(detail),
            );
        }
        _ => {}
    }
}

/// Browser approval and local claim completion are separate steps. The backend
/// returns this bounded 400 while the owner is still looking at the claim page;
/// it is an expected polling result, not a rejected pairing attempt.
fn auth_complete_error_is_pending(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if details.status != Some(400) {
        return false;
    }
    details.body_excerpt.as_deref().is_some_and(|body| {
        body.to_ascii_lowercase()
            .contains("setup claim session is pending")
    })
}

fn auth_complete_log_endpoint(endpoint: &str) -> String {
    let marker = "/api/v1/setup-claims/";
    let Some(start) = endpoint.find(marker) else {
        return endpoint.to_string();
    };
    let prefix_end = start + marker.len();
    let Some(suffix_start) = endpoint[prefix_end..].find("/local-client/complete") else {
        return endpoint.to_string();
    };
    let suffix_index = prefix_end + suffix_start;
    format!(
        "{}[claim]{}",
        &endpoint[..prefix_end],
        &endpoint[suffix_index..]
    )
}

enum ClaimRelayDeviceCredential {
    None,
    Legacy(LocalDeviceBinding, String),
    Prepared(DeviceCredentialPreparationApiResponse),
}

/// Validate and materialize the relay-device credential transition from a
/// claim completion without persisting anything. Modern and legacy forms are
/// mutually exclusive so a malformed response cannot silently downgrade after
/// the server has created a preparation.
fn relay_device_credentials_from_claim_completion(
    completed: &SetupClaimCompleteResponse,
    prior: Option<&PriorDeviceCredential>,
) -> Result<ClaimRelayDeviceCredential, LocalApiError> {
    if let Some(prepared) = &completed.relay_device_credential_preparation {
        if completed.relay_device.is_some() || completed.relay_device_secret.is_some() {
            return Err(claim_completion_response_unexpected(
                "claim completion mixed prepared and active relay-device credentials",
            ));
        }
        validate_device_credential_preparation(
            "/api/v1/setup-claims/[claim]/local-client/complete",
            prepared,
            prior,
        )?;
        return Ok(ClaimRelayDeviceCredential::Prepared(prepared.clone()));
    }
    match (&completed.relay_device, &completed.relay_device_secret) {
        (None, None) => Ok(ClaimRelayDeviceCredential::None),
        (Some(device), Some(device_secret)) => {
            if device.sources.is_empty() || device_secret.trim().is_empty() {
                return Err(claim_completion_response_unexpected(
                    "claim completion returned incomplete relay-device credentials",
                ));
            }
            Ok(ClaimRelayDeviceCredential::Legacy(
                LocalDeviceBinding {
                    device_id: device.id.clone(),
                    machine_id: device
                        .machine_id
                        .clone()
                        .or_else(|| completed.machine_id.clone()),
                    sources: device.sources.clone(),
                },
                device_secret.clone(),
            ))
        }
        _ => Err(claim_completion_response_unexpected(
            "claim completion returned partial relay-device credentials",
        )),
    }
}

#[cfg(test)]
fn persist_relay_device_credentials(
    device: &LocalDeviceBinding,
    device_secret: &str,
) -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    persist_relay_device_credentials_locked(device, device_secret, None)
}

fn persist_relay_device_credentials_locked(
    device: &LocalDeviceBinding,
    device_secret: &str,
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    let device_store = FileDeviceStore::default();
    let current_device = device_store.load().or_state_poisoned()?;

    let secret_store = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT);
    let current_secret = match current_device {
        Some(_) => match secret_store.load() {
            Ok(secret) => Some(secret),
            Err(TokenStoreError::Missing) => None,
            Err(_) => return Err(LocalApiError::StatePoisoned),
        },
        // With no active device binding, a stray old secret is not usable
        // authority and does not need to be read for rollback. This also lets
        // first registration use the owner-only fallback when Keychain reads
        // are transiently unavailable.
        None => None,
    };
    secret_store.save(device_secret).or_state_poisoned()?;
    if device_store.save(device).is_ok() {
        return Ok(());
    }

    // The device binding is an atomic file replace, but the credential spans
    // that file and Keychain. Restore the exact prior secret on any file-side
    // failure so callers never observe a durably half-rotated pair.
    let rollback = match current_secret {
        Some(secret) => secret_store.save(&secret),
        None => secret_store.delete(),
    };
    if rollback.is_err() {
        return Err(LocalApiError::StatePoisoned);
    }
    Err(LocalApiError::StatePoisoned)
}

fn pending_device_credential_from_preparation(
    api_base_url: &str,
    prepared: &DeviceCredentialPreparationApiResponse,
    confirmation_authorized: bool,
    claim_commit: Option<PendingClaimCredentialCommit>,
    request_authority: PendingDeviceCredentialRequestAuthority,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    Ok(PendingDeviceCredentialPreparation {
        schema_version: PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION,
        capability: prepared.capability.clone(),
        preparation_id: prepared.preparation_id.clone(),
        api_base_url: validated_api_base_url(Some(api_base_url))?,
        expires_at: prepared.expires_at.clone(),
        credential_generation: prepared.credential_generation,
        secret_commitment_sha256: secret_sha256(&prepared.candidate_secret),
        request_authority: Some(request_authority),
        device: LocalDeviceBinding {
            device_id: prepared.device.id.clone(),
            machine_id: prepared.device.machine_id.clone(),
            sources: prepared.device.sources.clone(),
        },
        confirmation_authorized,
        preconfirm_guards_passed: false,
        claim_commit,
        confirmed_at: None,
    })
}

fn authorize_pending_device_credential_confirmation(
    preparation_id: &str,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    let store = FilePendingDeviceCredentialStore::default();
    let mut pending = store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if pending.preparation_id != preparation_id {
        return Err(LocalApiError::StatePoisoned);
    }
    if pending.confirmation_authorized {
        return Ok(pending);
    }
    pending.confirmation_authorized = true;
    store.save(&pending).or_state_poisoned()?;
    if store.load().or_state_poisoned()?.as_ref() != Some(&pending) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(pending)
}

fn mark_pending_device_credential_guards_passed(
    pending: &PendingDeviceCredentialPreparation,
    pending_store: &FilePendingDeviceCredentialStore,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    if pending.confirmed_at.is_some() {
        return if pending.confirmation_authorized && pending.preconfirm_guards_passed {
            Ok(pending.clone())
        } else {
            Err(LocalApiError::StatePoisoned)
        };
    }
    if !pending.confirmation_authorized {
        return Err(LocalApiError::StatePoisoned);
    }
    let current = pending_store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if current != *pending {
        return Err(LocalApiError::StatePoisoned);
    }
    let mut guarded = pending.clone();
    guarded.preconfirm_guards_passed = true;
    pending_store.save(&guarded).or_state_poisoned()?;
    if pending_store.load().or_state_poisoned()?.as_ref() != Some(&guarded) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(guarded)
}

fn stage_pending_device_credential(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    stage_pending_device_credential_with_stores(
        pending,
        candidate_secret,
        &FilePendingDeviceCredentialStore::default(),
        &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
    )
}

fn stage_pending_device_credential_with_stores(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.preparation_id.trim().is_empty()
        || pending.credential_generation == 0
        || validate_pending_candidate_secret(pending, candidate_secret).is_err()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    validate_owner_snapshot_selection(
        pending,
        candidate_secret,
        &FileOwnerSnapshotNamespaceStore::default(),
    )?;
    let existing = pending_store.load().or_state_poisoned()?;
    let effective_pending = if let Some(current) = existing.as_ref() {
        // An idempotent server retry must reproduce the entire immutable
        // preparation and candidate. Never replace a same-ID candidate or
        // mutate its account commit merely because the identifier matches.
        let mut immutable = current.clone();
        immutable.confirmation_authorized = pending.confirmation_authorized;
        immutable.preconfirm_guards_passed = pending.preconfirm_guards_passed;
        immutable.confirmed_at = pending.confirmed_at.clone();
        if immutable != *pending {
            return Err(LocalApiError::IdentityMutationInProgress);
        }
        match pending_secret_store.load() {
            Ok(stored) if stored == candidate_secret => return Ok(()),
            Ok(_) => return Err(LocalApiError::StatePoisoned),
            Err(TokenStoreError::Missing) => {}
            Err(_) => return Err(LocalApiError::StatePoisoned),
        }
        current
    } else {
        pending
    };

    pending_secret_store
        .save(candidate_secret)
        .or_state_poisoned()?;
    if pending_store.save(effective_pending).is_err() {
        // A newly written orphan candidate is not active authority. Remove it
        // when possible; if deletion itself fails, the active credential and
        // device binding are still unchanged and usable.
        if existing.is_none() {
            let _ = pending_secret_store.delete();
        }
        return Err(LocalApiError::StatePoisoned);
    }
    let stored_secret = pending_secret_store.load().or_state_poisoned()?;
    let stored_pending = pending_store.load().or_state_poisoned()?;
    if stored_secret != candidate_secret || stored_pending.as_ref() != Some(effective_pending) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn stage_pending_setup_run_token(
    pending: &PendingDeviceCredentialPreparation,
    setup_run_token: &str,
) -> Result<(), LocalApiError> {
    let store = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT);
    stage_pending_setup_run_token_with_store(pending, setup_run_token, &store)
}

fn stage_pending_setup_run_token_with_store<S: ControlTokenStore + ?Sized>(
    pending: &PendingDeviceCredentialPreparation,
    setup_run_token: &str,
    store: &S,
) -> Result<(), LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    if setup_run_token.trim().is_empty()
        || claim.setup_run_token_sha256 != secret_sha256(setup_run_token)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    match store.load() {
        Ok(current) if current == setup_run_token => return Ok(()),
        // A different value cannot belong to this hash-bound journal. It is
        // an inert orphan from a cut before the journal write and is safe to
        // replace with the exact server-reproduced token.
        // The same recovery is safe when the old value cannot be read (for
        // example, while macOS is re-resolving a replaced login Keychain):
        // the exact journal-bound value is written and then read back before
        // this function succeeds.
        Ok(_) | Err(_) => {}
    }
    store.save(setup_run_token).or_state_poisoned()?;
    if store.load().or_state_poisoned()? != setup_run_token {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

pub(crate) fn secret_sha256(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

pub(crate) fn secret_commitment_matches(commitment: &str, secret: &str) -> bool {
    constant_work_eq(commitment.as_bytes(), secret_sha256(secret).as_bytes())
}

fn constant_work_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_pending_candidate_secret(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    if candidate_secret.trim().is_empty()
        || !valid_secret_commitment(&pending.secret_commitment_sha256)
        || !secret_commitment_matches(&pending.secret_commitment_sha256, candidate_secret)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn valid_secret_commitment(commitment: &str) -> bool {
    commitment.len() == 71
        && commitment.starts_with("sha256:")
        && commitment[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_pending_prior_credential_binding(
    pending: &PendingDeviceCredentialPreparation,
) -> Result<(), LocalApiError> {
    let Some(authority) = pending.request_authority.as_ref() else {
        // Additive compatibility for a v2 journal created by an older binary.
        return if pending.schema_version == OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION {
            Err(LocalApiError::StatePoisoned)
        } else {
            Ok(())
        };
    };
    if !matches!(authority.flow.as_str(), "register" | "setup_claim")
        || !valid_secret_commitment(&authority.credential_preparation_idempotency_key)
        || authority.machine_id.trim().is_empty()
        || authority.installation_id.trim().is_empty()
        || authority
            .identity_continuity_capability
            .as_deref()
            .is_some_and(|value| value != IDENTITY_CONTINUITY_CAPABILITY)
        || authority
            .canonical_snapshot_namespace
            .as_deref()
            .is_some_and(|namespace| {
                authority.flow != "setup_claim"
                    || (pending.schema_version == PENDING_DEVICE_CREDENTIAL_SCHEMA_VERSION
                        && authority.prior_device_id.is_none())
                    || !crate::hex::is_sha256_lower(namespace)
            })
    {
        return Err(LocalApiError::StatePoisoned);
    }
    if authority.incoming_snapshot_namespace.is_some()
        && (pending.schema_version != OWNER_RETURN_CREDENTIAL_SCHEMA_VERSION
            || authority.flow != "setup_claim")
    {
        return Err(LocalApiError::StatePoisoned);
    }
    match (
        authority.prior_device_id.as_deref(),
        authority.prior_device_sources.as_deref(),
        authority.prior_secret_commitment_sha256.as_deref(),
    ) {
        (None, None, None) => Ok(()),
        (Some(device_id), Some(sources), Some(commitment))
            if !device_id.trim().is_empty()
                && !sources.is_empty()
                && authority.identity_continuity_capability.as_deref()
                    == Some(IDENTITY_CONTINUITY_CAPABILITY)
                && valid_secret_commitment(commitment) =>
        {
            Ok(())
        }
        _ => Err(LocalApiError::StatePoisoned),
    }
}

fn mark_pending_device_credential_confirmed(
    pending: &PendingDeviceCredentialPreparation,
    confirmed_at: &str,
    pending_store: &FilePendingDeviceCredentialStore,
) -> Result<PendingDeviceCredentialPreparation, LocalApiError> {
    if !pending.confirmation_authorized || !pending.preconfirm_guards_passed {
        return Err(LocalApiError::StatePoisoned);
    }
    let current = pending_store
        .load()
        .or_state_poisoned()?
        .ok_or(LocalApiError::StatePoisoned)?;
    if current != *pending {
        return Err(LocalApiError::StatePoisoned);
    }
    let mut confirmed = pending.clone();
    confirmed.confirmed_at = Some(confirmed_at.to_string());
    pending_store.save(&confirmed).or_state_poisoned()?;
    if pending_store.load().or_state_poisoned()?.as_ref() != Some(&confirmed) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(confirmed)
}

fn write_and_verify_active_device_credential(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let expected_binding = LocalDeviceCredentialBinding {
        device: pending.device.clone(),
        credential_generation: pending.credential_generation,
        continuity: DeviceCredentialContinuity {
            owner: pending_credential_owner(pending),
            snapshot_namespace: pending_snapshot_alias(pending),
        },
    };

    active_secret_store
        .save(candidate_secret)
        .or_state_poisoned()?;
    device_store
        .save_with_credential_generation(&expected_binding)
        .or_state_poisoned()?;

    let active_secret = active_secret_store.load().or_state_poisoned()?;
    let active_binding = device_store
        .load_with_credential_generation()
        .or_state_poisoned()?;
    if active_secret != candidate_secret || active_binding.as_ref() != Some(&expected_binding) {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

/// The journaled same-account namespace, bound to the staged candidate secret.
fn pending_snapshot_alias(
    pending: &PendingDeviceCredentialPreparation,
) -> Option<SnapshotNamespaceAlias> {
    let namespace = pending
        .request_authority
        .as_ref()?
        .canonical_snapshot_namespace
        .clone()?;
    Some(SnapshotNamespaceAlias {
        namespace,
        secret_commitment_sha256: pending.secret_commitment_sha256.clone(),
    })
}

fn clear_pending_device_credential(
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    pending_store.reset().or_state_poisoned()?;
    let _ = pending_secret_store.delete();
    let _ = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT).delete();
    Ok(())
}

pub(crate) fn promote_pending_device_credential_with_stores(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
    device_store: &FileDeviceStore,
    active_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    // A failed marker write keeps the candidate staged, so recovery retries both.
    if let Ok(Some(current)) = device_store.load() {
        crate::snapshot_sync::disable_sources_dropped_from_grant(
            &default_support_dir(),
            &current,
            &pending.device,
        )
        .or_state_poisoned()?;
    }
    // After server confirmation the old active secret may already be invalid.
    // Never roll it back on a file-side failure: keep the separately staged
    // candidate intact so restart recovery can finish the same generation.
    write_and_verify_active_device_credential(
        pending,
        candidate_secret,
        device_store,
        active_secret_store,
    )?;

    // Delete metadata first. A crash between these operations leaves only an
    // inert orphan Keychain entry while the verified active pair keeps working.
    clear_pending_device_credential(pending_store, pending_secret_store)
}

fn backend_error_has_status(error: &LocalApiError, status: u16) -> bool {
    matches!(error, LocalApiError::Backend(details) if details.status == Some(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrunedDeviceCredentialProbe {
    Confirmed,
    Inactive,
}

fn pending_device_credential_is_past_expiry(pending: &PendingDeviceCredentialPreparation) -> bool {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(&pending.expires_at, &Rfc3339)
        .is_ok_and(|expires_at| expires_at <= time::OffsetDateTime::now_utc())
}

fn relay_auth_local_error(url: &str, status: u16) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::Rejected,
        endpoint: safe_backend_endpoint(url),
        status: Some(status),
        body_excerpt: None,
        reason_code: None,
    })
}

fn probe_pruned_device_credential_authority(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<PrunedDeviceCredentialProbe, LocalApiError> {
    validate_pending_candidate_secret(pending, candidate_secret)?;
    let api_base_url = validated_api_base_url(Some(&pending.api_base_url))?;
    let url = api_url_with_base(
        &api_base_url,
        &format!(
            "/api/v1/telemetry/devices/{}/relay-token",
            pending.device.device_id
        ),
    );
    let source = pending
        .device
        .sources
        .first()
        .ok_or(LocalApiError::StatePoisoned)?;
    let body = relay_token_request_payload(&pending.device, source);
    let mut probe =
        crate::relay_auth::Probe::begin(&api_base_url, &pending.device, candidate_secret, source)
            .map_err(|held| relay_auth_local_error(&url, held.status))?;
    match backend_post_json::<serde_json::Value>(
        &url,
        &body,
        &[("X-Ottto-Device-Secret", candidate_secret)],
    ) {
        Ok(_) => {
            probe.success();
            Ok(PrunedDeviceCredentialProbe::Confirmed)
        }
        Err(error)
            if matches!(
                &error,
                LocalApiError::Backend(details) if details.status == Some(401)
            ) && pending_device_credential_is_past_expiry(pending) =>
        {
            probe.reject(401);
            Ok(PrunedDeviceCredentialProbe::Inactive)
        }
        Err(error) => {
            if let LocalApiError::Backend(details) = &error {
                if let Some(status @ (401 | 403)) = details.status {
                    probe.reject(status);
                }
            }
            Err(error)
        }
    }
}

fn discard_server_inactive_pending_device_credential(
    pending_store: &FilePendingDeviceCredentialStore,
    pending_secret_store: &impl ControlTokenStore,
) -> Result<(), LocalApiError> {
    clear_pending_device_credential(pending_store, pending_secret_store)
}

fn write_and_verify_pending_claim_commit(
    pending: &PendingDeviceCredentialPreparation,
    candidate_secret: &str,
) -> Result<(), LocalApiError> {
    let claim = pending
        .claim_commit
        .as_ref()
        .ok_or(LocalApiError::StatePoisoned)?;
    if pending.confirmed_at.is_none()
        || !pending.confirmation_authorized
        || !pending.preconfirm_guards_passed
        || claim.target_user_id.trim().is_empty()
        || claim.connection.setup_run_id.trim().is_empty()
        || claim
            .connection
            .claim_code
            .as_deref()
            .map_or(true, str::is_empty)
        || claim
            .account
            .user
            .as_ref()
            .map_or(true, |user| user.id != claim.target_user_id)
        || validated_api_base_url(Some(&claim.connection.api_base_url))?
            != claim.connection.api_base_url
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let pending_setup_token_store = KeychainSecretStore::new(OTTTO_PENDING_SETUP_RUN_TOKEN_ACCOUNT);
    let setup_run_token = pending_setup_token_store.load().or_state_poisoned()?;
    if claim.setup_run_token_sha256 != secret_sha256(&setup_run_token) {
        return Err(LocalApiError::StatePoisoned);
    }

    validate_owner_snapshot_selection(
        pending,
        candidate_secret,
        &FileOwnerSnapshotNamespaceStore::default(),
    )?;
    // The attribution boundary must become durable before any credential or
    // account binding from the new claim. This operation is idempotent.
    persist_claim_backfill_policy(
        claim.backfill_policy.as_deref(),
        claim.backfill_cutoff_at.as_deref(),
        &claim.target_user_id,
        Some(crate::snapshot_sync::snapshot_destination_namespace(
            &pending.device,
            candidate_secret,
            pending_snapshot_alias(pending).as_ref(),
        )),
    )?;
    write_and_verify_active_device_credential(
        pending,
        candidate_secret,
        &FileDeviceStore::default(),
        &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
    )?;
    KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .save(&setup_run_token)
        .or_state_poisoned()?;
    FileAccountStore::default()
        .save(&claim.account)
        .or_state_poisoned()?;
    FileConnectionStore::default()
        .save(&claim.connection)
        .or_state_poisoned()?;

    let active_setup_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .or_state_poisoned()?;
    let active_account = FileAccountStore::default().load().or_state_poisoned()?;
    let active_connection = FileConnectionStore::default().load().or_state_poisoned()?;
    if active_setup_token != setup_run_token
        || active_account != claim.account
        || active_connection.as_ref() != Some(&claim.connection)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    publish_owner_snapshot_history(pending, &FileOwnerSnapshotNamespaceStore::default())?;
    Ok(())
}

/// Resume an exact prepared generation before relays start. Local wall-clock
/// expiry never deletes a pending candidate: only a definitive server 410 can
/// prove an unconfirmed preparation is safe to discard.
pub fn recover_pending_device_credential_at_startup() -> Result<bool, LocalApiError> {
    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending_secret_store = KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT);
    let Some(pending) = pending_store.load().or_state_poisoned()? else {
        return Ok(false);
    };
    if !supported_pending_credential_schema(pending.schema_version)
        || pending.capability != DEVICE_CREDENTIAL_PREPARATION_CAPABILITY
        || pending.preparation_id.trim().is_empty()
        || pending.credential_generation == 0
        || validate_pending_prior_credential_binding(&pending).is_err()
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let candidate_secret = pending_secret_store.load().or_state_poisoned()?;
    validate_pending_candidate_secret(&pending, &candidate_secret)?;
    if pending.confirmed_at.is_none() && !pending.confirmation_authorized {
        return match inspect_device_credential_preparation(&pending, &candidate_secret) {
            Ok(status) if status.status == "pending" => Ok(false),
            Ok(status) if matches!(status.status.as_str(), "expired" | "superseded") => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                Ok(false)
            }
            // A server-confirmed switch that was never locally authorized is
            // an invariant violation. Retain both halves for operator recovery;
            // never silently install or discard it.
            Ok(_) => Err(LocalApiError::StatePoisoned),
            Err(error) if backend_error_has_status(&error, 410) => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                Ok(false)
            }
            Err(error) if backend_error_has_status(&error, 404) => {
                match probe_pruned_device_credential_authority(&pending, &candidate_secret)? {
                    PrunedDeviceCredentialProbe::Confirmed => Err(LocalApiError::StatePoisoned),
                    PrunedDeviceCredentialProbe::Inactive => {
                        discard_server_inactive_pending_device_credential(
                            &pending_store,
                            &pending_secret_store,
                        )?;
                        Ok(false)
                    }
                }
            }
            Err(error) => Err(error),
        };
    }
    if pending.confirmed_at.is_some()
        && (!pending.confirmation_authorized || !pending.preconfirm_guards_passed)
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let identity_reservation = reserve_identity_mutation()?;
    // A persisted guard bit records the prior process's cut, but it is never
    // authority to confirm. Revalidate a fresh reservation at the last
    // possible point before confirm/promotion.
    let pending = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        if pending.confirmed_at.is_none() {
            mark_pending_device_credential_guards_passed(&pending, &pending_store)?
        } else {
            pending
        }
    };
    let confirmed = if pending.confirmed_at.is_some() {
        pending
    } else {
        match confirm_device_credential_preparation(&pending, &candidate_secret) {
            Ok(receipt) => mark_pending_device_credential_confirmed(
                &pending,
                &receipt.confirmed_at,
                &pending_store,
            )?,
            Err(error) if registration_history_choice_required(&error) => {
                // The lower-level refusal persisted the browser re-offer. Leave
                // the same pending candidate and old credential pair intact.
                return Ok(false);
            }
            Err(error) if backend_error_has_status(&error, 410) => {
                discard_server_inactive_pending_device_credential(
                    &pending_store,
                    &pending_secret_store,
                )?;
                return Ok(false);
            }
            Err(error) if backend_error_has_status(&error, 404) => {
                match probe_pruned_device_credential_authority(&pending, &candidate_secret)? {
                    PrunedDeviceCredentialProbe::Confirmed => {
                        mark_pending_device_credential_confirmed(
                            &pending,
                            &current_rfc3339_timestamp(),
                            &pending_store,
                        )?
                    }
                    PrunedDeviceCredentialProbe::Inactive => {
                        discard_server_inactive_pending_device_credential(
                            &pending_store,
                            &pending_secret_store,
                        )?;
                        return Ok(false);
                    }
                }
            }
            Err(error) => return Err(error),
        }
    };
    let _identity_lifecycle_lock = lock_setup_run_binding();
    identity_reservation.validate_locked()?;
    if confirmed.claim_commit.is_some() {
        write_and_verify_pending_claim_commit(&confirmed, &candidate_secret)?;
        clear_pending_device_credential(&pending_store, &pending_secret_store)?;
    } else {
        promote_pending_device_credential_with_stores(
            &confirmed,
            &candidate_secret,
            &pending_store,
            &pending_secret_store,
            &FileDeviceStore::default(),
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
    }
    Ok(true)
}

#[cfg(test)]
fn save_relay_device_binding(device: &LocalDeviceBinding) -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    save_relay_device_binding_locked(device, None)
}

#[cfg(test)]
fn save_relay_device_binding_locked(
    device: &LocalDeviceBinding,
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    FileDeviceStore::default().save(device).or_state_poisoned()
}

fn claim_completion_response_unexpected(detail: &str) -> LocalApiError {
    LocalApiError::Backend(BackendErrorDetails {
        kind: BackendErrorKind::ResponseUnexpected,
        endpoint: "/api/v1/setup-claims/[claim]/local-client/complete".to_string(),
        status: None,
        body_excerpt: Some(detail.to_string()),
        reason_code: None,
    })
}

/// `only_if_bound`: reset only while this setup run is still the bound one
/// (the automatic reset after a terminal refresh answer about it).
fn auth_reset(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    local_only: bool,
    forget_installation: bool,
    only_if_bound: Option<&LocalConnectionBinding>,
) -> Result<AuthResetResponse, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    // Both ordinary and explicit local-only logout replace account/device
    // authority, so both drain admitted Codex cloud-task I/O first.
    let identity_reservation = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        require_setup_run_still_bound(daemon, only_if_bound)?;
        reserve_identity_mutation_locked()?
    };
    let mut cloud_disconnect: Option<SetupRunDisconnectResponse> = None;
    let mut setup_run_already_ended = false;
    let mut released_without_setup_run = false;

    if !local_only {
        let connection = daemon
            .connection_for_authorized_client()?
            .ok_or_else(|| cloud_logout_requires_connection_error(forget_installation))?;
        let setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .load()
            .map_err(|_| cloud_logout_requires_connection_error(forget_installation))?;
        let api_base_url = validated_api_base_url(Some(connection.api_base_url.as_str()))?;
        // Read the release proof before any local deletion below; the server
        // revokes this Mac's registration only when both halves authenticate.
        let release = load_device_release_proof();
        match disconnect_setup_run_with_refresh(
            &api_base_url,
            &connection,
            &setup_run_token,
            release.as_ref(),
        ) {
            Ok(disconnect) => cloud_disconnect = Some(disconnect),
            // Ottto already ended this run, so it can never be disconnected.
            // This Mac can still release its own registration with its device
            // secret, which needs no setup run; once Ottto confirms, the reset
            // continues exactly like a successful cloud logout. Otherwise a
            // plain logout falls through to the local-only cleanup (prior
            // device proof kept for reconnecting) and reports that Ottto was
            // not changed; forgetting the installation still needs the
            // release, and every other failure still aborts with local state
            // intact.
            Err(error)
                if terminal_refresh_rejection(&error)
                    == Some(TerminalRefreshRejection::SetupRunEnded) =>
            {
                if release
                    .as_ref()
                    .is_some_and(|release| release_device_without_setup_run(&api_base_url, release))
                {
                    released_without_setup_run = true;
                } else if forget_installation {
                    return Err(error);
                } else {
                    setup_run_already_ended = true;
                }
            }
            Err(error) => return Err(error),
        }
    }
    let local_only = local_only || setup_run_already_ended;

    // Every local deletion, Keychain included, happens under the identity
    // lifecycle lock after the binding is rechecked, so a setup run attached
    // meanwhile (which takes the same lock) is never cleared by this reset.
    let mut reset = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        require_setup_run_still_bound(daemon, only_if_bound)?;
        let retain_active = seed_owner_snapshot_history_for_logout()?;
        if local_only && retain_active {
            retain_prior_device_credential_for_logout()?;
        } else if local_only {
            // A partial promotion may mix the active file and secret halves.
            // Existing history stays intact; that mixed pair is not
            // predecessor authority for a later registration.
            clear_prior_device_selector()?;
        }
        clear_pending_device_credential(
            &FilePendingDeviceCredentialStore::default(),
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
        if !local_only || forget_installation {
            // The public selector is the usable half of a retained predecessor
            // credential. A destructive reset must durably remove it before
            // reporting success. The now-unusable Keychain half is deleted
            // best-effort below so a locked Keychain cannot strand the reset.
            clear_prior_device_selector()?;
        }
        reset_local_account_files_locked(Some(&identity_reservation))?;
        if forget_installation {
            forget_installation_state_locked()?;
        }
        let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
        let _ = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT).delete();
        if !local_only || forget_installation {
            let _ = KeychainSecretStore::new(OTTTO_PRIOR_RELAY_DEVICE_SECRET_ACCOUNT).delete();
        }
        daemon.reset_account_for_authorized_client()?
    };
    reset.local_only = local_only;
    reset.cloud_disconnected = cloud_disconnect.is_some();
    reset.setup_run_id = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.setup_run_id.clone());
    reset.disconnected_at = cloud_disconnect
        .as_ref()
        .map(|disconnect| disconnect.disconnected_at.clone());
    reset.device_released = if released_without_setup_run {
        Some(true)
    } else {
        cloud_disconnect
            .as_ref()
            .map(|disconnect| disconnect.device_released)
    };
    reset.message = if released_without_setup_run {
        released_without_setup_run_message(forget_installation)
    } else if setup_run_already_ended {
        StableMessage {
            code: "setup_run_already_ended".to_string(),
            text: "Ottto had already ended this Mac's setup run, so nothing changed in Ottto and this Mac's server registration was not released. Active local credentials were cleared; prior device proof was retained securely for reconnection."
                .to_string(),
        }
    } else {
        auth_reset_message(forget_installation, reset.device_released)
    };
    Ok(reset)
}

const FORGOTTEN_INSTALLATION: &str = "Installation identity and credentials were cleared. Collected state and local sync receipts stay; only uninstall deletes them. Agent source data was not changed. Restart ottto-service before pairing.";

/// `device_released` is `None` for a local-only reset, which never contacts
/// Ottto, and the server's answer for a cloud reset.
fn auth_reset_message(forget_installation: bool, device_released: Option<bool>) -> StableMessage {
    const NOT_RELEASED: &str = "Ottto did not confirm releasing this Mac's server registration, so it may still be active; the account that owns it can disconnect this Mac on its Apps page (Disconnect).";
    const STILL_REGISTERED: &str = "This Mac may still be registered to the previous Ottto account on the server. If that account was deleted or already disconnected this Mac, sign in and choose Replace it on the claim page. Otherwise a different account can connect it only after the previous account disconnects this Mac on its Apps page (Disconnect). The normal path is `ottto logout --forget-installation --confirm` without --local-only, which releases the registration first.";
    const FORGOTTEN: &str = FORGOTTEN_INSTALLATION;
    let (code, text) = match (forget_installation, device_released) {
        (true, None) => (
            "installation_forgotten",
            format!("Ottto was not contacted. {FORGOTTEN} {STILL_REGISTERED}"),
        ),
        (true, Some(true)) => (
            "installation_forgotten",
            format!(
                "This Mac was disconnected from Ottto and its server registration was released. {FORGOTTEN}"
            ),
        ),
        (true, Some(false)) => (
            "installation_forgotten",
            format!("This Mac was disconnected from Ottto. {NOT_RELEASED} {FORGOTTEN}"),
        ),
        (false, None) => (
            "local_disconnect_complete",
            "Active local credentials were cleared without changing cloud state; prior device proof was retained securely for reconnection."
                .to_string(),
        ),
        (false, Some(true)) => (
            "cloud_disconnect_complete",
            "This Mac was disconnected from Ottto and its server registration was released."
                .to_string(),
        ),
        (false, Some(false)) => (
            "cloud_disconnect_complete",
            format!("This Mac was disconnected from Ottto. {NOT_RELEASED}"),
        ),
    };
    StableMessage {
        code: code.to_string(),
        text,
    }
}

/// A cloud reset whose setup run had already ended, after this Mac released
/// its own server registration directly.
fn released_without_setup_run_message(forget_installation: bool) -> StableMessage {
    const RELEASED: &str = "This Mac's Ottto connection had expired, so it released its server registration directly and was logged out.";
    if forget_installation {
        StableMessage {
            code: "installation_forgotten".to_string(),
            text: format!("{RELEASED} {FORGOTTEN_INSTALLATION}"),
        }
    } else {
        StableMessage {
            code: "device_released_after_run_ended".to_string(),
            text: RELEASED.to_string(),
        }
    }
}

fn forget_installation_state_locked() -> Result<(), LocalApiError> {
    // This explicit identity-forget action closes the old local ceremony.
    // Complete secure cleanup BEFORE replacing the installation identity.
    {
        let _history_lock = lock_history_recovery()?;
        let stores = history_stores();
        clear_local_release(&stores)?;
        stores.browser.delete().or_state_poisoned()?;
    }
    // Collected state, caches and receipts stay; only uninstall deletes them.
    FileMachineStore::default().reset().or_state_poisoned()?;
    Ok(())
}

#[cfg(test)]
fn reset_local_account_files() -> Result<(), LocalApiError> {
    let _identity_lifecycle_lock = lock_setup_run_binding();
    reset_local_account_files_locked(None)
}

fn reset_local_account_files_locked(
    reservation: Option<&IdentityMutationReservation>,
) -> Result<(), LocalApiError> {
    require_identity_mutation_reservation(reservation)?;
    FileAccountStore::default().reset().or_state_poisoned()?;
    FileConnectionStore::default().reset().or_state_poisoned()?;
    FileDeviceStore::default().reset().or_state_poisoned()?;
    Ok(())
}

fn cloud_logout_requires_connection_error(forget_installation: bool) -> LocalApiError {
    LocalApiError::InvalidRequest(if forget_installation {
        "logout --forget-installation requires an active Ottto cloud connection to release this Mac's server registration; use --local-only --forget-installation only to clear local state without updating Ottto"
            .to_string()
    } else {
        "logout requires an active Ottto cloud connection; use --local-only only to clear local state without updating Ottto"
            .to_string()
    })
}

fn create_setup_claim(
    machine: &MachineIdentity,
    nonce: &str,
) -> Result<SetupClaimCreateResponse, LocalApiError> {
    let url = api_url("/api/v1/setup-claims");
    let _receipt_lock = lock_history_recovery()?;
    create_setup_claim_with_history(&url, machine, nonce, &history_stores(), history_now())
}

const REVOCATION_RECEIPT_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;

static REVOCATION_RECEIPT_LOCK: Mutex<()> = Mutex::new(());

fn history_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn lock_history_recovery() -> Result<MutexGuard<'static, ()>, LocalApiError> {
    REVOCATION_RECEIPT_LOCK.lock().or_state_poisoned()
}

struct HistoryStores {
    receipt: Box<dyn ControlTokenStore>,
    marker: Box<dyn ControlTokenStore>,
    proof: Box<dyn ControlTokenStore>,
    browser: Box<dyn ControlTokenStore>,
}

fn history_support_dir() -> PathBuf {
    #[cfg(test)]
    if std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR").is_none() {
        return ottto_core::token_store::isolated_test_secret_dir()
            .expect("isolated history test store")
            .join(format!("history-{:?}", std::thread::current().id()));
    }
    default_support_dir()
}

fn history_account_store() -> FileAccountStore {
    FileAccountStore::new(history_support_dir().join("account.json"))
}

fn history_connection_store() -> FileConnectionStore {
    FileConnectionStore::new(history_support_dir().join("connection.json"))
}

fn history_stores() -> HistoryStores {
    HistoryStores {
        receipt: history_secret_store(OTTTO_REVOCATION_RECEIPT_ACCOUNT),
        marker: history_secret_store(HISTORY_MARKER_ACCOUNT),
        proof: history_secret_store(HISTORY_PROOF_ACCOUNT),
        browser: history_secret_store(HISTORY_BROWSER_ACCOUNT),
    }
}

fn history_secret_store(account: &'static str) -> Box<dyn ControlTokenStore> {
    #[cfg(not(test))]
    {
        Box::new(KeychainSecretStore::keychain_only(account))
    }
    #[cfg(test)]
    {
        // Synthetic stores survive a daemon reload, without ever touching the
        // host Keychain or writing a receipt/device proof to a fixture file.
        use ottto_core::token_store::MemoryTokenStore;
        type TestHistoryStores = Mutex<BTreeMap<(PathBuf, &'static str), MemoryTokenStore>>;
        static STORES: std::sync::OnceLock<TestHistoryStores> = std::sync::OnceLock::new();
        let mut stores = STORES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap();
        Box::new(
            stores
                .entry((history_support_dir(), account))
                .or_default()
                .clone(),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRevocationReceipt {
    revocation_receipt: SecretString,
    received_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalReleaseMarker {
    device_id: String,
    api_base_url: String,
    released_at: i64,
    #[serde(default)]
    cleanup_required: bool,
    #[serde(default)]
    ceremony_closed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalReleaseProof {
    device_id: String,
    device_secret: SecretString,
}

// This contains claim credentials and a nonce. Never derive Debug or put it in
// account.json; only the non-secret re-offer message belongs in that file.
#[derive(Serialize, Deserialize)]
struct StoredHistoryBrowserClaim {
    installation_id: String,
    account_scope: Option<String>,
    api_base_url: String,
    setup_run_id: Option<String>,
    #[serde(default)]
    registration_pending: bool,
    nonce: SecretString,
    claim: SetupClaimCreateResponse,
}

fn history_load<T: DeserializeOwned>(
    store: &dyn ControlTokenStore,
) -> Result<Option<T>, LocalApiError> {
    match store.load() {
        Ok(encoded) => serde_json::from_str(&encoded).map(Some).or_state_poisoned(),
        Err(TokenStoreError::Missing) => Ok(None),
        Err(_) => Err(LocalApiError::StatePoisoned),
    }
}

fn history_save<T: Serialize>(
    store: &dyn ControlTokenStore,
    value: &T,
) -> Result<(), LocalApiError> {
    let encoded = serde_json::to_string(value).or_state_poisoned()?;
    store.save(&encoded).or_state_poisoned()?;
    if store.load().or_state_poisoned()? != encoded {
        return Err(LocalApiError::StatePoisoned);
    }
    Ok(())
}

fn stage_local_release(
    api_base_url: &str,
    release: &DeviceReleaseProof,
    stores: &HistoryStores,
    now: i64,
) -> Result<(), LocalApiError> {
    let api_base_url = validated_api_base_url(Some(api_base_url))?;
    let existing: Option<LocalReleaseMarker> = history_load(stores.marker.as_ref())?;
    // Preserve the original boundary across a refresh/retry of the release.
    let same_release = existing.as_ref().is_some_and(|m| {
        m.device_id == release.device_id
            && m.api_base_url == api_base_url
            && !m.ceremony_closed
            && now
                .checked_sub(m.released_at)
                .is_some_and(|age| (0..REVOCATION_RECEIPT_MAX_AGE_SECONDS).contains(&age))
    });
    if !same_release {
        stores.receipt.delete().or_state_poisoned()?;
        stores.browser.delete().or_state_poisoned()?;
    }
    let released_at = existing
        .filter(|_| same_release)
        .map_or(now, |m| m.released_at);
    history_save(
        stores.proof.as_ref(),
        &LocalReleaseProof {
            device_id: release.device_id.clone(),
            device_secret: SecretString::new(&release.device_secret),
        },
    )?;
    history_save(
        stores.marker.as_ref(),
        &LocalReleaseMarker {
            device_id: release.device_id.clone(),
            api_base_url,
            released_at,
            cleanup_required: false,
            ceremony_closed: false,
        },
    )?;
    persist_local_release_expected()
}

fn remember_revocation_receipt(
    device_released: bool,
    receipt: Option<SecretString>,
    stores: &HistoryStores,
    now: i64,
) {
    if device_released {
        // The marker and own-device proof were durably staged BEFORE release.
        // A missing receipt or failed write is recovered by the re-issue API.
        if let Some(receipt) = receipt.filter(|s| !s.expose_secret().trim().is_empty()) {
            let _ = history_save(
                stores.receipt.as_ref(),
                &StoredRevocationReceipt {
                    revocation_receipt: receipt,
                    received_at: now,
                },
            );
        }
    }
}

fn clear_local_release(stores: &HistoryStores) -> Result<(), LocalApiError> {
    // Marker is last: any partial cleanup remains a recoverable pending action.
    if let Some(mut marker) = history_load::<LocalReleaseMarker>(stores.marker.as_ref())? {
        marker.cleanup_required = true;
        marker.ceremony_closed = true;
        history_save(stores.marker.as_ref(), &marker)?;
    }
    stores.receipt.delete().or_state_poisoned()?;
    stores.proof.delete().or_state_poisoned()?;
    clear_local_release_expected()?;
    stores.marker.delete().or_state_poisoned()
}

#[derive(Debug, Deserialize)]
struct RevocationReceiptRecoveryResponse {
    outcome: String,
    #[serde(default)]
    revocation_receipt: Option<SecretString>,
    #[serde(default)]
    claim_code: Option<SecretString>,
    #[serde(default)]
    claim_token: Option<SecretString>,
    #[serde(default)]
    client_nonce: Option<SecretString>,
}

enum ReceiptRecovery {
    Receipt(SecretString),
    Claim(SetupClaimCreateResponse),
    Refused,
}

fn reissue_revocation_receipt(
    marker: &LocalReleaseMarker,
    proof: &LocalReleaseProof,
) -> Result<ReceiptRecovery, LocalApiError> {
    let base = validated_api_base_url(Some(&marker.api_base_url))?;
    if marker.device_id != proof.device_id
        || marker.device_id.is_empty()
        || !marker
            .device_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let url = api_url_with_base(
        &base,
        &format!(
            "/api/v1/telemetry/devices/{}/revocation-receipt",
            marker.device_id
        ),
    );
    let response: RevocationReceiptRecoveryResponse = match backend_post_json(
        &url,
        &json!({}),
        &[("X-Ottto-Device-Secret", proof.device_secret.expose_secret())],
    ) {
        Ok(response) => response,
        Err(LocalApiError::Backend(ref details))
            if matches!(details.status, Some(401 | 409))
                && details.reason_code.as_deref().is_some_and(|code| {
                    matches!(
                        code,
                        "device_secret_invalid"
                            | "device_reactivated"
                            | "origin_not_local_switch"
                            | "release_window_expired"
                            | "ceremony_closed"
                    )
                }) =>
        {
            eprintln!(
                "ottto-service: local history recovery outcome={}",
                details.reason_code.as_deref().unwrap()
            );
            return Ok(ReceiptRecovery::Refused);
        }
        // Daemon-first rollout: old servers do not expose this endpoint yet.
        Err(LocalApiError::Backend(ref details)) if matches!(details.status, Some(404 | 405)) => {
            eprintln!("ottto-service: local history recovery outcome=receipt_reissue_unavailable");
            return Ok(ReceiptRecovery::Refused);
        }
        Err(error) => return Err(error),
    };
    match response.outcome.as_str() {
        "receipt_issued" => {
            let receipt = response
                .revocation_receipt
                .filter(|s| !s.expose_secret().trim().is_empty())
                .ok_or(LocalApiError::StatePoisoned)?;
            eprintln!("ottto-service: local history recovery outcome=receipt_issued");
            Ok(ReceiptRecovery::Receipt(receipt))
        }
        "claim_recovered" => {
            let code = response.claim_code.ok_or(LocalApiError::StatePoisoned)?;
            let token = response.claim_token.ok_or(LocalApiError::StatePoisoned)?;
            let nonce = response.client_nonce.ok_or(LocalApiError::StatePoisoned)?;
            if !code
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(LocalApiError::StatePoisoned);
            }
            #[derive(Deserialize)]
            struct ClaimStatus {
                claim_url: String,
                expires_at: String,
            }
            let status: ClaimStatus = backend_get_json(
                &api_url_with_base(
                    &base,
                    &format!("/api/v1/setup-claims/{}", code.expose_secret()),
                ),
                &[],
            )?;
            eprintln!("ottto-service: local history recovery outcome=claim_recovered");
            Ok(ReceiptRecovery::Claim(SetupClaimCreateResponse {
                claim_code: code.expose_secret().to_string(),
                claim_token: token.expose_secret().to_string(),
                client_nonce: Some(nonce.expose_secret().to_string()),
                claim_url: status.claim_url,
                expires_at: status.expires_at,
            }))
        }
        _ => Err(LocalApiError::StatePoisoned),
    }
}

fn persist_history_browser_claim(
    claim: &SetupClaimCreateResponse,
    nonce: &str,
    machine: &MachineIdentity,
    base: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    history_save(
        stores.browser.as_ref(),
        &StoredHistoryBrowserClaim {
            installation_id: machine.installation_id.clone(),
            account_scope: machine.account_scope.clone(),
            api_base_url: base.to_string(),
            setup_run_id: history_connection_store()
                .load()
                .or_state_poisoned()?
                .filter(|c| c.api_base_url == base)
                .map(|c| c.setup_run_id),
            registration_pending: history_account_store()
                .load()
                .is_ok_and(|account| registration_history_choice_account(&account)),
            nonce: SecretString::new(claim.client_nonce.as_deref().unwrap_or(nonce)),
            claim: claim.clone(),
        },
    )
}

fn create_setup_claim_with_history(
    url: &str,
    machine: &MachineIdentity,
    nonce: &str,
    stores: &HistoryStores,
    now: i64,
) -> Result<SetupClaimCreateResponse, LocalApiError> {
    let base = validated_api_base_url(Some(
        url.strip_suffix("/api/v1/setup-claims")
            .ok_or(LocalApiError::StatePoisoned)?,
    ))?;
    let expected = local_history_recovery_expected()?;
    let mut marker: Option<LocalReleaseMarker> = match history_load(stores.marker.as_ref()) {
        Ok(marker) => marker,
        Err(_) if !expected => None,
        Err(error) => return Err(error),
    };
    if marker.as_ref().is_some_and(|m| {
        m.ceremony_closed
            || now
                .checked_sub(m.released_at)
                .is_some_and(|age| age >= REVOCATION_RECEIPT_MAX_AGE_SECONDS)
    }) {
        clear_local_release(stores)?;
        marker = None;
    }
    // Only a release or registration refusal needs durable recovery. Existing
    // first-time and same-account sign-in still works with file-only stores.
    if marker.is_none() && !local_history_recovery_expected()? {
        return backend_post_json(url, &setup_claim_create_body(machine, nonce), &[]);
    }
    if marker.is_none()
        && expected
        && !history_account_store()
            .load()
            .is_ok_and(|a| registration_history_choice_account(&a))
    {
        return Err(LocalApiError::StatePoisoned);
    }
    let stored = history_load::<StoredRevocationReceipt>(stores.receipt.as_ref());
    let mut receipt = stored.ok().flatten().filter(|r| {
        now.checked_sub(r.received_at)
            .is_some_and(|age| (0..REVOCATION_RECEIPT_MAX_AGE_SECONDS).contains(&age))
    });
    if let Some(marker) = &marker {
        if marker.api_base_url != base {
            return Err(LocalApiError::StatePoisoned);
        }
        if receipt.is_none() || marker.cleanup_required {
            let proof = history_load::<LocalReleaseProof>(stores.proof.as_ref())?
                .ok_or(LocalApiError::StatePoisoned)?;
            match reissue_revocation_receipt(marker, &proof)? {
                ReceiptRecovery::Receipt(value) => {
                    history_save(
                        stores.receipt.as_ref(),
                        &StoredRevocationReceipt {
                            revocation_receipt: value.clone(),
                            received_at: now,
                        },
                    )?;
                    receipt = Some(StoredRevocationReceipt {
                        revocation_receipt: value,
                        received_at: now,
                    });
                }
                ReceiptRecovery::Claim(claim) => {
                    persist_history_browser_claim(&claim, nonce, machine, &base, stores)?;
                    return Ok(claim);
                }
                ReceiptRecovery::Refused => {
                    receipt = None;
                }
            }
        }
    } else if receipt.is_none() {
        // No released-local marker means an ordinary first/same-device claim.
        // A corrupt orphan receipt is purged, never logged or sent.
        stores.receipt.delete().or_state_poisoned()?;
    }
    let mut body = setup_claim_create_body(machine, nonce);
    if let Some(receipt) = &receipt {
        body["revocation_receipt"] = json!(receipt.revocation_receipt.expose_secret());
    }
    let response = crate::retry_tls::credential_agent()
        .post(url)
        .set("Accept", "application/json")
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .send_json(&body);
    match response {
        Ok(response) => {
            let response = backend_success(url, response)?;
            let claim: SetupClaimCreateResponse = response
                .into_json()
                .map_err(|error| backend_response_unexpected(url, error.to_string()))?;
            if claim.claim_code.trim().is_empty()
                || claim.claim_token.trim().is_empty()
                || claim.claim_url.trim().is_empty()
            {
                return Err(LocalApiError::StatePoisoned);
            }
            // Durable browser handoff precedes secret cleanup. Even a lost local
            // reply/restart returns this exact ceremony and its original nonce.
            persist_history_browser_claim(&claim, nonce, machine, &base, stores)?;
            if stores.receipt.delete().is_err() {
                if let Some(mut marker) = marker {
                    marker.cleanup_required = true;
                    history_save(stores.marker.as_ref(), &marker)?;
                }
            }
            Ok(claim)
        }
        Err(error) => {
            if matches!(&error, ureq::Error::Status(status, _) if definitive_claim_refusal(*status))
            {
                clear_local_release(stores)?;
            }
            Err(backend_error_from_ureq(url, error))
        }
    }
}

fn definitive_claim_refusal(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 408 | 425 | 429)
}

fn resume_history_browser_claim(
    machine: &MachineIdentity,
    base: &str,
) -> Result<Option<PendingAuthClaim>, LocalApiError> {
    let _lock = lock_history_recovery()?;
    resume_history_browser_claim_with_stores(machine, base, &history_stores())
}

fn resume_history_browser_claim_with_stores(
    machine: &MachineIdentity,
    base: &str,
    stores: &HistoryStores,
) -> Result<Option<PendingAuthClaim>, LocalApiError> {
    let stored = match history_load::<StoredHistoryBrowserClaim>(stores.browser.as_ref()) {
        Ok(Some(stored)) => stored,
        Ok(None) => return Ok(None),
        Err(_) if !local_history_recovery_expected()? => return Ok(None),
        Err(_) if history_load::<LocalReleaseMarker>(stores.marker.as_ref())?.is_some() => {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    if stored.installation_id != machine.installation_id
        || stored.account_scope != machine.account_scope
        || stored.api_base_url != base
    {
        return Err(LocalApiError::StatePoisoned);
    }
    if auth_claim_is_expired(&stored.claim.expires_at) {
        return Ok(None);
    }
    Ok(Some(PendingAuthClaim {
        claim_code: stored.claim.claim_code,
        claim_token: stored.claim.claim_token,
        nonce: stored.nonce.expose_secret().to_string(),
        claim_url: append_nonce_to_claim_url(&stored.claim.claim_url, stored.nonce.expose_secret()),
        expires_at: stored.claim.expires_at,
    }))
}

fn finish_history_browser_claim(claim_code: &str) -> Result<(), LocalApiError> {
    let _lock = lock_history_recovery()?;
    finish_history_browser_claim_with_stores(claim_code, &history_stores())
}

fn finish_history_browser_claim_with_stores(
    claim_code: &str,
    stores: &HistoryStores,
) -> Result<(), LocalApiError> {
    let stored: Option<StoredHistoryBrowserClaim> = history_load(stores.browser.as_ref())?;
    if !stored.is_some_and(|stored| stored.claim.claim_code == claim_code) {
        return Ok(());
    }
    clear_local_release(stores)?;
    stores.browser.delete().or_state_poisoned()
}

fn setup_claim_create_body(machine: &MachineIdentity, nonce: &str) -> serde_json::Value {
    json!({
        "machine_id": machine.machine_id,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": "macos",
        "client_nonce": nonce,
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "local_platform_version": machine.local_platform_version,
            "capabilities": {
                "deeplink": { "registered": true },
                "setup_run": true,
                "smoke_verification": true,
            },
        },
    })
}

fn complete_setup_claim(
    claim: &PendingAuthClaim,
    machine: &MachineIdentity,
    identity_reservation: Option<&IdentityMutationReservation>,
) -> Result<SetupClaimCompletion, LocalApiError> {
    let url = api_url(&format!(
        "/api/v1/setup-claims/{}/local-client/complete",
        claim.claim_code
    ));
    // Snapshot established file + Keychain authority under the identity
    // lifecycle fence. Network I/O runs without the mutex, while the
    // reservation prevents legitimate local writers from rotating authority.
    let prior_device_credential = {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        match identity_reservation {
            Some(reservation) => reservation.validate_locked()?,
            None => require_identity_mutation_reservation(None)?,
        }
        prior_device_credential_for_registration()?
    };
    let request_authority = device_credential_request_authority(
        "setup_claim",
        &claim.claim_code,
        machine,
        prior_device_credential.as_ref(),
        prior_device_credential
            .as_ref()
            .map(|_| IDENTITY_CONTINUITY_CAPABILITY),
    );
    let mut body = setup_claim_complete_body(claim, machine);
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "credential_preparation_capability".to_string(),
            json!(DEVICE_CREDENTIAL_PREPARATION_CAPABILITY),
        );
        object.insert(
            "credential_preparation_idempotency_key".to_string(),
            json!(request_authority
                .credential_preparation_idempotency_key
                .clone()),
        );
    }
    if let Some(prior) = prior_device_credential.as_ref() {
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "identity_continuity_capability".to_string(),
                json!(IDENTITY_CONTINUITY_CAPABILITY),
            );
            object.insert("relay_device_id".to_string(), json!(prior.device_id));
            object.insert(
                "relay_device_sources".to_string(),
                json!(prior.device_sources),
            );
            object.insert(
                "prior_device_secret".to_string(),
                json!(prior.device_secret),
            );
        }
    }
    let response = backend_post_json(
        &url,
        &body,
        &[("X-Ottto-Setup-Claim-Token", claim.claim_token.as_str())],
    )?;
    // Revalidate immediately after the remote preparation and before any
    // journal write. This catches out-of-band Keychain mutation in addition
    // to file/account mutations fenced by the reservation snapshot.
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        match identity_reservation {
            Some(reservation) => reservation.validate_locked()?,
            None => require_identity_mutation_reservation(None)?,
        }
        let current = prior_device_credential_for_registration()?;
        if !same_prior_device_authority(prior_device_credential.as_ref(), current.as_ref()) {
            return Err(LocalApiError::StatePoisoned);
        }
    }
    Ok(SetupClaimCompletion {
        response,
        prior_device_credential,
        request_authority,
    })
}

fn setup_claim_complete_body(
    claim: &PendingAuthClaim,
    machine: &MachineIdentity,
) -> serde_json::Value {
    json!({
        "nonce": claim.nonce,
        "machine_id": machine.machine_id,
        "machine_identity_capability": MACHINE_IDENTITY_CAPABILITY,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": "macos",
    })
}

#[cfg(test)]
mod machine_icon_tests {
    use super::apply_machine_icon;

    #[test]
    fn injects_icon_when_machine_matches() {
        let mut status =
            serde_json::json!({ "machine": { "machine_id": "otm_x", "hostname": "h" } });
        apply_machine_icon(
            &mut status,
            Some(("otm_x".to_string(), "https://icon.png".to_string())),
        );
        assert_eq!(
            status["machine"]["icon_url"],
            serde_json::json!("https://icon.png")
        );
    }

    #[test]
    fn skips_on_mismatch_empty_or_none() {
        let mut status = serde_json::json!({ "machine": { "machine_id": "otm_x" } });
        apply_machine_icon(
            &mut status,
            Some(("otm_other".to_string(), "https://icon.png".to_string())),
        );
        assert!(status["machine"].get("icon_url").is_none());
        apply_machine_icon(&mut status, Some(("otm_x".to_string(), String::new())));
        assert!(status["machine"].get("icon_url").is_none());
        apply_machine_icon(&mut status, None);
        assert!(status["machine"].get("icon_url").is_none());
    }
}

/// Background reconcile retry after Ottto refused the scan result with a 400:
/// the payload is rebuilt the same way each attempt, so the refusal repeats.
/// Still a retry, not a park: binding changes and daemon restarts reset it.
const SETUP_RECONCILE_REFUSED_RETRY: Duration = Duration::from_secs(24 * 60 * 60);

fn setup_action(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    action_type: String,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let status = status_for(daemon, authorization)?;
    let mut connection = daemon.connection_for_authorized_client()?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let connection = connection
        .take()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let mut credentials = setup_run_token_for_connection(&api_base_url, &connection)?;
    let action_type = match action_type.trim() {
        "install_source" | "verify_source" => action_type.trim().to_string(),
        _ => {
            return Err(LocalApiError::InvalidRequest(
                "setup_action only supports install_source and verify_source".to_string(),
            ))
        }
    };
    let queued = queue_setup_action(&api_base_url, &mut credentials, &source, &action_type)?;
    if action_type == "install_source" {
        set_source_marker(crate::snapshot_sync::reconnect_snapshot_source, &source)?;
    }
    let action_results =
        process_setup_actions(daemon, &api_base_url, &mut credentials, &status.machine)?;
    request_snapshot_sync_after_setup_actions(daemon, &action_results);
    let detail = action_results
        .last()
        .and_then(|result| result.detail.clone())
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "queued setup action did not return a setup-run detail".to_string(),
            )
        })?;
    let mut result =
        setup_result_from_detail(&credentials.connection, detail, false, action_results)?;
    // Lets the client bind a completion to the action this request queued.
    result["queued_action_id"] = json!(queued.id);
    Ok(result)
}

fn request_snapshot_sync_after_setup_actions(
    daemon: &LocalDaemon,
    action_results: &[SetupActionResult],
) {
    let registered_device = action_results.iter().any(|result| {
        result.action_type == "install_source"
            && result.status == "succeeded"
            && result
                .source
                .as_deref()
                .and_then(source_from_slug)
                .is_some_and(|source| source_requires_device_registration(&source))
    });
    if registered_device {
        request_snapshot_sync_after_device_registration(daemon);
    }
}

fn setup_result_from_detail(
    connection: &LocalConnectionBinding,
    detail: SetupRunDetailApiResponse,
    claim_code_provided: bool,
    action_results: Vec<SetupActionResult>,
) -> Result<serde_json::Value, LocalApiError> {
    let source_count = detail
        .sources
        .iter()
        .filter(|source| source.detected)
        .count();
    let detected_sources = detail
        .sources
        .iter()
        .filter(|source| source.detected)
        .map(|source| {
            let mut summary = json!({
                "source": source.source,
                "state": source.state,
                "readiness_percent": source.readiness_percent,
                "missing_fields": source.missing_fields,
            });
            if let Some(ready) = source.local_import_ready {
                summary["local_import_ready"] = json!(ready);
            }
            if let Some(required) = source.live_telemetry_required {
                summary["live_telemetry_required"] = json!(required);
            }
            summary
        })
        .collect::<Vec<_>>();

    let local_claim: Option<StoredHistoryBrowserClaim> =
        match history_load(history_stores().browser.as_ref()) {
            Ok(claim) => claim,
            Err(_) if !local_history_recovery_expected()? => None,
            Err(error) => return Err(error),
        };
    let local_claim_url = local_claim
        .filter(|claim| {
            claim.setup_run_id.as_deref() == Some(connection.setup_run_id.as_str())
                && claim.api_base_url == connection.api_base_url
                && !auth_claim_is_expired(&claim.claim.expires_at)
        })
        .map(|claim| {
            append_nonce_to_claim_url(&claim.claim.claim_url, claim.nonce.expose_secret())
        });
    Ok(json!({
        "status": detail.run.status,
        "setup_run_id": connection.setup_run_id,
        "claim_code_provided": claim_code_provided,
        "source_count": source_count,
        "detected_sources": detected_sources,
        "next_question": detail.next_question,
        "next_action": detail.next_action,
        "setup_claim_url": local_claim_url.or(detail.setup_claim_url),
        "actions": action_results,
    }))
}

fn attach_setup_run_by_claim_code(
    api_base_url: &str,
    claim_code: &str,
    machine: &MachineIdentity,
) -> Result<SetupRunAttachResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!("/api/v1/setup-claims/{claim_code}/attach"),
    );
    let body = setup_run_attach_body(machine);
    backend_post_json(&url, &body, &[])
}

fn setup_run_attach_body(machine: &MachineIdentity) -> serde_json::Value {
    json!({
        "machine_id": machine.machine_id,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "local_platform_version": machine.local_platform_version,
            "capabilities": {
                "deeplink": { "registered": true },
                "setup_run": true,
                "smoke_verification": true,
            },
        },
    })
}

fn process_setup_actions(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
) -> Result<Vec<SetupActionResult>, LocalApiError> {
    process_setup_actions_with_status(daemon, api_base_url, credentials, machine, &mut 0)
        .map(|(results, _, _)| results)
}

fn process_setup_actions_with_status(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
    actions_processed: &mut usize,
) -> Result<(Vec<SetupActionResult>, Option<String>, bool), LocalApiError> {
    let mut results = Vec::new();
    let mut last_run_status = None;
    for _ in 0..8 {
        let next = get_next_setup_action(api_base_url, credentials)?;
        last_run_status = next.run_status;
        let Some(action) = next.action else {
            return Ok((results, last_run_status, true));
        };
        let source_slug = action.source.clone();
        let source = source_slug.as_deref().and_then(source_from_slug);
        if source.as_ref().is_some_and(setup_source_paused) {
            let detail = complete_setup_action(
                api_base_url,
                credentials,
                &action,
                "cancelled",
                "source_paused",
                json!({ "reason": "source_paused" }),
            )?;
            results.push(SetupActionResult {
                action_id: action.id,
                action_type: action.action_type,
                source: source_slug,
                status: "cancelled".to_string(),
                detail: Some(detail),
                verification: None,
            });
            *actions_processed += 1;
            continue;
        }
        if let Err(error) = record_setup_action_event(
            api_base_url,
            credentials,
            &action,
            SetupActionEvent {
                event_type: "action.started",
                status: "running",
                message: "Local daemon started setup action",
                metadata: None,
            },
        ) {
            let (status, message, result) =
                setup_action_execution_error_result(&action, source.as_ref(), &error);
            let detail = complete_setup_action(
                api_base_url,
                credentials,
                &action,
                &status,
                &message,
                result,
            )?;
            results.push(SetupActionResult {
                action_id: action.id,
                action_type: action.action_type,
                source: source_slug,
                status,
                detail: Some(detail),
                verification: None,
            });
            *actions_processed += 1;
            continue;
        }
        let action_outcome = match action.action_type.as_str() {
            "install_source" => {
                run_install_source_action(daemon, api_base_url, credentials, &action, machine)
                    .map(|(status, message, result)| (status, message, result, None))
            }
            "verify_source" => {
                if let Some(source) = source.clone() {
                    crate::provider_calls::with_trigger(
                        crate::provider_calls::Trigger::Setup,
                        || {
                            run_verify_source_action(
                                daemon,
                                api_base_url,
                                credentials,
                                &action,
                                source,
                            )
                        },
                    )
                } else {
                    Ok((
                        "failed".to_string(),
                        "Setup action source was missing".to_string(),
                        json!({
                            "verified": false,
                            "error_code": "source_missing",
                            "error_message": "Setup action source was missing",
                        }),
                        None,
                    ))
                }
            }
            _ => Ok((
                "failed".to_string(),
                format!("Unsupported setup action {}", action.action_type),
                json!({
                    "error_code": "unsupported_action",
                    "error_message": format!("Unsupported setup action {}", action.action_type),
                }),
                None,
            )),
        };
        let (status, message, result, verification) = match action_outcome {
            Ok(outcome) => outcome,
            Err(error) if registration_history_choice_required(&error) => {
                reoffer_registration_browser_claim(daemon, machine, api_base_url)?;
                results.push(SetupActionResult {
                    action_id: action.id,
                    action_type: action.action_type,
                    source: source_slug,
                    status: "running".to_string(),
                    detail: None,
                    verification: None,
                });
                *actions_processed += 1;
                break;
            }
            Err(error) => {
                let (status, message, result) =
                    setup_action_execution_error_result(&action, source.as_ref(), &error);
                (status, message, result, None)
            }
        };
        let detail = complete_setup_action(
            api_base_url,
            credentials,
            &action,
            &status,
            &message,
            result,
        )?;
        results.push(SetupActionResult {
            action_id: action.id,
            action_type: action.action_type,
            source: source_slug,
            status,
            detail: Some(detail),
            verification,
        });
        *actions_processed += 1;
    }
    // A response containing an action cannot establish that the run is idle.
    Ok((results, last_run_status, false))
}

fn setup_action_execution_error_result(
    action: &SetupRunActionApiResponse,
    source: Option<&SourceKind>,
    error: &LocalApiError,
) -> (String, String, serde_json::Value) {
    let (error_code, error_message) = setup_action_execution_error_detail(error);
    let mut result = json!({
        "action_type": action.action_type.as_str(),
        "source": action.source.as_deref().or_else(|| source.map(source_slug)),
        "verified": false,
        "error_code": error_code,
        "error_message": error_message,
    });
    if source == Some(&SourceKind::Codex) {
        result["live_telemetry_required"] = json!(false);
        result["local_import_ready"] = json!(false);
    }
    ("failed".to_string(), error_message, result)
}

fn setup_action_execution_error_detail(error: &LocalApiError) -> (&'static str, String) {
    match error {
        LocalApiError::SetupRunConnectionMissing => (
            "setup_run_connection_missing",
            "This Mac needs an active Ottto setup flow. Start setup from the Ottto app, then retry.".to_string(),
        ),
        LocalApiError::SetupRunConnectionMismatch => (
            "setup_run_connection_mismatch",
            "This setup action belongs to a different Ottto setup run. Start setup again from the Ottto app.".to_string(),
        ),
        LocalApiError::TimedOut(_) => (
            "setup_action_timed_out",
            "Setup action timed out while waiting for Ottto. Check your network and retry setup.".to_string(),
        ),
        LocalApiError::NetworkUnavailable => (
            "network_unavailable",
            "Network is unavailable while running setup. Check your connection and retry setup.".to_string(),
        ),
        LocalApiError::Backend(details) => {
            if details.status == Some(401) || details.status == Some(403) {
                return (
                    "setup_action_rejected",
                    "Ottto rejected this setup action. Start setup from the Ottto app, then retry.".to_string(),
                );
            }
            if details.status == Some(404) {
                return (
                    "setup_run_missing",
                    "Ottto could not find this setup run. Start setup again from the Ottto app.".to_string(),
                );
            }
            match details.kind {
                BackendErrorKind::Unreachable => (
                    "backend_unreachable",
                    "Could not reach Ottto while running setup. Check your network and retry setup.".to_string(),
                ),
                BackendErrorKind::Unavailable => (
                    "backend_unavailable",
                    "Ottto was unavailable while running setup. Retry setup in a moment.".to_string(),
                ),
                BackendErrorKind::Rejected => (
                    "backend_rejected",
                    "Ottto rejected this setup action. Start setup from the Ottto app, then retry.".to_string(),
                ),
                BackendErrorKind::ResponseUnexpected => (
                    "backend_response_unexpected",
                    "Ottto returned an unexpected setup response. Retry setup in a moment.".to_string(),
                ),
            }
        }
        LocalApiError::LocalOperationFailed(_) => (
            "local_operation_failed",
            "A local setup step failed. Open Diagnostics or retry setup.".to_string(),
        ),
        LocalApiError::StatePoisoned => (
            "local_state_unavailable",
            "Local Ottto setup state is unavailable. Restart Ottto and retry setup.".to_string(),
        ),
        LocalApiError::RepairLocked => (
            "repair_locked",
            "Another Ottto repair is already running. Wait for it to finish, then retry setup.".to_string(),
        ),
        LocalApiError::ManualFenceReviewRequired => (
            "manual_fence_review_required",
            "Setup needs manual config review before it can continue.".to_string(),
        ),
        LocalApiError::CloudSessionCleanupRequired => (
            "cloud_session_cleanup_required",
            error.to_string(),
        ),
        LocalApiError::IdentityMutationInProgress => (
            "identity_mutation_in_progress",
            error.to_string(),
        ),
        LocalApiError::InvalidRequest(_) | LocalApiError::RetiredCommand(_) => (
            "invalid_setup_action",
            "Ottto could not run this setup action. Start setup again from the Ottto app.".to_string(),
        ),
        LocalApiError::Unauthorized
        | LocalApiError::LocalClientNotTrusted
        | LocalApiError::AccountResetRequired
        | LocalApiError::AccountSwitchCandidate { .. }
        | LocalApiError::EmptyControlToken
        | LocalApiError::NoPendingAuthClaim
        | LocalApiError::AuthClaimMismatch => (
            "setup_action_failed",
            "Ottto could not finish this setup action. Start setup from the Ottto app, then retry.".to_string(),
        ),
    }
}

fn get_next_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
) -> Result<SetupRunNextActionResponse, LocalApiError> {
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/next-action",
                active.setup_run_id
            ),
        );
        heartbeat_setup_run(api_base_url, active, token, "polling_next_action")?;
        backend_get_json(&url, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn heartbeat_setup_run(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    status: &str,
) -> Result<(), LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/heartbeat",
            connection.setup_run_id
        ),
    );
    let body = json!({
        "status": status,
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            // Report the live running version so the Apps surface can read it
            // from the heartbeat (the source of truth) instead of inferring it
            // from setup-scan / telemetry-device snapshots.
            "local_platform_version": compiled_release_version(),
        },
    });
    let _: serde_json::Value =
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
    Ok(())
}

fn record_setup_action_event(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    event: SetupActionEvent<'_>,
) -> Result<(), LocalApiError> {
    let body = json!({
        "event_type": event.event_type,
        "status": event.status,
        "message": event.message,
        "source": action.source,
        "metadata": event.metadata,
    });
    let _: serde_json::Value =
        setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
            let url = api_url_with_base(
                api_base_url,
                &format!(
                    "/api/v1/setup-runs/{}/local-client/actions/{}/events",
                    active.setup_run_id, action.id
                ),
            );
            backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
        })?;
    Ok(())
}

fn complete_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    status: &str,
    message: &str,
    result: serde_json::Value,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let body = json!({
        "status": status,
        "message": message,
        "result": result,
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/actions/{}/complete",
                active.setup_run_id, action.id
            ),
        );
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn run_install_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    machine: &MachineIdentity,
) -> Result<(String, String, serde_json::Value), LocalApiError> {
    let Some(source) = action.source.as_deref() else {
        return Ok((
            "failed".to_string(),
            "Install source action did not include a source".to_string(),
            json!({
            "error_code": "source_missing",
            "error_message": "Install source action did not include a source",
            }),
        ));
    };
    let body = json!({
        "action_id": action.id,
        "source": source,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "architecture": machine.arch,
        "client_name": OTTTO_CLIENT_NAME,
        "setup_origin": "companion_setup_run",
    });
    let install_session: InstallSessionApiResponse =
        setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
            let url = api_url_with_base(
                api_base_url,
                &format!(
                    "/api/v1/setup-runs/{}/local-client/install-sessions",
                    active.setup_run_id
                ),
            );
            backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
        })?;
    let Some(source_kind) = source_from_slug(source) else {
        return Ok((
            "failed".to_string(),
            format!("Unsupported local source: {source}"),
            json!({
                "install_session_id": install_session.install_session_id,
                "source": source,
                "error_code": "source_unsupported",
                "error_message": format!("Unsupported local source: {source}"),
            }),
        ));
    };
    if !source_requires_device_registration(&source_kind) {
        return Ok((
            "succeeded".to_string(),
            "Local source setup prepared".to_string(),
            json!({
                "install_session_id": install_session.install_session_id,
                "source": source,
                "local_changes": "prepared",
            }),
        ));
    }

    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "device.registration.started",
            status: "running",
            message: &format!(
                "Registering local {} telemetry device",
                source_display_name(&source_kind)
            ),
            metadata: Some(json!({"source": source})),
            device_id: None,
        },
    )?;
    // Resolve any previously confirmed-but-not-promoted generation before
    // beginning another identity mutation. Uncertain pending state fails
    // closed; it is never overwritten by a modern-to-legacy fallback.
    recover_pending_device_credential_at_startup()?;
    if FileAccountStore::default()
        .load()
        .is_ok_and(|account| registration_history_choice_account(&account))
    {
        reoffer_registration_browser_claim(daemon, machine, api_base_url)?;
        return Err(LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Rejected,
            endpoint: "/api/v1/telemetry/devices/registration-preparations".to_string(),
            status: Some(400),
            body_excerpt: Some("Setup claim session is pending".to_string()),
            reason_code: Some("history_choice_required".to_string()),
        }));
    }
    // Preparation is server-side non-authoritative. Hold a panic-safe local
    // reservation across prepare, local durable staging, confirm, and exact
    // promotion while leaving the lifecycle mutex free during network I/O.
    let identity_reservation = reserve_identity_mutation()?;
    let (prepared, _prior, request_authority) =
        prepare_telemetry_device_registration(api_base_url, &install_session, machine)?;
    let pending = pending_device_credential_from_preparation(
        api_base_url,
        &prepared,
        true,
        None,
        request_authority,
    )?;
    stage_pending_device_credential(&pending, &prepared.candidate_secret)?;
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let pending = mark_pending_device_credential_guards_passed(
        &pending,
        &FilePendingDeviceCredentialStore::default(),
    )?;
    let confirmed = confirm_device_credential_preparation(&pending, &prepared.candidate_secret)?;
    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending = mark_pending_device_credential_confirmed(
        &pending,
        &confirmed.confirmed_at,
        &pending_store,
    )?;
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        promote_pending_device_credential_with_stores(
            &pending,
            &prepared.candidate_secret,
            &pending_store,
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
            &FileDeviceStore::default(),
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
    }
    let device = pending.device;
    let device_id = device.device_id.clone();
    drop(identity_reservation);
    // The local device binding + secret are now durable. Wake the snapshot
    // collector before any backend completion/event call that can transiently
    // fail after registration has already succeeded.
    request_snapshot_sync_after_device_registration(daemon);
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "device.registration.completed",
            status: "succeeded",
            message: &format!(
                "Registered local {} telemetry device",
                source_display_name(&source_kind)
            ),
            metadata: Some(json!({"source": source})),
            device_id: Some(&device_id),
        },
    )?;
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "secure_store.saved",
            status: "succeeded",
            message: "Saved local relay device secret",
            metadata: Some(json!({"source": source, "store": "keychain"})),
            device_id: Some(&device_id),
        },
    )?;

    let codex_cleanup = if source_kind == SourceKind::Codex {
        Some(reconcile_codex_source_off()?)
    } else {
        None
    };
    if source_kind == SourceKind::Codex || !source_requires_config_patch(&source_kind) {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "config.patch.skipped",
                status: "succeeded",
                message: &format!(
                    "{} does not require local OTLP config patching",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "reason": "not_required",
                })),
                device_id: Some(&device_id),
            },
        )?;
        let message = format!(
            "{} local session import prepared",
            source_display_name(&source_kind)
        );
        let mut result = install_source_registration_result(
            &install_session.install_session_id,
            &device_id,
            source,
            &message,
        );
        if let Some(cleanup) = codex_cleanup {
            result["live_telemetry_required"] = json!(false);
            result["local_import_ready"] = json!(
                snapshot_device_credentials_include_source("codex")
                    && codex_config_state_at(
                        &home_path(".codex/config.toml"),
                        "~/.codex/config.toml",
                        "",
                        false
                    )
                    .drift
                    .is_empty()
                    && !source_patch_disabled(&source_kind)
            );
            result["managed_telemetry_disabled"] = json!(!source_patch_disabled(&source_kind));
            result["config_updated"] = json!(cleanup.changed);
            result["requires_restart"] = json!(cleanup.changed);
            result["message"] = json!(if cleanup.changed {
                "Codex local import prepared; restart existing Codex processes to stop managed telemetry"
            } else {
                &message
            });
        }
        return Ok(("succeeded".to_string(), message, result));
    }

    if source_patch_disabled(&source_kind) {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "config.patch.skipped",
                status: "succeeded",
                message: &format!(
                    "{} telemetry config patching is disabled by environment",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "reason": "disabled_by_env",
                })),
                device_id: Some(&device_id),
            },
        )?;
        let message = format!(
            "{} telemetry config patching skipped by environment",
            source_display_name(&source_kind)
        );
        return Ok((
            "succeeded".to_string(),
            message.clone(),
            install_source_patch_disabled_result(
                &install_session.install_session_id,
                &device_id,
                source,
                &message,
            ),
        ));
    }

    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    let relay_port = local_relay_port_for_daemon(daemon);
    let patch = match source_kind {
        SourceKind::Codex => reconcile_codex_source_off()?,
        SourceKind::ClaudeCode => {
            patch_claude_code_settings_with_relay_base(machine, &relay_base_url, false)?
        }
        SourceKind::Pi => unreachable!("Pi install actions do not patch OTLP config"),
    };
    let kept = patch.kept.map(claude_settings_kept_reason);
    let config_event_message = if let Some((_, text)) = kept {
        text.to_string()
    } else if patch.changed {
        format!(
            "Patched {} telemetry settings",
            source_display_name(&source_kind)
        )
    } else {
        format!(
            "{} telemetry settings already up to date",
            source_display_name(&source_kind)
        )
    };
    let mut metadata = json!({
        "source": source,
        "settings": match source_kind {
            SourceKind::Codex => "codex_config",
            SourceKind::ClaudeCode => "claude_settings",
            SourceKind::Pi => "none",
        },
        "changed": patch.changed,
        "created": patch.created,
        "backup_created": patch.backup_created,
        "backup_scope": "source_config",
        "restore_operation": "uninstall_restore",
    });
    if let Some((reason, _)) = kept {
        metadata["reason"] = json!(reason);
    }
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: if kept.is_some() {
                "config.patch.skipped"
            } else if patch.changed {
                "config.patched"
            } else {
                "config.unchanged"
            },
            status: "succeeded",
            message: &config_event_message,
            metadata: Some(metadata),
            device_id: Some(&device_id),
        },
    )?;

    let relay_running = loopback_listener_available(relay_port);
    if relay_running {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "relay.started",
                status: "succeeded",
                message: &format!(
                    "{} local OTLP relay is listening",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "port": relay_port,
                })),
                device_id: Some(&device_id),
            },
        )?;
    }

    let status = if relay_running { "succeeded" } else { "failed" }.to_string();
    let message = if let Some((_, text)) = kept {
        if relay_running {
            text.to_string()
        } else {
            format!("{text} The local OTLP relay is not listening.")
        }
    } else if relay_running {
        format!(
            "{} telemetry setup installed",
            source_display_name(&source_kind)
        )
    } else {
        let config_state = if patch.changed {
            "config was written"
        } else {
            "config is unchanged"
        };
        format!(
            "{} telemetry {config_state}, but the local OTLP relay is not listening",
            source_display_name(&source_kind)
        )
    };
    Ok((
        status,
        message.clone(),
        install_source_action_result(
            &install_session.install_session_id,
            &device_id,
            source,
            relay_running,
            relay_port,
            &message,
            patch.changed,
        ),
    ))
}

fn patch_disabled_message(source: &SourceKind) -> StableMessage {
    StableMessage {
        code: "patch_disabled".to_string(),
        text: format!(
            "{} telemetry config patching is disabled by environment; Ottto will not inspect or repair local config.",
            source_display_name(source)
        ),
    }
}

fn install_source_registration_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    message: &str,
) -> serde_json::Value {
    json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "registered",
        "config_patched": false,
        "relay_required": false,
        "message": message,
    })
}

fn install_source_action_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    relay_running: bool,
    relay_port: u16,
    message: &str,
    config_patched: bool,
) -> serde_json::Value {
    let mut result = json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "installed",
        "config_patched": config_patched,
        "relay_running": relay_running,
        "relay_port": relay_port,
        "relay_source": source,
    });
    if !relay_running {
        result["error_code"] = json!("relay_unavailable");
        result["error_message"] = json!(message);
    }
    result
}

fn install_source_patch_disabled_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    message: &str,
) -> serde_json::Value {
    json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "patch_disabled",
        "config_patched": false,
        "relay_required": true,
        "message": message,
    })
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(all(test, unix))]
#[path = "control_smoke_session_tests.rs"]
mod smoke_session_tests;
