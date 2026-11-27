//! The local control API: request entry points, command dispatch, the shared setup and backend
//! constants, and the re-exports of its child modules.

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
pub mod cloud_connect;
mod diagnostics;
mod managed_config;
mod peer;
mod policy;
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
use auth::require_cli_token;
use auth::require_local_caller;
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
use backend_http::backend_send_raw_json;
use backend_http::backend_success;
use backend_http::bounded_display_text;
use backend_http::cli_error;
use backend_http::cli_error_message;
use backend_http::control_token_validation_base_url;
use backend_http::form_url_encode;
pub(crate) use backend_http::is_production_api_base_url;
pub(crate) use backend_http::is_trusted_api_base_url;
pub(crate) use backend_http::loopback_base::developer_loopback_base;
use backend_http::reattach_required_state;
use backend_http::require_request_base_matches_binding;
#[cfg(test)]
use backend_http::safe_backend_body_excerpt;
use backend_http::safe_backend_endpoint;
use backend_http::staging_pair;
pub(crate) use backend_http::terminal_refresh_rejection;
use backend_http::validated_api_base_url;
#[cfg(test)]
use backend_http::with_test_staging_pair;
#[cfg(test)]
use backend_http::without_test_loopback_allowance;
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
pub use managed_config::remove_claude_shell_env_at_startup;
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
#[cfg(target_os = "macos")]
pub(crate) use peer::installed_companion_code_requirement;
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
use setup::actions::attach_setup_run_by_claim_code;
#[cfg(test)]
use setup::actions::install_source_action_result;
#[cfg(test)]
use setup::actions::install_source_registration_result;
use setup::actions::patch_disabled_message;
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
use setup::actions::process_setup_actions;
use setup::actions::process_setup_actions_with_status;
use setup::actions::record_setup_action_event;
use setup::actions::request_snapshot_sync_after_setup_actions;
use setup::actions::setup_action;
use setup::actions::setup_action_execution_error_detail;
use setup::actions::setup_result_from_detail;
#[cfg(test)]
use setup::actions::setup_run_attach_body;
#[cfg(test)]
use setup::actions::smoke::classify_source_smoke_failure;
#[cfg(test)]
use setup::actions::smoke::claude_smoke_command;
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
use setup::actions::smoke::run_claude_smoke_prompt;
use setup::actions::smoke::run_verification_smoke_prompt;
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
use setup::actions::smoke::NO_LIVE_CHECK_CODE;
use setup::actions::telemetry_control;
#[cfg(test)]
use setup::actions::telemetry_control_with_detector;
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
use setup::actions::verification::pi_route_result_from_smoke;
#[cfg(test)]
use setup::actions::verification::pi_route_result_from_verification;
#[cfg(test)]
use setup::actions::verification::run_one_pi_route_verification;
#[cfg(test)]
use setup::actions::verification::run_pi_route_pre_smoke;
#[cfg(test)]
use setup::actions::verification::run_pi_route_pre_smoke_with;
#[cfg(test)]
use setup::actions::verification::run_pi_route_smoke_prompt;
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
use setup::claims::auth_claim_is_expired;
use setup::claims::auth_complete;
#[cfg(test)]
use setup::claims::auth_complete_log_endpoint;
use setup::claims::auth_complete_pending;
use setup::claims::auth_reset;
use setup::claims::auth_start;
use setup::claims::auth_switch_account;
pub(crate) use setup::claims::backend_error_indicates_account_gone;
#[cfg(test)]
use setup::claims::begin_durable_browser_claim;
pub(crate) use setup::claims::capture_credential_authority;
#[cfg(test)]
use setup::claims::clear_local_release;
pub(crate) use setup::claims::commit_if_credential_current;
#[cfg(test)]
use setup::claims::complete_pending_auth_claim;
#[cfg(test)]
use setup::claims::complete_setup_claim;
use setup::claims::constant_work_eq;
#[cfg(test)]
use setup::claims::create_setup_claim_with_history;
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
pub(crate) use setup::claims::credentials::idle_credential_probe;
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
pub(crate) use setup::claims::credentials::IdleProbeAnswer;
use setup::claims::credentials::PriorDeviceCredential;
#[cfg(test)]
use setup::claims::credentials::SetupRunConnectionStore;
use setup::claims::credentials::IDENTITY_CONTINUITY_CAPABILITY;
use setup::claims::credentials::MACHINE_IDENTITY_CAPABILITY;
#[cfg(test)]
use setup::claims::credentials::OWNER_SNAPSHOT_MACHINE_FOR_TEST;
pub(crate) use setup::claims::device_credential_epoch;
#[cfg(test)]
use setup::claims::finish_history_browser_claim_with_stores;
#[cfg(test)]
use setup::claims::forget_installation_state_locked;
use setup::claims::history_load;
use setup::claims::history_now;
#[cfg(test)]
use setup::claims::history_save;
use setup::claims::history_stores;
pub(crate) use setup::claims::identity_mutation_in_progress;
use setup::claims::local_history_recovery_expected;
use setup::claims::lock_history_recovery;
pub(crate) use setup::claims::lock_setup_run_binding;
use setup::claims::mark_pending_device_credential_confirmed;
use setup::claims::mark_pending_device_credential_guards_passed;
use setup::claims::pending_device_credential_from_preparation;
#[cfg(test)]
use setup::claims::pending_snapshot_alias;
#[cfg(test)]
use setup::claims::persist_history_browser_claim;
#[cfg(test)]
use setup::claims::persist_local_release_expected;
#[cfg(test)]
pub(crate) use setup::claims::persist_relay_device_credentials;
pub(crate) use setup::claims::persisted_connection_for_epoch;
pub(crate) use setup::claims::promote_pending_device_credential_with_stores;
pub use setup::claims::recover_pending_device_credential_at_startup;
use setup::claims::registration_history_choice_account;
use setup::claims::registration_history_choice_error;
use setup::claims::registration_history_choice_required;
#[cfg(test)]
use setup::claims::relay_device_credentials_from_claim_completion;
#[cfg(test)]
use setup::claims::releasable_on_switch;
use setup::claims::remember_revocation_receipt;
use setup::claims::reoffer_registration_browser_claim;
use setup::claims::require_identity_mutation_reservation;
use setup::claims::reserve_identity_mutation;
#[cfg(test)]
use setup::claims::reset_local_account_files;
#[cfg(test)]
use setup::claims::resume_history_browser_claim;
#[cfg(test)]
use setup::claims::resume_history_browser_claim_with_stores;
#[cfg(test)]
use setup::claims::retire_refused_registration_after_browser_answer_with_stores;
#[cfg(test)]
use setup::claims::save_relay_device_binding;
pub(crate) use setup::claims::secret_commitment_matches;
pub(crate) use setup::claims::secret_sha256;
#[cfg(test)]
use setup::claims::setup_claim_complete_body;
#[cfg(test)]
use setup::claims::setup_claim_create_body;
use setup::claims::stage_local_release;
use setup::claims::stage_pending_device_credential;
#[cfg(test)]
use setup::claims::stage_pending_device_credential_with_stores;
#[cfg(test)]
use setup::claims::stage_pending_setup_run_token;
#[cfg(test)]
use setup::claims::stage_pending_setup_run_token_with_store;
pub(crate) use setup::claims::try_lock_setup_run_binding;
use setup::claims::validate_pending_candidate_secret;
use setup::claims::validate_pending_prior_credential_binding;
#[cfg(test)]
use setup::claims::write_and_verify_active_device_credential;
#[cfg(test)]
use setup::claims::ClaimRelayDeviceCredential;
pub(crate) use setup::claims::CredentialAuthority;
#[cfg(test)]
use setup::claims::HistoryStores;
#[cfg(test)]
use setup::claims::LocalReleaseMarker;
use setup::claims::StoredHistoryBrowserClaim;
#[cfg(test)]
use setup::claims::StoredRevocationReceipt;
#[cfg(test)]
use setup::claims::IDENTITY_MUTATION_RESERVATION;
#[cfg(test)]
use setup::claims::REVOCATION_RECEIPT_MAX_AGE_SECONDS;
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
use status::install_variant_conflict;
#[cfg(test)]
use status::install_variant_conflict_in;
use status::local_lifecycle_home;
use status::operating_system_slug;
pub(crate) use status::probe_idle_device_credential;
#[cfg(test)]
pub(crate) use status::probe_idle_device_credential_with;
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
pub(crate) use status::IdleCredentialCheck;
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
    let cli_session_exec = request.client_kind == Some(LocalClientKind::Cli);
    let admitted = policy::admit(
        &policy::policy(&request.command),
        cli_session_exec,
        &authorization,
        daemon,
    );
    match admitted.and_then(|()| {
        let client_install_owner = request
            .client_install_owner
            .unwrap_or(InstallOwner::Unknown);
        handle_command(
            daemon,
            authorization,
            request.command,
            client_install_owner,
            cli_session_exec,
        )
    }) {
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
    cli_session_exec: bool,
) -> Result<serde_json::Value, LocalApiError> {
    #[cfg(test)]
    crate::test_effects::record(
        "control_dispatch_entered",
        vec![(
            "trusted_companion",
            crate::test_effects::Scalar::Bool(
                authorization == RequestAuthorization::TrustedCompanionApp,
            ),
        )],
    );
    // Invalidate pending handoffs before any explicit account/slot mutation.
    // Existing mutation handlers retain all of their authorization and order.
    if policy::policy(&command).changes_identity {
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
            require_cli_token(cli_session_exec, &authorization)?;
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
            require_cli_token(cli_session_exec, &authorization)?;
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
                refresh_agent_status_for(daemon, &authorization, None)?;
            }
            let mut status = status_for(daemon, &authorization)?;
            status.update.install_owner = detect_install_owner();
            // Doctor (`retry_relay_authorization`) and refresh requests probe launchd live.
            status.service_owner = if retry_relay_authorization || refresh_agent_status {
                service_owner_state(client_install_owner)
            } else {
                status::cached_service_owner_state(client_install_owner)
            };
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
            if retry_relay_authorization {
                if let Some(conflict) = install_variant_conflict(detect_install_owner()) {
                    value["install_variants"] = conflict;
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
                    || request_explicit_quota_refresh(source.as_ref()),
                );
            }
            to_value(refresh_agent_status_for(daemon, &authorization, source)?)
        }
        LocalControlCommand::AgentStatusCached { source } => {
            // Unlike the usual authorization helper, this skips the daemon-state
            // poison check: the cached read uses no daemon state.
            require_local_caller(daemon, &authorization)?;
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
        command @ (LocalControlCommand::CloudConnectStatus { .. }
        | LocalControlCommand::CloudConnectEnsure { .. }
        | LocalControlCommand::CloudConnectSubmit { .. }
        | LocalControlCommand::CloudConnectPoll { .. }
        | LocalControlCommand::CloudConnectCancel { .. }) => {
            Ok(cloud_connect::dispatch_agent(daemon, command))
        }
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
                RequestAuthorization::Untrusted | RequestAuthorization::DaemonInternal => {
                    Err(LocalApiError::LocalClientNotTrusted)
                }
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
                RequestAuthorization::Untrusted | RequestAuthorization::DaemonInternal => {
                    Err(LocalApiError::LocalClientNotTrusted)
                }
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
            // Only a request caller may uninstall: refuse the daemon's own
            // caller before the shared check admits it and before any work.
            if authorization == RequestAuthorization::DaemonInternal {
                return Err(LocalApiError::LocalClientNotTrusted);
            }
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
                RequestAuthorization::Untrusted | RequestAuthorization::DaemonInternal => {
                    return Err(LocalApiError::LocalClientNotTrusted)
                }
            }
            to_value(result)
        }
    }
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

#[cfg(test)]
pub(crate) mod tests;

#[cfg(all(test, unix))]
#[path = "control/tests/control_smoke_session_tests.rs"]
mod smoke_session_tests;
