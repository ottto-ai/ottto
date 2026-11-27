mod account_nicknames;
pub mod active_sessions;
pub mod adaptive_collector;
pub mod agent_configs;
pub mod agent_status;
pub mod agent_status_refresh;
mod app_bundle_version;
pub mod backfill;
pub mod canonical_json;
pub mod claude_browser_auth;
mod claude_desktop;
pub mod claude_local_otel;
pub(crate) mod claude_refresher;
mod claude_session_registrations;
mod claude_shell_telemetry;
pub(crate) mod claude_spawn_gate;
pub mod claude_upkeep;
pub mod client_report;
pub mod cloud_sessions;
pub mod codex_prelude_footprint;
mod codex_process_homes;
mod codex_scan_diagnostics;
pub mod codex_sign_in;
mod collection_health;
pub(crate) mod command_env;
mod composition_kinds;
pub mod context_composition;
mod context_file_counts;
pub mod context_footprint;
pub mod context_posture;
pub mod control;
pub mod control_plane_health;
mod desktop_recent;
pub mod detected_uses;
mod durable_tail_codec;
#[cfg(unix)]
mod external_scheduler_attribution;
mod grant_rebind;
mod hex;
pub mod homebrew_step_aside;
mod instruction_inventory;
mod internal_session;
pub mod keychain;
mod launch_events;
pub mod legacy_service;
mod local_resource_diagnostics;
#[cfg(unix)]
mod local_state_sweep;
#[cfg(unix)]
pub mod locked_state_dir;
mod loopback_base;
pub mod macos_service;
pub mod mcp_inventory;
pub(crate) mod net_resilience;
pub mod net_transition;
pub mod otlp_relay;
#[cfg(unix)]
pub(crate) mod process_guard;
pub(crate) mod provider_calls;
pub mod provider_daily_reference;
pub(crate) mod quota_credit_model;
mod relay_auth;
mod retry_tls;
mod scan_clock;
pub mod session_attribution;
pub mod session_launch;
pub mod snapshot_audit;
pub mod snapshot_client;
pub(crate) mod snapshot_retry;
mod snapshot_roots;
pub mod snapshot_sync;
pub mod snapshot_watcher;
pub mod snapshots;
mod source_rotation;
pub mod telemetry_attach;
#[cfg(test)]
mod test_effects;
#[cfg(test)]
mod test_isolation;
#[cfg(test)]
mod test_scratch;
mod tracking_confirmation;
mod transcript_acquisition;
mod transcript_cache;
#[cfg(unix)]
pub mod unix_socket;
mod upload_policy;
pub mod upload_receipts;
pub mod xpc_mach;

pub use grant_rebind::{live_hardware_id, validated_hardware_id};

pub use local_resource_diagnostics::{log_startup_resources, rotate_service_log_at_startup};

#[cfg(unix)]
pub use local_state_sweep::{run_local_state_sweep_command, sweep_local_state_at_startup};
use ottto_core::compiled_release_version;
#[cfg(unix)]
pub use ottto_core::state_dir_lock;
mod daemon;
mod source_health;

use daemon::health::clear_local_health_upload_auth_rejection;
use daemon::health::clear_setup_run_read_rejection;
pub use daemon::health::current_rfc3339_timestamp;
#[cfg(test)]
pub(crate) use daemon::health::latest_local_health_upload;
#[cfg(test)]
use daemon::health::latest_local_health_upload_in;
#[cfg(test)]
use daemon::health::latest_setup_run_read_rejection;
#[cfg(test)]
pub(crate) use daemon::health::local_health_problem_code_slug;
use daemon::health::next_local_health_sequence;
use daemon::health::problem_detail_is_usage_limited;
use daemon::health::push_local_health_event;
pub use daemon::health::refresh_canonical_local_health;
use daemon::health::refresh_canonical_local_health_with_started_at;
use daemon::health::retain_latest_local_health_events;
#[cfg(test)]
use daemon::health::runtime_heartbeat_for_status;
#[cfg(test)]
use daemon::health::runtime_identity_for_status_with_installed_app_version;
use daemon::health::setup_run_read_revision;
pub(crate) use daemon::health::text_indicates_usage_limited;
#[cfg(test)]
use daemon::health::LatestLocalHealthUpload;
pub use daemon::health::LocalHealthUploadFailureKind;
pub(crate) use daemon::health::SetupRunReadStart;
use daemon::repair::config_backup_metadata;
pub use daemon::repair::diagnostics_local_only_upload_report;
use daemon::repair::no_repair_approval;
use daemon::repair::repair_authority_for_state;
use daemon::repair::setup_safe_repair_approval;
pub use daemon::repair::RepairLease;
pub use daemon::state::account_scope_from_uid;
pub use daemon::state::current_account_uid;
pub use daemon::state::local_account_scope;
pub use daemon::state::AccountSwitchCandidateInfo;
pub use daemon::state::BackendErrorDetails;
pub use daemon::state::BackendErrorKind;
use daemon::state::BlockerFirstSeen;
pub use daemon::state::ControlToken;
use daemon::state::DaemonState;
pub use daemon::state::LocalApiError;
pub use daemon::state::LocalDaemon;
pub use daemon::state::PendingAuthClaim;
pub use daemon::state::StagedAccountSwitch;
pub use daemon::state::ACCOUNT_NOT_FOUND_MESSAGE_CODE;
pub use daemon::status::effective_account_binding;
pub use daemon::status::personal_meter_local_snapshot_from_status;
use daemon::status::projected_scan_index_refusal;
#[cfg(test)]
use daemon::status::status_from_state_with_relay_finding;
#[cfg(test)]
pub(crate) use daemon::status::ACCOUNT_RECONNECT_REQUIRED_MESSAGE_CODE;
use daemon::verification::claude_connected_health;
use daemon::verification::has_verification_failure_problem;
use daemon::verification::is_codex_usage_read_retrying_problem;
use daemon::verification::is_usage_checks_paused_problem;
use daemon::verification::preserve_blocking_verification_state;
use daemon::verification::usage_checks_paused_problem;
#[cfg(test)]
use daemon::verification::verification_result_records_success;
pub(crate) use daemon::verification::AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE;
pub(crate) use daemon::verification::CLAUDE_OAUTH_REAUTH_REQUIRED_VERIFICATION_CODE;
use daemon::verification::CODEX_USAGE_CHECK_RETRYING_REASON;
use daemon::verification::CODEX_USAGE_READ_RETRYING_TITLE;
pub(crate) use daemon::verification::PI_DEFAULT_MODEL_TEXT;
#[cfg(test)]
use daemon::verification::PI_ROUTE_SMOKE_FAILED_MESSAGE_CODE;
pub(crate) use daemon::verification::SOURCE_NOT_INSTALLED_VERIFICATION_CODE;
use daemon::verification::USAGE_CHECKS_PAUSED_REASON;
use source_health::bound_user;
use source_health::detected_uses_for_health;
use source_health::load_source_state;
#[cfg(test)]
use source_health::merge_current_plan_quota;
#[cfg(test)]
use source_health::prune_detected_uses_for_health;
use source_health::quota_window_matches_snapshot_account;
use source_health::seed_registered_sources;
use source_health::source_descriptor;
use source_health::source_display_name;
#[cfg(test)]
use source_health::source_health_from_agent_status;
use source_health::source_slug;
use source_health::telemetry_configured_for_source;
use source_health::upsert_agent_status_snapshot;

include!("lib_tests.rs");

mod heap_layout_bound;
mod owned_heap;

#[cfg(test)]
mod retry_allocation_probe;

#[cfg(all(test, unix))]
mod scan_index_persistence_contract_tests;
