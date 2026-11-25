//! Agent status facade for Claude, Codex, and Pi collection.
//! Called by service status, setup, and session-launch consumers.
//! Preserves public paths and owns declarations retained for exact moves.

use crate::locked_state_dir::open_private_lock_file;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(test)]
use base64::Engine as _;
#[cfg(test)]
use ottto_core::claude_account_identifier_hash;
use ottto_core::{
    billing_identity_hash, compiled_release_version, default_support_dir,
    read_claude_statusline_cache, read_claude_statusline_context_cache,
    read_claude_statusline_context_history, ClaudeConfigDirSlot, ClaudeSlotAccountBinding,
    ClaudeStatusLineContextWindowCache, ClaudeStatusLineContextWindowHistory,
    ClaudeStatusLineContextWindowSample, ClaudeStatusLineRateLimitCache,
    CodexAccountSlotSettingsError, CodexHomeTrust, FileClaudeConfigSlotSettingsStore,
    FileCodexAccountSlotSettingsStore, MAX_CLAUDE_ACCOUNT_SLOTS,
};
use ottto_protocol::{
    AgentAccountStatus, AgentAvailableModelStatus, AgentCapabilityGap, AgentCapabilityStatus,
    AgentContextCompleteness, AgentContextPressureSample, AgentContextState, AgentContextStatus,
    AgentCreditBalance, AgentCreditBalanceStatus, AgentCreditBalanceUnit, AgentDiagnosticSeverity,
    AgentLoginState, AgentModelStatus, AgentQuotaWindow, AgentQuotaWindowFreshness,
    AgentQuotaWindowScope, AgentQuotaWindowStatus, AgentRuntimeDefaults,
    AgentStatusCollectionMethod, AgentStatusConfidence, AgentStatusDiagnostic,
    AgentStatusPlanObservation, AgentStatusSnapshot, AgentStatusState,
    ClaudeAccountAnchorCoverageV1, ClaudeAccountAnchorDescriptorV1,
    ClaudeAccountAnchorDurabilityV1, ClaudeAccountAnchorHealthV1,
    ClaudeAccountAnchorSetupBlockerV1, ClaudeAccountsStatusV1, ClaudeConfigSlotAccountProfileV1,
    ClaudeConfigSlotCollectionStateV1, ClaudeConfigSlotCollectionStatusV1,
    ClaudeConfigSlotDescriptorV1, ClaudeConfigSlotDiagnosticCodeV1, ClaudeConfigSlotDiagnosticV1,
    ClaudeConfigSlotOwnership, ClaudeConfigSlotQuotaSnapshotStateV1,
    ClaudeConfigSlotQuotaSnapshotV1, ClaudeConfigSlotUpkeepResultV1, ClaudeQuotaAccessState,
    ClaudeUnresolvedAccountDescriptorV1, ClaudeUnresolvedAccountEvidenceKind,
    CodexAccountSlotCollectionStateV1, CodexAccountSlotCollectionStatusV1,
    CodexAccountSlotDescriptorV1, CodexAccountSlotDiagnosticV1, CodexAccountSlotOwnershipV1,
    CodexAccountSlotQuotaSnapshotV1, CodexAccountSlotRelationshipV1, CodexAccountTargetCoverageV1,
    CodexAccountTargetDescriptorV1, CodexAccountTargetDurabilityV1, CodexAccountTargetHealthV1,
    CodexAccountTargetSetupBlockerV1, CodexAccountsStatusV1, CreditAmount, SourceKind,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::{
    format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime, UtcOffset,
};

/// The durable owner-only status files (fsync kept, identical bytes skipped),
/// counted as durable small-file writes.
fn write_owner_only_file_atomic_if_changed(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    crate::locked_state_dir::replace_owner_only_file_counted(
        path,
        bytes,
        true,
        crate::locked_state_dir::SmallFileClass::Durable,
    )
}

mod claude;
mod codex;
mod collect;
mod pi;
mod redaction;
mod selection;
mod types;
#[cfg(test)]
use claude::collect::apply_claude_statusline_context_provenance;
use claude::collect::apply_claude_token_owner;
#[cfg(test)]
use claude::collect::bind_claude_relogin_warning;
#[cfg(test)]
use claude::collect::claude_alternative_auth;
pub(crate) use claude::collect::claude_alternative_auth_layers;
pub(crate) use claude::collect::claude_refresher_skip_reason;
#[cfg(test)]
use claude::collect::claude_runtime_defaults_from_paths;
use claude::collect::claude_settings_failure_bound_exceeded;
#[cfg(test)]
use claude::collect::claude_settings_failure_outlasted;
use claude::collect::collect_claude_status;
use claude::collect::load_claude_slot_settings_for_pass;
use claude::collect::prove_claude_token_owner;
#[cfg(test)]
use claude::collect::resolve_claude_default_home_owner;
pub(crate) use claude::collect::ClaudeAlternativeAuth;
use claude::collect::ClaudeTokenOwner;
#[cfg(test)]
use claude::collect::CLAUDE_SETTINGS_FAILURE_BOUND_PASSES;
use claude::desktop::append_claude_desktop_pairs_snapshot;
use claude::desktop::append_claude_desktop_plan_observations;
use claude::desktop::claude_cli_config_path;
pub(crate) use claude::desktop::claude_default_account_fingerprint;
#[cfg(test)]
use claude::desktop::claude_desktop_builder_plan_observation;
use claude::desktop::claude_desktop_metadata_present;
#[cfg(test)]
use claude::desktop::claude_desktop_pair_observation;
#[cfg(test)]
use claude::desktop::claude_desktop_pairs_snapshot;
#[cfg(test)]
use claude::desktop::claude_desktop_plan_observations_from_root;
use claude::desktop::claude_desktop_scan_from_root;
use claude::desktop::claude_desktop_support_dir;
#[cfg(test)]
use claude::desktop::claude_desktop_unambiguous_duplicate_session_owners;
pub(crate) use claude::login::claude_credential_modified_marker;
use claude::login::claude_credentials_in_keychain;
#[cfg(test)]
use claude::login::claude_gate_credential;
use claude::login::claude_local_login_state;
#[cfg(test)]
use claude::login::claude_oauth_account_identifier_hash_for;
#[cfg(test)]
use claude::login::claude_oauth_keychain_lookup_arguments;
use claude::login::claude_oauth_usage_cache_path;
use claude::login::claude_oauth_usage_error;
use claude::login::claude_oauth_usage_legacy_cache_path;
use claude::login::claude_strong_oauth_identity_hashes;
use claude::login::effective_user_account_name;
#[cfg(unix)]
use claude::login::effective_user_identity;
#[cfg(not(unix))]
use claude::login::effective_user_identity;
use claude::login::parse_claude_auth_json;
#[cfg(test)]
use claude::login::parse_claude_cli_oauth_account;
#[cfg(test)]
use claude::login::parse_claude_oauth_access_token;
#[cfg(test)]
use claude::login::parse_claude_oauth_credential;
#[cfg(test)]
use claude::login::parse_claude_oauth_credential_read;
use claude::login::read_claude_cli_oauth_account;
#[cfg(unix)]
#[cfg(test)]
use claude::login::read_claude_credentials_file;
#[cfg(not(unix))]
#[cfg(test)]
use claude::login::read_claude_credentials_file;
pub(crate) use claude::login::read_claude_live_login_for_slot;
use claude::login::read_claude_oauth_credential_for_slot;
#[cfg(test)]
use claude::login::read_claude_oauth_credential_from_keychain_with_timeout;
#[cfg(test)]
pub(crate) use claude::login::read_claude_oauth_credential_metadata_for_slot;
use claude::login::read_claude_oauth_credential_state_for_slot;
#[cfg(test)]
use claude::login::read_claude_oauth_credential_state_from_store;
pub(crate) use claude::login::read_claude_spawn_gate_credential;
use claude::login::refine_claude_local_plan_metadata;
#[cfg(test)]
use claude::login::refine_claude_max_rate_limit_plan;
use claude::login::require_claude_auth_identity_agreement;
pub(crate) use claude::login::resolved_claude_slot_command;
pub(crate) use claude::login::session_launch_claude_identity;
pub(crate) use claude::login::session_launch_claude_login_state;
use claude::login::stable_claude_slot_credential;
use claude::login::stamp_claude_cli_account_identity;
use claude::login::ClaudeCliOauthAccount;
#[cfg(test)]
use claude::login::ClaudeKeychainRead;
use claude::oauth_cache::claude_account_session_not_offered_capability;
use claude::oauth_cache::claude_account_weekly_not_offered_capability;
use claude::oauth_cache::claude_has_account_windows;
use claude::oauth_cache::claude_oauth_account_session_not_offered;
use claude::oauth_cache::claude_oauth_account_weekly_not_offered;
use claude::oauth_cache::claude_oauth_credit_balances;
use claude::oauth_cache::claude_oauth_credit_balances_and_refusals;
use claude::oauth_cache::claude_oauth_money_cents;
#[cfg(test)]
use claude::oauth_cache::claude_oauth_quota_window;
use claude::oauth_cache::claude_oauth_quota_windows;
use claude::oauth_cache::claude_oauth_retry_after_epoch_seconds;
#[cfg(test)]
use claude::oauth_cache::claude_oauth_usage_cache_belongs_to_identity;
use claude::oauth_cache::claude_oauth_usage_from_cache;
use claude::oauth_cache::claude_snapshot_account_session_not_offered;
use claude::oauth_cache::claude_snapshot_account_weekly_not_offered;
use claude::oauth_cache::claude_snapshot_has_account_windows;
use claude::oauth_cache::fresh_quota_windows;
pub(crate) use claude::oauth_cache::ottto_user_agent;
#[cfg(test)]
use claude::oauth_cache::read_claude_oauth_usage_cache;
use claude::oauth_cache::read_claude_oauth_usage_cache_with_legacy_migration;
use claude::oauth_cache::write_claude_oauth_usage_cache;
use claude::oauth_schedule::claude_background_read_withheld;
#[cfg(test)]
use claude::oauth_schedule::claude_explicit_refresh_attempts;
use claude::oauth_schedule::claude_explicit_refresh_request;
use claude::oauth_schedule::claude_explicit_refresh_requested;
pub(crate) use claude::oauth_schedule::claude_next_reset_read_at;
use claude::oauth_schedule::claude_oauth_activity;
use claude::oauth_schedule::claude_oauth_end_caller_run;
use claude::oauth_schedule::claude_oauth_end_slot_run;
use claude::oauth_schedule::claude_oauth_pass_reached_collector;
use claude::oauth_schedule::claude_oauth_passive_config;
use claude::oauth_schedule::claude_oauth_usage_fresh_age_seconds;
use claude::oauth_schedule::claude_oauth_usage_record_reading;
use claude::oauth_schedule::claude_oauth_usage_serve_gate_seconds;
use claude::oauth_schedule::claude_oauth_usage_slot_seconds;
pub(crate) use claude::oauth_schedule::claude_pass_saved_only;
use claude::oauth_schedule::claude_quota_check_diagnostic;
use claude::oauth_schedule::claude_rate_limit_held;
use claude::oauth_schedule::claude_rate_limit_holds;
use claude::oauth_schedule::claude_statusline_fresh_for_binding;
use claude::oauth_schedule::claude_transient_failure_held;
use claude::oauth_schedule::claude_transient_failures;
use claude::oauth_schedule::note_claude_explicit_refresh_attempt;
pub(crate) use claude::oauth_schedule::request_claude_explicit_refresh;
use claude::oauth_schedule::set_claude_binding_time;
pub(crate) use claude::oauth_schedule::with_claude_pass;
#[cfg(test)]
use claude::oauth_schedule::ClaudeBindingTime;
#[cfg(test)]
use claude::oauth_schedule::ClaudeExplicitRefreshRequest;
use claude::oauth_schedule::ClaudeOAuthCollectionPass;
use claude::oauth_schedule::ClaudeOAuthReading;
use claude::oauth_schedule::ClaudePass;
use claude::oauth_schedule::CLAUDE_BACKGROUND_REFRESH_OFF_MESSAGE;
use claude::oauth_schedule::CLAUDE_OAUTH_CALLER_BINDINGS;
#[cfg(test)]
use claude::oauth_schedule::CLAUDE_OAUTH_PASS_CALLERS;
#[cfg(test)]
use claude::oauth_schedule::CLAUDE_TRANSIENT_FAILURE_RETRY_SECONDS;
use claude::oauth_state::claude_oauth_account_state_lock;
use claude::oauth_state::claude_oauth_binding_key;
use claude::oauth_state::claude_oauth_usage_account_state_dir;
#[cfg(test)]
use claude::oauth_state::claude_oauth_usage_breaker_after_auth_failure;
#[cfg(test)]
use claude::oauth_state::claude_oauth_usage_breaker_after_failure;
use claude::oauth_state::claude_oauth_usage_breaker_is_open;
#[cfg(test)]
use claude::oauth_state::claude_oauth_usage_breaker_path;
use claude::oauth_state::claude_oauth_usage_caller_auth_hold;
use claude::oauth_state::claude_oauth_usage_caller_auth_hold_diagnostic;
use claude::oauth_state::claude_oauth_usage_circuit_open_diagnostic;
use claude::oauth_state::claude_oauth_usage_config_fingerprint;
use claude::oauth_state::claude_oauth_usage_failure_class;
use claude::oauth_state::claude_oauth_usage_legacy_breaker_path;
pub(crate) use claude::oauth_state::claude_oauth_usage_network_disabled;
use claude::oauth_state::claude_oauth_usage_opaque_caller_key;
use claude::oauth_state::claude_oauth_usage_slot_caller_key;
#[cfg(test)]
pub(crate) use claude::oauth_state::clear_claude_oauth_usage_auth_breaker;
#[cfg(test)]
use claude::oauth_state::clear_claude_oauth_usage_breaker;
use claude::oauth_state::clear_claude_oauth_usage_breaker_after_success;
use claude::oauth_state::read_claude_oauth_usage_breaker;
use claude::oauth_state::record_claude_oauth_usage_auth_failure;
use claude::oauth_state::record_claude_oauth_usage_failure;
use claude::oauth_state::try_claude_oauth_collection_attempt;
use claude::oauth_usage::claude_oauth_stamp_account_identity;
#[cfg(test)]
use claude::oauth_usage::claude_slot_after_pre_gate_hook;
#[cfg(test)]
use claude::oauth_usage::collect_claude_oauth_usage_with_access_token;
use claude::oauth_usage::collect_claude_oauth_usage_with_credential;
#[cfg(test)]
use claude::oauth_usage::ClaudeOAuthTestResponder;
#[cfg(test)]
use claude::oauth_usage::ClaudeSlotTestHook;
use claude::oauth_usage::CLAUDE_OAUTH_USAGE_RATE_LIMITED_CODE;
use claude::oauth_usage::CLAUDE_OAUTH_USAGE_RATE_LIMITED_SAVED_RESETS_MESSAGE;
use claude::oauth_usage::CLAUDE_OAUTH_USAGE_RATE_LIMITED_USAGE_MESSAGE;
use claude::oauth_usage::CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_CODE;
use claude::oauth_usage::CLAUDE_SAVED_RESET_VARIANT_UNRECOGNIZED_MESSAGE;
#[cfg(test)]
use claude::selection::append_canonical_anchor_worker_receipts;
#[cfg(test)]
use claude::selection::apply_claude_anchor_continuity;
use claude::selection::bounded_claude_custom_descriptors;
#[cfg(test)]
use claude::selection::claude_breaker_auth_pause_until;
#[cfg(test)]
use claude::selection::claude_custom_slot_needs_attention;
pub(crate) use claude::selection::claude_default_check_skipped;
#[cfg(test)]
use claude::selection::claude_default_full_meter_needs_attention;
#[cfg(test)]
use claude::selection::claude_default_snapshot_is_uploadable;
#[cfg(test)]
use claude::selection::claude_default_upload_withheld;
#[cfg(test)]
use claude::selection::claude_paused_usage_accounts;
#[cfg(test)]
use claude::selection::claude_registered_owned_bindings;
#[cfg(test)]
use claude::selection::claude_runtime_defaults_carrier;
#[cfg(test)]
use claude::selection::claude_setup_snapshot_index;
#[cfg(test)]
use claude::selection::claude_snapshot_candidate_rank;
#[cfg(test)]
use claude::selection::claude_stale_saved_slot_states;
#[cfg(test)]
use claude::selection::claude_uploaded_candidate_snapshot;
#[cfg(test)]
use claude::selection::claude_usage_checks_paused_diagnostics;
use claude::selection::collect_claude_status_snapshots;
#[cfg(test)]
use claude::selection::strip_slot_owned_plan_observations;
#[cfg(test)]
use claude::selection::ClaudePausedUsageAccount;
pub(crate) use claude::selection::CLAUDE_OTTTO_SIGNED_IN;
pub(crate) use claude::selection::CLAUDE_USAGE_CHECKS_PAUSED_DIAGNOSTIC_CODE;
pub(crate) use claude::slot_state::annotate_claude_accounts_status;
use claude::slot_state::bounded_claude_collection_timestamp;
#[cfg(test)]
use claude::slot_state::claude_anchor_target_id;
#[cfg(test)]
use claude::slot_state::claude_slot_collection_state_path;
#[cfg(test)]
use claude::slot_state::derive_claude_account_anchor_coverage;
use claude::slot_state::derive_unresolved_claude_accounts;
#[cfg(test)]
use claude::slot_state::merge_claude_slot_collection_state;
#[cfg(test)]
use claude::slot_state::merge_claude_slot_collection_state_at;
use claude::slot_state::persist_claude_slot_collection_states;
pub(crate) use claude::slot_state::persist_one_claude_slot_collection_state;
#[cfg(test)]
use claude::slot_state::persist_one_claude_slot_collection_state_with;
use claude::slot_state::projected_claude_anchor_health;
pub(crate) use claude::slot_state::prune_claude_slot_collection_state;
#[cfg(test)]
pub(crate) use claude::slot_state::publish_blocked_claude_slot_for_test;
use claude::slot_state::read_persisted_claude_slot_collection_state;
#[cfg(test)]
use claude::slot_state::record_claude_anchor_transitions;
#[cfg(test)]
use claude::slot_state::retain_claude_worker_receipt_for_blocked_candidate;
#[cfg(test)]
use claude::slot_state::write_persisted_claude_slot_collection_state;
use claude::slot_status::apply_claude_quota_access_state;
use claude::slot_status::apply_claude_slot_approval_notice;
use claude::slot_status::apply_claude_worker_needs_login_state;
use claude::slot_status::claude_config_slot_for_descriptor;
use claude::slot_status::claude_oauth_plan_type_for_label;
#[cfg(test)]
use claude::slot_status::claude_plan_label;
use claude::slot_status::claude_plan_name;
use claude::slot_status::claude_retained_snapshot_relabelled;
use claude::slot_status::claude_slot_approval_blocked_status;
use claude::slot_status::claude_slot_approvals;
#[cfg(test)]
use claude::slot_status::claude_slot_binding_mismatch_message;
use claude::slot_status::claude_slot_binding_mismatch_status;
pub(crate) use claude::slot_status::claude_slot_login_unapproved;
use claude::slot_status::claude_slot_owner_unproven_message;
use claude::slot_status::claude_slot_post_resolution_gate;
use claude::slot_status::claude_slot_pre_collection_gate;
use claude::slot_status::claude_slot_status_carries_meters;
use claude::slot_status::claude_slot_unknown_login_message;
use claude::slot_status::claude_usage_has_exact_identity;
#[cfg(test)]
use claude::slot_status::clear_claude_slot_binding;
#[cfg(test)]
use claude::slot_status::degraded_claude_slot_snapshot;
use claude::slot_status::degraded_claude_slot_snapshots;
#[cfg(test)]
use claude::slot_status::exact_claude_slot_account_profile;
use claude::slot_status::inherit_claude_slot_account_profile;
use claude::slot_status::local_claude_quota_snapshot;
use claude::slot_status::local_claude_quota_snapshot_is_fresh_for_account;
use claude::slot_status::local_claude_quota_snapshot_within_retention;
use claude::slot_status::mark_quota_meters_stale;
use claude::slot_status::projected_claude_quota_access_state;
use claude::slot_status::remember_claude_slot_account_profile;
use claude::slot_status::retain_exact_claude_slot_binding;
#[cfg(test)]
use claude::slot_status::retain_previous_complete_claude_read;
use claude::slot_status::retain_registered_claude_slot_binding;
use claude::slot_status::retain_verified_claude_binding;
use claude::slot_status::retain_verified_claude_slot_binding;
use claude::slot_status::safe_claude_slot_check_diagnostics;
use claude::slot_status::stale_local_claude_quota_snapshot;
#[cfg(test)]
use claude::slot_status::CLAUDE_BLOCKED_REFRESH_FAILURE_WORKER_CODES;
use claude::slot_status::CLAUDE_CACHE_REUSED_MESSAGE;
#[cfg(test)]
use claude::slots::append_claude_worker_diagnostic;
use claude::slots::claude_account_from_local_metadata;
pub(crate) use claude::slots::claude_auth_ceremony_witness;
use claude::slots::claude_local_plan_facts_contradict;
use claude::slots::claude_owner_call_allowed;
use claude::slots::claude_slot_owned_usage_bindings;
use claude::slots::claude_slot_owner_rule;
use claude::slots::claude_worker_diagnostic_message;
#[cfg(test)]
use claude::slots::claude_worker_receipt_status;
pub(crate) use claude::slots::collect_registered_claude_slot_status;
use claude::slots::collect_registered_claude_slot_step;
#[cfg(test)]
use claude::slots::custom_claude_snapshot_from_usage;
use claude::slots::ordered_claude_slot_descriptors;
use claude::slots::read_claude_slot_locally;
use claude::slots::read_registered_claude_slot_locally;
#[cfg(test)]
pub(crate) use claude::slots::reconcile_registered_claude_valid_access;
#[cfg(test)]
use claude::slots::reconciled_valid_access_status;
#[cfg(test)]
use claude::slots::reconciled_valid_access_status_with_worker_receipt;
#[cfg(test)]
pub(crate) use claude::slots::record_registered_claude_worker_observation;
#[cfg(test)]
use claude::slots::resolve_registered_claude_slot;
#[cfg(test)]
use claude::slots::resolve_registered_claude_slot_from_local;
#[cfg(test)]
use claude::slots::valid_access_reconciliation_due;
pub(crate) use claude::slots::verify_claude_local_identity;
#[cfg(test)]
pub(crate) use claude::slots::ClaudeLocalIdentityFailure;
pub(crate) use claude::slots::ClaudeLocalIdentityProof;
use claude::slots::ClaudeSlotCollectionStep;
use claude::slots::ClaudeSlotOwnerRule;
#[cfg(test)]
use claude::slots::ClaudeWorkerDiagnostic;
use claude::statusline::claude_account_identifier_hashes_from_observations;
#[cfg(test)]
use claude::statusline::claude_statusline_attribution_failure;
#[cfg(test)]
use claude::statusline::claude_statusline_context_from_cache;
#[cfg(test)]
use claude::statusline::claude_statusline_quota_windows_from_cache;
use claude::statusline::collect_claude_statusline_context_status;
use claude::statusline::collect_claude_statusline_quota_windows;
use claude::statusline::prefer_newer_exact_claude_statusline_windows;
use claude::statusline::ClaudeStatusLineQuota;
#[cfg(test)]
use claude::statusline::ClaudeStatusLineUnattributable;
use claude::upkeep::append_claude_upkeep_result_receipt;
use claude::upkeep::apply_claude_upkeep_observation;
use claude::upkeep::apply_credential_metadata;
use claude::upkeep::blocked_claude_upkeep_status;
use claude::upkeep::capacity_exceeded_status;
#[cfg(test)]
use claude::upkeep::claude_default_slot_collection_status;
use claude::upkeep::claude_relogin_warning;
use claude::upkeep::collection_in_progress_status;
use claude::upkeep::collection_paused_status;
use claude::upkeep::default_claude_identity_diagnostic;
#[cfg(test)]
use claude::upkeep::duplicate_account_status;
use claude::upkeep::fresh_slot_status;
use claude::upkeep::paused_claude_refresh_status;
use claude::upkeep::prepare_default_claude_slot_status;
use claude::upkeep::provider_unavailable_status;
use claude::upkeep::registered_claude_failure_status;
#[cfg(test)]
pub(crate) use claude::upkeep::registered_claude_race_status_for_test;
use claude::upkeep::upkeep_state_diagnostic;
#[cfg(test)]
use codex::app_server::call_codex_app_server_rate_limits;
#[cfg(test)]
use codex::app_server::call_codex_app_server_rate_limits_for_home;
#[cfg(test)]
use codex::app_server::codex_app_server_auth_rejected;
#[cfg(test)]
use codex::app_server::codex_app_server_rpc_failure;
use codex::app_server::codex_app_server_success_diagnostic;
#[cfg(test)]
use codex::app_server::codex_app_server_test_timeouts;
pub(crate) use codex::app_server::codex_child_drain;
#[cfg(test)]
use codex::app_server::codex_credit_binding;
#[cfg(test)]
use codex::app_server::codex_reset_credit_detail_summary;
#[cfg(test)]
use codex::app_server::codex_usage_probe_from_app_server_observation;
use codex::app_server::collect_codex_app_server_usage_for_home;
#[cfg(test)]
use codex::app_server::read_bounded_codex_app_server_stdout;
#[cfg(test)]
pub(crate) use codex::app_server::with_codex_app_server_test_timeouts;
#[cfg(test)]
use codex::app_server::CodexAppServerObservation;
#[cfg(test)]
use codex::app_server::CodexAppServerTestTimeouts;
pub(crate) use codex::app_server::CODEX_CHILD_DRAIN;
use codex::app_server::CODEX_CLI_NOT_FOUND_FOR_PROBE;
pub(crate) use codex::bindings::annotate_codex_accounts_status;
use codex::bindings::apply_codex_candidate_statuses;
use codex::bindings::canonicalize_codex_candidates;
use codex::bindings::codex_candidate_is_better;
#[cfg(test)]
use codex::bindings::codex_collection_status_from_snapshot;
use codex::bindings::codex_home_slots;
use codex::bindings::codex_home_slots_checked;
#[cfg(test)]
use codex::bindings::codex_local_slot_status;
#[cfg(test)]
use codex::bindings::codex_slot_status_binding;
use codex::bindings::collect_codex_home_candidate;
use codex::bindings::collect_codex_slot_candidates;
pub(crate) use codex::bindings::collect_registered_codex_slot_for_setup;
pub(crate) use codex::bindings::daily_reference_homes;
#[cfg(test)]
use codex::bindings::derive_codex_account_target_coverage;
use codex::bindings::empty_codex_accounts_status;
#[cfg(test)]
use codex::bindings::enforce_codex_registered_binding;
#[cfg(test)]
pub use codex::bindings::parse_codex_status_fallback;
pub(crate) use codex::bindings::session_launch_codex_accounts_status;
#[cfg(test)]
use codex::bindings::session_launch_codex_candidate;
pub(crate) use codex::bindings::CodexSetupRead;
pub(crate) use codex::bindings::CodexSlotSetupCollectionError;
pub(crate) use codex::bindings::DailyReferenceHome;
use codex::collect::append_codex_credential_read_failed_diagnostic;
#[cfg(test)]
use codex::collect::append_configured_codex_unavailable_snapshots;
#[cfg(test)]
use codex::collect::append_failed_default_codex_snapshot;
use codex::collect::apply_codex_dead_login;
use codex::collect::claude_version_detected;
use codex::collect::cli_binary_stamp;
#[cfg(test)]
use codex::collect::cli_meta;
#[cfg(test)]
use codex::collect::codex_canonical_identity_spelling;
#[cfg(test)]
use codex::collect::codex_cli_meta;
use codex::collect::codex_last_known_slot_reading;
use codex::collect::codex_probe_failed_only;
#[cfg(test)]
use codex::collect::codex_source_health_snapshot;
#[cfg(test)]
use codex::collect::codex_status_selection;
#[cfg(test)]
use codex::collect::collect_codex_model_status_from_output;
use codex::collect::collect_codex_status_for_home;
use codex::collect::collect_codex_status_snapshots;
#[cfg(test)]
use codex::collect::collect_codex_usage_for_home;
use codex::collect::keep_failed_default_codex_binding;
use codex::collect::note_codex_scope_read;
#[cfg(test)]
use codex::collect::parse_codex_text_context;
#[cfg(test)]
use codex::collect::parse_codex_text_model;
#[cfg(test)]
use codex::collect::parse_codex_text_quota_windows;
use codex::collect::read_codex_usage_from_provider;
use codex::collect::remember_codex_last_known_reading;
#[cfg(test)]
use codex::collect::stamp_codex_meter_identity;
use codex::collect::CliMeta;
use codex::collect::CodexCliMeta;
#[cfg(test)]
use codex::collect::CLI_META_MAX_AGE;
use codex::login::chatgpt_subscription_product;
pub(crate) use codex::login::codex_access_token_claimed_account_hash;
use codex::login::codex_app_server_account;
use codex::login::codex_app_server_account_absent;
pub(crate) use codex::login::codex_cli_home;
pub(crate) use codex::login::codex_cli_home_claimed_account_hash;
use codex::login::codex_credential_claim_lapses_at;
use codex::login::codex_credential_claimed_account_hash;
use codex::login::codex_credential_claimed_binding;
pub(crate) use codex::login::codex_home_claimed_account_hash;
use codex::login::codex_identity_hashes;
pub(crate) use codex::login::codex_jwt_claimed_ids;
pub(crate) use codex::login::codex_login_command;
#[cfg(test)]
pub(crate) use codex::login::codex_slot_login_cause;
use codex::login::codex_workspace_target_evidence_from_id_token;
use codex::login::merge_codex_accounts;
use codex::login::normalize_plan_type;
use codex::login::parse_codex_account_text;
#[cfg(test)]
use codex::login::parse_codex_id_token_account;
use codex::login::read_codex_auth_account_at;
use codex::login::read_codex_auth_credentials_at;
use codex::login::read_codex_config_model_at;
pub(crate) use codex::login::registered_codex_creator_slots;
use codex::login::resolved_codex_home_command;
pub(crate) use codex::login::session_launch_codex_api_key_route;
pub(crate) use codex::login::session_launch_codex_identity;
pub(crate) use codex::login::structurally_valid_codex_jwt_claims;
use codex::login::validated_codex_identity;
use codex::quota::codex_app_server_credit_balances;
#[cfg(test)]
use codex::quota::codex_app_server_quota_window;
use codex::quota::codex_app_server_quota_windows;
use codex::quota::codex_app_server_rate_limit_snapshots;
use collect::append_codex_workspace_observations_at;
use collect::append_current_plan_observation;
use collect::append_registered_claude_plan_observations;
use collect::base_snapshot;
use collect::billing_identity_evidence_for;
pub(crate) use collect::claude_session_registrations;
pub(crate) use collect::collect_agent_status_collection;
pub(crate) use collect::collect_agent_status_collection_reusing;
use collect::default_codex_home;
use collect::executable_exists;
pub(crate) use collect::home_dir;
use collect::home_path;
use collect::not_installed_snapshot;
#[cfg(test)]
use collect::plan_observation_from_snapshot_account;
use collect::run_codex_home_command;
use collect::run_command_capture;
#[cfg(test)]
use collect::single_agent_status_collection;
#[cfg(test)]
use pi::collect_pi_model_status_from_output;
#[cfg(test)]
use pi::collect_pi_model_status_from_settings;
#[cfg(test)]
use pi::collect_pi_routes_from_settings;
use pi::collect_pi_status;
pub(crate) use pi::pi_agent_dir;
#[cfg(test)]
use pi::pi_agent_dir_from;
pub(crate) use pi::pi_identity_hints_for_route;
use pi::pi_route_classification;
pub(crate) use pi::pi_sessions_dir;
pub(crate) use pi::read_pi_agent_auth;
pub(crate) use pi::read_pi_smoke_routes;
use redaction::collect_model_names_from_json;
use redaction::command_diagnostic;
use redaction::command_output_text;
use redaction::current_unix_seconds;
use redaction::extract_email;
#[cfg(test)]
use redaction::extract_percent_before;
use redaction::extract_plan_type;
use redaction::file_modified_epoch_seconds;
use redaction::first_json_string;
use redaction::first_non_empty;
use redaction::json_bool;
use redaction::json_timestamp_rfc3339;
use redaction::json_u64;
use redaction::json_u8;
use redaction::looks_like_local_json_file;
use redaction::looks_like_model_name;
use redaction::looks_like_safe_model_id;
use redaction::nested_json_string;
use redaction::parse_yes_no;
use redaction::percent_quota_status;
use redaction::read_json_file;
use redaction::rfc3339_from_unix_seconds;
use redaction::rfc3339_minus_seconds;
use redaction::safe_display_label;
use redaction::safe_local_identifier;
use redaction::strip_secret_json;
use redaction::supported_capability;
use redaction::timestamp_value_epoch_seconds;
use redaction::unsupported_account;
use redaction::unsupported_capability;
use redaction::unsupported_context;
use redaction::unsupported_quota_window;
use selection::canonical_anchor_health;
use selection::canonical_registered_anchors;
use selection::claude_cross_binding_meter_collisions;
pub(crate) use selection::claude_slot_connection_usable;
#[cfg(test)]
use selection::claude_slot_projection_quality;
use selection::claude_snapshot_candidate_disposition;
use selection::claude_stale_cross_binding_meter_collisions;
use selection::quarantine_claude_cross_account_meters;
use selection::select_claude_snapshot_candidates;
pub(crate) use types::AgentStatusCollection;
pub(crate) use types::BillingIdentityHints;
use types::ClaudeCredentialRead;
use types::ClaudeDesktopAgentModeSessionMetadata;
use types::ClaudeDesktopCodeSessionMetadata;
use types::ClaudeDesktopConfig;
pub(crate) use types::ClaudeDesktopMetadataCache;
use types::ClaudeDesktopMetadataEntries;
use types::ClaudeDesktopPairBuilder;
use types::ClaudeDesktopPairKey;
use types::ClaudeDesktopPairObservation;
use types::ClaudeDesktopPairs;
use types::ClaudeDesktopProfileBuilder;
use types::ClaudeDesktopScan;
pub(crate) use types::ClaudeLiveLogin;
pub(crate) use types::ClaudeLocalLoginState;
use types::ClaudeOAuthCollectionAttemptGuard;
use types::ClaudeOAuthCredential;
pub(crate) use types::ClaudeOAuthCredentialMetadata;
use types::ClaudeOAuthUsage;
use types::ClaudeOAuthUsageAuthFailureRecord;
use types::ClaudeOAuthUsageBreaker;
use types::ClaudeOAuthUsageCache;
use types::ClaudeOAuthUsageCaller;
use types::ClaudeOAuthUsageCallerAuthState;
use types::ClaudeOAuthUsageFailure;
use types::ClaudeOAuthUsageOutcome;
use types::ClaudeSlotCollectionStateGuard;
use types::ClaudeSlotProbeFailure;
use types::ClaudeSnapshotCandidate;
use types::ClaudeSnapshotDisposition;
use types::ClaudeSnapshotQuality;
use types::ClaudeSnapshotSelection;
use types::ClaudeSnapshotSlotClass;
use types::ClaudeStrongBinding;
use types::CodexAuthCredentials;
use types::CodexCredentialReadError;
pub(crate) use types::CodexHomeBinding;
use types::CodexHomeSlot;
use types::CodexIdentityHashes;
use types::CodexQuotaRead;
use types::CodexSlotCandidate;
pub(crate) use types::CodexStrongIdentity;
use types::CodexUsageProbe;
use types::CodexWorkspaceTargetEvidence;
use types::CommandOutput;
use types::PersistedClaudeSlotCollectionStateV1;
pub(crate) use types::PiModelRoute;
pub(crate) use types::PiRouteClassification;
use types::ResolvedClaudeSlot;
use types::StableClaudeSlotCredential;
use types::AGENT_STATUS_UPLOAD_SNAPSHOT_MAX;
use types::CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS;
use types::CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE;
use types::CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION;
use types::CLAUDE_DESKTOP_AGENT_MODE_MAX_FILES_PER_ORG;
use types::CLAUDE_DESKTOP_CODE_SESSION_MAX_FILES_PER_ORG;
use types::CLAUDE_DESKTOP_DUPLICATE_SESSION_OBSERVATION_MAX;
use types::CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX;
#[cfg(test)]
use types::CLAUDE_OAUTH_BEFORE_SEND_HOOK;
use types::CLAUDE_OAUTH_BETA_HEADER;
use types::CLAUDE_OAUTH_COLLECTION_ATTEMPT_LOCKS;
use types::CLAUDE_OAUTH_LEGACY_MIGRATION_LOCK;
#[cfg(test)]
use types::CLAUDE_OAUTH_PROVIDER_CALLS;
#[cfg(test)]
use types::CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN;
use types::CLAUDE_OAUTH_USAGE_ACCOUNT_STATE_DIR;
use types::CLAUDE_OAUTH_USAGE_AUTH_BACKOFF_BASE_SECONDS;
use types::CLAUDE_OAUTH_USAGE_BREAKER_AUTH_THRESHOLD;
use types::CLAUDE_OAUTH_USAGE_BREAKER_COOLDOWN_SECONDS;
use types::CLAUDE_OAUTH_USAGE_BREAKER_FILE;
#[cfg(test)]
use types::CLAUDE_OAUTH_USAGE_BREAKER_RATE_LIMIT_THRESHOLD;
use types::CLAUDE_OAUTH_USAGE_BREAKER_SCHEMA_VERSION;
#[cfg(test)]
use types::CLAUDE_OAUTH_USAGE_BREAKER_SHAPE_THRESHOLD;
use types::CLAUDE_OAUTH_USAGE_CACHE_FILE;
use types::CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_JITTER_SECONDS;
use types::CLAUDE_OAUTH_USAGE_CACHE_FRESH_AGE_SECONDS;
use types::CLAUDE_OAUTH_USAGE_CACHE_MAX_AGE_SECONDS;
use types::CLAUDE_OAUTH_USAGE_CACHE_SCHEMA_VERSION;
use types::CLAUDE_OAUTH_USAGE_ENDPOINT;
use types::CLAUDE_OAUTH_USAGE_LEGACY_BREAKER_FILE;
use types::CLAUDE_OAUTH_USAGE_LEGACY_CACHE_FILE;
use types::CLAUDE_OAUTH_USAGE_LEGACY_CACHE_SCHEMA_VERSION;
pub(crate) use types::CLAUDE_OAUTH_USAGE_NETWORK_DISABLED_FILE;
use types::CLAUDE_OAUTH_USAGE_RAW_SLOT_CALLER_KEY_PREFIX;
use types::CLAUDE_OAUTH_USAGE_REFRESH_SECONDS;
use types::CLAUDE_OAUTH_USAGE_RETRY_AFTER_FALLBACK_SECONDS;
use types::CLAUDE_OAUTH_USAGE_SLOT_CALLER_KEY_PREFIX;
use types::CLAUDE_QUOTA_ACCESS_CAPABILITY;
use types::CLAUDE_SLOT_COLLECTION_STATE_LOCK;
use types::CLAUDE_STATUSLINE_CACHE_FRESH_AGE_SECONDS;
use types::CLAUDE_STATUSLINE_CACHE_MAX_AGE_SECONDS;
use types::CLAUDE_STATUSLINE_CONTEXT_HISTORY_RESPONSE_MAX_SAMPLES;
use types::CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS;
use types::CODEX_APP_SERVER_CHANNEL_CAPACITY;
use types::CODEX_APP_SERVER_MAX_LINE_BYTES;
use types::CODEX_APP_SERVER_MAX_MESSAGES;
use types::CODEX_APP_SERVER_MAX_TOTAL_BYTES;
#[cfg(test)]
use types::CODEX_APP_SERVER_RUNS;
use types::CODEX_APP_SERVER_TIMEOUT;
use types::COMMAND_TIMEOUT;
use types::MAX_AVAILABLE_MODELS;
use types::PIPE_DRAIN_TIMEOUT;

mod statics;
use statics::CLAUDE_PASS;
#[cfg(test)]
use statics::{CLAUDE_DESKTOP_JSON_READ_RECEIPT, CODEX_APP_SERVER_TEST_TIMEOUTS};

mod claude_credit_pools;
mod claude_token_owner;

/// Rest-heap diagnostics: homes with a remembered token verdict.
pub(crate) fn token_owner_entries() -> usize {
    claude_token_owner::owner_entries()
}
mod codex_credit_grants;
mod codex_last_known;
#[cfg(test)]
pub(crate) mod codex_login_oracle_support;
mod codex_probe_catalog;
mod codex_saved_quota;
mod codex_setup_gate;
mod credit_amount_input;

use codex_saved_quota::{path_stamp, PathStamp};

#[cfg(test)]
pub(crate) use codex_saved_quota::scheduled_round_now as codex_scheduled_round_now;
pub use codex_saved_quota::start_codex_quota_scheduler;
pub(crate) use codex_saved_quota::{
    adopt_saved_codex_reading, refresh_codex_quota_now, saved_codex_quota_generation,
    stop_codex_quota_scheduler, wake_codex_quota_scheduler, with_codex_home_read_lock,
    with_codex_home_read_lock_until,
};
#[cfg(test)]
pub(crate) use codex_setup_gate::SetupGateTestClock;

const CLAUDE_CONFIG_SLOT_COLLECTION_STATE_FILE: &str = "claude-config-slot-collection-state.json";

static CLAUDE_OAUTH_ACCOUNT_STATE_LOCKS: OnceLock<Mutex<BTreeMap<String, Arc<Mutex<()>>>>> =
    OnceLock::new();

type CliFacts<K, F, const N: usize> = crate::transcript_acquisition::StampedFacts<
    K,
    CliMeta<F>,
    [crate::transcript_acquisition::SourceStamp; N],
>;

static CODEX_CLI_META: OnceLock<Mutex<CliFacts<PathBuf, CodexCliMeta, 3>>> = OnceLock::new();
static CLAUDE_CLI_META: OnceLock<Mutex<CliFacts<PathBuf, (), 1>>> = OnceLock::new();

/// Prefix of a failed read's fixed text when its `account/read` named no
/// account before the rest of the session failed, or rejected the login
/// ([`codex_app_server_auth_rejected`]): the login is dead even though no
/// reading came back. A prefix keeps the stage, kind and code
/// parsing of [`codex_probe_failure_stage_and_kind`] intact.
const CODEX_NO_ACCOUNT_FAILURE_PREFIX: &str = "The provider named no signed-in user. ";
/// [`CODEX_NO_ACCOUNT_FAILURE_PREFIX`] when the provider rejected the login
/// itself (`account/read` refused it, or its refresh was refused with "sign in
/// again"), not merely named no account: the user's own default login needs
/// a new sign-in too. It starts with the no-account prefix, so every check of
/// that prefix keeps its meaning.
const CODEX_LOGIN_REJECTED_FAILURE_PREFIX: &str =
    "The provider named no signed-in user. Codex asked to sign in again. ";

/// `slot_owned_bindings` names exact account+organization bindings that a
/// registered managed slot has proved it reads (see
/// `claude_slot_owned_usage_bindings`). For those, the default login is not a
/// second provider caller: it serves the shared account cache only.
/// Snapshot diagnostic for the default login's lifetime warning.
const CLAUDE_RELOGIN_APPROACHING_CODE: &str = "claude_relogin_approaching";

/// Warning: the default home's token belongs to a known account other than
/// the one its `.claude.json` names (Claude Desktop and the terminal signed
/// in as different accounts there).
const CLAUDE_DEFAULT_HOME_SPLIT_LOGIN_CODE: &str = "claude_default_home_split_login";

/// A failing registered-slot settings read keeps the last saved slot states
/// and withholds default uploads for slot-owned accounts for at most this
/// long, or this many consecutive passes.
const CLAUDE_SETTINGS_FAILURE_BOUND: Duration = Duration::from_secs(60 * 60);

#[cfg(test)]
static CLAUDE_SLOT_AFTER_PRE_GATE_HOOK: Mutex<Option<ClaudeSlotTestHook>> = Mutex::new(None);

#[cfg(test)]
static CLAUDE_OAUTH_TEST_RESPONSE: Mutex<Option<ClaudeOAuthTestResponder>> = Mutex::new(None);

/// Lets a unit test change the slot's identity files while its stored login
/// is being read, as another Claude Code process could.
#[cfg(test)]
pub(crate) mod claude_credentials_file_test_hooks {
    use std::path::Path;
    use std::sync::Mutex;

    type Hook = Box<dyn Fn(&Path) + Send>;

    static BEFORE_READ: Mutex<Option<Hook>> = Mutex::new(None);

    pub(crate) fn before_read(path: &Path) {
        if let Some(hook) = BEFORE_READ
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            hook(path);
        }
    }

    /// Installs `hook` until the returned guard drops.
    pub(crate) fn install(hook: impl Fn(&Path) + Send + 'static) -> Installed {
        *BEFORE_READ
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
        Installed
    }

    pub(crate) struct Installed;

    impl Drop for Installed {
        fn drop(&mut self) {
            *BEFORE_READ
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }
}

/// Capability a Claude snapshot carries when Claude said the account has no
/// account-wide weekly limit, so completeness checks over the snapshot expect
/// only its session window.
const CLAUDE_ACCOUNT_WEEKLY_NOT_OFFERED_CAPABILITY: &str = "account_weekly_window";

/// Capability a Claude snapshot carries when Claude said the account has no
/// 5-hour session limit, so completeness checks expect only its weekly window.
const CLAUDE_ACCOUNT_SESSION_NOT_OFFERED_CAPABILITY: &str = "account_session_window";

/// Decides, after the routine reading, whether to send the detailed read in
/// the same session: `(account result, rate-limit result, refreshed
/// credentials)`.
type CodexNeedsDetails<'a> = &'a dyn Fn(&Value, &Value, Option<&CodexAuthCredentials>) -> bool;

/// At or below this exact balance (five credits), Codex credits are low.
const CODEX_LOW_CREDITS: CreditAmount = CreditAmount::from_micros(5_000_000);

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod usage_checks_paused_tests;

/// Phase 0 of the durable Claude login fix: status passes never spawn a
/// credential-using `claude`, paused slots resume on their own, and a locally
/// expired access token is never sent. Every test runs on throwaway HOME and
/// support dirs with a logging fake `claude`, a fixture-emitting fake
/// `security`, fresh usage caches and provider requests forbidden.
#[cfg(test)]
mod claude_login_phase0_tests;
