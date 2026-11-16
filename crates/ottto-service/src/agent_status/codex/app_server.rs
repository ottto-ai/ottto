//! Codex status app server operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::bounded_claude_collection_timestamp;
use crate::agent_status::codex_app_server_account;
use crate::agent_status::codex_app_server_account_absent;
use crate::agent_status::codex_app_server_credit_balances;
use crate::agent_status::codex_app_server_quota_windows;
use crate::agent_status::codex_credential_claimed_account_hash;
use crate::agent_status::codex_credential_claimed_binding;
use crate::agent_status::codex_credit_grants;
use crate::agent_status::codex_home_claimed_account_hash;
use crate::agent_status::codex_probe_catalog;
use crate::agent_status::compiled_release_version;
use crate::agent_status::credit_amount_input;
use crate::agent_status::current_unix_seconds;
#[cfg(test)]
use crate::agent_status::default_codex_home;
use crate::agent_status::effective_user_identity;
use crate::agent_status::mpsc;
use crate::agent_status::read_codex_auth_credentials_at;
use crate::agent_status::rfc3339_from_unix_seconds;
use crate::agent_status::thread;
use crate::agent_status::validated_codex_identity;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::BufRead;
use crate::agent_status::BufReader;
use crate::agent_status::CodexAuthCredentials;
use crate::agent_status::CodexHomeTrust;
use crate::agent_status::CodexIdentityHashes;
use crate::agent_status::CodexNeedsDetails;
use crate::agent_status::CodexStrongIdentity;
use crate::agent_status::CodexUsageProbe;
use crate::agent_status::Command;
use crate::agent_status::Digest;
use crate::agent_status::Duration;
use crate::agent_status::Instant;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Path;
use crate::agent_status::Read;
use crate::agent_status::Sha256;
use crate::agent_status::Stdio;
use crate::agent_status::Value;
use crate::agent_status::Write;
use crate::agent_status::CODEX_APP_SERVER_CHANNEL_CAPACITY;
use crate::agent_status::CODEX_APP_SERVER_MAX_LINE_BYTES;
use crate::agent_status::CODEX_APP_SERVER_MAX_MESSAGES;
use crate::agent_status::CODEX_APP_SERVER_MAX_TOTAL_BYTES;
#[cfg(test)]
use crate::agent_status::CODEX_APP_SERVER_RUNS;
#[cfg(test)]
use crate::agent_status::CODEX_APP_SERVER_TEST_TIMEOUTS;
use crate::agent_status::CODEX_APP_SERVER_TIMEOUT;
use crate::agent_status::CODEX_NO_ACCOUNT_FAILURE_PREFIX;

pub(in crate::agent_status) fn collect_codex_app_server_usage_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
) -> Result<CodexUsageProbe, String> {
    let now = current_unix_seconds();
    let needs_details =
        |account: &Value, rate_limits: &Value, credentials: Option<&CodexAuthCredentials>| {
            let binding = credentials
                .and_then(|credentials| {
                    validated_codex_identity(credentials, Some(account), Some(rate_limits), true)
                })
                .map(|identity| codex_credit_binding(&identity));
            codex_credit_grants::routine_read_needs_details(binding.as_deref(), rate_limits, now)
        };
    let started = Instant::now();
    let observation =
        match call_codex_app_server_rate_limits_for_home(codex_home, home_trust, &needs_details) {
            Ok(observation) => observation,
            Err(message) => {
                eprintln!(
                    "{}",
                    codex_probe_failure_log_line(
                        &message,
                        codex_home,
                        started.elapsed(),
                        current_unix_seconds(),
                    )
                );
                // No reading at all: the detail back-off still applies to the
                // account last validated at this home.
                codex_credit_grants::record_session_failure(codex_home, now);
                return Err(message);
            }
        };
    let probe = codex_usage_probe_from_app_server_observation(observation);
    if let Some(identity) = probe.identity.as_ref() {
        codex_credit_grants::remember_home_binding(codex_home, &codex_credit_binding(identity));
    }
    Ok(probe)
}

/// One log line per failed app-server probe: wall-clock time, the session
/// stage, the error kind, the JSON-RPC error code, a digest of the Codex home
/// and the elapsed time.
/// Built from the fixed producer text only; no path, account or provider text.
pub(in crate::agent_status) fn codex_probe_failure_log_line(
    message: &str,
    codex_home: &Path,
    elapsed: Duration,
    now: u64,
) -> String {
    let (stage, kind) = codex_probe_failure_stage_and_kind(message);
    // The JSON-RPC error code from `codex_app_server_rpc_failure`, digits only.
    let code = message
        .split_once("RPC failed with code ")
        .and_then(|(_, rest)| rest.trim_end_matches('.').parse::<i64>().ok())
        .map_or_else(|| "none".to_string(), |code| code.to_string());
    format!(
        "codex usage probe failed: at={} stage={stage} kind={kind} code={code} home={} elapsed_ms={}",
        rfc3339_from_unix_seconds(now).unwrap_or_else(|| "unknown".to_string()),
        codex_home_log_label(codex_home),
        elapsed.as_millis()
    )
}

/// The 12-hex digest of a Codex home that the probe's log lines carry.
pub(in crate::agent_status) fn codex_home_log_label(codex_home: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:codex-home-log:v1\0");
    digest.update(codex_home.as_os_str().as_encoded_bytes());
    format!("{:x}", digest.finalize())[..12].to_string()
}

/// `(stage, kind)` of a failed app-server probe, from its fixed producer text
/// (`codex_app_server_rpc_failure`, `codex_app_server_end_failure` and the
/// session's own messages).
pub(in crate::agent_status) fn codex_probe_failure_stage_and_kind(
    message: &str,
) -> (&'static str, &'static str) {
    let kind = if message.contains("timed out") {
        "timeout"
    } else if message.contains("RPC failed") {
        "rpc_error"
    } else if message.contains("stdout closed") {
        "stdout_closed"
    } else if message.contains("stdout read failed") {
        "read_failed"
    } else if message.contains("exceeded") {
        "output_bound"
    } else if message.contains("not found")
        || message.contains("could not be started")
        || message.contains("was unavailable")
    {
        "start"
    } else if message.contains("request") && message.contains("failed") {
        "request_failed"
    } else {
        "other"
    };
    let stage = message
        .split(|character: char| !character.is_ascii_alphanumeric())
        .find_map(|word| match word {
            "initialize" => Some("initialize"),
            "account" => Some("account"),
            "quota" => Some("quota"),
            _ => None,
        })
        .unwrap_or(if kind == "start" { "start" } else { "session" });
    (stage, kind)
}

pub(in crate::agent_status) fn codex_credit_binding(identity: &CodexStrongIdentity) -> String {
    codex_credit_grants::binding_key(
        &identity.account_identifier_hash,
        &identity.workspace_identifier_hash,
    )
}

pub(in crate::agent_status) fn codex_usage_probe_from_app_server_observation(
    observation: CodexAppServerObservation,
) -> CodexUsageProbe {
    let identity = observation
        .refreshed_credentials
        .as_ref()
        .and_then(|credentials| {
            validated_codex_identity(
                credentials,
                Some(&observation.account),
                Some(&observation.rate_limits),
                true,
            )
        });
    let mut quota_windows = codex_app_server_quota_windows(&observation.rate_limits);
    for window in &mut quota_windows {
        window.observed_at = observation.response_completed_at.clone();
    }
    let now = current_unix_seconds();
    let binding = identity.as_ref().map(codex_credit_binding);
    let mut credit_balances = codex_app_server_credit_balances(&observation.rate_limits);
    let model_diagnostics = codex_credit_grants::attach_reset_bank_grants(
        &mut credit_balances,
        &observation.rate_limits,
        codex_credit_grants::CodexCreditRead {
            binding: binding.as_deref(),
            details_requested: observation.details_requested,
            details_answered: observation.details_answered,
            observed_at: observation.response_completed_at.as_deref(),
            now,
        },
    );
    codex_credit_grants::stamp_read_clock(
        &mut credit_balances,
        observation.response_completed_at.as_deref(),
    );
    let reset_credit_detail_summary = if observation.details_requested {
        codex_reset_credit_detail_summary(&observation.rate_limits)
    } else {
        codex_credit_grants::routine_reset_credit_summary(&observation.rate_limits)
    }
    .map(|summary| summary + &codex_credit_grants::model_diagnostics_suffix(&model_diagnostics));
    CodexUsageProbe {
        quota_windows,
        credit_balances,
        account: codex_app_server_account(&observation.account),
        provider_account_absent: codex_app_server_account_absent(&observation.account),
        identity,
        saved_identity: None,
        credential_read_failed: observation.credential_read_failed,
        response_completed_at: observation.response_completed_at,
        reset_credit_detail_summary,
        rate_limit_pool_summary: Some(codex_credit_grants::rate_limit_pools_summary(
            &observation.rate_limits,
            now,
        )),
    }
}

/// V1 acquisition evidence from the existing read. Summarize at most 20 rows,
/// without grant ids, titles, descriptions, timestamps or invented semantics.
pub(in crate::agent_status) fn codex_reset_credit_detail_summary(value: &Value) -> Option<String> {
    let credits = value.get("rateLimitResetCredits")?.as_object()?;
    let count = codex_credit_grants::available_count(value)
        .filter(|n| *n <= 10_000)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unreported".to_string());
    let Some(rows) = credits.get("credits").and_then(Value::as_array) else {
        return Some(format!(
            "Codex reset details: count {count}; list unobserved."
        ));
    };
    let mut states = [0usize; 4];
    let mut expiry_present = 0;
    for row in rows.iter().take(20) {
        let bucket = match row.get("status").and_then(Value::as_str) {
            Some("available") => 0,
            Some("redeeming") => 1,
            Some("redeemed") => 2,
            _ => 3,
        };
        states[bucket] += 1;
        if row.get("expiresAt").is_some_and(|v| !v.is_null()) {
            expiry_present += 1;
        }
    }
    Some(format!("Codex reset details: count {count}; list rows {}; sampled {}; available {}, redeeming {}, redeemed {}, unknown {}; expiry present {}.",
        rows.len(), rows.len().min(20), states[0], states[1], states[2], states[3], expiry_present))
}

pub(in crate::agent_status) struct CodexAppServerObservation {
    pub(in crate::agent_status) account: Value,
    pub(in crate::agent_status) rate_limits: Value,
    pub(in crate::agent_status) refreshed_credentials: Option<CodexAuthCredentials>,
    pub(in crate::agent_status) credential_read_failed: bool,
    pub(in crate::agent_status) response_completed_at: Option<String>,
    /// A detailed (reset-credit list) read was sent in this session.
    pub(in crate::agent_status) details_requested: bool,
    /// That detailed read answered with a result.
    pub(in crate::agent_status) details_answered: bool,
}

pub(in crate::agent_status) fn codex_app_server_success_diagnostic(
    response_completed_at: Option<String>,
    identity: Option<&CodexIdentityHashes>,
    has_usage: bool,
) -> Option<AgentStatusDiagnostic> {
    let identity = identity.filter(|_| has_usage)?;
    let completed_at = response_completed_at?;
    bounded_claude_collection_timestamp(Some(&completed_at), OffsetDateTime::now_utc())?;
    Some(
        AgentStatusDiagnostic::source(
            "codex_app_server_usage_response",
            AgentDiagnosticSeverity::Info,
            "Codex app-server account and quota read completed successfully; this clock records the read, not when quota last changed.",
        )
        .with_observed_at(Some(completed_at))
        .with_quota_binding(
            Some(identity.account_identifier_hash.clone()),
            Some(identity.workspace_identifier_hash.clone()),
        ),
    )
}

/// No `codex` executable: not a transient read failure (see
/// [`codex_probe_failed_only`]).
pub(in crate::agent_status) const CODEX_CLI_NOT_FOUND_FOR_PROBE: &str =
    "Codex CLI was not found for app-server rate-limit collection.";

/// Fixed producer text only; never persist provider error messages or data.
pub(in crate::agent_status) fn codex_app_server_rpc_failure(phase: &str, error: &Value) -> String {
    match error.get("code").and_then(Value::as_i64) {
        Some(code) => format!("Codex app-server {phase} RPC failed with code {code}."),
        None => format!("Codex app-server {phase} RPC failed without a numeric code."),
    }
}

/// Class `auth_rejected`: an `account/read` error with which the provider
/// rejected this login (Codex's workspace discovery "unauthorized (401)", or
/// its refresh rejection asking to "sign in again"). It reads as a dead login
/// ([`CODEX_NO_ACCOUNT_FAILURE_PREFIX`]); the provider text is never kept, and
/// any other text stays a plain failure.
pub(in crate::agent_status) fn codex_app_server_auth_rejected(error: &Value) -> bool {
    error
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| {
            let message = message.to_ascii_lowercase();
            message.contains("unauthorized (401)") || message.contains("sign in again")
        })
}

/// `ended`: the child's own exit status, when it ended before our cleanup;
/// never report our own stop signal.
pub(in crate::agent_status) fn codex_app_server_end_failure(
    phase: &str,
    disconnected: bool,
    initialize_error: Option<&str>,
    ended: Option<std::process::ExitStatus>,
) -> String {
    if let Some(message) = initialize_error {
        return message.to_string();
    }
    if !disconnected {
        return format!("Codex app-server {phase} read timed out.");
    }
    if let Some(status) = ended {
        if let Some(code) = status.code() {
            return format!(
                "Codex app-server stdout closed during {phase}; child exited with code {code}."
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return format!("Codex app-server stdout closed during {phase}; child terminated by signal {signal}.");
            }
        }
    }
    format!("Codex app-server stdout closed during {phase}; child termination was not observed before cleanup.")
}

/// What one `codex app-server` run asked of the provider, for the
/// provider-call log.
#[derive(Default)]
pub(in crate::agent_status) struct CodexAppServerRun {
    pub(in crate::agent_status) spawned: bool,
    /// Whether the session asked for the detailed rate-limits read.
    pub(in crate::agent_status) detail_read_sent: bool,
    /// Whether the CLI rejected the routine read's parameter itself; that
    /// read never reached the provider, and the detailed read replaced it.
    pub(in crate::agent_status) routine_read_rejected: bool,
    pub(in crate::agent_status) timed_out: bool,
    /// `account/read` answered with no account
    /// ([`codex_app_server_account_absent`]), or the provider rejected the
    /// login there ([`codex_app_server_auth_rejected`]), whatever the rest of
    /// the session did.
    pub(in crate::agent_status) account_absent: bool,
    /// The binary whose bundled model list was passed to Codex
    /// ([`codex_probe_catalog`]), so it sent no models request.
    pub(in crate::agent_status) model_list: Option<crate::transcript_acquisition::SourceStamp>,
    /// `account/read` answered, with a result or an error.
    pub(in crate::agent_status) account_answered: bool,
}

/// Provider requests a started `codex app-server` quota session counts at
/// least, sent whether or not they were answered: workspace discovery, models
/// (one fewer when given its bundled list) and the rate-limits read. Each
/// read lets Codex refresh its login when due; such a refresh is counted only
/// by the rewrite log line.
pub(in crate::agent_status) const CODEX_APP_SERVER_MIN_REQUESTS: u32 = 3;

/// How long an ended Codex child (stdin closed, or a run past its deadline)
/// gets to exit by itself before its group is killed: it may be refreshing
/// its login. Codex's app-server exits within 45 s of its stdin closing.
pub(crate) const CODEX_CHILD_DRAIN: Duration = Duration::from_secs(46);

/// [`CODEX_CHILD_DRAIN`], or a test's scaled bound.
pub(crate) fn codex_child_drain() -> Duration {
    #[cfg(test)]
    if let Some(timeouts) = codex_app_server_test_timeouts() {
        return timeouts.drain;
    }
    CODEX_CHILD_DRAIN
}

/// Bound on one `codex app-server` quota session: [`CODEX_APP_SERVER_TIMEOUT`],
/// or a test's scaled bound.
pub(in crate::agent_status) fn codex_app_server_timeout() -> Duration {
    #[cfg(test)]
    if let Some(timeouts) = codex_app_server_test_timeouts() {
        return timeouts.session;
    }
    CODEX_APP_SERVER_TIMEOUT
}

/// Scaled app-server bounds for tests only; production constants are never
/// changed.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(in crate::agent_status) struct CodexAppServerTestTimeouts {
    pub(in crate::agent_status) session: Duration,
    pub(in crate::agent_status) detail_min: Duration,
    pub(in crate::agent_status) detail_max: Duration,
    pub(in crate::agent_status) drain: Duration,
}

#[cfg(test)]
pub(in crate::agent_status) fn codex_app_server_test_timeouts() -> Option<CodexAppServerTestTimeouts>
{
    CODEX_APP_SERVER_TEST_TIMEOUTS.with(std::cell::Cell::get)
}

/// Runs `run` with the session bound, the detailed read's budget bounds and
/// the child drain scaled down. The session runs on the calling thread, so
/// the override reaches it and no other test.
#[cfg(test)]
pub(crate) fn with_codex_app_server_test_timeouts<T>(
    session: Duration,
    detail_min: Duration,
    detail_max: Duration,
    drain: Duration,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CODEX_APP_SERVER_TEST_TIMEOUTS.with(|timeouts| timeouts.set(None));
        }
    }
    CODEX_APP_SERVER_TEST_TIMEOUTS.with(|timeouts| {
        timeouts.set(Some(CodexAppServerTestTimeouts {
            session,
            detail_min,
            detail_max,
            drain,
        }))
    });
    let _reset = Reset;
    run()
}

/// One `codex app-server` quota session for `codex_home`, logged as one
/// provider-call line when the CLI started.
pub(in crate::agent_status) fn call_codex_app_server_rate_limits_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    needs_details: CodexNeedsDetails<'_>,
) -> Result<CodexAppServerObservation, String> {
    use crate::provider_calls::{CallKind, CallResult, Provider, ProviderCall, Trigger};
    // The credential before the session, read once: the account for the call
    // log, and the login (at any token age) a validated identity must match.
    let before = crate::provider_calls::readable_for_account(codex_home)
        .then(|| read_codex_auth_credentials_at(codex_home, home_trust).ok())
        .flatten()
        .flatten();
    let account_before = before
        .as_ref()
        .and_then(codex_credential_claimed_account_hash);
    let named_before = before
        .as_ref()
        .and_then(|credentials| codex_credential_claimed_binding(credentials, false));
    let auth_before = ottto_core::codex_auth_file_mark(codex_home);
    let started = Instant::now();
    let mut run = CodexAppServerRun::default();
    let result = run_codex_app_server_rate_limits_for_home(
        codex_home,
        home_trust,
        named_before.as_deref(),
        needs_details,
        &mut run,
    );
    if run.spawned {
        let result_class = match &result {
            Ok(_) => CallResult::Ok,
            Err(_) if run.timed_out => CallResult::Timeout,
            Err(message) if message.contains("RPC failed") => CallResult::Error("rpc_error"),
            Err(message) if message.contains("stdout closed") => CallResult::Error("exited"),
            Err(message) if message.contains("exceeded its") => CallResult::Error("output_bound"),
            Err(_) => CallResult::Error("error"),
        };
        let account =
            account_before.or_else(|| codex_home_claimed_account_hash(codex_home, home_trust));
        crate::provider_calls::record(ProviderCall::subprocess(
            Provider::Openai,
            CallKind::CodexAppServerQuota,
            crate::provider_calls::trigger_or(Trigger::Other),
            account.as_deref(),
            result_class,
            started.elapsed(),
            CODEX_APP_SERVER_MIN_REQUESTS - u32::from(run.model_list.is_some())
                + u32::from(run.detail_read_sent && !run.routine_read_rejected),
        ));
    }
    // A Codex that ended (not timed out) without answering `account/read`
    // may not take the list: later probes run without it until it changes.
    if let (Some(binary), false, false) = (&run.model_list, run.account_answered, run.timed_out) {
        codex_probe_catalog::give_up(binary);
    }
    if run.spawned && ottto_core::codex_auth_file_mark(codex_home) != auth_before {
        eprintln!(
            "codex usage probe: login rewritten during read home={} elapsed_ms={}",
            codex_home_log_label(codex_home),
            started.elapsed().as_millis()
        );
    }
    if run.account_absent {
        return result.map_err(|message| format!("{CODEX_NO_ACCOUNT_FAILURE_PREFIX}{message}"));
    }
    result
}

pub(in crate::agent_status) fn run_codex_app_server_rate_limits_for_home(
    codex_home: &Path,
    home_trust: CodexHomeTrust,
    named_before: Option<&str>,
    needs_details: CodexNeedsDetails<'_>,
    run: &mut CodexAppServerRun,
) -> Result<CodexAppServerObservation, String> {
    #[cfg(test)]
    CODEX_APP_SERVER_RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let Some(program_path) = crate::command_env::executable_path("codex") else {
        return Err(CODEX_CLI_NOT_FOUND_FOR_PROBE.to_string());
    };
    let Some(identity) = effective_user_identity() else {
        return Err("Codex app-server user identity was unavailable.".to_string());
    };
    let mut command = Command::new(program_path);
    // Turn off Codex's startup installers, which write into the account's home:
    // the bundled system-skill install and the curated plugin sync. A CLI that
    // lacks either key warns and keeps its default.
    command.args([
        "-c",
        "skills.bundled.enabled=false",
        "-c",
        "features.plugins=false",
    ]);
    let model_list = codex_probe_catalog::for_probe();
    if let Some((path, _)) = &model_list {
        let path = toml_edit::Value::from(&*path.to_string_lossy());
        command.args(["-c", &format!("model_catalog_json={path}")]);
    }
    command.args(["app-server", "--stdio"]).env_clear();
    command
        .env("HOME", &identity.home_dir)
        .env("USER", identity.account_name)
        .env("CODEX_HOME", codex_home)
        .env("CODEX_SQLITE_HOME", codex_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for locale_key in ["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = std::env::var_os(locale_key) {
            command.env(locale_key, value);
        }
    }
    if let Some(path_env) = crate::command_env::path_env() {
        command.env("PATH", path_env);
    }
    // Its own process group, so the end reaches the native child too.
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = crate::cloud_sessions::CodexChild::new(
        crate::local_resource_diagnostics::cli_children::spawn(&mut command)
            .map_err(|_| "Codex app-server could not be started.".to_string())?,
    );
    run.spawned = true;
    run.model_list = model_list.map(|(_, binary)| binary);
    // Declared after `child`: stdin and the output reader close before the
    // child is ended, so neither holds up its own exit.
    let (stdin, stdout) = child.take_pipes();
    let stdout = stdout.ok_or_else(|| "Codex app-server stdout was unavailable.".to_string())?;
    let (sender, receiver) =
        mpsc::sync_channel::<Result<Value, String>>(CODEX_APP_SERVER_CHANNEL_CAPACITY);
    thread::spawn(move || {
        read_bounded_codex_app_server_stdout(BufReader::new(stdout), sender);
    });

    let mut stdin = stdin.ok_or_else(|| "Codex app-server stdin was unavailable.".to_string())?;
    let initialize = serde_json::json!({
        "method": "initialize",
        "id": 1,
        "params": {
            "clientInfo": {
                "name": "ottto_local_platform",
                "title": "Ottto Local Platform",
                "version": compiled_release_version()
            },
            "capabilities": {
                "experimentalApi": true,
                "optOutNotificationMethods": ["account/rateLimits/updated"]
            }
        }
    });
    let initialized = serde_json::json!({"method": "initialized"});
    // Never forces a token refresh: Codex refreshes its login itself when due.
    let account = serde_json::json!({
        "method": "account/read",
        "id": "ottto_account",
        "params": { "refreshToken": false }
    });
    // Every poll reads usage and the count first; the reset-credit list
    // follows in this session only when the cadence asks for it.
    let read = codex_credit_grants::CodexRateLimitsRead::Routine.request("ottto_rate_limits");
    let detail_read = codex_credit_grants::CodexRateLimitsRead::Detailed
        .request(codex_credit_grants::DETAIL_READ_ID);
    let write_result = (|| -> Result<(), String> {
        for message in [initialize, initialized, account] {
            serde_json::to_writer(&mut stdin, &message)
                .map_err(|_| "Codex app-server request serialization failed.".to_string())?;
            stdin
                .write_all(b"\n")
                .map_err(|_| "Codex app-server request write failed.".to_string())?;
        }
        stdin
            .flush()
            .map_err(|_| "Codex app-server request flush failed.".to_string())
    })();
    if let Err(message) = write_result {
        drop((stdin, receiver));
        let _ = child.stop_and_reap();
        return Err(message);
    }

    let start = Instant::now();
    let mut deadline = start + codex_app_server_timeout();
    let mut initialize_error = None;
    let mut initialize_completed = false;
    let mut disconnected = false;
    let mut account_result = None;
    let mut rate_limits_result: Option<(Value, Option<String>)> = None;
    let mut detail_result: Option<(Value, Option<String>)> = None;
    let mut rate_limits_requested = false;
    // The detailed read sent after the routine one in this session.
    let mut detail_requested = false;
    let mut detail_failed = false;
    let mut credentials: Option<(Option<CodexAuthCredentials>, bool)> = None;
    // Only a credential that names the login the home had before the session
    // can confirm an identity: one switched (or unreadable) before it confirms
    // none, so nothing is saved or remembered under it.
    let read_credentials = || match read_codex_auth_credentials_at(codex_home, home_trust) {
        Ok(credentials) => (
            credentials.filter(|credentials| {
                named_before.is_some()
                    && codex_credential_claimed_binding(credentials, false).as_deref()
                        == named_before
            }),
            false,
        ),
        Err(_) => (None, true),
    };
    // `Ok(true)`: settled; `Ok(false)`: timed out or the server went away.
    let outcome: Result<bool, String> = loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            run.timed_out = true;
            break Ok(false);
        };
        let message = match receiver.recv_timeout(remaining.min(Duration::from_millis(250))) {
            // Output bounds still end the session; a routine reading taken
            // before the detailed read stands (the attempt counts as failed).
            Ok(Err(_)) if detail_requested && rate_limits_result.is_some() => break Ok(true),
            Ok(Err(message)) => break Err(message),
            Ok(Ok(message)) => message,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                disconnected = true;
                break Ok(false);
            }
        };
        if message.get("id").and_then(Value::as_i64) == Some(1) {
            if let Some(error) = message.get("error") {
                initialize_error = Some(codex_app_server_rpc_failure("initialize", error));
            } else if message.get("result").is_some() {
                initialize_completed = true;
            }
        }
        // An earlier initialize rejection is the likelier cause of a later
        // RPC failure.
        let rpc_failure = |phase: &str, error: &Value| {
            initialize_error
                .clone()
                .unwrap_or_else(|| codex_app_server_rpc_failure(phase, error))
        };
        let response_id = message.get("id").and_then(Value::as_str);
        run.account_answered |= response_id == Some("ottto_account");
        let error = message.get("error");
        let arrived_at = || rfc3339_from_unix_seconds(current_unix_seconds());
        let mut send_details = false;
        match (response_id, error) {
            (Some("ottto_account"), Some(error)) => {
                run.account_absent = codex_app_server_auth_rejected(error);
                break Err(rpc_failure("account", error));
            }
            (Some("ottto_account"), None) => {
                account_result = message.get("result").cloned();
                run.account_absent = account_result
                    .as_ref()
                    .is_some_and(codex_app_server_account_absent);
            }
            (Some("ottto_rate_limits"), Some(error))
                if !detail_requested && codex_credit_grants::routine_param_rejected(error) =>
            {
                // A server that does not accept the routine parameter still
                // answers the plain read it always accepted.
                send_details = true;
                run.routine_read_rejected = true;
            }
            (Some("ottto_rate_limits"), Some(error)) => {
                break Err(rpc_failure("quota", error));
            }
            (Some("ottto_rate_limits"), None) if rate_limits_result.is_none() => {
                rate_limits_result = message
                    .get("result")
                    .cloned()
                    .map(|result| (result, arrived_at()));
            }
            (Some(codex_credit_grants::DETAIL_READ_ID), Some(error)) => {
                if rate_limits_result.is_none() {
                    break Err(rpc_failure("quota", error));
                }
                detail_failed = true;
            }
            (Some(codex_credit_grants::DETAIL_READ_ID), None) => {
                detail_result = message
                    .get("result")
                    .cloned()
                    .map(|result| (result, arrived_at()));
            }
            _ => {}
        }
        if account_result.is_some() && !rate_limits_requested {
            if write_codex_app_server_message(&mut stdin, &read).is_err() {
                break Err("Codex app-server quota request failed.".to_string());
            }
            rate_limits_requested = true;
        }
        if !send_details && !detail_requested {
            if let (Some(account), Some((rate_limits, _))) =
                (account_result.as_ref(), rate_limits_result.as_ref())
            {
                let (refreshed, _) = credentials.get_or_insert_with(read_credentials);
                if !needs_details(account, rate_limits, refreshed.as_ref()) {
                    break Ok(true);
                }
                send_details = true;
            }
        }
        if send_details {
            detail_requested = true;
            let now = Instant::now();
            deadline = now
                + codex_credit_grants::detail_read_budget(deadline.saturating_duration_since(now));
            if write_codex_app_server_message(&mut stdin, &detail_read).is_err() {
                if rate_limits_result.is_some() {
                    // The routine reading stands; the attempt counts as failed.
                    break Ok(true);
                }
                break Err("Codex app-server quota request failed.".to_string());
            }
            run.detail_read_sent = true;
            continue;
        }
        if detail_requested
            && account_result.is_some()
            && (detail_result.is_some() || (detail_failed && rate_limits_result.is_some()))
        {
            break Ok(true);
        }
    };
    // A detailed read that did not answer in time leaves the routine reading.
    let settled = match outcome {
        Ok(settled) => settled || (detail_requested && rate_limits_result.is_some()),
        Err(message) => {
            drop((stdin, receiver));
            let _ = child.stop_and_reap();
            return Err(message);
        }
    };
    let phase = if account_result.is_some() {
        "quota"
    } else if initialize_completed {
        "account"
    } else {
        "initialize"
    };
    let details_answered = detail_result.is_some();
    let (Some(account), Some((rate_limits, response_completed_at)), true) = (
        account_result,
        detail_result.or(rate_limits_result),
        settled,
    ) else {
        // Observe the child's own end before our cleanup.
        let ended = child.exited().unwrap_or(false);
        drop((stdin, receiver));
        let status = child.stop_and_reap().ok().filter(|_| ended);
        return Err(codex_app_server_end_failure(
            phase,
            disconnected,
            initialize_error.as_deref(),
            status,
        ));
    };
    let (refreshed_credentials, credential_read_failed) =
        credentials.unwrap_or_else(read_credentials);
    drop((stdin, receiver));
    let _ = child.stop_and_reap();
    Ok(CodexAppServerObservation {
        account,
        rate_limits,
        refreshed_credentials,
        credential_read_failed,
        response_completed_at,
        details_requested: detail_requested,
        details_answered,
    })
}

pub(in crate::agent_status) fn write_codex_app_server_message(
    stdin: &mut impl Write,
    message: &Value,
) -> Result<(), ()> {
    serde_json::to_writer(&mut *stdin, message).map_err(|_| ())?;
    stdin.write_all(b"\n").map_err(|_| ())?;
    stdin.flush().map_err(|_| ())
}

pub(in crate::agent_status) fn read_bounded_codex_app_server_stdout<R: BufRead>(
    mut reader: R,
    sender: mpsc::SyncSender<Result<Value, String>>,
) {
    let mut total_bytes = 0_usize;
    let mut message_count = 0_usize;
    loop {
        let mut line = Vec::new();
        let read = match reader
            .by_ref()
            .take((CODEX_APP_SERVER_MAX_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
        {
            Ok(read) => read,
            Err(_) => {
                let _ = sender.send(Err("Codex app-server stdout read failed.".to_string()));
                return;
            }
        };
        if read == 0 {
            return;
        }
        total_bytes = total_bytes.saturating_add(read);
        if read > CODEX_APP_SERVER_MAX_LINE_BYTES || total_bytes > CODEX_APP_SERVER_MAX_TOTAL_BYTES
        {
            let _ = sender.send(Err(
                "Codex app-server output exceeded its byte limit.".to_string()
            ));
            return;
        }
        let Ok(line) = std::str::from_utf8(&line) else {
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        message_count = message_count.saturating_add(1);
        if message_count > CODEX_APP_SERVER_MAX_MESSAGES {
            let _ = sender.send(Err(
                "Codex app-server output exceeded its message limit.".to_string()
            ));
            return;
        }
        if let Some(value) =
            credit_amount_input::decode(line, credit_amount_input::CreditBody::CodexMessage)
        {
            if sender.send(Ok(value)).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
pub(in crate::agent_status) fn call_codex_app_server_rate_limits() -> Result<Value, String> {
    call_codex_app_server_rate_limits_for_home(
        &default_codex_home(),
        CodexHomeTrust::ProviderDefault,
        &|_, _, _| false,
    )
    .map(|observation| observation.rate_limits)
}
