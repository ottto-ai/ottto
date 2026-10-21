//! The daemon's side of the local provider-call log
//! ([`ottto_core::provider_call_log`]): where lines go, and how call outcomes
//! become result classes. Every site that contacts OpenAI or Anthropic, over
//! HTTP or through a provider CLI, records one line here after the call.

use std::path::PathBuf;
use std::time::SystemTime;

pub(crate) use ottto_core::provider_call_log::{
    current_trigger, with_trigger, CallKind, CallResult, Provider, ProviderCall, Trigger,
};

/// Record one call, best effort: never fails the call it describes.
pub(crate) fn record(call: ProviderCall) {
    ottto_core::provider_call_log::record_provider_call(
        &log_support_dir(),
        &call,
        SystemTime::now(),
    );
}

/// The trigger set by the caller on this thread, else `default`.
pub(crate) fn trigger_or(default: Trigger) -> Trigger {
    current_trigger().unwrap_or(default)
}

/// The account identifier hash a Claude login's `.claude.json` names.
pub(crate) fn claude_slot_account_hash(slot: &ottto_core::ClaudeConfigDirSlot) -> Option<String> {
    let path = match slot {
        ottto_core::ClaudeConfigDirSlot::Default => ottto_core::default_claude_cli_config_path(),
        ottto_core::ClaudeConfigDirSlot::Registered { .. } => {
            slot.identity_path(&std::env::var_os("HOME").map(PathBuf::from)?)
        }
    };
    if !readable_for_account(&path) {
        return None;
    }
    let hash = ottto_core::claude_cli_account_identifier_hash_at(&path);
    (!hash.is_empty()).then_some(hash)
}

/// Whether `path` may be read to name an account. Unit tests read only
/// scratch files, never the operator's own logins.
pub(crate) fn readable_for_account(path: &std::path::Path) -> bool {
    #[cfg(test)]
    {
        let canonical = |path: &std::path::Path| {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        };
        let scratch = std::env::temp_dir();
        path.starts_with(&scratch) || canonical(path).starts_with(canonical(&scratch))
    }
    #[cfg(not(test))]
    {
        let _ = path;
        true
    }
}

/// Unit tests that did not choose a support dir log to a per-process
/// scratch dir, never the real one.
fn log_support_dir() -> PathBuf {
    #[cfg(test)]
    if std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR").is_none() {
        return test_support_dir();
    }
    ottto_core::default_support_dir()
}

#[cfg(test)]
fn test_support_dir() -> PathBuf {
    std::env::temp_dir().join(format!("ottto-provider-calls-tests-{}", std::process::id()))
}

/// The result class of a direct HTTP request.
pub(crate) fn http_result<T>(result: &Result<T, ureq::Error>) -> CallResult {
    match result {
        Ok(_) => CallResult::Ok,
        Err(ureq::Error::Status(status, _)) => CallResult::Http(*status),
        Err(ureq::Error::Transport(transport)) => transport_result(transport),
    }
}

fn transport_result(transport: &ureq::Transport) -> CallResult {
    use std::error::Error as _;
    let timed_out = transport
        .source()
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
        });
    if timed_out {
        return CallResult::Timeout;
    }
    // Typed: a TLS setup failure keeps the category ureq gave it before.
    CallResult::Error(match crate::retry_tls::transport_kind(transport) {
        ureq::ErrorKind::Dns => "dns_error",
        ureq::ErrorKind::ConnectionFailed => "connect_error",
        ureq::ErrorKind::Io => "io_error",
        _ => "transport_error",
    })
}

/// The result class of a provider CLI run from its exit status.
pub(crate) fn exit_result(status: Option<std::process::ExitStatus>, timed_out: bool) -> CallResult {
    if timed_out {
        return CallResult::Timeout;
    }
    match status {
        Some(status) if status.success() => CallResult::Ok,
        Some(status) => status
            .code()
            .map_or(CallResult::Error("killed"), CallResult::Exit),
        None => CallResult::Error("not_observed"),
    }
}

/// Lines a test's calls wrote: those of `kind` for the account whose
/// identifier hash starts with `account_prefix`, or `unknown` (tests may
/// share one log dir).
#[cfg(test)]
pub(crate) fn test_lines(
    kind: CallKind,
    account_prefix: &str,
) -> Vec<ottto_core::provider_call_log::ProviderCallLine> {
    let dir = ottto_core::provider_call_log::provider_call_log_dir(&log_support_dir());
    let mut lines = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let body = std::fs::read_to_string(entry.path()).unwrap_or_default();
        lines.extend(
            body.lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .filter(|line: &ottto_core::provider_call_log::ProviderCallLine| {
                    line.kind == kind.as_str()
                        && line.account
                            == ottto_core::provider_call_log::short_account(Some(account_prefix))
                }),
        );
    }
    lines
}

/// Every line in the test log, raw, for secret checks.
#[cfg(test)]
pub(crate) fn test_raw_log() -> String {
    let dir = ottto_core::provider_call_log::provider_call_log_dir(&log_support_dir());
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_and_exit_outcomes_become_result_classes() {
        let ok: Result<(), ureq::Error> = Ok(());
        assert_eq!(http_result(&ok), CallResult::Ok);
        let response = ureq::Response::new(429, "Too Many Requests", "").expect("response");
        let limited: Result<(), ureq::Error> = Err(ureq::Error::Status(429, response));
        assert_eq!(http_result(&limited), CallResult::Http(429));
        // A closed local port: a transport failure, never a provider.
        let refused = ureq::get("http://127.0.0.1:9/")
            .timeout(std::time::Duration::from_secs(2))
            .call();
        assert!(matches!(
            http_result(&refused),
            CallResult::Error("connect_error" | "io_error" | "transport_error")
                | CallResult::Timeout
        ));

        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            let exited = |code: i32| std::process::ExitStatus::from_raw(code << 8);
            assert_eq!(exit_result(Some(exited(0)), false), CallResult::Ok);
            assert_eq!(exit_result(Some(exited(3)), false), CallResult::Exit(3));
            assert_eq!(
                exit_result(Some(std::process::ExitStatus::from_raw(9)), false),
                CallResult::Error("killed")
            );
        }
        assert_eq!(exit_result(None, true), CallResult::Timeout);
        assert_eq!(exit_result(None, false), CallResult::Error("not_observed"));
    }
}
