//! setup reconcile for local control.

use crate::control::bounded_display_text;
use crate::control::lock_setup_run_binding;
use crate::control::process_setup_actions_with_status;
use crate::control::refresh_setup_run_token_via_device_secret;
use crate::control::request_snapshot_sync_after_setup_actions;
use crate::control::scan_setup_run_with_action_count;
use crate::control::setup_action_execution_error_detail;
use crate::control::terminal_refresh_rejection;
use crate::control::FileConnectionStore;
use crate::control::FileDeviceStore;
use crate::control::Instant;
use crate::control::LocalApiError;
use crate::control::LocalDaemon;
use crate::control::Mutex;
use crate::control::OrStatePoisoned;
use crate::control::SetupRunCredentials;
use crate::control::SETUP_RECONCILE_REFUSED_RETRY;

#[derive(Default)]
pub(in crate::control) struct SetupScanReconcile {
    pub(in crate::control) binding: Option<(String, String)>,
    pub(in crate::control) failures: u32,
    pub(in crate::control) next_due: Option<Instant>,
}

pub(in crate::control) static SETUP_SCAN: std::sync::LazyLock<Mutex<SetupScanReconcile>> =
    std::sync::LazyLock::new(|| Mutex::new(SetupScanReconcile::default()));

fn setup_run_status_is_active(status: &str) -> bool {
    matches!(
        status,
        "scanning" | "waiting_for_companion" | "running_action"
    )
}

/// The observed deterministic refusal: a 400 from the scan-result route. Other
/// statuses and routes keep their own handling or the jittered backoff.
pub(in crate::control) fn setup_reconcile_refused(error: &LocalApiError) -> bool {
    matches!(
        error,
        LocalApiError::Backend(details)
            if details.status == Some(400)
                && setup_reconcile_route(&details.endpoint) == "scan-result"
    )
}

/// The endpoint's last path segment (`scan-result`), or `other` when that
/// segment is not a plain route name, so no id is logged.
fn setup_reconcile_route(endpoint: &str) -> &str {
    let path = endpoint.split('?').next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    if last.len() <= 40
        && last.starts_with(|character: char| character.is_ascii_lowercase())
        && last
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '-')
    {
        last
    } else {
        "other"
    }
}

/// ` endpoint=<route> status=<n> code=<reason>` for a backend error; empty
/// otherwise.
pub(in crate::control) fn setup_reconcile_backend_fields(error: &LocalApiError) -> String {
    let LocalApiError::Backend(details) = error else {
        return String::new();
    };
    let mut fields = format!(" endpoint={}", setup_reconcile_route(&details.endpoint));
    if let Some(status) = details.status {
        fields.push_str(&format!(" status={status}"));
    }
    if let Some(code) = &details.reason_code {
        fields.push_str(&format!(" code={code}"));
    }
    fields
}

fn setup_reconcile_status_reason(status: Option<&str>) -> String {
    format!(
        "status:{}",
        bounded_display_text(status.unwrap_or("unknown"), 64)
    )
}

pub(crate) fn reconcile_setup_scan_in_background(daemon: &LocalDaemon) {
    let Ok(mut state) = SETUP_SCAN.try_lock() else {
        return;
    };
    let store = FileConnectionStore::default();
    let Ok(Some(binding)) = store.load() else {
        return;
    };
    let key = (binding.api_base_url.clone(), binding.setup_run_id.clone());
    if state.binding.as_ref() != Some(&key) {
        *state = SetupScanReconcile {
            binding: Some(key),
            ..Default::default()
        };
    }
    if state.next_due.is_some_and(|due| Instant::now() < due) {
        return;
    }
    let mut network_attempted = false;
    let mut actions_processed = 0;
    let result = (|| {
        let settled_run = store.setup_scan_settled_run_id().or_state_poisoned()?;
        if settled_run.as_deref() == Some(binding.setup_run_id.as_str()) {
            return Ok((true, String::new()));
        }
        let device = FileDeviceStore::default()
            .load()
            .or_state_poisoned()?
            .ok_or(LocalApiError::SetupRunConnectionMissing)?;
        network_attempted = true;
        let refreshed = refresh_setup_run_token_via_device_secret(&binding.api_base_url, &binding)?;
        let run = refreshed
            .run
            .ok_or(LocalApiError::SetupRunConnectionMissing)?;
        let mut credentials = SetupRunCredentials {
            connection: refreshed.connection,
            setup_run_token: refreshed.setup_run_token,
        };
        let machine = daemon.machine_for_trusted_client()?;
        match run.status.as_str() {
            "scanning" => {
                let result = scan_setup_run_with_action_count(
                    daemon,
                    &binding.api_base_url,
                    &mut credentials,
                    &machine,
                    Vec::new(),
                    false,
                    Some(&device.device_id),
                    &mut actions_processed,
                )?;
                let status = result["status"].as_str();
                Ok((
                    !status.is_some_and(setup_run_status_is_active),
                    setup_reconcile_status_reason(status),
                ))
            }
            "waiting_for_companion" | "running_action" => {
                let (actions, last_run_status, idle) = process_setup_actions_with_status(
                    daemon,
                    &binding.api_base_url,
                    &mut credentials,
                    &machine,
                    &mut actions_processed,
                )?;
                request_snapshot_sync_after_setup_actions(daemon, &actions);
                Ok((
                    idle && matches!(
                        last_run_status.as_deref(),
                        Some("waiting_for_user" | "completed")
                    ),
                    setup_reconcile_status_reason(last_run_status.as_deref()),
                ))
            }
            _ => Ok((true, setup_reconcile_status_reason(Some(&run.status)))),
        }
    })();
    let mut refused = false;
    let mut backend_fields = String::new();
    let (mut settled, mut reason) = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            refused = setup_reconcile_refused(&error);
            backend_fields = setup_reconcile_backend_fields(&error);
            (
                terminal_refresh_rejection(&error).is_some(),
                format!("error:{}", setup_action_execution_error_detail(&error).0),
            )
        }
    };
    if settled {
        let _binding_lock = lock_setup_run_binding();
        if let Err(error) = store.settle_setup_scan(&binding).or_state_poisoned() {
            settled = false;
            reason = format!("error:{}", setup_action_execution_error_detail(&error).0);
        }
    }
    let attempt = state.failures.saturating_add(1);
    let next_in = if settled {
        state.failures = 0;
        state.next_due = None;
        None
    } else {
        state.failures = attempt;
        let delay = if refused {
            SETUP_RECONCILE_REFUSED_RETRY
        } else {
            crate::snapshot_sync::full_jitter_backoff(state.failures)
        };
        state.next_due = Some(Instant::now() + delay);
        Some(delay.as_secs())
    };
    if network_attempted {
        let outcome = if settled { "settled" } else { "retry" };
        let next_in = next_in
            .map(|seconds| format!(" next_in={seconds}s"))
            .unwrap_or_default();
        eprintln!(
            "setup reconcile attempt={attempt} outcome={outcome} reason={reason}{backend_fields} actions={actions_processed}{next_in}"
        );
    }
}
