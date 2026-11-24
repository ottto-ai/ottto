//! Codex daily aggregates, normalized to the `provider_daily_reference.v1`
//! upload contract.
//!
//! The capability is "verify Ottto against your provider's own numbers": an
//! accuracy and self-audit surface, not cloud sessions and not community-led.
//! With an explicit, versioned, revocable disclosure grant the collector reads
//! the customer's own Codex daily aggregate endpoint with the customer's own
//! already-issued credential, normalizes it locally to a closed struct of
//! scalars, and uploads only that struct over the existing relay-device
//! channel.
//!
//! Boundaries this module enforces, not merely documents:
//!
//! * **Scalars only.** Every string that crosses the upload boundary is a
//!   fixed literal, an opaque `hmac-sha256:` fingerprint, a UUID, an ISO date
//!   or timestamp, a closed surface enum, or a bounded lowercase model slug.
//!   `wire_payload_is_content_free` proves it, and a test drives poisoned
//!   provider text through the whole path.
//! * **Content endpoints are never contacted.** Only
//!   `wham/analytics/daily-workspace-usage-counts` is read. `wham/tasks/*`,
//!   `teleport-events`, and `/v1/sessions` are permanently out of scope.
//! * **The credential and the raw response body never leave the machine.**
//! * **Dark by default.** No grant, no sentinel-free support directory, or no
//!   approved server policy each stop the cycle before a socket is opened.
//!   The backend separately applies its collector-build admission list to each
//!   upload and stores nothing from an unadmitted build.
//!
//! Layout: `wire` (contract shapes and the content-free proof), `grant`
//! (consent), `status` (control-socket view), `state` (cadence and circuit
//! breaker), `provider_read` (the one provider route), `normalize`,
//! `batching`, `transport`, `cycle` (one tick) and `logins` (the Codex logins
//! a read may use). This file keeps the contract constants, the kill switch,
//! the composed entry point, the supervisor and the shared helpers.

use crate::grant_rebind::{self, GrantKind};
use crate::hex::{encode as hex, is_uuid};
use crate::local_resource_diagnostics::StageWindow;
use anyhow::{anyhow, Context, Result};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use ottto_core::{default_support_dir, FileAccountStore, FileConnectionStore, FileDeviceStore};
use ottto_protocol::{AgentStatusDiagnostic, LocalAccountState};
use serde::Serialize;
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::thread;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

mod batching;
mod cycle;
mod grant;
mod normalize;
mod provider_read;
mod state;
mod status;
mod transport;
mod wire;

pub use self::batching::collection_window;
use self::cycle::{
    attribution_unavailable_cycle, deferred, network_disabled_cycle, runtime_ready_grant,
};
pub use self::cycle::{Collector, Cycle, CycleOutcome, Runtime};
pub use self::grant::{
    grant_runtime_block_reason, grant_runtime_ready, BackendGrantBinding, DailyReferenceGrant,
    GrantCreateRequest, GrantRevokeTarget, GrantSetup, GrantStatus, GrantStore,
};
pub use self::normalize::{normalize_provider_window, DayTotalMismatch, NormalizedWindow};
use self::provider_read::codex_credential_from_auth;
pub(crate) use self::provider_read::CodexLogin;
pub use self::provider_read::{
    ChatGptDailyUsageReader, CodexCredential, ProviderDailyUsageReader, ProviderReadError,
};
pub use self::state::{ProviderFailure, StateStore};
pub(crate) use self::status::control_account_scope;
pub use self::status::{
    collector_status, control_token_use_store, status_with_live_binding, CollectorAccountStatusV1,
    CollectorStatusV1, RuntimeState, COLLECTOR_STATUS_SCHEMA_VERSION,
};
pub use self::transport::{
    DailyReferenceTransport, DeferredTransport, RelayTransport, UploadError,
};
pub(crate) use self::wire::AccountIdentityHashes;
pub use self::wire::{
    normalized_model_slug, surface_for_client_id, wire_payload_is_content_free,
    DailyReferenceBatch, DailyReferenceRow, Surface, PROVIDER_DAY_TOTAL_SURFACE,
};

// ---------------------------------------------------------------------------
// Contract identity - every value here is fixed by the backend contract
// ---------------------------------------------------------------------------

/// Wire schema of the upload contract.
pub const SCHEMA_VERSION: &str = "provider_daily_reference.v1";
/// Wire source. This collector reads Codex only.
pub const SOURCE: &str = "codex";
/// Wire collector id.
pub const COLLECTOR_ID: &str = "provider_daily_reference";
/// Versioned disclosure the grant is bound to.
pub const DISCLOSURE_VERSION: &str = "provider_daily_reference_disclosure.v2";
const DISCLOSURE_VERSION_V1: &str = "provider_daily_reference_disclosure.v1";
/// Release lane the server admits.
pub const RELEASE_LANE: &str = "supported";
/// Ack schema the backend answers a batch with.
const ACK_SCHEMA_VERSION: &str = "provider_daily_reference_ack.v1";
/// Provider days are UTC days. The contract pins this literal.
const PROVIDER_DAY_TIMEZONE: &str = "UTC";
/// Sentinel row model meaning "the surface total, not one model".
const ALL_MODELS: &str = "__all__";
/// Hard bound on one batch's declared coverage window.
const MAX_COVERAGE_DAYS: i64 = 200;
/// Hard bound on rows in one batch.
const MAX_ROWS_PER_BATCH: usize = 1_000;
/// How far back a full collection reaches. The provider window is ~120 days.
const LOOKBACK_DAYS: i64 = 120;

/// Local grant-file schema. Independent of the wire schema on purpose: the
/// on-disk shape may change without the contract changing.
const GRANT_FILE_SCHEMA_VERSION: &str = "codex_daily_aggregates_grant.v1";
// Schema 2 keys one entry per account read. A schema-1 file (one account)
// loads as empty: every account starts at its first read.
const STATE_FILE_SCHEMA_VERSION: u16 = 2;
/// An entry no complete discovery has seen for this many days is dropped.
const STATE_ENTRY_RETENTION_DAYS: i64 = 7;

// ---------------------------------------------------------------------------
// Local operator surface - names an operator sees on disk
// ---------------------------------------------------------------------------

const GRANT_DIR: &str = "codex-daily-aggregates";
const GRANT_FILE: &str = "grant.json";
const STATE_FILE: &str = "state.json";
/// Presence disables the capability outright. Fixed contract with the macOS
/// Companion toggle, exactly like the Claude OAuth usage sentinel.
const SENTINEL_FILE: &str = "codex-daily-aggregates-disabled";

// ---------------------------------------------------------------------------
// Posture: honest identity, sparse polling, circuit break instead of adapt
// ---------------------------------------------------------------------------

const PROVIDER_ENDPOINT: &str =
    "https://chatgpt.com/backend-api/wham/analytics/daily-workspace-usage-counts";
/// Day-grain data does not reward frequent polling. Six hours with a modest
/// deterministic spread across our own installs.
const FETCH_INTERVAL_SECONDS: u64 = 6 * 60 * 60;
const FETCH_INTERVAL_JITTER_SECONDS: u64 = 15 * 60;
/// Supervisor tick. The cadence gate above does the real limiting; the short
/// tick only means a grant created after boot activates without a restart.
const POLL_INTERVAL: Duration = Duration::from_secs(30 * 60);
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_LOGGED_DIAGNOSTICS_PER_CYCLE: usize = 20;
/// An unchanged stop is logged again at most this often.
const REPEATED_CYCLE_LOG_INTERVAL_SECONDS: u64 = 6 * 60 * 60;

const BREAKER_COOLDOWN_SECONDS: u64 = 24 * 60 * 60;
const BREAKER_AUTH_THRESHOLD: u32 = 3;
const BREAKER_SHAPE_THRESHOLD: u32 = 3;
const BREAKER_RATE_LIMIT_THRESHOLD: u32 = 5;

const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const LEGACY_API_BASE_URL: &str = "https://ottto.net/backend";

static COLLECTOR_SUPERVISOR_STARTED: AtomicBool = AtomicBool::new(false);

type HmacSha256 = Hmac<Sha256>;

/// Server policy for this grant. Defaults closed so a binding written before
/// the field existed can never be read as approval.
///
/// Lives in the protocol crate because the same value crosses the local control
/// socket; the on-disk and on-wire representations are one type on purpose.
pub use ottto_protocol::ProviderDailyReferenceServerPolicyState as ServerPolicyState;

/// The subset of the backend grant response the daemon binds against. Shared
/// with the local control socket, so the app hands the daemon exactly this
/// projection of the ordinary-browser response and nothing else.
pub use ottto_protocol::ProviderDailyReferenceBackendGrantResponseV1 as GrantResponse;

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

fn sentinel_path() -> PathBuf {
    default_support_dir().join(SENTINEL_FILE)
}

/// Presence of the sentinel disables the capability. Absent is the default and
/// is not by itself permission: the grant still has to be live.
pub fn network_disabled() -> bool {
    sentinel_path().is_file()
}

// ---------------------------------------------------------------------------
// Composition and supervisor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorStartup {
    Started,
}

/// Compose the real runtime and run one cycle.
///
/// Ordering matters: consent is read first, so a machine without a grant does
/// no local work beyond one file read and never touches the account, device,
/// connection, credential, or keychain state.
pub fn collect_composed_once(now: OffsetDateTime) -> Cycle {
    let _stage = StageWindow::begin("codex", "offpass_daily_reference");
    let collector = Collector::default();
    if collector.network_disabled() {
        collector.state.clear();
        return network_disabled_cycle();
    }

    // The default/off path is one local grant read. Nothing below - account,
    // device, connection, destination, credential, or keychain - is touched
    // until consent is capable of becoming runtime-ready.
    if let Err(cycle) = runtime_ready_grant(&collector.grants) {
        return cycle;
    }

    let (runtime, api_base_url) = match load_runtime_binding() {
        Ok(binding) => binding,
        Err(reason) => return deferred(reason),
    };
    // Every Codex home is read once here, after consent and the destination
    // are validated and before any device credential or network use.
    let Some(grant_key) = collector.grants.hmac_key().ok().flatten() else {
        return attribution_unavailable_cycle();
    };
    let (homes, homes_complete) = crate::agent_status::daily_reference_homes();
    let discovery = logins::discover(homes, homes_complete, &grant_key, unix_seconds(now));
    let Ok((device, device_secret)) = crate::snapshot_client::load_snapshot_device_credentials()
    else {
        return deferred("device_credentials_unavailable");
    };
    let hardware = match grant_rebind::verified_live_hardware() {
        Ok(hardware) => hardware,
        Err(reason) => {
            let _ = collector.grants.record_health(None, Some(reason));
            return deferred(reason);
        }
    };
    let account = match FileAccountStore::default().load() {
        Ok(account) => account,
        Err(_) => return deferred("account_state_unreadable"),
    };
    let (Some(organization), Some(user)) = (account.organization.as_ref(), account.user.as_ref())
    else {
        return deferred("account_not_connected");
    };
    if device.device_id != runtime.installation_id {
        return deferred("local_binding_changed");
    }
    // One rebind per tick. A v1 grant covers one account, so it rebinds with
    // that account's login; v2 omits the account from its scope.
    let v1_grant = collector
        .grants
        .load()
        .ok()
        .flatten()
        .filter(|grant| grant.disclosure_version == DISCLOSURE_VERSION_V1);
    let rebind_login = match &v1_grant {
        Some(grant) => discovery.logins.iter().find(|login| {
            opaque_key(&grant_key, &login.credential.account_scope) == grant.account_fingerprint
        }),
        None => discovery.logins.first(),
    };
    let setup = GrantSetup {
        installation_id: runtime.installation_id.clone(),
        organization_scope: organization.id.clone(),
        effective_user_scope: user.id.clone(),
        provider_account_scope: rebind_login
            .map(|login| login.credential.account_scope.clone())
            .unwrap_or_default(),
    };
    let proposal = match collector.grants.prepare_rebind(&setup, hardware) {
        Ok(proposal) => proposal,
        Err(_) if v1_grant.is_some() && rebind_login.is_none() => {
            return deferred("v1_account_not_signed_in")
        }
        Err(_) => return deferred("account_mismatch"),
    };
    if let Some(proposal) = proposal {
        let _ = collector.grants.record_health(None, Some("rebinding"));
        let binding = proposal
            .expected
            .backend_binding
            .as_ref()
            .expect("bound grant");
        let client = crate::snapshot_client::SnapshotApiClient::new(api_base_url.clone());
        match grant_rebind::rebind(
            &client,
            GrantKind::DailyReference,
            &binding.grant_id,
            &proposal.request,
            &device,
            &device_secret,
            UPLOAD_TIMEOUT,
        ) {
            Ok(value) => {
                let response = serde_json::from_value::<GrantResponse>(value);
                if response
                    .ok()
                    .and_then(|response| {
                        collector
                            .grants
                            .bind_backend_grant_with_rebind(
                                &response,
                                &runtime.installation_id,
                                Some(&proposal),
                            )
                            .ok()
                    })
                    .is_none()
                {
                    return deferred("stale_binding");
                }
            }
            Err(failure) => {
                let _ = collector.grants.record_health(None, Some(failure.code));
                return deferred(failure.code);
            }
        }
    }
    let transport = RelayTransport::new(api_base_url, device, device_secret);
    collector.run_tick(
        &runtime,
        &discovery,
        &ChatGptDailyUsageReader,
        &transport,
        &OffsetDateTime::now_utc,
    )
}

/// The account, device, connection and destination a cycle collects with. A
/// gap is a closed reason code so a waiting cycle can say which piece is
/// missing without naming any of its contents. No credential is read here.
fn load_runtime_binding() -> std::result::Result<(Runtime, String), &'static str> {
    let account = FileAccountStore::default()
        .load()
        .map_err(|_| "account_state_unreadable")?;
    if account.state != LocalAccountState::Connected {
        return Err("account_not_connected");
    }
    let device = FileDeviceStore::default()
        .load()
        .map_err(|_| "device_state_unreadable")?
        .ok_or("device_missing")?;
    if !is_uuid(&device.device_id) || !device.sources.iter().any(|source| source == SOURCE) {
        return Err("device_not_bound_to_codex");
    }
    let connection = FileConnectionStore::default()
        .load()
        .map_err(|_| "connection_state_unreadable")?
        .ok_or("connection_missing")?;
    if connection.setup_run_id.trim().is_empty() {
        return Err("connection_setup_incomplete");
    }
    if connection.machine_id != device.machine_id {
        return Err("connection_device_mismatch");
    }
    // Validate the destination before any credential is read, so an on-disk URL
    // can never receive one.
    let api_base_url =
        validated_api_base_url(&connection.api_base_url).map_err(|_| "api_base_url_refused")?;
    Ok((
        Runtime {
            installation_id: device.device_id,
        },
        api_base_url,
    ))
}

fn validated_api_base_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.contains('@') || trimmed.contains('?') || trimmed.contains('#') {
        return Err(anyhow!("api base url is not an accepted destination"));
    }
    let accepted = trimmed == DEFAULT_API_BASE_URL
        || trimmed == LEGACY_API_BASE_URL
        || std::env::var("OTTTO_API_BASE_URL")
            .is_ok_and(|override_url| override_url.trim().trim_end_matches('/') == trimmed);
    if !accepted {
        return Err(anyhow!("api base url is not an accepted destination"));
    }
    Ok(trimmed.to_string())
}

/// Start the collector supervisor.
///
/// The supervisor starts unconditionally and every tick is inert until consent,
/// server policy, and admission all allow, so a grant created after boot
/// activates without a daemon restart.
pub fn spawn_codex_daily_aggregate_collector() -> Result<CollectorStartup> {
    if COLLECTOR_SUPERVISOR_STARTED
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_err()
    {
        return Ok(CollectorStartup::Started);
    }
    let spawned = thread::Builder::new()
        .name("ottto-codex-daily-aggregates".to_string())
        .spawn(|| {
            let started = std::time::Instant::now();
            let mut throttle = CycleLogThrottle::default();
            loop {
                let cycle = collect_composed_once(OffsetDateTime::now_utc());
                for line in throttle.lines(&cycle, started.elapsed().as_secs()) {
                    eprintln!("{line}");
                }
                thread::sleep(POLL_INTERVAL + cycle_jitter());
            }
        });
    if let Err(error) = spawned {
        COLLECTOR_SUPERVISOR_STARTED.store(false, AtomicOrdering::Release);
        return Err(anyhow!("spawn Codex daily aggregates collector: {error}"));
    }
    Ok(CollectorStartup::Started)
}

/// Deduplicates the cycle log of a stuck gate.
///
/// Gate outcomes are re-evaluated every tick without contacting anything, so an
/// unchanged stop would otherwise print the same lines every half hour. A
/// changed report prints at once; an unchanged one prints again only after
/// [`REPEATED_CYCLE_LOG_INTERVAL_SECONDS`], with the number of ticks it hid.
/// Outcomes that follow a provider read are rare (cadence-gated) and always
/// print.
#[derive(Debug, Default)]
struct CycleLogThrottle {
    last_signature: Option<String>,
    last_logged_at: u64,
    suppressed: u64,
}

impl CycleLogThrottle {
    /// Lines to print for this cycle. `now` is monotonic seconds.
    fn lines(&mut self, cycle: &Cycle, now: u64) -> Vec<String> {
        let mut lines = Vec::new();
        if !matches!(cycle.outcome, CycleOutcome::Disabled | CycleOutcome::Noop) {
            lines.push(cycle_summary_log(cycle));
        }
        // Diagnostics are printed whatever the outcome. A Disabled cycle is
        // the one most worth explaining: it is where a live consent quietly
        // stops collecting. Silent outcomes carry no diagnostics anyway.
        lines.extend(cycle_diagnostic_log_lines(&cycle.diagnostics));
        let repeatable_gate = matches!(
            cycle.outcome,
            CycleOutcome::Disabled
                | CycleOutcome::Deferred
                | CycleOutcome::CircuitOpen
                | CycleOutcome::AccountExcluded
        ) && cycle.normalized_row_count.is_none();
        if lines.is_empty() || !repeatable_gate {
            self.last_signature = None;
            return self.with_suppressed_count(lines);
        }
        let signature = lines.join("\n");
        if self.last_signature.as_deref() == Some(signature.as_str())
            && now.saturating_sub(self.last_logged_at) < REPEATED_CYCLE_LOG_INTERVAL_SECONDS
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return Vec::new();
        }
        self.last_signature = Some(signature);
        self.last_logged_at = now;
        self.with_suppressed_count(lines)
    }

    /// Lead printed lines with how many identical reports were hidden since the
    /// last printed one, so a gap in the log never reads as a gap in ticks.
    fn with_suppressed_count(&mut self, lines: Vec<String>) -> Vec<String> {
        if lines.is_empty() || self.suppressed == 0 {
            return lines;
        }
        let mut counted = vec![format!(
            "codex_daily_aggregates_collector_repeats_suppressed count={}",
            self.suppressed
        )];
        self.suppressed = 0;
        counted.extend(lines);
        counted
    }
}

fn cycle_summary_log(cycle: &Cycle) -> String {
    let rows = cycle
        .normalized_row_count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    // Ordinals, home kinds and closed reasons only: never an id or a path.
    let accounts = cycle
        .accounts
        .iter()
        .map(|account| {
            format!(
                "{}:{}:{:?}:{}",
                account.ordinal,
                account.home_kind,
                account.outcome,
                account.reason.unwrap_or("not_due")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "codex_daily_aggregates_collector outcome={:?} rows={rows} diagnostics={} accounts=[{accounts}]",
        cycle.outcome,
        cycle.diagnostics.len()
    )
}

fn cycle_diagnostic_log_lines(diagnostics: &[AgentStatusDiagnostic]) -> Vec<String> {
    let mut lines = diagnostics
        .iter()
        .take(MAX_LOGGED_DIAGNOSTICS_PER_CYCLE)
        .map(|diagnostic| {
            format!(
                "codex_daily_aggregates_collector_diagnostic severity={:?} code={} message={:?}",
                diagnostic.severity, diagnostic.code, diagnostic.message
            )
        })
        .collect::<Vec<_>>();
    let suppressed = diagnostics
        .len()
        .saturating_sub(MAX_LOGGED_DIAGNOSTICS_PER_CYCLE);
    if suppressed > 0 {
        lines.push(format!(
            "codex_daily_aggregates_collector_diagnostics_suppressed count={suppressed}"
        ));
    }
    lines
}

fn cycle_jitter() -> Duration {
    Duration::from_secs(u64::from(OffsetDateTime::now_utc().second()) % 61)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn opaque_key(key: &[u8], raw: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(raw.as_bytes());
    format!("hmac-sha256:{}", hex(&mac.finalize().into_bytes()))
}

fn timestamp(value: OffsetDateTime) -> String {
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn unix_seconds(value: OffsetDateTime) -> u64 {
    u64::try_from(value.unix_timestamp()).unwrap_or_default()
}

fn atomic_json_write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("codex daily aggregates state path has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let payload = serde_json::to_vec(value)?;
    let mut nonce = [0_u8; 16];
    random_fill(&mut nonce).map_err(|_| anyhow!("generate codex daily aggregates nonce"))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("codex daily aggregates state filename is invalid"))?;
    let temporary = parent.join(format!(".{filename}.{}.tmp", hex(&nonce)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .context("create codex daily aggregates temporary state")?;
        file.write_all(&payload)
            .context("write codex daily aggregates temporary state")?;
        file.sync_all()
            .context("sync codex daily aggregates temporary state")?;
        drop(file);
        fs::rename(&temporary, path).context("replace codex daily aggregates state")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync codex daily aggregates state directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

pub(crate) mod logins;

#[cfg(test)]
mod tests;
