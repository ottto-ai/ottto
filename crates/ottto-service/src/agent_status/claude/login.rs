//! Claude status login operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::billing_identity_evidence_for;
use crate::agent_status::billing_identity_hash;
#[cfg(test)]
use crate::agent_status::claude_account_identifier_hash;
#[cfg(test)]
use crate::agent_status::claude_credentials_file_test_hooks;
use crate::agent_status::claude_oauth_usage_account_state_dir;
use crate::agent_status::default_support_dir;
use crate::agent_status::first_json_string;
use crate::agent_status::fs;
use crate::agent_status::home_dir;
use crate::agent_status::nested_json_string;
use crate::agent_status::normalize_plan_type;
use crate::agent_status::run_command_capture;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::ClaudeConfigDirSlot;
use crate::agent_status::ClaudeCredentialRead;
use crate::agent_status::ClaudeLiveLogin;
use crate::agent_status::ClaudeLocalLoginState;
use crate::agent_status::ClaudeOAuthCredential;
#[cfg(test)]
use crate::agent_status::ClaudeOAuthCredentialMetadata;
use crate::agent_status::ClaudeSlotProbeFailure;
use crate::agent_status::Command;
use crate::agent_status::Duration;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
#[cfg(unix)]
use crate::agent_status::Read;
use crate::agent_status::Rfc3339;
use crate::agent_status::StableClaudeSlotCredential;
use crate::agent_status::TimeDuration;
use crate::agent_status::Value;
use crate::agent_status::CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS;
use crate::agent_status::CLAUDE_OAUTH_USAGE_CACHE_FILE;
use crate::agent_status::CLAUDE_OAUTH_USAGE_LEGACY_CACHE_FILE;
use crate::agent_status::COMMAND_TIMEOUT;

pub(in crate::agent_status) fn claude_local_login_state(
    read: &ClaudeCredentialRead,
    now: OffsetDateTime,
) -> ClaudeLocalLoginState {
    let credential = match read {
        ClaudeCredentialRead::Absent => return ClaudeLocalLoginState::NotSignedIn,
        ClaudeCredentialRead::Unreadable => return ClaudeLocalLoginState::Unreadable,
        ClaudeCredentialRead::Present(credential) => credential,
    };
    if credential.cleared_by_cli() {
        return ClaudeLocalLoginState::SignedOutByCli;
    }
    if !credential.has_refresh_token {
        return ClaudeLocalLoginState::NeedsLogin;
    }
    let parse = |at: Option<&str>| at.and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok());
    if parse(credential.relogin_required_at.as_deref()).is_some_and(|deadline| deadline <= now) {
        return ClaudeLocalLoginState::NeedsLogin;
    }
    let Some(access_expiry) = parse(credential.access_expires_at.as_deref()) else {
        // A refresh token without a readable access deadline: the gate cannot
        // prove a spawn is safe and the status cannot say what holds.
        return ClaudeLocalLoginState::Unreadable;
    };
    if credential.access_token.is_none() || credential.has_inference_scope != Some(true) {
        return ClaudeLocalLoginState::Unreadable;
    }
    if access_expiry > now + TimeDuration::seconds(CLAUDE_ACCESS_EXPIRY_MARGIN_SECONDS) {
        ClaudeLocalLoginState::AccessValid
    } else {
        ClaudeLocalLoginState::RefreshPending
    }
}

pub(in crate::agent_status) fn read_claude_oauth_credential_for_slot(
    slot: &ClaudeConfigDirSlot,
) -> Option<ClaudeOAuthCredential> {
    read_claude_oauth_credential_state_for_slot(slot).into_credential()
}

#[cfg(test)]
pub(crate) fn read_claude_oauth_credential_metadata_for_slot(
    slot: &ClaudeConfigDirSlot,
) -> Option<ClaudeOAuthCredentialMetadata> {
    read_claude_oauth_credential_state_for_slot(slot).metadata()
}

/// Read one exact slot's stored Claude login from where Claude Code keeps it
/// on this OS (see [`claude_credentials_in_keychain`]).
pub(in crate::agent_status) fn read_claude_oauth_credential_state_for_slot(
    slot: &ClaudeConfigDirSlot,
) -> ClaudeCredentialRead {
    read_claude_oauth_credential_state_from_store(slot, claude_credentials_in_keychain())
}

/// Claude Code keeps its login in the keychain on macOS and in the native
/// credentials file (`<config dir>/.credentials.json`) everywhere else. Off
/// macOS the keychain tool is never run, even when some program named
/// `security` is on the search path.
pub(in crate::agent_status) const fn claude_credentials_in_keychain() -> bool {
    cfg!(target_os = "macos")
}

/// With `keychain`, the keychain item first, then the credentials-file
/// fallback. Only `security` exit 44 (item not found) falls through to the
/// file; every other keychain outcome (no `security` tool on the search path,
/// locked keychain, timeout, spawn failure, unparseable JSON) is
/// `Unreadable`: the login cannot be confirmed either way, never "signed
/// out". Without `keychain`, the credentials file alone. Both read the file
/// through [`read_claude_credentials_file`].
///
/// The item is read with `security find-generic-password -w`, so the secret
/// passes through a pipe into daemon memory. It is parsed here and dropped;
/// only the access token travels on, to the usage request.
pub(in crate::agent_status) fn read_claude_oauth_credential_state_from_store(
    slot: &ClaudeConfigDirSlot,
    keychain: bool,
) -> ClaudeCredentialRead {
    if !keychain {
        return read_claude_oauth_credential_from_credentials_file(slot);
    }
    match read_claude_oauth_credential_from_keychain(slot) {
        ClaudeKeychainRead::Found(payload) => parse_claude_oauth_credential_read(&payload),
        ClaudeKeychainRead::NotFound => read_claude_oauth_credential_from_credentials_file(slot),
        ClaudeKeychainRead::Failed => ClaudeCredentialRead::Unreadable,
    }
}

/// Exact-slot login state from one fresh local read. Never spawns `claude`.
pub(crate) fn read_claude_live_login_for_slot(slot: &ClaudeConfigDirSlot) -> ClaudeLiveLogin {
    let read = read_claude_oauth_credential_state_for_slot(slot);
    ClaudeLiveLogin {
        state: claude_local_login_state(&read, OffsetDateTime::now_utc()),
        metadata: read.metadata(),
    }
}

/// The stored credential's modification marker, for the refresher's log: on
/// macOS the keychain item's `mdat` attribute (read without `-w`, so no secret
/// is printed), otherwise the credentials file's mtime. Never the contents.
pub(crate) fn claude_credential_modified_marker(slot: &ClaudeConfigDirSlot) -> Option<String> {
    if claude_credentials_in_keychain() && crate::command_env::executable_path("security").is_some()
    {
        if let Some(account) = effective_user_account_name() {
            let service = slot.service_name();
            let output = run_command_capture(
                "security",
                &["find-generic-password", "-a", &account, "-s", &service],
                COMMAND_TIMEOUT,
            );
            if output.success {
                return output
                    .stdout
                    .lines()
                    .chain(output.stderr.lines())
                    .find(|line| line.trim_start().starts_with("\"mdat\""))
                    .map(|line| line.trim().to_string());
            }
        }
    }
    std::fs::metadata(slot.credentials_path(&home_dir()))
        .and_then(|metadata| metadata.modified())
        .ok()
        .map(|modified| format!("{modified:?}"))
}

/// Spawn-gate view of one exact slot's stored credential: token presence and
/// the raw access deadline only.
pub(crate) fn read_claude_spawn_gate_credential(
    slot: &ClaudeConfigDirSlot,
) -> crate::claude_spawn_gate::ClaudeGateCredential {
    claude_gate_credential(
        &read_claude_oauth_credential_state_for_slot(slot),
        OffsetDateTime::now_utc(),
    )
}

/// The spawn gate's view, derived from the one login classifier
/// ([`claude_local_login_state`]) so the status, the gate and the refresher
/// always agree. A missing or unparseable access deadline, a missing access
/// token or inference scope, or a failed read is `Unreadable` there and
/// `ReadFailed` here: no spawn, no refresh.
pub(in crate::agent_status) fn claude_gate_credential(
    read: &ClaudeCredentialRead,
    now: OffsetDateTime,
) -> crate::claude_spawn_gate::ClaudeGateCredential {
    use crate::claude_spawn_gate::ClaudeGateCredential;
    match claude_local_login_state(read, now) {
        ClaudeLocalLoginState::NotSignedIn => ClaudeGateCredential::Absent,
        ClaudeLocalLoginState::Unreadable => ClaudeGateCredential::ReadFailed,
        // Nothing left to refresh, so nothing a short run could lose.
        ClaudeLocalLoginState::SignedOutByCli | ClaudeLocalLoginState::NeedsLogin => {
            ClaudeGateCredential::Present {
                has_refresh_token: false,
                access_expires_at: None,
            }
        }
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending => {
            ClaudeGateCredential::Present {
                has_refresh_token: true,
                access_expires_at: read.metadata().and_then(|metadata| {
                    OffsetDateTime::parse(metadata.access_expires_at.as_deref()?, &Rfc3339).ok()
                }),
            }
        }
    }
}

pub(in crate::agent_status) enum ClaudeKeychainRead {
    Found(String),
    NotFound,
    Failed,
}

/// `security` exits 44 (`errSecItemNotFound`) when the item does not exist.
pub(in crate::agent_status) const SECURITY_ITEM_NOT_FOUND_EXIT_CODE: i32 = 44;

pub(in crate::agent_status) fn read_claude_oauth_credential_from_keychain(
    slot: &ClaudeConfigDirSlot,
) -> ClaudeKeychainRead {
    read_claude_oauth_credential_from_keychain_with_timeout(slot, COMMAND_TIMEOUT)
}

pub(in crate::agent_status) fn read_claude_oauth_credential_from_keychain_with_timeout(
    slot: &ClaudeConfigDirSlot,
    timeout: Duration,
) -> ClaudeKeychainRead {
    if crate::command_env::executable_path("security").is_none() {
        // Without the keychain tool the stored login cannot be confirmed
        // either way: fail closed, never "no login".
        return ClaudeKeychainRead::Failed;
    }
    let Some(account) = effective_user_account_name() else {
        return ClaudeKeychainRead::Failed;
    };
    let Some(arguments) = claude_oauth_keychain_lookup_arguments(slot, &account) else {
        return ClaudeKeychainRead::Failed;
    };
    let argument_refs: Vec<_> = arguments.iter().map(String::as_str).collect();
    let output = run_command_capture("security", &argument_refs, timeout);
    if output.success {
        return ClaudeKeychainRead::Found(output.stdout);
    }
    if output.command_found && output.status_code == Some(SECURITY_ITEM_NOT_FOUND_EXIT_CODE) {
        return ClaudeKeychainRead::NotFound;
    }
    ClaudeKeychainRead::Failed
}

pub(in crate::agent_status) struct EffectiveUserIdentity {
    pub(in crate::agent_status) account_name: String,
    pub(in crate::agent_status) home_dir: PathBuf,
}

pub(in crate::agent_status) fn effective_user_account_name() -> Option<String> {
    effective_user_identity().map(|identity| identity.account_name)
}

#[cfg(unix)]
pub(in crate::agent_status) fn effective_user_identity() -> Option<EffectiveUserIdentity> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    // LaunchAgents are not guaranteed to inherit USER. Resolve the account
    // that owns this daemon from its effective uid instead of trusting ambient
    // environment state when selecting a same-service Keychain item.
    let uid = unsafe { libc::geteuid() };
    let size_hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_size = usize::try_from(size_hint)
        .ok()
        .filter(|size| (1_024..=1_048_576).contains(size))
        .unwrap_or(16_384);

    for _ in 0..3 {
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_size];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_size = buffer_size.checked_mul(2)?.min(1_048_576);
            continue;
        }
        if status != 0 || result.is_null() {
            return None;
        }
        let passwd = unsafe { passwd.assume_init() };
        if passwd.pw_name.is_null() || passwd.pw_dir.is_null() {
            return None;
        }
        let account = unsafe { CStr::from_ptr(passwd.pw_name) }
            .to_str()
            .ok()?
            .to_string();
        let home_dir = PathBuf::from(unsafe { CStr::from_ptr(passwd.pw_dir) }.to_str().ok()?);
        #[cfg(test)]
        let home_dir = std::env::var_os("OTTTO_EFFECTIVE_USER_HOME_FOR_TESTS")
            .map(PathBuf::from)
            .unwrap_or(home_dir);
        if account.is_empty() || !home_dir.is_absolute() {
            return None;
        }
        return Some(EffectiveUserIdentity {
            account_name: account,
            home_dir,
        });
    }
    None
}

#[cfg(not(unix))]
pub(in crate::agent_status) fn effective_user_identity() -> Option<EffectiveUserIdentity> {
    let account_name = std::env::var("USER")
        .ok()
        .filter(|account| !account.is_empty() && !account.contains('\0'))?;
    let home_dir = PathBuf::from(std::env::var_os("HOME")?);
    home_dir.is_absolute().then_some(EffectiveUserIdentity {
        account_name,
        home_dir,
    })
}

pub(in crate::agent_status) fn claude_oauth_keychain_lookup_arguments(
    slot: &ClaudeConfigDirSlot,
    account: &str,
) -> Option<Vec<String>> {
    if account.is_empty() || account.contains('\0') {
        return None;
    }
    Some(vec![
        "find-generic-password".to_string(),
        "-a".to_string(),
        account.to_string(),
        "-s".to_string(),
        slot.service_name(),
        "-w".to_string(),
    ])
}

pub(in crate::agent_status) fn read_claude_oauth_credential_from_credentials_file(
    slot: &ClaudeConfigDirSlot,
) -> ClaudeCredentialRead {
    read_claude_credentials_file(&slot.credentials_path(&home_dir()))
}

/// The one reader for Claude Code's native credentials file, used by the
/// status read on every OS (directly off macOS, after keychain "not found" on
/// macOS) and by the session-launch check. A missing file is `Absent`. A file
/// that cannot be opened without following a final symlink, is not a regular
/// file, is not owned by the effective user or grants any group/other
/// permission is `Unreadable`, as is any other I/O failure. The whole file is
/// read from the checked handle and never modified. Unit-test reads are
/// scratch-only.
#[cfg(unix)]
pub(in crate::agent_status) fn read_claude_credentials_file(path: &Path) -> ClaudeCredentialRead {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !crate::provider_calls::readable_for_account(path) {
        return ClaudeCredentialRead::Unreadable;
    }
    #[cfg(test)]
    claude_credentials_file_test_hooks::before_read(path);
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ClaudeCredentialRead::Absent
        }
        Err(_) => return ClaudeCredentialRead::Unreadable,
    };
    let Ok(metadata) = file.metadata() else {
        return ClaudeCredentialRead::Unreadable;
    };
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return ClaudeCredentialRead::Unreadable;
    }
    let mut body = String::new();
    if file.read_to_string(&mut body).is_err() {
        return ClaudeCredentialRead::Unreadable;
    }
    parse_claude_oauth_credential_read(&body)
}

/// Without owner, mode and no-follow checks the file cannot be trusted:
/// fail closed.
#[cfg(not(unix))]
pub(in crate::agent_status) fn read_claude_credentials_file(_path: &Path) -> ClaudeCredentialRead {
    ClaudeCredentialRead::Unreadable
}

/// A stored payload that is not JSON, or whose `claudeAiOauth` is not an
/// object, is `Unreadable`. A JSON object without `claudeAiOauth` (for example
/// an item that holds only MCP server logins) carries no Claude login.
pub(in crate::agent_status) fn parse_claude_oauth_credential_read(
    payload: &str,
) -> ClaudeCredentialRead {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return ClaudeCredentialRead::Unreadable;
    };
    if !value.is_object() {
        return ClaudeCredentialRead::Unreadable;
    }
    match value.get("claudeAiOauth") {
        None | Some(Value::Null) => ClaudeCredentialRead::Absent,
        Some(oauth) if oauth.is_object() => parse_claude_oauth_credential_value(oauth).map_or(
            ClaudeCredentialRead::Unreadable,
            ClaudeCredentialRead::Present,
        ),
        Some(_) => ClaudeCredentialRead::Unreadable,
    }
}

#[cfg(test)]
pub(in crate::agent_status) fn parse_claude_oauth_access_token(payload: &str) -> Option<String> {
    parse_claude_oauth_credential(payload)?.access_token
}

#[cfg(test)]
pub(in crate::agent_status) fn parse_claude_oauth_credential(
    payload: &str,
) -> Option<ClaudeOAuthCredential> {
    let value: Value = serde_json::from_str(payload).ok()?;
    parse_claude_oauth_credential_value(value.get("claudeAiOauth")?)
}

pub(in crate::agent_status) fn parse_claude_oauth_credential_value(
    oauth: &Value,
) -> Option<ClaudeOAuthCredential> {
    let access_token = oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToString::to_string);
    let has_refresh_token = oauth
        .get("refreshToken")
        .and_then(Value::as_str)
        .is_some_and(|token| !token.trim().is_empty());
    let timestamp = |field: &str| {
        oauth
            .get(field)
            .and_then(Value::as_i64)
            .and_then(rfc3339_from_epoch_millis)
    };
    let has_inference_scope = oauth.get("scopes").and_then(Value::as_array).map(|scopes| {
        scopes
            .iter()
            .filter_map(Value::as_str)
            .any(|scope| scope.trim() == CLAUDE_INFERENCE_SCOPE)
    });
    let has_profile_scope = oauth
        .get("scopes")
        .and_then(Value::as_array)
        .is_some_and(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .any(|scope| scope.trim() == CLAUDE_PROFILE_SCOPE)
        });
    let subscription_type = oauth
        .get("subscriptionType")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    Some(ClaudeOAuthCredential {
        access_token,
        has_refresh_token,
        access_expires_at: timestamp("expiresAt"),
        relogin_required_at: timestamp("refreshTokenExpiresAt"),
        has_inference_scope,
        has_profile_scope,
        subscription_type,
    })
}

/// The OAuth scope Claude Code requires before it reports a login as signed in.
pub(in crate::agent_status) const CLAUDE_INFERENCE_SCOPE: &str = "user:inference";

/// The OAuth scope Claude Code's `/usage` needs before it reads plan usage.
pub(in crate::agent_status) const CLAUDE_PROFILE_SCOPE: &str = "user:profile";

pub(in crate::agent_status) fn rfc3339_from_epoch_millis(epoch_millis: i64) -> Option<String> {
    let seconds = epoch_millis.div_euclid(1_000);
    let nanos = u32::try_from(epoch_millis.rem_euclid(1_000)).ok()? * 1_000_000;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .replace_nanosecond(nanos)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

pub(in crate::agent_status) fn claude_oauth_usage_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(401 | 403, _) => {
            "Claude OAuth usage endpoint rejected the local Claude Code session.".to_string()
        }
        ureq::Error::Status(429, _) => "Claude OAuth usage endpoint is rate limited.".to_string(),
        ureq::Error::Status(status, _) => {
            format!("Claude OAuth usage endpoint returned HTTP {status}.")
        }
        ureq::Error::Transport(_) => "Claude OAuth usage endpoint was unreachable.".to_string(),
    }
}

pub(in crate::agent_status) fn claude_oauth_usage_cache_path(
    account_identifier_hash: &str,
    organization_identifier_hash: &str,
) -> PathBuf {
    claude_oauth_usage_account_state_dir(account_identifier_hash, organization_identifier_hash)
        .join(CLAUDE_OAUTH_USAGE_CACHE_FILE)
}

pub(in crate::agent_status) fn claude_oauth_usage_legacy_cache_path() -> PathBuf {
    default_support_dir().join(CLAUDE_OAUTH_USAGE_LEGACY_CACHE_FILE)
}

/// Identify the Claude account that currently owns the local Claude Code
/// credential, as a `billing_identity_hash`. Callers resolve it from
/// `read_claude_cli_oauth_account`; an account-less config yields an empty
/// hash.
///
/// Deliberately NOT a hash of the access token: the token rotates on refresh
/// while the account does not, so a token fingerprint would discard a valid
/// same-account cache on every rotation -- extra fetches against an endpoint
/// that rate-limits, and no cache left to fall back on when it answers 429.
/// `oauthAccount` is rewritten by Claude Code itself on every profile refresh,
/// so it tracks the credential without inheriting its rotation.
#[cfg(test)]
pub(in crate::agent_status) fn claude_oauth_account_identifier_hash_for(
    account: &ClaudeCliOauthAccount,
) -> String {
    // Same preference order the subscription grouping uses: provider account
    // id, then organization, then email. It lives in `ottto-core` because the
    // CLI's statusLine writer stamps the same hash and the two must agree
    // exactly -- a divergence would read as "foreign cache" and quota would
    // silently vanish rather than fail loudly.
    claude_account_identifier_hash(
        account.account_uuid.as_deref(),
        account.organization_uuid.as_deref(),
        account.email_address.as_deref(),
    )
}

/// Multi-account collection never assigns full meters through organization or
/// email fallback. Both provider UUIDs must be present and independently
/// hashed before a window or credit can leave the machine.
pub(in crate::agent_status) fn claude_strong_oauth_identity_hashes(
    account: &ClaudeCliOauthAccount,
) -> Option<(String, String)> {
    let account_hash = account
        .account_uuid
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "account", value))?;
    let organization_hash = account
        .organization_uuid
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "organization", value))?;
    Some((account_hash, organization_hash))
}

pub(in crate::agent_status) fn stable_claude_slot_credential(
    initial_oauth_account: Option<ClaudeCliOauthAccount>,
    initial_credential: Option<ClaudeOAuthCredential>,
    final_oauth_account: Option<ClaudeCliOauthAccount>,
) -> Result<StableClaudeSlotCredential, ClaudeSlotProbeFailure> {
    let (Some(initial_oauth_account), Some(final_oauth_account)) =
        (initial_oauth_account, final_oauth_account)
    else {
        return Err(ClaudeSlotProbeFailure::IdentityUnknown);
    };
    if initial_oauth_account != final_oauth_account {
        return Err(ClaudeSlotProbeFailure::ConcurrentMutation);
    }
    Ok(StableClaudeSlotCredential {
        oauth_account: initial_oauth_account,
        credential: initial_credential.unwrap_or(ClaudeOAuthCredential {
            access_token: None,
            has_refresh_token: false,
            access_expires_at: None,
            relogin_required_at: None,
            has_inference_scope: None,
            has_profile_scope: false,
            subscription_type: None,
        }),
    })
}

pub(in crate::agent_status) fn parse_claude_auth_json(value: &Value) -> AgentAccountStatus {
    let login_state = match first_json_string(
        value,
        &["status", "state", "login_state", "logged_in", "loggedIn"],
    )
    .as_deref()
    {
        Some("authenticated") | Some("signed_in") | Some("logged_in") | Some("true") => {
            AgentLoginState::SignedIn
        }
        Some("signed_out") | Some("logged_out") | Some("unauthenticated") | Some("false") => {
            AgentLoginState::SignedOut
        }
        _ => {
            if first_json_string(value, &["email", "account_email", "accountEmail"]).is_some() {
                AgentLoginState::SignedIn
            } else {
                AgentLoginState::Unknown
            }
        }
    };
    let plan_type = first_json_string(
        value,
        &[
            "subscription_type",
            "subscriptionType",
            "plan_type",
            "planType",
            "plan",
            "tier",
        ],
    )
    .map(normalize_plan_type);
    let api_provider = first_json_string(value, &["api_provider", "apiProvider"]);
    let organization_id = first_json_string(
        value,
        &["organization_id", "organizationId", "org_id", "orgId"],
    )
    .or_else(|| nested_json_string(value, &["organization", "org"], &["id"]));
    let organization_label = first_json_string(
        value,
        &[
            "organization_label",
            "organizationLabel",
            "organization_name",
            "organizationName",
            "org_name",
            "orgName",
        ],
    )
    .or_else(|| nested_json_string(value, &["organization", "org"], &["name", "label"]));
    let account_id = first_json_string(value, &["account_id", "accountId", "user_id", "userId"]);
    let account_identifier_hash = account_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "account", value));
    let organization_identifier_hash = organization_id
        .as_deref()
        .and_then(|value| billing_identity_hash("anthropic", "organization", value));
    let billing_identity_evidence = billing_identity_evidence_for(
        &account_identifier_hash,
        &organization_identifier_hash,
        &None,
    );
    AgentAccountStatus {
        login_state,
        provider: Some("anthropic".to_string()),
        auth_method: first_json_string(
            value,
            &[
                "auth_method",
                "authMethod",
                "auth_type",
                "authType",
                "method",
            ],
        )
        .or(Some("oauth".to_string())),
        email: first_json_string(value, &["email", "account_email", "accountEmail"]),
        account_id,
        organization_id,
        organization_label,
        plan_type: plan_type.clone(),
        subscription_product: plan_type.clone().map(|plan| {
            if plan.starts_with("claude_") {
                plan
            } else {
                format!("claude_{plan}")
            }
        }),
        billing_channel: Some(claude_billing_channel(
            api_provider.as_deref(),
            plan_type.as_deref(),
        )),
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash,
        organization_identifier_hash,
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence,
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    }
}

pub(in crate::agent_status) fn claude_billing_channel(
    api_provider: Option<&str>,
    plan_type: Option<&str>,
) -> String {
    match api_provider.map(|value| normalize_plan_type(value.to_string())) {
        Some(provider) if provider.contains("bedrock") => "amazon_bedrock".to_string(),
        Some(provider) if provider.contains("vertex") => "google_vertex".to_string(),
        Some(provider) if provider.contains("first_party") || provider.contains("firstparty") => {
            "subscription".to_string()
        }
        Some(provider) if provider.contains("anthropic") && plan_type.is_none() => {
            "direct_api".to_string()
        }
        _ if plan_type.is_some() => "subscription".to_string(),
        _ => "subscription".to_string(),
    }
}

/// Display-safe account metadata Claude Code itself persists to
/// `~/.claude.json` under `oauthAccount` after each profile refresh. The file
/// holds no tokens or secrets; it is the same class of local app state as the
/// Claude Desktop config and statusLine caches this collector already reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::agent_status) struct ClaudeCliOauthAccount {
    pub(in crate::agent_status) account_uuid: Option<String>,
    pub(in crate::agent_status) email_address: Option<String>,
    pub(in crate::agent_status) organization_uuid: Option<String>,
    /// Display only; replaces the `orgName` that `claude auth status` printed.
    pub(in crate::agent_status) organization_name: Option<String>,
    pub(in crate::agent_status) organization_type: Option<String>,
    pub(in crate::agent_status) seat_tier: Option<String>,
    pub(in crate::agent_status) organization_rate_limit_tier: Option<String>,
    pub(in crate::agent_status) user_rate_limit_tier: Option<String>,
}

/// Full-meter collection requires a signed-in account whose email and
/// organization UUID are both present and equal to the exact slot's local
/// account metadata before the account UUID from that identity file may become
/// strong meter identity. The account is now built from that same local
/// metadata (as `claude auth status` itself did), so this check keeps its old
/// requirement that both fields exist. Absence of contradiction is not
/// identity evidence.
pub(in crate::agent_status) fn require_claude_auth_identity_agreement(
    account: &AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Result<(), ClaudeSlotProbeFailure> {
    if account.login_state != AgentLoginState::SignedIn {
        return Err(ClaudeSlotProbeFailure::CredentialUnavailable);
    }
    let (Some(auth_email), Some(auth_organization)) =
        (account.email.as_deref(), account.organization_id.as_deref())
    else {
        return Err(ClaudeSlotProbeFailure::IdentityUnknown);
    };
    let (Some(local_email), Some(local_organization)) = (
        oauth.email_address.as_deref(),
        oauth.organization_uuid.as_deref(),
    ) else {
        return Err(ClaudeSlotProbeFailure::IdentityUnknown);
    };
    if !auth_email.trim().eq_ignore_ascii_case(local_email.trim())
        || !auth_organization
            .trim()
            .eq_ignore_ascii_case(local_organization.trim())
    {
        return Err(ClaudeSlotProbeFailure::IdentityMismatch);
    }
    Ok(())
}

/// Local claims only: compare with the accepted slot binding, never adopt.
/// Use the established local login classifier before granting launch or
/// nickname authority. The exact passwd home is used for file fallback.
/// No provider executable is invoked. Test reads are scratch-only and never
/// consult the real Keychain, including on the native CI lane.
pub(crate) fn session_launch_claude_login_state(
    slot: &ClaudeConfigDirSlot,
    home: &Path,
) -> ClaudeLocalLoginState {
    let read_file = || read_claude_credentials_file(&slot.credentials_path(home));
    #[cfg(all(target_os = "macos", not(test)))]
    let read =
        match read_claude_oauth_credential_from_keychain_with_timeout(slot, Duration::from_secs(2))
        {
            ClaudeKeychainRead::Found(payload) => parse_claude_oauth_credential_read(&payload),
            ClaudeKeychainRead::NotFound => read_file(),
            ClaudeKeychainRead::Failed => ClaudeCredentialRead::Unreadable,
        };
    #[cfg(any(not(target_os = "macos"), test))]
    let read = read_file();
    claude_local_login_state(&read, OffsetDateTime::now_utc())
}

pub(crate) fn session_launch_claude_identity(
    slot: &ClaudeConfigDirSlot,
    home: &Path,
) -> Option<(String, String)> {
    let identity = read_claude_cli_oauth_account(&slot.identity_path(home))?;
    Some((
        billing_identity_hash("anthropic", "account", identity.account_uuid.as_deref()?)?,
        billing_identity_hash(
            "anthropic",
            "organization",
            identity.organization_uuid.as_deref()?,
        )?,
    ))
}

pub(in crate::agent_status) fn read_claude_cli_oauth_account(
    path: &Path,
) -> Option<ClaudeCliOauthAccount> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    parse_claude_cli_oauth_account(&value)
}

pub(in crate::agent_status) fn parse_claude_cli_oauth_account(
    value: &Value,
) -> Option<ClaudeCliOauthAccount> {
    let account = value.get("oauthAccount")?;
    if !account.is_object() {
        return None;
    }
    let field = |key: &str| {
        account
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    Some(ClaudeCliOauthAccount {
        account_uuid: field("accountUuid"),
        email_address: field("emailAddress"),
        organization_uuid: field("organizationUuid"),
        organization_name: field("organizationName"),
        organization_type: field("organizationType"),
        seat_tier: field("seatTier"),
        organization_rate_limit_tier: field("organizationRateLimitTier"),
        user_rate_limit_tier: field("userRateLimitTier"),
    })
}

/// Identity guard shared by every consumer of `~/.claude.json` account
/// metadata: the file can lag behind `claude auth status` after an account
/// switch, so metadata is only trusted when neither the email nor the
/// organization contradicts the auth-status identity. A field absent on
/// either side is not a mismatch — only two present-and-different values
/// refuse.
pub(in crate::agent_status) fn claude_cli_oauth_identity_mismatch(
    account: &AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> bool {
    let mismatch = |ours: &Option<String>, theirs: &Option<String>| match (ours, theirs) {
        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b.trim()),
        _ => false,
    };
    mismatch(&account.email, &oauth.email_address)
        || mismatch(&account.organization_id, &oauth.organization_uuid)
}

/// Stamp the Claude account identity from the local Claude Code account
/// metadata (`~/.claude.json` `oauthAccount`) onto the auth-status account.
/// `claude auth status --json` names the organization but not the account
/// uuid, so without this the CLI plan observation reaches the backend with an
/// organization hash only while the quota windows from the very same
/// `oauthAccount` carry the account hash — plan and quota evidence then
/// resolve at different ranks and cannot deterministically converge.
///
/// Same identity guard as the seat/tier refinements above: stale metadata
/// from a different account must never be stamped, and a present auth-status
/// account id that disagrees with `accountUuid` also refuses. Uses the exact
/// `billing_identity_hash("anthropic", "account", …)` the quota path stamps,
/// never a second hashing implementation.
pub(in crate::agent_status) fn stamp_claude_cli_account_identity(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> bool {
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return false;
    }
    let Some(account_uuid) = oauth.account_uuid.as_deref() else {
        return false;
    };
    if let Some(existing) = account.account_id.as_deref() {
        if !existing.eq_ignore_ascii_case(account_uuid.trim()) {
            return false;
        }
    }
    let Some(account_identifier_hash) = billing_identity_hash("anthropic", "account", account_uuid)
    else {
        return false;
    };
    if account.account_id.is_none() {
        account.account_id = Some(account_uuid.to_string());
    }
    if account.account_identifier_hash.is_none() {
        account.account_identifier_hash = Some(account_identifier_hash);
    }
    account.billing_identity_evidence = billing_identity_evidence_for(
        &account.account_identifier_hash,
        &account.organization_identifier_hash,
        &account.credential_fingerprint_hash,
    );
    true
}

/// Outcome of the local-metadata plan refinements, one field per rule.
#[derive(Debug, Default, PartialEq, Eq)]
pub(in crate::agent_status) struct RefinedClaudeLocalPlan {
    pub(in crate::agent_status) seat_plan: Option<&'static str>,
    pub(in crate::agent_status) max_plan: Option<&'static str>,
}

/// Apply every local-metadata plan refinement to a freshly parsed Claude
/// account.
///
/// The stored `subscriptionType` (what `claude auth status` printed) is a bare
/// `team` for every seat tier and a bare `max` for BOTH Max tiers, so the only
/// disambiguator is the rate-limit / seat metadata in the slot's own
/// `.claude.json`. Every collector must run these refinements, not just the
/// default slot:
/// a registered (`CLAUDE_CONFIG_DIR`) slot left unrefined ships a bare plan,
/// and the backend then prices the conservative lower bound — a Max 20x
/// account reads as Max 5x ($100 instead of $200), a Team Premium seat as
/// Team Standard ($25 instead of $125).
///
/// Callers must have already established identity agreement between `account`
/// and `oauth`; each rule additionally re-checks identity itself.
pub(in crate::agent_status) fn refine_claude_local_plan_metadata(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> RefinedClaudeLocalPlan {
    // Mutually exclusive by plan_type gate (`team` vs `max`).
    RefinedClaudeLocalPlan {
        seat_plan: refine_claude_team_seat_plan(account, oauth),
        max_plan: refine_claude_max_rate_limit_plan(account, oauth),
    }
}

/// Refine a generic Claude `team` plan into `team_premium` / `team_standard`
/// when the local Claude Code account metadata carries an explicit seat-tier
/// signal. Mirrors the Claude Max 5x/20x rule: explicit collector evidence
/// only, never a guess — an unrecognized or absent signal leaves the generic
/// `team` plan untouched. Premium detection accepts either a literal
/// `seatTier` value or the `*_max_5x` rate-limit tier, which is the signal
/// Claude Code's own internals use to identify a premium Team seat.
pub(in crate::agent_status) fn refine_claude_team_seat_plan(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Option<&'static str> {
    if account.plan_type.as_deref() != Some("team") {
        return None;
    }
    // Identity guard: `~/.claude.json` can lag behind `claude auth status`
    // after an account switch. Refuse to mix metadata across accounts.
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return None;
    }
    if let Some(organization_type) = oauth.organization_type.as_deref() {
        if normalize_plan_type(organization_type.to_string()) != "claude_team" {
            return None;
        }
    }
    let seat_tier = oauth
        .seat_tier
        .clone()
        .map(normalize_plan_type)
        .unwrap_or_default();
    // Only the user-level rate-limit tier can prove a per-seat tier: Team
    // orgs mix Standard and Premium seats, so the org-wide tier says nothing
    // about THIS seat.
    let rate_limit_tier = oauth
        .user_rate_limit_tier
        .clone()
        .map(normalize_plan_type)
        .unwrap_or_default();
    let seat_plan = if seat_tier.contains("premium") || rate_limit_tier.ends_with("max_5x") {
        "team_premium"
    } else if seat_tier.contains("standard") {
        "team_standard"
    } else {
        return None;
    };
    account.plan_type = Some(seat_plan.to_string());
    account.subscription_product = Some(format!("claude_{seat_plan}"));
    Some(seat_plan)
}

/// Refine a generic Claude `max` plan into `max_5x` / `max_20x` when the local
/// Claude Code account metadata carries an explicit rate-limit tier. Mirrors
/// `refine_claude_team_seat_plan`: explicit collector evidence only, never a
/// guess — `claude auth status` reports bare `max` for BOTH Max tiers, so an
/// absent or unrecognized signal leaves the generic plan untouched (the
/// backend prices that as the conservative lower bound). Max is an individual
/// plan, so the organization-level rate-limit tier speaks for the account;
/// the user-level tier is accepted as a same-shaped fallback.
pub(in crate::agent_status) fn refine_claude_max_rate_limit_plan(
    account: &mut AgentAccountStatus,
    oauth: &ClaudeCliOauthAccount,
) -> Option<&'static str> {
    if account.plan_type.as_deref() != Some("max") {
        return None;
    }
    // Identity guard: `~/.claude.json` can lag behind `claude auth status`
    // after an account switch. Refuse to mix metadata across accounts.
    if claude_cli_oauth_identity_mismatch(account, oauth) {
        return None;
    }
    if let Some(organization_type) = oauth.organization_type.as_deref() {
        if normalize_plan_type(organization_type.to_string()) != "claude_max" {
            return None;
        }
    }
    let tier_signal = |value: &Option<String>| -> Option<&'static str> {
        let normalized = value.clone().map(normalize_plan_type)?;
        if normalized.ends_with("max_5x") {
            Some("max_5x")
        } else if normalized.ends_with("max_20x") {
            Some("max_20x")
        } else {
            None
        }
    };
    let refined = tier_signal(&oauth.organization_rate_limit_tier)
        .or_else(|| tier_signal(&oauth.user_rate_limit_tier))?;
    account.plan_type = Some(refined.to_string());
    account.subscription_product = Some(format!("claude_{refined}"));
    Some(refined)
}

/// Resolve Claude once and apply the single shared sanitized exact-slot
/// environment used by the browser sign-in and the background refresher. No
/// provider or token-shaped ambient variables survive `env_clear`.
pub(crate) fn resolved_claude_slot_command(
    slot: &ClaudeConfigDirSlot,
    args: &[&str],
) -> Option<Command> {
    let identity = effective_user_identity()?;
    let program_path = crate::command_env::claude_executable_path(&identity.home_dir)?;
    let mut command = Command::new(program_path);
    command
        .args(args)
        .env_clear()
        .env("HOME", &identity.home_dir)
        .env("USER", identity.account_name);
    for locale_key in ["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = std::env::var_os(locale_key) {
            command.env(locale_key, value);
        }
    }
    if let Some(path_env) = crate::command_env::claude_path_env(&identity.home_dir) {
        command.env("PATH", path_env);
    }
    match slot.config_dir() {
        Some(config_dir) => {
            command.env("CLAUDE_CONFIG_DIR", config_dir);
        }
        None => {
            command.env_remove("CLAUDE_CONFIG_DIR");
        }
    }
    Some(command)
}
