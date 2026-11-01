//! Display-only nicknames, revision ordered and bound to a live device/org.
//! No polling, offline writes, registration or nickname logging.
use ottto_core::{default_support_dir, FileAccountStore, FileDeviceStore, LocalDeviceBinding};
use ottto_protocol::{
    AccountNicknameOutcomeV1 as Outcome, AccountNicknamePairV1 as Pair, AccountNicknameSetResultV1,
    AccountNicknameV1 as Entry, AccountNicknamesV1, LocalAccountState, SecretString,
    SessionLaunchProviderV1 as Provider,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

const CACHE_NAME: &str = "account-nicknames.json";
const MAX_ENTRIES: usize = 2000;
static EPOCH: AtomicU64 = AtomicU64::new(0);
static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Generation {
    binding: String,
    epoch: u64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Cache {
    generation: String,
    entries: Vec<Entry>,
    refreshed: i64,
    capability: bool,
    rejected: bool,
    #[serde(skip)]
    persisted_at: i64,
}

/// Call while the identity lifecycle lock is held. The epoch fences requests
/// already in flight even if a failed mutation restores the same disk binding.
pub(crate) fn invalidate_locked() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    if let Ok(mut cache) = CACHE.lock() {
        *cache = None;
    }
    let _ = fs::remove_file(default_support_dir().join(CACHE_NAME));
}

fn generation_locked() -> Option<Generation> {
    if crate::control::identity_mutation_in_progress() {
        return None;
    }
    let account = FileAccountStore::default().load().ok()?;
    if account.state != LocalAccountState::Connected {
        return None;
    }
    let device = FileDeviceStore::default().load().ok()??;
    let credential = FileDeviceStore::default()
        .load_with_credential_generation()
        .ok()
        .flatten();
    let material = serde_json::to_vec(&(
        &device.device_id,
        &device.machine_id,
        credential.map(|value| value.credential_generation),
        account.user?.id,
        account.organization?.id,
        account.connected_at,
        crate::snapshot_sync::snapshot_api_base_url().ok()?,
    ))
    .ok()?;
    Some(Generation {
        binding: format!("{:x}", Sha256::digest(material)),
        epoch: EPOCH.load(Ordering::Acquire),
    })
}

pub(crate) fn generation() -> Option<Generation> {
    let _lock = crate::control::lock_setup_run_binding();
    generation_locked()
}

pub(crate) fn launch_generation() -> (u64, Option<Generation>) {
    let _lock = crate::control::lock_setup_run_binding();
    (EPOCH.load(Ordering::Acquire), generation_locked())
}

fn generation_for_device_locked(device: &LocalDeviceBinding) -> Option<Generation> {
    if FileDeviceStore::default().load().ok().flatten().as_ref() != Some(device) {
        return None;
    }
    generation_locked()
}

fn generation_for_device_blocking(device: &LocalDeviceBinding) -> Option<Generation> {
    let _lock = crate::control::lock_setup_run_binding();
    generation_for_device_locked(device)
}

pub(crate) fn generation_for_device(device: &LocalDeviceBinding) -> Option<Generation> {
    let _lock = crate::control::try_lock_setup_run_binding()?;
    generation_for_device_locked(device)
}

fn load_cache(generation: &Generation) -> Cache {
    let path = default_support_dir().join(CACHE_NAME);
    let read = || -> Option<Cache> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .ok()?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > 2 * 1024 * 1024
        {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        let mut cache: Cache = serde_json::from_slice(&bytes).ok()?;
        cache.persisted_at = cache.refreshed;
        (cache.generation == generation.binding && cache.entries.len() <= MAX_ENTRIES)
            .then_some(cache)
    };
    if let Some(cache) = read() {
        return cache;
    }
    let _ = fs::remove_file(path);
    Cache {
        generation: generation.binding.clone(),
        ..Default::default()
    }
}

fn persist(cache: &Cache, support: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(support)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    let token = ottto_core::generate_control_token()
        .map_err(|_| std::io::Error::other("cache unavailable"))?;
    let temporary = support.join(format!(".account-nicknames-{token}.tmp"));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let bytes =
            serde_json::to_vec(cache).map_err(|_| std::io::Error::other("cache unavailable"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, support.join(CACHE_NAME))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(crate) fn read() -> AccountNicknamesV1 {
    let _lock = crate::control::lock_setup_run_binding();
    let Some(generation) = generation_locked() else {
        return AccountNicknamesV1 {
            entries: Some(Vec::new()),
            stale: Some(true),
            connected: Some(false),
        };
    };
    let Ok(mut state) = CACHE.lock() else {
        return AccountNicknamesV1::default();
    };
    if state
        .as_ref()
        .map_or(true, |cache| cache.generation != generation.binding)
    {
        *state = Some(load_cache(&generation));
    }
    let cache = state.as_ref().expect("cache initialized");
    AccountNicknamesV1 {
        entries: Some(cache.entries.clone()),
        stale: Some(
            cache.rejected
                || time::OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .saturating_sub(cache.refreshed)
                    > 900,
        ),
        connected: Some(cache.capability && !cache.rejected),
    }
}

/// Called on an ordinary upload response. Absence is deliberately a no-op.
pub(crate) fn apply_upload(generation: Option<&Generation>, entries: Option<&[Entry]>) {
    let (Some(generation), Some(entries)) = (generation, entries) else {
        return;
    };
    let Some(_lock) = crate::control::try_lock_setup_run_binding() else {
        return;
    };
    if generation_locked().as_ref() != Some(generation) {
        return;
    }
    let Ok(mut state) = CACHE.lock() else {
        return;
    };
    if state
        .as_ref()
        .map_or(true, |cache| cache.generation != generation.binding)
    {
        *state = Some(load_cache(generation));
    }
    let cache = state.as_mut().expect("cache initialized");
    let changed = merge(cache, entries);
    let first_capability = !cache.capability;
    cache.capability = true;
    cache.refreshed = time::OffsetDateTime::now_utc().unix_timestamp();
    if (changed || first_capability || cache.refreshed.saturating_sub(cache.persisted_at) >= 900)
        && persist(cache, &default_support_dir()).is_ok()
    {
        cache.persisted_at = cache.refreshed;
    }
}

fn valid_pair(pair: &Pair) -> bool {
    pair.source != Provider::Unknown
        && pair
            .account_identifier_hash
            .as_deref()
            .is_some_and(crate::hex::is_sha256_lower)
        && pair
            .organization_identifier_hash
            .as_deref()
            .is_some_and(|org| org.is_empty() || crate::hex::is_sha256_lower(org))
}

fn merge(cache: &mut Cache, entries: &[Entry]) -> bool {
    let mut changed = false;
    for entry in entries.iter().take(MAX_ENTRIES) {
        let (Some(pair), Some(revision)) = (&entry.pair, entry.revision) else {
            continue;
        };
        if !valid_pair(pair)
            || revision == 0
            || entry
                .nickname
                .as_ref()
                .is_some_and(|text| normalize(Some(text.expose_secret())).is_err())
        {
            continue;
        }
        if let Some(current) = cache
            .entries
            .iter_mut()
            .find(|current| current.pair.as_ref() == Some(pair))
        {
            if revision > current.revision.unwrap_or(0) {
                *current = entry.clone();
                changed = true;
            }
        } else if cache.entries.len() < MAX_ENTRIES {
            cache.entries.push(entry.clone());
            changed = true;
        }
    }
    changed
}

pub(crate) fn normalize(text: Option<&str>) -> Result<Option<String>, ()> {
    use unicode_general_category::{get_general_category, GeneralCategory};
    use unicode_normalization::UnicodeNormalization;
    let Some(text) = text else {
        return Ok(None);
    };
    // Match the write endpoint: reject before trimming; never echo submitted text.
    if text.chars().count() > 256
        || text.chars().any(|ch| {
            // Category data is Unicode 15.0 plus the three additions in 15.1,
            // matching the endpoint's Unicode 15.1 validation baseline.
            // https://www.unicode.org/versions/Unicode15.1.0/
            let category = match ch {
                '\u{2ebf0}'..='\u{2ee5d}' => GeneralCategory::OtherLetter,
                '\u{2ffc}'..='\u{2fff}' | '\u{31ef}' => GeneralCategory::OtherSymbol,
                _ => get_general_category(ch),
            };
            matches!(
                category,
                GeneralCategory::Control
                    | GeneralCategory::Surrogate
                    | GeneralCategory::PrivateUse
                    | GeneralCategory::Unassigned
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            ) || (category == GeneralCategory::Format && ch != '\u{200d}')
        })
    {
        return Err(());
    }
    let text = text.nfc().collect::<String>();
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let chars = text.chars().collect::<Vec<_>>();
    if chars.len() > 40
        || chars.windows(3).any(|part| {
            part[1] == '@'
                && part[0] != '@'
                && part[2] != '@'
                && !part[0].is_whitespace()
                && !part[2].is_whitespace()
        })
    {
        return Err(());
    }
    Ok(Some(text.to_owned()))
}

pub(crate) fn set(
    pair: Pair,
    nickname: Option<SecretString>,
    base_revision: Option<u64>,
) -> AccountNicknameSetResultV1 {
    let finish = |outcome| AccountNicknameSetResultV1 {
        outcome: Some(outcome),
        entry: None,
    };
    let Ok(nickname) = normalize(nickname.as_ref().map(SecretString::expose_secret)) else {
        return finish(Outcome::Invalid);
    };
    if !valid_pair(&pair) {
        return finish(Outcome::Invalid);
    }
    let Some(generation) = generation() else {
        return finish(Outcome::NotConnected);
    };
    let status = read();
    if status.connected != Some(true) {
        let rejected = CACHE
            .lock()
            .ok()
            .and_then(|state| state.as_ref().map(|cache| cache.rejected))
            .unwrap_or(false);
        return finish(if rejected {
            Outcome::NotConnected
        } else {
            Outcome::Unavailable
        });
    }
    let Ok((device, secret)) = crate::snapshot_client::load_snapshot_device_credentials() else {
        return finish(Outcome::NotConnected);
    };
    if generation_for_device_blocking(&device).as_ref() != Some(&generation) {
        return finish(Outcome::NotConnected);
    }
    let Ok(Some(machine_id)) = crate::snapshot_sync::snapshot_machine_id(&device) else {
        return finish(Outcome::NotConnected);
    };
    if !crate::session_launch::nickname_target_is_current(&pair) {
        return finish(Outcome::TargetUnknown);
    }
    let source = match pair.source {
        Provider::ClaudeCode => crate::snapshots::SnapshotSource::ClaudeCode,
        Provider::Codex => crate::snapshots::SnapshotSource::Codex,
        Provider::Unknown => return finish(Outcome::Invalid),
    };
    if !device
        .sources
        .iter()
        .any(|registered| registered == source.api_slug())
    {
        return finish(Outcome::NotConnected);
    }
    let Ok(api_base_url) = crate::snapshot_sync::snapshot_api_base_url() else {
        return finish(Outcome::Unavailable);
    };
    let client = crate::snapshot_client::SnapshotApiClient::new(api_base_url);
    let token = match client.issue_relay_token(&device, &secret, source) {
        Ok(token) => token,
        Err(error) => {
            if error
                .downcast_ref::<crate::snapshot_client::RelayTokenAuthorizationRejected>()
                .is_some()
            {
                reject(&generation);
                return finish(Outcome::NotConnected);
            }
            return finish(Outcome::Unavailable);
        }
    };
    if generation_for_device_blocking(&device).as_ref() != Some(&generation) {
        return finish(Outcome::NotConnected);
    }
    let mut payload = serde_json::json!({ "machine_id":machine_id, "source":pair.source,
        "account_identifier_hash":pair.account_identifier_hash,
        "organization_identifier_hash":pair.organization_identifier_hash,
        "nickname":nickname });
    if let Some(revision) = base_revision {
        payload["base_revision"] = serde_json::json!(revision);
    }
    match client.put_account_nickname(&token, &payload) {
        Ok(Some(entry))
            if entry.pair.as_ref() == Some(&pair)
                && entry.revision.is_some_and(|revision| revision > 0)
                && entry
                    .nickname
                    .as_ref()
                    .map_or(true, |text| normalize(Some(text.expose_secret())).is_ok()) =>
        {
            if self::generation().as_ref() != Some(&generation) {
                return finish(Outcome::NotConnected);
            }
            apply_upload(Some(&generation), Some(std::slice::from_ref(&entry)));
            AccountNicknameSetResultV1 {
                outcome: Some(Outcome::Saved),
                entry: Some(entry),
            }
        }
        Err(401 | 403) => {
            reject(&generation);
            finish(Outcome::NotConnected)
        }
        Err(404) => finish(Outcome::TargetUnknown),
        Err(400 | 422) => finish(Outcome::Invalid),
        _ => finish(Outcome::Unavailable),
    }
}

fn reject(generation: &Generation) {
    let _lock = crate::control::lock_setup_run_binding();
    if generation_locked().as_ref() != Some(generation) {
        return;
    }
    if let Ok(mut state) = CACHE.lock() {
        if let Some(cache) = state.as_mut() {
            cache.rejected = true;
            cache.capability = false;
            // An ordinary restart cannot restore edit authority. If atomic
            // persistence fails, discard the older capability-bearing cache.
            let support = default_support_dir();
            if persist(cache, &support).is_err() {
                let _ = fs::remove_file(support.join(CACHE_NAME));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(revision: u64, nickname: Option<&str>) -> Entry {
        Entry {
            pair: Some(Pair {
                source: Provider::Codex,
                account_identifier_hash: Some("a".repeat(64)),
                organization_identifier_hash: Some(String::new()),
            }),
            revision: Some(revision),
            nickname: nickname.map(SecretString::new),
        }
    }
    #[test]
    fn revisions_and_tombstones_cannot_be_rolled_back() {
        let mut cache = Cache::default();
        merge(&mut cache, &[entry(2, Some("חדש")), entry(1, Some("old"))]);
        assert_eq!(cache.entries[0].revision, Some(2));
        merge(&mut cache, &[entry(3, None), entry(2, Some("old"))]);
        assert!(cache.entries[0].nickname.is_none());
        assert!(!format!("{:?}", entry(4, Some("private text"))).contains("private text"));
    }
    #[test]
    fn nickname_validation_is_unicode_and_private() {
        assert_eq!(
            normalize(Some("  העבודה של רון 🚀  ")).unwrap(),
            Some("העבודה של רון 🚀".into())
        );
        for text in [
            "a@example.invalid",
            "a@b",
            "line\nbreak",
            "\nedge",
            "\u{202e}hidden",
            "\u{2067}hidden",
            "\u{00ad}hidden",
            "\u{200c}hidden",
            "\u{e000}private",
            "\u{0378}unassigned",
            "\u{2028}separator",
        ] {
            assert!(normalize(Some(text)).is_err());
        }
        assert_eq!(normalize(Some("e\u{301}")).unwrap(), Some("é".into()));
        assert_eq!(
            normalize(Some("👩\u{200d}💻")).unwrap(),
            Some("👩\u{200d}💻".into())
        );
        assert_eq!(
            normalize(Some(&"e\u{301}".repeat(40))).unwrap(),
            Some("é".repeat(40))
        );
        assert!(normalize(Some("\u{2ebf0}\u{2ee5d}\u{2ffc}\u{31ef}")).is_ok());
        assert!(normalize(Some("a@@b")).is_ok());
        assert!(normalize(Some(&"a".repeat(41))).is_err());
        assert_eq!(normalize(Some("  ")).unwrap(), None);
    }

    #[test]
    fn missing_organization_is_unknown_not_personal() {
        let mut pair = entry(1, None).pair.unwrap();
        assert!(valid_pair(&pair));
        pair.organization_identifier_hash = None;
        assert!(!valid_pair(&pair));
        assert_eq!(set(pair, None, None).outcome, Some(Outcome::Invalid));
    }

    #[test]
    fn cache_permissions_absent_field_and_late_generation_response() {
        if !crate::test_isolation::run_here() {
            return;
        }
        let scratch = crate::test_scratch::ScratchDir::new("nicknames");
        let root = scratch.as_ref();
        std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", root);
        let account = serde_json::from_value(serde_json::json!({
            "state":"connected", "user":{"id":"user-one","email":"synthetic@example.invalid"},
            "organization":{"id":"org-one","name":"Synthetic"},
            "connected_at":"2026-10-28T00:00:00Z", "last_refreshed_at":null, "message":null
        }))
        .unwrap();
        FileAccountStore::default().save(&account).unwrap();
        FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: "device-one".into(),
                machine_id: Some("machine-one".into()),
                sources: vec!["codex".into()],
            })
            .unwrap();
        let first = generation().unwrap();
        apply_upload(Some(&first), Some(&[entry(2, Some("חדש"))]));
        assert_eq!(
            fs::metadata(root.join(CACHE_NAME)).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(read().entries.unwrap()[0].revision, Some(2));
        apply_upload(Some(&first), None);
        assert_eq!(read().entries.unwrap()[0].revision, Some(2));
        // Reclaim fences even a late response carrying a higher revision for
        // the same pair; the old nickname never crosses the new generation.
        {
            let _lock = crate::control::lock_setup_run_binding();
            invalidate_locked();
        }
        apply_upload(Some(&first), Some(&[entry(99, Some("old generation"))]));
        assert!(read().entries.unwrap().is_empty());
        let next = generation().unwrap();
        apply_upload(Some(&next), Some(&[entry(3, None)]));
        assert!(read().entries.unwrap()[0].nickname.is_none());
        reject(&next);
        assert_eq!(read().connected, Some(false));
        *CACHE.lock().unwrap() = None; // fresh process, same device/org binding
        assert_eq!(read().connected, Some(false));
        apply_upload(Some(&next), Some(&[]));
        assert_eq!(read().connected, Some(false));
        {
            let _lock = crate::control::lock_setup_run_binding();
            invalidate_locked();
        }
        let reclaimed = generation().unwrap();
        apply_upload(Some(&reclaimed), Some(&[]));
        assert_eq!(read().connected, Some(true));
        std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
    }
}

crate::heap_layout_bound::fields!(Generation; binding, epoch);
