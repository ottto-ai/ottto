//! Bounded, local-only folder history. These paths never enter status uploads.
use crate::snapshots::codex_sqlite_read::CodexSqliteRead;
use hmac::{Hmac, Mac};
use ottto_core::{
    generate_control_token, session_launch::launch_user, FileClaudeConfigSlotSettingsStore,
    FileCodexAccountSlotSettingsStore,
};
use ottto_protocol::{
    SessionLaunchFolderKindV1 as Kind, SessionLaunchProviderV1 as Provider,
    SessionLaunchRecencyPrecisionV1 as Precision, SessionLaunchRecentFolderV1 as Item,
    SessionLaunchRecentFoldersV1 as Response,
};
use rusqlite::{Connection, OpenFlags};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type SavedProjection = (
    Instant,
    Option<Provider>,
    Option<String>,
    Option<crate::account_nicknames::Generation>,
    Response,
);

#[derive(Default)]
pub(super) struct Cache {
    saved: Option<SavedProjection>,
    key: Option<String>,
}

impl Cache {
    pub(super) fn resolve(&self, id: &str) -> Option<PathBuf> {
        let (saved, _, _, _, response) = self.saved.as_ref()?;
        if saved.elapsed() >= Duration::from_secs(30) {
            return None;
        }
        response
            .items
            .as_ref()?
            .iter()
            .find(|item| item.id.as_deref() == Some(id))?
            .path
            .as_ref()
            .map(PathBuf::from)
    }

    pub(super) fn get(
        &mut self,
        provider: Option<Provider>,
        slot_id: Option<&str>,
        limit: usize,
        support: &Path,
    ) -> Response {
        if provider == Some(Provider::Unknown) {
            return Response {
                items: Some(Vec::new()),
                partial: Some(false),
                ..Default::default()
            };
        }
        let generation = crate::account_nicknames::generation();
        if let Some((saved, prior_provider, prior_slot, prior_generation, response)) = &self.saved {
            if saved.elapsed() < Duration::from_secs(30)
                && *prior_provider == provider
                && prior_slot.as_deref() == slot_id
                && *prior_generation == generation
            {
                let mut response = response.clone();
                if let Some(items) = &mut response.items {
                    items.truncate(limit.min(100));
                }
                return response;
            }
        }
        let Some(key) = self.key.clone().or_else(|| generate_control_token().ok()) else {
            return Response {
                cli_launchable: cli_launchable(provider),
                ..partial("recent_unavailable")
            };
        };
        self.key = Some(key.clone());
        let support = support.to_owned();
        let selected_slot = slot_id.map(str::to_owned);
        let worker_slot = selected_slot.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let deadline = Instant::now() + Duration::from_secs(1);
        std::thread::spawn(move || {
            let _ = send.send(collect(
                provider,
                worker_slot.as_deref(),
                &support,
                &key,
                deadline - Duration::from_millis(50),
            ));
        });
        let response = Response {
            cli_launchable: cli_launchable(provider),
            ..receive
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| partial("recent_timeout"))
        };
        self.saved = Some((
            Instant::now(),
            provider,
            selected_slot,
            generation,
            response.clone(),
        ));
        let mut response = response;
        if let Some(items) = &mut response.items {
            items.truncate(limit.min(100));
        }
        response
    }
}

fn partial(reason: &str) -> Response {
    Response {
        items: Some(Vec::new()),
        partial: Some(true),
        partial_reason: Some(reason.into()),
        ..Default::default()
    }
}

struct Root {
    path: PathBuf,
    provider: Provider,
    slot: String,
}
struct Candidate {
    path: PathBuf,
    seconds: Option<i64>,
    root: Option<usize>,
    live: bool,
    repository: Option<String>,
}

fn roots() -> Vec<Root> {
    let Some(user) = launch_user() else {
        return Vec::new();
    };
    let mut roots = Vec::new();
    if let Ok(status) = FileClaudeConfigSlotSettingsStore::default().load() {
        for slot in std::iter::once(status.default_slot)
            .chain(status.managed_slots)
            .chain(status.external_slots)
            .take(10)
        {
            roots.push(Root {
                path: slot
                    .config_dir
                    .map(PathBuf::from)
                    .unwrap_or_else(|| user.home.join(".claude")),
                provider: Provider::ClaudeCode,
                slot: slot.slot_id,
            });
        }
    }
    let store = FileCodexAccountSlotSettingsStore::default();
    if let Ok(status) = store.load_for_session_launch() {
        roots.push(Root {
            path: user.home.join(".codex"),
            provider: Provider::Codex,
            slot: status.default_slot.slot_id,
        });
        for slot in status.managed_slots.into_iter().take(9) {
            if let Ok(path) = store.slot_home(&slot.slot_id) {
                roots.push(Root {
                    path,
                    provider: Provider::Codex,
                    slot: slot.slot_id,
                });
            }
        }
    }
    roots
}

fn collect(
    provider: Option<Provider>,
    slot: Option<&str>,
    support: &Path,
    key: &str,
    deadline: Instant,
) -> Response {
    let read_deadline = deadline - Duration::from_millis(100);
    let roots = roots();
    let mut candidates = Vec::new();
    let mut partial_reason = None;
    for (index, root) in roots.iter().enumerate() {
        if Instant::now() >= read_deadline {
            partial_reason = Some("recent_timeout");
            break;
        }
        match root.provider {
            Provider::ClaudeCode => {
                for path in
                    crate::claude_session_registrations::collect_cwds(&root.path.join("sessions"))
                {
                    candidates.push(Candidate {
                        path: path.into(),
                        seconds: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
                        root: Some(index),
                        live: true,
                        repository: None,
                    });
                }
            }
            Provider::Codex => {
                match codex_folders(&root.path.join("state_5.sqlite"), read_deadline) {
                    Ok(rows) => {
                        for (path, seconds) in rows {
                            candidates.push(Candidate {
                                path: path.into(),
                                seconds,
                                root: Some(index),
                                live: false,
                                repository: None,
                            });
                        }
                    }
                    Err(reason) => {
                        partial_reason = Some(reason);
                    }
                }
            }
            Provider::Unknown => {}
        }
    }
    let (scopes, incomplete) = crate::context_composition::recent_scopes(support, read_deadline);
    if incomplete {
        partial_reason = Some("composition_unavailable");
    }
    for scope in scopes {
        let root = scope
            .transcript
            .as_ref()
            .and_then(|path| roots.iter().position(|root| path.starts_with(&root.path)));
        candidates.push(Candidate {
            path: scope.path,
            seconds: scope.seconds,
            root,
            live: false,
            repository: scope.repository_label,
        });
    }
    let mut merged = BTreeMap::<PathBuf, (Item, Option<i64>)>::new();
    for candidate in candidates.into_iter().take(8000) {
        if Instant::now() >= deadline {
            partial_reason = Some("recent_timeout");
            break;
        }
        if !candidate.path.is_absolute()
            || candidate
                .path
                .to_str()
                .map_or(true, |text| text.chars().any(char::is_control))
        {
            continue;
        }
        let canonical = candidate
            .path
            .canonicalize()
            .unwrap_or_else(|_| candidate.path.clone());
        if canonical
            .to_str()
            .map_or(true, |text| text.chars().any(char::is_control))
        {
            continue;
        }
        let exists = Some(canonical.is_dir());
        let label = canonical
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        let owned = candidate.root.and_then(|index| roots.get(index));
        let with_login = owned.is_some_and(|root| {
            provider.is_some_and(|provider| root.provider == provider)
                && slot.is_some_and(|slot| root.slot == slot)
        });
        let pair = merged.entry(canonical.clone()).or_insert_with(|| {
            (
                Item {
                    id: Some(opaque_id(key, &canonical)),
                    path: Some(canonical.to_string_lossy().into_owned()),
                    label,
                    kind: Some(if candidate.repository.is_some() {
                        Kind::Repository
                    } else {
                        Kind::Directory
                    }),
                    repository_label: candidate.repository.clone(),
                    live: Some(false),
                    providers: Some(Vec::new()),
                    slot_ids: Some(Vec::new()),
                    exists,
                    with_this_login: Some(false),
                    ..Default::default()
                },
                None,
            )
        });
        let (item, seconds) = pair;
        item.live = Some(item.live == Some(true) || candidate.live);
        item.with_this_login = Some(item.with_this_login == Some(true) || with_login);
        if let Some(root) = owned {
            let providers = item.providers.get_or_insert_with(Vec::new);
            if !providers.contains(&root.provider) {
                providers.push(root.provider);
            }
            let slots = item.slot_ids.get_or_insert_with(Vec::new);
            if !slots.contains(&root.slot) {
                slots.push(root.slot.clone());
            }
        }
        if candidate.seconds > *seconds {
            *seconds = candidate.seconds;
            item.last_used_at = candidate
                .seconds
                .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
                .and_then(|time| {
                    time.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                });
            item.precision = item.last_used_at.as_ref().map(|_| Precision::Exact);
        }
    }
    let mut items: Vec<_> = merged.into_values().collect();
    items.sort_by(|(a, at), (b, bt)| {
        b.with_this_login
            .cmp(&a.with_this_login)
            .then_with(|| bt.cmp(at))
            .then_with(|| a.path.cmp(&b.path))
    });
    Response {
        items: Some(items.into_iter().take(100).map(|(item, _)| item).collect()),
        partial: Some(partial_reason.is_some()),
        partial_reason: partial_reason.map(str::to_owned),
        ..Default::default()
    }
}

/// Answered apart from the folder scan: a slow or unavailable history read must
/// not hide the terminal actions, which only need the CLI itself.
fn cli_launchable(provider: Option<Provider>) -> Option<bool> {
    let user = launch_user()?;
    provider.map(|provider| {
        crate::command_env::interactive_cli_path(
            if provider == Provider::Codex {
                "codex"
            } else {
                "claude"
            },
            &user.home,
        )
        .is_some()
    })
}

fn opaque_id(key: &str, path: &Path) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key");
    mac.update(path.as_os_str().as_encoded_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn codex_folders(
    path: &Path,
    deadline: Instant,
) -> Result<Vec<(String, Option<i64>)>, &'static str> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let connection = CodexSqliteRead::open(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        Duration::from_millis(100),
    )
    .map_err(|_| "codex_database")?;
    // SQLite must stop CPU-bound scans too, not only lock waits. The callback
    // borrows this stack deadline only until connection/statement destruction.
    unsafe extern "C" fn progress(context: *mut std::ffi::c_void) -> libc::c_int {
        let deadline = unsafe { &*(context.cast::<Instant>()) };
        i32::from(Instant::now() >= *deadline)
    }
    unsafe {
        rusqlite::ffi::sqlite3_progress_handler(
            connection.handle(),
            1000,
            Some(progress),
            (&deadline as *const Instant).cast_mut().cast(),
        );
    }
    // A snapshot the database moved past fails as a database error before
    // any schema error its moved pages may show.
    connection
        .read(|connection| Ok(codex_folder_rows(connection)))
        .map_err(|_| "codex_database")?
}

fn codex_folder_rows(connection: &Connection) -> Result<Vec<(String, Option<i64>)>, &'static str> {
    let mut columns = connection
        .prepare("PRAGMA table_info(threads)")
        .map_err(|_| "codex_schema")?;
    let columns = columns
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| "codex_schema")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "codex_schema")?;
    if !columns.iter().any(|column| column == "cwd") {
        return Err("codex_schema");
    }
    let timestamp = if columns.iter().any(|column| column == "updated_at_ms") {
        "updated_at_ms / 1000"
    } else if columns.iter().any(|column| column == "updated_at") {
        "updated_at"
    } else {
        "NULL"
    };
    if !columns.iter().any(|column| column == "archived") {
        return Err("codex_schema");
    }
    let query = format!("SELECT cwd, {timestamp} AS stamp FROM threads WHERE archived=0 AND cwd IS NOT NULL ORDER BY stamp DESC LIMIT 200");
    let mut statement = connection.prepare(&query).map_err(|_| "codex_schema")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|_| "codex_database")?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| "codex_database")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timed_out_folder_scan_still_answers_cli_launchable() {
        let support = std::env::temp_dir().join(format!(
            "recent-support-{}",
            generate_control_token().unwrap()
        ));
        let mut cache = Cache::default();
        let response = cache.get(Some(Provider::ClaudeCode), None, 10, &support);
        assert_eq!(
            response.cli_launchable,
            cli_launchable(Some(Provider::ClaudeCode))
        );
        // The CLI answer must not depend on a completed scan.
        let timed_out = Response {
            cli_launchable: cli_launchable(Some(Provider::Codex)),
            ..partial("recent_timeout")
        };
        assert_eq!(timed_out.partial_reason.as_deref(), Some("recent_timeout"));
        assert_eq!(timed_out.cli_launchable.is_some(), launch_user().is_some());
        assert_eq!(cli_launchable(None), None);
    }
    #[test]
    fn sqlite_projection_is_bounded_ordered_and_schema_aware() {
        let path = std::env::temp_dir().join(format!(
            "recent-{}.sqlite",
            generate_control_token().unwrap()
        ));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE threads (cwd TEXT, updated_at_ms INTEGER, archived INTEGER);",
            )
            .unwrap();
        for index in 0..205 {
            connection
                .execute(
                    "INSERT INTO threads VALUES (?1, ?2, 0)",
                    rusqlite::params![format!("/folder/{index}"), index * 1000],
                )
                .unwrap();
        }
        let folders = codex_folders(&path, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(folders.len(), 200);
        assert_eq!(folders[0], ("/folder/204".into(), Some(204)));
        connection
            .execute_batch("DROP TABLE threads; CREATE TABLE threads (archived INTEGER);")
            .unwrap();
        assert_eq!(
            codex_folders(&path, Instant::now() + Duration::from_secs(1)).unwrap_err(),
            "codex_schema"
        );
        drop(connection);
        let _ = std::fs::remove_file(path);
    }
}
