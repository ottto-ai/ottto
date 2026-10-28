//! Hash-only lifetime history. PR1 records evidence; it never labels usage.
use ottto_core::{billing_identity_hash, write_owner_only_file_atomic};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
const BYTES: usize = 4 * 1024 * 1024;
const FOLDERS: usize = 128;
const SESSIONS: usize = 16384;
const GAPS: usize = 64;
type Pair = (String, String);
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    version: u8,
    uncertain: bool,
    enabled: i64,
    boundary: i64,
    folders: BTreeMap<String, Folder>,
    sessions: BTreeMap<String, Session>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Folder {
    first_observed: i64,
    #[serde(deserialize_with = "required")]
    pair: Option<Pair>,
    ineligible: bool,
    #[serde(deserialize_with = "required")]
    object: Option<String>,
    gaps: Vec<(i64, i64)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    first_seen: i64,
    #[serde(deserialize_with = "required")]
    folder: Option<String>,
    #[serde(deserialize_with = "required")]
    attributed: Option<Pair>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    folders: Vec<String>,
    #[serde(deserialize_with = "required")]
    rollback_pin: Option<String>,
}
fn required<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
fn durable(path: &Path, bytes: &[u8]) -> bool {
    write_owner_only_file_atomic(path, bytes)
        .and_then(|()| std::fs::File::open(path.parent().unwrap())?.sync_all())
        .is_ok()
}
#[derive(Clone, Copy)]
pub(crate) enum Gap {
    DaemonDown,
    WatcherError,
}
#[derive(Default, Serialize)]
pub(crate) struct Counts {
    folders_tracked: usize,
    folders_ineligible: usize,
    health_gaps: BTreeMap<&'static str, u64>,
}
struct Owner {
    history: History,
    path: PathBuf,
    files: Vec<(PathBuf, PathBuf)>,
    gaps: [u64; 2],
}
static OWNER: Mutex<Option<Owner>> = Mutex::new(None);
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn hash(kind: &str, value: &str) -> String {
    billing_identity_hash("ottto-sole-login-v1", kind, value).unwrap_or_default()
}
fn folder_key(folder: &Path) -> String {
    hash("folder", &folder.to_string_lossy())
}
fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_pair(pair: &Pair) -> bool {
    is_hash(&pair.0) && is_hash(&pair.1)
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.len() > BYTES as u64
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(BYTES as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= BYTES)
        .then(|| serde_json::from_slice(&bytes).ok())
        .flatten()
}
fn pair(value: &serde_json::Value) -> Option<Pair> {
    let oauth = value.get("oauthAccount")?;
    let field = |name, role| {
        let value = oauth.get(name)?.as_str()?;
        uuid::Uuid::parse_str(value).ok()?;
        billing_identity_hash("anthropic", role, value)
    };
    Some((
        field("accountUuid", "account")?,
        field("organizationUuid", "organization")?,
    ))
}
fn object(folder: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(folder).ok()?;
    (meta.is_dir() && std::fs::canonicalize(folder).ok()?.as_path() == folder)
        .then(|| hash("object", &format!("{}:{}", meta.dev(), meta.ino())))
}
impl History {
    fn unknown(at: i64) -> Self {
        Self {
            version: 1,
            enabled: at,
            boundary: at,
            ..Self::default()
        }
    }
    fn valid(&self, at: i64) -> bool {
        let time = |t| self.enabled <= t && t <= self.boundary;
        self.version == 1
            && self.enabled > 0
            && self.enabled <= self.boundary
            && self.boundary <= at
            && self.folders.len() <= FOLDERS
            && self.sessions.len() <= SESSIONS
            && self.folders.iter().all(|(key, f)| {
                is_hash(key)
                    && time(f.first_observed)
                    && f.pair.as_ref().map_or(true, valid_pair)
                    && f.object.as_deref().map_or(true, is_hash)
                    && f.gaps.len() <= GAPS
                    && f.gaps.iter().all(|(a, b)| time(*a) && time(*b) && a <= b)
                    && f.gaps.windows(2).all(|g| g[0].1 < g[1].0)
            })
            && self.sessions.iter().all(|(key, s)| {
                is_hash(key)
                    && time(s.first_seen)
                    && s.folder.as_deref().map_or(true, is_hash)
                    && s.attributed.as_ref().map_or(true, valid_pair)
            })
    }
    fn gap(&mut self, at: i64) {
        let from = self.boundary.min(at).max(self.enabled);
        for f in self.folders.values_mut() {
            f.gap(from, at.max(self.boundary));
        }
        self.boundary = at.max(self.boundary);
    }
    fn observe(&mut self, key: String, object: Option<String>, pair: Option<Pair>, at: i64) {
        if !self.folders.contains_key(&key) && self.folders.len() == FOLDERS {
            return;
        }
        let aliases: Vec<_> = self
            .folders
            .iter()
            .filter(|(k, f)| **k != key && object.is_some() && f.object == object)
            .map(|(k, _)| k.clone())
            .collect();
        for alias in &aliases {
            self.folders.get_mut(alias).unwrap().ineligible = true;
        }
        let f = self.folders.entry(key).or_insert(Folder {
            first_observed: at,
            pair: None,
            ineligible: false,
            object: object.clone(),
            gaps: Vec::new(),
        });
        f.ineligible |= f
            .object
            .as_ref()
            .zip(object.as_ref())
            .is_some_and(|(old, new)| old != new)
            || !aliases.is_empty();
        if object.is_none() {
            f.gap(
                self.boundary.min(at).max(self.enabled),
                at.max(self.boundary),
            );
        }
        if f.object.is_none() {
            f.object = object;
        }
        match (&f.pair, pair) {
            (Some(old), Some(new)) if *old != new => f.ineligible = true,
            (None, Some(new)) => {
                f.first_observed = at;
                f.pair = Some(new);
            }
            (_, None) => f.gap(
                self.boundary.min(at).max(self.enabled),
                at.max(self.boundary),
            ),
            _ => {}
        }
        self.boundary = self.boundary.max(at);
    }
}
impl Folder {
    fn gap(&mut self, from: i64, to: i64) {
        self.gaps.push((from, to));
        self.gaps.sort_unstable();
        let mut merged: Vec<(i64, i64)> = Vec::new();
        for (a, b) in self.gaps.drain(..) {
            if let Some(last) = merged.last_mut().filter(|last| last.1 >= a) {
                last.1 = last.1.max(b);
            } else {
                merged.push((a, b));
            }
        }
        if merged.len() > GAPS {
            let end = merged.remove(1).1;
            merged[0].1 = end;
        }
        self.gaps = merged;
    }
}
impl Owner {
    fn intent(&self, folder: Option<&Path>, pin: Option<&str>) -> bool {
        let mut folders: Vec<_> = self.history.folders.keys().cloned().collect();
        for folder in self
            .files
            .iter()
            .map(|(folder, _)| folder.as_path())
            .chain(folder)
        {
            let key = folder_key(folder);
            if !folders.contains(&key) {
                folders.push(key);
            }
        }
        serde_json::to_vec(&Intent {
            folders,
            rollback_pin: pin.map(str::to_owned),
        })
        .is_ok_and(|bytes| durable(&self.path.with_extension("intent"), &bytes))
    }
    fn save(&mut self) -> bool {
        let saved = serde_json::to_vec(&self.history)
            .ok()
            .filter(|bytes| bytes.len() <= BYTES)
            .is_some_and(|bytes| durable(&self.path, &bytes));
        if saved {
            // The commit is durable before cleanup. A surviving marker only refuses more.
            let _ = std::fs::remove_file(self.path.with_extension("intent"))
                .and_then(|()| std::fs::File::open(self.path.parent().unwrap())?.sync_all());
        }
        saved
    }
    fn recover(path: PathBuf, at: i64) -> Self {
        let mut history = read::<History>(&path)
            .filter(|h| h.valid(at))
            .unwrap_or_else(|| History::unknown(at));
        let marker = path.with_extension("intent");
        if std::fs::symlink_metadata(&marker).is_ok() {
            match read::<Intent>(&marker).filter(|i| {
                i.folders.len() <= FOLDERS + 1
                    && i.folders.iter().all(|key| is_hash(key))
                    && i.rollback_pin.as_deref().map_or(true, is_hash)
            }) {
                Some(intent) => {
                    for key in intent.folders {
                        if history.folders.len() == FOLDERS && !history.folders.contains_key(&key) {
                            history.uncertain = true;
                            continue;
                        }
                        history
                            .folders
                            .entry(key)
                            .or_insert(Folder {
                                first_observed: at,
                                pair: None,
                                ineligible: true,
                                object: None,
                                gaps: Vec::new(),
                            })
                            .ineligible = true;
                    }
                    if let Some(pin) = intent
                        .rollback_pin
                        .and_then(|key| history.sessions.get_mut(&key))
                    {
                        pin.attributed = None;
                    }
                }
                None => {
                    history.uncertain = true;
                    for folder in history.folders.values_mut() {
                        folder.ineligible = true;
                    }
                }
            }
        }
        Self {
            history,
            path,
            files: Vec::new(),
            gaps: [0; 2],
        }
    }
    fn gap(&mut self, reason: Gap) {
        self.gaps[reason as usize] += 1;
        self.history.gap(now());
    }
    fn observe(&mut self, folder: &Path, value: Option<&serde_json::Value>) {
        self.history.observe(
            folder_key(folder),
            object(folder),
            value.and_then(pair),
            now(),
        );
    }
    // PR2 calls this only after identity installation succeeds; PR1 has no caller.
    #[allow(dead_code)]
    fn pin(&mut self, session: &str, pair: Pair) -> bool {
        let Some(record) = self.history.sessions.get_mut(session) else {
            return false;
        };
        if record.attributed.is_some() {
            return record.attributed.as_ref() == Some(&pair);
        }
        if !valid_pair(&pair) || !self.intent(None, Some(session)) {
            return false;
        }
        self.history.sessions.get_mut(session).unwrap().attributed = Some(pair);
        if self.save() {
            return true;
        }
        self.history.sessions.get_mut(session).unwrap().attributed = None;
        false
    }
}
/// Invoked immediately after the daemon publishes its held state-directory lock.
pub(crate) fn start(support: &Path) {
    if crate::locked_state_dir::held_for(support).is_none() {
        return;
    }
    let Ok(mut guard) = OWNER.lock() else {
        return;
    };
    if guard.is_some() {
        return;
    }
    let at = now();
    let path = support.join("identity/claude-login-history-v1.json");
    let mut owner = Owner::recover(path, at);
    if owner.intent(None, None) {
        owner.gap(Gap::DaemonDown);
        owner.save();
    }
    *guard = Some(owner);
}
fn identity_files(roots: Vec<PathBuf>) -> Vec<(PathBuf, PathBuf)> {
    let home = crate::agent_status::home_dir();
    roots
        .into_iter()
        .filter_map(|root| {
            let folder = root.parent()?.to_path_buf();
            let file = if folder == home.join(".claude") {
                home.join(".claude.json")
            } else {
                folder.join(".claude.json")
            };
            Some((folder, file))
        })
        .collect()
}
fn update(files: Option<Vec<(PathBuf, PathBuf)>>, change: impl FnOnce(&mut Owner)) {
    if let Ok(mut guard) = OWNER.lock() {
        if let Some(owner) = guard.as_mut() {
            if let Some(files) = files {
                owner.files = files;
            }
            if owner.intent(None, None) {
                // Watcher qualification is deferred. Every unobserved interval is a gap.
                owner.gap(Gap::WatcherError);
                change(owner);
                owner.save();
            }
        }
    }
}
pub(crate) fn cadence() {
    let home = crate::agent_status::home_dir();
    let roots =
        crate::snapshot_roots::scan_roots(crate::snapshots::SnapshotSource::ClaudeCode, &home, &[]);
    let files = roots.ok().map(identity_files);
    update(files, |owner| {
        for (folder, file) in owner.files.clone() {
            owner.observe(&folder, read::<serde_json::Value>(&file).as_ref());
        }
    });
}
pub(crate) fn account_read(
    path: &Path,
    read: impl FnOnce() -> Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    let mut guard = OWNER.lock().ok()?;
    let Some(owner) = guard.as_mut() else {
        return read();
    };
    let parent = path.parent()?;
    let folder = if path == crate::agent_status::home_dir().join(".claude.json") {
        parent.join(".claude")
    } else {
        parent.to_path_buf()
    };
    if !owner.intent(Some(&folder), None) {
        return None;
    }
    owner.gap(Gap::WatcherError);
    let value = read();
    owner.observe(&folder, value.as_ref());
    owner.save();
    value
}
pub(crate) fn seen(session: &str, path: &Path) {
    update(None, |owner| {
        let key = hash("session", session);
        let folder = path
            .ancestors()
            .skip(1)
            .find(|p| p.file_name().is_some_and(|name| name == "projects"))
            .and_then(Path::parent)
            .map(folder_key);
        if owner.history.sessions.contains_key(&key) || owner.history.sessions.len() < SESSIONS {
            let at = now();
            let s = owner.history.sessions.entry(key).or_insert(Session {
                first_seen: at,
                folder: folder.clone(),
                attributed: None,
            });
            if s.folder != folder {
                s.folder = None;
            }
            owner.history.boundary = owner.history.boundary.max(at);
        }
    });
}
pub(crate) fn counts() -> Option<Counts> {
    let mut guard = OWNER.lock().ok()?;
    let owner = guard.as_mut()?;
    let folders = &owner.history.folders;
    Some(Counts {
        folders_tracked: folders.len(),
        folders_ineligible: folders.values().filter(|f| f.ineligible).count(),
        health_gaps: ["daemon_down", "watcher_error"]
            .into_iter()
            .zip(std::mem::take(&mut owner.gaps))
            .filter(|(_, n)| *n > 0)
            .collect(),
    })
}
#[cfg(test)]
#[path = "claude_sole_login_tests.rs"]
mod tests;
