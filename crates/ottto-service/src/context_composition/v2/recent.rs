//! Read-only folder projection. No transcript reads or composition mutations.
use super::checkpoint::Index;
use std::collections::BTreeMap;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime};

#[derive(Clone)]
pub(crate) struct RecentScope {
    pub(crate) path: PathBuf,
    pub(crate) transcript: Option<PathBuf>,
    pub(crate) seconds: Option<i64>,
    pub(crate) repository_label: Option<String>,
}

type CachedIndex = (SystemTime, u64, Vec<RecentScope>);
static CACHE: OnceLock<Mutex<BTreeMap<PathBuf, CachedIndex>>> = OnceLock::new();

pub(crate) fn recent_scopes(support: &Path, deadline: Instant) -> (Vec<RecentScope>, bool) {
    let mut output = Vec::new();
    let mut partial = false;
    let Ok(mut cache) = CACHE.get_or_init(Mutex::default).lock() else {
        return (output, true);
    };
    for source in ["claude-code", "codex"] {
        if Instant::now() >= deadline {
            return (output, true);
        }
        let path = super::harvest::state_dir(support).join(format!("index-{source}.json"));
        let metadata = match std::fs::metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                partial = true;
                continue;
            }
        };
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if let Some((stamp, size, entries)) = cache.get(&path) {
            if *stamp == modified && *size == metadata.len() {
                output.extend(entries.clone());
                continue;
            }
        }
        match read_index(&path).map(project) {
            Ok(entries) => {
                if cache.len() >= 4 {
                    cache.clear();
                }
                cache.insert(path, (modified, metadata.len(), entries.clone()));
                output.extend(entries);
            }
            Err(_) => {
                partial = true;
            }
        }
    }
    (output, partial)
}

fn read_index(path: &Path) -> Result<Index, ()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err(());
    }
    let mut magic = [0; 4];
    let size = file.read(&mut magic).map_err(|_| ())?;
    file.rewind().map_err(|_| ())?;
    let reader: Box<dyn Read> = if size == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(zstd::stream::read::Decoder::new(file).map_err(|_| ())?)
    } else {
        Box::new(file)
    };
    let mut bytes = Vec::new();
    reader
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn project(index: Index) -> Vec<RecentScope> {
    if index.schema != super::STATE_SCHEMA {
        return Vec::new();
    }
    let mut entries = Vec::new();
    for pin in index.files.values().take(2000) {
        if let Some(scope) = pin
            .scope
            .as_ref()
            .and_then(|scope| index.scope_info.get(scope))
        {
            entries.push(RecentScope {
                path: scope.workspace_path.clone().into(),
                transcript: Some(pin.path.clone().into()),
                seconds: Some(pin.mtime.0),
                repository_label: scope.identity.repository_label.clone(),
            });
        }
    }
    for (cwd, scope_id) in index.cwd_scopes.iter().take(2000) {
        entries.push(RecentScope {
            path: cwd.into(),
            transcript: None,
            seconds: None,
            repository_label: index
                .scope_info
                .get(scope_id)
                .and_then(|scope| scope.identity.repository_label.clone()),
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_preserves_login_transcript_and_main_checkout() {
        let index: Index = serde_json::from_value(serde_json::json!({
            "schema":1, "files":{"one":{"path":"/slot/projects/a/session.jsonl","dev":1,"ino":2,"scope":"repo","start":0,"size":10,"mtime":[10,0],"last_seen":20261028}},
            "scope_info":{"repo":{"workspace_hash":"h","workspace_path":"/project/main","identity":{}}},
            "cwd_scopes":{"/project/worktree":"repo"}
        })).unwrap();
        let entries = project(index);
        assert_eq!(entries[0].path, Path::new("/project/main"));
        assert_eq!(
            entries[0].transcript.as_deref(),
            Some(Path::new("/slot/projects/a/session.jsonl"))
        );
        assert!(entries[1].transcript.is_none());
    }
}
