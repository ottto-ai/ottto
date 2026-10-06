//! Bounded Claude process registrations, projected into local display metadata.
//! No transcript, credentials, peer transport, launcher or accounting acquisition.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

const MAX_ENTRIES: usize = 256;
const MAX_FILES: usize = 16;
const MAX_FILE_BYTES: u64 = 8 * 1024;
#[cfg(any(target_os = "macos", test))]
const MAX_PROCESS_BYTES: usize = 4096;

pub(crate) type Registrations = BTreeMap<String, Registration>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Registration {
    pub name: Option<String>,
    pub name_source: Option<String>,
    pub entrypoint: Option<String>,
}

/// Provenance lives in the existing local cache, never on the upload wire.
/// The cache's reconciliation time is the observation time, not a process end.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RegistrationEvidence {
    pub name_source: Option<String>,
    pub entrypoint: Option<String>,
    pub process_witness: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    pid: u32,
    session_id: String,
    proc_start: String,
    pid_domain: Option<String>,
    kind: Option<String>,
    name: Option<String>,
    name_source: Option<String>,
    entrypoint: Option<String>,
}

#[cfg(not(test))]
pub(crate) fn collect(root: &Path) -> Registrations {
    collect_with_processes(root, process_starts)
}

fn collect_with_processes(
    root: &Path,
    processes: impl FnOnce(&[u32]) -> BTreeMap<u32, String>,
) -> Registrations {
    let records = read_records(root);
    if records.is_empty() {
        return Registrations::new();
    }
    let pids = records.iter().map(|r| r.pid).collect::<Vec<_>>();
    let starts = processes(&pids);
    let mut selected = BTreeMap::<String, Option<Registration>>::new();
    for record in records {
        if starts.get(&record.pid).map(String::as_str) != Some(record.proc_start.trim()) {
            continue;
        }
        let projection = Registration {
            name: record
                .name
                .and_then(crate::snapshots::claude_registration_display_title),
            name_source: record.name_source.filter(|source| {
                matches!(
                    source.as_str(),
                    "user" | "derived" | "auto" | "peer" | "hook" | "collision"
                )
            }),
            entrypoint: record
                .entrypoint
                .filter(|value| matches!(value.as_str(), "claude-desktop" | "cli" | "sdk-cli")),
        };
        selected
            .entry(record.session_id)
            .and_modify(|current| {
                if current.as_ref() != Some(&projection) {
                    *current = None;
                }
            })
            .or_insert(Some(projection));
    }
    selected
        .into_iter()
        .filter_map(|(id, value)| value.map(|value| (id, value)))
        .collect()
}

fn read_records(root: &Path) -> Vec<Record> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // Reject a redirected sessions directory and redirected .claude parent.
        if root.parent().is_some_and(|parent| {
            fs::symlink_metadata(parent).map_or(true, |m| !m.is_dir() || m.file_type().is_symlink())
        }) {
            return Vec::new();
        }
        let Ok(directory) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(root)
        else {
            return Vec::new();
        };
        let Ok(identity) = directory.metadata() else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(root) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for (position, entry) in entries.enumerate() {
            // An incomplete census cannot rule out a conflicting registration.
            if position >= MAX_ENTRIES {
                return Vec::new();
            }
            let Ok(entry) = entry else { return Vec::new() };
            let name = entry.file_name();
            let Some(text) = name.to_str() else { continue };
            let Some(pid) = text
                .strip_suffix(".json")
                .and_then(|stem| stem.parse::<u32>().ok())
            else {
                continue;
            };
            if pid > 1 {
                names.push((name, pid));
            }
        }
        if names.len() > MAX_FILES {
            return Vec::new();
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        let mut records = Vec::new();
        for (name, pid) in names {
            let Ok(name) = std::ffi::CString::new(name.as_encoded_bytes()) else {
                continue;
            };
            // Open relative to the pinned directory: replacement races cannot
            // redirect acquisition to a different directory or symlink target.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                continue;
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
                continue;
            }
            let mut body = Vec::new();
            if file
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut body)
                .is_err()
                || body.len() as u64 > MAX_FILE_BYTES
            {
                continue;
            }
            let Ok(record) = serde_json::from_slice::<Record>(&body) else {
                continue;
            };
            if record.pid != pid
                || record.session_id.is_empty()
                || record.session_id.len() > 128
                || !record
                    .session_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || record.proc_start.is_empty()
                || record.proc_start.len() > 64
                || record
                    .pid_domain
                    .as_deref()
                    .is_some_and(|domain| domain != "darwin")
                || record
                    .kind
                    .as_deref()
                    .is_some_and(|kind| kind != "interactive")
            {
                continue;
            }
            records.push(record);
        }
        // Loss/replacement after enumeration is unknown, never fresh evidence.
        if fs::symlink_metadata(root).map_or(true, |m| {
            m.dev() != identity.dev() || m.ino() != identity.ino()
        }) {
            return Vec::new();
        }
        records
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Vec::new()
    }
}

#[cfg(any(not(test), target_os = "macos"))]
fn process_starts(pids: &[u32]) -> BTreeMap<u32, String> {
    #[cfg(target_os = "macos")]
    {
        let selected = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let Some(bytes) = crate::external_scheduler_attribution::bounded_command_stdout_with_env(
            "/bin/ps",
            &["-o", "pid=,lstart=", "-p", &selected],
            MAX_PROCESS_BYTES,
            &[("LC_ALL", "C"), ("TZ", "UTC")],
        ) else {
            return BTreeMap::new();
        };
        parse_process_starts(&bytes)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pids;
        BTreeMap::new()
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_process_starts(bytes: &[u8]) -> BTreeMap<u32, String> {
    if bytes.len() > MAX_PROCESS_BYTES {
        return BTreeMap::new();
    }
    let Ok(body) = std::str::from_utf8(bytes) else {
        return BTreeMap::new();
    };
    let mut starts = BTreeMap::new();
    for line in body.lines() {
        let line = line.trim();
        let Some((pid, start)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let start = start.trim();
        if start.len() <= 64 && start.split_whitespace().count() == 5 {
            starts.insert(pid, start.to_string());
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::*;
    const START: &str = "Tue Oct  6 01:00:00 2026";
    fn record(pid: u32, id: &str, name: &str) -> String {
        serde_json::json!({"pid":pid,"sessionId":id,"procStart":START,"name":name,
            "nameSource":"user","kind":"interactive","pidDomain":"darwin","entrypoint":"claude-desktop",
            "startedAt":1,"updatedAt":9999999999999_i64,"status":"busy","messagingSocketPath":"private-ignore"}).to_string()
    }
    fn fixture_root() -> std::path::PathBuf {
        let root = crate::test_scratch::private_dir("ottto-claude-registration").join("sessions");
        fs::create_dir_all(&root).unwrap();
        root
    }
    fn collect(root: &Path) -> Registrations {
        collect_with_processes(root, |pids| {
            pids.iter().map(|pid| (*pid, START.to_string())).collect()
        })
    }
    #[test]
    fn bounded_allowlist_adoption_resume_and_process_reuse() {
        let root = fixture_root();
        fs::write(
            root.join("42.json"),
            record(42, "old-session", "Repair startup"),
        )
        .unwrap();
        assert!(collect(&root).contains_key("old-session"));
        fs::write(
            root.join("42.json"),
            record(42, "adopted-session", "Review metadata"),
        )
        .unwrap();
        let current = collect(&root);
        assert!(!current.contains_key("old-session"));
        assert_eq!(
            current["adopted-session"].name_source.as_deref(),
            Some("user")
        );
        assert!(collect_with_processes(&root, |_| BTreeMap::from([(
            42,
            "Wed Oct  7 01:00:00 2026".into()
        )]))
        .is_empty());
        assert!(collect_with_processes(&root, |_| BTreeMap::new()).is_empty());
        fs::remove_file(root.join("42.json")).unwrap();
        assert!(collect(&root).is_empty());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }
    #[test]
    fn malformed_oversize_symlink_and_conflict_isolate_healthy_siblings() {
        let root = fixture_root();
        fs::write(
            root.join("42.json"),
            record(42, "healthy", "Repair startup"),
        )
        .unwrap();
        fs::write(root.join("43.json"), "{broken").unwrap();
        fs::write(
            root.join("44.json"),
            vec![b'x'; MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("42.json"), root.join("45.json")).unwrap();
        fs::write(root.join("46.json"), record(46, "conflict", "First name")).unwrap();
        fs::write(root.join("47.json"), record(47, "conflict", "Second name")).unwrap();
        let values = collect(&root);
        assert_eq!(values.len(), 1);
        assert!(values.contains_key("healthy"));
        // A crashed conflicting holder is not a current competing name.
        let values = collect_with_processes(&root, |_| {
            BTreeMap::from([(42, START.into()), (46, START.into())])
        });
        assert!(values.contains_key("conflict"));
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }
    #[test]
    fn limits_and_unsupported_domains_fail_closed() {
        let root = fixture_root();
        for pid in 2..=MAX_FILES as u32 + 2 {
            fs::write(
                root.join(format!("{pid}.json")),
                record(pid, "one", "Repair startup"),
            )
            .unwrap();
        }
        assert!(collect(&root).is_empty());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
        let root = fixture_root();
        let mut value: serde_json::Value =
            serde_json::from_str(&record(42, "one", "Repair startup")).unwrap();
        for (key, bad) in [("pidDomain", "remote"), ("kind", "bg")] {
            value[key] = bad.into();
            fs::write(root.join("42.json"), value.to_string()).unwrap();
            assert!(collect(&root).is_empty());
            value = serde_json::from_str(&record(42, "one", "Repair startup")).unwrap();
        }
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn native_process_witness_matches_only_exact_start() {
        let pid = std::process::id();
        let starts = process_starts(&[pid]);
        let start = starts.get(&pid).expect("native test process start witness");
        let root = fixture_root();
        let mut value: serde_json::Value =
            serde_json::from_str(&record(pid, "native-fixture", "Repair startup")).unwrap();
        value["procStart"] = start.clone().into();
        fs::write(root.join(format!("{pid}.json")), value.to_string()).unwrap();
        assert!(collect_with_processes(&root, process_starts).contains_key("native-fixture"));
        value["procStart"] = "Tue Oct  6 00:00:00 1970".into();
        fs::write(root.join(format!("{pid}.json")), value.to_string()).unwrap();
        assert!(collect_with_processes(&root, process_starts).is_empty());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[test]
    fn process_projection_is_locale_stable_and_bounded() {
        assert_eq!(
            parse_process_starts(format!(" 42 {START}\n").as_bytes())[&42],
            START
        );
        assert!(parse_process_starts(&vec![b'x'; MAX_PROCESS_BYTES + 1]).is_empty());
    }
}
