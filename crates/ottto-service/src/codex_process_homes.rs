//! Bounded, local-only evidence of each Codex process's transcript home.
//! Open rollout paths prove which home that process used without reading its
//! environment, arguments, credentials, or any transcript content.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CodexProcessHome {
    pub auth_home: PathBuf,
}

pub(crate) fn running_codex_homes() -> Vec<CodexProcessHome> {
    #[cfg(target_os = "macos")]
    {
        let Some(bytes) = crate::external_scheduler_attribution::bounded_command_stdout(
            "/usr/sbin/lsof",
            &["-nP", "-c", "codex", "-Fnpc"],
            2 * 1024 * 1024,
        ) else {
            return Vec::new();
        };
        parse_open_rollouts(&String::from_utf8_lossy(&bytes))
    }
    #[cfg(not(target_os = "macos"))]
    Vec::new()
}

fn parse_open_rollouts(body: &str) -> Vec<CodexProcessHome> {
    let mut processes = BTreeMap::<u32, (String, BTreeSet<PathBuf>)>::new();
    let mut current_pid = None;
    for line in body.lines() {
        if let Some(pid) = line.strip_prefix('p') {
            current_pid = pid.parse::<u32>().ok();
        } else if let Some(command) = line.strip_prefix('c') {
            if let Some(pid) = current_pid {
                processes.entry(pid).or_default().0 = command.to_string();
            }
        } else if let Some(path) = line.strip_prefix('n') {
            if let (Some(pid), Some(home)) = (current_pid, rollout_home(Path::new(path))) {
                processes.entry(pid).or_default().1.insert(home);
            }
        }
    }
    processes
        .into_values()
        .filter(|(command, homes)| command == "codex" && homes.len() == 1)
        .filter_map(|(_, homes)| homes.into_iter().next())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(32)
        .map(|auth_home| CodexProcessHome { auth_home })
        .collect()
}

fn rollout_home(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute()
        || path.extension().and_then(|part| part.to_str()) != Some("jsonl")
        || !path
            .file_name()
            .and_then(|part| part.to_str())
            .is_some_and(|name| name.starts_with("rollout-"))
    {
        return None;
    }
    path.ancestors()
        .skip(1)
        .find(|ancestor| {
            matches!(
                ancestor.file_name().and_then(|part| part.to_str()),
                Some("sessions" | "archived_sessions")
            )
        })
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rollouts_bind_only_one_exact_home_per_codex_process() {
        let body = concat!(
            "p123\nccodex\n",
            "n/synthetic/account-a/sessions/2026/rollout-a.jsonl\n",
            "n/synthetic/account-a/auth.json\n",
            "p124\nccodex\n",
            "n/synthetic/account-b/archived_sessions/rollout-b.jsonl\n",
            "p125\nccodex-code-mode-host\n",
            "n/synthetic/ignored/sessions/rollout-c.jsonl\n",
            "p126\nccodex\n",
            "n/synthetic/one/sessions/rollout-d.jsonl\n",
            "n/synthetic/two/sessions/rollout-e.jsonl\n",
            "p127\nccodex\n",
            "n/synthetic/ignored/auth.json\n",
        );
        assert_eq!(
            parse_open_rollouts(body),
            vec![
                CodexProcessHome {
                    auth_home: PathBuf::from("/synthetic/account-a"),
                },
                CodexProcessHome {
                    auth_home: PathBuf::from("/synthetic/account-b"),
                },
            ]
        );
    }
}
