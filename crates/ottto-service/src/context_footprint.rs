//! Context footprint uploads: the shared wire model, repository identity,
//! and the low-cadence thread that runs the Codex session-start harvest
//! (`codex_prelude_footprint`). The Claude Code `/context` harvest is retired:
//! it ran a background Claude on the default home, which Ottto never starts.
//! This is separate from `AgentContextStatus`/`context_live`, which reflects
//! active session load from statusLine `context_window`.

use crate::context_file_counts::FileCounts;
use anyhow::{anyhow, Result};
use ottto_core::default_support_dir;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONTEXT_FOOTPRINT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const GIT_STDOUT_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ContextFootprintCategoryInput {
    pub(crate) name: String,
    pub(crate) tokens: u64,
    pub(crate) pct: f64,
    pub(crate) loading_mode: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ContextFootprintItemInput {
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) relative_path: Option<String>,
    pub(crate) loading_mode: String,
    #[serde(flatten)]
    pub(crate) file_counts: FileCounts,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ContextFootprintIngestRequest {
    pub(crate) agent_source: String,
    pub(crate) machine_id: String,
    pub(crate) workspace_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) repository_identity_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_kind: Option<String>,
    pub(crate) config_hash: String,
    pub(crate) captured_at: String,
    pub(crate) collector_version: String,
    pub(crate) counter_source: String,
    pub(crate) model: String,
    pub(crate) used_tokens: u64,
    pub(crate) context_window_tokens: u64,
    pub(crate) pct_context: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) free_space_tokens: Option<u64>,
    pub(crate) categories: Vec<ContextFootprintCategoryInput>,
    pub(crate) memory_files: Vec<ContextFootprintItemInput>,
    pub(crate) skills: Vec<ContextFootprintItemInput>,
    pub(crate) custom_agents: Vec<ContextFootprintItemInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositoryIdentity {
    pub(crate) repository_hash: Option<String>,
    pub(crate) repository_label: Option<String>,
    pub(crate) repository_label_source: Option<String>,
    pub(crate) repository_identity_source: Option<String>,
    pub(crate) workspace_kind: Option<String>,
}

/// Codex session starts share this thread: no extra background job.
pub fn spawn_context_footprint_sync(daemon: &crate::LocalDaemon) -> Result<()> {
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = default_support_dir();
    let codex_preludes = Arc::clone(&daemon.codex_preludes);
    std::thread::Builder::new()
        .name("ottto-context-footprint-sync".to_string())
        .spawn(move || loop {
            if let Err(error) =
                crate::codex_prelude_footprint::harvest_once(&home, &support_dir, &codex_preludes)
            {
                eprintln!(
                    "codex session start harvest skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            std::thread::sleep(CONTEXT_FOOTPRINT_INTERVAL);
        })
        .map_err(|error| anyhow!("spawn context footprint sync: {error}"))?;
    Ok(())
}

pub(crate) fn resolve_repository_identity(
    workspace: &Path,
    labels_enabled: bool,
) -> RepositoryIdentity {
    let Some(toplevel) = git_toplevel(workspace) else {
        return RepositoryIdentity {
            repository_hash: None,
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: None,
            workspace_kind: Some("non_git".to_string()),
        };
    };
    let Some(common_dir_raw) = git_stdout(workspace, &["rev-parse", "--git-common-dir"]) else {
        return RepositoryIdentity {
            repository_hash: None,
            repository_label: labels_enabled
                .then(|| toplevel.file_name()?.to_str())
                .flatten()
                .and_then(|name| safe_text(name, 255)),
            repository_label_source: labels_enabled.then(|| "git_root".to_string()),
            repository_identity_source: None,
            workspace_kind: Some("unknown".to_string()),
        };
    };
    let common_dir = absolutize_git_path(workspace, &common_dir_raw);
    let git_dir = git_stdout(workspace, &["rev-parse", "--git-dir"])
        .map(|raw| absolutize_git_path(workspace, &raw));
    let common_text = common_dir.to_string_lossy();
    let linked_worktree = git_dir
        .as_ref()
        .map(|git_dir| canonical_or_self(git_dir) != canonical_or_self(&common_dir))
        .unwrap_or(false);
    let workspace_kind = if linked_worktree {
        "linked_worktree"
    } else if same_path(workspace, &toplevel) {
        "repository_root"
    } else {
        "repository_subdir"
    };
    // For linked worktrees, `--show-toplevel` is the throwaway worktree
    // directory, so labels would surface names like "gallant-albattani-9baa0b".
    // Use the main checkout directory (the parent of the shared `.git` common
    // dir) instead, falling back to the toplevel for layouts where the common
    // dir does not end in `.git` (e.g. bare-ish repositories).
    let label_basis: &Path = if linked_worktree {
        main_checkout_dir(&common_dir).unwrap_or(&toplevel)
    } else {
        &toplevel
    };
    RepositoryIdentity {
        repository_hash: Some(sha256_hex(&[common_text.as_ref()])),
        repository_label: labels_enabled
            .then(|| label_basis.file_name()?.to_str())
            .flatten()
            .and_then(|name| safe_text(name, 255)),
        repository_label_source: labels_enabled.then(|| "git_root".to_string()),
        repository_identity_source: Some(
            if linked_worktree {
                "git_worktree"
            } else {
                "git_common_dir"
            }
            .to_string(),
        ),
        workspace_kind: Some(workspace_kind.to_string()),
    }
}

/// The main checkout folder of the repository holding `workspace` (the
/// parent of its shared `.git` folder), else the workspace's top level for
/// layouts without one. `None` outside git.
pub(crate) fn repository_main_checkout(workspace: &Path) -> Option<PathBuf> {
    let toplevel = git_stdout(workspace, &["rev-parse", "--show-toplevel"])?;
    let toplevel = absolutize_git_path(workspace, &toplevel);
    let Some(common_dir) = git_stdout(workspace, &["rev-parse", "--git-common-dir"]) else {
        return Some(toplevel);
    };
    let common_dir = absolutize_git_path(workspace, &common_dir);
    Some(
        main_checkout_dir(&common_dir)
            .map(Path::to_path_buf)
            .unwrap_or(toplevel),
    )
}

pub(crate) fn git_toplevel(workspace: &Path) -> Option<PathBuf> {
    git_stdout(workspace, &["rev-parse", "--show-toplevel"])
        .map(|raw| absolutize_git_path(workspace, &raw))
}

fn git_stdout(workspace: &Path, args: &[&str]) -> Option<String> {
    let bytes = git_stdout_capped(workspace, args, GIT_STDOUT_MAX_BYTES).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(4096).collect())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GitOutputError {
    Failed,
    TooLarge,
    TimedOut,
}

/// Successful git stdout, read while git runs so output over the pipe buffer
/// cannot stall it. Reading stops past `max_bytes` (git then gets SIGPIPE).
/// On timeout the child is killed and reaped; a reader still held open by a
/// descendant is left to finish on its own thread.
pub(crate) fn git_stdout_capped(
    dir: &Path,
    args: &[&str],
    max_bytes: usize,
) -> Result<Vec<u8>, GitOutputError> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| GitOutputError::Failed)?;
    let deadline = Instant::now() + GIT_COMMAND_TIMEOUT;
    fn stop(
        mut child: std::process::Child,
        error: GitOutputError,
    ) -> Result<Vec<u8>, GitOutputError> {
        let _ = child.kill();
        let _ = child.wait();
        Err(error)
    }
    let Some(stdout) = child.stdout.take() else {
        return stop(child, GitOutputError::Failed);
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("ottto-git-stdout".to_string())
        .spawn(move || {
            let mut bytes = Vec::new();
            let read = stdout
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send(read);
        });
    if spawned.is_err() {
        return stop(child, GitOutputError::Failed);
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => return stop(child, GitOutputError::TimedOut),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return stop(child, GitOutputError::Failed),
        }
    };
    let bytes = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return Err(GitOutputError::Failed),
        Err(_) => return Err(GitOutputError::TimedOut),
    };
    if bytes.len() > max_bytes {
        return Err(GitOutputError::TooLarge);
    }
    if !status.success() {
        return Err(GitOutputError::Failed);
    }
    Ok(bytes)
}

/// The directory holding the main checkout of a repository whose shared git
/// common dir is `common_dir`. For the standard layout the common dir is
/// `<main-checkout>/.git`, so this is its parent. Returns `None` when the
/// common dir does not end in `.git` (bare or unusual layouts), signalling the
/// caller to fall back to the workspace toplevel.
fn main_checkout_dir(common_dir: &Path) -> Option<&Path> {
    (common_dir.file_name()? == ".git")
        .then(|| common_dir.parent())
        .flatten()
}

fn absolutize_git_path(workspace: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    let absolute = if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    };
    canonical_or_self(&absolute)
}

fn canonical_or_self(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn same_path(left: &Path, right: &Path) -> bool {
    canonical_or_self(left) == canonical_or_self(right)
}

pub(crate) fn safe_text(raw: &str, max_len: usize) -> Option<String> {
    let normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    let lowered = normalized.to_ascii_lowercase();
    if lowered.contains("/users/")
        || lowered.contains("\\users\\")
        || lowered.contains("/home/")
        || lowered.contains("\\home\\")
        || lowered.contains("file://")
        || lowered.contains("transcript_path")
        || lowered.contains("workspace_path")
        || lowered.contains("authorization:")
        || lowered.contains("bearer ")
        || lowered.contains("otdev_")
        || lowered.contains("otsi_")
        || lowered.contains("otsr_")
        || lowered.contains("otel_")
        || lowered.contains("otrelay_")
    {
        return None;
    }
    Some(normalized.chars().take(max_len).collect())
}

pub(crate) fn request_content_hash_for_request(
    request: &ContextFootprintIngestRequest,
) -> Result<String> {
    let canonical = json!({
        "cache_schema": "context_footprint_request_v3",
        "agent_source": &request.agent_source,
        "machine_id": &request.machine_id,
        "workspace_hash": &request.workspace_hash,
        "workspace_label": &request.workspace_label,
        "workspace_label_source": &request.workspace_label_source,
        "repository_hash": &request.repository_hash,
        "repository_label": &request.repository_label,
        "repository_label_source": &request.repository_label_source,
        "repository_identity_source": &request.repository_identity_source,
        "workspace_kind": &request.workspace_kind,
        "config_hash": &request.config_hash,
        "collector_version": &request.collector_version,
        "counter_source": &request.counter_source,
        "model": &request.model,
        "used_tokens": request.used_tokens,
        "context_window_tokens": request.context_window_tokens,
        "pct_context": request.pct_context,
        "free_space_tokens": request.free_space_tokens,
        "categories": &request.categories,
        "memory_files": &request.memory_files,
        "skills": &request.skills,
        "custom_agents": &request.custom_agents,
        // Only Claude `/context` reported MCP tools; the empty list keeps
        // cached Codex digests unchanged.
        "mcp_tools": [],
    });
    let canonical =
        serde_json::to_vec(&canonical).map_err(|error| anyhow!("hash encode failed: {error}"))?;
    Ok(sha256_bytes(&canonical))
}

pub(crate) fn sha256_hex(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

pub(crate) fn workspace_label(workspace: &Path) -> Option<String> {
    workspace
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| safe_text(name, 255))
        .or_else(|| Some("workspace".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_client::{workspace_labels_allowed, ActivityHintResponse};
    use serde_json::Value;
    use std::fs;

    use crate::test_scratch;

    fn temp_dir(name: &str) -> PathBuf {
        test_scratch::private_dir(&format!("ottto-context-footprint-{name}"))
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_git_repo(name: &str) -> PathBuf {
        let repo = temp_dir(name);
        run_git(&repo, &["init"]);
        run_git(&repo, &["config", "user.email", "test@example.com"]);
        run_git(&repo, &["config", "user.name", "Test User"]);
        fs::write(repo.join("README.md"), "test\n").unwrap();
        run_git(&repo, &["add", "README.md"]);
        run_git(&repo, &["commit", "-m", "initial"]);
        repo
    }

    /// [format] File counts keep the shared v1 wire shape.
    #[test]
    fn context_file_counts_generated_wire_fixture() {
        let item = ContextFootprintItemInput {
            kind: "memory_file".to_string(),
            name: "MEMORY.md".to_string(),
            tokens: 6000,
            pct: None,
            source: Some("AutoMem".to_string()),
            relative_path: Some("MEMORY.md".to_string()),
            loading_mode: "always_on".to_string(),
            file_counts: crate::context_file_counts::measure_bytes(
                "x\n".repeat(300).as_bytes(),
                true,
                Some(&[7; 32]),
            )
            .unwrap(),
        };
        let actual = json!({
            "contract_version": "context_footprint_file_counts:v1",
            "max_file_bytes": crate::context_file_counts::MAX_FILE_BYTES,
            "character_unit": "utf16",
            "auto_memory_limit": {"lines": crate::context_file_counts::AUTO_MEMORY_LIMIT.0,
                "chars": crate::context_file_counts::AUTO_MEMORY_LIMIT.1},
            "hash_scheme": "sha256(ottto-context-file-v1\\0 || device_salt_32_bytes || file_bytes):hex64",
            "item": &item,
        });
        let expected: Value = serde_json::from_str(include_str!(
            "../../../fixtures/context-footprint/file-counts-v1.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn repository_identity_groups_root_and_subdir_without_raw_paths() {
        let repo = init_git_repo("repo-identity-root");
        let subdir = repo.join("backend");
        fs::create_dir_all(&subdir).unwrap();

        let root_identity = resolve_repository_identity(&repo, true);
        let subdir_identity = resolve_repository_identity(&subdir, true);

        assert_eq!(
            root_identity.repository_hash,
            subdir_identity.repository_hash
        );
        assert_eq!(root_identity.repository_hash.as_ref().unwrap().len(), 64);
        assert_eq!(
            root_identity.repository_label.as_deref(),
            repo.file_name().and_then(|name| name.to_str())
        );
        assert_eq!(
            root_identity.repository_label_source.as_deref(),
            Some("git_root")
        );
        assert_eq!(
            root_identity.repository_identity_source.as_deref(),
            Some("git_common_dir")
        );
        assert_eq!(
            root_identity.workspace_kind.as_deref(),
            Some("repository_root")
        );
        assert_eq!(
            subdir_identity.workspace_kind.as_deref(),
            Some("repository_subdir")
        );
        let encoded = serde_json::to_string(&root_identity.repository_label).unwrap();
        assert!(!encoded.contains("/Users/"));
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn repository_identity_withholds_labels_unless_a_hint_allows_them() {
        let repo = init_git_repo("repo-identity-hint-policy");
        let hint = |labels: bool| {
            crate::snapshot_client::decode_activity_hint(serde_json::json!({
                "source": "claude_code", "server_time": "2026-10-25T10:00:00Z",
                "record_count_15m": 0, "record_count_24h": 0,
                "local_usage_reconciliation_enabled": true, "backfill_window_days": 183,
                "workspace_labels_enabled": labels,
                "recommended_scan_after": "2026-10-25T10:05:00Z",
            }))
            .unwrap()
        };
        let identity = |hint: Option<&ActivityHintResponse>| {
            resolve_repository_identity(&repo, workspace_labels_allowed(hint))
        };

        // Policy ON keeps today's labelled identity.
        let on = identity(Some(&hint(true)));
        assert_eq!(on, resolve_repository_identity(&repo, true));
        assert!(on.repository_label.is_some());
        // Policy OFF and a failed hint fetch both withhold the labels.
        let withheld = resolve_repository_identity(&repo, false);
        assert_eq!(identity(Some(&hint(false))), withheld);
        assert_eq!(identity(None), withheld);
        assert!(withheld.repository_label.is_none());
        assert!(withheld.repository_label_source.is_none());
        assert_eq!(withheld.repository_hash, on.repository_hash);
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn repository_identity_marks_non_git_without_repository_hash() {
        let dir = temp_dir("repo-identity-non-git");

        let identity = resolve_repository_identity(&dir, true);

        assert!(identity.repository_hash.is_none());
        assert!(identity.repository_label.is_none());
        assert!(identity.repository_label_source.is_none());
        assert!(identity.repository_identity_source.is_none());
        assert_eq!(identity.workspace_kind.as_deref(), Some("non_git"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn repository_identity_groups_linked_worktree_to_common_repo() {
        let repo = init_git_repo("repo-identity-worktree");
        let worktree = temp_dir("repo-identity-worktree-linked");
        fs::remove_dir_all(&worktree).unwrap();
        let worktree_text = worktree.to_string_lossy().to_string();
        run_git(
            &repo,
            &["worktree", "add", "-b", "context-test", &worktree_text],
        );

        let root_identity = resolve_repository_identity(&repo, true);
        let worktree_identity = resolve_repository_identity(&worktree, true);

        assert_eq!(
            root_identity.repository_hash,
            worktree_identity.repository_hash
        );
        assert_eq!(
            worktree_identity.repository_identity_source.as_deref(),
            Some("git_worktree")
        );
        assert_eq!(
            worktree_identity.workspace_kind.as_deref(),
            Some("linked_worktree")
        );
        // The label must name the main checkout, not the throwaway worktree
        // directory the user happens to be working from.
        assert_eq!(
            worktree_identity.repository_label,
            root_identity.repository_label
        );
        let worktree_dir_name = worktree.file_name().unwrap().to_str().unwrap();
        assert_ne!(
            worktree_identity.repository_label.as_deref(),
            Some(worktree_dir_name)
        );
        let _ = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["worktree", "remove", "--force", &worktree_text])
            .status();
        let _ = fs::remove_dir_all(&repo);
    }

    /// Discovery before the projection: every recent file is parsed whole,
    /// then deduplicated by repository and truncated to one cycle.
    fn sample_request() -> ContextFootprintIngestRequest {
        ContextFootprintIngestRequest {
            agent_source: "claude-code".to_string(),
            machine_id: "machine-a".to_string(),
            workspace_hash: "workspace-a".to_string(),
            workspace_label: Some("coding-agents-observability".to_string()),
            workspace_label_source: Some("directory_name".to_string()),
            repository_hash: Some("repo-a".to_string()),
            repository_label: Some("coding-agents-observability".to_string()),
            repository_label_source: Some("git_root".to_string()),
            repository_identity_source: Some("git_common_dir".to_string()),
            workspace_kind: Some("repository_root".to_string()),
            config_hash: "config-a".to_string(),
            captured_at: "2026-07-05T00:00:00Z".to_string(),
            collector_version: "0.1.69".to_string(),
            counter_source: "claude_code_context_v1".to_string(),
            model: "claude".to_string(),
            used_tokens: 10,
            context_window_tokens: 100,
            pct_context: 10.0,
            free_space_tokens: Some(90),
            categories: vec![ContextFootprintCategoryInput {
                name: "Free space".to_string(),
                tokens: 90,
                pct: 90.0,
                loading_mode: "unknown".to_string(),
            }],
            memory_files: Vec::new(),
            skills: Vec::new(),
            custom_agents: Vec::new(),
        }
    }

    #[test]
    fn request_upload_cache_hash_tracks_repository_identity_and_label_policy() {
        let base = sample_request();
        let mut legacy_shape = base.clone();
        legacy_shape.repository_hash = None;
        legacy_shape.repository_label = None;
        legacy_shape.repository_label_source = None;
        legacy_shape.repository_identity_source = None;
        legacy_shape.workspace_kind = None;
        let mut labels_disabled = base.clone();
        labels_disabled.workspace_label = None;
        labels_disabled.workspace_label_source = None;
        labels_disabled.repository_label = None;
        labels_disabled.repository_label_source = None;

        let base_hash = request_content_hash_for_request(&base).unwrap();
        assert_eq!(base_hash.len(), 64);
        assert_ne!(
            base_hash,
            request_content_hash_for_request(&legacy_shape).unwrap()
        );
        assert_ne!(
            base_hash,
            request_content_hash_for_request(&labels_disabled).unwrap()
        );
    }

    #[test]
    fn capped_git_output_drains_large_output_and_refuses_over_cap() {
        let repo = init_git_repo("git-capped");
        let blob = repo.join("blob");
        fs::write(&blob, "x".repeat(300_000)).unwrap();
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["hash-object", "-w", "blob"])
            .output()
            .unwrap();
        let id = String::from_utf8(output.stdout).unwrap().trim().to_string();
        let args = ["cat-file", "-p", id.as_str()];
        assert_eq!(
            git_stdout_capped(&repo, &args, GIT_STDOUT_MAX_BYTES)
                .unwrap()
                .len(),
            300_000
        );
        assert_eq!(
            git_stdout_capped(&repo, &args, 100_000),
            Err(GitOutputError::TooLarge)
        );
        assert_eq!(
            git_stdout_capped(&repo, &["cat-file", "-p", "missing"], 1024),
            Err(GitOutputError::Failed)
        );
        // A descendant still holding stdout cannot hold the caller past the
        // timeout; the reader thread finishes once the pipe closes.
        let started = Instant::now();
        assert_eq!(
            git_stdout_capped(&repo, &["-c", "alias.slow=!sleep 4", "slow"], 1024),
            Err(GitOutputError::TimedOut)
        );
        assert!(started.elapsed() < GIT_COMMAND_TIMEOUT + Duration::from_secs(1));
        // Non-ASCII output keeps the 4,096-character (not byte) result.
        fs::write(repo.join("wide"), "\u{e9}".repeat(5000)).unwrap();
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["hash-object", "-w", "wide"])
            .output()
            .unwrap();
        let wide = String::from_utf8(output.stdout).unwrap().trim().to_string();
        assert_eq!(
            git_stdout(&repo, &["cat-file", "-p", wide.as_str()]),
            Some("\u{e9}".repeat(4096))
        );
        fs::remove_dir_all(repo).unwrap();
    }
}
