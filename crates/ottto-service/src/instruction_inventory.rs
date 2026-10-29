//! Claude Code instruction-file inventory for one `/context` capture.
//!
//! Lists which `AGENTS.md` and CLAUDE files (`CLAUDE.md`, `.claude/CLAUDE.md`,
//! `CLAUDE.local.md`) exist in the checkout the capture ran in, their sizes
//! from `stat`, and whether that same capture listed each one. No file
//! contents, hashes, absolute paths or worktree data are collected. It also
//! reports Claude Code's Project instructions setting (`instructionFiles` of
//! the built-in agents-md plugin) for the login that ran the capture.
//!
//! The backend decides what Claude Code did not load; this module only
//! reports facts. Anything it could not establish makes the list partial,
//! never "missing": a partial list suppresses the backend's file alerts.

use crate::snapshots::{read_claude_settings_document, ClaudeSettingsDocument};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) const MAX_ENTRIES: usize = 200;
/// Serialized block ceiling, checked while adding entries.
pub(crate) const MAX_BLOCK_BYTES: usize = 8192;
/// Room for every non-entry field at its largest, all six reasons included.
const NON_ENTRY_RESERVE_BYTES: usize = 512;
/// Backend `relative_path` bound, in characters.
const MAX_RELATIVE_PATH_CHARS: usize = 512;
const LS_FILES_MAX_BYTES: usize = 1024 * 1024;
/// Scratch bounds: nested AGENTS.md paths kept from `ls-files` (the index is
/// sorted, so these are the first in order) and folders memoized for the
/// CLAUDE-file chain. Past either, the list is partial (`file_cap`).
const MAX_NESTED_CANDIDATES: usize = 1000;
const MAX_CHAIN_FOLDERS: usize = 2000;
/// Checked between stats; one blocked `stat` cannot be interrupted.
const TIME_BUDGET: Duration = Duration::from_secs(1);

/// Root files, in bytewise order: always listed first, so they fit any cap.
const ROOT_FILES: [&str; 4] = [
    ".claude/CLAUDE.md",
    "AGENTS.md",
    "CLAUDE.local.md",
    "CLAUDE.md",
];
/// CLAUDE files checked in each folder between a nested AGENTS.md and the root.
const CHAIN_CLAUDE_FILES: [&str; 3] = [".claude/CLAUDE.md", "CLAUDE.local.md", "CLAUDE.md"];
const ENTRY_FILE_NAMES: [&str; 3] = ["AGENTS.md", "CLAUDE.md", "CLAUDE.local.md"];

/// Both ids of Claude Code's built-in agents-md plugin in `pluginConfigs`.
const AGENTS_MD_PLUGIN_IDS: [&str; 2] = ["cc-plugin-agents-md@builtin", "agents-md@builtin"];
/// Same file `agent_status` reads as managed settings.
const CLAUDE_MANAGED_SETTINGS_PATH: &str =
    "/Library/Application Support/ClaudeCode/managed-settings.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ClaudeInstructionMode {
    /// Claude Code's default: AGENTS.md loads only where no CLAUDE.md exists.
    #[serde(rename = "claude-md-or-agents-md")]
    OrAgentsMd,
    #[serde(rename = "claude-md-and-agents-md")]
    AndAgentsMd,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PartialReason {
    FileCap,
    SizeCap,
    TimeBudget,
    StatError,
    GitFailed,
    PathsWithheld,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstructionInventory {
    pub(crate) started_at_root: bool,
    pub(crate) claude_mode: ClaudeInstructionMode,
    pub(crate) files: InstructionInventoryFiles,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstructionInventoryFiles {
    pub(crate) complete: bool,
    pub(crate) partial_reasons: Vec<PartialReason>,
    pub(crate) entries: Vec<InstructionInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstructionInventoryEntry {
    pub(crate) relative_path: String,
    pub(crate) file_bytes: u64,
    pub(crate) observed_at_start: bool,
}

/// Whether the organization's label policy allows instruction paths to leave
/// the machine. Only an explicit "labels on" from the activity hint collects
/// them; a failed hint sends no block at all (the caller passes `None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryPaths {
    Collect,
    Withhold,
}

/// Mode of the default login, which the `/context` run uses: managed settings
/// plus `~/.claude/settings.json`. Claude Code reads plugin options only from
/// user, `--settings` and managed settings, so project and `settings.local`
/// files are not consulted.
pub(crate) fn default_login_claude_mode(home: &Path) -> ClaudeInstructionMode {
    resolve_claude_mode(&[
        Path::new(CLAUDE_MANAGED_SETTINGS_PATH),
        &home.join(".claude").join("settings.json"),
    ])
}

/// Named keys only: `pluginConfigs.<id>.options.instructionFiles`, the legacy
/// `options.projectInstructions` and `enabledPlugins.<id>`. Missing files are
/// skipped; an unreadable or malformed file, the legacy option anywhere, a
/// disabled plugin, a value outside the two proven ones, or values that
/// disagree all give `unknown`. No value anywhere is Claude Code's default.
pub(crate) fn resolve_claude_mode(settings_files: &[&Path]) -> ClaudeInstructionMode {
    let mut values = BTreeSet::new();
    for path in settings_files {
        match read_claude_settings_document(path) {
            ClaudeSettingsDocument::Missing => {}
            ClaudeSettingsDocument::Failed => return ClaudeInstructionMode::Unknown,
            ClaudeSettingsDocument::Parsed(document) => {
                if !collect_mode_values(&document, &mut values) {
                    return ClaudeInstructionMode::Unknown;
                }
            }
        }
    }
    let mut values = values.into_iter();
    match (values.next().as_deref(), values.next()) {
        (None, _) => ClaudeInstructionMode::OrAgentsMd,
        (Some("claude-md-or-agents-md"), None) => ClaudeInstructionMode::OrAgentsMd,
        (Some("claude-md-and-agents-md"), None) => ClaudeInstructionMode::AndAgentsMd,
        _ => ClaudeInstructionMode::Unknown,
    }
}

/// Adds this file's `instructionFiles` values; false when the file alone
/// makes the mode unknown.
fn collect_mode_values(document: &Value, values: &mut BTreeSet<String>) -> bool {
    for id in AGENTS_MD_PLUGIN_IDS {
        if document
            .get("enabledPlugins")
            .and_then(|plugins| plugins.get(id))
            == Some(&Value::Bool(false))
        {
            return false;
        }
        let Some(options) = document
            .get("pluginConfigs")
            .and_then(|configs| configs.get(id))
            .and_then(|config| config.get("options"))
        else {
            continue;
        };
        let Some(options) = options.as_object() else {
            return false;
        };
        if options.contains_key("projectInstructions") {
            return false;
        }
        match options.get("instructionFiles") {
            None => {}
            Some(Value::String(value)) => {
                values.insert(value.clone());
            }
            Some(_) => return false,
        }
    }
    true
}

/// The block for one capture, or `None` outside a git checkout (no top level
/// to describe). `observed` holds the capture's Project/Local rows as
/// symlink-resolved paths.
pub(crate) fn build_instruction_inventory(
    workspace: &Path,
    observed: &BTreeSet<PathBuf>,
    claude_mode: ClaudeInstructionMode,
    paths: InventoryPaths,
) -> Option<InstructionInventory> {
    let toplevel = crate::context_footprint::git_toplevel(workspace)?;
    let started_at_root = canonical_or_self(workspace) == canonical_or_self(&toplevel);
    let files = match paths {
        InventoryPaths::Withhold => InstructionInventoryFiles {
            complete: false,
            partial_reasons: vec![PartialReason::PathsWithheld],
            entries: Vec::new(),
        },
        InventoryPaths::Collect => collect_files(&toplevel, observed, Instant::now() + TIME_BUDGET),
    };
    Some(InstructionInventory {
        started_at_root,
        claude_mode,
        files,
    })
}

fn collect_files(
    toplevel: &Path,
    observed: &BTreeSet<PathBuf>,
    deadline: Instant,
) -> InstructionInventoryFiles {
    let mut reasons = BTreeSet::new();
    let mut found: BTreeMap<String, u64> = BTreeMap::new();
    for name in ROOT_FILES {
        stat_into(toplevel, name.to_string(), &mut found, &mut reasons);
    }
    match nested_agents_paths(toplevel, &mut reasons) {
        Some(nested) => {
            let mut chain_checked = BTreeSet::new();
            'nested: for agents in nested {
                if Instant::now() >= deadline {
                    reasons.insert(PartialReason::TimeBudget);
                    break;
                }
                if found.len() > MAX_ENTRIES {
                    reasons.insert(PartialReason::FileCap);
                    break;
                }
                // A tracked file deleted locally is not in this checkout.
                if !stat_into(toplevel, agents.clone(), &mut found, &mut reasons) {
                    continue;
                }
                let mut folder = Path::new(&agents).parent();
                while let Some(dir) = folder.filter(|dir| !dir.as_os_str().is_empty()) {
                    if chain_checked.contains(dir) {
                        break;
                    }
                    if chain_checked.len() == MAX_CHAIN_FOLDERS {
                        reasons.insert(PartialReason::FileCap);
                        break 'nested;
                    }
                    chain_checked.insert(dir.to_path_buf());
                    if Instant::now() >= deadline {
                        reasons.insert(PartialReason::TimeBudget);
                        break 'nested;
                    }
                    for name in CHAIN_CLAUDE_FILES {
                        let relative = format!("{}/{name}", dir.to_string_lossy());
                        stat_into(toplevel, relative, &mut found, &mut reasons);
                    }
                    folder = dir.parent();
                }
            }
        }
        None => {
            reasons.insert(PartialReason::GitFailed);
        }
    }
    let roots: Vec<_> = ROOT_FILES
        .iter()
        .filter_map(|name| found.remove_entry(*name))
        .collect();
    let root_count = roots.len();
    let is_observed =
        |relative: &str| observed.contains(&canonical_or_self(&toplevel.join(relative)));
    let entries = capped_entries(
        roots.into_iter().chain(found),
        root_count,
        is_observed,
        deadline,
        &mut reasons,
    );
    InstructionInventoryFiles {
        complete: reasons.is_empty(),
        partial_reasons: reasons.into_iter().collect(),
        entries,
    }
}

/// Keeps entries in order until the 200-entry or 8 KiB block cap. Each
/// observed check resolves symlinks, so the deadline applies after the root
/// files, which always stay.
fn capped_entries(
    ordered: impl Iterator<Item = (String, u64)>,
    root_count: usize,
    is_observed: impl Fn(&str) -> bool,
    deadline: Instant,
    reasons: &mut BTreeSet<PartialReason>,
) -> Vec<InstructionInventoryEntry> {
    let mut entries = Vec::new();
    let mut block_bytes = NON_ENTRY_RESERVE_BYTES;
    for (relative_path, file_bytes) in ordered {
        if entries.len() == MAX_ENTRIES {
            reasons.insert(PartialReason::FileCap);
            break;
        }
        if entries.len() >= root_count && Instant::now() >= deadline {
            reasons.insert(PartialReason::TimeBudget);
            break;
        }
        let entry = InstructionInventoryEntry {
            observed_at_start: is_observed(&relative_path),
            relative_path,
            file_bytes,
        };
        let entry_bytes = serde_json::to_vec(&entry).map_or(usize::MAX, |bytes| bytes.len() + 1);
        if block_bytes.saturating_add(entry_bytes) > MAX_BLOCK_BYTES {
            reasons.insert(PartialReason::SizeCap);
            break;
        }
        block_bytes += entry_bytes;
        entries.push(entry);
    }
    entries
}

/// Tracked nested AGENTS.md paths in bytewise order, from the index only (no
/// untracked walk). `None` when git failed, timed out or over-produced.
fn nested_agents_paths(
    toplevel: &Path,
    reasons: &mut BTreeSet<PartialReason>,
) -> Option<BTreeSet<String>> {
    let output = crate::context_footprint::git_stdout_capped(
        toplevel,
        &["ls-files", "-z", "--", "AGENTS.md", ":(glob)**/AGENTS.md"],
        LS_FILES_MAX_BYTES,
    )
    .ok()?;
    let mut paths = BTreeSet::new();
    for raw in output
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let Ok(path) = std::str::from_utf8(raw) else {
            reasons.insert(PartialReason::PathsWithheld);
            continue;
        };
        let nested = path.rsplit_once('/').is_some_and(|(dir, name)| {
            name == "AGENTS.md" && !dir.split('/').any(|part| part == ".claude")
        });
        if nested {
            if paths.len() == MAX_NESTED_CANDIDATES {
                reasons.insert(PartialReason::FileCap);
                break;
            }
            paths.insert(path.to_string());
        }
    }
    Some(paths)
}

/// Adds an existing regular file; true when it exists. Not found (or a
/// non-directory in the path) is absent; any other error makes the list
/// partial and is never reported as absent.
fn stat_into(
    toplevel: &Path,
    relative: String,
    found: &mut BTreeMap<String, u64>,
    reasons: &mut BTreeSet<PartialReason>,
) -> bool {
    if found.contains_key(&relative) {
        return true;
    }
    match std::fs::metadata(toplevel.join(&relative)) {
        Ok(metadata) if metadata.is_file() => {
            if sendable_relative_path(&relative) {
                found.insert(relative, metadata.len());
            } else {
                reasons.insert(PartialReason::PathsWithheld);
            }
            true
        }
        Ok(_) => false,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            false
        }
        Err(_) => {
            reasons.insert(PartialReason::StatError);
            false
        }
    }
}

/// Mirrors the backend's admission rules, so one odd folder name withholds
/// that path instead of rejecting the whole footprint snapshot.
fn sendable_relative_path(relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    if !ENTRY_FILE_NAMES.contains(&name)
        || relative.chars().count() > MAX_RELATIVE_PATH_CHARS
        || relative.contains('\\')
        || relative.starts_with(['/', '~'])
        || relative.contains(":/")
        || relative.split('/').any(|part| part == "..")
    {
        return false;
    }
    crate::context_footprint::safe_text(relative, MAX_RELATIVE_PATH_CHARS).is_some()
}

fn canonical_or_self(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::test_scratch;
    use std::fs;
    use std::process::Command;

    const FIXTURE: &str =
        include_str!("../../../fixtures/context-footprint/instruction-inventory-v1.json");

    fn fixture_variant(name: &str) -> Value {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        fixture["variants"][name]["instruction_inventory"].clone()
    }

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn write_sized(path: &Path, bytes: u64) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::File::create(path).unwrap().set_len(bytes).unwrap();
    }

    /// The fixture's repository: root files, tracked nested AGENTS.md files,
    /// an ignored CLAUDE.local.md at the root and a tracked frontend/CLAUDE.md.
    fn fixture_repo(name: &str, root_claude_bytes: u64) -> PathBuf {
        let repo = test_scratch::private_dir(&format!("ottto-instruction-inventory-{name}"));
        git(&repo, &["init", "-q"]);
        for (path, bytes) in [
            ("AGENTS.md", 18300),
            ("CLAUDE.local.md", 4300),
            ("CLAUDE.md", root_claude_bytes),
            ("backend/AGENTS.md", 5612),
            ("frontend/AGENTS.md", 3100),
            ("frontend/CLAUDE.md", 12),
            // Excluded: under `.claude`, and not an instruction file name.
            (".claude/agents/AGENTS.md", 9),
            ("docs/README.md", 9),
        ] {
            write_sized(&repo.join(path), bytes);
        }
        fs::write(repo.join(".gitignore"), "CLAUDE.local.md\n").unwrap();
        git(&repo, &["add", "."]);
        repo
    }

    fn observed(repo: &Path, paths: &[&str]) -> BTreeSet<PathBuf> {
        paths
            .iter()
            .map(|path| repo.join(path).canonicalize().unwrap())
            .collect()
    }

    fn assert_fixture(inventory: &InstructionInventory, variant: &str) {
        let expected = fixture_variant(variant);
        assert_eq!(
            serde_json::to_value(inventory).unwrap(),
            expected,
            "{variant}"
        );
        // Same compact UTF-8 payload size as the fixture (key order aside).
        assert_eq!(
            serde_json::to_vec(inventory).unwrap().len(),
            serde_json::to_vec(&expected).unwrap().len(),
            "{variant} bytes"
        );
        let decoded: InstructionInventory = serde_json::from_value(expected).unwrap();
        assert_eq!(&decoded, inventory, "{variant} round trip");
    }

    #[test]
    fn bounded_repo_matches_every_frozen_fixture_variant() {
        let root = ["AGENTS.md", "CLAUDE.local.md", "CLAUDE.md"];
        let repo = fixture_repo("default", 10);
        let build = |mode, paths, seen: &[&str]| {
            build_instruction_inventory(&repo, &observed(&repo, seen), mode, paths).unwrap()
        };
        let mode = ClaudeInstructionMode::OrAgentsMd;
        assert_fixture(&build(mode, InventoryPaths::Collect, &root), "default_mode");
        assert_fixture(
            &build(
                ClaudeInstructionMode::Unknown,
                InventoryPaths::Collect,
                &root,
            ),
            "legacy_project_instructions_option",
        );
        assert_fixture(&build(mode, InventoryPaths::Withhold, &root), "labels_off");
        // A subfolder start reports the same checkout, not started at root.
        let from_subdir = build_instruction_inventory(
            &repo.join("backend"),
            &observed(&repo, &root),
            mode,
            InventoryPaths::Collect,
        )
        .unwrap();
        assert!(!from_subdir.started_at_root);
        assert_eq!(
            from_subdir.files,
            build(mode, InventoryPaths::Collect, &root).files
        );

        let large = fixture_repo("over-skip-limit", 4_500_000);
        let inventory = build_instruction_inventory(
            &large,
            &observed(&large, &["AGENTS.md", "CLAUDE.local.md"]),
            mode,
            InventoryPaths::Collect,
        )
        .unwrap();
        assert_fixture(&inventory, "root_claude_md_over_skip_limit");

        // CLAUDE.md -> AGENTS.md: /context lists one path; both resolve to it.
        let linked = test_scratch::private_dir("ottto-instruction-inventory-symlink");
        git(&linked, &["init", "-q"]);
        write_sized(&linked.join("AGENTS.md"), 18300);
        write_sized(&linked.join("backend/AGENTS.md"), 5612);
        std::os::unix::fs::symlink("AGENTS.md", linked.join("CLAUDE.md")).unwrap();
        git(&linked, &["add", "."]);
        let inventory = build_instruction_inventory(
            &linked,
            &observed(&linked, &["CLAUDE.md"]),
            mode,
            InventoryPaths::Collect,
        )
        .unwrap();
        assert_fixture(&inventory, "symlinked_root_claude_md");
        for dir in [repo, large, linked] {
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn errors_and_caps_make_the_list_partial_never_missing() {
        let mode = ClaudeInstructionMode::OrAgentsMd;
        let none = BTreeSet::new();
        // Outside git: no block.
        let plain = test_scratch::private_dir("ottto-instruction-inventory-plain");
        assert!(
            build_instruction_inventory(&plain, &none, mode, InventoryPaths::Collect).is_none()
        );

        // An unreadable chain folder is a stat error, not an absent CLAUDE file.
        let repo = fixture_repo("stat-error", 10);
        fs::set_permissions(
            repo.join("frontend"),
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();
        let blocked =
            build_instruction_inventory(&repo, &none, mode, InventoryPaths::Collect).unwrap();
        fs::set_permissions(
            repo.join("frontend"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(
            blocked.files.partial_reasons,
            vec![PartialReason::StatError]
        );
        assert!(!blocked.files.complete);
        assert!(!blocked
            .files
            .entries
            .iter()
            .any(|entry| entry.relative_path.starts_with("frontend/")));

        // A tracked file deleted locally is dropped; the list stays complete.
        fs::remove_file(repo.join("backend/AGENTS.md")).unwrap();
        let deleted =
            build_instruction_inventory(&repo, &none, mode, InventoryPaths::Collect).unwrap();
        assert!(deleted.files.complete);
        assert!(!deleted
            .files
            .entries
            .iter()
            .any(|entry| entry.relative_path == "backend/AGENTS.md"));

        // Non-ASCII folder names are sent as UTF-8, sized in bytes.
        write_sized(&repo.join("d\u{e9}j\u{e0}/AGENTS.md"), 7);
        git(&repo, &["add", "."]);
        let unicode =
            build_instruction_inventory(&repo, &none, mode, InventoryPaths::Collect).unwrap();
        assert!(unicode.files.complete);
        assert!(unicode
            .files
            .entries
            .iter()
            .any(|entry| !entry.relative_path.is_ascii() && entry.file_bytes == 7));

        // A path the backend would reject is withheld, never sent.
        write_sized(&repo.join("a/home/x/AGENTS.md"), 5);
        git(&repo, &["add", "a"]);
        let withheld =
            build_instruction_inventory(&repo, &none, mode, InventoryPaths::Collect).unwrap();
        assert_eq!(
            withheld.files.partial_reasons,
            vec![PartialReason::PathsWithheld]
        );
        assert!(!withheld
            .files
            .entries
            .iter()
            .any(|entry| entry.relative_path.contains("home/")));

        // Over-budget time: roots only, partial.
        let mut reasons = BTreeSet::new();
        let late = collect_files(&repo, &none, Instant::now() - Duration::from_secs(1));
        reasons.insert(PartialReason::TimeBudget);
        assert_eq!(
            late.partial_reasons,
            reasons.into_iter().collect::<Vec<_>>()
        );
        let names: Vec<_> = late
            .entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        assert_eq!(names, ["AGENTS.md", "CLAUDE.local.md", "CLAUDE.md"]);
        // The deadline also stops the observed checks after the root files.
        let mut reasons = BTreeSet::new();
        let past = Instant::now() - Duration::from_secs(1);
        let listed = [("CLAUDE.md", 1), ("a/AGENTS.md", 1), ("b/AGENTS.md", 1)]
            .map(|(path, bytes)| (path.to_string(), bytes));
        let kept = capped_entries(listed.into_iter(), 1, |_| true, past, &mut reasons);
        assert_eq!(kept.len(), 1);
        assert_eq!(
            reasons.into_iter().collect::<Vec<_>>(),
            [PartialReason::TimeBudget]
        );
        for dir in [plain, repo] {
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn caps_keep_root_files_and_bound_the_block() {
        let repo = test_scratch::private_dir("ottto-instruction-inventory-caps");
        git(&repo, &["init", "-q"]);
        write_sized(&repo.join("CLAUDE.md"), 1);
        for index in 0..230 {
            write_sized(&repo.join(format!("p{index:03}/AGENTS.md")), 1);
        }
        git(&repo, &["add", "."]);
        let mode = ClaudeInstructionMode::OrAgentsMd;
        let none = BTreeSet::new();
        let capped =
            build_instruction_inventory(&repo, &none, mode, InventoryPaths::Collect).unwrap();
        assert_eq!(capped.files.entries[0].relative_path, "CLAUDE.md");
        assert!(capped.files.entries.len() <= MAX_ENTRIES);
        assert!(serde_json::to_vec(&capped).unwrap().len() <= MAX_BLOCK_BYTES);
        assert!(!capped.files.complete);
        assert!(
            capped
                .files
                .partial_reasons
                .contains(&PartialReason::SizeCap)
                || capped
                    .files
                    .partial_reasons
                    .contains(&PartialReason::FileCap)
        );

        // 200 entries with 512-character paths, every reason: still in bounds.
        let long = format!("{}/AGENTS.md", "d".repeat(MAX_RELATIVE_PATH_CHARS - 10));
        assert!(sendable_relative_path(&long));
        let mut found = BTreeMap::new();
        for index in 0..MAX_ENTRIES {
            found.insert(format!("{index:03}{}", &long[3..]), u64::MAX >> 11);
        }
        let mut reasons = BTreeSet::new();
        let far = Instant::now() + Duration::from_secs(60);
        let kept = capped_entries(found.into_iter(), 0, |_| false, far, &mut reasons);
        assert_eq!(
            reasons.into_iter().collect::<Vec<_>>(),
            vec![PartialReason::SizeCap]
        );
        let worst = InstructionInventory {
            started_at_root: false,
            claude_mode: ClaudeInstructionMode::AndAgentsMd,
            files: InstructionInventoryFiles {
                complete: false,
                partial_reasons: vec![
                    PartialReason::FileCap,
                    PartialReason::SizeCap,
                    PartialReason::TimeBudget,
                    PartialReason::StatError,
                    PartialReason::GitFailed,
                    PartialReason::PathsWithheld,
                ],
                entries: kept,
            },
        };
        assert!(serde_json::to_vec(&worst).unwrap().len() <= MAX_BLOCK_BYTES);
        fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn mode_reads_named_settings_and_never_collapses_failures() {
        let dir = test_scratch::private_dir("ottto-instruction-mode");
        let file = |name: &str, body: &str| {
            let path = dir.join(name);
            fs::write(&path, body).unwrap();
            path
        };
        let options = |id: &str, options: &str| {
            format!(r#"{{"pluginConfigs":{{"{id}":{{"options":{options}}}}}}}"#)
        };
        let missing = dir.join("missing.json");
        let and = file(
            "and.json",
            &options(
                "agents-md@builtin",
                r#"{"instructionFiles":"claude-md-and-agents-md"}"#,
            ),
        );
        let or = file(
            "or.json",
            &options(
                "cc-plugin-agents-md@builtin",
                r#"{"instructionFiles":"claude-md-or-agents-md"}"#,
            ),
        );
        let legacy = file(
            "legacy.json",
            &options("agents-md@builtin", r#"{"projectInstructions":"both"}"#),
        );
        let legacy_with_new = file(
            "legacy-new.json",
            &options(
                "agents-md@builtin",
                r#"{"instructionFiles":"claude-md-or-agents-md","projectInstructions":"claude"}"#,
            ),
        );
        let other_value = file(
            "other.json",
            &options("agents-md@builtin", r#"{"instructionFiles":"claude-md"}"#),
        );
        let disabled = file(
            "disabled.json",
            r#"{"enabledPlugins":{"agents-md@builtin":false}}"#,
        );
        let unrelated = file(
            "unrelated.json",
            r#"{"model":"opus","pluginConfigs":{"x@y":{"options":{}}}}"#,
        );
        let malformed = file("malformed.json", "{\"pluginConfigs\":");
        let directory = dir.join("directory.json");
        fs::create_dir(&directory).unwrap();
        use ClaudeInstructionMode::*;
        for (files, expected) in [
            (vec![&missing], OrAgentsMd),
            (vec![&unrelated, &missing], OrAgentsMd),
            (vec![&and], AndAgentsMd),
            (vec![&or, &missing], OrAgentsMd),
            (vec![&and, &or], Unknown),
            (vec![&legacy], Unknown),
            (vec![&legacy_with_new], Unknown),
            (vec![&other_value], Unknown),
            (vec![&disabled], Unknown),
            (vec![&malformed, &and], Unknown),
            (vec![&directory], Unknown),
        ] {
            let paths: Vec<&Path> = files.iter().map(|path| path.as_path()).collect();
            assert_eq!(resolve_claude_mode(&paths), expected, "{files:?}");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    /// Resource cost on real checkouts: `OTTTO_D5_MEASURE_REPOS` is a
    /// colon-separated list of repository roots. Prints CPU (self + git
    /// children), wall, peak RSS and block bytes; collects nothing else.
    #[test]
    #[ignore = "measures real checkouts named in OTTTO_D5_MEASURE_REPOS"]
    fn measure_instruction_inventory() {
        fn usage(who: libc::c_int) -> libc::rusage {
            let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
            assert_eq!(unsafe { libc::getrusage(who, usage.as_mut_ptr()) }, 0);
            unsafe { usage.assume_init() }
        }
        fn cpu_us(usage: &libc::rusage) -> i64 {
            // i32 on macOS, i64 on Linux.
            #[allow(clippy::useless_conversion)]
            let micros = |time: libc::timeval| time.tv_sec * 1_000_000 + i64::from(time.tv_usec);
            micros(usage.ru_utime) + micros(usage.ru_stime)
        }
        let repos = std::env::var("OTTTO_D5_MEASURE_REPOS").unwrap_or_default();
        let observed = BTreeSet::new();
        for repo in repos.split(':').filter(|repo| !repo.is_empty()) {
            for run in ["cold", "warm1", "warm2"] {
                let (self_before, child_before) =
                    (usage(libc::RUSAGE_SELF), usage(libc::RUSAGE_CHILDREN));
                let started = Instant::now();
                let inventory = build_instruction_inventory(
                    Path::new(repo),
                    &observed,
                    ClaudeInstructionMode::OrAgentsMd,
                    InventoryPaths::Collect,
                )
                .unwrap();
                let wall_us = started.elapsed().as_micros();
                let (self_after, child_after) =
                    (usage(libc::RUSAGE_SELF), usage(libc::RUSAGE_CHILDREN));
                println!(
                    "D5_MEASURE {}",
                    serde_json::json!({
                        "repo": Path::new(repo).file_name().and_then(|name| name.to_str()),
                        "run": run,
                        "wall_us": wall_us,
                        "self_cpu_us": cpu_us(&self_after) - cpu_us(&self_before),
                        "git_cpu_us": cpu_us(&child_after) - cpu_us(&child_before),
                        "peak_rss_bytes": self_after.ru_maxrss,
                        "block_bytes": serde_json::to_vec(&inventory).unwrap().len(),
                        "entries": inventory.files.entries.len(),
                        "partial_reasons": inventory.files.partial_reasons,
                    })
                );
            }
        }
    }
}
