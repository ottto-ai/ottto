//! Transcript roots are registration metadata, never account evidence.
use crate::snapshots::SnapshotSource;
use anyhow::{Context, Result};
use ottto_core::FileClaudeConfigSlotSettingsStore;
use std::path::{Path, PathBuf};

pub(crate) fn scan_roots(
    source: SnapshotSource,
    home: &Path,
    codex_homes: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let claude_homes = if source == SnapshotSource::ClaudeCode {
        FileClaudeConfigSlotSettingsStore::default()
            .registered_config_dirs()
            .context("read registered Claude transcript roots")?
    } else {
        Vec::new()
    };
    Ok(compose_roots(source, home, codex_homes, &claude_homes))
}

fn compose_roots(
    source: SnapshotSource,
    home: &Path,
    codex_homes: &[PathBuf],
    claude_homes: &[PathBuf],
) -> Vec<PathBuf> {
    let mut roots = source.default_roots(home);
    let extras = match source {
        SnapshotSource::Codex => codex_homes
            .iter()
            .flat_map(|home| [home.join("sessions"), home.join("archived_sessions")])
            .collect::<Vec<_>>(),
        SnapshotSource::ClaudeCode => claude_homes
            .iter()
            .map(|home| home.join("projects"))
            .collect(),
        SnapshotSource::Pi => Vec::new(),
    };
    for root in extras {
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    // Registration order is not collection authority. A reordered registry
    // with the same paths must not restart a traversal or replace the watcher.
    if source == SnapshotSource::ClaudeCode {
        roots.sort();
    }
    roots
}

pub(crate) fn watcher_roots(home: &Path) -> Result<Vec<(SnapshotSource, PathBuf)>> {
    [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .map(|source| {
        Ok(scan_roots(source, home, &[])?
            .into_iter()
            .map(|root| (source, root))
            .collect::<Vec<_>>())
    })
    .collect::<Result<Vec<_>>>()
    .map(|roots| roots.into_iter().flatten().collect())
}

pub(crate) fn validate_claude_roots(home: &Path, expected: &[PathBuf]) -> Result<()> {
    validate_claude_roots_at(
        home,
        expected,
        &FileClaudeConfigSlotSettingsStore::default(),
    )
}

fn validate_claude_roots_at(
    home: &Path,
    expected: &[PathBuf],
    store: &FileClaudeConfigSlotSettingsStore,
) -> Result<()> {
    let current = compose_roots(
        SnapshotSource::ClaudeCode,
        home,
        &[],
        &store.registered_config_dirs()?,
    );
    anyhow::ensure!(
        current == expected,
        "registered Claude transcript roots changed during scan"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::{scan_source_roots, ScanIndex};
    use crate::test_scratch::ScratchDir;
    use serde_json::json;
    use std::fs;

    fn registered_roots(store: &FileClaudeConfigSlotSettingsStore, home: &Path) -> Vec<PathBuf> {
        compose_roots(
            SnapshotSource::ClaudeCode,
            home,
            &[],
            &store.registered_config_dirs().unwrap(),
        )
    }

    fn write_session(root: &Path, id: &str, tokens: u64) {
        fs::create_dir_all(root.join("project")).unwrap();
        let record = json!({
            "type": "assistant", "sessionId": id,
            "uuid": format!("record-{id}"), "requestId": format!("req-{id}"),
            "timestamp": "2026-10-07T12:00:01Z",
            "message": {"id": format!("msg-{id}"), "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": tokens, "output_tokens": 2}}
        });
        fs::write(
            root.join("project").join(format!("{id}.jsonl")),
            format!("{record}\n"),
        )
        .unwrap();
    }

    #[test]
    fn registered_claude_folders_include_default_once_without_account_inputs() {
        let home = Path::new("/synthetic/user");
        let slots = [
            home.join(".claude"),
            home.join("slot-a"),
            home.join("slot-a"),
            home.join("slot-b"),
        ];
        assert_eq!(
            compose_roots(SnapshotSource::ClaudeCode, home, &[], &slots),
            [
                home.join(".claude/projects"),
                home.join("slot-a/projects"),
                home.join("slot-b/projects")
            ]
        );
        assert_eq!(
            compose_roots(SnapshotSource::Codex, home, &[], &slots),
            SnapshotSource::Codex.default_roots(home)
        );
    }

    #[test]
    fn registered_roots_use_normal_import_and_restart_without_account_assignment() {
        let scratch = ScratchDir::new("claude-registered-import");
        let home = scratch.join("home");
        let store = FileClaudeConfigSlotSettingsStore::new(scratch.join("slots.json"));
        store
            .register_path(1, home.join("slot-a").to_string_lossy().into_owned())
            .unwrap();
        store
            .register_path(1, home.join("slot-b").to_string_lossy().into_owned())
            .unwrap();
        let roots = registered_roots(&store, &home);
        for (i, root) in roots.iter().enumerate() {
            write_session(root, &format!("session-{i}"), 10 * (i as u64 + 1));
        }
        let mut index = ScanIndex::default();
        let imported = scan_source_roots(
            SnapshotSource::ClaudeCode,
            &roots,
            &mut index,
            "2026-10-07T12:01:00Z",
            30,
        )
        .unwrap();
        assert!(imported.census_complete);
        assert_eq!(imported.snapshots.len(), 3);
        assert_eq!(
            imported
                .snapshots
                .iter()
                .map(|item| item.input_tokens)
                .sum::<u64>(),
            60
        );
        assert!(imported
            .snapshots
            .iter()
            .flat_map(|item| &item.model_usage)
            .all(|row| row.account_identifier_hash.is_none()));
        // Restart uses the ordinary persisted index, not a folder-specific cursor.
        let index_path = scratch.join("index.json");
        index.save(&index_path).unwrap();
        let mut restarted = ScanIndex::load(&index_path).unwrap();
        let repeated = scan_source_roots(
            SnapshotSource::ClaudeCode,
            &roots,
            &mut restarted,
            "2026-10-07T12:02:00Z",
            30,
        )
        .unwrap();
        assert!(repeated.census_complete);
        assert!(repeated.snapshots.is_empty());
        let first = &roots[0];
        write_session(first, "session-0", 15);
        let changed = scan_source_roots(
            SnapshotSource::ClaudeCode,
            &roots,
            &mut restarted,
            "2026-10-07T12:03:00Z",
            30,
        )
        .unwrap();
        assert_eq!(changed.snapshots.len(), 1);
        assert_eq!(changed.snapshots[0].input_tokens, 15);
    }

    #[test]
    fn registration_add_remove_repoint_and_order_change_update_shared_roots() {
        let scratch = ScratchDir::new("claude-registration-lifecycle");
        let home = scratch.join("home");
        let path = scratch.join("slots.json");
        let store = FileClaudeConfigSlotSettingsStore::new(&path);
        store
            .register_path(1, home.join("slot-a").to_string_lossy().into_owned())
            .unwrap();
        let before = registered_roots(&store, &home);
        validate_claude_roots_at(&home, &before, &store).unwrap();
        store
            .register_path(1, home.join("slot-b").to_string_lossy().into_owned())
            .unwrap();
        let added = registered_roots(&store, &home);
        assert!(validate_claude_roots_at(&home, &before, &store).is_err());
        assert_eq!(added.len(), before.len() + 1);
        let mut registry: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        registry["registered_slots"]
            .as_array_mut()
            .unwrap()
            .reverse();
        fs::write(&path, serde_json::to_vec(&registry).unwrap()).unwrap();
        assert_eq!(registered_roots(&store, &home), added);
        validate_claude_roots_at(&home, &added, &store).unwrap();
        registry["registered_slots"].as_array_mut().unwrap().pop();
        registry["registered_slots"][0]["config_dir"] =
            json!(home.join("repointed").to_string_lossy());
        fs::write(&path, serde_json::to_vec(&registry).unwrap()).unwrap();
        let current = registered_roots(&store, &home);
        assert_eq!(
            current,
            compose_roots(
                SnapshotSource::ClaudeCode,
                &home,
                &[],
                &[home.join("repointed")]
            )
        );
        assert_ne!(before, current);
        assert!(validate_claude_roots_at(&home, &added, &store).is_err());
        assert!(!current.contains(&home.join("slot-b/projects")));
        fs::write(&path, b"invalid JSON").unwrap();
        assert!(store.registered_config_dirs().is_err());
        assert!(validate_claude_roots_at(&home, &current, &store).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_registered_folder_does_not_hide_healthy_sessions_or_claim_complete() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = ScratchDir::new("claude-root-permissions");
        let home = scratch.join("home");
        let roots = compose_roots(
            SnapshotSource::ClaudeCode,
            &home,
            &[],
            &[home.join("blocked")],
        );
        for root in &roots {
            write_session(
                root,
                if root.starts_with(home.join("blocked")) {
                    "blocked"
                } else {
                    "healthy"
                },
                9,
            );
        }
        let blocked = home.join("blocked/projects");
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
        let scanned = scan_source_roots(
            SnapshotSource::ClaudeCode,
            &roots,
            &mut ScanIndex::default(),
            "2026-10-07T12:01:00Z",
            30,
        );
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
        let scanned = scanned.unwrap();
        assert!(!scanned.census_complete);
        assert!(scanned.unreadable_path_count > 0);
        assert_eq!(scanned.snapshots.len(), 1);
        assert_eq!(scanned.snapshots[0].source_session_id, "healthy");
    }

    #[test]
    fn duplicate_root_keeps_existing_native_entity_and_ack_identity() {
        let scratch = ScratchDir::new("claude-root-alias");
        let home = scratch.join("home");
        let root = home.join(".claude/projects");
        write_session(&root, "same-session", 7);
        let roots = compose_roots(
            SnapshotSource::ClaudeCode,
            &home,
            &[],
            &[home.join(".claude"), home.join(".claude")],
        );
        let mut index = ScanIndex::default();
        let imported = scan_source_roots(
            SnapshotSource::ClaudeCode,
            &roots,
            &mut index,
            "2026-10-07T12:01:00Z",
            30,
        )
        .unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(imported.snapshots.len(), 1);
        assert_eq!(imported.snapshots[0].source_session_id, "same-session");
        assert_eq!(imported.snapshots[0].input_tokens, 7);
    }

    #[test]
    fn same_id_files_keep_existing_logical_identity_without_summing_or_selecting() {
        let scratch = ScratchDir::new("claude-existing-copy-boundary");
        let home = scratch.join("home");
        let roots = compose_roots(SnapshotSource::ClaudeCode, &home, &[], &[home.join("slot")]);
        // This test preserves the existing whole-body wire boundary. It does
        // not introduce copied-history reconciliation or a folder winner.
        write_session(&roots[0], "same-session", 7);
        write_session(&roots[1], "same-session", 11);
        let imported = scan_source_roots(
            SnapshotSource::ClaudeCode,
            &roots,
            &mut ScanIndex::default(),
            "2026-10-07T12:01:00Z",
            30,
        )
        .unwrap();
        assert_eq!(imported.snapshots.len(), 2);
        assert!(imported
            .snapshots
            .iter()
            .all(|item| item.source_session_id == "same-session"));
        assert_eq!(
            imported
                .snapshots
                .iter()
                .map(|item| item.input_tokens)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([7, 11])
        );
        // The accepted entity remains (source, Mac, session ID); existing
        // duplicate-body conflicts/CAS/ACK decide these unchanged wire shapes.
        assert!(imported
            .snapshots
            .iter()
            .all(|item| item.input_tokens != 18));
    }
}
