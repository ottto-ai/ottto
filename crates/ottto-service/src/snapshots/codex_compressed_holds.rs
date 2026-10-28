//! Pre-discovery custody. Holds grant no membership, acquisition or ACK.
use super::*;

pub(super) fn parent_unbound(
    parent: &str,
    census: CodexParentCensus<'_>,
    metadata: &CodexTitleMetadata,
) -> bool {
    let parent = resolve_codex_identity(parent);
    let mut archive = false;
    for key in census.paths {
        let path = Path::new(key);
        let compressed = is_compressed_codex_rollout(Some(path), None);
        let logical = if compressed {
            path.with_extension("")
        } else {
            path.to_owned()
        };
        if codex_session_id_candidates_from_path(&logical).contains(&parent) {
            if !compressed {
                return false;
            }
            archive = true;
        }
    }
    if archive {
        return true;
    }
    // State metadata can locate a compressed parent before archive discovery.
    // Only lstat: this cannot create an archive candidate or decoder permission.
    metadata
        .state_threads
        .get(&parent)
        .and_then(|thread| thread.rollout_path.as_deref())
        .is_some_and(|key| {
            let path = Path::new(key);
            let compressed = is_compressed_codex_rollout(Some(path), None);
            let plain = if compressed {
                path.with_extension("")
            } else {
                path.to_owned()
            };
            let archive = if compressed {
                path.to_owned()
            } else {
                PathBuf::from(format!("{key}.zst"))
            };
            census
                .scan_roots
                .iter()
                .any(|root| archive.starts_with(root))
                && fs::symlink_metadata(plain).is_err()
                && fs::symlink_metadata(archive)
                    .is_ok_and(|stat| stat.is_file() && !stat.file_type().is_symlink())
        })
}

impl ScanIndex {
    pub(super) fn hold_compressed(
        &mut self,
        path: &Path,
        owners: BTreeSet<String>,
        cause: CodexZstCause,
    ) {
        let key = local_index_key(path);
        let entry = self.files.entry(key.clone()).or_default();
        // Parent custody is the more specific reason when a family also holds.
        if entry.codex_compressed_hold != Some(CodexZstCause::ParentLedgerUnbound) {
            entry.codex_compressed_hold = Some(cause);
        }
        if let Some(archive) = entry.archive.as_mut() {
            archive.disposition = ArchiveDisposition::Held {
                cause: entry.codex_compressed_hold.expect("hold set"),
            };
        }
        self.codex_state_only_blocked_session_ids
            .extend(owners.iter().cloned());
        self.extend_codex_blocked_attribution(&key, owners);
        crate::local_resource_diagnostics::codex_zst_held(cause);
    }
}

impl codex_file_join::HeaderInventory {
    pub(super) fn hold_compressed_families(&mut self, index: &mut ScanIndex) {
        let mut families = BTreeMap::<String, (usize, bool)>::new();
        for header in &self.headers {
            let (members, compressed) = families.entry(header.owner.clone()).or_default();
            *members += 1;
            *compressed |= is_compressed_codex_rollout(Some(&header.candidate.path), None);
        }
        for (key, owners) in &index.codex_state_only_blocked_by_file {
            if index
                .files
                .get(key)
                .is_some_and(|e| e.codex_compressed_hold == Some(CodexZstCause::FamilyUnproven))
            {
                for owner in owners {
                    families.insert(owner.clone(), (2, true));
                }
            }
        }
        for header in &self.headers {
            let (members, compressed) = families[header.owner.as_str()];
            if members > 1 && compressed {
                self.held_owners.insert(header.owner.clone());
                self.held_archives
                    .insert(local_index_key(&header.candidate.path));
                index.hold_compressed(
                    &header.candidate.path,
                    BTreeSet::from([header.owner.clone()]),
                    CodexZstCause::FamilyUnproven,
                );
            }
        }
    }
}
