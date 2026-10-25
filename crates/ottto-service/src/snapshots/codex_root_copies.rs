//! Reconcile provider metadata across homes without moving file-ownership proof.
use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct RootSidecar {
    pub threads: BTreeMap<String, CodexStateThread>,
    pub extents: BTreeMap<String, CodexRolloutExtent>,
}

// A copied provider row can reconstruct its millisecond creation time from a
// native clock rather than the original SQLite clock. Accept subsecond drift
// only with the same UUID, complete root-relative locator and coherent progress.
// Keep the precise clock in each home for the existing native ownership checks.
const COPY_CREATION_PRECISION_NANOS: i128 = 1_000_000_000;

fn copy_locator<'a>(root: &Path, id: &str, row: &'a CodexStateThread) -> Option<&'a Path> {
    let path = Path::new(row.rollout_path.as_deref()?);
    let relative = path.strip_prefix(root).ok()?;
    if !path.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        || !matches!(
            relative.components().next()?.as_os_str().to_str()?,
            "sessions" | "archived_sessions"
        )
        || !codex_identity_is_uuid_shaped(id)
        || !codex_session_id_candidates_from_path(path).contains(&id.to_string())
    {
        return None;
    }
    Some(relative)
}

fn compatible_copy(
    id: &str,
    left_root: &Path,
    left: &CodexStateThread,
    right_root: &Path,
    right: &CodexStateThread,
) -> bool {
    if left == right {
        return true;
    }
    if left.title != right.title || left.model != right.model || left.archived != right.archived {
        return false;
    }
    let Some(locator) = copy_locator(left_root, id, left) else {
        return false;
    };
    if copy_locator(right_root, id, right) != Some(locator) {
        return false;
    }
    let Some((left_created, right_created)) = left
        .created_at
        .as_deref()
        .and_then(rfc3339_unix_nanos)
        .zip(right.created_at.as_deref().and_then(rfc3339_unix_nanos))
    else {
        return false;
    };
    if (left_created - right_created).abs() >= COPY_CREATION_PRECISION_NANOS {
        return false;
    }
    let Some((left_updated, right_updated)) = left
        .updated_at
        .as_deref()
        .and_then(rfc3339_unix_nanos)
        .zip(right.updated_at.as_deref().and_then(rfc3339_unix_nanos))
    else {
        return false;
    };
    match left_updated.cmp(&right_updated) {
        Ordering::Less => left.tokens_used <= right.tokens_used,
        Ordering::Equal => left.tokens_used == right.tokens_used,
        Ordering::Greater => left.tokens_used >= right.tokens_used,
    }
}

pub(super) fn merge_threads(
    metadata: &mut CodexTitleMetadata,
    root: &Path,
    incoming: &BTreeMap<String, CodexStateThread>,
) {
    for (id, row) in incoming {
        if metadata.identity_conflicts.contains(id) {
            metadata.state_threads.remove(id);
            continue;
        }
        // Compare every physical copy, not just the selected row: tolerances
        // must not chain across three or more roots. A third root cannot clear
        // an identity conflict discovered by the first two.
        let incompatible = metadata
            .root_sidecars
            .iter()
            .find_map(|(prior_root, sidecar)| {
                let prior = sidecar.threads.get(id)?;
                (!compatible_copy(id, prior_root, prior, root, row)).then_some(prior)
            });
        if let Some(prior) = incompatible {
            metadata
                .local_diagnostics
                .identity_conflict_taxonomy
                .observe_state_cross_root(codex_state_thread_field_diffs(prior, row));
            metadata.identity_conflicts.insert(id.clone());
            metadata.state_threads.remove(id);
            continue;
        }
        let replace = metadata.state_threads.get(id).map_or(true, |prior| {
            (row.tokens_used, &row.updated_at, &row.rollout_path)
                > (prior.tokens_used, &prior.updated_at, &prior.rollout_path)
        });
        if replace {
            metadata.state_threads.insert(id.clone(), row.clone());
        }
    }
}

pub(super) fn merge_extents(
    metadata: &mut CodexTitleMetadata,
    incoming: &BTreeMap<String, CodexRolloutExtent>,
) {
    for (id, extent) in incoming {
        if metadata.identity_conflicts.contains(id) {
            metadata.rollout_extents.remove(id);
            continue;
        }
        let Some(prior) = metadata.rollout_extents.get(id).copied() else {
            metadata.rollout_extents.insert(id.clone(), *extent);
            continue;
        };
        if extent.next_byte_offset >= prior.next_byte_offset
            && extent.next_ordinal >= prior.next_ordinal
        {
            metadata.rollout_extents.insert(id.clone(), *extent);
        } else if extent.next_byte_offset > prior.next_byte_offset
            || extent.next_ordinal > prior.next_ordinal
        {
            metadata.rollout_extents.remove(id);
            metadata.identity_conflicts.insert(id.clone());
        }
        // A shorter, older copy is progress, not a different identity. These
        // maxima decorate metadata only; parser file proofs use RootSidecar.
    }
}

crate::heap_layout_bound::fields!(RootSidecar; threads, extents);

#[cfg(test)]
mod tests;

/// A cross-home group is admitted only as byte-for-byte prefixes of one
/// selected rollout. Read bounded chunks and revalidate both opened objects
/// every step; UUID/metadata agreement alone never authorizes dropping a file.
#[derive(Debug, Clone, Default)]
pub(super) struct CopyProof {
    pub winner: usize,
    pub member: usize,
    offset: u64,
}
impl CopyProof {
    pub fn new(members: &[CandidateFile]) -> Option<Self> {
        let winner = members
            .iter()
            .enumerate()
            .max_by_key(|(_, member)| (member.size_bytes, &member.path))?
            .0;
        Some(Self {
            winner,
            ..Self::default()
        })
    }

    /// `Ok(true)` means all prefixes were proved, `Err` preserves strict debt.
    pub fn step(
        &mut self,
        members: &[CandidateFile],
        allowance: &mut u64,
        charge: &mut u64,
    ) -> Result<bool> {
        if self.member >= members.len() {
            return Ok(true);
        }
        if self.member == self.winner {
            self.member += 1;
            return Ok(false);
        }
        let candidate = &members[self.member];
        let winner = &members[self.winner];
        let remaining = candidate
            .size_bytes
            .checked_sub(self.offset)
            .context("copy offset")?;
        let bytes = remaining.min(32 * 1024);
        anyhow::ensure!(
            bytes.saturating_mul(2).saturating_add(1) <= *allowance,
            "copy proof page budget exhausted"
        );
        // Reserve before I/O so divergent or unreadable copies are charged too.
        let reserved = bytes.saturating_mul(2).saturating_add(1);
        *allowance = allowance.saturating_sub(reserved);
        *charge = charge.saturating_add(reserved);
        let mut left = candidate.clone();
        let mut right = winner.clone();
        let mut a = open_candidate_file(SnapshotSource::Codex, &mut left)?;
        let mut b = open_candidate_file(SnapshotSource::Codex, &mut right)?;
        anyhow::ensure!(
            left.opened_object_identity == candidate.opened_object_identity
                && right.opened_object_identity == winner.opened_object_identity,
            "copy changed before proof"
        );
        a.seek(SeekFrom::Start(self.offset))?;
        b.seek(SeekFrom::Start(self.offset))?;
        let mut ab = [0_u8; 32 * 1024];
        let mut bb = [0_u8; 32 * 1024];
        a.read_exact(&mut ab[..bytes as usize])?;
        b.read_exact(&mut bb[..bytes as usize])?;
        anyhow::ensure!(
            ab[..bytes as usize] == bb[..bytes as usize],
            "divergent cross-home rollout"
        );
        anyhow::ensure!(
            opened_object_identity(SnapshotSource::Codex, &mut a)?
                == candidate.opened_object_identity
                && opened_object_identity(SnapshotSource::Codex, &mut b)?
                    == winner.opened_object_identity,
            "copy changed during proof"
        );
        self.offset += bytes;
        if self.offset == candidate.size_bytes {
            // A short file ending in a partial record is not a complete alias.
            if self.offset > 0 {
                a.seek(SeekFrom::Start(self.offset - 1))?;
                let mut last = [0];
                a.read_exact(&mut last)?;
                anyhow::ensure!(last == [b'\n'], "incomplete copy record");
            }
            self.member += 1;
            self.offset = 0;
        }
        Ok(false)
    }
}
crate::heap_layout_bound::fields!(CopyProof; winner, member, offset);
