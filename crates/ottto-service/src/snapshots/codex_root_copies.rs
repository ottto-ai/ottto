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

pub(super) fn copy_locator<'a>(
    root: &Path,
    id: &str,
    row: &'a CodexStateThread,
) -> Option<&'a Path> {
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
            (
                row.tokens_used,
                row.updated_at.as_deref().and_then(rfc3339_unix_nanos),
                &row.rollout_path,
            ) > (
                prior.tokens_used,
                prior.updated_at.as_deref().and_then(rfc3339_unix_nanos),
                &prior.rollout_path,
            )
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
        // A dominating maximum does not prove all older copies agree:
        // (1000,100) dominates both (500,80) and (600,70), but those two
        // disagree on progress order. Home sort order must never hide it.
        let incompatible = metadata.root_sidecars.values().any(|sidecar| {
            sidecar.extents.get(id).is_some_and(|prior| {
                !((extent.next_byte_offset >= prior.next_byte_offset
                    && extent.next_ordinal >= prior.next_ordinal)
                    || (extent.next_byte_offset <= prior.next_byte_offset
                        && extent.next_ordinal <= prior.next_ordinal))
            })
        });
        if incompatible {
            metadata.rollout_extents.remove(id);
            metadata.identity_conflicts.insert(id.clone());
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
