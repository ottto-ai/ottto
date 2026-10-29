//! Production reader adapter; synchronous legacy saves retain the full semantic CAS.
use super::*;

pub(super) fn scan_index_storage_binding(path: &Path) -> Option<scan_index_persistence::Binding> {
    use scan_index_persistence::{Binding, Source};
    let namespace = path.parent()?.file_name()?.to_str()?;
    if namespace.len() != 64 || !namespace.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let source = if name.starts_with("claude_code-") {
        Source::Claude
    } else if name.starts_with("codex") {
        Source::Codex
    } else if name.starts_with("pi-") {
        Source::Pi
    } else {
        return None;
    };
    Some(Binding {
        source,
        namespace_hash: namespace.into(),
    })
}
pub(super) fn read_scan_index_representation(
    path: &Path,
    stage: &str,
    source: &'static str,
    cap: Option<usize>,
) -> Result<ScanIndex> {
    let Some(binding) = scan_index_storage_binding(path) else {
        return match cap {
            Some(cap) => claude_request_census::decode_bounded_index(
                &crate::snapshot_retry::read_state(path, cap)?,
            ),
            None => lenient_decode::read_file(File::open(path)?, stage, source).map_err(Into::into),
        };
    };
    let store =
        scan_index_persistence::LockedStore::new(path, binding.clone(), lenient_decode::FIELDS)?;
    let (mut index, mut root) = match open_storage(&store, source)? {
        scan_index_persistence::Opened::Missing(root) => {
            debug_assert!(root.generation().is_none());
            return Err(anyhow::anyhow!("scan_index_root_disappeared"));
        }
        scan_index_persistence::Opened::Legacy(file, root) => {
            let index = match cap {
                Some(cap) => {
                    if file.metadata()?.len() > cap as u64 {
                        return Err(anyhow::anyhow!("scan_index_read_limit"));
                    }
                    let mut bytes = Vec::new();
                    std::io::Read::take(file, cap as u64 + 1).read_to_end(&mut bytes)?;
                    if bytes.len() > cap {
                        return Err(anyhow::anyhow!("scan_index_read_limit"));
                    }
                    claude_request_census::decode_bounded_index(&bytes)?
                }
                None => lenient_decode::read_file(file, stage, source)?,
            };
            (index, root)
        }
        scan_index_persistence::Opened::Partial(partial, root) => (
            lenient_decode::read_partial_persistence(partial, stage, source, cap)?,
            root,
        ),
        scan_index_persistence::Opened::Sharded(mut reader, root) => {
            // Keep the existing bounded CAS node/depth/census admission. The
            // bounded branch may materialize only its ALREADY admitted byte cap.
            let index = if let Some(cap) = cap {
                if reader.seek(std::io::SeekFrom::End(0))? > cap as u64 {
                    return Err(anyhow::anyhow!("scan_index_read_limit"));
                }
                reader.seek(std::io::SeekFrom::Start(0))?;
                let mut bytes = Vec::new();
                std::io::Read::take(reader, cap as u64 + 1).read_to_end(&mut bytes)?;
                if bytes.len() > cap {
                    return Err(anyhow::anyhow!("scan_index_read_limit"));
                }
                claude_request_census::decode_bounded_index(&bytes)
            } else {
                lenient_decode::read(BufReader::new(reader), stage, source).map_err(Into::into)
            }
            .map_err(storage_decode_error)?;
            (index, root)
        }
    };
    // Cross-field held scopes can freeze a map after its isolated validation.
    // Keep the raw debt, withhold the WHOLE map, and count semantic unavailability.
    let fields = [
        scan_index_persistence::Field::AccountPending,
        scan_index_persistence::Field::UsagePending,
        scan_index_persistence::Field::RequestCensus,
    ];
    let mut semantic_stats = [[0; 6]; 3];
    for (i, field) in fields.into_iter().enumerate() {
        if !root.is_legacy()
            && index.persistence_unavailable[i].is_none()
            && index.decode_holds.contains_field(field.name())
        {
            index.persistence_unavailable[i] = Some(scan_index_persistence::MapUnavailable {
                map: field,
                cause: scan_index_persistence::UnavailableCause::Decode,
            });
            semantic_stats[i][scan_index_persistence::UnavailableCause::Decode as usize] = 1;
        }
    }
    if semantic_stats.iter().flatten().any(|n| *n != 0) {
        crate::local_resource_diagnostics::scan_index_storage(source, 0, semantic_stats);
    }
    if !index.persistence_available() {
        root = root.unavailable();
    }
    // Root/binding, controls, claims and shared raw custody use one bounded
    // preflight BEFORE the additional baseline allocation. Never charge files.
    let mut budget = crate::source_rotation::PARKED_BUDGET;
    let fixed = root
        .retained_bytes()
        .and_then(|n| n.checked_add(binding.namespace_hash.capacity()))
        .and_then(|n| n.checked_add(std::mem::size_of_val(&index.persistence_root)))
        .and_then(|n| n.checked_add(std::mem::size_of_val(&index.persistence_unavailable)))
        .ok_or_else(|| anyhow::anyhow!("scan_index_storage_admission"))?;
    budget = budget
        .checked_sub(fixed)
        .ok_or_else(|| anyhow::anyhow!("scan_index_storage_admission"))?;
    index.persistence_controls = Some(lenient_decode::persistence_controls(&index, budget)?);
    index.persistence_root = Some((binding, root));
    Ok(index)
}

fn drain_stats(store: &scan_index_persistence::LockedStore, source: &'static str) {
    let stats = store.take_read_stats();
    crate::local_resource_diagnostics::scan_index_storage(
        source,
        stats.scanindex_orphan_init_discarded,
        stats.index_shard_unavailable,
    );
}
pub(super) fn open_storage(
    store: &scan_index_persistence::LockedStore,
    source: &'static str,
) -> Result<scan_index_persistence::Opened> {
    let result = store.open_with_map_validator(&mut lenient_decode::validate_persistence_map);
    drain_stats(store, source);
    result
}
pub(super) fn check_missing(path: &Path, source: &'static str) -> Result<()> {
    if let Some(binding) = scan_index_storage_binding(path) {
        if path.parent().is_some_and(Path::exists) {
            let _lock = CheckpointLock::acquire(path)?;
            let store =
                scan_index_persistence::LockedStore::new(path, binding, lenient_decode::FIELDS)?;
            anyhow::ensure!(
                matches!(
                    open_storage(&store, source)?,
                    scan_index_persistence::Opened::Missing(_)
                ),
                "scan_index_root_appeared_requires_reload"
            );
        }
    }
    Ok(())
}
pub(super) fn storage_decode_error(error: anyhow::Error) -> anyhow::Error {
    if matches!(
        error.downcast_ref::<lenient_decode::Error>(),
        Some(lenient_decode::Error::Refused(
            "schema_version" | "accepted-ledger version"
        ))
    ) {
        return error;
    }
    lenient_decode::Error::Refused("storage generation requires repair").into()
}
impl crate::heap_layout_bound::HeapLayoutBound for scan_index_persistence::Binding {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(self.namespace_hash.capacity())
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for scan_index_persistence::LoadedRoot {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(self.retained_bytes()?)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for scan_index_persistence::MapUnavailable {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, _: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        Some(())
    }
}
impl ScanIndex {
    pub(crate) fn persistence_available(&self) -> bool {
        self.persistence_unavailable.iter().all(Option::is_none)
    }
    pub(crate) fn require_persistence_available(&self) -> Result<()> {
        anyhow::ensure!(self.persistence_available(), "scan_index_map_unavailable");
        Ok(())
    }
}

pub(super) fn publish(
    store: &scan_index_persistence::LockedStore,
    expected: &scan_index_persistence::LoadedRoot,
    index: &ScanIndex,
) -> Result<scan_index_persistence::LoadedRoot> {
    index.require_persistence_available()?;
    let result = if scan_index_writer::ENABLED {
        scan_index_writer::publish(store, expected, index)
    } else {
        store.write_legacy(expected, index.generation, |out| {
            lenient_decode::write_index(out, index).map_err(Into::into)
        })
    };
    drain_stats(store, "unattributed");
    result
}

#[cfg(test)]
#[path = "scan_index_integration_tests.rs"]
mod tests;

pub(super) fn publish_at(
    path: &Path,
    index: &ScanIndex,
) -> Result<
    Option<(
        scan_index_persistence::Binding,
        scan_index_persistence::LoadedRoot,
    )>,
> {
    let Some(binding) = index
        .persistence_root
        .as_ref()
        .map(|(binding, _)| binding.clone())
        .or_else(|| scan_index_storage_binding(path))
    else {
        return Ok(None);
    };
    anyhow::ensure!(
        scan_index_storage_binding(path).as_ref() == Some(&binding),
        "scan_index_binding"
    );
    let store =
        scan_index_persistence::LockedStore::new(path, binding.clone(), lenient_decode::FIELDS)?;
    let expected = if let Some((_, expected)) = &index.persistence_root {
        expected.clone()
    } else {
        match open_storage(&store, "unattributed")? {
            scan_index_persistence::Opened::Missing(root)
            | scan_index_persistence::Opened::Legacy(_, root) => root,
            _ => return Err(anyhow::anyhow!("current_index_requires_reload")),
        }
    };
    publish(&store, &expected, index).map(|root| Some((binding, root)))
}
