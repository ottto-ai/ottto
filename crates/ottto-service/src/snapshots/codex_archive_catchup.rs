#[derive(Clone, Debug, Default)]
pub(crate) struct Pass {
    pub started: bool,
    pub cpu: u64,
    pub work: u64,
    pub power: bool,
    pub prep_after: Option<String>,
}
crate::heap_layout_bound::fields!(Pass; started, cpu, work, power, prep_after);
impl Pass {
    pub fn prepare(&mut self) {
        let prep_after = self.prep_after.take();
        *self = Self {
            prep_after,
            ..Self::default()
        };
        self.power = crate::snapshot_sync::archive_power_ready();
    }
    pub fn ready(&self, remaining: u64) -> bool {
        self.power
            && crate::snapshot_sync::archive_acquisition_power_ready(self.power)
            && self.cpu < 30_000_000
            && remaining > 0
            && crate::snapshot_sync::archive_work_ready(self.work)
    }
    pub fn observe(&mut self, cpu: Option<u64>, wall: u64) {
        if self.started || cpu.is_none() {
            self.cpu = cpu.map_or(u64::MAX, |cpu| self.cpu.saturating_add(cpu));
        }
        self.work = self.work.saturating_add(wall);
    }
}

use super::*;
use codex_compressed_input::{HeaderRead, HeaderWork};

/// A classification is never an ACK, ownership proof or permission to retire
/// another carrier. `Deferred` keeps selection debt in the existing queue.
pub(super) enum Admission {
    Read,
    Held,
    Deferred,
}

impl ScanIndex {
    /// Custody is negative scope only; acquisition and ACK remain independent.
    pub(super) fn classify_archive(
        &mut self,
        candidate: &CandidateFile,
        file: &File,
        inventory: Option<&codex_file_join::HeaderInventory>,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
        budget: &mut sampled_scan::codex_cursor::PageBudget,
    ) -> Result<Admission> {
        let key = local_index_key(&candidate.path);
        let ids = codex_session_id_candidates_from_path(&candidate.path);
        if self
            .files
            .get(&key)
            .is_some_and(|entry| entry.codex_compressed_hold.is_some())
        {
            return Ok(Admission::Held);
        }
        let prior = self
            .files
            .get(&key)
            .and_then(|e| e.archive.as_deref())
            .filter(|a| a.matches(file));
        if prior.is_some_and(|a| a.quiet(file)) {
            return Ok(Admission::Held);
        }
        let retry =
            prior.is_some_and(|a| matches!(a.disposition, ArchiveDisposition::Pending { .. }));
        let family = inventory.is_some_and(|i| {
            i.headers
                .iter()
                .any(|h| h.candidate.path != candidate.path && ids.contains(&h.owner))
        }) || self.traversal.as_ref().is_some_and(|t| {
            t.codex_rollout_paths.iter().any(|p| {
                p != &key
                    && codex_archive_path(Path::new(p))
                    && !inventory
                        .and_then(|i| i.owner_for_path(Path::new(p)))
                        .is_some_and(|owner| !ids.iter().any(|id| id == owner))
                    && codex_session_id_candidates_from_path(Path::new(p))
                        .iter()
                        .any(|id| ids.contains(id))
            })
        });
        let old_carrier = ids.iter().any(|id| {
            let owner = codex_protected_owner(id);
            self.codex_counting_tombstones.contains_key(&owner)
                || self.codex_counting_moved_evidence.contains_key(&owner)
                || self.files.iter().any(|(path, e)| {
                    path != &key
                        && (e.codex_protected_owner.as_ref() == Some(&owner)
                            || (!codex_archive_path(Path::new(path))
                                && codex_session_id_candidates_from_path(Path::new(path))
                                    .contains(id)))
                })
        });
        if family || (!retry && old_carrier) {
            self.hold_compressed(
                &candidate.path,
                ids.iter().cloned().collect(),
                if family {
                    CodexZstCause::FamilyUnproven
                } else {
                    CodexZstCause::ArchiveEquivalenceUnproven
                },
            );
            return Ok(Admission::Held);
        }
        // A partial/old intake census is negative scope only. New archive
        // acquisition waits until every configured root has been inventoried.
        if inventory.is_some_and(|inventory| !inventory.complete) {
            return Ok(Admission::Deferred);
        }
        if !self
            .archive_pass
            .ready(budget.singleton_remaining(sampled_scan::codex_cursor::Limits::current()))
        {
            return Ok(Admission::Deferred);
        }
        // An unchanged pending object already has a validated header. The
        // retained hit (or bounded lost-copy retry) is resolved by the parser.
        if retry {
            return Ok(Admission::Read);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            let mut bytes = [0; 18];
            let n = file.read_at(&mut bytes, 0)?;
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_frame_header",
                "codex",
                &BTreeMap::from([("codex_zst_frame_header_bytes", n as u64)]),
            );
            if let Some(length) = zstd::zstd_safe::get_frame_content_size(&bytes[..n])
                .ok()
                .flatten()
            {
                if length > codex_compressed_input::FIRST_READ_DECODED_LIMIT {
                    self.hold_compressed(
                        &candidate.path,
                        ids.iter().cloned().collect(),
                        CodexZstCause::CatchupTooLarge,
                    );
                    crate::local_resource_diagnostics::traversal_point(
                        "codex_zst_catchup_too_large",
                        "codex",
                        &BTreeMap::from([("codex_zst_held_declared_bytes", length)]),
                    );
                    return Ok(Admission::Held);
                }
            }
        }
        if budget.singleton_remaining(sampled_scan::codex_cursor::Limits::current())
            < 2 * codex_file_join::MAX_HEADER_BYTES as u64
        {
            return Ok(Admission::Deferred);
        }
        if !self
            .archive_pass
            .ready(budget.singleton_remaining(sampled_scan::codex_cursor::Limits::current()))
        {
            return Ok(Admission::Deferred);
        }
        crate::context_composition::set_utility_qos();
        let mut work = HeaderWork {
            allowed: true,
            ..HeaderWork::default()
        };
        let header = self.inventory_archive_header(candidate, cache, &mut work);
        self.archive_pass.started |= work.decoded_bytes > 0;
        budget.charge(false, work.decoded_bytes);
        match header? {
            HeaderRead::Deferred => Ok(Admission::Deferred),
            HeaderRead::Validated(_) | HeaderRead::BoundReached => Ok(Admission::Read),
        }
    }
}

/// Order the supported header population globally before selecting a page.
/// Each archive stat is cached on its queued path; comparisons do no I/O and
/// unstable sorting needs no roster-sized sort scratch. Larger populations
/// retain the existing bounded inventory/custody behavior, never an unbounded
/// prep walk. Plain work always sorts ahead of archive backlog.
pub(super) fn order_pending(pending: &mut VecDeque<ScanTraversalPath>) {
    let quantum = codex_file_join::MAX_HEADER_FILES;
    let mut checks = 0_u64;
    for (position, member) in pending.iter_mut().take(quantum).enumerate() {
        let modified = if codex_archive_path(&member.path) {
            match member.order_modified {
                Some((modified, _)) => modified,
                None => {
                    checks += 1;
                    fs::symlink_metadata(&member.path)
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::UNIX_EPOCH)
                }
            }
        } else {
            std::time::UNIX_EPOCH
        };
        member.order_modified = Some((modified, position));
    }
    if pending.len() <= quantum {
        let compare = |a: &ScanTraversalPath, b: &ScanTraversalPath| {
            let a_archive = codex_archive_path(&a.path);
            let b_archive = codex_archive_path(&b.path);
            a_archive.cmp(&b_archive).then_with(|| {
                if a_archive {
                    std::cmp::Reverse(a.order_modified.map(|(mtime, _)| mtime))
                        .cmp(&std::cmp::Reverse(b.order_modified.map(|(mtime, _)| mtime)))
                        .then_with(|| a.path.cmp(&b.path))
                } else {
                    a.order_modified
                        .map(|(_, position)| position)
                        .cmp(&b.order_modified.map(|(_, position)| position))
                }
            })
        };
        if !pending
            .iter()
            .zip(pending.iter().skip(1))
            .all(|(a, b)| compare(a, b) != std::cmp::Ordering::Greater)
        {
            pending.make_contiguous().sort_unstable_by(compare);
        }
    }
    crate::local_resource_diagnostics::traversal_point(
        "codex_zst_order_metadata",
        "codex",
        &BTreeMap::from([("codex_zst_order_metadata_checks", checks)]),
    );
}
