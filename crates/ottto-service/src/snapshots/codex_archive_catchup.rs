use super::*;
use codex_compressed_input::ArchiveEvidence;

#[derive(Default)]
pub(super) struct Pass {
    pub started: bool,
    pub cpu: u64,
    pub work: u64,
    pub power: bool,
    pub seen: BTreeSet<String>,
    pub aliases: BTreeSet<String>,
}
crate::heap_layout_bound::fields!(Pass; started, cpu, work, power, seen, aliases);
impl Pass {
    pub fn prepare(&mut self, index: &ScanIndex) {
        self.power = crate::snapshot_sync::archive_power_ready();
        self.seen = index
            .files
            .iter()
            .filter(|(_, e)| {
                e.last_snapshot_fingerprint.is_some()
                    || e.archive.as_ref().map_or(true, |a| {
                        !matches!(a.disposition, ArchiveDisposition::HeaderValidated)
                    })
            })
            .flat_map(|(p, _)| codex_session_id_candidates_from_path(Path::new(p)))
            .collect();
        self.aliases = index
            .traversal
            .as_ref()
            .map(|t| archive_ids(&t.codex_rollout_paths))
            .unwrap_or_default();
    }
    pub fn retains(&self, key: &str) -> bool {
        replaces_plain(Path::new(key), &self.aliases)
    }
    pub fn ready(&self, remaining: u64) -> bool {
        self.power && self.cpu < 30_000_000 && remaining > 0 && self.work <= 20_000_000
    }
    pub fn observe(&mut self, cpu: Option<u64>, wall: u64) {
        if self.started || cpu.is_none() {
            self.cpu = cpu.map_or(u64::MAX, |cpu| self.cpu.saturating_add(cpu));
        }
        self.work = self.work.max(wall);
    }
}

pub(super) fn archive_ids(roster: &BTreeSet<String>) -> BTreeSet<String> {
    roster
        .iter()
        .filter(|p| codex_archive_path(Path::new(p)))
        .flat_map(|p| codex_session_id_candidates_from_path(Path::new(p)))
        .collect()
}
pub(super) fn replaces_plain(path: &Path, aliases: &BTreeSet<String>) -> bool {
    !codex_archive_path(path)
        && codex_session_id_candidates_from_path(path)
            .iter()
            .any(|id| aliases.contains(id))
}
pub(super) fn adjacent_archive(path: &Path) -> bool {
    !codex_archive_path(path)
        && fs::symlink_metadata(path.with_extension("jsonl.zst"))
            .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}

fn frame_length(file: &File) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let mut bytes = [0; 18];
        let n = file.read_at(&mut bytes, 0).ok()?;
        zstd::zstd_safe::get_frame_content_size(&bytes[..n])
            .ok()
            .flatten()
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        None
    }
}

impl ScanIndex {
    pub(super) fn classify_archive(
        &mut self,
        candidate: &CandidateFile,
        inventory: Option<&codex_file_join::HeaderInventory>,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
        pass: &mut Pass,
        budget: &mut sampled_scan::codex_cursor::PageBudget,
    ) -> bool {
        let ids = codex_session_id_candidates_from_path(&candidate.path);
        self.codex_state_only_blocked_session_ids
            .extend(ids.iter().cloned());
        let key = local_index_key(&candidate.path);
        let file = match open_candidate_beneath_root(candidate) {
            Ok(file) => file,
            Err(_) => return false,
        };
        if let Some(twin) = inventory.and_then(|i| {
            i.headers
                .iter()
                .find(|h| !codex_archive_path(&h.candidate.path) && ids.contains(&h.owner))
        }) {
            if codex_logical_rollout_path(&candidate.path).as_ref() == twin.candidate.path {
                crate::local_resource_diagnostics::codex_zst_classified(
                    "codex_zst_plain_twin_skip",
                );
            } else {
                self.hold_archive(candidate, &file, CodexZstCause::ArchiveEquivalenceUnproven);
            }
            return false;
        }
        let previous = self
            .files
            .get(&key)
            .and_then(|e| e.archive.as_ref())
            .filter(|a| a.matches(&file));
        if previous.is_some_and(|a| a.quiet(&file)) {
            return false;
        }
        let retry =
            previous.is_some_and(|a| matches!(a.disposition, ArchiveDisposition::Pending { .. }));
        // Any old evidence is a move/ambiguity, including tombstone-only state.
        // HOLD before a header decode; preserve every old fact, body and ACK.
        if !retry
            && ids.iter().any(|id| {
                pass.seen.contains(id)
                    || self
                        .codex_counting_tombstones
                        .contains_key(&codex_protected_owner(id))
            })
        {
            self.hold_archive(candidate, &file, CodexZstCause::ArchiveEquivalenceUnproven);
            return false;
        }
        if frame_length(&file).is_some_and(|n| n > 1 << 30) {
            self.hold_archive(candidate, &file, CodexZstCause::CatchupTooLarge);
            return false;
        }
        if !pass.ready(budget.singleton_remaining(sampled_scan::codex_cursor::Limits::current())) {
            sampled_scan::codex_cursor::requeue(self, &BTreeMap::new(), candidate);
            return false;
        }
        pass.started = true;
        crate::context_composition::set_utility_qos();
        match self.inventory_archive_header(candidate, cache) {
            Ok((_, bytes)) => {
                pass.seen.extend(ids);
                budget.charge(false, bytes as u64);
                true
            }
            Err(_) => {
                sampled_scan::codex_cursor::requeue(self, &BTreeMap::new(), candidate);
                false
            }
        }
    }
    fn hold_archive(&mut self, candidate: &CandidateFile, file: &File, cause: CodexZstCause) {
        let key = local_index_key(&candidate.path);
        if let Ok(mut archive) = ArchiveEvidence::begin(
            file,
            &candidate.path,
            self.files.get(&key).and_then(|e| e.archive.as_ref()),
        ) {
            archive.disposition = ArchiveDisposition::Held { cause };
            self.files.entry(key).or_default().archive = Some(archive);
            self.mark_bounded_sweep_unsettled();
            crate::local_resource_diagnostics::codex_zst_refused(cause);
            crate::local_resource_diagnostics::codex_zst_classified("codex_zst_held");
        }
    }
}
